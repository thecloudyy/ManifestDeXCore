#include "DevToolsClient.h"
#include "MDXBrowser.h"

#include "OSTPlatform/include/Encoding.h"
#include "OSTPlatform/include/Log.h"
#include "Utils/Json/Json.h"

#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
#include <windows.h>
#include <detours.h>

namespace MDXBrowser {

namespace {

static constexpr uint16_t kDevtoolsPort = 9467;

static bool CaseInsensitiveContains(const wchar_t* str, const wchar_t* toFind) {
    if (!str || !toFind) return false;
    size_t strLen = wcslen(str);
    size_t toFindLen = wcslen(toFind);
    if (strLen < toFindLen) return false;

    for (size_t i = 0; i <= strLen - toFindLen; ++i) {
        if (_wcsnicmp(&str[i], toFind, toFindLen) == 0) {
            return true;
        }
    }
    return false;
}

// --- CreateProcessW hook ---
static decltype(CreateProcessW)* g_realCreateProcessW = nullptr;

static BOOL WINAPI HkCreateProcessW(
    LPCWSTR lpApp, LPWSTR lpCmd,
    LPSECURITY_ATTRIBUTES lpPA, LPSECURITY_ATTRIBUTES lpTA,
    BOOL bIH, DWORD dwCF, LPVOID lpEnv, LPCWSTR lpCD,
    LPSTARTUPINFOW lpSI, LPPROCESS_INFORMATION lpPI)
{
    bool isSteamWH = false;
    if (lpApp && CaseInsensitiveContains(lpApp, L"steamwebhelper.exe")) isSteamWH = true;
    if (!isSteamWH && lpCmd && CaseInsensitiveContains(lpCmd, L"steamwebhelper.exe")) isSteamWH = true;

    if (isSteamWH && lpCmd && !CaseInsensitiveContains(lpCmd, L"--remote-debugging")) {
        std::wstring cmd(lpCmd);
        cmd += L" --remote-debugging-port=" + std::to_wstring(kDevtoolsPort);
        OSTP_LOG_INFO("CDP: injected --remote-debugging-port={}", kDevtoolsPort);
        return g_realCreateProcessW(lpApp, &cmd[0], lpPA, lpTA, bIH, dwCF, lpEnv, lpCD, lpSI, lpPI);
    }

    return g_realCreateProcessW(lpApp, lpCmd, lpPA, lpTA, bIH, dwCF, lpEnv, lpCD, lpSI, lpPI);
}

static std::string MakeMsg(uint32_t id, const std::string& m, const std::string& p = "{}") {
    return "{\"id\":" + std::to_string(id) + ",\"method\":\"" + m + "\",\"params\":" + p + "}";
}

} // namespace

// --- Hook install ---
bool DevToolsClient::InstallProcessHook() {
    if (g_realCreateProcessW) return true;
    
    LONG err = DetourTransactionBegin();
    if (err != NO_ERROR) {
        OSTP_LOG_WARN("CDP: DetourTransactionBegin failed in InstallProcessHook (error={})", err);
        return false;
    }
    
    err = DetourUpdateThread(GetCurrentThread());
    if (err != NO_ERROR) {
        OSTP_LOG_WARN("CDP: DetourUpdateThread failed in InstallProcessHook (error={})", err);
        DetourTransactionAbort();
        return false;
    }
    
    g_realCreateProcessW = (decltype(CreateProcessW)*)
        DetourFindFunction("Kernel32.dll", "CreateProcessW");
    if (!g_realCreateProcessW) {
        OSTP_LOG_WARN("CDP: DetourFindFunction failed in InstallProcessHook");
        DetourTransactionAbort();
        return false;
    }
    
    err = DetourAttach(&(PVOID&)g_realCreateProcessW, HkCreateProcessW);
    if (err != NO_ERROR) {
        OSTP_LOG_WARN("CDP: DetourAttach failed in InstallProcessHook (error={})", err);
        DetourTransactionAbort();
        g_realCreateProcessW = nullptr;
        return false;
    }
    
    err = DetourTransactionCommit();
    if (err != NO_ERROR) {
        OSTP_LOG_WARN("CDP: DetourTransactionCommit failed in InstallProcessHook (error={})", err);
        g_realCreateProcessW = nullptr;
        return false;
    }
    
    OSTP_LOG_INFO("CDP: CreateProcessW hook installed (port {})", kDevtoolsPort);
    return true;
}

bool DevToolsClient::RemoveProcessHook() {
    if (!g_realCreateProcessW) return true;
    
    LONG err = NO_ERROR;
    for (int retry = 0; retry < 5; ++retry) {
        err = DetourTransactionBegin();
        if (err != NO_ERROR) {
            OSTP_LOG_WARN("CDP: DetourTransactionBegin failed in RemoveProcessHook (error={})", err);
            continue;
        }
        
        err = DetourUpdateThread(GetCurrentThread());
        if (err != NO_ERROR) {
            OSTP_LOG_WARN("CDP: DetourUpdateThread failed in RemoveProcessHook (error={})", err);
            DetourTransactionAbort();
            continue;
        }
        
        err = DetourDetach(&(PVOID&)g_realCreateProcessW, HkCreateProcessW);
        if (err != NO_ERROR) {
            OSTP_LOG_WARN("CDP: DetourDetach failed in RemoveProcessHook (error={})", err);
            DetourTransactionAbort();
            continue;
        }
        
        err = DetourTransactionCommit();
        if (err == NO_ERROR) {
            g_realCreateProcessW = nullptr;
            OSTP_LOG_INFO("CDP: CreateProcessW hook removed");
            return true;
        }
        
        OSTP_LOG_WARN("CDP: DetourTransactionCommit failed in RemoveProcessHook (error={}, attempt={}/5), retrying...", err, retry + 1);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    
    OSTP_LOG_ERROR("CDP: CRITICAL - Failed to remove CreateProcessW hook after retries (error={}). DLL unload may crash!", err);
    return false;
}

// --- Connection management ---

void DevToolsClient::Disconnect() {
    isConnected_.store(false, std::memory_order_release);
    if (ws_) {
        ws_->Close();
    }
    if (recvThread_.joinable()) {
        recvThread_.join();
    }
    if (ws_) {
        delete ws_;
        ws_ = nullptr;
    }
    currentTargetId_.clear();
    currentUrl_.clear();
    lastLoaderId_.clear();
    {
        std::lock_guard<std::mutex> lock(pendingMtx_);
        pending_.clear();
    }
    lastInjectedScript_.clear();
}

uint16_t DevToolsClient::FindActivePort() {
    // Probe the last known-good port first so steady-state (re)connects don't
    // burn seconds timing out on dead ports. Dead-port probes use short
    // timeouts (250ms resolve/connect) since a live localhost port answers
    // almost instantly — a long timeout only ever penalizes the miss case.
    std::vector<uint16_t> ports;
    if (lastGoodPort_ != 0) ports.push_back(lastGoodPort_);
    for (uint16_t p : {kDevtoolsPort, (uint16_t)9222, (uint16_t)8080}) {
        if (p != lastGoodPort_) ports.push_back(p);
    }

    for (uint16_t port : ports) {
        auto url = "http://localhost:" + std::to_string(port) + "/json/version";
        auto r = OSTPlatform::Http::Execute(L"GET", url.c_str(), nullptr, 0, nullptr,
                                            250, 250, 1000, 1000);
        if (r.ok && r.status == 200) {
            OSTP_LOG_INFO("CDP: DevTools active on port {}", port);
            lastGoodPort_ = port;
            return port;
        }
    }
    return 0;
}

std::vector<DevToolsTarget> DevToolsClient::FetchTargets(uint16_t port) {
    std::vector<DevToolsTarget> targets;
    if (port == 0) return targets;

    auto url = "http://localhost:" + std::to_string(port) + "/json";
    auto r = OSTPlatform::Http::Execute(L"GET", url.c_str(), nullptr, 0, nullptr,
                                        2000, 2000, 5000, 5000);
    if (!r.ok || r.status != 200) return targets;

    auto aStart = r.body.find('[');
    if (aStart == std::string::npos) return targets;

    size_t p = aStart + 1;
    while (p < r.body.size()) {
        auto oS = r.body.find('{', p);
        if (oS == std::string::npos) break;
        auto oE = r.body.find('}', oS);
        if (oE == std::string::npos) break;
        std::string_view obj(r.body.data() + oS, oE - oS + 1);
        p = oE + 1;

        auto id = MdxJson::GetString(obj, "id");
        auto type = MdxJson::GetString(obj, "type");
        auto url = MdxJson::GetString(obj, "url");
        auto ws = MdxJson::GetString(obj, "webSocketDebuggerUrl");
        if (id && type && url && ws)
            targets.push_back({*id, *type, MdxJson::GetString(obj, "title").value_or(""), *url, *ws});
    }
    return targets;
}

// --- CDP communication ---

bool DevToolsClient::SendCdp(const std::string& method, const std::string& params) {
    if (!ws_ || !ws_->IsOpen()) return false;
    uint32_t mid = 0;
    {
        std::lock_guard<std::mutex> lock(pendingMtx_);
        mid = nextMsgId_++;
        pending_[mid] = method;
    }
    auto msg = MakeMsg(mid, method, params);
    if (!ws_->SendText(msg)) {
        std::lock_guard<std::mutex> lock(pendingMtx_);
        pending_.erase(mid);
        return false;
    }
    return true;
}

bool DevToolsClient::RecvAndDispatch(uint32_t timeoutMs) {
    if (!ws_ || !ws_->IsOpen()) return false;
    auto msg = ws_->Receive(timeoutMs);
    if (msg.closed) return false;
    if (msg.text.empty() && msg.binary.empty()) return false;

    auto json = std::string_view(msg.text);
    auto method = MdxJson::GetString(json, "method");
    auto id = MdxJson::GetUInt64(json, "id");

    if (method) {
        if (*method == "Page.frameNavigated") {
            HandleFrameNavigated(std::string(json));
        } else if (*method == "Runtime.consoleAPICalled") {
            // Single scan for all MDX console-prefixed messages.
            // All known prefixes are checked in order of expected frequency.
            static constexpr std::string_view kCancelSub = "__mdx_cancel_ad";
            static constexpr std::string_view kReopenPrefix = "__mdx_reopen_ad:";
            static constexpr std::string_view kClickPrefix = "__mdx_click:";

            // __mdx_cancel_ad — user clicked Cancel on the ad-waiting modal
            if (msg.text.find(kCancelSub) != std::string::npos) {
                OSTP_LOG_INFO("CDP: Ad-wait cancel event received");
                g_adCancelled.store(true, std::memory_order_release);
            }

            // __mdx_reopen_ad:<url> — user clicked the retry link; open the
            // ad URL in the system browser (ShellExecuteW) so it never goes
            // through Steam's own CEF browser.
            if (auto rPos = msg.text.find(kReopenPrefix); rPos != std::string::npos) {
                auto urlStart = rPos + kReopenPrefix.size();
                // The URL is embedded in a JSON string — advance past any
                // leading double-quote that the CDP payload may have added.
                while (urlStart < msg.text.size() && msg.text[urlStart] == '"') urlStart++;
                auto urlEnd = urlStart;
                while (urlEnd < msg.text.size() &&
                       msg.text[urlEnd] != '"' &&
                       msg.text[urlEnd] != '\\' &&
                       msg.text[urlEnd] != '\n') {
                    urlEnd++;
                }
                if (urlEnd > urlStart) {
                    std::string url = msg.text.substr(urlStart, urlEnd - urlStart);
                    OSTP_LOG_INFO("CDP: Reopening ad URL in system browser: {}", url);
                    std::wstring urlW = OSTPlatform::Encoding::Utf8ToWide(url);
                    ShellExecuteW(nullptr, L"open", urlW.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
                }
            }

            // __mdx_click:<appId>;depots=...;dlcs=...
            if (auto clickPos = msg.text.find(kClickPrefix); clickPos != std::string::npos) {
                auto start = clickPos + kClickPrefix.size();
                auto digitEnd = msg.text.find_first_not_of("0123456789", start);
                if (digitEnd == std::string::npos) digitEnd = msg.text.size();
                std::string appIdStr = msg.text.substr(start, digitEnd - start);
                if (!appIdStr.empty()) {
                    try {
                        uint32_t appId = (uint32_t)std::stoul(appIdStr);
                        std::string customDepots;
                        std::string customDlcs;

                        // Parse optional custom depots/dlcs
                        // format: __mdx_click:<appId>;depots=...;dlcs=...
                        static constexpr std::string_view kDepotsPrefix = "depots=";
                        static constexpr std::string_view kDlcsPrefix = "dlcs=";

                        if (auto depotsPos = msg.text.find(kDepotsPrefix, start);
                            depotsPos != std::string::npos) {
                            auto dStart = depotsPos + kDepotsPrefix.size();
                            auto dEnd = msg.text.find(';', dStart);
                            customDepots = msg.text.substr(dStart, dEnd != std::string::npos ? dEnd - dStart : dEnd);
                        }

                        if (auto dlcsPos = msg.text.find(kDlcsPrefix, start);
                            dlcsPos != std::string::npos) {
                            auto dlStart = dlcsPos + kDlcsPrefix.size();
                            auto dlEnd = msg.text.find(';', dlStart);
                            customDlcs = msg.text.substr(dlStart, dlEnd != std::string::npos ? dlEnd - dlStart : dlEnd);
                        }

                        OSTP_LOG_INFO("CDP: Console event click detected for appId={}, depots={}, dlcs={}", appId, customDepots, customDlcs);
                        if (onAddClick_) {
                            auto cb = onAddClick_;
                            std::thread([cb, appId, customDepots, customDlcs] { cb(appId, customDepots, customDlcs); }).detach();
                        }
                    } catch (...) {}
                }
            }
        }
        return true;
    }
    if (id) {
        std::lock_guard<std::mutex> lock(pendingMtx_);
        pending_.erase((uint32_t)*id);
        return true;
    }
    return true;
}

bool DevToolsClient::WaitForResponse(uint32_t msgId, int maxWaitMs) {
    int waited = 0;
    while (waited < maxWaitMs) {
        if (isConnected_.load(std::memory_order_acquire)) {
            // Background thread is running and calling RecvAndDispatch;
            // we just lock, check if message is resolved, and sleep.
            {
                std::lock_guard<std::mutex> lock(pendingMtx_);
                if (pending_.find(msgId) == pending_.end()) return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            waited += 10;
        } else {
            // Connection phase: main thread does it synchronously
            RecvAndDispatch((std::min)(50, maxWaitMs - waited));
            {
                std::lock_guard<std::mutex> lock(pendingMtx_);
                if (pending_.find(msgId) == pending_.end()) return true;
            }
            waited += 50;
        }
    }
    return false;
}

// --- Frame navigation handler ---

void DevToolsClient::HandleFrameNavigated(const std::string& paramsJson) {
    // Ignore child-frame (iframe) navigations — e.g. ads/widgets embedded in
    // the store page — so they can't corrupt currentUrl_/lastLoaderId_.
    // CDP only includes "parentId" on the frame object for non-main frames.
    if (MdxJson::GetString(paramsJson, "parentId")) return;

    auto url = MdxJson::GetString(paramsJson, "url");
    if (!url) return;
    OSTP_LOG_INFO("CDP: Frame navigated to {}", *url);

    // Handle mdx://add?appId=... button click — do NOT update currentUrl_
    if (url->rfind("mdx://add?appId=", 0) == 0) {
        std::string appIdStr = url->substr(16); // length of "mdx://add?appId="
        // strip any trailing query params
        auto amp = appIdStr.find('&');
        if (amp != std::string::npos) appIdStr = appIdStr.substr(0, amp);
        try {
            uint32_t appId = (uint32_t)std::stoul(appIdStr);
            OSTP_LOG_INFO("CDP: mdx:// click for appId={}", appId);
            if (onAddClick_) {
                // Fire on a separate detached thread so Pump() is not blocked
                auto cb = onAddClick_;
                std::thread([cb, appId] { cb(appId, "", ""); }).detach();
            }
        } catch (...) {}
        return; // don't change currentUrl_
    }

    // Dedup only against exact-duplicate frameNavigated events for the SAME
    // navigation (CDP can emit the event more than once per commit). We key on
    // loaderId, which is unique per real navigation — including a reload of the
    // same URL (which destroys the page's JS context and so must re-inject).
    //
    // We intentionally do NOT suppress the first post-connect event: attaching
    // mid-load means the real commit arrives as a frameNavigated into a fresh
    // JS context that genuinely needs injection. Re-injecting into a context
    // that already has the button is harmless — the injected script's
    // window['__mdxObserver_<appId>'] guard makes the second run a no-op, and
    // injectBtn() self-dedups at the DOM level as a final backstop.
    auto loaderId = MdxJson::GetString(paramsJson, "loaderId");
    if (loaderId && *loaderId == lastLoaderId_) return;
    if (loaderId) lastLoaderId_ = *loaderId;
    currentUrl_ = *url;

    if (currentUrl_.find("store.steampowered.com/app/") != std::string::npos) {
        size_t pos = currentUrl_.find("/app/") + 5;
        size_t end = currentUrl_.find('/', pos);
        if (end == std::string::npos) end = currentUrl_.size();
        try {
            uint32_t appId = (uint32_t)std::stoul(currentUrl_.substr(pos, end - pos));
            if (onStorePage_) onStorePage_(appId, currentUrl_);
        } catch (...) {}
    }
}

// --- Main Connect ---

bool DevToolsClient::Connect(const std::string& steamInstallPath) {
    Disconnect();
    OSTP_LOG_INFO("CDP: Connecting to Steam CEF DevTools...");

    // 1. Ensure marker file exists (works for next Steam restart)
    std::string markerPath = steamInstallPath + "\\.cef-enable-remote-debugging";
    if (!std::filesystem::exists(markerPath)) {
        std::error_code ec;
        std::ofstream(markerPath).close();
        OSTP_LOG_INFO("CDP: Created {}", markerPath);
    }

    // 2. Find active devtools port
    uint16_t port = FindActivePort();
    if (port == 0) {
        OSTP_LOG_WARN("CDP: No active DevTools port. Install hook is active for next steamwebhelper restart.");
        return false;
    }

    // 3. Get store page targets
    auto targets = FetchTargets(port);
    if (targets.empty()) {
        OSTP_LOG_WARN("CDP: No targets found on port {}", port);
        return false;
    }

    // 4. Find store page target, or fall back to the first page target
    DevToolsTarget* target = nullptr;
    for (auto& t : targets) {
        if (t.type == "page" && t.url.find("store.steampowered.com/app/") != std::string::npos) {
            target = &t;
            break;
        }
    }
    if (!target) {
        for (auto& t : targets) {
            if (t.type == "page") { target = &t; break; }
        }
    }
    // If still no target, try SharedJSContext
    if (!target && !targets.empty()) { target = &targets[0]; }
    if (!target) {
        OSTP_LOG_WARN("CDP: No page target available");
        return false;
    }

    // 5. Parse ws URL
    auto& wsUrl = target->webSocketDebuggerUrl;
    std::string host = "localhost";
    uint16_t wsPort = port;
    std::string path = "/devtools/page/" + target->id;
    if (wsUrl.size() > 5) {
        auto rest = wsUrl.substr(5);
        auto slash = rest.find('/');
        auto hp = (slash != std::string::npos) ? rest.substr(0, slash) : rest;
        auto colon = hp.find(':');
        if (colon != std::string::npos) {
            host = hp.substr(0, colon);
            wsPort = (uint16_t)std::stoul(hp.substr(colon + 1));
        } else { host = hp; }
        if (slash != std::string::npos) path = rest.substr(slash);
    }

    currentTargetId_ = target->id;
    currentUrl_ = target->url;

    // 6. Open WS
    ws_ = new OSTPlatform::WebSocket::Client();
    if (!ws_->Connect(host, wsPort, path)) {
        OSTP_LOG_WARN("CDP: WS connect to {}:{}{} failed", host, wsPort, path);
        delete ws_; ws_ = nullptr;
        return false;
    }
    OSTP_LOG_INFO("CDP: WS connected to {} {} (target={})", currentUrl_, path, currentTargetId_);

    // 7. Enable CDP domains
    SendCdp("Page.enable", "{}");
    WaitForResponse(nextMsgId_ - 1, 500);
    SendCdp("Runtime.enable", "{}");
    WaitForResponse(nextMsgId_ - 1, 500);

    // 8. Inject into current page if it's a store page
    if (currentUrl_.find("store.steampowered.com/app/") != std::string::npos) {
        size_t pos = currentUrl_.find("/app/") + 5;
        size_t end = currentUrl_.find('/', pos);
        if (end == std::string::npos) end = currentUrl_.size();
        try {
            uint32_t appId = (uint32_t)std::stoul(currentUrl_.substr(pos, end - pos));
            if (onStorePage_) onStorePage_(appId, currentUrl_);
        } catch (...) {}
    }

    // 9. Start background receive thread
    // Uses a bounded receive timeout (rather than blocking forever) so the
    // thread wakes up periodically to recheck isConnected_/IsOpen(). With an
    // unbounded receive, Disconnect()'s recvThread_.join() had to wait for
    // WinHttpWebSocketReceive to unblock after the handle was closed out
    // from under it, which could stall for many seconds — the actual cause
    // of the button taking ~17s to appear when switching from the library
    // target to a store-page target.
    isConnected_.store(true, std::memory_order_release);
    recvThread_ = std::thread([this] {
        while (isConnected_.load(std::memory_order_acquire)) {
            if (!ws_ || !ws_->IsOpen()) break;
            RecvAndDispatch(300); // false return may just mean "timed out"; IsOpen() is the real exit signal
        }
        OSTP_LOG_INFO("CDP: Background WS receive thread exiting");
        isConnected_.store(false, std::memory_order_release);
    });

    return true;
}

void DevToolsClient::Pump() {
    if (!ws_ || !ws_->IsOpen()) return;

    // Process queued scripts on the main thread to avoid thread safety issues
    std::vector<std::string> toInject;
    {
        std::lock_guard<std::mutex> lock(queueMtx_);
        while (!scriptQueue_.empty()) {
            toInject.push_back(scriptQueue_.front());
            scriptQueue_.pop();
        }
    }
    for (const auto& s : toInject) {
        auto expr = MdxJson::EscapeForJson(s);
        std::string params = R"({"expression":)" + expr +
            R"(,"returnByValue":true,"awaitPromise":false,"userGesture":true})";
        SendCdp("Runtime.evaluate", params);
    }

    // If the currently connected target is not a store page, periodically scan for one.
    // Scanning is cheap (localhost-only HTTP calls), so we run it near every
    // Pump() cycle rather than every 2s.
    //
    // currentUrl_ goes "not a store page" not only when we're attached to a
    // genuinely different target, but also transiently while browsing from the
    // library: Steam fires Page.frameNavigated to data:text/html,...library...
    // URLs on the SAME target we're already attached to. In that case the store
    // target we find here is the very target we're connected to — reconnecting
    // to it just tears down and rebuilds the same WebSocket, and each rebuild
    // pays FindActivePort's cost while disconnected (so the button can't be
    // injected). We only Disconnect/reconnect when the store target is actually
    // a DIFFERENT target; otherwise we just refresh currentUrl_ so scanning
    // stops and the existing connection keeps serving injections.
    if (currentUrl_.find("store.steampowered.com/app/") == std::string::npos) {
        static ULONGLONG lastScan = 0;
        ULONGLONG now = GetTickCount64();
        if (now - lastScan > 200) {
            lastScan = now;
            uint16_t port = FindActivePort();
            if (port != 0) {
                auto targets = FetchTargets(port);
                for (const auto& t : targets) {
                    if (t.type == "page" && t.url.find("store.steampowered.com/app/") != std::string::npos) {
                        if (t.id == currentTargetId_ && IsConnected()) {
                            // Already attached to this target — no reconnect needed.
                            OSTP_LOG_INFO("CDP: Store page target ({}) is the current target; refreshing url without reconnect", t.url);
                            currentUrl_ = t.url;
                        } else {
                            OSTP_LOG_INFO("CDP: Found store page target ({}), reconnecting...", t.url);
                            Disconnect();
                            return;
                        }
                    }
                }
            }
        }
    }
}

void DevToolsClient::QueueInjectScript(const std::string& script) {
    std::lock_guard<std::mutex> lock(queueMtx_);
    scriptQueue_.push(script);
}

bool DevToolsClient::InjectScript(const std::string& script) {
    if (!ws_ || !ws_->IsOpen()) return false;

    auto expr = MdxJson::EscapeForJson(script);
    std::string params = R"({"expression":)" + expr +
        R"(,"returnByValue":true,"awaitPromise":false,"userGesture":true})";

    uint32_t mid = 0;
    {
        std::lock_guard<std::mutex> lock(pendingMtx_);
        mid = nextMsgId_++;
        pending_[mid] = "Runtime.evaluate";
    }
    auto msg = MakeMsg(mid, "Runtime.evaluate", params);
    if (!ws_->SendText(msg)) {
        std::lock_guard<std::mutex> lock(pendingMtx_);
        pending_.erase(mid);
        return false;
    }

    if (WaitForResponse(mid, 3000)) {
        lastInjectedScript_ = script;
        return true;
    }
    return false;
}

} // namespace MDXBrowser
