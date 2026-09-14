#include "MDXBrowser.h"

#include "DevToolsClient.h"
#include "OSTPlatform/include/Http.h"
#include "OSTPlatform/include/Log.h"
#include "OSTPlatform/include/SecureStorage.h"
#include "OSTPlatform/include/Thread.h"
#include "Utils/Json/Json.h"
#include "dllmain.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>


#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>  // Socket API (must precede windows.h)
#include <ws2tcpip.h>
#include <shlobj.h>  // SHGetKnownFolderPath, FOLDERID_LocalAppData
#include <shellapi.h> // ShellExecuteW
#include <cstring>    // strlen
#include <windows.h>
#include <tlhelp32.h>

namespace MDXBrowser {

// Shared cancellation flag: set by DevToolsClient when it sees __mdx_cancel_ad
// in a Runtime.consoleAPICalled event; polled by HandleAddClick's wait loop.
std::atomic<bool> g_adCancelled{false};

namespace {

struct AuthData {
    std::string token;
    std::string expiresAt; // ISO 8601
    std::string savedAt;
};

std::atomic<bool>  g_active{false};
std::thread g_workerThread;
std::string g_steamInstallPath;
DevToolsClient g_devTools;
ScriptProvider g_scriptProvider;

std::optional<AuthData> ReadAuthToken() {
    // %LocalAppData%\ManifestDeX\auth.dat
    std::filesystem::path localAppData;
    wchar_t* path = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &path))) {
        localAppData = path;
        CoTaskMemFree(path);
    } else {
        OSTP_LOG_WARN("MDXBrowser: SHGetKnownFolderPath(FOLDERID_LocalAppData) failed");
        return std::nullopt;
    }

    std::filesystem::path authFile = localAppData / "ManifestDeX" / "auth.dat";
    if (!std::filesystem::exists(authFile)) {
        OSTP_LOG_WARN("MDXBrowser: auth.dat not found at {}", authFile.string());
        return std::nullopt;
    }

    // Read encrypted blob
    std::ifstream ifs(authFile, std::ios::binary);
    if (!ifs) {
        OSTP_LOG_WARN("MDXBrowser: Failed to open auth.dat");
        return std::nullopt;
    }
    std::vector<uint8_t> encrypted((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    ifs.close();

    if (encrypted.empty()) {
        OSTP_LOG_WARN("MDXBrowser: auth.dat is empty");
        return std::nullopt;
    }

    // Decrypt via DPAPI (CurrentUser, no entropy)
    auto decryptedOpt = OSTPlatform::SecureStorage::DecryptCurrentUser(encrypted.data(), encrypted.size());
    if (!decryptedOpt) {
        OSTP_LOG_WARN("MDXBrowser: Failed to decrypt auth.dat (DPAPI)");
        return std::nullopt;
    }

    std::string json(decryptedOpt->begin(), decryptedOpt->end());

    // Parse JSON: { "Token": "...", "ExpiresAt": "...", "SavedAt": "..." }
    auto tokenOpt = MdxJson::GetString(json, "Token");
    auto expiresOpt = MdxJson::GetString(json, "ExpiresAt");
    auto savedOpt = MdxJson::GetString(json, "SavedAt");

    if (!tokenOpt) {
        OSTP_LOG_WARN("MDXBrowser: auth.dat missing Token field");
        return std::nullopt;
    }

    AuthData auth;
    auth.token = *tokenOpt;
    auth.expiresAt = expiresOpt.value_or("");
    auth.savedAt = savedOpt.value_or("");
    return auth;
}

// Forward declaration of native click handler (stale 1-arg overload removed)

std::vector<uint32_t> ParseBasicDepotIds(const std::string& json) {
    std::vector<uint32_t> depotIds;
    const std::string key = "\"basicDepotIds\"";
    size_t keyPos = json.find(key);
    if (keyPos == std::string::npos) {
        const std::string key2 = "\"BasicDepotIds\"";
        keyPos = json.find(key2);
    }
    if (keyPos != std::string::npos) {
        size_t arrStart = json.find('[', keyPos);
        size_t arrEnd   = json.find(']', arrStart);
        if (arrStart != std::string::npos && arrEnd != std::string::npos) {
            std::string arr = json.substr(arrStart + 1, arrEnd - arrStart - 1);
            size_t pos = 0;
            while (pos < arr.size()) {
                while (pos < arr.size() && !std::isdigit((unsigned char)arr[pos])) ++pos;
                if (pos >= arr.size()) break;
                size_t numEnd = pos;
                while (numEnd < arr.size() && std::isdigit((unsigned char)arr[numEnd])) ++numEnd;
                if (numEnd > pos) {
                    try { depotIds.push_back((uint32_t)std::stoul(arr.substr(pos, numEnd - pos))); } catch (...) {}
                }
                pos = numEnd;
            }
        }
    }
    return depotIds;
}

bool HasDecryptionKeys(const std::string& json) {
    size_t depotsPos = json.find("\"depots\"");
    if (depotsPos == std::string::npos) {
        depotsPos = json.find("\"Depots\"");
    }
    if (depotsPos == std::string::npos) {
        return false;
    }

    size_t arrStart = json.find('[', depotsPos);
    size_t arrEnd   = json.find(']', arrStart);
    if (arrStart == std::string::npos || arrEnd == std::string::npos) {
        return false;
    }

    std::string arr = json.substr(arrStart + 1, arrEnd - arrStart - 1);
    size_t pos = 0;
    int depotsCount = 0;
    bool anyKey = false;

    while (pos < arr.size()) {
        size_t objStart = arr.find('{', pos);
        if (objStart == std::string::npos) break;

        size_t objEnd = std::string::npos;
        int depth = 0;
        bool inString = false;
        for (size_t i = objStart; i < arr.size(); ++i) {
            if (arr[i] == '"') {
                bool escaped = false;
                if (i > objStart && arr[i - 1] == '\\') {
                    size_t bs = 0;
                    for (size_t j = i - 1; j >= objStart && arr[j] == '\\'; --j) {
                        bs++;
                    }
                    if (bs % 2 != 0) {
                        escaped = true;
                    }
                }
                if (!escaped) {
                    inString = !inString;
                }
            } else if (!inString) {
                if (arr[i] == '{') {
                    depth++;
                } else if (arr[i] == '}') {
                    depth--;
                    if (depth == 0) {
                        objEnd = i;
                        break;
                    }
                }
            }
        }
        if (objEnd == std::string::npos) break;

        depotsCount++;
        std::string_view obj = std::string_view(arr).substr(objStart, objEnd - objStart + 1);

        auto hasKeyOpt = MdxJson::GetBool(obj, "hasDecryptionKey");
        if (!hasKeyOpt) {
            hasKeyOpt = MdxJson::GetBool(obj, "HasDecryptionKey");
        }

        if (hasKeyOpt && *hasKeyOpt) {
            anyKey = true;
        }

        pos = objEnd + 1;
    }

    if (depotsCount == 0) {
        return false;
    }

    return anyKey;
}

std::string DefaultScriptProvider(uint32_t appId, const std::string& detailsJson) {
    // Inject a MutationObserver that inserts "Add with Element" INSIDE the
    // existing .btn_addtocart div (alongside the real buy button).
    // On click, outputs a console message containing '__mdx_click:<appId>'
    // which our CDP client listens to via Runtime.consoleAPICalled.
    // Also injects visual states/animations (loading, success, error) and
    // a global state updater window.__mdxUpdateState.

    std::string appIdStr = std::to_string(appId);
    std::string detailsJsonVar = "null";
    if (!detailsJson.empty()) {
        detailsJsonVar = "JSON.parse(" + MdxJson::EscapeForJson(detailsJson) + ")";
    }

    std::string script = R"((function() {
    var guardKey = '__mdxObserver_)" + appIdStr + R"(';
    if (window[guardKey]) return 'already_running';
    window[guardKey] = true;

    // Details may not be known yet at inject time (the button is shown
    // optimistically before the backend responds) — BuildSetDetailsScript
    // fills window['__mdxDetails_<appId>'] in later; showConfigModal reads
    // it fresh on each click rather than from a frozen closure variable.
    window['__mdxDetails_)" + appIdStr + R"('] = )" + detailsJsonVar + R"(;

    // Styles are injected lazily from injectBtn() (below), not here — the
    // button is now injected optimistically right on Page.frameNavigated,
    // often before the page has finished building <head>, so document.head
    // can still be null at this point. ensureStyles() is safe to call
    // repeatedly; it retries via the MutationObserver until head exists.
    function ensureStyles() {
        if (!document.head || document.getElementById('mdx-styles')) return;
        var style = document.createElement('style');
        style.id = 'mdx-styles';
        document.head.appendChild(style);
        var ss = style.sheet;
        ss.insertRule('@keyframes mdx-pulse{0%{opacity:0.6;transform:scale(0.98)}50%{opacity:1;transform:scale(1.02)}100%{opacity:0.6;transform:scale(0.98)}}', ss.cssRules.length);
        ss.insertRule('@keyframes mdx-shake{0%,100%{transform:translateX(0)}20%,60%{transform:translateX(-4px)}40%,80%{transform:translateX(4px)}}', ss.cssRules.length);
        ss.insertRule('@keyframes mdx-pop{0%{transform:scale(1)}50%{transform:scale(1.15)}100%{transform:scale(1)}}', ss.cssRules.length);
        ss.insertRule('@keyframes mdx-spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}', ss.cssRules.length);
        ss.insertRule('.mdx-btn{transition:background 0.3s ease,transform 0.2s ease;vertical-align:top !important}', ss.cssRules.length);
        ss.insertRule('.mdx-btn.mdx-unauth{display:inline-flex !important;align-items:center !important;justify-content:center !important;height:30px !important;box-sizing:border-box !important}', ss.cssRules.length);
        ss.insertRule('.mdx-btn.mdx-loading{animation:mdx-pulse 1.2s infinite ease-in-out;background:linear-gradient(to right,#555,#777) !important;pointer-events:none}', ss.cssRules.length);
        ss.insertRule('.mdx-btn.mdx-success{animation:mdx-pop 0.4s ease-out;background:linear-gradient(to right,#4caf50,#81c784) !important;pointer-events:none}', ss.cssRules.length);
        ss.insertRule('.mdx-btn.mdx-error{animation:mdx-shake 0.4s ease-in-out;background:linear-gradient(to right,#f44336,#e57373) !important;pointer-events:none}', ss.cssRules.length);
        ss.insertRule('.mdx-config-btn{margin-left:4px !important;vertical-align:top !important;min-width:0 !important}', ss.cssRules.length);
        ss.insertRule('.mdx-config-btn>span{padding:0 10px !important;text-align:center !important;min-width:0 !important;display:inline-flex !important;align-items:center !important;justify-content:center !important;height:30px !important;box-sizing:border-box !important}', ss.cssRules.length);
        ss.insertRule('.mdx-btn.mdx-loading+.mdx-config-btn,.mdx-btn.mdx-success+.mdx-config-btn,.mdx-btn.mdx-error+.mdx-config-btn{pointer-events:none;opacity:0.5}', ss.cssRules.length);
        ss.insertRule('.mdx-modal-backdrop{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);backdrop-filter:blur(5px);z-index:99999;display:flex;align-items:center;justify-content:center;opacity:0;transition:opacity 0.2s ease;font-family:"Motiva Sans",Sans-serif}', ss.cssRules.length);
        ss.insertRule('.mdx-modal-backdrop.mdx-show{opacity:1}', ss.cssRules.length);
        ss.insertRule('.mdx-modal-card{background:linear-gradient(180deg,#1b2838 0%,#101622 100%);border:1px solid #3d4f6c;border-radius:8px;width:520px;max-width:90%;max-height:80%;display:flex;flex-direction:column;box-shadow:0 15px 35px rgba(0,0,0,0.6);transform:scale(0.9);transition:transform 0.2s cubic-bezier(0.175,0.885,0.32,1.2);overflow:hidden}', ss.cssRules.length);
        ss.insertRule('.mdx-modal-backdrop.mdx-show .mdx-modal-card{transform:scale(1)}', ss.cssRules.length);
        ss.insertRule('.mdx-modal-header{padding:16px;background:rgba(0,0,0,0.2);border-bottom:1px solid #2d3b50;display:flex;justify-content:space-between;align-items:center;position:relative}', ss.cssRules.length);
        ss.insertRule('.mdx-modal-header-bg{position:absolute;top:0;left:0;width:100%;height:100%;background-size:cover;background-position:center;opacity:0.15;z-index:0;filter:blur(2px)}', ss.cssRules.length);
        ss.insertRule('.mdx-modal-title-container{z-index:1;display:flex;align-items:center;gap:12px}', ss.cssRules.length);
        ss.insertRule('.mdx-modal-header-img{width:80px;height:37px;border-radius:4px;object-fit:cover;border:1px solid #3d4f6c}', ss.cssRules.length);
        ss.insertRule('.mdx-modal-title{font-size:16px;font-weight:500;color:#ffffff;text-shadow:1px 1px 2px rgba(0,0,0,0.8)}', ss.cssRules.length);
        ss.insertRule('.mdx-modal-close{background:none;border:none;color:#a3a3a7;font-size:24px;cursor:pointer;z-index:1;transition:color 0.2s;line-height:1;padding:0 4px}', ss.cssRules.length);
        ss.insertRule('.mdx-modal-close:hover{color:#ffffff}', ss.cssRules.length);
        ss.insertRule('.mdx-modal-body{padding:20px;overflow-y:auto;flex-grow:1;font-size:14px;color:#c6d4df}', ss.cssRules.length);
        ss.insertRule('.mdx-modal-section{margin-bottom:20px}', ss.cssRules.length);
        ss.insertRule('.mdx-modal-section-title{font-size:14px;font-weight:600;color:#66c0f4;margin-bottom:12px;border-bottom:1px solid #2d3b50;padding-bottom:4px;display:flex;justify-content:space-between;align-items:center}', ss.cssRules.length);
        ss.insertRule('.mdx-section-helper{font-size:11px;color:#a3a3a7;cursor:pointer;text-decoration:underline}', ss.cssRules.length);
        ss.insertRule('.mdx-section-helper:hover{color:#66c0f4}', ss.cssRules.length);
        ss.insertRule('.mdx-list-item{display:flex;align-items:center;padding:8px 10px;border-radius:4px;background:rgba(255,255,255,0.02);margin-bottom:6px;cursor:pointer;transition:background 0.2s}', ss.cssRules.length);
        ss.insertRule('.mdx-list-item:hover{background:rgba(255,255,255,0.05)}', ss.cssRules.length);
        ss.insertRule('.mdx-checkbox-input{margin-right:12px;cursor:pointer;accent-color:#66c0f4}', ss.cssRules.length);
        ss.insertRule('.mdx-item-details{display:flex;flex-direction:column;gap:2px}', ss.cssRules.length);
        ss.insertRule('.mdx-item-name{font-weight:500;color:#dcdedf}', ss.cssRules.length);
        ss.insertRule('.mdx-item-meta{font-size:11px;color:#8f98a0}', ss.cssRules.length);
        ss.insertRule('.mdx-modal-footer{padding:16px;background:rgba(0,0,0,0.3);border-top:1px solid #2d3b50;display:flex;justify-content:flex-end;gap:10px}', ss.cssRules.length);
        ss.insertRule('.mdx-modal-btn{padding:8px 16px;border-radius:2px;font-size:14px;cursor:pointer;border:none;font-weight:500;transition:background 0.2s,transform 0.1s}', ss.cssRules.length);
        ss.insertRule('.mdx-modal-btn-cancel{background:#2f3e51;color:#dcdedf}', ss.cssRules.length);
        ss.insertRule('.mdx-modal-btn-cancel:hover{background:#3d5169}', ss.cssRules.length);
        ss.insertRule('.mdx-modal-btn-confirm{background:linear-gradient(135deg,#4785d9 0%,#2059a5 100%);color:#ffffff;box-shadow:0 4px 10px rgba(0,0,0,0.2)}', ss.cssRules.length);
        ss.insertRule('.mdx-modal-btn-confirm:hover{background:linear-gradient(135deg,#5193f0 0%,#2566bd 100%)}', ss.cssRules.length);
        ss.insertRule('.mdx-modal-btn:active{transform:translateY(1px)}', ss.cssRules.length);
        ss.insertRule('.mdx-ad-spinner{width:40px;height:40px;border:3px solid rgba(102,192,244,0.2);border-top-color:#66c0f4;border-radius:50%;animation:mdx-spin 0.9s linear infinite;flex-shrink:0}', ss.cssRules.length);
        ss.insertRule('.mdx-ad-body{display:flex;flex-direction:column;align-items:center;gap:18px;padding:28px 24px 8px;text-align:center}', ss.cssRules.length);
        ss.insertRule('.mdx-ad-spinner-row{display:flex;align-items:center;gap:16px}', ss.cssRules.length);
        ss.insertRule('.mdx-ad-title{font-size:15px;font-weight:600;color:#ffffff}', ss.cssRules.length);
        ss.insertRule('.mdx-ad-sub{font-size:13px;color:#8f98a0;line-height:1.5}', ss.cssRules.length);
        ss.insertRule('.mdx-ad-progress-track{width:100%;height:4px;background:rgba(255,255,255,0.08);border-radius:2px;overflow:hidden}', ss.cssRules.length);
        ss.insertRule('.mdx-ad-progress-bar{height:100%;background:linear-gradient(to right,#4785d9,#66c0f4);border-radius:2px;transition:width 1s linear}', ss.cssRules.length);
        ss.insertRule('.mdx-ad-timer{font-size:12px;color:#66c0f4;font-variant-numeric:tabular-nums}', ss.cssRules.length);
        ss.insertRule('.mdx-ad-retry{font-size:12px;color:#a3a3a7;text-decoration:underline;cursor:pointer;margin-top:2px}', ss.cssRules.length);
        ss.insertRule('.mdx-ad-retry:hover{color:#66c0f4}', ss.cssRules.length);
        ss.insertRule('.mdx-ad-footer{display:flex;justify-content:center;padding:16px;border-top:1px solid #2d3b50;background:rgba(0,0,0,0.3)}', ss.cssRules.length);
    }

    // Define global updater
)" + R"(
    if (!window.__mdxUpdateState) {
        window.__mdxUpdateState = function(tgtAppId, state, extra) {
            var btn = document.querySelector('a.mdx-btn[data-appid="' + tgtAppId + '"]');
            if (!btn) return;
            var span = btn.querySelector('span');
            if (!span) return;
            
            btn.classList.remove('mdx-loading', 'mdx-success', 'mdx-error');
            
            if (state === 'loading') {
                // Dismiss any lingering ad-waiting modal
                var old = document.getElementById('mdx-ad-modal');
                if (old) old.remove();
                btn.classList.add('mdx-loading');
                span.textContent = 'Adding...';
            } else if (state === 'ad-waiting') {
                ensureStyles();
                var adUrl = (extra && extra.adUrl) ? extra.adUrl : null;
                var totalSecs = (extra && extra.timeout) ? extra.timeout : 300;
                var existing = document.getElementById('mdx-ad-modal');
                if (existing) existing.remove();
                var backdrop = document.createElement('div');
                backdrop.id = 'mdx-ad-modal';
                backdrop.className = 'mdx-modal-backdrop';
                var card = document.createElement('div');
                card.className = 'mdx-modal-card';
                card.style.width = '420px';
                var header = document.createElement('div');
                header.className = 'mdx-modal-header';
                var headerTitle = document.createElement('div');
                headerTitle.className = 'mdx-modal-title';
                headerTitle.textContent = 'Complete Ad in Browser';
                header.appendChild(headerTitle);
                card.appendChild(header);
                var body = document.createElement('div');
                body.className = 'mdx-ad-body';
                var spinnerRow = document.createElement('div');
                spinnerRow.className = 'mdx-ad-spinner-row';
                var spinner = document.createElement('div');
                spinner.className = 'mdx-ad-spinner';
                var titleEl = document.createElement('div');
                titleEl.className = 'mdx-ad-title';
                titleEl.textContent = 'Waiting for ad to complete...';
                spinnerRow.appendChild(spinner);
                spinnerRow.appendChild(titleEl);
                body.appendChild(spinnerRow);
                var sub = document.createElement('div');
                sub.className = 'mdx-ad-sub';
                sub.textContent = 'You have run out of credits. Please finish the ad link opened in your browser to continue adding the game to your library.';
                body.appendChild(sub);
                var track = document.createElement('div');
                track.className = 'mdx-ad-progress-track';
                var bar = document.createElement('div');
                bar.className = 'mdx-ad-progress-bar';
                bar.style.width = '100%';
                track.appendChild(bar);
                body.appendChild(track);
                var timer = document.createElement('div');
                timer.className = 'mdx-ad-timer';
                function fmtTime(s) {
                    var m = Math.floor(s / 60);
                    var ss = s % 60;
                    return m + ':' + (ss < 10 ? '0' : '') + ss;
                }
                timer.textContent = fmtTime(totalSecs);
                body.appendChild(timer);
                if (adUrl) {
                    var retry = document.createElement('span');
                    retry.className = 'mdx-ad-retry';
                    retry.textContent = 'Ad tab closed? Click here to reopen it';
                    retry.onclick = function() { console.log('__mdx_reopen_ad:' + adUrl); };
                    body.appendChild(retry);
                }
                card.appendChild(body);
                var footer = document.createElement('div');
                footer.className = 'mdx-ad-footer';
                var cancelBtn = document.createElement('button');
                cancelBtn.className = 'mdx-modal-btn mdx-modal-btn-cancel';
                cancelBtn.textContent = 'Cancel';
                cancelBtn.onclick = function() {
                    console.log('__mdx_cancel_ad');
                    backdrop.classList.remove('mdx-show');
                    setTimeout(function() { backdrop.remove(); }, 250);
                    btn.classList.remove('mdx-loading');
                    span.textContent = 'Add with Element';
                };
                footer.appendChild(cancelBtn);
                card.appendChild(footer);
                backdrop.appendChild(card);
                document.body.appendChild(backdrop);
                setTimeout(function() { backdrop.classList.add('mdx-show'); }, 10);
                var remaining = totalSecs;
                var tickInterval = setInterval(function() {
                    remaining--;
                    if (remaining <= 0) { clearInterval(tickInterval); return; }
                    timer.textContent = fmtTime(remaining);
                    bar.style.width = ((remaining / totalSecs) * 100).toFixed(1) + '%';
                }, 1000);
                backdrop._mdxTick = tickInterval;
            } else if (state === 'ad-dismiss') {
                var adModal = document.getElementById('mdx-ad-modal');
                if (adModal) {
                    if (adModal._mdxTick) clearInterval(adModal._mdxTick);
                    adModal.classList.remove('mdx-show');
                    setTimeout(function() { adModal.remove(); }, 250);
                }
            } else if (state === 'success') {
                var adModal2 = document.getElementById('mdx-ad-modal');
                if (adModal2) {
                    if (adModal2._mdxTick) clearInterval(adModal2._mdxTick);
                    adModal2.classList.remove('mdx-show');
                    setTimeout(function() { adModal2.remove(); }, 250);
                }
                btn.classList.add('mdx-success');
                span.textContent = 'Added!';
                setTimeout(function() {
                    btn.classList.remove('mdx-success');
                    if (btn.classList.contains('mdx-unauth')) {
                        span.textContent = '';
                        var smallText = document.createElement('span');
                        smallText.textContent = 'ManifestDeX';
                        smallText.style.fontSize = '9px';
                        smallText.style.fontWeight = 'normal';
                        smallText.style.opacity = '0.8';
                        var mainText = document.createElement('span');
                        mainText.textContent = 'Login with M^X Desktop';
                        mainText.style.fontSize = '13px';
                        mainText.style.fontWeight = 'bold';
                        span.appendChild(smallText);
                        span.appendChild(mainText);
                    } else {
                        span.textContent = 'Add with Element';
                    }
                }, 3000);
            } else if (state === 'error') {
                btn.classList.add('mdx-error');
                span.textContent = 'Failed!';
                setTimeout(function() {
                    btn.classList.remove('mdx-error');
                    if (btn.classList.contains('mdx-unauth')) {
                        span.textContent = '';
                        var smallText = document.createElement('span');
                        smallText.textContent = 'ManifestDeX';
                        smallText.style.fontSize = '9px';
                        smallText.style.fontWeight = 'normal';
                        smallText.style.opacity = '0.8';
                        var mainText = document.createElement('span');
                        mainText.textContent = 'Login with M^X Desktop';
                        mainText.style.fontSize = '13px';
                        mainText.style.fontWeight = 'bold';
                        span.appendChild(smallText);
                        span.appendChild(mainText);
                    } else {
                        span.textContent = 'Add with Element';
                    }
                }, 3000);
            }
        };
    }

    function showConfigModal() {
        var details = window['__mdxDetails_)" + appIdStr + R"('] || null;
        if (!details) {
            console.log('__mdx_click:' + )" + appIdStr + R"();
            return;
        }

        var existing = document.getElementById('mdx-config-modal');
        if (existing) existing.remove();

        var backdrop = document.createElement('div');
        backdrop.id = 'mdx-config-modal';
        backdrop.className = 'mdx-modal-backdrop';

        var card = document.createElement('div');
        card.className = 'mdx-modal-card';

        var headerBg = document.createElement('div');
        headerBg.className = 'mdx-modal-header-bg';
        if (details.headerImage) {
            headerBg.style.backgroundImage = 'url(' + details.headerImage + ')';
        }

        var header = document.createElement('div');
        header.className = 'mdx-modal-header';
        header.appendChild(headerBg);

        var titleContainer = document.createElement('div');
        titleContainer.className = 'mdx-modal-title-container';

        if (details.headerImage) {
            var headerImg = document.createElement('img');
            headerImg.className = 'mdx-modal-header-img';
            headerImg.src = details.headerImage;
            titleContainer.appendChild(headerImg);
        }

        var title = document.createElement('div');
        title.className = 'mdx-modal-title';
        title.textContent = details.name ? ('Configure: ' + details.name) : 'Configure Download';
        titleContainer.appendChild(title);
        header.appendChild(titleContainer);

        var closeBtn = document.createElement('button');
        closeBtn.className = 'mdx-modal-close';
        closeBtn.innerHTML = '&times;';
        closeBtn.onclick = function() { closeModal(); };
        header.appendChild(closeBtn);
        card.appendChild(header);

        var body = document.createElement('div');
        body.className = 'mdx-modal-body';

        function formatBytes(bytes) {
            if (!bytes || bytes === 0) return '0 B';
            var k = 1024;
            var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            var i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function toggleAll(sectionClass, checked) {
            var checkboxes = body.querySelectorAll('.' + sectionClass + ' input[type="checkbox"]');
            checkboxes.forEach(function(cb) {
                cb.checked = checked;
            });
        }

        if (details.depots && details.depots.length > 0) {
            var depotSection = document.createElement('div');
            depotSection.className = 'mdx-modal-section mdx-depots-section';

            var depotTitle = document.createElement('div');
            depotTitle.className = 'mdx-modal-section-title';
            depotTitle.innerHTML = '<span>Depots</span>';

            var helpers = document.createElement('div');
            helpers.style.display = 'flex';
            helpers.style.gap = '8px';

            var selectAll = document.createElement('span');
            selectAll.className = 'mdx-section-helper';
            selectAll.textContent = 'All';
            selectAll.onclick = function() { toggleAll('mdx-depots-section', true); };
            helpers.appendChild(selectAll);

            var selectNone = document.createElement('span');
            selectNone.className = 'mdx-section-helper';
            selectNone.textContent = 'None';
            selectNone.onclick = function() { toggleAll('mdx-depots-section', false); };
            helpers.appendChild(selectNone);

            depotTitle.appendChild(helpers);
            depotSection.appendChild(depotTitle);

            var sortedDepots = details.depots.slice().sort(function(a, b) {
                if (a.isDlc !== b.isDlc) return a.isDlc ? 1 : -1;
                return a.depotId - b.depotId;
            });

            // All depots are pre-selected (the 'All' helper still exists for
            // re-selecting after 'None').
            sortedDepots.forEach(function(depot) {
                var label = document.createElement('label');
                label.className = 'mdx-list-item';

                var checkbox = document.createElement('input');
                checkbox.type = 'checkbox';
                checkbox.className = 'mdx-checkbox-input';
                checkbox.value = depot.depotId;
                checkbox.checked = true;

                var detailsDiv = document.createElement('div');
                detailsDiv.className = 'mdx-item-details';

                var nameSpan = document.createElement('span');
                nameSpan.className = 'mdx-item-name';
                nameSpan.textContent = depot.depotName || ('Depot ' + depot.depotId);

                var metaSpan = document.createElement('span');
                metaSpan.className = 'mdx-item-meta';
                
                var metaParts = [];
                metaParts.push('ID: ' + depot.depotId);
                if (depot.sizeBytes) {
                    metaParts.push('Size: ' + formatBytes(depot.sizeBytes));
                }
                if (depot.branchName && depot.branchName !== 'public') {
                    metaParts.push('Branch: ' + depot.branchName);
                }
                if (depot.isDlc && depot.dlcAppName) {
                    metaParts.push('DLC: ' + depot.dlcAppName);
                }
                metaSpan.textContent = metaParts.join(' | ');

                detailsDiv.appendChild(nameSpan);
                detailsDiv.appendChild(metaSpan);

                label.appendChild(checkbox);
                label.appendChild(detailsDiv);
                depotSection.appendChild(label);
            });

            body.appendChild(depotSection);
        }

        if (details.dlcs && details.dlcs.length > 0) {
            var dlcSection = document.createElement('div');
            dlcSection.className = 'mdx-modal-section mdx-dlcs-section';

            var dlcTitle = document.createElement('div');
            dlcTitle.className = 'mdx-modal-section-title';
            dlcTitle.innerHTML = '<span>DLCs</span>';

            var dlcHelpers = document.createElement('div');
            dlcHelpers.style.display = 'flex';
            dlcHelpers.style.gap = '8px';

            var dlcSelectAll = document.createElement('span');
            dlcSelectAll.className = 'mdx-section-helper';
            dlcSelectAll.textContent = 'All';
            dlcSelectAll.onclick = function() { toggleAll('mdx-dlcs-section', true); };
            dlcHelpers.appendChild(dlcSelectAll);

            var dlcSelectNone = document.createElement('span');
            dlcSelectNone.className = 'mdx-section-helper';
            dlcSelectNone.textContent = 'None';
            dlcSelectNone.onclick = function() { toggleAll('mdx-dlcs-section', false); };
            dlcHelpers.appendChild(dlcSelectNone);

            dlcTitle.appendChild(dlcHelpers);
            dlcSection.appendChild(dlcTitle);

            var sortedDlcs = details.dlcs.slice().sort(function(a, b) {
                return (a.name || '').localeCompare(b.name || '');
            });

            sortedDlcs.forEach(function(dlc) {
                var label = document.createElement('label');
                label.className = 'mdx-list-item';

                var checkbox = document.createElement('input');
                checkbox.type = 'checkbox';
                checkbox.className = 'mdx-checkbox-input';
                checkbox.value = dlc.appId;
                checkbox.checked = true;

                var detailsDiv = document.createElement('div');
                detailsDiv.className = 'mdx-item-details';

                var nameSpan = document.createElement('span');
                nameSpan.className = 'mdx-item-name';
                nameSpan.textContent = dlc.name || ('DLC ' + dlc.appId);

                var metaSpan = document.createElement('span');
                metaSpan.className = 'mdx-item-meta';
                metaSpan.textContent = 'AppID: ' + dlc.appId + (dlc.hasDecryptionKey ? '' : ' (No Decryption Key)');

                detailsDiv.appendChild(nameSpan);
                detailsDiv.appendChild(metaSpan);

                label.appendChild(checkbox);
                label.appendChild(detailsDiv);
                dlcSection.appendChild(label);
            });

            body.appendChild(dlcSection);
        }

        card.appendChild(body);

        var footer = document.createElement('div');
        footer.className = 'mdx-modal-footer';

        var cancelBtn = document.createElement('button');
        cancelBtn.className = 'mdx-modal-btn mdx-modal-btn-cancel';
        cancelBtn.textContent = 'Cancel';
        cancelBtn.onclick = function() { closeModal(); };

        var confirmBtn = document.createElement('button');
        confirmBtn.className = 'mdx-modal-btn mdx-modal-btn-confirm';
        confirmBtn.textContent = 'Add Selected';
        confirmBtn.onclick = function() {
            var selectedDepots = [];
            var selectedDlcs = [];

            body.querySelectorAll('.mdx-depots-section input[type="checkbox"]:checked').forEach(function(cb) {
                selectedDepots.push(cb.value);
            });

            body.querySelectorAll('.mdx-dlcs-section input[type="checkbox"]:checked').forEach(function(cb) {
                selectedDlcs.push(cb.value);
            });

            console.log('__mdx_click:' + )" + appIdStr + R"( + ';depots=' + selectedDepots.join(',') + ';dlcs=' + selectedDlcs.join(','));
            closeModal();
        };

        footer.appendChild(cancelBtn);
        footer.appendChild(confirmBtn);
        card.appendChild(footer);

        backdrop.appendChild(card);
        document.body.appendChild(backdrop);

        setTimeout(function() {
            backdrop.classList.add('mdx-show');
        }, 10);

        function handleEscape(e) {
            if (e.key === 'Escape') closeModal();
        }
        document.addEventListener('keydown', handleEscape);

        backdrop.onclick = function(e) {
            if (e.target === backdrop) closeModal();
        };

        function closeModal() {
            document.removeEventListener('keydown', handleEscape);
            backdrop.classList.remove('mdx-show');
            setTimeout(function() {
                backdrop.remove();
            }, 250);
        }
    }

    function injectBtn() {
        if (window['__mdxHidden_)" + appIdStr + R"(']) return;
        // SPA navigation guard: Steam's store is a single-page app. When the
        // user navigates from AppX to AppY the JS context is preserved, so
        // AppX's MutationObserver keeps firing on AppY's DOM mutations. Without
        // this check AppX's injectBtn() would inject AppX's button into AppY's
        // purchase area, causing two buttons to appear side-by-side.
        // When we detect we're no longer on this app's page we disconnect the
        // observer (stops the spurious injections) and delete the IIFE guard so
        // a fresh IIFE can run — and re-install a new observer — if the user
        // navigates back to this app's page later.
        if (window.location.href.indexOf('/app/)" + appIdStr + R"(') === -1) {
            if (typeof obs !== 'undefined' && obs) obs.disconnect();
            delete window[guardKey];
            return;
        }
        ensureStyles();
        // Self-dedup: if buttons for this appId already exist, keep exactly one
        // pair and remove any extras, then stop. This guarantees a single
        // button regardless of how many times or contexts this runs, so
        // duplicates can't survive whatever their upstream cause.
        var appid = ')" + appIdStr + R"(';
        var existing = document.querySelectorAll('a.mdx-btn[data-appid="' + appid + '"]');
        for (var i = 1; i < existing.length; i++) { existing[i].remove(); }
        var existingCfg = document.querySelectorAll('a.mdx-config-btn[data-appid="' + appid + '"]');
        for (var j = 1; j < existingCfg.length; j++) { existingCfg[j].remove(); }
        if (existing.length >= 1) return;
        // Store pages with a playable demo render an extra purchase card for
        // the demo (wrapped in .demo_above_purchase) ahead of the real game's
        // purchase card in DOM order. A plain first-match query grabs that
        // demo card, so the button ends up floating on the wrong control.
        // Prefer the first candidate NOT inside a demo card; fall back to
        // whatever exists (e.g. the demo's own store page) if none qualify.
        var addtocartDiv = null;
        var cartCandidates = document.querySelectorAll('.game_purchase_action_bg .btn_addtocart');
        for (var k = 0; k < cartCandidates.length; k++) {
            if (!cartCandidates[k].closest('.demo_above_purchase')) {
                addtocartDiv = cartCandidates[k];
                break;
            }
        }
        if (!addtocartDiv && cartCandidates.length > 0) addtocartDiv = cartCandidates[0];
        if (!addtocartDiv) return;

        var btn = document.createElement('a');
        btn.href = '#';
        btn.className = 'btn_blue_steamui btn_medium mdx-btn';
        btn.setAttribute('data-appid', ')" + appIdStr + R"(');
        btn.style.marginLeft = '4px';
        btn.onclick = function(e) {
            e.preventDefault();
            console.log('__mdx_click:' + )" + appIdStr + R"();
        };
        var span = document.createElement('span');
        span.textContent = 'Add with Element';
        btn.appendChild(span);
        addtocartDiv.appendChild(btn);

        var cfgBtn = document.createElement('a');
        cfgBtn.href = '#';
        cfgBtn.className = 'btn_blue_steamui btn_medium mdx-config-btn';
        cfgBtn.setAttribute('data-appid', ')" + appIdStr + R"(');
        cfgBtn.onclick = function(e) {
            e.preventDefault();
            showConfigModal();
        };
        var cfgSpan = document.createElement('span');
        cfgSpan.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="width: 14px; height: 14px; display: block;"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06-.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l.06-.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>';
        cfgBtn.appendChild(cfgSpan);
        addtocartDiv.appendChild(cfgBtn);

        console.log('[MDX] Injected buttons for appId=)" + appIdStr + R"(');
    }

    // Install the observer before the first injectBtn() attempt (and wrap
    // both in try/catch) so that if injectBtn() throws — e.g. a DOM shape
    // we didn't expect this early in page load — the observer is already
    // running and can still retry on subsequent mutations instead of the
    // whole script aborting with the guard flag stuck true.
    var obs = new MutationObserver(function() {
        try { injectBtn(); } catch (e) { console.log('[MDX] injectBtn error: ' + e); }
    });
    obs.observe(document.documentElement, {childList: true, subtree: true});
    try { injectBtn(); } catch (e) { console.log('[MDX] injectBtn error: ' + e); }
    return 'observer_installed';
})())";

    return script;
}

// Fills in details (depot/DLC list) for a button that was already injected
// optimistically, so the config/gear modal becomes usable once the backend
// responds. Does not touch the button/observer — those are already running.
std::string BuildSetDetailsScript(uint32_t appId, const std::string& detailsJson) {
    std::string appIdStr = std::to_string(appId);
    std::string detailsJsonVar = "null";
    if (!detailsJson.empty()) {
        detailsJsonVar = "JSON.parse(" + MdxJson::EscapeForJson(detailsJson) + ")";
    }
    return "window['__mdxDetails_" + appIdStr + "'] = " + detailsJsonVar + ";";
}

// Marks a button as permanently hidden (backend confirmed no decryption
// keys are available) and removes it from the DOM if already present. The
// hidden flag stops the MutationObserver from re-inserting it later.
std::string BuildRemoveButtonScript(uint32_t appId) {
    std::string appIdStr = std::to_string(appId);
    return "window['__mdxHidden_" + appIdStr + "'] = true;"
           "var b = document.querySelector('a.mdx-btn[data-appid=\"" + appIdStr + "\"]'); if (b) b.remove();"
           "var c = document.querySelector('a.mdx-config-btn[data-appid=\"" + appIdStr + "\"]'); if (c) c.remove();";
}

std::string BuildUpdateToUnauthenticatedScript(uint32_t appId) {
    std::string appIdStr = std::to_string(appId);
    return "(function() {"
           "var btn = document.querySelector('a.mdx-btn[data-appid=\"" + appIdStr + "\"]');"
           "if (!btn) return;"
           "btn.classList.add('mdx-unauth');"
           "btn.classList.remove('btn_blue_steamui');"
           "btn.classList.add('btn_grey_steamui');"
           "var span = btn.querySelector('span');"
           "if (span) {"
               "span.textContent = '';"
               "span.style.display = 'inline-flex';"
               "span.style.flexDirection = 'column';"
               "span.style.alignItems = 'center';"
               "span.style.justifyContent = 'center';"
               "span.style.lineHeight = '1.1';"
               "span.style.padding = '2px 10px';"
               
               "var smallText = document.createElement('span');"
               "smallText.textContent = 'ManifestDeX';"
               "smallText.style.fontSize = '9px';"
               "smallText.style.fontWeight = 'normal';"
               "smallText.style.opacity = '0.8';"
               
               "var mainText = document.createElement('span');"
               "mainText.textContent = 'Login with M^X Desktop';"
               "mainText.style.fontSize = '13px';"
               "mainText.style.fontWeight = 'bold';"
               
               "span.appendChild(smallText);"
               "span.appendChild(mainText);"
           "}"
           "var cfgBtn = document.querySelector('a.mdx-config-btn[data-appid=\"" + appIdStr + "\"]');"
           "if (cfgBtn) cfgBtn.remove();"
           "})();";
}

// Forward declarations
static void HandleAddClick(uint32_t appId, const std::string& customDepots, const std::string& customDlcs);
static void InjectForAppId(uint32_t appId);

static void KillSteamWebHelper() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        OSTP_LOG_WARN("MDXBrowser: CreateToolhelp32Snapshot failed");
        return;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"steamwebhelper.exe") == 0) {
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProc) {
                    OSTP_LOG_INFO("MDXBrowser: Terminating steamwebhelper.exe (PID {})", pe.th32ProcessID);
                    TerminateProcess(hProc, 0);
                    CloseHandle(hProc);
                }
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

void WorkerThread() {
    OSTP_LOG_INFO("MDXBrowser: Worker thread started for {}", g_steamInstallPath);

    // Install the store page callback BEFORE Connect, so it fires immediately
    g_devTools.SetStorePageCallback([](uint32_t appId, const std::string& url) {
        OSTP_LOG_INFO("MDXBrowser: Store page detected: appId={} url={}", appId, url);
        InjectForAppId(appId);
    });

    g_devTools.SetAddClickCallback([](uint32_t appId, const std::string& customDepots, const std::string& customDlcs) {
        HandleAddClick(appId, customDepots, customDlcs);
    });

    bool everConnected = false;
    bool killedForFlags = false;

    // Main connection and pump loop
    while (g_active.load(std::memory_order_acquire)) {
        if (!g_devTools.IsConnected()) {
            if (g_devTools.Connect(g_steamInstallPath)) {
                everConnected = true;
            } else {
                // Killing steamwebhelper is only correct at initial startup,
                // when it's running WITHOUT --remote-debugging-port and must be
                // relaunched so the CreateProcessW hook can add the flag. We do
                // that at most once, and only while we've never connected.
                //
                // After we've connected at least once, the flag is known to be
                // present, so a failed (re)connect is just a transient drop —
                // most commonly the brief window when switching from the library
                // target to a freshly-opened store-page target, where the new
                // target isn't listed in /json yet. Killing steamwebhelper there
                // forced a full ~15-20s restart, which is exactly why the button
                // took so long to appear when coming from the library page. In
                // that case we just retry quickly instead.
                if (!everConnected && !killedForFlags) {
                    killedForFlags = true;
                    OSTP_LOG_INFO("MDXBrowser: Initial DevTools connection failed. Terminating steamwebhelper to force restart with debugging flags.");
                    KillSteamWebHelper();
                    for (int i = 0; i < 20 && g_active.load(std::memory_order_acquire); ++i) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                } else {
                    for (int i = 0; i < 5 && g_active.load(std::memory_order_acquire); ++i) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                }
                continue;
            }
        }

        g_devTools.Pump();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    OSTP_LOG_INFO("MDXBrowser: Worker thread exiting");
}

static void InjectForAppId(uint32_t appId) {
    // Show the button immediately (optimistically), independent of the
    // backend check below, so it appears right away instead of waiting on
    // a network round-trip. The backend response (fetched in parallel on a
    // detached thread) only fills in details for the config modal, or
    // removes the button in the rare case no keys are available.
    {
        std::string script = g_scriptProvider ? g_scriptProvider(appId, "") : DefaultScriptProvider(appId, "");
        if (!script.empty()) {
            g_devTools.QueueInjectScript(script);
            OSTP_LOG_INFO("MDXBrowser: Injected button (queued) for appId={}", appId);
        }
    }

    OSTPlatform::Thread::StartDetached([appId]() {
        bool showButton = true;

        // 1. Read auth token
        auto authOpt = ReadAuthToken();
        std::wstring bearerHeaders;
        if (authOpt) {
            const std::string& token = authOpt->token;
            bearerHeaders = L"Authorization: Bearer " +
                            std::wstring(token.begin(), token.end()) +
                            L"\r\nX-Client-Platform: Desktop\r\n";
        } else {
            bearerHeaders = L"X-Client-Platform: Desktop\r\n";
        }

        // 2. GET /api/Manifest/desktop/details/{appId} to check if keys are available
        std::string detailsUrl = "https://api.manifestdex.com/api/Manifest/desktop/details/" + std::to_string(appId);

        auto detailsResult = OSTPlatform::Http::Execute(L"GET", detailsUrl.c_str(), nullptr, 0,
                                                        bearerHeaders.c_str(), 5000, 5000, 10000, 10000);

        if (detailsResult.ok) {
            if (detailsResult.status == 200) {
                if (!HasDecryptionKeys(detailsResult.body)) {
                    OSTP_LOG_INFO("MDXBrowser: No keys available for appId={} from backend (depots empty or all decryption keys are false)", appId);
                    showButton = false;
                }
            } else if (detailsResult.status == 404) {
                OSTP_LOG_INFO("MDXBrowser: No keys available for appId={} from backend (HTTP 404)", appId);
                showButton = false;
            } else if (detailsResult.status == 401 || detailsResult.status == 403) {
                // User is not logged in / auth failed, show the button so they can log in
                OSTP_LOG_INFO("MDXBrowser: details returned {} for appId={}, showing button for login", detailsResult.status, appId);
                showButton = true;
            } else {
                // Other HTTP statuses (e.g. 500) -> fail-safe, show the button
                OSTP_LOG_WARN("MDXBrowser: details returned status={} for appId={}, showing button as fail-safe", detailsResult.status, appId);
                showButton = true;
            }
        } else {
            // Network/HTTP execute failed -> fail-safe, show the button
            OSTP_LOG_WARN("MDXBrowser: details request failed for appId={}, showing button as fail-safe", appId);
            showButton = true;
        }

        if (showButton) {
            if (detailsResult.ok && detailsResult.status == 200) {
                g_devTools.QueueInjectScript(BuildSetDetailsScript(appId, detailsResult.body));
                OSTP_LOG_INFO("MDXBrowser: Filled in details (queued) for appId={}", appId);
            } else if (detailsResult.ok && (detailsResult.status == 401 || detailsResult.status == 403)) {
                // Button is always "Add with Element" (Element parity) — a
                // missing/expired ManifestDeX login must not restyle it, since
                // the click path installs from Ryuu without that login anyway.
                OSTP_LOG_INFO("MDXBrowser: details returned {} for appId={}, keeping button as-is", detailsResult.status, appId);
            }
            // Other fail-safe cases (500/network error): button is
            // already shown from the optimistic injection above; nothing
            // more to do since we have no details to fill in.
        } else {
            g_devTools.QueueInjectScript(BuildRemoveButtonScript(appId));
            OSTP_LOG_INFO("MDXBrowser: Removing button (queued) for appId={} (no keys available)", appId);
        }

        return 0u;
    });
}

static uint32_t WorkerThreadEntry() {
    WorkerThread();
    return 0;
}

std::vector<uint32_t> ParseCommaSeparatedIds(const std::string& str) {
    std::vector<uint32_t> ids;
    size_t start = 0;
    while (start < str.size()) {
        size_t end = str.find(',', start);
        if (end == std::string::npos) end = str.size();
        std::string part = str.substr(start, end - start);
        if (!part.empty()) {
            try {
                ids.push_back((uint32_t)std::stoul(part));
            } catch (...) {}
        }
        start = end + 1;
    }
    return ids;
}

// ── Ryuu direct download (Element app parity) ─────────────────────────
// Element downloads lua + manifests straight from the Ryuu API
// (https://generator.ryuu.lol — see ElementGui/AppConfig.cs: ApiBaseUrl and
// the compiled-in AuthKey) with no per-user login:
//   GET /api/download/{appId}?file_type=lua      → raw "{appId}.lua"
//   GET /api/download/{appId}?file_type=manifest → zip with "{appId}.lua"
//     plus "{depot}_{manifest}.manifest" files.
// Element's LuaInstaller then writes the .lua to config\stplug-in and every
// *.manifest to depotcache. This mirrors that so the store-page button
// behaves the same: lua → stplug-in, manifests → depotcache. Manifests go
// to BOTH <Steam>\depotcache (the folder Steam itself reads, sibling of
// steamapps) AND <Steam>\config\depotcache, so they land wherever the
// install expects them. Best-effort: never fails the overall add.

namespace {
// Hardcoded API keys (same values as Element's AppConfig.AuthKey / AppConfig.HubcapKey).
// The Hubcap key can also be overridden per-machine via ElementGui settings
// (%AppData%\ElementGui\settings.json -> "HubcapKey"); the settings value wins.
constexpr char kRyuuAuthKey[] = "hqGqlo1bw6aWFl08";
constexpr char kHubcapKey[] = "smm_da41ecae4378061052ce32dc357c9ae118c5f64cf6aab072c08c606c57d7558afe894d27e1eb14f90c521752894eebed";
constexpr char kHubcapBase[] = "https://hubcapmanifest.com";

// Reads one top-level string value from ElementGui's settings file
// (%AppData%\ElementGui\settings.json). Returns nullopt when the file, the
// key, or a string value is absent. Used for "BuiltInButtonMode" and the
// "HubcapKey" override so the store button follows ElementGui settings.
std::optional<std::string> ReadElementGuiSetting(const char* key) {
    wchar_t* path = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &path))) {
        return std::nullopt;
    }
    std::filesystem::path settingsFile =
        std::filesystem::path(path) / L"ElementGui" / L"settings.json";
    CoTaskMemFree(path);

    std::error_code ec;
    if (!std::filesystem::exists(settingsFile, ec)) return std::nullopt;
    std::ifstream ifs(settingsFile);
    if (!ifs) return std::nullopt;
    std::string json((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    if (json.empty()) return std::nullopt;
    return MdxJson::GetString(json, key);
}

// Which API the "Add with Element" button installs from: "hubcap" (default)
// or "ryuu". Adjusted from ElementGui settings -> Built-In Button Mode.
std::string ReadButtonMode() {
    auto v = ReadElementGuiSetting("BuiltInButtonMode");
    if (!v) return "hubcap";
    std::string lower = *v;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    if (lower == "ryuu") return "ryuu";
    return "hubcap";
}

std::string ReadHubcapKey() {
    auto v = ReadElementGuiSetting("HubcapKey");
    if (v && !v->empty()) return *v;
    return kHubcapKey;
}
} // namespace

static bool EndsWithI(const std::string& s, const char* suffix) {
    size_t sl = s.size(), xl = std::strlen(suffix);
    if (sl < xl) return false;
    for (size_t i = 0; i < xl; ++i) {
        if (std::tolower((unsigned char)s[sl - xl + i]) != std::tolower((unsigned char)suffix[i]))
            return false;
    }
    return true;
}

// Runs a command line hidden and waits up to timeoutMs. Returns true on exit code 0.
static bool RunHiddenAndWait(std::wstring cmdLine, DWORD timeoutMs) {
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmdLine.data(), nullptr, nullptr, FALSE,
                         CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        return false;
    }
    DWORD wait = WaitForSingleObject(pi.hProcess, timeoutMs);
    DWORD exitCode = 1;
    if (wait == WAIT_OBJECT_0) GetExitCodeProcess(pi.hProcess, &exitCode);
    else TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return wait == WAIT_OBJECT_0 && exitCode == 0;
}

// Extracts a zip using OS tools (no third-party dep): tar.exe first
// (ships with Win10 1803+), PowerShell Expand-Archive as fallback.
static bool ExtractZipViaOsTools(const std::filesystem::path& zipPath,
                                 const std::filesystem::path& destDir) {
    std::wstring zip = zipPath.wstring();
    std::wstring dst = destDir.wstring();
    {
        std::wstring cmd = L"tar.exe -xf \"" + zip + L"\" -C \"" + dst + L"\"";
        if (RunHiddenAndWait(cmd, 30000)) return true;
        OSTP_LOG_WARN("MDXBrowser: tar.exe extract failed, trying Expand-Archive");
    }
    {
        std::wstring cmd = L"powershell.exe -NoProfile -NonInteractive -Command \"Expand-Archive -LiteralPath '" +
                           zip + L"' -DestinationPath '" + dst + L"' -Force\"";
        if (RunHiddenAndWait(cmd, 60000)) return true;
    }
    return false;
}

// True when `data` ends with a complete zip (end-of-central-directory
// record present). Catches truncated downloads — e.g. from an HTTP client
// body cap — before they reach the extractor as corrupt zips.
static bool HasZipEndOfCentralDirectory(const std::string& data) {
    if (data.size() < 22) return false;
    const size_t scanStart = data.size() > (65535 + 22) ? data.size() - (65535 + 22) : 0;
    for (size_t i = data.size() - 22; ; --i) {
        if (data[i] == 'P' && data[i + 1] == 'K' && data[i + 2] == '\x05' && data[i + 3] == '\x06')
            return true;
        if (i == scanStart) break;
    }
    return false;
}

// Downloads lua + manifests for appId from Ryuu and installs them the way
// Element does. Returns true if anything landed (lua or ≥1 manifest).
static bool InstallFromRyuu(uint32_t appId) {
    if (g_steamInstallPath.empty()) {
        OSTP_LOG_WARN("MDXBrowser: Ryuu install skipped, no Steam path");
        return false;
    }
    std::string appIdStr = std::to_string(appId);
    std::wstring headers = L"X-Auth-Key: ";
    headers += std::wstring(kRyuuAuthKey, kRyuuAuthKey + std::strlen(kRyuuAuthKey));
    headers += L"\r\n";

    // Temp workspace under %TEMP%.
    wchar_t tmpRoot[MAX_PATH]{};
    DWORD tmpLen = GetTempPathW(MAX_PATH, tmpRoot);
    if (tmpLen == 0 || tmpLen >= MAX_PATH) {
        OSTP_LOG_WARN("MDXBrowser: Ryuu install skipped, no temp path");
        return false;
    }
    std::filesystem::path workDir =
        std::filesystem::path(tmpRoot) / ("mdx-ryuu-" + appIdStr + "-" + std::to_string(GetTickCount64()));
    std::error_code ec;
    std::filesystem::create_directories(workDir, ec);
    if (ec) {
        OSTP_LOG_WARN("MDXBrowser: Ryuu install skipped, cannot create temp dir: {}", ec.message());
        return false;
    }
    auto cleanup = [&]() {
        std::error_code rmEc;
        std::filesystem::remove_all(workDir, rmEc);
    };

    bool luaInstalled = false;
    int manifestCount = 0;

    std::filesystem::path stplugDir = std::filesystem::path(LuaDir);
    std::filesystem::path depotDir = std::filesystem::path(g_steamInstallPath) / "depotcache";
    std::filesystem::path depotDirLegacy = std::filesystem::path(g_steamInstallPath) / "config" / "depotcache";
    std::filesystem::create_directories(stplugDir, ec);
    std::filesystem::create_directories(depotDir, ec);
    std::filesystem::create_directories(depotDirLegacy, ec);
    ec.clear();

    // 1) Manifest bundle (zip with lua + *.manifest). This is the same call
    //    Element's DownloadManifestAsync makes (file_type=manifest).
    {
        std::string url = "https://generator.ryuu.lol/api/download/" + appIdStr + "?file_type=manifest";
        auto res = OSTPlatform::Http::Execute(L"GET", url.c_str(), nullptr, 0,
                                              headers.c_str(), 5000, 5000, 30000, 60000);
        if (res.ok && res.status == 200 && res.body.size() > 4 &&
            res.body[0] == 'P' && res.body[1] == 'K' &&
            res.body[2] == '\x03' && res.body[3] == '\x04' &&
            HasZipEndOfCentralDirectory(res.body)) {
            std::filesystem::path zipPath = workDir / (appIdStr + ".zip");
            {
                std::ofstream zf(zipPath, std::ios::binary | std::ios::trunc);
                if (zf) zf.write(res.body.data(), static_cast<std::streamsize>(res.body.size()));
            }
            std::filesystem::path extractDir = workDir / "ex";
            std::filesystem::create_directories(extractDir, ec);
            if (ExtractZipViaOsTools(zipPath, extractDir)) {
                std::error_code iterEc;
                for (auto it = std::filesystem::recursive_directory_iterator(
                         extractDir, std::filesystem::directory_options::skip_permission_denied, iterEc);
                     it != std::filesystem::recursive_directory_iterator(); ++it) {
                    if (iterEc) break;
                    if (!it->is_regular_file(iterEc)) continue;
                    std::string name = it->path().filename().string();
                    std::error_code cpEc;
                    if (EndsWithI(name, ".lua")) {
                        // Element forces the lua to <appid>.lua on install.
                        std::filesystem::copy_file(it->path(), stplugDir / (appIdStr + ".lua"),
                                                   std::filesystem::copy_options::overwrite_existing, cpEc);
                        if (!cpEc) luaInstalled = true;
                        else OSTP_LOG_WARN("MDXBrowser: Ryuu lua copy failed: {}", cpEc.message());
                    } else if (EndsWithI(name, ".manifest")) {
                        // Manifest names are content-addressed ({depot}_{gid});
                        // skip existing like Element (avoids Steam-locked failures).
                        bool oneOk = false;
                        for (const auto& dir : { depotDir, depotDirLegacy }) {
                            std::filesystem::path dest = dir / name;
                            if (std::filesystem::exists(dest, cpEc)) { oneOk = true; continue; }
                            std::filesystem::copy_file(it->path(), dest, cpEc);
                            if (!cpEc) oneOk = true;
                            else OSTP_LOG_WARN("MDXBrowser: Ryuu manifest copy failed ({}): {}", dest.string(), cpEc.message());
                        }
                        if (oneOk) manifestCount++;
                    }
                }
                OSTP_LOG_INFO("MDXBrowser: Ryuu bundle for appId={}: lua={} manifests={}", appId, luaInstalled, manifestCount);
            } else {
                OSTP_LOG_WARN("MDXBrowser: Ryuu zip extract failed for appId={}", appId);
            }
        } else {
            OSTP_LOG_WARN("MDXBrowser: Ryuu manifest bundle failed for appId={} (ok={} status={})",
                          appId, res.ok, res.status);
        }
    }

    // 2) Raw lua fallback (no zip involved): same call as Element's DownloadLuaAsync.
    if (!luaInstalled) {
        std::string url = "https://generator.ryuu.lol/api/download/" + appIdStr + "?file_type=lua";
        auto res = OSTPlatform::Http::Execute(L"GET", url.c_str(), nullptr, 0,
                                              headers.c_str(), 5000, 5000, 15000, 30000);
        if (res.ok && res.status == 200 && !res.body.empty()) {
            // Guard against a JSON error payload arriving under a 200.
            size_t first = res.body.find_first_not_of(" \t\r\n");
            if (first == std::string::npos || res.body[first] != '{') {
                std::filesystem::path dest = stplugDir / (appIdStr + ".lua");
                std::ofstream ofs(dest, std::ios::binary | std::ios::trunc);
                if (ofs) {
                    ofs.write(res.body.data(), static_cast<std::streamsize>(res.body.size()));
                    ofs.close();
                    luaInstalled = true;
                    OSTP_LOG_INFO("MDXBrowser: Ryuu raw lua for appId={} ({} bytes)", appId, res.body.size());
                }
            }
        }
        if (!luaInstalled)
            OSTP_LOG_WARN("MDXBrowser: Ryuu raw lua failed for appId={} (ok={} status={})", appId, res.ok, res.status);
    }

    cleanup();
    return luaInstalled || manifestCount > 0;
}

// ── Hubcap direct download (Element app parity) ─────────────────────────
// Same install layout as InstallFromRyuu (lua → stplug-in, manifests → both
// depotcache dirs), but against the Hubcap API with a Bearer key:
//   GET {hubcap}/api/v1/manifest/{appId} → zip with "{depot}_{manifest}.manifest"
//   GET {hubcap}/api/v1/lua/{appId}      → raw "{appId}.lua" (fallback when the
//     zip carries no lua). Quota is spent here, never on the button's
//     free-only availability probe.
static bool InstallFromHubcap(uint32_t appId, const std::string& hubcapKey) {
    if (g_steamInstallPath.empty()) {
        OSTP_LOG_WARN("MDXBrowser: Hubcap install skipped, no Steam path");
        return false;
    }
    if (hubcapKey.empty()) {
        OSTP_LOG_WARN("MDXBrowser: Hubcap install skipped, no Hubcap key");
        return false;
    }
    std::string appIdStr = std::to_string(appId);
    std::wstring headers = L"Authorization: Bearer " +
                           std::wstring(hubcapKey.begin(), hubcapKey.end()) +
                           L"\r\n";

    wchar_t tmpRoot[MAX_PATH]{};
    DWORD tmpLen = GetTempPathW(MAX_PATH, tmpRoot);
    if (tmpLen == 0 || tmpLen >= MAX_PATH) {
        OSTP_LOG_WARN("MDXBrowser: Hubcap install skipped, no temp path");
        return false;
    }
    std::filesystem::path workDir =
        std::filesystem::path(tmpRoot) / ("mdx-hubcap-" + appIdStr + "-" + std::to_string(GetTickCount64()));
    std::error_code ec;
    std::filesystem::create_directories(workDir, ec);
    if (ec) {
        OSTP_LOG_WARN("MDXBrowser: Hubcap install skipped, cannot create temp dir: {}", ec.message());
        return false;
    }
    auto cleanup = [&]() {
        std::error_code rmEc;
        std::filesystem::remove_all(workDir, rmEc);
    };

    bool luaInstalled = false;
    int manifestCount = 0;

    std::filesystem::path stplugDir = std::filesystem::path(LuaDir);
    std::filesystem::path depotDir = std::filesystem::path(g_steamInstallPath) / "depotcache";
    std::filesystem::path depotDirLegacy = std::filesystem::path(g_steamInstallPath) / "config" / "depotcache";
    std::filesystem::create_directories(stplugDir, ec);
    std::filesystem::create_directories(depotDir, ec);
    std::filesystem::create_directories(depotDirLegacy, ec);
    ec.clear();

    // 1) Manifest bundle (zip with *.manifest, may also carry the lua).
    {
        std::string url = std::string(kHubcapBase) + "/api/v1/manifest/" + appIdStr;
        auto res = OSTPlatform::Http::Execute(L"GET", url.c_str(), nullptr, 0,
                                              headers.c_str(), 5000, 5000, 30000, 60000);
        if (res.ok && res.status == 200 && res.body.size() > 4 &&
            res.body[0] == 'P' && res.body[1] == 'K' &&
            res.body[2] == '\x03' && res.body[3] == '\x04' &&
            HasZipEndOfCentralDirectory(res.body)) {
            std::filesystem::path zipPath = workDir / (appIdStr + ".zip");
            {
                std::ofstream zf(zipPath, std::ios::binary | std::ios::trunc);
                if (zf) zf.write(res.body.data(), static_cast<std::streamsize>(res.body.size()));
            }
            std::filesystem::path extractDir = workDir / "ex";
            std::filesystem::create_directories(extractDir, ec);
            if (ExtractZipViaOsTools(zipPath, extractDir)) {
                std::error_code iterEc;
                for (auto it = std::filesystem::recursive_directory_iterator(
                         extractDir, std::filesystem::directory_options::skip_permission_denied, iterEc);
                     it != std::filesystem::recursive_directory_iterator(); ++it) {
                    if (iterEc) break;
                    if (!it->is_regular_file(iterEc)) continue;
                    std::string name = it->path().filename().string();
                    std::error_code cpEc;
                    if (EndsWithI(name, ".lua")) {
                        std::filesystem::copy_file(it->path(), stplugDir / (appIdStr + ".lua"),
                                                   std::filesystem::copy_options::overwrite_existing, cpEc);
                        if (!cpEc) luaInstalled = true;
                        else OSTP_LOG_WARN("MDXBrowser: Hubcap lua copy failed: {}", cpEc.message());
                    } else if (EndsWithI(name, ".manifest")) {
                        bool oneOk = false;
                        for (const auto& dir : { depotDir, depotDirLegacy }) {
                            std::filesystem::path dest = dir / name;
                            if (std::filesystem::exists(dest, cpEc)) { oneOk = true; continue; }
                            std::filesystem::copy_file(it->path(), dest, cpEc);
                            if (!cpEc) oneOk = true;
                            else OSTP_LOG_WARN("MDXBrowser: Hubcap manifest copy failed ({}): {}", dest.string(), cpEc.message());
                        }
                        if (oneOk) manifestCount++;
                    }
                }
                OSTP_LOG_INFO("MDXBrowser: Hubcap bundle for appId={}: lua={} manifests={}", appId, luaInstalled, manifestCount);
            } else {
                OSTP_LOG_WARN("MDXBrowser: Hubcap zip extract failed for appId={}", appId);
            }
        } else if (res.ok && (res.status == 401 || res.status == 403)) {
            OSTP_LOG_WARN("MDXBrowser: Hubcap manifest bundle rejected for appId={} (HTTP {}, key invalid/expired)", appId, res.status);
        } else if (res.ok && res.status == 404) {
            OSTP_LOG_INFO("MDXBrowser: No Hubcap manifest for appId={} (HTTP 404)", appId);
        } else if (res.ok && res.status == 429) {
            OSTP_LOG_WARN("MDXBrowser: Hubcap daily limit reached for appId={}", appId);
        } else {
            OSTP_LOG_WARN("MDXBrowser: Hubcap manifest bundle failed for appId={} (ok={} status={})",
                          appId, res.ok, res.status);
        }
    }

    // 2) Raw lua fallback (no zip involved).
    if (!luaInstalled) {
        std::string url = std::string(kHubcapBase) + "/api/v1/lua/" + appIdStr;
        auto res = OSTPlatform::Http::Execute(L"GET", url.c_str(), nullptr, 0,
                                              headers.c_str(), 5000, 5000, 15000, 30000);
        if (res.ok && res.status == 200 && !res.body.empty()) {
            size_t first = res.body.find_first_not_of(" \t\r\n");
            if (first == std::string::npos || res.body[first] != '{') {
                std::filesystem::path dest = stplugDir / (appIdStr + ".lua");
                std::ofstream ofs(dest, std::ios::binary | std::ios::trunc);
                if (ofs) {
                    ofs.write(res.body.data(), static_cast<std::streamsize>(res.body.size()));
                    ofs.close();
                    luaInstalled = true;
                    OSTP_LOG_INFO("MDXBrowser: Hubcap raw lua for appId={} ({} bytes)", appId, res.body.size());
                }
            }
        }
        if (!luaInstalled)
            OSTP_LOG_WARN("MDXBrowser: Hubcap raw lua failed for appId={} (ok={} status={})", appId, res.ok, res.status);
    }

    cleanup();
    return luaInstalled || manifestCount > 0;
}

// Native click handler: reads auth, fetches basic depots or uses custom, generates and saves .lua
void HandleAddClick(uint32_t appId, const std::string& customDepots, const std::string& customDlcs) {
    OSTP_LOG_INFO("MDXBrowser: Handling add click for appId={}, customDepots='{}', customDlcs='{}'", appId, customDepots, customDlcs);

    // 1. Check if unauth action requested
    if (customDepots == "unauth") {
        OSTP_LOG_WARN("MDXBrowser: Unauthenticated button clicked — opening login page");
        ShellExecuteW(nullptr, L"open", L"https://manifestdex.com/desktop", nullptr, nullptr, SW_SHOWNORMAL);
        return;
    }

    auto notifyError = [appId]() {
        g_devTools.QueueInjectScript("if (window.__mdxUpdateState) window.__mdxUpdateState(" + std::to_string(appId) + ", 'error');");
    };
    auto notifySuccess = [appId]() {
        g_devTools.QueueInjectScript("if (window.__mdxUpdateState) window.__mdxUpdateState(" + std::to_string(appId) + ", 'success');");
    };

    // 2. Notify page that we are loading
    g_devTools.QueueInjectScript("if (window.__mdxUpdateState) window.__mdxUpdateState(" + std::to_string(appId) + ", 'loading');");

    // 3. Built-in install first (Element parity): which API it uses comes from
    //    ElementGui settings -> Built-In Button Mode ("Hubcap" default, or "Ryuu").
    //    Drops the lua to stplug-in plus the manifests to depotcache
    //    (<Steam>\depotcache and <Steam>\config\depotcache). Best-effort — the
    //    ManifestDeX flow below still runs afterwards for decryption keys and
    //    custom depot/DLC selections, overwriting the lua with its version.
    bool builtinOk = false;
    {
        std::string mode = ReadButtonMode();
        if (mode == "ryuu") {
            OSTP_LOG_INFO("MDXBrowser: Built-In Button Mode=Ryuu for appId={}", appId);
            builtinOk = InstallFromRyuu(appId);
        } else {
            OSTP_LOG_INFO("MDXBrowser: Built-In Button Mode=Hubcap for appId={}", appId);
            builtinOk = InstallFromHubcap(appId, ReadHubcapKey());
        }
    }

    // 4. Read auth token from %LocalAppData%\ManifestDeX\auth.dat
    auto authOpt = ReadAuthToken();
    if (!authOpt) {
        if (builtinOk) {
            // Built-in path already delivered working files; no login needed.
            OSTP_LOG_INFO("MDXBrowser: No ManifestDeX token, but built-in install succeeded for appId={}", appId);
            notifySuccess();
            return;
        }
        OSTP_LOG_WARN("MDXBrowser: No valid auth token — opening login page");
        ShellExecuteW(nullptr, L"open", L"https://manifestdex.com/desktop", nullptr, nullptr, SW_SHOWNORMAL);
        notifyError();
        return;
    }

    const std::string& token = authOpt->token;

    std::wstring bearerHeaders = L"Authorization: Bearer " +
                                 std::wstring(token.begin(), token.end()) +
                                 L"\r\nX-Client-Platform: Desktop\r\n";

    std::vector<uint32_t> depotIds;
    std::vector<uint32_t> selectedDlcAppIds;

    if (!customDepots.empty()) {
        depotIds = ParseCommaSeparatedIds(customDepots);
        selectedDlcAppIds = ParseCommaSeparatedIds(customDlcs);
        OSTP_LOG_INFO("MDXBrowser: Using custom configuration: {} depots, {} DLCs", depotIds.size(), selectedDlcAppIds.size());
    } else {
        // 3. GET /api/Manifest/desktop/details/{appId} to obtain BasicDepotIds
        std::string detailsUrl = "https://api.manifestdex.com/api/Manifest/desktop/details/" + std::to_string(appId);

        auto detailsResult = OSTPlatform::Http::Execute(L"GET", detailsUrl.c_str(), nullptr, 0,
                                                        bearerHeaders.c_str(), 5000, 5000, 15000, 15000);

        if (!detailsResult.ok || detailsResult.status != 200) {
            OSTP_LOG_WARN("MDXBrowser: desktop/details failed (status={})", detailsResult.status);
            notifyError();
            return;
        }

        // Parse BasicDepotIds from response JSON
        depotIds = ParseBasicDepotIds(detailsResult.body);

        if (depotIds.empty()) {
            OSTP_LOG_WARN("MDXBrowser: No BasicDepotIds returned for appId={}", appId);
            notifyError();
            return;
        }
        OSTP_LOG_INFO("MDXBrowser: Got {} basic depots for appId={}", depotIds.size(), appId);
    }

    // 4. Bind a local TCP listener on a random port so we can receive the
    //    ad-link redirect callback (used when the user has no credits).
    //    We bind now (before the HTTP request) so the port is known and can
    //    be included in the generate-lua body.
    SOCKET listenSock = INVALID_SOCKET;
    uint16_t localPort = 0;
    {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
        listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSock != INVALID_SOCKET) {
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = 0; // let OS pick
            if (bind(listenSock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0 &&
                listen(listenSock, 1) == 0) {
                int addrLen = sizeof(addr);
                getsockname(listenSock, reinterpret_cast<sockaddr*>(&addr), &addrLen);
                localPort = ntohs(addr.sin_port);
                OSTP_LOG_INFO("MDXBrowser: Listening on localhost:{} for ad-link callback", localPort);
            } else {
                closesocket(listenSock);
                listenSock = INVALID_SOCKET;
                OSTP_LOG_WARN("MDXBrowser: Failed to bind local listener, ad-link path may not work");
            }
        }
    }

    // Cleanup guard for the listener socket.
    auto closeListener = [&]() {
        if (listenSock != INVALID_SOCKET) {
            closesocket(listenSock);
            listenSock = INVALID_SOCKET;
        }
    };

    // 5. POST /api/Manifest/generate-lua with the depot IDs, DLCs, and local port
    std::string depotIdsJson = "[";
    for (size_t i = 0; i < depotIds.size(); ++i) {
        if (i > 0) depotIdsJson += ",";
        depotIdsJson += std::to_string(depotIds[i]);
    }
    depotIdsJson += "]";

    std::string dlcIdsJson = "[";
    for (size_t i = 0; i < selectedDlcAppIds.size(); ++i) {
        if (i > 0) dlcIdsJson += ",";
        dlcIdsJson += std::to_string(selectedDlcAppIds[i]);
    }
    dlcIdsJson += "]";

    std::string genBody = "{\"AppId\":" + std::to_string(appId) +
                          ",\"DepotIds\":" + depotIdsJson +
                          ",\"SelectedDlcAppIds\":" + dlcIdsJson +
                          ",\"DownloadToken\":\"\""
                          ",\"Port\":" + std::to_string(localPort) + "}";

    std::wstring genHeaders = bearerHeaders + L"Content-Type: application/json\r\n";

    auto genResult = OSTPlatform::Http::Execute(L"POST",
                                                "https://api.manifestdex.com/api/Manifest/generate-lua",
                                                genBody.data(), static_cast<uint32_t>(genBody.size()),
                                                genHeaders.c_str(), 5000, 5000, 30000, 30000);

    if (!genResult.ok || genResult.status != 200) {
        OSTP_LOG_WARN("MDXBrowser: generate-lua failed (status={})", genResult.status);
        closeListener();
        notifyError();
        return;
    }

    auto genUrlOpt = MdxJson::GetString(genResult.body, "url");
    if (!genUrlOpt) {
        OSTP_LOG_WARN("MDXBrowser: generate-lua missing url field");
        closeListener();
        notifyError();
        return;
    }

    // Check whether credits were used. When creditsUsed == false AND the url
    // does not already contain a token= parameter, it is a shortened ad-link
    // that must be opened in the browser. PRO users also receive
    // creditsUsed == false (no credit was deducted) but their url already
    // embeds token=, so we can extract it directly without the ad-link flow.
    auto creditsUsedOpt = MdxJson::GetBool(genResult.body, "creditsUsed");
    bool creditsUsed = !creditsUsedOpt.has_value() || *creditsUsedOpt; // default true (old behaviour)

    // If the URL already carries a token, treat it as a direct download
    // regardless of the creditsUsed flag (covers PRO/unlimited-credit users).
    if (!creditsUsed && genUrlOpt->find("token=") != std::string::npos) {
        creditsUsed = true;
    }

    std::string downloadToken;

    if (!creditsUsed) {
        // --- Ad-link path: open shortened URL in system browser, wait for callback ---
        OSTP_LOG_INFO("MDXBrowser: No credits used — opening ad link in system browser and waiting for callback");

        if (listenSock == INVALID_SOCKET) {
            OSTP_LOG_WARN("MDXBrowser: No listener socket available for ad-link callback");
            notifyError();
            return;
        }

        // Reset the cancellation flag before showing the modal.
        g_adCancelled.store(false, std::memory_order_release);

        // Open the ad URL in the user's default browser (not Steam's browser).
        const std::string& adUrl = *genUrlOpt;
        std::wstring adUrlW(adUrl.begin(), adUrl.end());
        ShellExecuteW(nullptr, L"open", adUrlW.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        OSTP_LOG_INFO("MDXBrowser: Opened ad URL in system browser: {}", adUrl);

        // Show the ad-waiting modal inside Steam with the ad URL (for the retry
        // link) and the timeout so the JS countdown matches the native timer.
        {
            const int kTimeoutSeconds = 900; // 15 minutes
            std::string escapedAdUrl = adUrl;
            // Minimal escaping: replace backslashes and single-quotes so the
            // URL is safe to embed inside a JS string literal.
            for (size_t i = 0; i < escapedAdUrl.size(); ++i) {
                if (escapedAdUrl[i] == '\'') { escapedAdUrl.insert(i, "\\"); i++; }
                else if (escapedAdUrl[i] == '\\') { escapedAdUrl.insert(i, "\\"); i++; }
            }
            std::string adWaitingScript =
                "if (window.__mdxUpdateState) window.__mdxUpdateState(" +
                std::to_string(appId) +
                ", 'ad-waiting', {adUrl: '" + escapedAdUrl + "', timeout: " +
                std::to_string(kTimeoutSeconds) + "});";
            g_devTools.QueueInjectScript(adWaitingScript);

            // Wait for the ad-link redirect to land on our local listener.
            // The ManifestDeX website will redirect to:
            //   https://manifestdex.com/desktop/download-lua?token={token}&port={port}
            // which in turn redirects to:
            //   http://localhost:{port}?token={token}
            // We accept one connection, read the HTTP request line, extract token=,
            // send an HTTP 200 response, and close.
            fd_set readSet;
            struct timeval tv{};
            int elapsed = 0;
            SOCKET clientSock = INVALID_SOCKET;
            bool userCancelled = false;

            while (g_active.load(std::memory_order_acquire) && elapsed < kTimeoutSeconds) {
                // Check if the user hit Cancel in the Steam modal.
                if (g_adCancelled.load(std::memory_order_acquire)) {
                    userCancelled = true;
                    break;
                }

                FD_ZERO(&readSet);
                FD_SET(listenSock, &readSet);
                tv.tv_sec  = 1;
                tv.tv_usec = 0;
                int sel = select(0, &readSet, nullptr, nullptr, &tv);
                if (sel > 0) {
                    sockaddr_in clientAddr{};
                    int clientAddrLen = sizeof(clientAddr);
                    clientSock = accept(listenSock, reinterpret_cast<sockaddr*>(&clientAddr), &clientAddrLen);
                    break;
                }
                elapsed++;
            }

            closeListener(); // done with the listening socket

            if (userCancelled) {
                OSTP_LOG_INFO("MDXBrowser: Ad-link wait cancelled by user for appId={}", appId);
                // Modal was already dismissed by the JS cancel button handler;
                // just reset the button state.
                g_devTools.QueueInjectScript(
                    "if (window.__mdxUpdateState) window.__mdxUpdateState(" +
                    std::to_string(appId) + ", 'error');");
                return;
            }

            if (clientSock == INVALID_SOCKET) {
                // Timed out — dismiss the modal then show error.
                OSTP_LOG_WARN("MDXBrowser: Timed out waiting for ad-link callback for appId={}", appId);
                g_devTools.QueueInjectScript(
                    "if (window.__mdxUpdateState) window.__mdxUpdateState(" +
                    std::to_string(appId) + ", 'ad-dismiss');");
                notifyError();
                return;
            }

            // Read the HTTP request (first line is enough: "GET /?token=xxx HTTP/1.1")
            std::string requestBuf;
            requestBuf.reserve(512);
            char chunk[256];
            while (requestBuf.size() < 4096) {
                int r = recv(clientSock, chunk, sizeof(chunk) - 1, 0);
                if (r <= 0) break;
                chunk[r] = '\0';
                requestBuf += chunk;
                // Stop once we have the first line
                if (requestBuf.find('\n') != std::string::npos) break;
            }

            // Send a minimal HTTP response so the browser doesn't hang.
            const char* httpOk =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: 54\r\n"
                "Connection: close\r\n"
                "\r\n"
                "<html><body>Download started. You may close this tab.</body></html>";
            send(clientSock, httpOk, static_cast<int>(strlen(httpOk)), 0);
            closesocket(clientSock);

            // Extract token from the request line.
            // Example: "GET /?token=abc123&... HTTP/1.1"
            size_t tokenPos = requestBuf.find("token=");
            if (tokenPos != std::string::npos) {
                size_t tStart = tokenPos + 6;
                size_t tEnd   = requestBuf.find_first_of(" \t&\r\n", tStart);
                if (tEnd == std::string::npos) tEnd = requestBuf.size();
                downloadToken = requestBuf.substr(tStart, tEnd - tStart);
            }

            if (downloadToken.empty()) {
                OSTP_LOG_WARN("MDXBrowser: Ad-link callback did not contain a token");
                g_devTools.QueueInjectScript(
                    "if (window.__mdxUpdateState) window.__mdxUpdateState(" +
                    std::to_string(appId) + ", 'ad-dismiss');");
                notifyError();
                return;
            }

            // Dismiss the modal — the 'success' state also clears it, but
            // dismissing first removes the visible gap while download-lua runs.
            g_devTools.QueueInjectScript(
                "if (window.__mdxUpdateState) window.__mdxUpdateState(" +
                std::to_string(appId) + ", 'ad-dismiss');");

            OSTP_LOG_INFO("MDXBrowser: Received token via ad-link callback for appId={}", appId);
        }
    } else {
        // --- Direct path: credits used, token is embedded in the url field ---
        closeListener(); // no longer needed
        const std::string& genUrl = *genUrlOpt;
        size_t pos = genUrl.find("token=");
        if (pos != std::string::npos) {
            size_t start = pos + 6;
            size_t end   = genUrl.find('&', start);
            if (end == std::string::npos) end = genUrl.size();
            downloadToken = genUrl.substr(start, end - start);
        }

        if (downloadToken.empty()) {
            OSTP_LOG_WARN("MDXBrowser: Could not extract token from generate-lua response");
            notifyError();
            return;
        }
    }

    // 6. GET /api/Manifest/download-lua?token=... — response body is the raw .lua
    std::string dlUrl = "https://api.manifestdex.com/api/Manifest/download-lua?token=" + downloadToken;
    auto dlResult = OSTPlatform::Http::Execute(L"GET", dlUrl.c_str(), nullptr, 0,
                                               bearerHeaders.c_str(), 5000, 5000, 30000, 30000);

    if (!dlResult.ok || dlResult.status != 200) {
        OSTP_LOG_WARN("MDXBrowser: download-lua failed (status={})", dlResult.status);
        notifyError();
        return;
    }

    const std::string& luaContent = dlResult.body;
    if (luaContent.empty()) {
        OSTP_LOG_WARN("MDXBrowser: download-lua returned empty content");
        notifyError();
        return;
    }

    // 7. Write to <Steam>/config/stplug-in/{appId}.lua
    std::filesystem::path luaPath =
        std::filesystem::path(LuaDir) / (std::to_string(appId) + ".lua");
    std::error_code ec;
    std::filesystem::create_directories(luaPath.parent_path(), ec);
    if (ec) {
        OSTP_LOG_WARN("MDXBrowser: create_directories failed: {}", ec.message());
        notifyError();
        return;
    }

    std::ofstream ofs(luaPath, std::ios::binary | std::ios::trunc);
    if (!ofs) {
        OSTP_LOG_WARN("MDXBrowser: Failed to open {} for writing", luaPath.string());
        notifyError();
        return;
    }
    ofs.write(luaContent.data(), static_cast<std::streamsize>(luaContent.size()));
    ofs.close();

    OSTP_LOG_INFO("MDXBrowser: Successfully wrote {}.lua ({} bytes)", appId, luaContent.size());

    // 8. Notify page that we successfully added the game
    g_devTools.QueueInjectScript("if (window.__mdxUpdateState) window.__mdxUpdateState(" + std::to_string(appId) + ", 'success');");
}

} // namespace

void Initialize(const char* steamInstallPath) {
    if (!steamInstallPath || steamInstallPath[0] == '\0') {
        OSTP_LOG_WARN("MDXBrowser: Initialize called with empty steamInstallPath");
        return;
    }

    // The browser is always enabled: the button injects regardless of the
    // [mdx_browser].enabled config value.

    bool expected = false;
    if (!g_active.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        OSTP_LOG_WARN("MDXBrowser: Already initialized");
        return;
    }

    // Install CreateProcessW hook so future steamwebhelper spawns get
    // the --remote-debugging-port=9467 flag injected automatically.
    DevToolsClient::InstallProcessHook();

    g_steamInstallPath = steamInstallPath;
    g_scriptProvider = DefaultScriptProvider;

    g_workerThread = std::thread([] {
        WorkerThreadEntry();
    });

    OSTP_LOG_INFO("MDXBrowser: Initialize queued for {}", steamInstallPath);
}

void Shutdown() {
    if (!g_active.exchange(false, std::memory_order_acq_rel)) {
        return; // Already shut down
    }

    g_devTools.Disconnect();
    DevToolsClient::RemoveProcessHook();

    if (g_workerThread.joinable()) {
        g_workerThread.join();
    }

    OSTP_LOG_INFO("MDXBrowser: Shutdown complete");
}

bool IsActive() {
    return g_active.load(std::memory_order_acquire);
}

void SetScriptProvider(ScriptProvider provider) {
    g_scriptProvider = std::move(provider);
}

void OnPageNavigation(const std::string& newUrl) {
    // This is called from DevToolsClient's navigation callback
    // (which runs on the worker thread). We just need to trigger re-inject.
    // The callback is already set in WorkerThread to handle mdx:// and re-inject.
}

std::optional<uint32_t> ExtractAppIdFromUrl(const std::string& url) {
    // Match https://store.steampowered.com/app/730/... or /app/730
    const std::string prefix = "store.steampowered.com/app/";
    size_t pos = url.find(prefix);
    if (pos == std::string::npos) return std::nullopt;

    size_t start = pos + prefix.size();
    size_t end = url.find('/', start);
    if (end == std::string::npos) end = url.size();

    std::string appIdStr = url.substr(start, end - start);
    try {
        uint32_t appId = std::stoul(appIdStr);
        if (appId == 0) return std::nullopt;
        return appId;
    } catch (...) {
        return std::nullopt;
    }
}

} // namespace MDXBrowser