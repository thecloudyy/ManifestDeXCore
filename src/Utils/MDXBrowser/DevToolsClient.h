#pragma once

// Chrome DevTools Protocol (CDP) client for Steam's CEF (steamwebhelper).
//
// Design:
// 1. Creates .cef-enable-remote-debugging marker for port 8080
// 2. Hooks CreateProcessW to inject --remote-debugging-port=9467
// 3. Polls known DevTools ports until one responds
// 4. Polls /json endpoint for store page targets
// 5. When a target is found, connects WebSocket and injects script
// 6. Re-injects on navigation

#include "OSTPlatform/include/WebSocket.h"
#include "OSTPlatform/include/Http.h"

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <queue>
#include <thread>
#include <atomic>

namespace MDXBrowser {

struct DevToolsTarget {
    std::string id;
    std::string type;
    std::string title;
    std::string url;
    std::string webSocketDebuggerUrl;
};

class DevToolsClient {
public:
    using OnStorePage  = std::function<void(uint32_t appId, const std::string& url)>;
    // Fired when the injected button is clicked (mdx://add?appId=... navigation).
    using OnAddClick   = std::function<void(uint32_t appId, const std::string& customDepots, const std::string& customDlcs)>;

    DevToolsClient() = default;
    ~DevToolsClient() { Disconnect(); }

    // devtools port scanning + target discovery + WS connection + script injection
    bool Connect(const std::string& steamInstallPath);

    void Disconnect();
    bool IsConnected() const { return ws_ && ws_->IsOpen(); }

    // Keep calling Pump() periodically from a worker thread to handle events
    void Pump();

    // Inject script into the currently connected page target
    bool InjectScript(const std::string& script);
    void QueueInjectScript(const std::string& script);

    // Called when we detect a store page (via polling /json or navigation events)
    void SetStorePageCallback(OnStorePage cb) { onStorePage_ = std::move(cb); }

    // Called when the injected button is clicked (mdx://add?appId=... navigation)
    void SetAddClickCallback(OnAddClick cb)   { onAddClick_  = std::move(cb); }

    // CreateProcessW hook to inject --remote-debugging-port for future steamwebhelper spawns
    static bool InstallProcessHook();
    static bool RemoveProcessHook();

private:
    OSTPlatform::WebSocket::Client* ws_ = nullptr;
    // Last port that answered /json/version. Steam's actual debug port depends
    // on how it was enabled (marker file -> 8080, our hook -> 9467), so we cache
    // the winner and probe it first — otherwise every (re)connect wastes several
    // seconds timing out on the dead ports ahead of it in the scan list.
    uint16_t lastGoodPort_ = 0;
    std::string currentTargetId_;
    std::string currentUrl_;
    std::string lastLoaderId_;
    std::string lastInjectedScript_;
    OnStorePage onStorePage_;
    OnAddClick  onAddClick_;
    uint32_t nextMsgId_ = 1;
    std::unordered_map<uint32_t, std::string> pending_;

    bool SendCdp(const std::string& method, const std::string& params);
    bool RecvAndDispatch(uint32_t timeoutMs = 100);
    bool WaitForResponse(uint32_t msgId, int maxWaitMs = 2000);

    // Returns active devtools port or 0 if none found
    uint16_t FindActivePort();
    // Fetches /json and returns matching store page targets
    std::vector<DevToolsTarget> FetchTargets(uint16_t port);
    void HandleFrameNavigated(const std::string& paramsJson);
    std::mutex queueMtx_;
    std::queue<std::string> scriptQueue_;
    std::mutex pendingMtx_;
    std::thread recvThread_;
    std::atomic<bool> isConnected_{false};
};

} // namespace MDXBrowser
