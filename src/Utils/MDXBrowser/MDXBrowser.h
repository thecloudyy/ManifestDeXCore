#pragma once

// MDXBrowser — "Add with Element" button injection into Steam store pages.
//
// Optional background module (mirrors CloudRedirectHost pattern):
//   - Initialize(steamInstallPath)  — enable CEF remote debug, connect to DevTools,
//                                     inject button JS into store pages.
//   - Shutdown()                    — close WS, clean up.
//   - IsActive()                    — true when initialized and DevTools session alive.
//   - SetLastInjectedScript()       — called after successful injection for nav re-inject.
//
// The module runs on a dedicated worker thread (created by Initialize). It:
//   1. Writes .cef-enable-remote-debugging to Steam root.
//   2. Discovers steamwebhelper's remote-debugging port (default 8080).
//   3. Connects via CDP WebSocket to the store page target.
//   4. Injects JavaScript that adds "Add with Element" button to the purchase area.
//   5. When clicked, the button posts a message to the native side via a custom
//      scheme handler (implemented by the DevTools client pumping).
//   6. Native handler installs lua + manifests straight from the configured
//      built-in API (ElementGui settings -> Built-In Button Mode: "Hubcap"
//      by default, or "Ryuu"; same sources/endpoints as the Element app),
//      writing {appId}.lua to <Steam>/config/stplug-in/ and *.manifest to
//      <Steam>/depotcache/ and <Steam>/config/depotcache/, then also runs the
//      generate-lua/download-lua flow for decryption keys / custom picks.

#include <atomic>
#include <functional>
#include <optional>
#include <string>
#include <thread>

namespace MDXBrowser {

    // Called once from the DLL init worker thread (after Steam hooks are installed).
    // steamInstallPath is the Steam root directory (e.g. C:\Program Files (x86)\Steam).
    // Returns immediately; actual work runs on a background thread.
    void Initialize(const char* steamInstallPath);

    // Called from DLL_PROCESS_DETACH to tear down.
    void Shutdown();

    // True once Initialize() succeeded and the DevTools session is active.
    bool IsActive();

    // The worker thread will call this when a store app page navigation is detected.
    // Return the JavaScript to inject (or empty to skip).
    using ScriptProvider = std::function<std::string(uint32_t appId, const std::string& detailsJson)>;

    // Set a custom script provider (for testing). Default builds the production script.
    void SetScriptProvider(ScriptProvider provider);

    // Internal: called by DevToolsClient when navigation happens.
    // The module will re-inject the last script if the new URL is a store app page.
    void OnPageNavigation(const std::string& newUrl);

    // Extract appId from a store URL like "https://store.steampowered.com/app/730/..."
    std::optional<uint32_t> ExtractAppIdFromUrl(const std::string& url);

    // Cancellation flag for the ad-link wait loop.
    // Set to true by DevToolsClient when __mdx_cancel_ad is received from JS.
    // Reset to false at the start of each ad-wait. Not part of the public API
    // but declared here so DevToolsClient.cpp can reference it without a
    // separate internal header.
    extern std::atomic<bool> g_adCancelled;

} // namespace MDXBrowser