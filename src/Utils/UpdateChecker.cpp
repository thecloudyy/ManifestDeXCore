#include "UpdateChecker.h"
#include "dllmain.h"
#include "OSTPlatform/include/Hash.h"
#include "Utils/Logging/Log.h"
#include "Utils/SteamMetadata/PatternLoader.h"
#include "OSTPlatform/include/Http.h"

#include <atomic>
#include <cstring>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <windows.h>
#include <detours.h>
#include <shellapi.h>

#pragma comment(lib, "shell32.lib")

// ---------------------------------------------------------------------------
// Compile-time API URL selection.
// Define MANIFESTDEXCORE_UPDATE_URL_OVERRIDE to use a custom endpoint.
// In debug builds we target localhost; release builds use the production API.
// ---------------------------------------------------------------------------
#ifndef MANIFESTDEXCORE_UPDATE_URL_OVERRIDE
#  ifdef NDEBUG
#    define MANIFESTDEXCORE_HASH_API_URL \
         "https://api.manifestdex.com/api/public/corefiles/hashes"
#  else
#    define MANIFESTDEXCORE_HASH_API_URL \
         "http://localhost:5065/api/public/corefiles/hashes"
#  endif
#endif

// The website to open when the user clicks "Open Website".
static constexpr const wchar_t* kUpdateUrl = L"https://manifestdex.com/docs";

namespace UpdateChecker {

namespace {

// ---------------------------------------------------------------------------
// Minimal JSON string-value extractor.
// Looks for  "key": "value"  in a flat JSON object body.
// Returns an empty string if the key is absent or the value is not a string.
// ---------------------------------------------------------------------------
static std::string ExtractJsonStringValue(std::string_view json,
                                          std::string_view key)
{
    // Build search token:  "key":
    std::string token;
    token.reserve(key.size() + 3);
    token += '"';
    token += key;
    token += '"';

    auto keyPos = json.find(token);
    if (keyPos == std::string_view::npos)
        return {};

    // Skip past the key and any whitespace / colon.
    auto pos = keyPos + token.size();
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' ||
                                  json[pos] == '\r' || json[pos] == '\n'))
        ++pos;
    if (pos >= json.size() || json[pos] != ':')
        return {};
    ++pos; // skip ':'

    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' ||
                                  json[pos] == '\r' || json[pos] == '\n'))
        ++pos;
    if (pos >= json.size() || json[pos] != '"')
        return {};
    ++pos; // skip opening '"'

    // Read until closing '"' (no escape handling — hashes are hex only).
    auto end = json.find('"', pos);
    if (end == std::string_view::npos)
        return {};

    return std::string(json.substr(pos, end - pos));
}

// ---------------------------------------------------------------------------
// SteamUI QueryBox bridge.
//
// Function addresses resolve through PatternLoader::FindPattern, sourced from
// the embedded src/pattern/steamui.supplement.toml supplement (see
// PatternLoader::LoadSupplement in dllmain.cpp), not a local hardcoded table.
// ---------------------------------------------------------------------------
using QueryBoxCtor_t = void* (__fastcall*)(void* self, const char* title,
                                           const char* message, int unknown,
                                           bool showCancel, int initVtables);
using QueryBoxSetButtonText_t = void (__fastcall*)(void* self, const char* text);
using MessageBoxShowModal_t = void (__fastcall*)(void* self);
using SteamUiAlloc_t = void* (__fastcall*)(size_t size);
using QueryBoxOnCommand_t = void (__fastcall*)(void* self, const char* command);

static std::atomic<void*> g_updateQueryBox = nullptr;
static std::atomic_bool g_updateDialogPending = false;
static QueryBoxOnCommand_t g_queryBoxOnCommand = nullptr;
static std::mutex g_queryBoxHookMutex;
static bool g_queryBoxHookInstalled = false;

static void* ResolveSteamUiPattern(const char* name)
{
    if (!ui_hModule)
        return nullptr;

    return PatternLoader::FindPattern(ui_hModule, name);
}

static void __fastcall HookedQueryBoxOnCommand(void* self, const char* command)
{
    const bool isUpdateDialog =
        (self == g_updateQueryBox.load(std::memory_order_acquire));

    if (isUpdateDialog && command && _stricmp(command, "OK") == 0) {
        std::thread([]() {
            ShellExecuteW(nullptr, L"open", kUpdateUrl, nullptr, nullptr, SW_SHOWNORMAL);
        }).detach();
    }

    g_queryBoxOnCommand(self, command);

    if (isUpdateDialog &&
        command &&
        (_stricmp(command, "OK") == 0 ||
         _stricmp(command, "Cancel") == 0 ||
         _stricmp(command, "Close") == 0)) {
        void* expected = self;
        g_updateQueryBox.compare_exchange_strong(expected, nullptr,
                                                 std::memory_order_acq_rel);
    }
}

static bool EnsureQueryBoxCommandHook(void* queryBox)
{
    std::lock_guard<std::mutex> lock(g_queryBoxHookMutex);
    if (g_queryBoxHookInstalled)
        return true;

    if (!queryBox)
        return false;

    auto** vtable = *reinterpret_cast<void***>(queryBox);
    constexpr size_t kOnCommandVtableIndex = 40;
    g_queryBoxOnCommand =
        reinterpret_cast<QueryBoxOnCommand_t>(vtable[kOnCommandVtableIndex]);
    if (!g_queryBoxOnCommand)
        return false;

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(reinterpret_cast<PVOID*>(&g_queryBoxOnCommand),
                 reinterpret_cast<PVOID>(HookedQueryBoxOnCommand));
    const LONG result = DetourTransactionCommit();
    if (result != NO_ERROR) {
        LOG_WARN("UpdateChecker: failed to hook QueryBox OnCommand (err={})", result);
        g_queryBoxOnCommand = nullptr;
        return false;
    }

    g_queryBoxHookInstalled = true;
    return true;
}

static void ShowUpdateDialog()
{
    auto alloc = reinterpret_cast<SteamUiAlloc_t>(
        ResolveSteamUiPattern("vgui_Alloc"));
    auto ctor = reinterpret_cast<QueryBoxCtor_t>(
        ResolveSteamUiPattern("vgui_QueryBox_ctor"));
    auto setOkText = reinterpret_cast<QueryBoxSetButtonText_t>(
        ResolveSteamUiPattern("vgui_QueryBox_SetOKButtonText"));
    auto setCancelText = reinterpret_cast<QueryBoxSetButtonText_t>(
        ResolveSteamUiPattern("vgui_QueryBox_SetCancelButtonText"));
    auto showModal = reinterpret_cast<MessageBoxShowModal_t>(
        ResolveSteamUiPattern("vgui_MessageBox_ShowModal"));

    if (!alloc || !ctor || !setOkText || !setCancelText || !showModal) {
        LOG_WARN("UpdateChecker: Steam QueryBox functions missing; update dialog skipped");
        return;
    }

    void* dialog = alloc(0x350);
    if (!dialog) {
        LOG_WARN("UpdateChecker: Steam QueryBox allocation failed");
        return;
    }

    ctor(dialog,
         "ManifestDex",
         "A new version of manifestdexcore is available.\n"
         "Download and install the latest update from the website or ManifestDeX.Desktop app to keep everything working correctly.",
         0,
         true,
         1);

    setOkText(dialog, "Open Website");
    setCancelText(dialog, "Skip");

    if (!EnsureQueryBoxCommandHook(dialog)) {
        LOG_WARN("UpdateChecker: QueryBox command hook unavailable; OK button will only close the dialog");
    }

    g_updateQueryBox.store(dialog, std::memory_order_release);

    std::thread([]() {
        for (int i = 0; i < 20; ++i) {
            Sleep(50);
            HWND hwnd = FindWindowW(nullptr, L"ManifestDex");
            if (hwnd) {
                HMONITOR hMonitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTOPRIMARY);
                MONITORINFO mi = { sizeof(mi) };
                if (GetMonitorInfoW(hMonitor, &mi)) {
                    RECT rc;
                    GetWindowRect(hwnd, &rc);
                    int w = rc.right - rc.left;
                    int h = rc.bottom - rc.top;
                    int x = mi.rcWork.left + (mi.rcWork.right - mi.rcWork.left - w) / 2;
                    int y = mi.rcWork.top + (mi.rcWork.bottom - mi.rcWork.top - h) / 2;
                    SetWindowPos(hwnd, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
                }
                break;
            }
        }
    }).detach();

    showModal(dialog);
}

} // namespace

void PumpSteamUi()
{
    if (!g_updateDialogPending.exchange(false, std::memory_order_acq_rel))
        return;

    if (g_updateQueryBox.load(std::memory_order_acquire)) {
        LOG_DEBUG("UpdateChecker: update QueryBox is already active");
        return;
    }

    LOG_INFO("UpdateChecker: showing Steam QueryBox on SteamUI frame thread");
    ShowUpdateDialog();
}

// ---------------------------------------------------------------------------
void Check(const char* steamInstallPath)
{
    constexpr const char* kApiUrl = MANIFESTDEXCORE_HASH_API_URL;

    // -----------------------------------------------------------------------
    // 1. Fetch the hash list from the API (short timeouts — best-effort only).
    // -----------------------------------------------------------------------
    LOG_INFO("UpdateChecker: fetching hashes from {}", kApiUrl);

    OSTPlatform::Http::Result http = OSTPlatform::Http::Execute(
        L"GET", kApiUrl,
        nullptr, 0,   // no request body
        nullptr,      // no extra headers
        5000,         // resolve timeout  5 s
        5000,         // connect timeout  5 s
        8000,         // send timeout     8 s
        8000          // recv timeout     8 s
    );

    if (!http.ok || http.status != 200) {
        LOG_WARN("UpdateChecker: request failed (ok={} status={}) — skipping update check",
                 http.ok, http.status);
        return;
    }

    const std::string_view body(http.body);

    // Quick sanity check: the response must look like a success payload.
    if (body.find("\"success\"") == std::string_view::npos ||
        body.find("\"hashes\"")  == std::string_view::npos) {
        LOG_WARN("UpdateChecker: unexpected response body — skipping update check");
        return;
    }

    // -----------------------------------------------------------------------
    // 2. Extract expected hashes for the three core DLLs.
    // -----------------------------------------------------------------------
    const std::string expectedDwmapi        = ExtractJsonStringValue(body, "dwmapi.dll");
    const std::string expectedCore          = ExtractJsonStringValue(body, "manifestdexcore.dll");
    const std::string expectedXinput        = ExtractJsonStringValue(body, "xinput1_4.dll");

    LOG_INFO("UpdateChecker: remote hashes — dwmapi={} core={} xinput={}",
             expectedDwmapi, expectedCore, expectedXinput);

    // -----------------------------------------------------------------------
    // 3. Compute SHA-256 of each local DLL and compare.
    // -----------------------------------------------------------------------
    char dwmapiPath[MAX_PATH], corePath[MAX_PATH], xinputPath[MAX_PATH];
    sprintf_s(dwmapiPath,  MAX_PATH, "%s\\dwmapi.dll",           steamInstallPath);
    sprintf_s(corePath,    MAX_PATH, "%s\\manifestdexcore.dll",  steamInstallPath);
    sprintf_s(xinputPath,  MAX_PATH, "%s\\xinput1_4.dll",        steamInstallPath);

    struct Entry {
        const char* name;
        const char* path;
        const std::string& expected;
    };

    const Entry entries[] = {
        { "dwmapi.dll",          dwmapiPath,  expectedDwmapi  },
        { "manifestdexcore.dll", corePath,    expectedCore    },
        { "xinput1_4.dll",       xinputPath,  expectedXinput  },
    };

    bool anyMismatch = false;

    for (const auto& e : entries) {
        if (e.expected.empty()) {
            // Hash not present in the API response — skip this file.
            LOG_WARN("UpdateChecker: no expected hash for {} in API response", e.name);
            continue;
        }

        const std::string actual = OSTPlatform::Hash::Sha256OfFile(e.path);
        if (actual.empty()) {
            LOG_WARN("UpdateChecker: could not hash local file {}", e.path);
            continue;
        }

        if (actual != e.expected) {
            LOG_WARN("UpdateChecker: hash MISMATCH for {} — local={} remote={}",
                     e.name, actual, e.expected);
            anyMismatch = true;
        } else {
            LOG_INFO("UpdateChecker: {} OK", e.name);
        }
    }

    // -----------------------------------------------------------------------
    // 4. Notify the user if any file is out of date.
    //    Run the dialog on a detached thread so Steam's message pump is not
    //    blocked — consistent with SteamDiagnostics::ShowWarning.
    // -----------------------------------------------------------------------
    if (anyMismatch) {
        LOG_WARN("UpdateChecker: update available - queueing Steam QueryBox");
        g_updateDialogPending.store(true, std::memory_order_release);
    } else {
        LOG_INFO("UpdateChecker: all files are up to date");
    }
}

} // namespace UpdateChecker
