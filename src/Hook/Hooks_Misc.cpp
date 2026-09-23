#include "Hooks_Misc.h"
#include "HookMacros.h"
#include "Utils/HookSupport/VehCommon.h"
#include "dllmain.h"
#include "OSTPlatform/include/Detour.h"
#include "OSTPlatform/include/Encoding.h"

#include <windows.h>
#include <shellapi.h>
#include <cwctype>

namespace {
    // ── Resolve-only functions ─────────────────────────────────────
    RESOLVE_FUNC(CUtlBufferEnsureCapacity, void*, CUtlBuffer* pCUtlBuffer, uint32 newCapacity);

    // ── VEH-captured functions (one-shot int3) ───────────────────────────────
    // On int3 hit, ctx->Rcx is stored to the named output variable.
    CAPTURE_THIS_FUNC(GetAppIDForCurrentPipe, AppId_t,      g_steamEngine,    void*);
    CAPTURE_THIS_FUNC(GetAppDataFromAppInfo,  int64,        g_pCAppInfoCache, void*, AppId_t, const char*, uint8*, int32);

    // Assumes one game at a time.  Set by SpawnProcess VEH when -onlinefix
    // is detected; cleared when a non-onlinefix game launches.
    AppId_t   g_OnlineFixRealAppId;
    std::unordered_map<AppId_t, std::string> g_GameNameCache;


    // ── SpawnProcess interception ────────────────────────────────────────────
    // CUser_SpawnProcess(pCUser, pExePath, pCommandLine, pWorkingDir,
    //                    pGameID, ...)
    // arg1=pCUser, arg2=pExePath, arg3=pCommandLine, arg4=pWorkingDir
    // arg5=pGameID (CGameID*; low 24 bits = AppId)
    static void OnSpawnProcessHit(OSTPlatform::Trap::Context& ctx, const VehCommon::Int3Site& /*site*/) {
        CGameID* pGameID = VehCommon::GetArg<CGameID*>(ctx, 5);
        AppId_t appId = static_cast<AppId_t>(pGameID->AppID(true));
        const char* cmdLine = VehCommon::GetArg<const char*>(ctx, 3);
        const char* exePath = VehCommon::GetArg<const char*>(ctx, 2);
        LOG_MISC_INFO("SpawnProcess: appid={} exe=\"{}\" cmd=\"{}\"",
                      appId, exePath ? exePath : "<null>", cmdLine ? cmdLine : "<null>");

        if (LuaConfig::HasDepot(appId) && cmdLine && strstr(cmdLine, "-onlinefix"))
        {
            g_OnlineFixRealAppId = appId;
            pGameID->SetAppID(kOnlineFixAppId);
            LOG_MISC_INFO("SpawnProcess: appid {} -> {}, cmd=\"{}\"",appId, kOnlineFixAppId, cmdLine);
        } else {
            g_OnlineFixRealAppId = 0;
        }
    }

    // ── -launchexe=<path> launch-exe override ────────────────────────────────
    // Steam copies launch options verbatim into the spawned game's command
    // line, so the -launchexe token reaches CreateProcessW. We intercept there
    // (the kernel boundary where the executable is actually decided) and:
    //   1. remove the -launchexe[=value] token from the command line
    //   2. repoint lpApplicationName at the requested executable
    // Any remaining launch args pass through untouched.

    static decltype(CreateProcessW)* g_realCreateProcessW = nullptr;
    static decltype(CreateProcessA)* g_realCreateProcessA = nullptr;
    static decltype(CreateProcessAsUserW)* g_realCreateProcessAsUserW = nullptr;
    static decltype(ShellExecuteW)* g_realShellExecuteW = nullptr;
    static decltype(ShellExecuteExW)* g_realShellExecuteExW = nullptr;

    static void LogSpawnA(const char* tag, const char* app, const char* cmd) {
        LOG_MISC_INFO("{}: app=\"{}\" cmd=\"{}\"", tag,
                      app ? app : "<null>", cmd ? cmd : "<null>");
    }
    static void LogSpawnW(const char* tag, const wchar_t* app, const wchar_t* cmd) {
        LOG_MISC_INFO("{}: app=\"{}\" cmd=\"{}\"", tag,
                      app ? OSTPlatform::Encoding::WideToUtf8(app) : "<null>",
                      cmd ? OSTPlatform::Encoding::WideToUtf8(cmd) : "<null>");
    }

    static BOOL WINAPI HkCreateProcessA(
        LPCSTR lpApp, LPSTR lpCmd,
        LPSECURITY_ATTRIBUTES lpPA, LPSECURITY_ATTRIBUTES lpTA,
        BOOL bIH, DWORD dwCF, LPVOID lpEnv, LPCSTR lpCD,
        LPSTARTUPINFOA lpSI, LPPROCESS_INFORMATION lpPI)
    {
        LogSpawnA("CreateProcessA", lpApp, lpCmd);
        return g_realCreateProcessA(lpApp, lpCmd, lpPA, lpTA, bIH, dwCF, lpEnv, lpCD, lpSI, lpPI);
    }

    static HINSTANCE WINAPI HkShellExecuteW(
        HWND hwnd, LPCWSTR lpOp, LPCWSTR lpFile, LPCWSTR lpParams, LPCWSTR lpDir, INT nShow)
    {
        std::wstring full;
        if (lpFile) full = lpFile;
        if (lpParams) { full += L" "; full += lpParams; }
        LogSpawnW("ShellExecuteW", lpFile, full.c_str());
        return g_realShellExecuteW(hwnd, lpOp, lpFile, lpParams, lpDir, nShow);
    }

    static BOOL WINAPI HkShellExecuteExW(LPSHELLEXECUTEINFOW pExecInfo)
    {
        LogSpawnW("ShellExecuteExW",
                  pExecInfo ? pExecInfo->lpFile : nullptr,
                  pExecInfo ? pExecInfo->lpParameters : nullptr);
        return g_realShellExecuteExW(pExecInfo);
    }

    // Case-insensitive wide substring search.
    static bool WStrContains(const wchar_t* hay, const wchar_t* needle) {
        if (!hay || !needle) return false;
        std::wstring h(hay);
        std::wstring n(needle);
        for (auto& c : h) c = towlower(c);
        for (auto& c : n) c = towlower(c);
        return h.find(n) != std::wstring::npos;
    }

    // Extract the -launchexe value (quoted or space-delimited) from a wide
    // command line. Returns true and fills outExe when parsed.
    static bool TryParseLaunchExeWide(const wchar_t* cmdLine, std::wstring& outExe) {
        if (!cmdLine) return false;

        std::wstring lower(cmdLine);
        for (auto& c : lower) c = towlower(c);
        size_t pos = lower.find(L"-launchexe");
        if (pos == std::wstring::npos) return false;

        const wchar_t* p = cmdLine + pos + wcslen(L"-launchexe"); // at '=' or whitespace

        while (*p == L' ' || *p == L'\t') ++p;
        if (*p == L'=') ++p;
        while (*p == L' ' || *p == L'\t') ++p;

        const wchar_t* valStart = nullptr;
        const wchar_t* valEnd   = nullptr;
        if (*p == L'"') {
            ++p; valStart = p;
            while (*p && *p != L'"') ++p;
            valEnd = p;
        } else {
            valStart = p;
            while (*p && *p != L' ' && *p != L'\t') ++p;
            valEnd = p;
        }

        if (!valStart || !valEnd || valEnd == valStart) return false;
        outExe.assign(valStart, static_cast<size_t>(valEnd - valStart));
        return true;
    }

    // Rebuild the command line with the -launchexe token removed.
    static bool StripLaunchExeWide(const wchar_t* cmdLine, std::wstring& outCmdLine) {
        if (!cmdLine) return false;

        std::wstring lower(cmdLine);
        for (auto& c : lower) c = towlower(c);
        size_t pos = lower.find(L"-launchexe");
        if (pos == std::wstring::npos) return false;

        // skip any separating space before the token (keeps spacing tidy)
        size_t end = pos + wcslen(L"-launchexe");
        if (cmdLine[end] == L'=') {
            ++end;
            if (cmdLine[end] == L'"') {
                ++end;
                while (cmdLine[end] && cmdLine[end] != L'"') ++end;
                if (cmdLine[end] == L'"') ++end;
            } else {
                while (cmdLine[end] && cmdLine[end] != L' ' && cmdLine[end] != L'\t') ++end;
            }
        } else {
            while (cmdLine[end] == L' ' || cmdLine[end] == L'\t') ++end;
            if (cmdLine[end] == L'"') {
                ++end;
                while (cmdLine[end] && cmdLine[end] != L'"') ++end;
                if (cmdLine[end] == L'"') ++end;
            } else {
                while (cmdLine[end] && cmdLine[end] != L' ' && cmdLine[end] != L'\t') ++end;
            }
        }

        outCmdLine.assign(cmdLine, pos);
        outCmdLine.append(cmdLine + end);
        return true;
    }

    // Resolve -launchexe from the wide command line. Returns false (no
    // override) when the token is absent, or true with the derived exe/cmd
    // (token stripped) when present. Caller replaces its lpApplicationName /
    // lpCommandLine with the outputs when true.
    struct LaunchExeOverride {
        bool present = false;
        std::wstring exe;
        std::wstring cmd;
    };
    static LaunchExeOverride ResolveLaunchExe(const wchar_t* lpCmd) {
        LaunchExeOverride o;
        if (!lpCmd || !WStrContains(lpCmd, L"-launchexe")) return o;
        o.present = TryParseLaunchExeWide(lpCmd, o.exe)
                 && StripLaunchExeWide(lpCmd, o.cmd);
        return o;
    }

    static BOOL WINAPI HkCreateProcessW(
        LPCWSTR lpApp, LPWSTR lpCmd,
        LPSECURITY_ATTRIBUTES lpPA, LPSECURITY_ATTRIBUTES lpTA,
        BOOL bIH, DWORD dwCF, LPVOID lpEnv, LPCWSTR lpCD,
        LPSTARTUPINFOW lpSI, LPPROCESS_INFORMATION lpPI)
    {
        LogSpawnW("CreateProcessW", lpApp, lpCmd);
        LaunchExeOverride o = ResolveLaunchExe(lpCmd);
        if (o.present) {
            LOG_MISC_INFO("CreateProcessW: -launchexe override exe=\"{}\" cmd=\"{}\"",
                          OSTPlatform::Encoding::WideToUtf8(o.exe),
                          OSTPlatform::Encoding::WideToUtf8(o.cmd));
            return g_realCreateProcessW(o.exe.c_str(), &o.cmd[0], lpPA, lpTA, bIH, dwCF,
                                        lpEnv, lpCD, lpSI, lpPI);
        }
        return g_realCreateProcessW(lpApp, lpCmd, lpPA, lpTA, bIH, dwCF, lpEnv, lpCD, lpSI, lpPI);
    }

    static BOOL WINAPI HkCreateProcessAsUserW(
        HANDLE hToken, LPCWSTR lpApp, LPWSTR lpCmd,
        LPSECURITY_ATTRIBUTES lpPA, LPSECURITY_ATTRIBUTES lpTA,
        BOOL bIH, DWORD dwCF, LPVOID lpEnv, LPCWSTR lpCD,
        LPSTARTUPINFOW lpSI, LPPROCESS_INFORMATION lpPI)
    {
        LogSpawnW("CreateProcessAsUserW", lpApp, lpCmd);
        LaunchExeOverride o = ResolveLaunchExe(lpCmd);
        if (o.present) {
            LOG_MISC_INFO("CreateProcessAsUserW: -launchexe override exe=\"{}\" cmd=\"{}\"",
                          OSTPlatform::Encoding::WideToUtf8(o.exe),
                          OSTPlatform::Encoding::WideToUtf8(o.cmd));
            return g_realCreateProcessAsUserW(hToken, o.exe.c_str(), &o.cmd[0], lpPA, lpTA,
                                              bIH, dwCF, lpEnv, lpCD, lpSI, lpPI);
        }
        return g_realCreateProcessAsUserW(hToken, lpApp, lpCmd, lpPA, lpTA,
                                          bIH, dwCF, lpEnv, lpCD, lpSI, lpPI);
    }

    // ── CUser_LegacyKeyRegistrationMethod ────────────────────────────────────
    // Third-party launcher games (Ubisoft Connect and similar) carry a
    // legacycdkeymethod / LegacyKeyRegistrationMethod config key. Steam reads
    // it here and, when nonzero, drives the game through the legacy CD-key
    // pipeline (GettingLegacyKey LaunchApp task), which fetches a key from the
    // server and fails with k_EResultAccessDenied (15) for unlocked copies —
    // aborting the launch BEFORE CUser_SpawnProcess is ever reached. Forcing 0
    // here short-circuits the whole pipeline (sub_1389D2F20 returns early) so
    // the game falls through to the normal SpawnProcess path instead.
    //
    // Resolved from the ManifestDexCore embedded supplement patterns (not the
    // shared steam-monitor repo) — see src/pattern/steamclient.supplement.toml.
    HOOK_FUNC(LegacyKeyRegistrationMethod, __int64, void* pThis)
    {
        __int64 r = oLegacyKeyRegistrationMethod(pThis);
        if (r != 0) {
            LOG_MISC_INFO("LegacyKeyRegistrationMethod: forcing 0 (was {}) to bypass legacy CD-key gate", static_cast<unsigned int>(r));
            return 0;
        }
        return r;
    }

    // ── SteamController_OptedInMask ──────────────────────────────────────────
    // Called by CUser_BuildSpawnEnvBlock with pGameID's appid to
    // compute EnableConfiguratorSupport and the SDL_* env vars.
    // With 480 the spawned game inherits Spacewar's Steam Input
    // opt-in and gameoverlayrenderer hijacks the XInput stream.
    HOOK_FUNC(OptedInMask, int64,void* pThis, AppId_t appId)
    {
        if (appId == kOnlineFixAppId && g_OnlineFixRealAppId) {
            LOG_MISC_INFO("OptedInMask: appid {} -> {}",appId, g_OnlineFixRealAppId);
            appId = g_OnlineFixRealAppId;
        }
        return oOptedInMask(pThis, appId);
    }

    // ── CUser_BuildSpawnEnvBlock ─────────────────────────────────────────────
    // pOverlayCGameID drives SteamOverlayGameId, which the in-game
    // overlay reads for screenshot tags, community URLs, and asset
    // selection.  pCGameID drives SteamGameId / SteamAppId; leave it
    // at 480 so the in-game ownership bypass holds.
    HOOK_FUNC(BuildSpawnEnvBlock, int64,
              void* pThis, CGameID* pCGameID, void* a3, void* env,
              CGameID* pOverlayCGameID, void* a6, int a7,
              void* a8, void* a9, unsigned int a10, char a11)
    {
        if (g_OnlineFixRealAppId && pOverlayCGameID
            && pOverlayCGameID->AppID(true) == kOnlineFixAppId) 
        {
            LOG_MISC_INFO("BuildSpawnEnvBlock: SetAppID in OverlayCGameID {} -> {}",
                          pOverlayCGameID->AppID(true), g_OnlineFixRealAppId);
            pOverlayCGameID->SetAppID(g_OnlineFixRealAppId);
        }
        return oBuildSpawnEnvBlock(pThis, pCGameID, a3, env,
                                    pOverlayCGameID, a6, a7,
                                    a8, a9, a10, a11);
    }

    // CAppInfoCache::GetOrAddAppData
    // The injected package keeps Lua-provided ids in PackageInfo::AppIdVec.
    // Some of those ids can actually be depot ids, but we cannot trust the
    // Lua config to classify app ids and depot ids for us. In offline mode,
    // depot ids usually have only placeholder appinfo data. That blocks
    // CClientAppManager_ProcessPendingLicenseUpdates, because it waits for
    // every AppIdVec entry to have resolved appinfo unless the entry has been
    // marked as a known-unknown id by the PICS path. For injected ids that
    // still have placeholder appinfo, set skip_flag so Steam treats them like
    // PICS unknown_appids instead of keeping the license update pending.
    HOOK_FUNC(GetOrAddAppData,CAppData*,void* pCache, AppId_t appId,bool bCreate)
    {
        CAppData* pData = oGetOrAddAppData(pCache, appId, bCreate);
        // LOG_MISC_TRACE("GetOrAddAppData: appId={} bCreate={} -> pData={}", appId, bCreate, pData ? pData->DebugString() : "null");
        // TODO: find a more robust way
        if (LuaConfig::HasDepot(appId, false) && pData && !bCreate && pData->IsUnresolvedAppInfo()) {
            LOG_MISC_DEBUG("GetOrAddAppData: Marking appId {} as skip_flag=true to bypass license update blocking", appId);
            pData->bSkipFlag = true;
        }
        return pData;
    }
}

namespace Hooks_Misc {
    void Install() {
        RESOLVE_C(CUtlBufferEnsureCapacity);

        ARM_CAPTURE_C(GetAppIDForCurrentPipe);
        ARM_CAPTURE_C(GetAppDataFromAppInfo);

        ARM_INT3_C(SpawnProcess, true, &OnSpawnProcessHit, nullptr);

        HOOK_BEGIN();
        INSTALL_HOOK_C(BuildSpawnEnvBlock);
        INSTALL_HOOK_C(OptedInMask);
        INSTALL_HOOK_C(LegacyKeyRegistrationMethod);
        // INSTALL_HOOK_C(GetOrAddAppData);
        HOOK_END();

        // -launchexe override: detour spawn APIs Steam may use for game launch.
        {
            HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
            HMODULE sh  = GetModuleHandleW(L"shell32.dll");
            HMODULE av  = GetModuleHandleW(L"advapi32.dll");

            OSTPlatform::Detour::BeginTransaction();

            if (k32) {
                auto realW = reinterpret_cast<decltype(CreateProcessW)*>(
                    GetProcAddress(k32, "CreateProcessW"));
                if (realW) {
                    g_realCreateProcessW = realW;
                    OSTPlatform::Detour::Attach(
                        reinterpret_cast<void**>(&g_realCreateProcessW),
                        reinterpret_cast<void*>(&HkCreateProcessW));
                    LOG_MISC_INFO("CreateProcessW hook installed (kernel32)");
                } else {
                    LOG_MISC_WARN("CreateProcessW: GetProcAddress failed");
                }

                auto realA = reinterpret_cast<decltype(CreateProcessA)*>(
                    GetProcAddress(k32, "CreateProcessA"));
                if (realA) {
                    g_realCreateProcessA = realA;
                    OSTPlatform::Detour::Attach(
                        reinterpret_cast<void**>(&g_realCreateProcessA),
                        reinterpret_cast<void*>(&HkCreateProcessA));
                    LOG_MISC_INFO("CreateProcessA hook installed (kernel32)");
                } else {
                    LOG_MISC_WARN("CreateProcessA: GetProcAddress failed");
                }
            } else {
                LOG_MISC_WARN("Spawning hooks: GetModuleHandleW kernel32.dll failed");
            }

            if (av) {
                auto realAsUser = reinterpret_cast<decltype(CreateProcessAsUserW)*>(
                    GetProcAddress(av, "CreateProcessAsUserW"));
                if (realAsUser) {
                    g_realCreateProcessAsUserW = realAsUser;
                    OSTPlatform::Detour::Attach(
                        reinterpret_cast<void**>(&g_realCreateProcessAsUserW),
                        reinterpret_cast<void*>(&HkCreateProcessAsUserW));
                    LOG_MISC_INFO("CreateProcessAsUserW hook installed (advapi32)");
                } else {
                    LOG_MISC_WARN("CreateProcessAsUserW: GetProcAddress failed");
                }
            } else {
                LOG_MISC_WARN("Spawning hooks: GetModuleHandleW advapi32.dll failed");
            }

            if (sh) {
                auto realSE = reinterpret_cast<decltype(ShellExecuteW)*>(
                    GetProcAddress(sh, "ShellExecuteW"));
                if (realSE) {
                    g_realShellExecuteW = realSE;
                    OSTPlatform::Detour::Attach(
                        reinterpret_cast<void**>(&g_realShellExecuteW),
                        reinterpret_cast<void*>(&HkShellExecuteW));
                    LOG_MISC_INFO("ShellExecuteW hook installed (shell32)");
                }

                auto realSEx = reinterpret_cast<decltype(ShellExecuteExW)*>(
                    GetProcAddress(sh, "ShellExecuteExW"));
                if (realSEx) {
                    g_realShellExecuteExW = realSEx;
                    OSTPlatform::Detour::Attach(
                        reinterpret_cast<void**>(&g_realShellExecuteExW),
                        reinterpret_cast<void*>(&HkShellExecuteExW));
                    LOG_MISC_INFO("ShellExecuteExW hook installed (shell32)");
                }
            } else {
                LOG_MISC_WARN("Spawning hooks: GetModuleHandleW shell32.dll failed");
            }

            OSTPlatform::Detour::CommitTransaction();
        }
    }

    void Uninstall() {
        UNHOOK_BEGIN();
        UNINSTALL_HOOK(BuildSpawnEnvBlock);
        UNINSTALL_HOOK(OptedInMask);
        UNINSTALL_HOOK(LegacyKeyRegistrationMethod);
        // UNINSTALL_HOOK(GetOrAddAppData);
        UNHOOK_END();

        OSTPlatform::Detour::BeginTransaction();
        if (g_realCreateProcessW) {
            OSTPlatform::Detour::Detach(
                reinterpret_cast<void**>(&g_realCreateProcessW),
                reinterpret_cast<void*>(&HkCreateProcessW));
            g_realCreateProcessW = nullptr;
        }
        if (g_realCreateProcessA) {
            OSTPlatform::Detour::Detach(
                reinterpret_cast<void**>(&g_realCreateProcessA),
                reinterpret_cast<void*>(&HkCreateProcessA));
            g_realCreateProcessA = nullptr;
        }
        if (g_realCreateProcessAsUserW) {
            OSTPlatform::Detour::Detach(
                reinterpret_cast<void**>(&g_realCreateProcessAsUserW),
                reinterpret_cast<void*>(&HkCreateProcessAsUserW));
            g_realCreateProcessAsUserW = nullptr;
        }
        if (g_realShellExecuteW) {
            OSTPlatform::Detour::Detach(
                reinterpret_cast<void**>(&g_realShellExecuteW),
                reinterpret_cast<void*>(&HkShellExecuteW));
            g_realShellExecuteW = nullptr;
        }
        if (g_realShellExecuteExW) {
            OSTPlatform::Detour::Detach(
                reinterpret_cast<void**>(&g_realShellExecuteExW),
                reinterpret_cast<void*>(&HkShellExecuteExW));
            g_realShellExecuteExW = nullptr;
        }
        OSTPlatform::Detour::CommitTransaction();
    }

    AppId_t GetAppIDForCurrentPipeWrap() {
        if (!CAPTURE_READY(GetAppIDForCurrentPipe)) {
            LOG_MISC_WARN("GetAppIDForCurrentPipeWrap called before capture — returning 0");
            return 0;
        }
        auto appid = oGetAppIDForCurrentPipe(g_steamEngine);
        if (!appid) {
            LOG_MISC_TRACE("GetAppIDForCurrentPipeWrap: AppId=0(Not GamePipe)");
        } else {
            LOG_MISC_TRACE("GetAppIDForCurrentPipeWrap: AppId={}", appid);
        }
        return appid;
    }

    
    AppId_t ResolveAppId() {
        if (g_OnlineFixRealAppId) return g_OnlineFixRealAppId;
        return GetAppIDForCurrentPipeWrap();
    }
    
    bool EnsureBufferCapacity(CUtlBuffer* pWrite, uint32 newCapacity,bool updatePut)
    {
        if (oCUtlBufferEnsureCapacity) {
            LOG_MISC_DEBUG("Before ensuring CUtlBuffer capacity: {}", pWrite->DebugString());
            oCUtlBufferEnsureCapacity(pWrite, newCapacity);
            LOG_MISC_DEBUG("After ensuring CUtlBuffer capacity: {}", pWrite->DebugString());
            if(updatePut) pWrite->m_Put = newCapacity;
            return true;
        }
        LOG_MISC_WARN("EnsureBufferCapacity: oCUtlBufferEnsureCapacity not resolved");
        return false;
    }

    // ── Game name ────────────────────────────────────────────────
    std::string GetGameNameByAppID(AppId_t appId)
    {
        auto it = g_GameNameCache.find(appId);
        if (it != g_GameNameCache.end()) return it->second;

        std::string name;

        if (CAPTURE_READY(GetAppDataFromAppInfo)) {
            char buf[256] = {};
            // "common/name" triggers auto-localization: the function detects
            // prefix "common" (keyType=2) + key "name", then tries
            // "name_localized/<current_lang>" before falling back to "name".
            // Returns strlen+1 on success, -1 on failure.
            int64 len = oGetAppDataFromAppInfo(g_pCAppInfoCache, appId, "common/name",
                reinterpret_cast<uint8*>(buf), sizeof(buf));
            if (len > 1)
                name.assign(buf, static_cast<size_t>(len - 1));
        }

        LOG_MISC_DEBUG("GetGameNameByAppID({}): {}", appId, name);
        g_GameNameCache[appId] = name;
        return name;
    }

}
