// ─────────────────────────────────────────────────────────────────
//  Module logger registry.
//  This file is included multiple times with different definitions
//  of MDX_MOD(varName, fileName).
//
//  Usage:
//    #define MDX_MOD(v, f) ...   // declare logger
//    #include "mdx_log_modules.h"
//    #undef MDX_MOD
//
//  Adding a new module:
//    1. Add  MDX_MOD(NewMod, "newmod")  below.
//    2. Run CMake configure (LOG_NEWMOD_* macros are auto-generated).
// ─────────────────────────────────────────────────────────────────

MDX_MOD(IPC,           "ipc")
MDX_MOD(NetPacket,     "netpacket")
MDX_MOD(Manifest,      "manifest")
MDX_MOD(KeyValue,      "keyvalue")
MDX_MOD(DecryptionKey, "decryptionkey")
MDX_MOD(Misc,          "misc")
MDX_MOD(WinHttp,       "winhttp")
MDX_MOD(Achievement,   "achievement")
MDX_MOD(Pics,          "pics")
MDX_MOD(OnlineFix,     "onlinefix")
MDX_MOD(RichPresence,  "richpresence")
MDX_MOD(Package,       "package")
MDX_MOD(SteamUI,       "steamui")
MDX_MOD(Pipe,          "pipe")
MDX_MOD(Platform,      "platform")
