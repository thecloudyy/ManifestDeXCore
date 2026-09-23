#pragma once

// ManifestDexCore supplemental patterns, embedded into the DLL at build time.
// Defined in the CMake-generated translation unit (SupplementPatterns.cpp).

namespace PatternSupplement {
    extern const char* Steamclient;   // steamclient64.dll supplemental TOML
    extern const char* Steamui;       // steamui.dll supplemental TOML
} // namespace PatternSupplement