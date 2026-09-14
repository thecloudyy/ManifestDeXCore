#pragma once

#include "OSTPlatform/include/DynamicLibrary.h"

#include <string>
#include <string_view>

namespace PatternLoader {

    // Load metadata before installing hooks for a module.
    bool Load(OSTPlatform::DynamicLibrary::ModuleHandle module, const std::string& dllPath, const std::string& component);

    // Merge ManifestDexCore-specific patterns (kept out of the shared
    // steam-monitor repo) into a module's existing pattern map. These entries
    // take no priority over remote entries — they simply become available to
    // FindPattern alongside them. Same TOML format: [0xFNV1a] name/rva/sig.
    void LoadSupplement(OSTPlatform::DynamicLibrary::ModuleHandle module, std::string_view body);

    // Resolve by RVA first, then fall back to signature scanning.
    void* FindPattern(OSTPlatform::DynamicLibrary::ModuleHandle module, const char* funcName);

    // Report unresolved functions after all hooks have been installed.
    void ReportMissingFunctions();

} // namespace PatternLoader
