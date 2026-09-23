#pragma once

// OS-agnostic interface to the platform's "current user" secret store.
//
// On Windows this is backed by DPAPI (CryptProtectData / CryptUnprotectData
// with DataProtectionScope.CurrentUser and no additional entropy), matching
// the encryption used by ManifestDeX.Desktop's TokenStorageService when it
// persists %LocalAppData%\ManifestDeX\auth.dat.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace OSTPlatform::SecureStorage {

    // Decrypts a blob previously protected for the current user.
    // Returns std::nullopt on any failure (wrong scope, corrupt blob, OS error).
    // The matching protect call used no extra entropy.
    std::optional<std::vector<uint8_t>> DecryptCurrentUser(const uint8_t* data, size_t len);

} // namespace OSTPlatform::SecureStorage
