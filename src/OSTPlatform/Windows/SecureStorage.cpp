#include "include/SecureStorage.h"

#include "include/Log.h"

#include <windows.h>
#include <dpapi.h>

#include <cstdint>
#include <vector>

#pragma comment(lib, "Crypt32.lib")

namespace OSTPlatform::SecureStorage {

std::optional<std::vector<uint8_t>> DecryptCurrentUser(const uint8_t* data, size_t len) {
    if (!data || len == 0) {
        OSTP_LOG_WARN("SecureStorage: DecryptCurrentUser called with empty input");
        return std::nullopt;
    }

    DATA_BLOB in{};
    in.pbData = const_cast<BYTE*>(data);
    in.cbData = static_cast<DWORD>(len);

    DATA_BLOB out{};

    // No optional entropy: matches ManifestDeX.Desktop's
    // ProtectedData.Protect(bytes, null, CurrentUser).
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        const DWORD err = GetLastError();
        OSTP_LOG_WARN("SecureStorage: CryptUnprotectData failed (error={})", err);
        return std::nullopt;
    }

    std::vector<uint8_t> result(out.pbData, out.pbData + out.cbData);

    if (out.pbData) {
        LocalFree(out.pbData);
    }

    return result;
}

} // namespace OSTPlatform::SecureStorage
