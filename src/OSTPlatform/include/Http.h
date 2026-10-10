#pragma once

#include <cstdint>
#include <string>

namespace OSTPlatform::Http {

    struct Result {
        std::string body;
        uint32_t status = 0;
        // True once WinHTTP produced a response; callers must still check status for 2xx.
        bool ok = false;
        // Raw response headers (CRLF-separated, status line included). Empty
        // when no response was received. Callers needing e.g. x-manifest-cdn
        // or Retry-After parse this themselves.
        std::string headers;
    };

    Result Execute(const wchar_t* method,
                   const char* url,
                   const void* reqBody = nullptr,
                   uint32_t reqBodyLen = 0,
                   const wchar_t* headers = nullptr,
                   uint32_t timeoutResolve = 5000,
                   uint32_t timeoutConnect = 5000,
                   uint32_t timeoutSend = 10000,
                   uint32_t timeoutRecv = 10000);

} // namespace OSTPlatform::Http
