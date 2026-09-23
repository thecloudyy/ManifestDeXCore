#include "include/Http.h"

#include "include/Encoding.h"
#include "include/Log.h"
#include "include/Numbers.h"

#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <bcrypt.h>

#include <chrono>
#include <cwctype>
#include <format>
#include <string>
#include <vector>

namespace OSTPlatform::Http {
namespace {

// ── certificate pinning ──────────────────────────────────────────
//
// Pins the backend API to a fixed set of SPKI SHA-256 digests (the same
// "sha256/<base64>" scheme used by HPKP / mobile TrustKit configs). Any
// certificate in the presented chain — leaf, intermediate, or root — that
// matches one of these pins is accepted, so the pin set doubles as a
// rotation-safe backup list.
constexpr std::wstring_view kPinnedHost = L"api.manifestdex.com";
constexpr const char* kPinnedSpkiSha256[] = {
    "kIdp6NNEd8wsugYyyIYFsi1ylMCED3hZbSR8ZFsa/A4=",
    "mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c=",
    "K87oWBWM9UZfyddvDfoxL+8lpNyoUB2ptGtn0fv6G2Q=",
};

bool HostEqualsIgnoreCase(std::wstring_view a, std::wstring_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::towlower(static_cast<wint_t>(a[i])) != std::towlower(static_cast<wint_t>(b[i])))
            return false;
    }
    return true;
}

// Computes SHA-256 over the DER-encoded SubjectPublicKeyInfo of `cert` and
// checks it against the pinned set.
bool CertSpkiMatchesPin(PCCERT_CONTEXT cert) {
    if (!cert || !cert->pCertInfo) return false;

    CERT_PUBLIC_KEY_INFO& spki = cert->pCertInfo->SubjectPublicKeyInfo;
    DWORD derLen = 0;
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, &spki, 0, nullptr, nullptr, &derLen))
        return false;

    std::vector<uint8_t> der(derLen);
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, &spki, 0, nullptr, der.data(), &derLen))
        return false;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        return false;
    uint8_t hash[32];
    const NTSTATUS hashStatus = BCryptHash(hAlg, nullptr, 0, der.data(), derLen, hash, sizeof(hash));
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (!BCRYPT_SUCCESS(hashStatus))
        return false;

    char b64[128];
    DWORD b64Len = sizeof(b64);
    if (!CryptBinaryToStringA(hash, sizeof(hash), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64, &b64Len))
        return false;
    const std::string_view digest(b64, b64Len);

    for (const char* pin : kPinnedSpkiSha256) {
        if (digest == pin) return true;
    }
    return false;
}

// Builds the certificate chain presented on `hRequest` and checks every
// element (leaf through root) against the pinned SPKI set. Called only for
// hosts in the pinned set, after the TLS handshake has completed.
bool VerifyPinnedCertificate(HINTERNET hRequest, const char* url) {
    PCCERT_CONTEXT pServerCert = nullptr;
    DWORD size = sizeof(pServerCert);
    if (!WinHttpQueryOption(hRequest, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &pServerCert, &size) || !pServerCert) {
        OSTP_LOG_WARN("{} - WinHttpQueryOption(SERVER_CERT_CONTEXT) failed (error={})", url ? url : "", GetLastError());
        return false;
    }

    bool matched = false;
    CERT_CHAIN_PARA chainPara = {};
    chainPara.cbSize = sizeof(chainPara);
    PCCERT_CHAIN_CONTEXT pChain = nullptr;

    if (CertGetCertificateChain(nullptr, pServerCert, nullptr, pServerCert->hCertStore,
                                 &chainPara, 0, nullptr, &pChain) && pChain && pChain->cChain > 0) {
        const CERT_SIMPLE_CHAIN* simple = pChain->rgpChain[0];
        for (DWORD i = 0; i < simple->cElement && !matched; ++i) {
            matched = CertSpkiMatchesPin(simple->rgpElement[i]->pCertContext);
        }
    } else {
        // Chain building failed (offline root store, etc.) — fall back to
        // checking the leaf certificate alone rather than failing open.
        OSTP_LOG_WARN("{} - CertGetCertificateChain failed (error={}), checking leaf only", url ? url : "", GetLastError());
        matched = CertSpkiMatchesPin(pServerCert);
    }

    if (pChain) CertFreeCertificateChain(pChain);
    CertFreeCertificateContext(pServerCert);
    return matched;
}

// Context threaded through the WinHTTP status callback below via
// WINHTTP_OPTION_CONTEXT_VALUE.
struct PinCallbackContext {
    const char* url = nullptr;
    bool pinFailed = false;
};

// WINHTTP_CALLBACK_STATUS_SENDING_REQUEST fires once the TLS handshake has
// completed but *before* the request line/headers/body are written to the
// socket. Validating the pin here — rather than after WinHttpSendRequest
// returns — means a mismatched (e.g. MITM-proxied) certificate causes the
// request to be aborted before any of it, including auth headers and body,
// ever reaches the other end.
void CALLBACK PinStatusCallback(HINTERNET hInternet, DWORD_PTR dwContext, DWORD dwInternetStatus,
                                 LPVOID /*lpvStatusInformation*/, DWORD /*dwStatusInformationLength*/) {
    if (dwInternetStatus != WINHTTP_CALLBACK_STATUS_SENDING_REQUEST) return;

    auto* ctx = reinterpret_cast<PinCallbackContext*>(dwContext);
    if (!ctx) return;

    if (!VerifyPinnedCertificate(hInternet, ctx->url)) {
        OSTP_LOG_WARN("{} - certificate pin mismatch, aborting before request is sent", ctx->url ? ctx->url : "");
        ctx->pinFailed = true;
        // Closing the request handle from inside its own status callback is
        // the documented way to cancel an in-flight WinHttpSendRequest.
        WinHttpCloseHandle(hInternet);
    }
}

struct ParsedUrl {
    std::wstring host;
    std::wstring path;
    INTERNET_PORT port = INTERNET_DEFAULT_HTTP_PORT;
    bool tls = false;
    bool valid = false;
};

ParsedUrl ParseUrl(const char* rawUrl) {
    ParsedUrl out;
    if (!rawUrl) return out;

    std::string url(rawUrl);
    if (url.starts_with("https://")) {
        out.tls = true;
        out.port = INTERNET_DEFAULT_HTTPS_PORT;
        url = url.substr(8);
    } else if (url.starts_with("http://")) {
        url = url.substr(7);
    } else {
        return out;
    }

    const size_t slash = url.find('/');
    const std::string hostPart = url.substr(0, slash);
    out.path = (slash != std::string::npos)
        ? L"/" + std::wstring(url.begin() + slash + 1, url.end())
        : L"/";

    const size_t colon = hostPart.find(':');
    if (colon != std::string::npos) {
        out.host = std::wstring(hostPart.begin(), hostPart.begin() + colon);
        const auto port = Numbers::ParseUInt32(hostPart, {colon + 1});
        if (!port || *port == 0 || *port > 65535) return out;
        out.port = static_cast<INTERNET_PORT>(*port);
    } else {
        out.host = std::wstring(hostPart.begin(), hostPart.end());
    }

    out.valid = !out.host.empty();
    return out;
}

} // namespace

Result Execute(const wchar_t* method,
               const char* url,
               const void* reqBody,
               uint32_t reqBodyLen,
               const wchar_t* headers,
               uint32_t timeoutResolve,
               uint32_t timeoutConnect,
               uint32_t timeoutSend,
               uint32_t timeoutRecv) {
    Result r;

    ParsedUrl pu = ParseUrl(url);
    if (!pu.valid) {
        OSTP_LOG_WARN("Invalid URL: {}", url ? url : "");
        return r;
    }

    auto t0 = std::chrono::steady_clock::now();

    HINTERNET hSession = WinHttpOpen(L"OpenSteamTool/1.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!hSession) {
        hSession = WinHttpOpen(L"OpenSteamTool/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0);
    }
    if (!hSession) {
        OSTP_LOG_WARN("{} - WinHttpOpen failed (error={})", url ? url : "", GetLastError());
        return r;
    }

    // Force TLS 1.2 and TLS 1.3
    DWORD dwProtocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    WinHttpSetOption(hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, &dwProtocols, sizeof(dwProtocols));

    WinHttpSetTimeouts(hSession, timeoutResolve, timeoutConnect, timeoutSend, timeoutRecv);

    HINTERNET hConnect = WinHttpConnect(hSession, pu.host.c_str(), pu.port, 0);
    if (!hConnect) {
        OSTP_LOG_WARN("{} - WinHttpConnect(host='{}', port={}) failed (error={})",
                      url ? url : "",
                      Encoding::WideToUtf8(pu.host),
                      pu.port,
                      GetLastError());
        WinHttpCloseHandle(hSession);
        return r;
    }

    const DWORD flags = pu.tls ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        method,
        pu.path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags);
    if (!hRequest) {
        OSTP_LOG_WARN("{} - WinHttpOpenRequest failed (error={})", url ? url : "", GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return r;
    }

    DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_REDIRECT_POLICY, &redirectPolicy, sizeof(redirectPolicy));

    DWORD decomp = WINHTTP_DECOMPRESSION_FLAG_GZIP | WINHTTP_DECOMPRESSION_FLAG_DEFLATE;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_DECOMPRESSION, &decomp, sizeof(decomp));

    if (headers && headers[0]) {
        if (!WinHttpAddRequestHeaders(
            hRequest,
            headers,
            static_cast<DWORD>(wcslen(headers)),
            WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE)) {
            OSTP_LOG_WARN("{} - WinHttpAddRequestHeaders failed (error={})", url ? url : "", GetLastError());
        }
    }

    const bool isPinnedHost = pu.tls && HostEqualsIgnoreCase(pu.host, kPinnedHost);
    PinCallbackContext pinCtx;
    pinCtx.url = url;

    if (isPinnedHost) {
        static constexpr wchar_t kUserAgentHeader[] = L"User-Agent: ManifestDeXCore/1.0\r\n";
        if (!WinHttpAddRequestHeaders(
            hRequest,
            kUserAgentHeader,
            static_cast<DWORD>(wcslen(kUserAgentHeader)),
            WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE)) {
            OSTP_LOG_WARN("{} - WinHttpAddRequestHeaders(User-Agent) failed (error={})", url ? url : "", GetLastError());
        }

        // Validate the pin from inside WINHTTP_CALLBACK_STATUS_SENDING_REQUEST,
        // i.e. after the TLS handshake but before any request bytes are sent —
        // see PinStatusCallback for why the check can't simply happen after
        // WinHttpSendRequest returns.
        DWORD_PTR ctxValue = reinterpret_cast<DWORD_PTR>(&pinCtx);
        if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_CONTEXT_VALUE, &ctxValue, sizeof(ctxValue))) {
            OSTP_LOG_WARN("{} - WinHttpSetOption(CONTEXT_VALUE) failed (error={})", url ? url : "", GetLastError());
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return r;
        }
        if (WinHttpSetStatusCallback(hRequest, PinStatusCallback, WINHTTP_CALLBACK_FLAG_SEND_REQUEST, 0)
                == WINHTTP_INVALID_STATUS_CALLBACK) {
            OSTP_LOG_WARN("{} - WinHttpSetStatusCallback failed (error={})", url ? url : "", GetLastError());
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return r;
        }
    }

    const DWORD totalLen = reqBodyLen;
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            const_cast<void*>(reqBody), reqBodyLen, totalLen, 0)) {
        OSTP_LOG_WARN("{} - WinHttpSendRequest failed (error={}){}", url, GetLastError(),
                      pinCtx.pinFailed ? " (pin mismatch)" : "");
    } else if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        OSTP_LOG_WARN("{} - WinHttpReceiveResponse failed (error={})", url, GetLastError());
    } else {
        DWORD sz = sizeof(r.status);
        if (!WinHttpQueryHeaders(
            hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &r.status,
            &sz,
            WINHTTP_NO_HEADER_INDEX)) {
            OSTP_LOG_WARN("{} - WinHttpQueryHeaders(status) failed (error={})", url ? url : "", GetLastError());
        }

        DWORD avail = 0;
        while (true) {
            if (!WinHttpQueryDataAvailable(hRequest, &avail)) {
                OSTP_LOG_WARN("{} - WinHttpQueryDataAvailable failed (error={})", url ? url : "", GetLastError());
                break;
            }
            if (!avail) break;

            const size_t off = r.body.size();
            r.body.resize(off + avail);
            DWORD read = 0;
            if (!WinHttpReadData(hRequest, r.body.data() + off, avail, &read)) {
                OSTP_LOG_WARN("{} - WinHttpReadData(size={}) failed (error={})",
                              url ? url : "", avail, GetLastError());
                r.body.resize(off);
                break;
            }
            r.body.resize(off + read);
            // Safety cap on a single response body. This used to be 256 KiB,
            // which silently truncated multi-megabyte downloads (notably the
            // Ryuu manifest bundles, which carry one .manifest per depot and
            // routinely exceed several MB) into corrupt zips. 64 MiB leaves
            // ample headroom for those while still bounding a runaway
            // response; stalled transfers remain bounded by the receive
            // timeout instead.
            if (r.body.size() > 64 * 1024 * 1024) break;
        }

        if (r.status < 200 || r.status >= 300) {
            OSTP_LOG_WARN("{} - unexpected HTTP {}  body={}",
                             url,
                             r.status,
                             r.body.size() > 512 ? r.body.substr(0, 512) + "..." : r.body);
        } else {
            OSTP_LOG_TRACE("{} - response body={} ({}bytes)",
                           url ? url : "", r.body, r.body.size());
        }
        r.ok = true;
    }

    // If the pin callback fired, it already closed hRequest itself to abort
    // the send — closing it again here would double-free the handle.
    if (!pinCtx.pinFailed) {
        WinHttpCloseHandle(hRequest);
    }
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
    OSTP_LOG_DEBUG("{} - elapsed: {}ms status={} body_bytes={}",
                   url ? url : "", elapsed, r.status, r.body.size());

    return r;
}

} // namespace OSTPlatform::Http
