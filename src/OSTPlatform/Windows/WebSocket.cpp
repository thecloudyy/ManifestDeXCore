#include "include/WebSocket.h"

#include "include/Log.h"

#include <windows.h>
#include <winhttp.h>

#include <cstdint>
#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")

namespace OSTPlatform::WebSocket {

struct Client::Impl {
    HINTERNET hSession = nullptr;
    HINTERNET hConnect = nullptr;
    HINTERNET hRequest = nullptr;   // the request handle used for the upgrade
    HINTERNET hWebSocket = nullptr; // the upgraded socket handle
    bool open = false;
};

Client::Client() : impl_(new Impl()) {}

Client::~Client() { Close(); }

Client::Client(Client&& other) noexcept : impl_(other.impl_) { other.impl_ = nullptr; }

Client& Client::operator=(Client&& other) noexcept {
    if (this != &other) {
        Close();
        delete impl_;
        impl_ = other.impl_;
        other.impl_ = nullptr;
    }
    return *this;
}

bool Client::Connect(const std::string& host, uint16_t port, const std::string& path) {
    if (!impl_) return false;

    impl_->hSession = WinHttpOpen(L"ManifestDexCore/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!impl_->hSession) {
        OSTP_LOG_WARN("WebSocket: WinHttpOpen failed (err={})", GetLastError());
        return false;
    }

    std::wstring whost(host.begin(), host.end());
    impl_->hConnect = WinHttpConnect(impl_->hSession, whost.c_str(), port, 0);
    if (!impl_->hConnect) {
        OSTP_LOG_WARN("WebSocket: WinHttpConnect('{}':{}) failed (err={})",
                      host, port, GetLastError());
        return false;
    }

    std::wstring wpath(path.begin(), path.end());
    impl_->hRequest = WinHttpOpenRequest(impl_->hConnect, L"GET", wpath.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!impl_->hRequest) {
        OSTP_LOG_WARN("WebSocket: WinHttpOpenRequest failed (err={})", GetLastError());
        return false;
    }

    // Tell WinHTTP to upgrade the request to a WebSocket. Must be set before Send.
    if (!WinHttpSetOption(impl_->hRequest, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET,
                          nullptr, 0)) {
        OSTP_LOG_WARN("WebSocket: WinHttpSetOption(UPGRADE) failed (err={})", GetLastError());
        return false;
    }

    if (!WinHttpSendRequest(impl_->hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        OSTP_LOG_WARN("WebSocket: WinHttpSendRequest failed (err={})", GetLastError());
        return false;
    }

    if (!WinHttpReceiveResponse(impl_->hRequest, nullptr)) {
        OSTP_LOG_WARN("WebSocket: WinHttpReceiveResponse failed (err={})", GetLastError());
        return false;
    }

    // Set receive timeout on request handle before completing the upgrade so the WebSocket handle inherits it.
    DWORD wsTimeout = 300; // 300ms
    WinHttpSetOption(impl_->hRequest, WINHTTP_OPTION_RECEIVE_TIMEOUT, &wsTimeout, sizeof(wsTimeout));

    impl_->hWebSocket = WinHttpWebSocketCompleteUpgrade(impl_->hRequest, 0);
    if (!impl_->hWebSocket) {
        OSTP_LOG_WARN("WebSocket: WinHttpWebSocketCompleteUpgrade failed (err={})",
                      GetLastError());
        return false;
    }

    // The request handle is no longer needed after the upgrade.
    WinHttpCloseHandle(impl_->hRequest);
    impl_->hRequest = nullptr;

    impl_->open = true;
    OSTP_LOG_DEBUG("WebSocket: connected to {}:{}{}", host, port, path);
    return true;
}

bool Client::IsOpen() const {
    return impl_ && impl_->open && impl_->hWebSocket;
}

bool Client::SendText(const std::string& text) {
    if (!IsOpen()) return false;
    DWORD err = WinHttpWebSocketSend(impl_->hWebSocket, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
                                     const_cast<char*>(text.data()),
                                     static_cast<DWORD>(text.size()));
    if (err != ERROR_SUCCESS) {
        OSTP_LOG_WARN("WebSocket: WinHttpWebSocketSend failed (err={})", err);
        return false;
    }
    return true;
}

static MessageType MapType(WINHTTP_WEB_SOCKET_BUFFER_TYPE t) {
    switch (t) {
    case WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE:
    case WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE:
        return MessageType::Text;
    case WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE:
    case WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE:
        return MessageType::Binary;
    case WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE:
        return MessageType::Close;
    default:
        return MessageType::Binary;
    }
}

Message Client::Receive(uint32_t timeoutMs) {
    Message msg;
    if (!IsOpen()) {
        msg.closed = true;
        return msg;
    }

    if (timeoutMs) {
        WinHttpSetTimeouts(impl_->hSession, 0, 0, 0, static_cast<int>(timeoutMs));
    }

    // Read fragments until a complete message arrives.
    std::string textAcc;
    std::vector<uint8_t> binAcc;
    bool gotText = false;
    bool gotBinary = false;

    for (;;) {
        uint8_t buf[8192];
        DWORD read = 0;
        WINHTTP_WEB_SOCKET_BUFFER_TYPE type = WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE;

        DWORD err = WinHttpWebSocketReceive(impl_->hWebSocket, buf, sizeof(buf), &read, &type);
        if (err != ERROR_SUCCESS) {
            if (err == ERROR_WINHTTP_TIMEOUT) {
                // Timed out waiting — caller may retry. Return an empty, non-closed message.
                return msg;
            }
            OSTP_LOG_DEBUG("WebSocket: WinHttpWebSocketReceive failed (err={})", err);
            msg.closed = true;
            impl_->open = false;
            return msg;
        }

        switch (type) {
        case WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE:
            textAcc.append(reinterpret_cast<char*>(buf), read);
            break;
        case WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE:
            textAcc.append(reinterpret_cast<char*>(buf), read);
            msg.text = std::move(textAcc);
            msg.type = MessageType::Text;
            return msg;
        case WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE:
            binAcc.insert(binAcc.end(), buf, buf + read);
            gotBinary = true;
            break;
        case WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE:
            binAcc.insert(binAcc.end(), buf, buf + read);
            msg.type = MessageType::Binary;
            msg.binary = std::move(binAcc);
            return msg;
        case WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE:
            msg.closed = true;
            msg.type = MessageType::Close;
            impl_->open = false;
            return msg;
        default:
            return msg;
        }
    }
}

void Client::Close() {
    if (!impl_) return;

    if (impl_->hWebSocket) {
        if (impl_->open) {
            WinHttpWebSocketClose(impl_->hWebSocket, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS,
                                  nullptr, 0);
        }
        WinHttpCloseHandle(impl_->hWebSocket);
        impl_->hWebSocket = nullptr;
    }
    if (impl_->hRequest) { WinHttpCloseHandle(impl_->hRequest); impl_->hRequest = nullptr; }
    if (impl_->hConnect) { WinHttpCloseHandle(impl_->hConnect); impl_->hConnect = nullptr; }
    if (impl_->hSession) { WinHttpCloseHandle(impl_->hSession); impl_->hSession = nullptr; }
    impl_->open = false;
}

} // namespace OSTPlatform::WebSocket
