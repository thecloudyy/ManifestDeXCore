#pragma once

// OS-agnostic interface to a blocking WebSocket client.
//
// Used by the MDXBrowser module to speak the Chrome DevTools Protocol to
// Steam's CEF (steamwebhelper) remote-debugging endpoint. The connection is
// opened via a plain HTTP request to  http://localhost:{port}/...  which the
// platform upgrades to a WebSocket. All operations are blocking.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace OSTPlatform::WebSocket {

    enum class MessageType {
        Text,
        Binary,
        Close,
    };

    struct Message {
        MessageType type = MessageType::Text;
        std::string text;                 // populated when type == Text
        std::vector<uint8_t> binary;      // populated when type == Binary
        bool closed = false;              // set when the peer closed the socket
    };

    // Connection handle. Opaque to callers; the platform owns the real OS
    // handles internally.
    class Client {
    public:
        Client();
        ~Client();

        Client(const Client&) = delete;
        Client& operator=(const Client&) = delete;
        Client(Client&&) noexcept;
        Client& operator=(Client&&) noexcept;

        // Connect and upgrade. `host` is without scheme/port (e.g. "localhost"),
        // `port` the devtools port (e.g. 8080), `path` begins with "/" (e.g.
        // "/devtools/page/ABC"). Returns true once the WS handshake succeeded.
        bool Connect(const std::string& host, uint16_t port, const std::string& path);

        bool IsOpen() const;

        // Send a text frame.
        bool SendText(const std::string& text);

        // Receive the next message. Blocks until a full frame arrives, the
        // socket closes, or the timeout (ms) elapses. On timeout returns a
        // Message with closed=false and empty payloads (caller may retry).
        Message Receive(uint32_t timeoutMs);

        void Close();

    private:
        struct Impl;
        Impl* impl_ = nullptr;
    };

} // namespace OSTPlatform::WebSocket
