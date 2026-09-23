#include "Json.h"

#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace MdxJson {

namespace {

bool IsSpace(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

// Skip whitespace starting at `pos`; returns the first non-space index.
size_t SkipWs(std::string_view json, size_t pos) {
    while (pos < json.size() && IsSpace(json[pos])) ++pos;
    return pos;
}

// Find the opening of a value after a matched key token "key".
// `keyToken` is the already-built  "key"  substring (with quotes).
// Returns the index just past the colon, or npos on failure.
size_t FindValueAfterKey(std::string_view json, std::string_view keyToken) {
    size_t keyPos = json.find(keyToken);
    if (keyPos == std::string_view::npos) return std::string_view::npos;

    size_t pos = keyPos + keyToken.size();
    pos = SkipWs(json, pos);
    if (pos >= json.size() || json[pos] != ':') return std::string_view::npos;
    ++pos;
    pos = SkipWs(json, pos);
    if (pos >= json.size()) return std::string_view::npos;
    return pos;
}

} // namespace

std::optional<std::string> GetString(std::string_view json, std::string_view key) {
    std::string token;
    token.reserve(key.size() + 3);
    token += '"';
    token += key;
    token += '"';

    size_t pos = FindValueAfterKey(json, token);
    if (pos == std::string_view::npos) return std::nullopt;
    if (json[pos] != '"') return std::nullopt; // not a string value
    ++pos;

    // Read raw until the closing quote. No escape handling: the tokens and
    // URLs we extract (bearer tokens, download tokens, manifestdex URLs)
    // never contain quotes or backslashes.
    size_t end = json.find('"', pos);
    if (end == std::string_view::npos) return std::nullopt;

    return std::string(json.substr(pos, end - pos));
}

std::optional<std::string> GetScalar(std::string_view json, std::string_view key) {
    std::string token;
    token.reserve(key.size() + 3);
    token += '"';
    token += key;
    token += '"';

    size_t pos = FindValueAfterKey(json, token);
    if (pos == std::string_view::npos) return std::nullopt;
    if (json[pos] == '"') {
        // String scalar — return the unquoted content.
        ++pos;
        size_t end = json.find('"', pos);
        if (end == std::string_view::npos) return std::nullopt;
        return std::string(json.substr(pos, end - pos));
    }

    // Non-string scalar: read until a comma, brace, or bracket terminates.
    size_t end = pos;
    while (end < json.size() &&
           json[end] != ',' && json[end] != '}' && json[end] != ']' &&
           !IsSpace(json[end])) {
        ++end;
    }
    if (end == pos) return std::nullopt;
    return std::string(json.substr(pos, end - pos));
}

std::optional<bool> GetBool(std::string_view json, std::string_view key) {
    auto s = GetScalar(json, key);
    if (!s) return std::nullopt;
    if (*s == "true") return true;
    if (*s == "false") return false;
    return std::nullopt;
}

std::optional<uint64_t> GetUInt64(std::string_view json, std::string_view key) {
    auto s = GetScalar(json, key);
    if (!s) return std::nullopt;
    uint64_t v = 0;
    auto [_, ec] = std::from_chars(s->data(), s->data() + s->size(), v);
    if (ec != std::errc{}) return std::nullopt;
    return v;
}

std::string EscapeForJson(std::string_view input) {
    std::string result;
    result.reserve(input.size() + 16);
    result += '"';
    for (char c : input) {
        switch (c) {
        case '"':  result += "\\\""; break;
        case '\\': result += "\\\\"; break;
        case '\b': result += "\\b"; break;
        case '\f': result += "\\f"; break;
        case '\n': result += "\\n"; break;
        case '\r': result += "\\r"; break;
        case '\t': result += "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                // Control character: \uXXXX
                char buf[7];
                snprintf(buf, sizeof(buf), "\\u%04X", static_cast<unsigned char>(c));
                result += buf;
            } else {
                result += c;
            }
        }
    }
    result += '"';
    return result;
}

} // namespace MdxJson
