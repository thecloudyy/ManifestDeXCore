#pragma once

// Minimal, allocation-light JSON scanner used by the MDXBrowser module.
//
// We deliberately avoid pulling in a full JSON library (nlohmann, rapidjson)
// to keep the DLL's dependency surface unchanged. The ManifestDex backend
// payloads we touch are small and well-known, so a hand-rolled "find a key,
// read its scalar value" extractor — the same approach already used in
// UpdateChecker.cpp and ManifestClient.cpp — is sufficient.
//
// Limitations (acceptable for our payloads):
//   - String values are not unescaped; we read raw bytes between quotes.
//     Tokens/URLs we extract contain neither quotes nor backslashes.
//   - No support for nested-object navigation; only flat top-level keys.
//   - Boolean/number parsing assumes standard JSON scalar forms.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace MdxJson {

    // Extract the string value of a top-level "key": "value" pair.
    // Returns std::nullopt when the key is absent or its value is not a
    // JSON string. Does not handle escapes.
    std::optional<std::string> GetString(std::string_view json, std::string_view key);

    // Extract the value of a top-level "key": <scalar> pair as a raw token
    // (the text between the colon and the next comma/brace, trimmed).
    // Useful for numbers and booleans where you want to interpret the type
    // yourself.
    std::optional<std::string> GetScalar(std::string_view json, std::string_view key);

    // Convenience: extract a boolean "key": true|false.
    std::optional<bool> GetBool(std::string_view json, std::string_view key);

    // Convenience: extract a 64-bit unsigned "key": <integer>.
    std::optional<uint64_t> GetUInt64(std::string_view json, std::string_view key);

    // Escapes a string for JSON string literal embedding (quotes, backslash,
    // newlines, tabs, carriage returns). Does not handle Unicode replacement.
    std::string EscapeForJson(std::string_view input);

} // namespace MdxJson
