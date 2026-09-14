# Embeds ManifestDexCore supplemental pattern TOML files as raw-string C++
# literals so they ship inside the DLL (no external file to distribute).
#
# Reads src/pattern/<component>.supplement.toml and configure_file()s a
# generated translation unit that exposes them via PatternSupplement::<Name>.
#
# IMPORTANT: content is read into variables via file(READ) + set() (never
# list(APPEND)/list(GET)) because TOML comments commonly contain a literal ';'
# which CMake list commands treat as a list separator and would silently split
# the embedded text.

set(_client_content "# (no supplemental patterns)\n")
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/pattern/steamclient.supplement.toml")
    file(READ "${CMAKE_CURRENT_SOURCE_DIR}/pattern/steamclient.supplement.toml" _client_content)
endif()

set(_ui_content "# (no supplemental patterns)\n")
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/pattern/steamui.supplement.toml")
    file(READ "${CMAKE_CURRENT_SOURCE_DIR}/pattern/steamui.supplement.toml" _ui_content)
endif()

set(STEAMCLIENT_SUPPLEMENT "${_client_content}")
set(STEAMUI_SUPPLEMENT "${_ui_content}")

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/pattern/SupplementPatterns.cpp.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/SupplementPatterns.cpp"
    @ONLY
)