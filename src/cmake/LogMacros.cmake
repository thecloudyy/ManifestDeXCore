# mdx_log_modules.h so that adding a new module only requires one line
# in mdx_log_modules.h — Log.h never needs to change.
#
# Output: ${CMAKE_CURRENT_BINARY_DIR}/generated/mdx_log_macros.h

set(_log_modules_h "${CMAKE_CURRENT_SOURCE_DIR}/Utils/Logging/mdx_log_modules.h")
set(_log_macros_out "${CMAKE_CURRENT_BINARY_DIR}/generated/mdx_log_macros.h")

file(STRINGS "${_log_modules_h}" _lines REGEX "^MDX_MOD\\(")
string(REGEX MATCHALL "MDX_MOD\\([A-Za-z_][A-Za-z0-9_]*" _matches "${_lines}")

set(_debug "")
set(_release "")

foreach(_m ${_matches})
    string(REGEX REPLACE "MDX_MOD\\(" "" _var "${_m}")
    string(TOUPPER "${_var}" _upper)

    string(APPEND _debug
"#define LOG_${_upper}_TRACE(...)  SPDLOG_LOGGER_TRACE(Log::${_var}, __VA_ARGS__)\n\
#define LOG_${_upper}_DEBUG(...)  SPDLOG_LOGGER_DEBUG(Log::${_var}, __VA_ARGS__)\n\
#define LOG_${_upper}_INFO(...)   SPDLOG_LOGGER_INFO(Log::${_var}, __VA_ARGS__)\n\
#define LOG_${_upper}_WARN(...)   SPDLOG_LOGGER_WARN(Log::${_var}, __VA_ARGS__)\n\
#define LOG_${_upper}_ERROR(...)  SPDLOG_LOGGER_ERROR(Log::${_var}, __VA_ARGS__)\n\n")

    string(APPEND _release
"#define LOG_${_upper}_TRACE(...)  ((void)0)\n\
#define LOG_${_upper}_DEBUG(...)  ((void)0)\n\
#define LOG_${_upper}_INFO(...)   ((void)0)\n\
#define LOG_${_upper}_WARN(...)   ((void)0)\n\
#define LOG_${_upper}_ERROR(...)  ((void)0)\n\n")
endforeach()
set(_new_content
"// Auto-generated from mdx_log_modules.h -- DO NOT EDIT\n\
#pragma once\n\n\
#ifdef MANIFESTDEXCORE_LOGGING_ENABLED\n\n\
${_debug}\
#else\n\n\
${_release}\
#endif\n")

set(_needs_write TRUE)
if(EXISTS "${_log_macros_out}")
    file(READ "${_log_macros_out}" _old_content)
    if("${_old_content}" STREQUAL "${_new_content}")
        set(_needs_write FALSE)
    endif()
endif()

if(_needs_write)
    file(WRITE "${_log_macros_out}" "${_new_content}")
    message(STATUS "Generated ${_log_macros_out}")
else()
    message(STATUS "LogMacros: ${_log_macros_out} is up to date")
endif()
