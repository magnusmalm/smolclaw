cmake_minimum_required(VERSION 3.14)
project(smolclaw VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Need POSIX APIs (localtime_r, usleep, popen, etc.)
add_compile_definitions(_POSIX_C_SOURCE=200112L _DEFAULT_SOURCE)

# Compiler warnings
add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)

# ========================================================================
# Build options (not feature selection — that comes from Kconfig)
# ========================================================================
option(SC_STATIC           "Link all dependencies statically (except glibc)" OFF)
option(SC_MUSL_STATIC      "Fully static musl-libc build (zero runtime deps)" OFF)
option(SC_STRIP            "Strip symbols from the binary"                  OFF)

# musl.cc toolchains default to dynamic linking — ensure all executables
# (including tests) are statically linked.
if(SC_MUSL_STATIC)
    add_link_options(-static)
endif()

# ========================================================================
# Feature flags via Kconfig (generates sc_features.h + sc_features.cmake)
# ========================================================================
include(cmake/kconfig.cmake)

# Local dev headers/libs extracted from packages
set(LOCAL_DEV "/tmp/devpkgs/usr")
set(LOCAL_DEV_INC "${LOCAL_DEV}/include" "${LOCAL_DEV}/include/x86_64-linux-gnu")
set(LOCAL_DEV_LIB "${LOCAL_DEV}/lib/x86_64-linux-gnu")

# ========================================================================
# Dependencies - static or dynamic
# ========================================================================
if(SC_MUSL_STATIC)
    # --- Fully static musl build: all deps from deps/musl-static-$ARCH/ ---
    if(DEFINED MUSL_STATIC_PREFIX)
        set(MUSL_PREFIX "${MUSL_STATIC_PREFIX}")
    else()
        if(NOT DEFINED TARGET_ARCH)
            execute_process(COMMAND uname -m OUTPUT_VARIABLE TARGET_ARCH OUTPUT_STRIP_TRAILING_WHITESPACE)
        endif()
        set(MUSL_PREFIX "${CMAKE_SOURCE_DIR}/deps/musl-static-${TARGET_ARCH}")
    endif()
    set(MUSL_REQUIRED_LIBS
        "${MUSL_PREFIX}/lib/libcurl.a"
        "${MUSL_PREFIX}/lib/libssl.a"
        "${MUSL_PREFIX}/lib/libcrypto.a"
        "${MUSL_PREFIX}/lib/libz.a"
        "${MUSL_PREFIX}/lib/libevent.a"
    )
    foreach(lib ${MUSL_REQUIRED_LIBS})
        if(NOT EXISTS "${lib}")
            message(FATAL_ERROR
                "Musl static lib not found: ${lib}\n"
                "Run: ./scripts/build_musl_deps.sh")
        endif()
    endforeach()

    set(CURL_INCLUDE_DIRS "${MUSL_PREFIX}/include")
    set(CURL_LIB "${MUSL_PREFIX}/lib/libcurl.a")
    set(SSL_LIB "${MUSL_PREFIX}/lib/libssl.a")
    set(CRYPTO_LIB "${MUSL_PREFIX}/lib/libcrypto.a")
    set(Z_LIB "${MUSL_PREFIX}/lib/libz.a")
    set(EVENT_LIB "${MUSL_PREFIX}/lib/libevent.a")

    # armv7l (32-bit ARM) needs libatomic for OpenSSL's 64-bit atomic operations
    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "armv7l")
        set(ATOMIC_LIB "atomic")
    endif()
elseif(SC_STATIC)
    # --- Static linking: use .a files directly ---
    set(STATIC_PREFIX "${CMAKE_SOURCE_DIR}/deps/static")
    set(STATIC_CURL "${STATIC_PREFIX}/lib/libcurl.a")

    if(NOT EXISTS "${STATIC_CURL}")
        message(FATAL_ERROR
            "Static libcurl not found at ${STATIC_CURL}\n"
            "Run: ./scripts/build_static_deps.sh")
    endif()

    set(CURL_INCLUDE_DIRS "${STATIC_PREFIX}/include")
    set(CURL_LIB "${STATIC_CURL}")

    # System static libraries
    set(SYS_STATIC "/usr/lib/x86_64-linux-gnu")
    set(SSL_LIB "${SYS_STATIC}/libssl.a")
    set(CRYPTO_LIB "${SYS_STATIC}/libcrypto.a")
    set(Z_LIB "${SYS_STATIC}/libz.a")

    find_library(EVENT_LIB libevent.a PATHS ${SYS_STATIC} ${LOCAL_DEV_LIB})
    if(NOT EVENT_LIB)
        message(FATAL_ERROR "Static libevent not found")
    endif()

    # Readline + terminfo
    find_library(READLINE_LIB libreadline.a PATHS ${SYS_STATIC})
    if(READLINE_LIB)
        find_library(TINFO_LIB libtinfo.a PATHS ${SYS_STATIC})
    endif()
else()
    # --- Dynamic linking (default, unchanged) ---
    find_package(CURL QUIET)
    if(NOT CURL_FOUND)
        set(CURL_INCLUDE_DIRS ${LOCAL_DEV_INC})
        if(EXISTS "/usr/lib/x86_64-linux-gnu/libcurl.so.4")
            set(CURL_LIB "/usr/lib/x86_64-linux-gnu/libcurl.so.4")
        else()
            find_library(CURL_LIB curl PATHS ${LOCAL_DEV_LIB} /usr/lib/x86_64-linux-gnu)
            if(NOT CURL_LIB)
                set(CURL_LIB "curl")
            endif()
        endif()
    endif()

    find_library(EVENT_LIB event PATHS ${LOCAL_DEV_LIB} /usr/lib/x86_64-linux-gnu)
    if(NOT EVENT_LIB)
        set(EVENT_LIB "event")
    endif()

    # OpenSSL needed for Discord (WebSocket TLS), IRC (optional TLS), Slack (WSS), Vault
    if(SC_ENABLE_DISCORD OR SC_ENABLE_IRC OR SC_ENABLE_SLACK OR SC_ENABLE_VAULT)
        find_package(OpenSSL QUIET)
        if(NOT OpenSSL_FOUND)
            find_library(SSL_LIB ssl PATHS ${LOCAL_DEV_LIB} /usr/lib/x86_64-linux-gnu)
            find_library(CRYPTO_LIB crypto PATHS ${LOCAL_DEV_LIB} /usr/lib/x86_64-linux-gnu)
            if(NOT SSL_LIB)
                set(SSL_LIB "ssl")
            endif()
            if(NOT CRYPTO_LIB)
                set(CRYPTO_LIB "crypto")
            endif()
        endif()
    endif()

    find_library(READLINE_LIB readline PATHS ${LOCAL_DEV_LIB} /usr/lib/x86_64-linux-gnu)
endif()

# Generate embedded workspace files
set(WORKSPACE_HEADER "${CMAKE_BINARY_DIR}/workspace_data.h")
add_custom_command(
    OUTPUT ${WORKSPACE_HEADER}
    COMMAND ${CMAKE_SOURCE_DIR}/scripts/embed_workspace.sh
            ${CMAKE_SOURCE_DIR}/workspace
            ${WORKSPACE_HEADER}
    DEPENDS ${CMAKE_SOURCE_DIR}/scripts/embed_workspace.sh
    COMMENT "Embedding workspace template files"
)

# Vendored cJSON
add_library(cjson STATIC deps/cJSON/cJSON.c)
target_include_directories(cjson PUBLIC deps/cJSON)

# Vendored SQLite (for FTS5 memory search)
if(SC_ENABLE_MEMORY_SEARCH)
    add_library(sqlite3 STATIC deps/sqlite3/sqlite3.c)
    target_include_directories(sqlite3 PUBLIC deps/sqlite3)
    target_compile_definitions(sqlite3 PRIVATE
        SQLITE_ENABLE_FTS5
        SQLITE_THREADSAFE=1
        SQLITE_OMIT_LOAD_EXTENSION
        SQLITE_OMIT_DEPRECATED)
    target_compile_options(sqlite3 PRIVATE -w)
    target_link_libraries(sqlite3 PUBLIC m)
endif()

# ========================================================================
# Source files — core (always compiled) + conditional features
# ========================================================================
set(SC_SOURCES
    src/util/str.c
    src/util/json_helpers.c
    src/util/uuid.c
    src/util/base64.c
    src/util/secrets.c
    src/util/prompt_guard.c
    src/util/sandbox.c
    src/logger.c
    src/config.c
    src/bus.c
    src/session.c
    src/state.c
    src/memory.c
    src/context.c
    src/agent.c
    src/audit.c
    src/tools/registry.c
    src/tools/exec_common.c
    src/tools/filesystem.c
    src/tools/shell.c
    src/tools/message.c
    src/tools/memory_tools.c
    src/providers/provider_common.c
    src/providers/http.c
    src/providers/claude.c
    src/providers/factory.c
    src/pairing.c
    src/rate_limit.c
    src/channels/base.c
    src/channels/manager.c
    src/channels/cli.c
    src/workspace.c
    src/cost.c
)

if(SC_ENABLE_GIT)
    list(APPEND SC_SOURCES src/tools/git.c)
endif()

if(SC_ENABLE_STREAMING)
    list(APPEND SC_SOURCES src/util/sse.c)
endif()

if(SC_ENABLE_DISCORD)
    list(APPEND SC_SOURCES src/util/websocket.c src/channels/discord.c)
endif()

if(SC_ENABLE_TELEGRAM)
    list(APPEND SC_SOURCES src/channels/telegram.c)
endif()

if(SC_ENABLE_WEB_TOOLS)
    list(APPEND SC_SOURCES src/tools/web.c)
endif()

if(SC_ENABLE_VOICE)
    list(APPEND SC_SOURCES src/voice/transcriber.c)
endif()

if(SC_ENABLE_CRON)
    list(APPEND SC_SOURCES src/tools/cron.c src/cron/service.c)
endif()

if(SC_ENABLE_SPAWN)
    list(APPEND SC_SOURCES src/tools/spawn.c)
endif()

if(SC_ENABLE_HEARTBEAT)
    list(APPEND SC_SOURCES src/heartbeat/service.c)
endif()

if(SC_ENABLE_BACKGROUND)
    list(APPEND SC_SOURCES src/tools/background.c)
endif()

if(SC_ENABLE_IRC)
    list(APPEND SC_SOURCES src/channels/irc.c)
endif()

if(SC_ENABLE_SLACK)
    list(APPEND SC_SOURCES src/channels/slack.c)
    if(NOT SC_ENABLE_DISCORD)
        list(APPEND SC_SOURCES src/util/websocket.c)
    endif()
endif()

if(SC_ENABLE_WEB)
    list(APPEND SC_SOURCES src/channels/web.c)
endif()

if(SC_ENABLE_MCP)
    list(APPEND SC_SOURCES src/mcp/client.c src/mcp/bridge.c)
endif()

if(SC_ENABLE_MEMORY_SEARCH)
    list(APPEND SC_SOURCES src/memory_index.c src/tools/memory_search.c)
endif()

if(SC_ENABLE_VAULT)
    list(APPEND SC_SOURCES src/util/vault.c)
endif()

# ========================================================================
# Library target
# ========================================================================
add_library(smolclaw_lib STATIC ${SC_SOURCES} ${WORKSPACE_HEADER})
target_include_directories(smolclaw_lib PUBLIC
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/deps/cJSON
    ${CMAKE_BINARY_DIR}
    ${LOCAL_DEV_INC}
)

if(SC_MUSL_STATIC)
    # CURL_STATICLIB needed for correct dllimport/visibility on curl headers
    target_compile_definitions(smolclaw_lib PUBLIC CURL_STATICLIB)
    target_include_directories(smolclaw_lib PUBLIC ${CURL_INCLUDE_DIRS})

    # Link order: curl → ssl → crypto → z → event → pthread → m
    # No -ldl: musl includes dlopen in libc. No readline: fgets fallback works.
    # ATOMIC_LIB is set for armv7l (32-bit ARM needs libatomic for 64-bit atomics).
    target_link_libraries(smolclaw_lib PUBLIC
        cjson ${CURL_LIB} ${SSL_LIB} ${CRYPTO_LIB} ${Z_LIB} ${EVENT_LIB}
        pthread m ${ATOMIC_LIB})
elseif(SC_STATIC)
    # CURL_STATICLIB needed for correct dllimport/visibility on curl headers
    target_compile_definitions(smolclaw_lib PUBLIC CURL_STATICLIB)
    target_include_directories(smolclaw_lib PUBLIC ${CURL_INCLUDE_DIRS})

    # Link order matters: curl → ssl → crypto → z → event → dl → pthread → m
    target_link_libraries(smolclaw_lib PUBLIC
        cjson ${CURL_LIB} ${SSL_LIB} ${CRYPTO_LIB} ${Z_LIB} ${EVENT_LIB}
        dl pthread m)

    if(READLINE_LIB)
        target_link_libraries(smolclaw_lib PUBLIC ${READLINE_LIB})
        if(TINFO_LIB)
            target_link_libraries(smolclaw_lib PUBLIC ${TINFO_LIB})
        endif()
        target_compile_definitions(smolclaw_lib PUBLIC HAVE_READLINE=1)
    endif()
else()
    if(CURL_FOUND)
        target_link_libraries(smolclaw_lib PUBLIC cjson CURL::libcurl ${EVENT_LIB} m)
    else()
        target_link_libraries(smolclaw_lib PUBLIC cjson ${CURL_LIB} ${EVENT_LIB} m)
        target_include_directories(smolclaw_lib PUBLIC ${CURL_INCLUDE_DIRS})
    endif()

    if(SC_ENABLE_DISCORD OR SC_ENABLE_IRC OR SC_ENABLE_SLACK OR SC_ENABLE_VAULT)
        if(OpenSSL_FOUND)
            target_link_libraries(smolclaw_lib PUBLIC OpenSSL::SSL OpenSSL::Crypto)
        else()
            target_link_libraries(smolclaw_lib PUBLIC ${SSL_LIB} ${CRYPTO_LIB})
        endif()
    endif()

    if(READLINE_LIB)
        target_link_libraries(smolclaw_lib PUBLIC ${READLINE_LIB})
        target_compile_definitions(smolclaw_lib PUBLIC HAVE_READLINE=1)
    endif()
endif()

# SQLite for memory search (all build modes)
if(SC_ENABLE_MEMORY_SEARCH)
    target_link_libraries(smolclaw_lib PUBLIC sqlite3)
endif()

# Main executable
add_executable(smolclaw src/main.c)
target_link_libraries(smolclaw PRIVATE smolclaw_lib)

if(SC_MUSL_STATIC)
    target_link_options(smolclaw PRIVATE -static)
elseif(SC_STATIC)
    target_link_options(smolclaw PRIVATE -static-libgcc)
endif()

if(SC_STRIP)
    add_custom_command(TARGET smolclaw POST_BUILD
        COMMAND ${CMAKE_STRIP} $<TARGET_FILE:smolclaw>
        COMMENT "Stripping smolclaw binary")
endif()

# ========================================================================
# Tests — core tests always, feature tests conditional
# ========================================================================
enable_testing()

set(TEST_SOURCES
    tests/test_str.c
    tests/test_config.c
    tests/test_session.c
    tests/test_tools.c
    tests/test_providers.c
    tests/test_pairing.c
    tests/test_agent.c
    tests/test_sandbox.c
    tests/test_memory_tools.c
)

if(SC_ENABLE_STREAMING)
    list(APPEND TEST_SOURCES tests/test_sse.c)
endif()

if(SC_ENABLE_TELEGRAM)
    list(APPEND TEST_SOURCES tests/test_telegram.c)
endif()

if(SC_ENABLE_DISCORD)
    list(APPEND TEST_SOURCES tests/test_discord.c)
endif()

if(SC_ENABLE_VOICE)
    list(APPEND TEST_SOURCES tests/test_voice.c)
endif()

if(SC_ENABLE_BACKGROUND)
    list(APPEND TEST_SOURCES tests/test_background.c)
endif()

if(SC_ENABLE_IRC)
    list(APPEND TEST_SOURCES tests/test_irc.c)
endif()

if(SC_ENABLE_MCP)
    list(APPEND TEST_SOURCES tests/test_mcp.c)
endif()

if(SC_ENABLE_WEB_TOOLS)
    list(APPEND TEST_SOURCES tests/test_web.c)
endif()

if(SC_ENABLE_CRON)
    list(APPEND TEST_SOURCES tests/test_cron.c)
endif()

if(SC_ENABLE_HEARTBEAT)
    list(APPEND TEST_SOURCES tests/test_heartbeat.c)
endif()

if(SC_ENABLE_MEMORY_SEARCH)
    list(APPEND TEST_SOURCES tests/test_memory_search.c)
endif()

if(SC_ENABLE_VAULT)
    list(APPEND TEST_SOURCES tests/test_vault.c)
endif()

foreach(test_src ${TEST_SOURCES})
    get_filename_component(test_name ${test_src} NAME_WE)
    add_executable(${test_name} ${test_src})
    target_link_libraries(${test_name} PRIVATE smolclaw_lib)
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

# Tests using mock_http.h need libevent_pthreads for thread-safe loopbreak
if(SC_MUSL_STATIC)
    set(EVENT_PTHREADS_LIB "${MUSL_PREFIX}/lib/libevent_pthreads.a")
elseif(SC_STATIC)
    find_library(EVENT_PTHREADS_LIB libevent_pthreads.a
        PATHS ${SYS_STATIC} ${LOCAL_DEV_LIB})
else()
    find_library(EVENT_PTHREADS_LIB event_pthreads
        PATHS ${LOCAL_DEV_LIB} /usr/lib/x86_64-linux-gnu)
endif()
if(EVENT_PTHREADS_LIB)
    target_link_libraries(test_providers PRIVATE ${EVENT_PTHREADS_LIB})
    if(SC_ENABLE_WEB_TOOLS)
        target_link_libraries(test_web PRIVATE ${EVENT_PTHREADS_LIB})
    endif()
    if(SC_ENABLE_TELEGRAM)
        target_link_libraries(test_telegram PRIVATE ${EVENT_PTHREADS_LIB})
    endif()
    if(SC_ENABLE_DISCORD)
        target_link_libraries(test_discord PRIVATE ${EVENT_PTHREADS_LIB})
    endif()
    if(SC_ENABLE_VOICE)
        target_link_libraries(test_voice PRIVATE ${EVENT_PTHREADS_LIB})
    endif()
endif()

# Production security test (not in ctest — requires production config)
add_executable(test_security_prod tests/test_security_prod.c)
target_link_libraries(test_security_prod PRIVATE smolclaw_lib)
set_target_properties(test_security_prod PROPERTIES EXCLUDE_FROM_ALL TRUE)

# Install
install(TARGETS smolclaw DESTINATION bin)

# ========================================================================
# Configuration summary
# ========================================================================
message(STATUS "")
message(STATUS "smolclaw v${PROJECT_VERSION} build configuration:")
message(STATUS "  Telegram channel .... ${SC_ENABLE_TELEGRAM}")
message(STATUS "  Discord channel ..... ${SC_ENABLE_DISCORD}")
message(STATUS "  Web tools ........... ${SC_ENABLE_WEB_TOOLS}")
message(STATUS "  Voice transcription . ${SC_ENABLE_VOICE}")
message(STATUS "  SSE streaming ....... ${SC_ENABLE_STREAMING}")
message(STATUS "  Cron service ........ ${SC_ENABLE_CRON}")
message(STATUS "  Spawn tool .......... ${SC_ENABLE_SPAWN}")
message(STATUS "  Heartbeat service ... ${SC_ENABLE_HEARTBEAT}")
message(STATUS "  Background procs .... ${SC_ENABLE_BACKGROUND}")
message(STATUS "  IRC channel ......... ${SC_ENABLE_IRC}")
message(STATUS "  MCP client ......... ${SC_ENABLE_MCP}")
message(STATUS "  Memory search ...... ${SC_ENABLE_MEMORY_SEARCH}")
message(STATUS "  Vault encryption ... ${SC_ENABLE_VAULT}")
message(STATUS "  Git tool ........... ${SC_ENABLE_GIT}")
message(STATUS "  Slack channel ...... ${SC_ENABLE_SLACK}")
message(STATUS "  Web channel ........ ${SC_ENABLE_WEB}")
message(STATUS "  Static linking ...... ${SC_STATIC}")
message(STATUS "  Musl static ......... ${SC_MUSL_STATIC}")
message(STATUS "  Strip binary ........ ${SC_STRIP}")
message(STATUS "")
