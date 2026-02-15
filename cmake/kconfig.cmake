# cmake/kconfig.cmake — Kconfig integration for smolclaw
#
# Runs kconfig_genconfig.py at configure time to produce:
#   ${CMAKE_BINARY_DIR}/sc_features.h      — C header with #define SC_ENABLE_X 0/1
#   ${CMAKE_BINARY_DIR}/sc_features.cmake  — CMake file with set(SC_ENABLE_X ON/OFF)
#
# Also provides targets: menuconfig, savedefconfig

find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(KCONFIG_ROOT "${CMAKE_SOURCE_DIR}/Kconfig")
set(KCONFIG_DOTCONFIG "${CMAKE_SOURCE_DIR}/.config")
set(KCONFIG_HEADER "${CMAKE_BINARY_DIR}/sc_features.h")
set(KCONFIG_CMAKE "${CMAKE_BINARY_DIR}/sc_features.cmake")
set(KCONFIG_SCRIPT "${CMAKE_SOURCE_DIR}/scripts/kconfig_genconfig.py")

# Collect any -DSC_ENABLE_* overrides from the CMake command line
set(_kconfig_overrides "")
foreach(_feat
    SC_ENABLE_TELEGRAM SC_ENABLE_DISCORD SC_ENABLE_IRC
    SC_ENABLE_WEB_TOOLS SC_ENABLE_VOICE SC_ENABLE_STREAMING
    SC_ENABLE_CRON SC_ENABLE_SPAWN SC_ENABLE_HEARTBEAT
    SC_ENABLE_BACKGROUND SC_ENABLE_MCP SC_ENABLE_MEMORY_SEARCH
    SC_ENABLE_VAULT SC_ENABLE_GIT SC_ENABLE_SLACK SC_ENABLE_WEB)
    if(DEFINED ${_feat})
        list(APPEND _kconfig_overrides "${_feat}=${${_feat}}")
    endif()
endforeach()

# Run genconfig at configure time
execute_process(
    COMMAND ${Python3_EXECUTABLE} ${KCONFIG_SCRIPT}
            ${KCONFIG_ROOT} ${KCONFIG_DOTCONFIG}
            ${KCONFIG_HEADER} ${KCONFIG_CMAKE}
            ${_kconfig_overrides}
    RESULT_VARIABLE _kconfig_result
    ERROR_VARIABLE _kconfig_stderr
)
if(NOT _kconfig_result EQUAL 0)
    message(FATAL_ERROR "kconfig_genconfig.py failed:\n${_kconfig_stderr}")
endif()
if(_kconfig_stderr)
    message(STATUS "${_kconfig_stderr}")
endif()

# Import the generated feature variables
include(${KCONFIG_CMAKE})

# Target: menuconfig — interactive feature configuration
add_custom_target(menuconfig
    COMMAND ${CMAKE_COMMAND} -E env
        KCONFIG_CONFIG=${KCONFIG_DOTCONFIG}
        ${Python3_EXECUTABLE} -m menuconfig ${KCONFIG_ROOT}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Interactive feature configuration (saves to .config)"
    USES_TERMINAL
)

# Target: savedefconfig — save current config as minimal defconfig
add_custom_target(savedefconfig
    COMMAND ${CMAKE_COMMAND} -E env
        KCONFIG_CONFIG=${KCONFIG_DOTCONFIG}
        ${Python3_EXECUTABLE} -m savedefconfig ${KCONFIG_ROOT}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Save minimal defconfig"
    USES_TERMINAL
)
