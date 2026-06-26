# Size-optimized release profile (phase 0.4).
# Applied automatically for MinSizeRel builds: LTO, section GC, -Os.

if(NOT CMAKE_BUILD_TYPE STREQUAL "MinSizeRel")
    return()
endif()

include(CheckIPOSupported)
check_ipo_supported(RESULT _sc_ipo_ok OUTPUT _sc_ipo_err LANGUAGES C)
if(NOT _sc_ipo_ok)
    message(FATAL_ERROR "MinSizeRel requires LTO support: ${_sc_ipo_err}")
endif()

# Prefer thin LTO when the toolchain accepts it; fall back to full -flto.
set(_sc_lto_flag "-flto")
include(CheckCCompilerFlag)
check_c_compiler_flag("-flto=thin" _sc_lto_thin_ok)
if(_sc_lto_thin_ok)
    set(_sc_lto_flag "-flto=thin")
endif()

set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
set(CMAKE_C_COMPILE_OPTIONS_IPO "${_sc_lto_flag}")
set(CMAKE_C_LINK_OPTIONS_IPO "${_sc_lto_flag}")

add_compile_options(-ffunction-sections -fdata-sections)
add_link_options(-Wl,--gc-sections)

message(STATUS "Size-optimized profile: MinSizeRel + ${_sc_lto_flag} + gc-sections")