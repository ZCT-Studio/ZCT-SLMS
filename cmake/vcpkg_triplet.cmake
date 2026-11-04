# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 ZCT Studio

if (WIN32 AND NOT VCPKG_TARGET_TRIPLET)
    if (CMAKE_GENERATOR_PLATFORM MATCHES "^[Ww][Ii][Nn]32$")
        set(VCPKG_TARGET_TRIPLET "x86-windows-static")
    elseif (CMAKE_GENERATOR_PLATFORM MATCHES "^[Aa][Rr][Mm]64$")
        set(VCPKG_TARGET_TRIPLET "arm64-windows-static")
    elseif (CMAKE_GENERATOR_PLATFORM MATCHES "^[Aa][Rr][Mm]$")
        set(VCPKG_TARGET_TRIPLET "arm-windows-static")
    else ()
        set(VCPKG_TARGET_TRIPLET "x64-windows-static")
    endif ()
endif ()
