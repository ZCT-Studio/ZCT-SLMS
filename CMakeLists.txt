cmake_minimum_required(VERSION 3.25)

include(cmake/vcpkg_triplet.cmake)

project(ZCT-SLMS
    VERSION 2.0.0
    LANGUAGES CXX
)

set(ZCT_SLMS_INCLUDE_DIRS
    "${CMAKE_SOURCE_DIR}/src"
    "${CMAKE_SOURCE_DIR}/libs"
)

include(cmake/compiler_flags.cmake)
include(cmake/dependencies.cmake)

add_executable(ZCT-SLMS src/main.cpp)
add_library(zct_slms_zaclib STATIC libs/ZACLib/ZACLib.cpp)
target_include_directories(zct_slms_zaclib PUBLIC "${CMAKE_SOURCE_DIR}/libs")
set_target_properties(zct_slms_zaclib PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED YES)
target_link_libraries(ZCT-SLMS PRIVATE zct_slms_zaclib)
target_include_directories(ZCT-SLMS PRIVATE ${ZCT_SLMS_INCLUDE_DIRS})

target_link_libraries(ZCT-SLMS PRIVATE
    Drogon::Drogon
    unofficial::sqlite3::sqlite3
    yaml-cpp::yaml-cpp
    OpenSSL::SSL OpenSSL::Crypto
    CURL::libcurl
    unofficial::argon2::libargon2
)

target_compile_definitions(ZCT-SLMS PRIVATE ZCT_SLMS_HAS_ARGON2=1)
if(MSVC)
    target_compile_options(ZCT-SLMS PRIVATE /bigobj)
endif()

include(cmake/optional_backends.cmake)

if(CMAKE_CROSSCOMPILING AND NOT MSVC AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "12")
        target_link_libraries(ZCT-SLMS PRIVATE stdc++fs)
    endif()
endif()

if(WIN32)
    set_target_properties(ZCT-SLMS PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
endif()
