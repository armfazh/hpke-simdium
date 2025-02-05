# This file is part of hpke-simdium.
#
# Copyright 2025 Armando Faz Hernandez.
#
# Licensed under the Mozilla Public License, v. 2.0. You may not use this
# file except in compliance with the License.
# You can obtain a copy of the License at:
#
# https://www.mozilla.org/en-US/MPL/2.0/
#
# SPDX-License-Identifier: MPL-2.0

cmake_minimum_required(VERSION 3.10)

project(hpke-simdium C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

find_package(OpenSSL REQUIRED)

add_subdirectory(third_party/libfaz_ecc_avx2)
add_subdirectory(bench)

include_directories(third_party/libfaz_ecc_avx2/include)
link_directories(third_party/libfaz_ecc_avx2/lib)

set(XIMPL "OSSL" CACHE STRING "Implementation of X25519")
set_property(CACHE XIMPL PROPERTY STRINGS OSSL AVX2)

if (XIMPL STREQUAL "OSSL")
    add_compile_definitions(XIMPL_OSSL)
elseif (XIMPL STREQUAL "AVX2")
    add_compile_definitions(XIMPL_AVX2)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)
add_library(hpke-simdium
    util.c
    types.c
    x25519.c
    x25519_ossl.c
    x25519_avx2.c
    kdf.c
    dhkem.c
    dhkem_ossl.c
)

add_executable(main main.c)
add_dependencies(main hpke-simdium)
target_link_libraries(main hpke-simdium OpenSSL::Crypto faz_ecc_avx2)