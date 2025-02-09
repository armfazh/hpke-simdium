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

cmake_minimum_required(VERSION 3.13)

project(hpke-simdium C)

set(CMAKE_BUILD_TYPE Release)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)
add_compile_options(-g -Werror -Wall -Wextra -O3 -std=c99 -m64 -mavx2 -mbmi2 -march=native -mtune=native)

file(GLOB crypto_sources x25519_crypto.c)

# OpenSSL
add_library(ossl ${crypto_sources})
target_compile_definitions(ossl PRIVATE CRYPTO_PROV=0)
target_include_directories(ossl PRIVATE third_party/ossl/include)
target_link_libraries(ossl PRIVATE crypto_ossl)
link_directories(third_party/ossl/lib64)

# BoringSSL
add_library(bssl ${crypto_sources})
target_compile_definitions(bssl PRIVATE CRYPTO_PROV=1 BORINGSSL_PREFIX=BSSL_)
target_include_directories(bssl PRIVATE third_party/bssl/include)
target_link_libraries(bssl PRIVATE crypto_bssl)
link_directories(third_party/bssl/lib64)

# faz_ecdh_avx2
include_directories(third_party/libfaz_ecc_avx2/include)
link_directories(third_party/libfaz_ecc_avx2/lib)

# hpke-simdium
add_library(hpke-simdium
    types.c
    x25519_avx2.c
    x25519.c
    kdf.c
    dhkem.c
)
target_link_libraries(hpke-simdium faz_ecc_avx2)

add_executable(main main.c)
target_link_libraries(main bssl ossl)

add_subdirectory(bench)