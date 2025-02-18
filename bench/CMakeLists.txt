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

include_directories(..)

# Benchmark OpenSSL
# find_package(OpenSSL REQUIRED)
add_executable(bench_ossl
    $<TARGET_OBJECTS:hpke-simdium-common>
    bench_ossl.c
    bench_x25519.c
    bench_dhkem.c
    dhkem.c
    x25519_crypto.c
    clocks.c
)
target_include_directories(bench_ossl PRIVATE ../third_party/ossl/include)
target_compile_definitions(bench_ossl PRIVATE CRYPTO_PROV=0)
target_link_libraries(bench_ossl PRIVATE crypto_ossl)
target_link_directories(bench_ossl PRIVATE ../third_party/ossl/lib64)

# Benchmark BoringSSL
add_executable(bench_bssl
    $<TARGET_OBJECTS:hpke-simdium-common>
    bench_bssl.c
    bench_x25519.c
    bench_dhkem.c
    dhkem.c
    x25519_crypto.c
    clocks.c
)
target_compile_definitions(bench_bssl PRIVATE CRYPTO_PROV=1 BORINGSSL_PREFIX=BSSL_)
target_include_directories(bench_bssl PRIVATE ../third_party/bssl/include)
target_link_libraries(bench_bssl PRIVATE crypto_bssl)
target_link_directories(bench_bssl PRIVATE ../third_party/bssl/lib64)

add_executable(bench_avx2
    bench_avx2.c
    bench_x25519.c
    bench_dhkem.c
    dhkem.c
    clocks.c
)

target_link_libraries(bench_avx2 hpke-simdium)
