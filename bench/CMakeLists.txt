# hpke-simdium
# Copyright 2025 Armando Faz Hernandez.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# SPDX-License-Identifier: MPL-2.0

include_directories(..)

# Benchmark OpenSSL
# find_package(OpenSSL REQUIRED)
add_executable(bench_ossl
    $<TARGET_OBJECTS:hpke-simdium-common>
    bench_ossl.c
    x25519_crypto.c
    dhkem.c
    bench.c
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
    x25519_crypto.c
    dhkem.c
    bench.c
    clocks.c
)
target_compile_definitions(bench_bssl PRIVATE CRYPTO_PROV=1 BORINGSSL_PREFIX=BSSL_)
target_include_directories(bench_bssl PRIVATE ../third_party/bssl/include)
target_link_libraries(bench_bssl PRIVATE crypto_bssl)
target_link_directories(bench_bssl PRIVATE ../third_party/bssl/lib)

add_executable(bench_avx2
    bench_avx2.c
    dhkem.c
    bench.c
    clocks.c
)

target_link_libraries(bench_avx2 hpke-simdium)
