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
add_executable(bench_ossl
    $<TARGET_OBJECTS:hpke-simdium-common>
    bench_ossl.c
    x25519_crypto.c
    bench_dhkem.c
    dhkem.c
    clocks.c
)
target_include_directories(bench_ossl PRIVATE ../third_party/ossl/include)
target_compile_definitions(bench_ossl PRIVATE CRYPTO_PROV=0)
target_link_libraries(bench_ossl PRIVATE crypto -static)
target_link_directories(bench_ossl PRIVATE ../third_party/ossl/lib)

# Benchmark BoringSSL
add_executable(bench_bssl
    $<TARGET_OBJECTS:hpke-simdium-common>
    bench_bssl.c
    x25519_crypto.c
    bench_dhkem.c
    dhkem.c
    clocks.c
)
target_compile_definitions(bench_bssl PRIVATE CRYPTO_PROV=1 BORINGSSL_PREFIX=BSSL_)
target_include_directories(bench_bssl PRIVATE ../third_party/bssl/include)
target_link_libraries(bench_bssl PRIVATE crypto_bssl -static)
target_link_directories(bench_bssl PRIVATE ../third_party/bssl/lib)

# Benchmark aws-lc
add_executable(bench_awslc
    $<TARGET_OBJECTS:hpke-simdium-common>
    bench_awslc.c
    x25519_crypto.c
    bench_dhkem.c
    dhkem.c
    clocks.c
)
target_compile_definitions(bench_awslc PRIVATE CRYPTO_PROV=2)
target_include_directories(bench_awslc PRIVATE ../third_party/awslc/include)
target_link_libraries(bench_awslc PRIVATE crypto_awslc -static)
target_link_directories(bench_awslc PRIVATE ../third_party/awslc/lib64)

add_executable(bench_hpke_simdium
    bench_hpke_simdium.c
    bench_avx2.c
    $<$<BOOL:${ENABLE_AVX512}>:bench_avx512.c>
    bench_dhkem.c
    dhkem.c
    clocks.c
)

target_link_libraries(bench_hpke_simdium hpke-simdium -static)
