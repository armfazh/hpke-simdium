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
include_directories(../third_party/libfaz_ecc_avx2/include)
link_directories(../third_party/libfaz_ecc_avx2/lib)

add_executable(bench
        clocks.h
        clocks.c
        bench_x25519.c
)

find_package(OpenSSL REQUIRED)
add_dependencies(bench hpke-simdium)
target_link_libraries(bench
        hpke-simdium
        faz_ecc_avx2
        OpenSSL::Crypto
)
