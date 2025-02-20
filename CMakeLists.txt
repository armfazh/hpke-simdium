# hpke-simdium
# Copyright 2025 Armando Faz Hernandez.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# SPDX-License-Identifier: MPL-2.0

cmake_minimum_required(VERSION 3.13)

project(hpke-simdium C)

set(CMAKE_BUILD_TYPE Release)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)
add_compile_options(-Werror -Wall -Wextra -O3 -m64 -mavx2 -mbmi2 -march=native -mtune=native)

# faz_ecc_avx512
include_directories(third_party/libfaz_ecc_avx512/include)
link_directories(third_party/libfaz_ecc_avx512/lib)

# hpke-simdium
add_library(hpke-simdium-common OBJECT
    types.c
)

add_library(hpke-simdium
    $<TARGET_OBJECTS:hpke-simdium-common>
    dhkem_x64.c
    dhkem_avx2.c
    dhkem_avx512.c
    dhkem.c
)
target_link_libraries(hpke-simdium faz_ecc_avx2)

# Tools
add_subdirectory(bench)

enable_testing()
add_subdirectory(test)
