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

include(FetchContent)
FetchContent_Declare(faz_ecc_avx2
    GIT_REPOSITORY https://github.com/armfazh/fld-ecc-vec/
    GIT_TAG fea63bceebfd4abdc0d74be33ca713c4286429ae
    CMAKE_ARGS -DENABLE_AVX512=ON
)
FetchContent_MakeAvailable(faz_ecc_avx2)

add_compile_options(-Werror -Wall -Wextra -O3 -m64 -march=native -mtune=native)
add_compile_definitions(ENABLED_AVX512)

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
target_link_libraries(hpke-simdium faz_ecc_avx2_static)
target_include_directories(hpke-simdium INTERFACE .)

# Tools
add_subdirectory(bench)

enable_testing()
add_subdirectory(test)
