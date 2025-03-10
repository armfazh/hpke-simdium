# hpke-simdium
# Copyright 2025 Armando Faz Hernandez.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# SPDX-License-Identifier: MPL-2.0

cmake_minimum_required(VERSION 3.14.7)

project(hpke-simdium C)

set(CMAKE_BUILD_TYPE Release)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -Wall -Wextra -O3 -m64 -mavx2 -mbmi2 -march=native -mtune=native")

option(ENABLE_AVX512 "Enables AVX512 code" OFF)
if(ENABLE_AVX512)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx512f -mavx512bw")
    add_compile_definitions(ENABLED_AVX512)
endif(ENABLE_AVX512)

# Download faz_ecc_avx2 dependency.
include(ExternalProject)
ExternalProject_Add(faz_ecc_avx2_build
    GIT_REPOSITORY https://github.com/armfazh/fld-ecc-vec/
    GIT_TAG 7ed98a46109775429487e8a946879214796d71b9
    GIT_SHALLOW true

    UPDATE_COMMAND ""
    CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}
    -DENABLE_AVX512=${ENABLE_AVX512}
)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/include)
link_directories(${CMAKE_CURRENT_BINARY_DIR}/lib)

# hpke-simdium
add_library(hpke-simdium-common OBJECT
    types.c
)

add_library(hpke-simdium
    $<TARGET_OBJECTS:hpke-simdium-common>
    dhkem_x64.c
    dhkem_avx2.c
    $<$<BOOL:${ENABLE_AVX512}>:dhkem_avx512.c>
    dhkem.c
)
add_dependencies(hpke-simdium faz_ecc_avx2_build)
target_link_libraries(hpke-simdium faz_ecc_avx2)
target_include_directories(hpke-simdium INTERFACE .)

# Tools
add_subdirectory(bench)

enable_testing()
add_subdirectory(test)
