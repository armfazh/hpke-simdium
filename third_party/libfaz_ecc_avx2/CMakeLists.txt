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

project(faz_ecc_avx2_ecdh C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

include_directories(./include)
link_directories(./lib)

add_compile_options(-Wall -Wextra -Wpedantic -g)
add_executable(faz_ecc_avx2_ecdh ecdh.c)
target_link_libraries(faz_ecc_avx2_ecdh faz_ecc_avx2)