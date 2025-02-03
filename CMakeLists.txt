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

add_compile_options(-Wall -Wextra -Wpedantic -g)
add_executable(hpke-simdium
    util.c
    types.c
    x25519.c
    kdf.c
    dhkem.c
    main.c
)
target_link_libraries(hpke-simdium OpenSSL::Crypto)