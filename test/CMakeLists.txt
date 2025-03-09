# hpke-simdium
# Copyright 2025 Armando Faz Hernandez.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# SPDX-License-Identifier: MPL-2.0

enable_language(CXX)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(GTest PATHS ../third_party/googletest)
include(GoogleTest)

include_directories(..)
add_executable(kdf_ossl kdf_test.cc common.cc ../kdf_ossl.c ../kdf.c ../types.c)
target_include_directories(kdf_ossl PRIVATE ../third_party/ossl/include)
target_link_libraries(kdf_ossl PRIVATE crypto GTest::gtest_main)
target_link_directories(kdf_ossl PRIVATE ../third_party/ossl/lib)
gtest_discover_tests(kdf_ossl)

add_executable(kdf_bssl kdf_test.cc common.cc ../kdf_bssl_awslc.c ../kdf.c ../types.c)
target_include_directories(kdf_bssl PRIVATE ../third_party/bssl/include)
target_link_libraries(kdf_bssl PRIVATE crypto GTest::gtest_main)
target_link_directories(kdf_bssl PRIVATE ../third_party/bssl/lib)
gtest_discover_tests(kdf_bssl)

add_executable(kdf_awslc kdf_test.cc common.cc ../kdf_bssl_awslc.c ../kdf.c ../types.c)
target_include_directories(kdf_awslc PRIVATE ../third_party/awslc/include)
target_link_libraries(kdf_awslc PRIVATE crypto GTest::gtest_main)
target_link_directories(kdf_awslc PRIVATE ../third_party/awslc/lib)
gtest_discover_tests(kdf_awslc)

add_executable(dhkem_ossl dhkem_test.cc common.cc ../kdf_ossl.c ../kdf.c)
target_include_directories(dhkem_ossl PRIVATE ../third_party/ossl/include)
target_link_libraries(dhkem_ossl PRIVATE hpke-simdium crypto GTest::gtest_main)
target_link_directories(dhkem_ossl PRIVATE ../third_party/ossl/lib)
gtest_discover_tests(dhkem_ossl)
