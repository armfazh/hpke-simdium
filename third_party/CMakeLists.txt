# hpke-simdium
# Copyright 2025 Armando Faz Hernandez.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# SPDX-License-Identifier: MPL-2.0

cmake_minimum_required(VERSION 3.14.7)

project(third_party)

include(ExternalProject)

# Building OpenSSL
set(OPENSSL_VERSION 3.4.1)
set(INSTALL_OSSL_DIR ${CMAKE_SOURCE_DIR}/ossl)
add_custom_target(openssl DEPENDS openssl-${OPENSSL_VERSION})
ExternalProject_Add(openssl-${OPENSSL_VERSION}
    EXCLUDE_FROM_ALL true
    URL https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz
    URL_HASH SHA256=002a2d6b30b58bf4bea46c43bdd96365aaf8daa6c428782aa4feee06da197df3
    DOWNLOAD_EXTRACT_TIMESTAMP true

    UPDATE_COMMAND ""
    CONFIGURE_COMMAND "<SOURCE_DIR>/Configure"
    "no-apps"
    "no-blake2"
    "no-deprecated"
    "no-docs"
    "no-dtls"
    "no-dtls1_2-method"
    "no-dtls1-method"
    "no-dynamic-engine"
    "no-http"
    "no-legacy"
    "no-mdc2"
    "no-pinshared"
    "no-quic"
    "no-rfc3779"
    "no-scrypt"
    "no-shared"
    "no-sock"
    "no-ssl"
    "no-threads"
    "no-tls"
    "no-tls1_1-method"
    "no-tls1_2-method"
    "no-tls1-method"
    "no-zlib"
    "enable-pie"
    "enable-pic"
    "-fPIE"
    "-pie"
    "-static"
    "--api=3.0"
    "--libdir=lib"
    "--prefix=${INSTALL_OSSL_DIR}"
    "--openssldir=${INSTALL_OSSL_DIR}"

    BUILD_COMMAND make build_sw
    INSTALL_COMMAND make install_sw
)

# Building BoringSSL
set(BORINGSSL_VERSION 0.20250212.0)
set(INSTALL_BSSL_DIR ${CMAKE_SOURCE_DIR}/bssl)
add_custom_target(boringssl DEPENDS boringssl-${BORINGSSL_VERSION})
ExternalProject_Add(boringssl-${BORINGSSL_VERSION}
    EXCLUDE_FROM_ALL true
    URL https://github.com/google/boringssl/releases/download/${BORINGSSL_VERSION}/boringssl-${BORINGSSL_VERSION}.tar.gz
    URL_HASH SHA256=bb8ed99fcafa7de27b5880e6f2aefb8155575f3e623e8de5ddd5390ac06a5458
    DOWNLOAD_EXTRACT_TIMESTAMP true

    CMAKE_ARGS
    -DCMAKE_BUILD_TYPE=Release
    -DCMAKE_INSTALL_PREFIX=${INSTALL_BSSL_DIR}
    -DCMAKE_INSTALL_LIBDIR=lib
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON
    UPDATE_COMMAND ""
)

# Building AWS-LC
set(AWSLC_VERSION v1.48.1)
set(INSTALL_AWSLC_DIR ${CMAKE_SOURCE_DIR}/awslc)
add_custom_target(awslc DEPENDS awslc-${AWSLC_VERSION})
ExternalProject_Add(awslc-${AWSLC_VERSION}
    EXCLUDE_FROM_ALL true
    URL https://github.com/aws/aws-lc/archive/refs/tags/${AWSLC_VERSION}.tar.gz
    URL_HASH SHA256=a65f79b01dc5ef3d2be743dabf5f9b72d4eda869c425348463154a5ae0746afd
    DOWNLOAD_EXTRACT_TIMESTAMP true

    CMAKE_ARGS
    -DCMAKE_BUILD_TYPE=Release
    -DCMAKE_INSTALL_PREFIX=${INSTALL_AWSLC_DIR}
    -DCMAKE_INSTALL_LIBDIR=lib
    -DBUILD_LIBSSL=NO
    -DBUILD_TESTING=NO
    -DBUILD_TOOL=NO
    UPDATE_COMMAND ""
)
