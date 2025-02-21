/**
 * hpke-simdium
 * Copyright 2025 Armando Faz Hernandez.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#include <gtest/gtest.h>
#include <dhkem.h>
#include <kdf.h>

extern testing::AssertionResult u8_cmp(const char *a_expr,
                                       const char *b_expr, u8 * a, u8 * b);

struct dhkem_test_vector
{
    struct
    {
        const char *ss, *enc, *skR, *pkR, *seed;
    } encapdecap;

    struct
    {
        const char *ss, *enc, *skR, *pkR, *skS, *pkS, *seed;
    } auth_encapdecap;
};

typedef testing::TestWithParam<dhkem_test_vector> DHKEM;

TEST_P(DHKEM, encapdecap)
{
    dhkem_test_vector v = GetParam();
    u8 seed = u8_hex_string(v.encapdecap.seed);
    u8 enc = u8_hex_string(v.encapdecap.enc);
    u8 skR = u8_hex_string(v.encapdecap.skR);
    u8 pkR = u8_hex_string(v.encapdecap.pkR);
    u8 ss_want = u8_hex_string(v.encapdecap.ss);

    u8_static(skE, 32);
    derive_key(&skE, &seed);

    u8_static(ss_encap, 32);
    encap(&ss_encap, &enc, &pkR, &skE);
    EXPECT_PRED_FORMAT2(u8_cmp, &ss_encap, &ss_want);

    u8_static(ss_decap, 32);
    decap(&ss_decap, &enc, &skR, &pkR);
    EXPECT_PRED_FORMAT2(u8_cmp, &ss_decap, &ss_want);

    u8_free(&enc);
    u8_free(&skR);
    u8_free(&pkR);
    u8_free(&ss_want);
}

TEST_P(DHKEM, auth_encapdecap)
{
    dhkem_test_vector v = GetParam();
    u8 seed = u8_hex_string(v.auth_encapdecap.seed);
    u8 enc = u8_hex_string(v.auth_encapdecap.enc);
    u8 skR = u8_hex_string(v.auth_encapdecap.skR);
    u8 pkR = u8_hex_string(v.auth_encapdecap.pkR);
    u8 skS = u8_hex_string(v.auth_encapdecap.skS);
    u8 pkS = u8_hex_string(v.auth_encapdecap.pkS);
    u8 ss_want = u8_hex_string(v.auth_encapdecap.ss);

    u8_static(skE, 32);
    derive_key(&skE, &seed);

    u8_static(ss_encap, 32);
    auth_encap(&ss_encap, &enc, &pkR, &skS, &pkS, &skE);
    EXPECT_PRED_FORMAT2(u8_cmp, &ss_encap, &ss_want);

    u8_static(ss_decap, 32);
    auth_decap(&ss_decap, &enc, &skR, &pkR, &pkS);
    EXPECT_PRED_FORMAT2(u8_cmp, &ss_decap, &ss_want);

    u8_free(&enc);
    u8_free(&skR);
    u8_free(&pkR);
    u8_free(&skS);
    u8_free(&pkS);
    u8_free(&ss_want);
}

INSTANTIATE_TEST_CASE_P(, DHKEM, testing::Values(dhkem_test_vector
{
    .encapdecap = {
        .ss = "88981076b632a816d78522e1e51993b583988288850e506062465cb31bd46366",
        .enc = "88981076b632a816d78522e1e51993b583988288850e506062465cb31bd46366",
        .skR = "88981076b632a816d78522e1e51993b583988288850e506062465cb31bd46366",
        .pkR = "88981076b632a816d78522e1e51993b583988288850e506062465cb31bd46366",
        .seed = "88981076b632a816d78522e1e51993b583988288850e506062465cb31bd46366",
    },
    .auth_encapdecap = {
        .ss = "88981076b632a816d78522e1e51993b583988288850e506062465cb31bd46366",
        .enc = "88981076b632a816d78522e1e51993b583988288850e506062465cb31bd46366",
        .skR = "88981076b632a816d78522e1e51993b583988288850e506062465cb31bd46366",
        .pkR = "88981076b632a816d78522e1e51993b583988288850e506062465cb31bd46366",
        .skS = "88981076b632a816d78522e1e51993b583988288850e506062465cb31bd46366",
        .pkS = "88981076b632a816d78522e1e51993b583988288850e506062465cb31bd46366",
        .seed = "88981076b632a816d78522e1e51993b583988288850e506062465cb31bd46366",
    },
}));