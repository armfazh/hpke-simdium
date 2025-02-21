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

#define STRUCT(NAME, E...) struct{const char E;} NAME;

struct dhkem_encapdecap_tv
{
    STRUCT(in, *skR, *pkR, *seed)
    STRUCT(out, *ss, *enc)
};

struct dhkem_authencapdecap_tv
{
    STRUCT(in, *skR, *pkR, *skS, *pkS, *seed)
    STRUCT(out, *ss, *enc)
};

#undef STRUCT

typedef testing::TestWithParam<dhkem_encapdecap_tv> DHKEM_Encap;
typedef testing::TestWithParam<dhkem_authencapdecap_tv> DHKEM_AuthEncap;

TEST_P(DHKEM_Encap, EncapDecap)
{
    dhkem_encapdecap_tv v = GetParam();
    u8 seed = u8_hex_string(v.in.seed);
    u8 skR = u8_hex_string(v.in.skR);
    u8 pkR = u8_hex_string(v.in.pkR);
    u8 enc_want = u8_hex_string(v.out.enc);
    u8 ss_want = u8_hex_string(v.out.ss);

    u8_static(skE, 32);
    derive_key(&skE, &seed);

    u8_static(ss_encap, 32);
    u8_static(enc, 32);
    encap(&ss_encap, &enc, &pkR, &skE);
    EXPECT_PRED_FORMAT2(u8_cmp, &enc, &enc_want);
    EXPECT_PRED_FORMAT2(u8_cmp, &ss_encap, &ss_want);

    u8_static(ss_decap, 32);
    decap(&ss_decap, &enc, &skR, &pkR);
    EXPECT_PRED_FORMAT2(u8_cmp, &ss_decap, &ss_want);

    u8_free(&seed);
    u8_free(&skR);
    u8_free(&pkR);
    u8_free(&enc_want);
    u8_free(&ss_want);
}

TEST_P(DHKEM_AuthEncap, AuthEncapDecap)
{
    dhkem_authencapdecap_tv v = GetParam();
    u8 seed = u8_hex_string(v.in.seed);
    u8 skR = u8_hex_string(v.in.skR);
    u8 pkR = u8_hex_string(v.in.pkR);
    u8 skS = u8_hex_string(v.in.skS);
    u8 pkS = u8_hex_string(v.in.pkS);
    u8 enc_want = u8_hex_string(v.out.enc);
    u8 ss_want = u8_hex_string(v.out.ss);

    u8_static(skE, 32);
    derive_key(&skE, &seed);

    u8_static(ss_encap, 32);
    u8_static(enc, 32);
    auth_encap(&ss_encap, &enc, &pkR, &skS, &pkS, &skE);
    EXPECT_PRED_FORMAT2(u8_cmp, &enc, &enc_want);
    EXPECT_PRED_FORMAT2(u8_cmp, &ss_encap, &ss_want);

    u8_static(ss_decap, 32);
    auth_decap(&ss_decap, &enc, &skR, &pkR, &pkS);
    EXPECT_PRED_FORMAT2(u8_cmp, &ss_decap, &ss_want);

    u8_free(&seed);
    u8_free(&skR);
    u8_free(&pkR);
    u8_free(&skS);
    u8_free(&pkS);
    u8_free(&enc_want);
    u8_free(&ss_want);
}

INSTANTIATE_TEST_CASE_P(, DHKEM_Encap, testing::Values(dhkem_encapdecap_tv
{
    .in = {
        .skR = "3a74b13cffe48046157df9498bc628a87da7dda6148612f3b903ea7b0f1f64dd",
        .pkR = "2e1ce4482ba464ab489a6c2cfb628480adc03469a02dc47b820cfda79e420521",
        .seed = "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2",
    },
    .out = {
        .ss = "c2f20d6360be4f11bafb1c8d4e52a7ee3970cd6feee3396115f865e4694978dc",
        .enc = "dccf528541b37e2d4c8d99977876d5e5725a7c116252bf99f3d49045fc8a765a",
    }
}));

INSTANTIATE_TEST_CASE_P(, DHKEM_AuthEncap,
                        testing::Values(dhkem_authencapdecap_tv
{
    .in = {
        .skR = "3a74b13cffe48046157df9498bc628a87da7dda6148612f3b903ea7b0f1f64dd",
        .pkR = "2e1ce4482ba464ab489a6c2cfb628480adc03469a02dc47b820cfda79e420521",
        .skS = "3bf62007a206f78fb24b450ab6d2d0ed2c07b4024546a4a6cb47d6fe9b8eb5fb",
        .pkS = "3b318bb960e01effe285886a645e642e74b9e816de0447a6a1feec8a52ee9121",
        .seed = "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2",
    },
    .out = {
        .ss = "f1b743a2ac9afcd88c98cb9b7e3fe6c494e6b6d8667d38d4c0d20da852fc800e",
        .enc = "dccf528541b37e2d4c8d99977876d5e5725a7c116252bf99f3d49045fc8a765a",
    }
}));