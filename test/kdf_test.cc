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
#include <kdf.h>

extern testing::AssertionResult u8_cmp(const char *a_expr,
                                       const char *b_expr, u8 * a, u8 * b);

struct kdf_test_vector
{
    const char *dh, *ct, *ss;
};

static void PrintTo(const kdf_test_vector& v, std::ostream* os)
{
#define str(X) " "#X": " << v.X
    *os << "{" << str(dh) << str(ct) << str(ss) << " }";
#undef str
}

typedef testing::TestWithParam<kdf_test_vector> KDF;

TEST_P(KDF, extract_and_expand)
{
    kdf_test_vector v = GetParam();
    u8_static(ss_got, 32);
    u8 dh = u8_hex_string(v.dh);
    u8 ct = u8_hex_string(v.ct);
    u8 ss_want = u8_hex_string(v.ss);
    extract_and_expand(&ss_got, &dh, &ct);
    EXPECT_PRED_FORMAT2(u8_cmp, &ss_got, &ss_want);
    u8_free(&dh);
    u8_free(&ct);
    u8_free(&ss_want);
}

TEST_P(KDF, extract_and_expand_single)
{
    kdf_test_vector v = GetParam();
    u8_static(ss_got, 32);
    u8 dh = u8_hex_string(v.dh);
    u8 ct = u8_hex_string(v.ct);
    u8 ss_want = u8_hex_string(v.ss);
    extract_and_expand_single(&ss_got, &dh, &ct);
    EXPECT_PRED_FORMAT2(u8_cmp, &ss_got, &ss_want);
    u8_free(&dh);
    u8_free(&ct);
    u8_free(&ss_want);
}

INSTANTIATE_TEST_CASE_P(, KDF, testing::Values(
                            kdf_test_vector
{
    .dh = "0000000000000000000000000000000000000000000000000000000000000000",
    .ct = "0000000000000000000000000000000000000000000000000000000000000000",
    .ss = "88981076b632a816d78522e1e51993b583988288850e506062465cb31bd46366",
},
kdf_test_vector
{
    .dh = "142fa012eef059c4076fbcd3207ecba05db92ac66c6a004282c9314ca26d21c8",
    .ct = "af25ac87601286c7e056d1bb4d0cff4917dc3be80e4fdef29aaf7f4fb3cf812c",
    .ss = "b06089b6094f6287ba11fd3ef73f9aaa63f2cda0699c25a58884685249176753",
},
kdf_test_vector
{
    .dh = "d6fc59154691ecbf0c7410cbeacf593a98b6968639c6c315d6b61df4fd1791fb",
    .ct = "",
    .ss = "911af401ae325c22dc381541a26c925ef816fb62448c573dc6d0aad8440c8cfa",
}));