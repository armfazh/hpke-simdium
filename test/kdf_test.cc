/**
 * This file is part of hpke-simdium.
 *
 * Copyright 2025 Armando Faz Hernandez.
 *
 * Licensed under the Mozilla Public License, v. 2.0. You may not use this
 * file except in compliance with the License.
 * You can obtain a copy of the License at:
 *
 * https://www.mozilla.org/en-US/MPL/2.0/
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#include <gtest/gtest.h>
#include <kdf.h>

static std::string u8_to_string(u8 *x)
{
    std::stringstream s;
    char str[3] = {0};
    for (size_t i = 0; i < x->len; i++) {
        sprintf(str,"%02x",x->data[i]);
        s << str ;
    };
    return s.str();
}

static testing::AssertionResult u8_cmp(
    const char* a_expr,
    const char* b_expr,
    u8 * a,
    u8 * b)
{
    if ( a->len == b->len   &&memcmp(a->data,b->data,a->len)==0) {
        return testing::AssertionSuccess();
    } else {
        return testing::AssertionFailure()
               << "mismatch "<< a_expr <<" and "<< b_expr
               << std::endl << "got:  (" << a->len << ") "<< u8_to_string(a)
               << std::endl << "want: (" << b->len << ") "<< u8_to_string(b);
    }
}

struct kdf_test_vector {
    const char* dh,*ct,*ss;
};

static void PrintTo(const kdf_test_vector& v, std::ostream* os)
{
#define str(X) " "#X": " << v.X
    *os << "{" << str(dh) << str(ct) << str(ss) << " }";
#undef str
}

typedef testing::TestWithParam<kdf_test_vector> KDF;

TEST_P(KDF,extract_and_expand)
{
    kdf_test_vector v = GetParam();
    u8_static(ss_got,32);
    u8 dh = u8_hex_string(v.dh);
    u8 ct = u8_hex_string(v.ct);
    u8 ss_want = u8_hex_string(v.ss);
    extract_and_expand(&ss_got,&dh,&ct);
    EXPECT_PRED_FORMAT2(u8_cmp,&ss_got,&ss_want);
    u8_free(&dh);
    u8_free(&ct);
    u8_free(&ss_want);
}

TEST_P(KDF,extract_and_expand_single)
{
    kdf_test_vector v = GetParam();
    u8_static(ss_got,32);
    u8 dh = u8_hex_string(v.dh);
    u8 ct = u8_hex_string(v.ct);
    u8 ss_want = u8_hex_string(v.ss);
    extract_and_expand_single(&ss_got,&dh,&ct);
    EXPECT_PRED_FORMAT2(u8_cmp,&ss_got,&ss_want);
    u8_free(&dh);
    u8_free(&ct);
    u8_free(&ss_want);
}

INSTANTIATE_TEST_CASE_P(, KDF, testing::Values(
kdf_test_vector{
    .dh= "0000000000000000000000000000000000000000000000000000000000000000",
    .ct= "0000000000000000000000000000000000000000000000000000000000000000",
    .ss= "88981076b632a816d78522e1e51993b583988288850e506062465cb31bd46366",
},
kdf_test_vector{
    .dh= "142fa012eef059c4076fbcd3207ecba05db92ac66c6a004282c9314ca26d21c8",
    .ct= "af25ac87601286c7e056d1bb4d0cff4917dc3be80e4fdef29aaf7f4fb3cf812c",
    .ss= "b06089b6094f6287ba11fd3ef73f9aaa63f2cda0699c25a58884685249176753",
}));
