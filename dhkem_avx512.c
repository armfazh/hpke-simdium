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
#include "dhkem.h"
#include "kdf.h"

#include <stdio.h>
#include <string.h>
#include <faz_ecdh_avx2.h>

void encap_avx512(u8 *shared_secret, u8 *enc, u8 *pkR)
{
    u8_static(gen, 32);
    u8_static(skE, 32);
    u8_static(pkE, 32);
    u8_static(dh, 32);
    struct X25519_KEY_x2 ss, sk, pk;

    gen.data[0] = 9;
    X25519_AVX512.randKey(skE.data);
    memcpy(sk.k0,skE.data,skE.len);
    memcpy(sk.k1,skE.data,skE.len);

    memcpy(pk.k0,gen.data,gen.len);
    memcpy(pk.k1,pkR->data,pkR->len);

    X25519_AVX512.shared(&ss,&pk,&sk);
    memcpy(pkE.data,ss.k0,pkE.len);
    memcpy(dh.data,ss.k1,dh.len);
    // x->keygen(&skE, &pkE);
    // x->shared(&dh, &skE, pkR);
    u8_copy(enc, &pkE);

    u8_static(kem_context, 2 * 32);
    uint8_t *ptr = kem_context.data;
    memcpy(ptr, enc->data, enc->len);
    ptr += enc->len;
    memcpy(ptr, pkR->data, pkR->len);

    extract_and_expand(shared_secret, &dh, &kem_context);
}

void decap_avx512(u8 *shared_secret, u8 *enc, u8 *skR, u8 *pkR)
{
    u8_static(dh, 32);
    X25519_AVX2.shared(dh.data, skR->data, enc->data);
    // x->shared(&dh, skR, enc);

    u8_static(kem_context, 2 * 32);
    uint8_t *ptr = kem_context.data;
    memcpy(ptr, enc->data, enc->len);
    ptr += enc->len;
    memcpy(ptr, pkR->data, pkR->len);

    extract_and_expand(shared_secret, &dh, &kem_context);
}

void auth_encap_avx512(u8 *shared_secret, u8 *enc, u8 *pkR, u8 *skS, u8 *pkS)
{
    u8_static(skE, 32);
    u8_static(pkE, 32);
    u8_static(dh1, 32);
    u8_static(dh2, 32);

    X25519_AVX2.keygen(skE.data, pkE.data);

    struct X25519_KEY_x2 ss, sk, pk;
    memcpy(sk.k0,skE.data,skE.len);
    memcpy(sk.k1,skS->data,skS->len);

    memcpy(pk.k0,pkR->data,pkR->len);
    memcpy(pk.k1,pkR->data,pkR->len);

    X25519_AVX512.shared(&ss,&pk,&sk);
    memcpy(dh1.data,ss.k1,dh1.len);
    memcpy(dh2.data,ss.k1,dh2.len);
    // x->shared(&dh1, &skE, pkR);
    // x->shared(&dh2, skS, pkR);

    u8_static(dh, 2 * 32);
    uint8_t *ptr = dh.data;
    memcpy(ptr, dh1.data, dh1.len);
    ptr += dh1.len;
    memcpy(ptr, dh2.data, dh2.len);

    u8_copy(enc, &pkE);

    u8_static(kem_context, 3 * 32);
    ptr = kem_context.data;
    memcpy(ptr, enc->data, enc->len);
    ptr += enc->len;
    memcpy(ptr, pkR->data, pkR->len);
    ptr += pkR->len;
    memcpy(ptr, pkS->data, pkS->len);

    extract_and_expand(shared_secret, &dh, &kem_context);
}

void auth_decap_avx512(u8 *shared_secret, u8 *enc, u8 *skR, u8 *pkR, u8 *pkS)
{
    u8_static(dh1, 32);
    u8_static(dh2, 32);

    struct X25519_KEY_x2 ss, sk, pk;
    memcpy(sk.k0,skR->data,skR->len);
    memcpy(sk.k1,skR->data,skR->len);

    memcpy(pk.k0,enc->data,enc->len);
    memcpy(pk.k1,pkS->data,pkS->len);

    X25519_AVX512.shared(&ss,&pk,&sk);
    memcpy(dh1.data,ss.k1,dh1.len);
    memcpy(dh2.data,ss.k1,dh2.len);
    // x->shared(&dh1, skR, enc);
    // x->shared(&dh2, skR, pkS);

    u8_static(dh, 2 * 32);
    uint8_t *ptr = dh.data;
    memcpy(ptr, dh1.data, dh1.len);
    ptr += dh1.len;
    memcpy(ptr, dh2.data, dh2.len);

    u8_static(kem_context, 3 * 32);
    ptr = kem_context.data;
    memcpy(ptr, enc->data, enc->len);
    ptr += enc->len;
    memcpy(ptr, pkR->data, pkR->len);
    ptr += pkR->len;
    memcpy(ptr, pkS->data, pkS->len);

    extract_and_expand(shared_secret, &dh, &kem_context);
}

int main_dhkem_avx512()
{
    u8 skR = u8_malloc(32);
    u8 pkR = u8_malloc(32);
    X25519_AVX2.keygen(skR.data, pkR.data);
    printf("skR: ");
    u8_print(&skR);
    printf("pkR: ");
    u8_print(&pkR);

    u8 ss1 = u8_malloc(32);
    u8 enc = u8_malloc(32);
    encap_avx512(&ss1, &enc, &pkR);
    printf("ss1: ");
    u8_print(&ss1);
    printf("enc: ");
    u8_print(&enc);

    u8 ss2 = u8_malloc(32);
    decap_avx512(&ss2, &enc, &skR, &pkR);
    printf("ss2: ");
    u8_print(&ss2);

    u8_free(&skR);
    u8_free(&pkR);

    u8_free(&ss1);
    u8_free(&ss2);
    u8_free(&enc);

    return 0;
}

int main_auth_dhkem_avx512()
{
    u8 skS = u8_malloc(32);
    u8 pkS = u8_malloc(32);
    X25519_AVX2.keygen(skS.data, pkS.data);
    printf("skS: ");
    u8_print(&skS);
    printf("pkS: ");
    u8_print(&pkS);

    u8 skR = u8_malloc(32);
    u8 pkR = u8_malloc(32);
    X25519_AVX2.keygen(skR.data, pkR.data);
    printf("skR: ");
    u8_print(&skR);
    printf("pkR: ");
    u8_print(&pkR);

    u8 ss1 = u8_malloc(32);
    u8 enc = u8_malloc(32);
    auth_encap_avx512(&ss1, &enc, &pkR, &skS, &pkS);
    printf("ss1: ");
    u8_print(&ss1);
    printf("enc: ");
    u8_print(&enc);

    u8 ss2 = u8_malloc(32);
    auth_decap_avx512(&ss2, &enc, &skR, &pkR, &pkS);
    printf("ss2: ");
    u8_print(&ss2);

    u8_free(&skS);
    u8_free(&pkS);

    u8_free(&skR);
    u8_free(&pkR);

    u8_free(&ss1);
    u8_free(&ss2);
    u8_free(&enc);

    return 0;
}