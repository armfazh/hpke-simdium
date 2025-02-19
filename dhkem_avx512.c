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
#include "dhkem_avx512.h"

#include <string.h>
#include <faz_ecdh_avx2.h>

void encap_avx512(u8 *dh, u8 *kem_context, u8 *enc, u8 *pkR)
{
    u8_static(gen, 32);
    u8_static(skE, 32);
    u8_static(pkE, 32);
    struct X25519_KEY_x2 ss, sk, pk;

    gen.data[0] = 9;
    X25519_AVX512.randKey(skE.data);
    memcpy(sk.k0,skE.data,skE.len);
    memcpy(sk.k1,skE.data,skE.len);

    memcpy(pk.k0,gen.data,gen.len);
    memcpy(pk.k1,pkR->data,pkR->len);

    X25519_AVX512.shared(&ss,&pk,&sk);
    memcpy(pkE.data,ss.k0,pkE.len);
    memcpy(dh->data,ss.k1,32);
    u8_copy(enc, &pkE);

    uint8_t *kc = kem_context->data;
    u8_append(&kc,enc);
    u8_append(&kc,pkR);
}

void decap_avx512(u8 *dh, u8 *kem_context, u8 *enc, u8 *skR, u8 *pkR)
{
    X25519_AVX2.shared(dh->data, skR->data, enc->data);

    uint8_t *kc = kem_context->data;
    u8_append(&kc,enc);
    u8_append(&kc,pkR);
}

void auth_encap_avx512(u8 *dh, u8 *kem_context, u8 *enc, u8 *pkR, u8 *skS, u8 *pkS)
{
    u8_static(skE, 32);
    u8_static(pkE, 32);

    X25519_AVX2.keygen(skE.data, pkE.data);

    struct X25519_KEY_x2 ss, sk, pk;
    memcpy(sk.k0,skE.data,skE.len);
    memcpy(sk.k1,skS->data,skS->len);

    memcpy(pk.k0,pkR->data,pkR->len);
    memcpy(pk.k1,pkR->data,pkR->len);

    X25519_AVX512.shared(&ss,&pk,&sk);
    memcpy(&dh->data[0], ss.k0,32);
    memcpy(&dh->data[32],ss.k1,32);
    u8_copy(enc, &pkE);

    uint8_t *kc = kem_context->data;
    u8_append(&kc,enc);
    u8_append(&kc,pkR);
    u8_append(&kc,pkS);
}

void auth_decap_avx512(u8 *dh, u8 *kem_context, u8 *enc, u8 *skR, u8 *pkR, u8 *pkS)
{
    struct X25519_KEY_x2 ss, sk, pk;
    memcpy(sk.k0,skR->data,skR->len);
    memcpy(sk.k1,skR->data,skR->len);

    memcpy(pk.k0,enc->data,enc->len);
    memcpy(pk.k1,pkS->data,pkS->len);

    X25519_AVX512.shared(&ss,&pk,&sk);
    memcpy(&dh->data[0], ss.k0,32);
    memcpy(&dh->data[32],ss.k1,32);

    uint8_t *kc = kem_context->data;
    u8_append(&kc,enc);
    u8_append(&kc,pkR);
    u8_append(&kc,pkS);
}
