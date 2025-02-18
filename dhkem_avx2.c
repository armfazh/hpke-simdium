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
#include "dhkem_avx2.h"

#include <stdio.h>
#include <string.h>

#include "kdf.h"
#include <faz_ecdh_avx2.h>

void encap_avx2(u8 *shared_secret, u8 *enc, u8 *pkR)
{
    u8_static(skE, 32);
    u8_static(pkE, 32);
    u8_static(dh, 32);

    X25519_AVX2.keygen(skE.data, pkE.data);
    X25519_AVX2.shared(dh.data, skE.data, pkR->data);
    u8_copy(enc, &pkE);

    u8_static(kem_context, 2 * 32);
    uint8_t *ptr = kem_context.data;
    memcpy(ptr, enc->data, enc->len);
    ptr += enc->len;
    memcpy(ptr, pkR->data, pkR->len);

    extract_and_expand_single(shared_secret, &dh, &kem_context);
}

void decap_avx2( u8 *shared_secret, u8 *enc, u8 *skR, u8 *pkR)
{
    u8_static(dh, 32);
    X25519_AVX2.shared(dh.data, skR->data, enc->data);

    u8_static(kem_context, 2 * 32);
    uint8_t *ptr = kem_context.data;
    memcpy(ptr, enc->data, enc->len);
    ptr += enc->len;
    memcpy(ptr, pkR->data, pkR->len);

    extract_and_expand_single(shared_secret, &dh, &kem_context);
}

void auth_encap_avx2( u8 *shared_secret, u8 *enc, u8 *pkR, u8 *skS, u8 *pkS)
{
    u8_static(skE, 32);
    u8_static(pkE, 32);
    u8_static(dh1, 32);
    u8_static(dh2, 32);

    X25519_AVX2.keygen(skE.data, pkE.data);
    X25519_AVX2.shared(dh1.data, skE.data, pkR->data);
    X25519_AVX2.shared(dh2.data, skS->data, pkR->data);

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

    extract_and_expand_single(shared_secret, &dh, &kem_context);
}

void auth_decap_avx2( u8 *shared_secret, u8 *enc, u8 *skR, u8 *pkR, u8 *pkS)
{
    u8_static(dh1, 32);
    u8_static(dh2, 32);
    X25519_AVX2.shared(dh1.data, skR->data, enc->data);
    X25519_AVX2.shared(dh2.data, skR->data, pkS->data);

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

    extract_and_expand_single(shared_secret, &dh, &kem_context);
}
