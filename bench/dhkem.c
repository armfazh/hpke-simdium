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

void encap(struct xdh *x, u8 *shared_secret, u8 *enc, u8 *pkR)
{
    u8_static(skE, 32);
    u8_static(pkE, 32);
    u8_static(dh, 32);

    x->keygen(&skE, &pkE);
    x->shared(&dh, &skE, pkR);
    u8_copy(enc, &pkE);

    u8_static(kem_context, 2 * 32);
    uint8_t *ptr = kem_context.data;
    memcpy(ptr, enc->data, enc->len);
    ptr += enc->len;
    memcpy(ptr, pkR->data, pkR->len);

    extract_and_expand_single(shared_secret, &dh, &kem_context);
}

void decap(struct xdh *x, u8 *shared_secret, u8 *enc, u8 *skR, u8 *pkR)
{
    u8_static(dh, 32);
    x->shared(&dh, skR, enc);

    u8_static(kem_context, 2 * 32);
    uint8_t *ptr = kem_context.data;
    memcpy(ptr, enc->data, enc->len);
    ptr += enc->len;
    memcpy(ptr, pkR->data, pkR->len);

    extract_and_expand_single(shared_secret, &dh, &kem_context);
}

void auth_encap(struct xdh *x, u8 *shared_secret, u8 *enc, u8 *pkR, u8 *skS, u8 *pkS)
{
    u8_static(skE, 32);
    u8_static(pkE, 32);
    u8_static(dh1, 32);
    u8_static(dh2, 32);

    x->keygen(&skE, &pkE);
    x->shared(&dh1, &skE, pkR);
    x->shared(&dh2, skS, pkR);

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

void auth_decap(struct xdh *x, u8 *shared_secret, u8 *enc, u8 *skR, u8 *pkR, u8 *pkS)
{
    u8_static(dh1, 32);
    u8_static(dh2, 32);
    x->shared(&dh1, skR, enc);
    x->shared(&dh2, skR, pkS);

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

int main_dhkem(struct xdh *x)
{
    u8 skR = u8_malloc(32);
    u8 pkR = u8_malloc(32);
    x->keygen(&skR, &pkR);
    printf("skR: ");
    u8_print(&skR);
    printf("pkR: ");
    u8_print(&pkR);

    u8 ss1 = u8_malloc(32);
    u8 enc = u8_malloc(32);
    encap(x, &ss1, &enc, &pkR);
    printf("ss1: ");
    u8_print(&ss1);
    printf("enc: ");
    u8_print(&enc);

    u8 ss2 = u8_malloc(32);
    decap(x, &ss2, &enc, &skR, &pkR);
    printf("ss2: ");
    u8_print(&ss2);

    u8_free(&skR);
    u8_free(&pkR);

    u8_free(&ss1);
    u8_free(&ss2);
    u8_free(&enc);

    return 0;
}

int main_auth_dhkem(struct xdh *x)
{
    u8 skS = u8_malloc(32);
    u8 pkS = u8_malloc(32);
    x->keygen(&skS, &pkS);
    printf("skS: ");
    u8_print(&skS);
    printf("pkS: ");
    u8_print(&pkS);

    u8 skR = u8_malloc(32);
    u8 pkR = u8_malloc(32);
    x->keygen(&skR, &pkR);
    printf("skR: ");
    u8_print(&skR);
    printf("pkR: ");
    u8_print(&pkR);

    u8 ss1 = u8_malloc(32);
    u8 enc = u8_malloc(32);
    auth_encap(x, &ss1, &enc, &pkR, &skS, &pkS);
    printf("ss1: ");
    u8_print(&ss1);
    printf("enc: ");
    u8_print(&enc);

    u8 ss2 = u8_malloc(32);
    auth_decap(x, &ss2, &enc, &skR, &pkR, &pkS);
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