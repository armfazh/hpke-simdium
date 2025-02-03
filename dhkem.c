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
#include "x25519.h"
#include "types.h"

#include <stdio.h>
#include <string.h>

void extract_and_expand(u8 *shared_secret, u8 *dh, u8 *kem_context)
{
    u8 label_eae = u8_string("eae_prk");
    u8 label_shared_secret = u8_string("shared_secret");
    u8_static(eae_prk, 32);
    u8_static(empty_salt, 32);
    labeled_extract(&eae_prk, dh, &empty_salt, &label_eae);
    labeled_expand(shared_secret, &eae_prk, kem_context, &label_shared_secret);
}

void encap(u8 *shared_secret, u8 *enc, u8 *pkR)
{
    u8_static(skE, 32);
    u8_static(pkE, 32);
    u8_static(dh, 32);

    keygen(&skE, &pkE);
    shared(&dh, &skE, pkR);
    u8_copy(enc, &dh);

    u8_static(kem_context, 2 * 32);
    uint8_t *ptr = kem_context.data;
    memcpy(ptr, enc->data, enc->len);
    ptr += enc->len;
    memcpy(ptr, pkR->data, pkR->len);

    extract_and_expand(shared_secret, &dh, &kem_context);
}

// void decap(uint8_t *shared_secret, uint8_t *enc, uint8_t *skR) {}
// void auth_encap(uint8_t *shared_secret, uint8_t *enc, uint8_t *pkR, uint8_t *pkS) {}
// void auth_decap(uint8_t *shared_secret, uint8_t *enc, uint8_t *skR, uint8_t *pkS) {}

int main_dhkem()
{
    u8 skR = u8_malloc(32);
    u8 pkR = u8_malloc(32);
    keygen(&skR, &pkR);
    printf("skR: ");
    u8_print(&skR);
    printf("pkR: ");
    u8_print(&pkR);

    u8 ss = u8_malloc(32);
    u8 enc = u8_malloc(32);
    encap(&ss, &enc, &pkR);
    printf("ss: ");
    u8_print(&ss);
    printf("enc: ");
    u8_print(&enc);

    u8_free(&skR);
    u8_free(&pkR);

    u8_free(&ss);
    u8_free(&enc);

    return 0;
}