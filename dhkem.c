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

void extract_and_expand(u8 *shared_secret, u8 *dh, u8 *kem_context)
{
    u8 label_eae = u8_string("eae_prk");
    u8 label_shared_secret = u8_string("shared_secret");
    u8 eae_prk = u8_malloc(32);
    u8 empty_salt = u8_malloc(32);
    labeled_extract(&eae_prk, dh, &empty_salt, &label_eae);
    labeled_expand(shared_secret, &eae_prk, kem_context, &label_shared_secret);
    u8_free(&eae_prk);
    u8_free(&empty_salt);
}

// void encap(u8 *shared_secret, u8 *enc, u8 *pkR)
// {
// keygen();
// }

// void decap(uint8_t *shared_secret, uint8_t *enc, uint8_t *skR) {}
// void auth_encap(uint8_t *shared_secret, uint8_t *enc, uint8_t *pkR, uint8_t *pkS) {}
// void auth_decap(uint8_t *shared_secret, uint8_t *enc, uint8_t *skR, uint8_t *pkS) {}

int main_dhkem()
{
    u8 ss = u8_malloc(32);
    u8 dh = u8_malloc(32);
    u8 ctx = u8_malloc(32);

    extract_and_expand(&ss, &dh, &ctx);

    printf("ss: ");
    u8_print(&ss);

    u8_free(&ss);
    u8_free(&dh);
    u8_free(&ctx);

    return 0;
}