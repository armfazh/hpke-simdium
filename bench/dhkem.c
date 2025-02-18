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
