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
#include "dhkem.h"

void encap(struct xdh *x, u8 *dh, u8 *kem_context, u8 *enc, u8 *pkR)
{
    u8_static(skE, 32);
    u8_static(pkE, 32);

    x->keygen(&skE, &pkE);
    x->shared(dh, &skE, pkR);
    u8_copy(enc, &pkE);

    uint8_t *kc = kem_context->data;
    u8_append(&kc, enc);
    u8_append(&kc, pkR);
}

void decap(struct xdh *x, u8 *dh, u8 *kem_context, u8 *enc, u8 *skR, u8 *pkR)
{
    x->shared(dh, skR, enc);

    uint8_t *kc = kem_context->data;
    u8_append(&kc, enc);
    u8_append(&kc, pkR);
}

void auth_encap(struct xdh *x, u8 *dh, u8 *kem_context, u8 *enc, u8 *pkR,
                u8 *skS, u8 *pkS)
{
    u8_static(skE, 32);
    u8_static(pkE, 32);
    u8_static(dh1, 32);
    u8_static(dh2, 32);

    x->keygen(&skE, &pkE);
    x->shared(&dh1, &skE, pkR);
    x->shared(&dh2, skS, pkR);
    u8_copy(enc, &pkE);

    uint8_t *dh1_dh2 = dh->data;
    u8_append(&dh1_dh2, &dh1);
    u8_append(&dh1_dh2, &dh2);

    uint8_t *kc = kem_context->data;
    u8_append(&kc, enc);
    u8_append(&kc, pkR);
    u8_append(&kc, pkS);
}

void auth_decap(struct xdh *x, u8 *dh, u8 *kem_context, u8 *enc, u8 *skR,
                u8 *pkR, u8 *pkS)
{
    u8_static(dh1, 32);
    u8_static(dh2, 32);
    x->shared(&dh1, skR, enc);
    x->shared(&dh2, skR, pkS);

    uint8_t *dh1_dh2 = dh->data;
    u8_append(&dh1_dh2, &dh1);
    u8_append(&dh1_dh2, &dh2);

    uint8_t *kc = kem_context->data;
    u8_append(&kc, enc);
    u8_append(&kc, pkR);
    u8_append(&kc, pkS);
}
