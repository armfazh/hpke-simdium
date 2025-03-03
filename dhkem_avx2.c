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
#include "dhkem_avx2.h"

#include <faz_ecdh_avx2.h>

void encap_avx2(u8 *dh, u8 *kem_context, u8 *enc, u8 *pkR, u8 *skE)
{
    u8_static(pkE, 32);

    X25519_AVX2.keygen(pkE.data, skE->data);
    X25519_AVX2.shared(dh->data, pkR->data, skE->data);
    u8_copy(enc, &pkE);

    uint8_t *kc = kem_context->data;
    u8_append(&kc, enc);
    u8_append(&kc, pkR);
}

void decap_avx2(u8 *dh, u8 *kem_context, u8 *enc, u8 *skR, u8 *pkR)
{
    X25519_AVX2.shared(dh->data, enc->data, skR->data);

    uint8_t *kc = kem_context->data;
    u8_append(&kc, enc);
    u8_append(&kc, pkR);
}

void auth_encap_avx2(u8 *dh, u8 *kem_context, u8 *enc, u8 *pkR, u8 *skS,
                     u8 *pkS, u8 *skE)
{
    u8_static(pkE, 32);

    X25519_AVX2.keygen(pkE.data, skE->data);
    X25519_AVX2.shared(&dh->data[0], pkR->data, skE->data);
    X25519_AVX2.shared(&dh->data[32], pkR->data, skS->data);
    u8_copy(enc, &pkE);

    uint8_t *kc = kem_context->data;
    u8_append(&kc, enc);
    u8_append(&kc, pkR);
    u8_append(&kc, pkS);
}

void auth_decap_avx2(u8 *dh, u8 *kem_context, u8 *enc, u8 *skR, u8 *pkR,
                     u8 *pkS)
{
    X25519_AVX2.shared(&dh->data[0], enc->data, skR->data);
    X25519_AVX2.shared(&dh->data[32], pkS->data, skR->data);

    uint8_t *kc = kem_context->data;
    u8_append(&kc, enc);
    u8_append(&kc, pkR);
    u8_append(&kc, pkS);
}
