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
#ifndef _DHKEM_H_
#define _DHKEM_H_

#include "types.h"

struct xdh
{
    char *name;
    void (*keygen)(u8 *sk, u8 *pk);
    void (*shared)(u8 *shared_secret, u8 *sk, u8 *pk);
};

void encap(struct xdh *x, u8 *dh, u8 *kem_context, u8 *enc, u8 *pkR);
void decap(struct xdh *x, u8 *dh, u8 *kem_context, u8 *enc, u8 *skR, u8 *pkR);
void auth_encap(struct xdh *x, u8 *dh, u8 *kem_context, u8 *enc, u8 *pkR,
                u8 *skS, u8 *pkS);
void auth_decap(struct xdh *x, u8 *dh, u8 *kem_context, u8 *enc, u8 *skR,
                u8 *pkR, u8 *pkS);

#endif /* _DHKEM_H_ */
