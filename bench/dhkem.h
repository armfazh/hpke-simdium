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
#ifndef _DHKEM_H_
#define _DHKEM_H_

#include "types.h"

struct xdh {
    char *name;
    void (*keygen)(u8 *sk, u8 *pk);
    void (*shared)(u8 *shared_secret, u8 *sk, u8 *pk);
};

void encap(struct xdh *x, u8 *dh, u8 *kem_context, u8 *enc, u8 *pkR);
void decap(struct xdh *x, u8 *dh, u8 *kem_context, u8 *enc, u8 *skR, u8 *pkR);
void auth_encap(struct xdh *x, u8 *dh, u8 *kem_context, u8 *enc, u8 *pkR, u8 *skS, u8 *pkS);
void auth_decap(struct xdh *x, u8 *dh, u8 *kem_context, u8 *enc, u8 *skR, u8 *pkR, u8 *pkS);

#endif /* _DHKEM_H_ */
