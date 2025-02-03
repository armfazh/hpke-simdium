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

void extract_and_expand(u8 *shared_secret, u8 *dh, u8 *kem_context);
void encap(u8 *shared_secret, u8 *enc, u8 *pkR);
void decap(u8 *shared_secret, u8 *enc, u8 *skR, u8 *pkR);
void auth_encap(uint8_t *shared_secret, uint8_t *enc, uint8_t *pkR, uint8_t *pkS);
void auth_decap(uint8_t *shared_secret, uint8_t *enc, uint8_t *skR, uint8_t *pkS);

int main_dhkem();

#endif /* _DHKEM_H_ */
