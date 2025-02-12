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
#ifndef _DHKEM_AVX512_H_
#define _DHKEM_AVX512_H_

#include "types.h"

void encap_avx512(u8 *shared_secret, u8 *enc, u8 *pkR);
void decap_avx512(u8 *shared_secret, u8 *enc, u8 *skR, u8 *pkR);
void auth_encap_avx512(u8 *shared_secret, u8 *enc, u8 *pkR, u8 *skS, u8 *pkS);
void auth_decap_avx512(u8 *shared_secret, u8 *enc, u8 *skR, u8 *pkR, u8 *pkS);

int main_dhkem_avx512();
int main_auth_dhkem_avx512();

#endif /* _DHKEM_AVX512_H_ */
