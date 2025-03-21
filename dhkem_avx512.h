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
#ifndef _DHKEM_AVX512_H_
#define _DHKEM_AVX512_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "types.h"

void encap_avx512(u8 *dh, u8 *kem_context, u8 *enc, u8 *pkR, u8 *skE);
void decap_avx512(u8 *dh, u8 *kem_context, u8 *enc, u8 *skR, u8 *pkR);
void auth_encap_avx512(u8 *dh, u8 *kem_context, u8 *enc, u8 *pkR, u8 *skS,
                       u8 *pkS, u8 *skE);
void auth_decap_avx512(u8 *dh, u8 *kem_context, u8 *enc, u8 *skR, u8 *pkR,
                       u8 *pkS);

#ifdef __cplusplus
} /* extern "C" */

#endif /* __cplusplus */

#endif /* _DHKEM_AVX512_H_ */
