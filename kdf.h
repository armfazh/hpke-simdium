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

#ifndef _KDF_H_
#define _KDF_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "types.h"

void derive_key(u8* key, u8 *seed);
void extract_and_expand(u8 *shared_secret, const u8 *dh, const u8 *kem_context);
void extract_and_expand_single(u8 *shared_secret, const u8 *dh,
                               const u8 *kem_context);

extern void hkdf_extract(u8 *key, const u8 *secret, const u8 *salt);
extern void hkdf_expand(u8 *out, const u8 *key, const u8 *info);
extern void hkdf_extract_expand(u8 *out, const u8 *secret, const u8 *info);

#ifdef __cplusplus
} /* extern "C" */

#endif /* __cplusplus */

#endif /* _KDF_H_ */
