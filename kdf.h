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
#ifndef _KDF_H_
#define _KDF_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "types.h"

void extract_and_expand(u8 *shared_secret, const u8 *dh, const u8 *kem_context);
void extract_and_expand_single(u8 *shared_secret, const u8 *dh, const u8 *kem_context);

extern void hkdf_extract(u8 *key, const u8 *secret, const u8 *salt);
extern void hkdf_expand(u8 *out, const u8 *key, const u8 *info);
extern void hkdf_extract_expand(u8 *out, const u8 *secret, const u8 *info);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* _KDF_H_ */
