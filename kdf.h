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

#include <stdint.h>
#include <stddef.h>

void extract(uint8_t *key, size_t key_len, uint8_t *secret, size_t secret_len, uint8_t *salt, size_t salt_len);
void expand(uint8_t *out, size_t out_len, uint8_t *key, size_t key_len, uint8_t *info, size_t info_len);
int main_kdf();

#endif /* _DHKEM_H_ */
