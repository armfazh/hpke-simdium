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

#include "types.h"

void labeled_extract(u8 *key, u8 *secret, u8 *salt, u8 *label);
void labeled_expand(u8 *out, u8 *key, u8 *info, u8 *label);

int main_kdf();

#endif /* _KDF_H_ */
