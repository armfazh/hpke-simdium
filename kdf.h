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

void extract_and_expand(u8 *shared_secret, u8 *dh, u8 *kem_context);

int main_kdf();

#endif /* _KDF_H_ */
