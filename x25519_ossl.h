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
#ifndef _X25519_OSSL_H_
#define _X25519_OSSL_H_

#include "types.h"

void keygen_ossl(u8 *sk, u8 *pk);
void shared_ossl(u8 *shared_secret, u8 *sk, u8 *pk);

int main_x25519_ossl();

#endif /* _X25519_OSSL_H_ */
