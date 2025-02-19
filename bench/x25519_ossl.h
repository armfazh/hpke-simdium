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
#ifndef _X25519_OSSL_H_
#define _X25519_OSSL_H_

#include "dhkem.h"

extern struct xdh XDH_ossl;
void info_ossl(void);

#endif /* _X25519_OSSL_H_ */
