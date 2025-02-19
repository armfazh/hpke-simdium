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
#ifndef _BENCH_H_
#define _BENCH_H_

#include "dhkem.h"

void bench_dhkem(void);
void bench_x25519(struct xdh *x);
void bench_dhkem_encapdecap(struct xdh *x);
void bench_dhkem_authencapdecap(struct xdh *x);

#endif /* _BENCH_H_ */
