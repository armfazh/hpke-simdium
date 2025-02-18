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
#ifndef _BENCH_H_
#define _BENCH_H_

#include "dhkem.h"

void bench_dhkem(void);
void bench_x25519(struct xdh *x);
void bench_dhkem_encapdecap(struct xdh *x);
void bench_dhkem_authencapdecap(struct xdh *x);

#endif /* _BENCH_H_ */
