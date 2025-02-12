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
#include "bench.h"

#include <x25519_ossl.h>
#include <x25519_bssl.h>

int main()
{
    info_ossl();
    info_bssl();

    bench_x25519();
    // bench_dhkem();

    return 0;
}