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
#include "bench_dhkem.h"

#include <dhkem_avx2.h>
#include <faz_ecdh_avx2.h>

#include "clocks.h"

static void keygen_x64(u8 *sk, u8 *pk)
{
    X25519_x64.randKey(sk->data);
    X25519_x64.keygen(pk->data, sk->data);
}

static void shared_x64(u8 *shared_secret, u8 *sk, u8 *pk)
{
    X25519_x64.shared(shared_secret->data, pk->data, sk->data);
}

static void keygen_avx2(u8 *sk, u8 *pk)
{
    X25519_AVX2.randKey(sk->data);
    X25519_AVX2.keygen(pk->data, sk->data);
}

static void shared_avx2(u8 *shared_secret, u8 *sk, u8 *pk)
{
    X25519_AVX2.shared(shared_secret->data, pk->data, sk->data);
}

struct xdh XDH_AVX2 =
{
    .name = "AVX2",
    .keygen = keygen_avx2,
    .shared = shared_avx2,
};

struct xdh XDH_x64 =
{
    .name = "x64",
    .keygen = keygen_x64,
    .shared = shared_x64,
};
