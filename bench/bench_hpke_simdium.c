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
#include<stdio.h>
#include "bench_dhkem.h"

extern void bench_x25519_avx512();
extern void bench_dhkem_encapdecap_avx512();
extern void bench_dhkem_authencapdecap_avx512();
extern struct xdh XDH_x64, XDH_AVX2;

int main()
{
    printf("==== Benchmarking DH ====\n");
    printf("====== X25519 x64  ======\n");
    bench_x25519(&XDH_x64);
    printf("====== X25519 AVX2 ======\n");
    bench_x25519(&XDH_AVX2);
#if defined(ENABLED_AVX512)
    printf("====== X25519 AVX512 ====\n");
    bench_x25519_avx512();
#endif /* defined(ENABLED_AVX512) */

    printf("===== Benchmarking DHKEM ====\n");
    printf("====== EncapDecap x64 ======\n");
    bench_dhkem_encapdecap(&XDH_x64);
    printf("====== EncapDecap AVX2 ======\n");
    bench_dhkem_encapdecap(&XDH_AVX2);
#if defined(ENABLED_AVX512)
    printf("====== EncapDecap AVX512 =====\n");
    bench_dhkem_encapdecap_avx512();
#endif /* defined(ENABLED_AVX512) */
    printf("===== Benchmarking AuthDHKEM ====\n");
    printf("==== AuthEncapDecap x64 ====\n");
    bench_dhkem_authencapdecap(&XDH_x64);
    printf("==== AuthEncapDecap AVX2 ====\n");
    bench_dhkem_authencapdecap(&XDH_AVX2);
#if defined(ENABLED_AVX512)
    printf("==== AuthEncapDecap AVX512 ====\n");
    bench_dhkem_authencapdecap_avx512();
#endif /* defined(ENABLED_AVX512) */

    return 0;
}
