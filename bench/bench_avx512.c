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

#include <dhkem_avx512.h>
#include <faz_ecdh_avx2.h>

#include "clocks.h"

void bench_x25519_avx512()
{
    struct X25519_KEY_x2 ss, sk, pk;
    X25519_AVX512.keygen(&sk, &pk);
    X25519_AVX512.shared(&ss, &sk, &pk);

    oper_second(, keygen, X25519_AVX512.keygen(&sk, &pk));
    oper_second(, shared, X25519_AVX512.shared(&ss, &sk, &pk));
}

void bench_dhkem_encapdecap_avx512()
{
    u8 skE = u8_malloc(32);
    X25519_AVX2.randKey(skE.data);

    u8 skR = u8_malloc(32);
    u8 pkR = u8_malloc(32);
    X25519_AVX2.keygen(skR.data, pkR.data);

    u8 dh = u8_malloc(32);
    u8 kc = u8_malloc(2 * 32);
    u8 enc = u8_malloc(32);
    encap_avx512(&dh, &kc, &enc, &pkR, &skE);
    decap_avx512(&dh, &kc, &enc, &skR, &pkR);

    oper_second(, keygen, X25519_AVX2.keygen(skR.data, pkR.data));
    oper_second(, encap, encap_avx512(&dh, &kc, &enc, &pkR, &skE));
    oper_second(, decap, decap_avx512(&dh, &kc, &enc, &skR, &pkR));

    u8_free(&skE);
    u8_free(&skR);
    u8_free(&pkR);

    u8_free(&dh);
    u8_free(&kc);
    u8_free(&enc);
}

void bench_dhkem_authencapdecap_avx512()
{
    u8 skE = u8_malloc(32);
    X25519_AVX2.randKey(skE.data);

    u8 skS = u8_malloc(32);
    u8 pkS = u8_malloc(32);
    X25519_AVX2.keygen(skS.data, pkS.data);

    u8 skR = u8_malloc(32);
    u8 pkR = u8_malloc(32);
    X25519_AVX2.keygen(skR.data, pkR.data);

    u8 dh = u8_malloc(2 * 32);
    u8 kc = u8_malloc(3 * 32);
    u8 enc = u8_malloc(32);
    auth_encap_avx512(&dh, &kc, &enc, &pkR, &skS, &pkS, &skE);
    auth_decap_avx512(&dh, &kc, &enc, &skR, &pkR, &pkS);

    oper_second(, keygen, X25519_AVX2.keygen(skR.data, pkR.data));
    oper_second(, auth_encap, auth_encap_avx512(&dh, &kc, &enc, &pkR, &skS, &pkS,
                                                &skE));
    oper_second(, auth_decap, auth_decap_avx512(&dh, &kc, &enc, &skR, &pkR, &pkS));

    u8_free(&skE);
    u8_free(&skS);
    u8_free(&pkS);

    u8_free(&skR);
    u8_free(&pkR);

    u8_free(&dh);
    u8_free(&kc);
    u8_free(&enc);
}
