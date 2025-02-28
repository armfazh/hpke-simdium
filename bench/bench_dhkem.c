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
#include "clocks.h"

void bench_x25519(struct xdh *x)
{
    u8_static(sk, 32);
    u8_static(pk, 32);
    u8_static(ss, 32);
    x->keygen(&sk, &pk);
    x->shared(&ss, &sk, &pk);

    oper_second(, keygen, x->keygen(&sk, &pk));
    oper_second(, shared, x->shared(&ss, &sk, &pk));
}

void bench_dhkem_encapdecap(struct xdh *x)
{
    u8 skR = u8_malloc(32);
    u8 pkR = u8_malloc(32);
    x->keygen(&skR, &pkR);

    u8 dh = u8_malloc(32);
    u8 kc = u8_malloc(2 * 32);
    u8 enc = u8_malloc(32);
    encap(x, &dh, &kc, &enc, &pkR);
    decap(x, &dh, &kc, &enc, &skR, &pkR);

    oper_second(, keygen, x->keygen(&skR, &pkR));
    oper_second(, encap, encap(x, &dh, &kc, &enc, &pkR));
    oper_second(, decap, decap(x, &dh, &kc, &enc, &skR, &pkR));

    u8_free(&skR);
    u8_free(&pkR);

    u8_free(&dh);
    u8_free(&kc);
    u8_free(&enc);
}

void bench_dhkem_authencapdecap(struct xdh *x)
{
    u8 skS = u8_malloc(32);
    u8 pkS = u8_malloc(32);
    x->keygen(&skS, &pkS);

    u8 skR = u8_malloc(32);
    u8 pkR = u8_malloc(32);
    x->keygen(&skR, &pkR);

    u8 dh = u8_malloc(2 * 32);
    u8 kc = u8_malloc(3 * 32);
    u8 enc = u8_malloc(32);
    auth_encap(x, &dh, &kc, &enc, &pkR, &skS, &pkS);
    auth_decap(x, &dh, &kc, &enc, &skR, &pkR, &pkS);

    oper_second(, keygen, x->keygen(&skR, &pkR));
    oper_second(, auth_encap, auth_encap(x, &dh, &kc, &enc, &pkR, &skS, &pkS));
    oper_second(, auth_decap, auth_decap(x, &dh, &kc, &enc, &skR, &pkR, &pkS));

    u8_free(&skS);
    u8_free(&pkS);

    u8_free(&skR);
    u8_free(&pkR);

    u8_free(&dh);
    u8_free(&kc);
    u8_free(&enc);
}
