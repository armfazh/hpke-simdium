#include "clocks.h"

#include <dhkem.h>
#include <x25519_avx2.h>
#include <x25519_ossl.h>
#include <x25519_bssl.h>
#include <dhkem_ossl.h>
#include <dhkem_bssl.h>

void bench_dhkem_encapdecap(struct xdh *x)
{
    u8 skR = u8_malloc(32);
    u8 pkR = u8_malloc(32);
    x->keygen(&skR, &pkR);

    u8 ss1 = u8_malloc(32);
    u8 enc = u8_malloc(32);
    encap(x, &ss1, &enc, &pkR);

    u8 ss2 = u8_malloc(32);
    decap(x, &ss2, &enc, &skR, &pkR);

    oper_second(, keygen, x->keygen(&skR, &pkR));
    oper_second(, encap, encap(x, &ss1, &enc, &pkR));
    oper_second(, decap, decap(x, &ss2, &enc, &skR, &pkR));

    u8_free(&skR);
    u8_free(&pkR);

    u8_free(&ss1);
    u8_free(&ss2);
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

    u8 ss1 = u8_malloc(32);
    u8 enc = u8_malloc(32);
    auth_encap(x, &ss1, &enc, &pkR, &skS, &pkS);

    u8 ss2 = u8_malloc(32);
    auth_decap(x, &ss2, &enc, &skR, &pkR, &pkS);

    oper_second(, keygen, x->keygen(&skR, &pkR));
    oper_second(, auth_encap, auth_encap(x, &ss1, &enc, &pkR, &skS, &pkS));
    oper_second(, auth_decap, auth_decap(x, &ss2, &enc, &skR, &pkR, &pkS));

    u8_free(&skS);
    u8_free(&pkS);

    u8_free(&skR);
    u8_free(&pkR);

    u8_free(&ss1);
    u8_free(&ss2);
    u8_free(&enc);
}

void bench_dhkem(void)
{
    printf("===== Benchmarking DHKEM ====\n");
    printf("====== EncapDecap x64 ======\n");
    bench_dhkem_encapdecap(&XDH_x64);
    printf("====== EncapDecap AVX2 ======\n");
    bench_dhkem_encapdecap(&XDH_AVX2);
    printf("====== EncapDecap OSSL ======\n");
    bench_dhkem_encapdecap(&XDH_ossl);
    printf("====== EncapDecap BSSL ======\n");
    bench_dhkem_encapdecap(&XDH_bssl);
    printf("==== HPKE OSSL ====\n");
    bench_dhkem_encapdecap_ossl();
    printf("==== HPKE BSSL ====\n");
    bench_dhkem_encapdecap_bssl();

    printf("===== Benchmarking AuthDHKEM ====\n");
    printf("==== AuthEncapDecap x64 ====\n");
    bench_dhkem_authencapdecap(&XDH_x64);
    printf("==== AuthEncapDecap AVX2 ====\n");
    bench_dhkem_authencapdecap(&XDH_AVX2);
    printf("==== AuthEncapDecap OSSL ====\n");
    bench_dhkem_authencapdecap(&XDH_ossl);
    printf("==== AuthEncapDecap BSSL ====\n");
    bench_dhkem_authencapdecap(&XDH_bssl);
    printf("==== HPKE OSSL ====\n");
    bench_dhkem_auth_encapdecap_ossl();
    printf("==== AuthHPKE BSSL ====\n");
    bench_dhkem_auth_encapdecap_bssl();
}
