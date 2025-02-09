#include "clocks.h"

#include <dhkem.h>
#include <x25519_avx2.h>
#include <x25519_ossl.h>
#include <x25519_bssl.h>

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

void bench_dhkem_encapdecap_ossl()
{
  // int mode = OSSL_HPKE_MODE_BASE;
  // OSSL_HPKE_SUITE suite = OSSL_HPKE_SUITE_DEFAULT;
  // EVP_PKEY *priv = NULL;
  // unsigned char pub[32];
  // size_t publen = sizeof(pub);
  // OSSL_HPKE_keygen(suite, pub, &publen, &priv, NULL, 0, NULL, NULL);

  // unsigned char enc[32];
  // size_t enclen = sizeof(enc);

  // OSSL_HPKE_CTX *sctx = OSSL_HPKE_CTX_new(mode, suite, OSSL_HPKE_ROLE_SENDER,
  // NULL, NULL); OSSL_HPKE_encap(sctx, enc, &enclen, pub, publen, NULL, 0);
  // OSSL_HPKE_CTX_free(sctx);

  // OSSL_HPKE_CTX *rctx = OSSL_HPKE_CTX_new(mode, suite,
  // OSSL_HPKE_ROLE_RECEIVER, NULL, NULL); OSSL_HPKE_decap(rctx, enc, enclen,
  // priv, NULL, 0); OSSL_HPKE_CTX_free(rctx);

  // oper_second(, OSSL_HPKE_keygen,
  //             EVP_PKEY *sk = NULL;
  //             OSSL_HPKE_keygen(suite, pub, &publen, &sk, NULL, 0, NULL,
  //             NULL); EVP_PKEY_free(sk));

  // oper_second(, OSSL_HPKE_encap,
  //             OSSL_HPKE_CTX *sctx = OSSL_HPKE_CTX_new(mode, suite,
  //             OSSL_HPKE_ROLE_SENDER, NULL, NULL); OSSL_HPKE_encap(sctx, enc,
  //             &enclen, pub, publen, NULL, 0); OSSL_HPKE_CTX_free(sctx));

  // oper_second(, OSSL_HPKE_decap,
  //             OSSL_HPKE_CTX *rctx = OSSL_HPKE_CTX_new(mode, suite,
  //             OSSL_HPKE_ROLE_RECEIVER, NULL, NULL); OSSL_HPKE_decap(rctx,
  //             enc, enclen, priv, NULL, 0); OSSL_HPKE_CTX_free(rctx));

  // EVP_PKEY_free(priv);
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
  // printf("==== HPKE OSSL ====\n");
  // bench_dhkem_encapdecap_ossl();

  printf("===== Benchmarking AuthDHKEM ====\n");
  printf("==== AuthEncapDecap x64 ====\n");
  bench_dhkem_authencapdecap(&XDH_x64);
  printf("==== AuthEncapDecap AVX2 ====\n");
  bench_dhkem_authencapdecap(&XDH_AVX2);
  printf("==== AuthEncapDecap OSSL ====\n");
  bench_dhkem_authencapdecap(&XDH_ossl);
  printf("==== AuthEncapDecap BSSL ====\n");
  bench_dhkem_authencapdecap(&XDH_bssl);
}
