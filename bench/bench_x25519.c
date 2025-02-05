#include <faz_ecdh_avx2.h>
#include "clocks.h"
#include <x25519_ossl.h>

static void bench_ecdh_avx2(const X_ECDH *ecdh)
{
  argECDHX_Key secret_key = ecdh->allocKey();
  argECDHX_Key session_key = ecdh->allocKey();
  argECDHX_Key shared_secret = ecdh->allocKey();

  ecdh->randKey(secret_key);

  oper_second(ecdh->randKey(secret_key), ecdh->keygen,
              ecdh->keygen(session_key, secret_key));

  oper_second(ecdh->randKey(secret_key);
              ecdh->randKey(session_key), ecdh->shared,
              ecdh->shared(shared_secret, session_key, secret_key));
  ecdh->freeKey(secret_key);
  ecdh->freeKey(session_key);
  ecdh->freeKey(shared_secret);
}

void bench_ecdh_ossl(void)
{
  u8_static(sk, 32);
  u8_static(pk, 32);
  u8_static(ss, 32);

  oper_second(, keygen_ossl, keygen_ossl(&sk, &pk));
  oper_second(, shared_ossl, shared_ossl(&ss, &sk, &pk));
}

void bench_x25519(void)
{
  printf("===== Benchmarking DH ====\n");
  printf("======  X25519 x64  ======\n");
  bench_ecdh_avx2(&X25519_x64);
  printf("======  X25519 AVX2 ======\n");
  bench_ecdh_avx2(&X25519);
  printf("======  X25519 OSSL ======\n");
  bench_ecdh_ossl();
}
