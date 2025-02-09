#include "clocks.h"
#include "x25519.h"
#include "x25519_avx2.h"
#include "x25519_ossl.h"
#include "x25519_bssl.h"

static void bench_x25519_any(struct xdh *x)
{
  u8_static(sk, 32);
  u8_static(pk, 32);
  u8_static(ss, 32);
  x->keygen(&sk, &pk);

  oper_second(, keygen, x->keygen(&sk, &pk));
  oper_second(, shared, x->shared(&ss, &sk, &pk));
}

void bench_x25519(void)
{
  printf("===== Benchmarking DH ====\n");
  printf("======  X25519 x64  ======\n");
  bench_x25519_any(&XDH_x64);
  printf("======  X25519 AVX2 ======\n");
  bench_x25519_any(&XDH_AVX2);
  printf("======  X25519 BSSL ======\n");
  bench_x25519_any(&XDH_bssl);
  printf("======  X25519 OSSL ======\n");
  bench_x25519_any(&XDH_ossl);
}
