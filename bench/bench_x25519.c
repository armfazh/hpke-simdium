#include "bench.h"
#include "clocks.h"

void bench_x25519(struct xdh *x)
{
    u8_static(sk, 32);
    u8_static(pk, 32);
    u8_static(ss, 32);
    x->keygen(&sk, &pk);

    oper_second(, keygen, x->keygen(&sk, &pk));
    oper_second(, shared, x->shared(&ss, &sk, &pk));
}