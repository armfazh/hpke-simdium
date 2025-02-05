#include "x25519_avx2.h"
#include "x25519_ossl.h"
#include <stdio.h>

void keygen(u8 *sk, u8 *pk)
{
#ifdef XIMPL_OSSL
    keygen_ossl(sk, pk);
#elif XIMPL_AVX2
    keygen_avx2(sk, pk);
#endif
}

void shared(u8 *shared_secret, u8 *sk, u8 *pk)
{
#if XIMPL_OSSL
    shared_ossl(shared_secret, sk, pk);
#elif XIMPL_AVX2
    shared_avx2(shared_secret, sk, pk);
#endif
}