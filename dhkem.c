#include "dhkem.h"

#include <immintrin.h>

#include "types.h"
#include "kdf.h"
#include "dhkem_avx2.h"
#include "dhkem_avx512.h"
#include "dhkem_x64.h"

void encap(u8 *shared, u8 *enc, u8 *pkR, u8 *skE)
{
    u8_static(dh, X255KEY_SIZE);
    u8_static(kc, 2 * X255KEY_SIZE);

    if (__builtin_cpu_supports("avx512f"))
    {
        encap_avx512(&dh, &kc, enc, pkR, skE);
    }
    else if (__builtin_cpu_supports("avx2"))
    {
        encap_avx2(&dh, &kc, enc, pkR, skE);
    }
    else
    {
        encap_x64(&dh, &kc, enc, pkR, skE);
    }

    extract_and_expand_single(shared, &dh, &kc);
}

void decap(u8 *shared, u8 *enc, u8 *skR, u8 *pkR)
{
    u8_static(dh, X255KEY_SIZE);
    u8_static(kc, 2 * X255KEY_SIZE);

    if (__builtin_cpu_supports("avx512f"))
    {
        decap_avx512(&dh, &kc, enc, skR, pkR);
    }
    else if (__builtin_cpu_supports("avx2"))
    {
        decap_avx2(&dh, &kc, enc, skR, pkR);
    }
    else
    {
        decap_x64(&dh, &kc, enc, skR, pkR);
    }

    extract_and_expand_single(shared, &dh, &kc);
}

void auth_encap(u8 *shared, u8 *enc, u8 *pkR, u8 *skS, u8 *pkS, u8 *skE)
{
    u8_static(dh, 2 * X255KEY_SIZE);
    u8_static(kc, 3 * X255KEY_SIZE);

    if (__builtin_cpu_supports("avx512f"))
    {
        auth_encap_avx512(&dh, &kc, enc, pkR, skS, pkS, skE);
    }
    else if (__builtin_cpu_supports("avx2"))
    {
        auth_encap_avx2(&dh, &kc, enc, pkR, skS, pkS, skE);
    }
    else
    {
        auth_encap_x64(&dh, &kc, enc, pkR, skS, pkS, skE);
    }

    extract_and_expand_single(shared, &dh, &kc);
}

void auth_decap(u8 *shared, u8 *enc, u8 *skR, u8 *pkR, u8 *pkS)
{
    u8_static(dh, 2 * X255KEY_SIZE);
    u8_static(kc, 3 * X255KEY_SIZE);

    if (__builtin_cpu_supports("avx512f"))
    {
        auth_decap_avx512(&dh, &kc, enc, skR, pkR, pkS);
    }
    else if (__builtin_cpu_supports("avx2"))
    {
        auth_decap_avx2(&dh, &kc, enc, skR, pkR, pkS);
    }
    else
    {
        auth_decap_x64(&dh, &kc, enc, skR, pkR, pkS);
    }

    extract_and_expand_single(shared, &dh, &kc);
}