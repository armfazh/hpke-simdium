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
#include "clocks.h"
#include <sys/time.h>
#include <time.h>

uint64_t time_now(void)
{
    struct timeval tv;
    uint64_t ret;

    gettimeofday(&tv, NULL);
    ret = tv.tv_sec;
    ret *= 1000000;
    ret += tv.tv_usec;

    return ret;
}

/**
 * Taken from
 * agl/curve25519-donna
 * https://github.com/agl/curve25519-donna/blob/master/speed-curve25519.c
 *
 * ticks - not tested on anything other than x86
 * */
uint64_t cycles_now(void)
{
#if defined(__GNUC__)
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)lo | ((uint64_t)hi << 32));
#else
    return 0; /* Undefined for now; should be obvious in the output */
#endif
}
