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
#ifndef _CLOCKS_H_
#define _CLOCKS_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __INTEL_COMPILER
#define BARRIER __memory_barrier()
#else
#define BARRIER __asm__ __volatile__("" ::: "memory")
#endif

#define CLOCKS_RANDOM(RANDOM, LABEL, FUNCTION)                           \
  do {                                                                   \
    uint64_t start, end;                                                 \
    int64_t i_bench, j_bench;                                            \
    unsigned cycles_high0, cycles_low0;                                  \
    unsigned cycles_high1, cycles_low1;                                  \
    __asm__ __volatile__(                                                \
        "mfence\n\t"                                                     \
        "RDTSC\n\t"                                                      \
        "mov %%edx, %0\n\t"                                              \
        "mov %%eax, %1\n\t"                                              \
        : "=r"(cycles_high0), "=r"(cycles_low0)::"%rax", "%rbx", "%rcx", \
          "%rdx");                                                       \
    BARRIER;                                                             \
    i_bench = BENCH;                                                     \
    do {                                                                 \
      j_bench = BENCH;                                                   \
      RANDOM;                                                            \
      do {                                                               \
        FUNCTION;                                                        \
        j_bench--;                                                       \
      } while (j_bench != 0);                                            \
      i_bench--;                                                         \
    } while (i_bench != 0);                                              \
    BARRIER;                                                             \
    __asm__ __volatile__(                                                \
        "RDTSCP\n\t"                                                     \
        "mov %%edx, %0\n\t"                                              \
        "mov %%eax, %1\n\t"                                              \
        "mfence\n\t"                                                     \
        : "=r"(cycles_high1), "=r"(cycles_low1)::"%rax", "%rbx", "%rcx", \
          "%rdx");                                                       \
    start = (((uint64_t)cycles_high0) << 32) | cycles_low0;              \
    end = (((uint64_t)cycles_high1) << 32) | cycles_low1;                \
    printf("%-15s= %6lu cc\n", #LABEL, (end - start) / (BENCH * BENCH)); \
  } while (0)

#define CLOCKS(LABEL, FUNCTION) CLOCKS_RANDOM(while (0), LABEL, FUNCTION)

#define oper_second(RANDOM, LABEL, FUNCTION)                 \
  do {                                                       \
    printf("%-14s : ", #LABEL);                              \
    RANDOM;                                                  \
                                                             \
    unsigned i;                                              \
    uint64_t start, end;                                     \
    const unsigned iterations = 10000;                       \
    uint64_t start_c, end_c;                                 \
                                                             \
    /* Load the caches*/                                     \
    for (i = 0; i < 1000; ++i) {                             \
      FUNCTION;                                              \
    }                                                        \
                                                             \
    start = time_now();                                      \
    start_c = cycles_now();                                  \
    for (i = 0; i < iterations; ++i) {                       \
      FUNCTION;                                              \
    }                                                        \
    end = time_now();                                        \
    end_c = cycles_now();                                    \
                                                             \
    printf("%3lu µs, %8.1f oper/s, %6lu cycles/op\n",        \
           (unsigned long)((end - start) / iterations),      \
           iterations*(double)1e6 / (end - start),           \
           (unsigned long)((end_c - start_c) / iterations)); \
  } while (0)

uint64_t time_now(void);
uint64_t cycles_now(void);

/* _CLOCKS_H_ */
#endif
