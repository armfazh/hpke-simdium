/**
 * This file is part of hpke-simdium.
 *
 * Copyright 2025 Armando Faz Hernandez.
 *
 * Licensed under the Mozilla Public License, v. 2.0. You may not use this
 * file except in compliance with the License.
 * You can obtain a copy of the License at:
 *
 * https://www.mozilla.org/en-US/MPL/2.0/
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#include "types.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <immintrin.h>

u8 u8_malloc(size_t len)
{
    u8 out = {
        .len = len,
        .data = (uint8_t *)_mm_malloc(len, 32),
    };
    memset(out.data, 0, out.len);
    return out;
}

void u8_free(u8 *x)
{
    _mm_free(x->data);
}

u8 u8_string(char *s)
{
    u8 out = {
        .len = strlen(s),
        .data = (uint8_t *)s,
    };
    return out;
}

void u8_copy(u8 *dst, u8 *src)
{
    dst->len = src->len;
    memcpy(dst->data, src->data, src->len);
}

void u8_print(u8 *x)
{
    size_t i = 0;
    for (i = 0; i < x->len; i++) {
        printf("%02x", x->data[i]);
    }
    printf("\n");
}