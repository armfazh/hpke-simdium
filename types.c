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

u8 u8_hex_string(const char *s)
{
    int len = strlen(s);
    u8 out = u8_malloc(len/2);
    char str[3]= {0};
    int i=0,b=0;
    for (i=0; i<len; i+=2) {
        str[0] = s[i];
        str[1] = s[i+1];
        sscanf(str,"%x", &b);
        out.data[i/2] = b;
    }
    return out;
}

u8 u8_string(char *s)
{
    u8 out = {
        .len = strlen(s),
        .data = (uint8_t *)s,
    };
    return out;
}

void u8_copy(u8 *dst, const u8 *src)
{
    dst->len = src->len;
    memcpy(dst->data, src->data, src->len);
}

void u8_print(const u8 *x)
{
    size_t i = 0;
    for (i = 0; i < x->len; i++) {
        printf("%02x", x->data[i]);
    }
    printf("\n");
}

void u8_append(uint8_t* *head,const u8* x)
{
    memcpy(*head, x->data, x->len);
    *head += x->len;
}

void u8_append_array(uint8_t* *head, const uint8_t* data, size_t len)
{
    memcpy(*head, data, len);
    *head += len;
}