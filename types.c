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
#include "util.h"
#include <string.h>
#include <stdlib.h>

u8 u8_malloc(size_t len)
{
    u8 out = {
        .len = len,
        .data = (uint8_t *)malloc(len),
    };
    memset(out.data, 0, out.len);
    return out;
}

void u8_free(u8 *x) { free(x->data); }
void u8_print(u8 *x) { print_hex(x->data, x->len); }
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