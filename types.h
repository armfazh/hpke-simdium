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
#ifndef _TYPES_H_
#define _TYPES_H_

#include <stdint.h>
#include <stddef.h>

typedef struct u8_slice {
    uint8_t *data;
    size_t len;
} u8;

u8 u8_malloc(size_t len);
void u8_free(u8 *x);
void u8_print(u8 *x);
u8 u8_string(char *s);
void u8_copy(u8 *dst, u8 *src);

#define u8_static(name, length)        \
    uint8_t name##_data[length] = {0}; \
    u8 name = {                        \
        .len = length,                 \
        .data = name##_data,           \
    };

#endif /* _TYPES_H_ */
