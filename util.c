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
#include <openssl/rand.h>
#include "util.h"

void print_hex(const unsigned char *data, size_t len)
{
    size_t i = 0;
    for (i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Generate a random byte array
int generate_random_bytes(unsigned char *buf, size_t len)
{
    if (RAND_bytes(buf, len) != 1)
    {
        handle_errors("random bytes");
    }
    return 1;
}