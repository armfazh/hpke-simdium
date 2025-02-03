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
#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>

void print_hex(const unsigned char *data, size_t len);
void handle_errors(char *msg);
int generate_random_bytes(unsigned char *buf, size_t len);

#endif /* _UTIL_H_ */
