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
#include "bench.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

int main()
{
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  printf("OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);

  // bench_x25519();
  bench_dhkem();
  return 0;
}