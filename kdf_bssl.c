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
#include "kdf.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>

#define handle_errors(msg)                                  \
    printf("error at %s:%d %s\n", __FILE__, __LINE__, msg); \
    ERR_print_errors_fp(stderr);                            \
    exit(1);

void hkdf_extract(u8 *key, const u8 *secret, const u8 *salt)
{
    if(HKDF_extract(key->data, &key->len, EVP_sha256(),
                    secret->data,  secret->len, salt->data, salt->len) <= 0) {
        handle_errors("HKDF_extract failed");
    }
}

void hkdf_expand(u8 *out, const u8 *key, const u8 *info)
{
    if(HKDF_expand(out->data, out->len, EVP_sha256(),
                   key->data,  key->len, info->data, info->len) <= 0) {
        handle_errors("HKDF_expand failed");
    }
}

void hkdf_extract_expand(u8 *out, const u8 *secret, const u8 *info)
{
    if(HKDF(out->data, out->len, EVP_sha256(),
            secret->data,  secret->len, NULL,  0,
            info->data,  info->len) <= 0) {
        handle_errors("HKDF failed");
    }
}
