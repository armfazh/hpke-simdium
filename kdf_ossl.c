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

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/kdf.h>

#define handle_errors(msg)                                  \
    printf("error at %s:%d %s\n", __FILE__, __LINE__, msg); \
    ERR_print_errors_fp(stderr);                            \
    exit(1);

void hkdf_extract(u8 *key, const u8 *secret, const u8 *salt)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        handle_errors("EVP_PKEY_derive_init failed");
    }

    if (EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0) {
        handle_errors("EVP_PKEY_CTX_hkdf_mode failed");
    }

    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) {
        handle_errors("EVP_PKEY_CTX_hkdf_mode failed");
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, secret->data, secret->len) <= 0) {
        handle_errors("EVP_PKEY_CTX_set1_hkdf_key failed");
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt->data, salt->len) <= 0) {
        handle_errors("EVP_PKEY_CTX_set1_hkdf_salt failed");
    }

    if (EVP_PKEY_derive(ctx, key->data, &key->len) <= 0) {
        handle_errors("EVP_PKEY_derive failed");
    }

    EVP_PKEY_CTX_free(ctx);
}

void hkdf_expand(u8 *out, const u8 *key, const u8 *info)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        handle_errors("EVP_PKEY_derive_init failed");
    }

    if (EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0) {
        handle_errors("EVP_PKEY_CTX_hkdf_mode failed");
    }

    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) {
        handle_errors("EVP_PKEY_CTX_hkdf_mode failed");
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, key->data, key->len) <= 0) {
        handle_errors("EVP_PKEY_CTX_set1_hkdf_key failed");
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info->data, info->len) <= 0) {
        handle_errors("EVP_PKEY_CTX_add1_hkdf_info failed");
    }

    if (EVP_PKEY_derive(ctx, out->data, &out->len) <= 0) {
        handle_errors("EVP_PKEY_derive failed");
    }

    EVP_PKEY_CTX_free(ctx);
}

void hkdf_extract_expand(u8 *out, const u8 *secret, const u8 *info)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        handle_errors("EVP_PKEY_derive_init failed");
    }

    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) {
        handle_errors("EVP_PKEY_CTX_hkdf_mode failed");
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, secret->data, secret->len) <= 0) {
        handle_errors("EVP_PKEY_CTX_set1_hkdf_key failed");
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info->data, info->len) <= 0) {
        handle_errors("EVP_PKEY_CTX_add1_hkdf_info failed");
    }

    if (EVP_PKEY_derive(ctx, out->data, &out->len) <= 0) {
        handle_errors("EVP_PKEY_derive failed");
    }
    EVP_PKEY_CTX_free(ctx);
}
