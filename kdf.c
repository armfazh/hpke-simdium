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
#include "kdf.h"

#include <string.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/kdf.h>

static const uint8_t Suite_ID[10] = {'H', 'P', 'K', 'E', 0x00, 0x20, 0x00, 0x01, 0x00, 0x01};
static const uint8_t Version[7] = {'H', 'P', 'K', 'E', '-', 'v', '1'};

// Utility to handle errors
#define handle_errors(msg)                                  \
    printf("error at %s:%d %s\n", __FILE__, __LINE__, msg); \
    ERR_print_errors_fp(stderr);                            \
    exit(1);

static void extract(u8 *key, u8 *secret, u8 *salt)
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

static void expand(u8 *out, u8 *key, u8 *info)
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

static void labeled_extract(u8 *key, u8 *secret, u8 *salt, u8 *label)
{
    u8 labeled_ikm = u8_malloc(sizeof(Version) + sizeof(Suite_ID) + label->len + secret->len);
    uint8_t *ptr = labeled_ikm.data;
    memcpy(ptr, Version, sizeof(Version));
    ptr += sizeof(Version);
    memcpy(ptr, Suite_ID, sizeof(Suite_ID));
    ptr += sizeof(Suite_ID);
    memcpy(ptr, label->data, label->len);
    ptr += label->len;
    memcpy(ptr, secret->data, secret->len);

    extract(key, &labeled_ikm, salt);
    u8_free(&labeled_ikm);
}

static void labeled_expand(u8 *out, u8 *key, u8 *info, u8 *label)
{
    uint8_t length[2] = {(out->len >> 8) & 0xFF, out->len & 0xFF};
    u8 labeled_info = u8_malloc(2 + sizeof(Version) + sizeof(Suite_ID) + label->len + info->len);

    uint8_t *ptr = labeled_info.data;
    memcpy(ptr, length, 2);
    ptr += 2;
    memcpy(ptr, Version, sizeof(Version));
    ptr += sizeof(Version);
    memcpy(ptr, Suite_ID, sizeof(Suite_ID));
    ptr += sizeof(Suite_ID);
    memcpy(ptr, label->data, label->len);
    ptr += label->len;
    memcpy(ptr, info->data, info->len);

    expand(out, key, &labeled_info);
    u8_free(&labeled_info);
}

void extract_and_expand(u8 *shared_secret, u8 *dh, u8 *kem_context)
{
    u8 label_eae = u8_string("eae_prk");
    u8 label_shared_secret = u8_string("shared_secret");
    u8_static(eae_prk, 32);
    u8_static(empty_salt, 32);
    labeled_extract(&eae_prk, dh, &empty_salt, &label_eae);
    labeled_expand(shared_secret, &eae_prk, kem_context, &label_shared_secret);
}

int main_kdf()
{
    u8 secret = u8_malloc(20);
    u8 salt = u8_malloc(10);

    printf("secret: ");
    u8_print(&secret);
    printf("salt: ");
    u8_print(&salt);

    u8 prk = u8_malloc(32);
    extract(&prk, &secret, &salt);
    printf("prk: ");
    u8_print(&prk);

    u8 info = u8_malloc(16);
    u8 out = u8_malloc(17);
    expand(&out, &prk, &info);
    printf("out: ");
    u8_print(&out);

    u8 label = u8_malloc(7);
    labeled_extract(&prk, &secret, &salt, &label);
    printf("prk: ");
    u8_print(&prk);

    labeled_expand(&out, &prk, &info, &label);
    printf("out: ");
    u8_print(&out);

    u8_free(&secret);
    u8_free(&salt);
    u8_free(&prk);
    u8_free(&info);
    u8_free(&label);
    u8_free(&out);

    return 0;
}
