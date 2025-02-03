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
#include "util.h"
#include "types.h"

#include <string.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

const uint8_t Suite_ID[10] = {'H', 'P', 'K', 'E', 0x00, 0x20, 0x00, 0x01, 0x00, 0x01};
const uint8_t Version[7] = {'H', 'P', 'K', 'E', '-', 'v', '1'};

void extract(u8 *key, u8 *secret, u8 *salt)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    OSSL_PARAM params[5];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, "EXTRACT_ONLY", strlen("EXTRACT_ONLY"));
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, SN_sha256, strlen(SN_sha256));
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, secret->data, secret->len);
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt->data, salt->len);
    params[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(ctx, key->data, key->len, params) <= 0)
    {
        handle_errors("EVP_KDF_derive failed");
    }

    EVP_KDF_CTX_free(ctx);
}

void expand(u8 *out, u8 *key, u8 *info)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    OSSL_PARAM params[5];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, "EXPAND_ONLY", strlen("EXPAND_ONLY"));
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, SN_sha256, strlen(SN_sha256));
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key->data, key->len);
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info->data, info->len);
    params[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(ctx, out->data, out->len, params) <= 0)
    {
        handle_errors("EVP_KDF_derive failed");
    }

    EVP_KDF_CTX_free(ctx);
}

void labeled_extract(u8 *key, u8 *secret, u8 *salt, u8 *label)
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

void labeled_expand(u8 *out, u8 *key, u8 *info, u8 *label)
{
    u8 labeled_info = u8_malloc(2 + sizeof(Version) + sizeof(Suite_ID) + label->len + info->len);
    uint8_t *ptr = labeled_info.data;

    uint8_t length[2] = {(out->len >> 8) & 0xFF, out->len & 0xFF};
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
