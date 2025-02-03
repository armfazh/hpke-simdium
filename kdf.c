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

#include <string.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

const uint8_t Suite_ID[10] = {'H', 'P', 'K', 'E', 0x00, 0x20, 0x00, 0x01, 0x00, 0x01};
const uint8_t Version[7] = {'H', 'P', 'K', 'E', '-', 'v', '1'};

void extract(uint8_t *key, size_t key_len, uint8_t *secret, size_t secret_len, uint8_t *salt, size_t salt_len)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    OSSL_PARAM params[5];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, "EXTRACT_ONLY", strlen("EXTRACT_ONLY"));
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, SN_sha256, strlen(SN_sha256));
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, secret, secret_len);
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, salt_len);
    params[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(ctx, key, key_len, params) <= 0)
    {
        handle_errors("EVP_KDF_derive failed");
    }

    EVP_KDF_CTX_free(ctx);
}

void expand(uint8_t *out, size_t out_len, uint8_t *key, size_t key_len, uint8_t *info, size_t info_len)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    OSSL_PARAM params[5];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, "EXPAND_ONLY", strlen("EXPAND_ONLY"));
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, SN_sha256, strlen(SN_sha256));
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key, key_len);
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, info_len);
    params[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(ctx, out, out_len, params) <= 0)
    {
        handle_errors("EVP_KDF_derive failed");
    }

    EVP_KDF_CTX_free(ctx);
}

void labeled_extract(
    uint8_t *key, size_t key_len,
    uint8_t *secret, size_t secret_len,
    uint8_t *salt, size_t salt_len,
    uint8_t *label, size_t label_len)
{
    size_t labeled_ikm_len = sizeof(Version) + sizeof(Suite_ID) + label_len + secret_len;
    uint8_t *labeled_ikm = (uint8_t *)malloc(labeled_ikm_len);

    uint8_t *ptr = labeled_ikm;
    memcpy(ptr, Version, sizeof(Version));
    ptr += sizeof(Version);
    memcpy(ptr, Suite_ID, sizeof(Suite_ID));
    ptr += sizeof(Suite_ID);
    memcpy(ptr, label, label_len);
    ptr += label_len;
    memcpy(ptr, secret, secret_len);

    extract(key, key_len, labeled_ikm, labeled_ikm_len, salt, salt_len);
    free(labeled_ikm);
}

void labeled_expand(
    uint8_t *out, size_t out_len,
    uint8_t *key, size_t key_len,
    uint8_t *info, size_t info_len,
    uint8_t *label, size_t label_len)
{
    size_t labeled_info_len = 2 + sizeof(Version) + sizeof(Suite_ID) + label_len + info_len;
    uint8_t *labeled_info = (uint8_t *)malloc(labeled_info_len);
    uint8_t *ptr = labeled_info;

    uint8_t length[2] = {(out_len >> 8) & 0xFF, out_len & 0xFF};
    memcpy(ptr, length, 2);
    ptr += 2;
    memcpy(ptr, Version, sizeof(Version));
    ptr += sizeof(Version);
    memcpy(ptr, Suite_ID, sizeof(Suite_ID));
    ptr += sizeof(Suite_ID);
    memcpy(ptr, label, label_len);
    ptr += label_len;
    memcpy(ptr, info, info_len);

    expand(out, out_len, key, key_len, labeled_info, labeled_info_len);
    free(labeled_info);
}

int main_kdf()
{
    uint8_t secret[20] = {0};
    uint8_t salt[10] = {0};
    printf("secret: ");
    print_hex(secret, sizeof(secret));
    printf("salt: ");
    print_hex(salt, sizeof(salt));

    uint8_t prk[32] = {0};
    extract(prk, sizeof(prk), secret, sizeof(secret), salt, sizeof(salt));
    printf("prk: ");
    print_hex(prk, sizeof(prk));

    uint8_t info[16] = {0};
    uint8_t out[17] = {0};
    expand(out, sizeof(out), prk, sizeof(prk), info, sizeof(info));
    printf("out: ");
    print_hex(out, sizeof(out));

    uint8_t label[7] = {0};
    labeled_extract(prk, sizeof(prk), secret, sizeof(secret), salt, sizeof(salt), label, sizeof(label));
    printf("prk: ");
    print_hex(prk, sizeof(prk));

    labeled_expand(out, sizeof(out), prk, sizeof(prk), info, sizeof(info), label, sizeof(label));
    printf("out: ");
    print_hex(out, sizeof(out));

    return 0;
}
