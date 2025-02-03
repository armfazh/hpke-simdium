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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <stdio.h>

#include "util.h"

void print_key(EVP_PKEY *key)
{
    size_t key_len = 0;
    if (EVP_PKEY_get_raw_private_key(key, NULL, &key_len) <= 0)
    {
        handle_errors("EVP_PKEY_get_raw_private_key failed");
    }

    unsigned char *buffer = (unsigned char *)OPENSSL_malloc(key_len);

    if (EVP_PKEY_get_raw_private_key(key, buffer, &key_len) <= 0)
    {
        handle_errors("EVP_PKEY_keygen_init failed");
    }

    printf("sk: ");
    print_hex(buffer, key_len);
    OPENSSL_free(buffer);

    buffer = (unsigned char *)OPENSSL_malloc(key_len);

    if (EVP_PKEY_get_raw_public_key(key, buffer, &key_len) <= 0)
    {
        handle_errors("EVP_PKEY_keygen_init failed");
    }

    printf("pk: ");
    print_hex(buffer, key_len);
    OPENSSL_free(buffer);
}

int keygen(EVP_PKEY **key)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx)
    {
        handle_errors("EVP_PKEY_CTX_new_id failed");
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        handle_errors("EVP_PKEY_keygen_init failed");
    }
    if (EVP_PKEY_keygen(ctx, key) <= 0)
    {
        handle_errors("EVP_PKEY_keygen failed");
    }

    EVP_PKEY_CTX_free(ctx);
    return 0;
}

int shared(unsigned char *shared_secret, EVP_PKEY *key, EVP_PKEY *key2)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx)
    {
        handle_errors("EVP_PKEY_CTX_new failed");
    }

    if (EVP_PKEY_derive_init(ctx) <= 0)
    {
        handle_errors("EVP_PKEY_derive_init failed");
    }

    if (EVP_PKEY_derive_set_peer(ctx, key2) <= 0)
    {
        handle_errors("EVP_PKEY_derive_set_peer failed");
    }

    size_t shared_secret_len = 32;
    if (EVP_PKEY_derive(ctx, shared_secret, &shared_secret_len) <= 0)
    {
        handle_errors("EVP_PKEY_derive failed");
    }

    EVP_PKEY_CTX_free(ctx);
    return 0;
}

int main_x25519()
{
    EVP_PKEY *aliceKey = NULL;
    keygen(&aliceKey);
    print_key(aliceKey);

    EVP_PKEY *bobKey = NULL;
    keygen(&bobKey);
    print_key(bobKey);

    unsigned char aliceShared[32];
    unsigned char bobShared[32];

    shared(aliceShared, aliceKey, bobKey);
    print_hex(aliceShared, 32);

    shared(bobShared, bobKey, aliceKey);
    print_hex(bobShared, 32);

    EVP_PKEY_free(aliceKey);
    EVP_PKEY_free(bobKey);

    return 0;
}
