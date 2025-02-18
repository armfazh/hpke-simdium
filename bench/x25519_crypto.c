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

#include "dhkem.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#define concat(X, Y) X##_##Y
#define stringify(X) #X

#if CRYPTO_PROV == 0
#define CRYPTO_NAME(X) X##_ossl
#elif CRYPTO_PROV == 1
#define CRYPTO_NAME(X) X##_bssl
#endif

// Utility to handle errors
#define handle_errors(msg)                                                    \
    printf("(%d) error at %s:%d %s\n", CRYPTO_PROV, __FILE__, __LINE__, msg); \
    ERR_print_errors_fp(stderr);                                              \
    exit(1);

void CRYPTO_NAME(info)(void)
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    printf("(%d) version: %s\n", CRYPTO_PROV, OPENSSL_VERSION_TEXT);
    printf("EVP_PKEY_X25519: %d\n", EVP_PKEY_X25519);
}

static void CRYPTO_NAME(keygen)(u8 *sk, u8 *pk)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) {
        handle_errors("EVP_PKEY_CTX_new_id failed");
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        handle_errors("EVP_PKEY_keygen_init failed");
    }
    if (EVP_PKEY_keygen(ctx, &key) <= 0) {
        handle_errors("EVP_PKEY_keygen failed");
    }

    if (EVP_PKEY_get_raw_private_key(key, sk->data, &sk->len) <= 0) {
        handle_errors("EVP_PKEY_get_raw_private_key failed");
    }

    if (EVP_PKEY_get_raw_public_key(key, pk->data, &pk->len) <= 0) {
        handle_errors("EVP_PKEY_get_raw_public_key failed");
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
}

static void CRYPTO_NAME(shared)(u8 *shared_secret, u8 *sk, u8 *pk)
{
    EVP_PKEY *sk_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk->data, sk->len);
    if (!sk_key) {
        handle_errors("EVP_PKEY_new_raw_private_key failed");
    }

    EVP_PKEY *pk_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pk->data, pk->len);
    if (!pk_key) {
        handle_errors("EVP_PKEY_new_raw_public_key failed");
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(sk_key, NULL);
    if (!ctx) {
        handle_errors("EVP_PKEY_CTX_new failed");
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        handle_errors("EVP_PKEY_derive_init failed");
    }

    if (EVP_PKEY_derive_set_peer(ctx, pk_key) <= 0) {
        handle_errors("EVP_PKEY_derive_set_peer failed");
    }

    if (EVP_PKEY_derive(ctx, shared_secret->data, &shared_secret->len) <= 0) {
        handle_errors("EVP_PKEY_derive failed");
    }

    EVP_PKEY_free(sk_key);
    EVP_PKEY_free(pk_key);
    EVP_PKEY_CTX_free(ctx);
}

struct xdh CRYPTO_NAME(XDH) = {
    .name = stringify(CRYPTO_NAME("")),
    .keygen = CRYPTO_NAME(keygen),
    .shared = CRYPTO_NAME(shared),
};
