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

#include "util.h"
#include "types.h"

#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>

void keygen(u8 *sk, u8 *pk)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx)
    {
        handle_errors("EVP_PKEY_CTX_new_id failed");
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        handle_errors("EVP_PKEY_keygen_init failed");
    }
    if (EVP_PKEY_keygen(ctx, &key) <= 0)
    {
        handle_errors("EVP_PKEY_keygen failed");
    }

    if (EVP_PKEY_get_raw_private_key(key, sk->data, &sk->len) <= 0)
    {
        handle_errors("EVP_PKEY_get_raw_private_key failed");
    }

    if (EVP_PKEY_get_raw_public_key(key, pk->data, &pk->len) <= 0)
    {
        handle_errors("EVP_PKEY_get_raw_public_key failed");
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
}

void shared(u8 *shared_secret, u8 *sk, u8 *pk)
{
    EVP_PKEY *sk_key = NULL;
    EVP_PKEY *pk_key = NULL;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (ctx == NULL)
    {
        handle_errors("Error creating EVP_PKEY_CTX");
    }

    if (EVP_PKEY_fromdata_init(ctx) <= 0)
    {
        handle_errors("Error initializing EVP_PKEY context");
    }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, sk->data, sk->len);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_fromdata(ctx, &sk_key, EVP_PKEY_KEYPAIR, params) <= 0)
    {
        handle_errors("Error loading raw private key into EVP_PKEY");
    }

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pk->data, pk->len);

    if (EVP_PKEY_fromdata(ctx, &pk_key, EVP_PKEY_KEYPAIR, params) <= 0)
    {
        handle_errors("Error loading raw public key into EVP_PKEY");
    }

    EVP_PKEY_CTX_free(ctx);
    ctx = EVP_PKEY_CTX_new(sk_key, NULL);
    if (!ctx)
    {
        handle_errors("EVP_PKEY_CTX_new failed");
    }

    if (EVP_PKEY_derive_init(ctx) <= 0)
    {
        handle_errors("EVP_PKEY_derive_init failed");
    }

    if (EVP_PKEY_derive_set_peer(ctx, pk_key) <= 0)
    {
        handle_errors("EVP_PKEY_derive_set_peer failed");
    }

    if (EVP_PKEY_derive(ctx, shared_secret->data, &shared_secret->len) <= 0)
    {
        handle_errors("EVP_PKEY_derive failed");
    }

    EVP_PKEY_free(sk_key);
    EVP_PKEY_free(pk_key);
    EVP_PKEY_CTX_free(ctx);
}

int main_x25519()
{
    u8 aSk = u8_malloc(32);
    u8 aPk = u8_malloc(32);
    keygen(&aSk, &aPk);
    printf("sk: ");
    u8_print(&aSk);
    printf("pk: ");
    u8_print(&aPk);

    u8 bSk = u8_malloc(32);
    u8 bPk = u8_malloc(32);
    keygen(&bSk, &bPk);
    printf("sk: ");
    u8_print(&bSk);
    printf("pk: ");
    u8_print(&bPk);

    u8 aliceShared = u8_malloc(32);
    u8 bobShared = u8_malloc(32);

    shared(&aliceShared, &aSk, &bPk);
    printf("ss: ");
    u8_print(&aliceShared);

    shared(&bobShared, &bSk, &aPk);
    printf("ss: ");
    u8_print(&bobShared);

    u8_free(&aSk);
    u8_free(&aPk);
    u8_free(&bSk);
    u8_free(&bPk);
    u8_free(&aliceShared);
    u8_free(&bobShared);

    return 0;
}
