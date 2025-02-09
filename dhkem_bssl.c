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
#include "dhkem_bssl.h"
#include "types.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/hpke.h>
#include "bench/clocks.h"

#define LBUFSIZE 48

// Utility to handle errors
#define handle_errors(msg)                                  \
    printf("error at %s:%d %s\n", __FILE__, __LINE__, msg); \
    ERR_print_errors_fp(stderr);                            \
    exit(1);

int main_dhkem_bssl(void)
{
    u8_static(pkR, EVP_HPKE_MAX_PUBLIC_KEY_LENGTH);

    const EVP_HPKE_KEM *kemID = EVP_hpke_x25519_hkdf_sha256();
    const EVP_HPKE_KDF *kdfID = EVP_hpke_hkdf_sha256();
    const EVP_HPKE_AEAD *aeadID = EVP_hpke_aes_128_gcm();

    EVP_HPKE_KEY key;
    if (EVP_HPKE_KEY_generate(&key, kemID) <= 0)
    {
        handle_errors("EVP_HPKE_KEY_generate failed");
    }

    if (EVP_HPKE_KEY_public_key(&key, pkR.data, &pkR.len, EVP_HPKE_MAX_PUBLIC_KEY_LENGTH) <= 0)
    {
        handle_errors("EVP_HPKE_KEY_public_key failed");
    }

    u8_static(enc, 32);
    EVP_HPKE_CTX *sctx = EVP_HPKE_CTX_new();
    if (EVP_HPKE_CTX_setup_sender(sctx, enc.data, &enc.len, 32,
                                  kemID, kdfID, aeadID,
                                  pkR.data, pkR.len,
                                  NULL, 0) <= 0)
    {
        handle_errors("EVP_HPKE_CTX_setup_sender failed");
    }

    unsigned char ct[LBUFSIZE] = {0};
    size_t ctlen = sizeof(ct);
    unsigned char clear[LBUFSIZE] = {0};
    size_t clearlen = sizeof(clear);
    const unsigned char *pt = (const unsigned char *)"a message not in a bottle";
    size_t ptlen = strlen((char *)pt);

    if (EVP_HPKE_CTX_seal(sctx, ct, &ctlen, LBUFSIZE, pt, ptlen, NULL, 0) <= 0)
    {
        handle_errors("EVP_HPKE_CTX_seal failed");
    }

    EVP_HPKE_CTX *rctx = EVP_HPKE_CTX_new();
    if (EVP_HPKE_CTX_setup_recipient(rctx, &key,
                                     kdfID, aeadID,
                                     enc.data, enc.len,
                                     NULL, 0) <= 0)
    {
        handle_errors("EVP_HPKE_CTX_setup_recipient failed");
    }

    if (EVP_HPKE_CTX_open(rctx, clear, &clearlen, LBUFSIZE, ct, ctlen, NULL, 0) <= 0)
    {
        handle_errors("EVP_HPKE_CTX_open failed");
    }

    EVP_HPKE_CTX_free(sctx);
    EVP_HPKE_CTX_free(rctx);
    EVP_HPKE_KEY_cleanup(&key);

    printf("pt0: %s\n", pt);
    printf("pt1: %s\n", clear);
    return 0;
}

int main_auth_dhkem_bssl(void)
{
    u8_static(pkR, EVP_HPKE_MAX_PUBLIC_KEY_LENGTH);
    u8_static(pkS, EVP_HPKE_MAX_PUBLIC_KEY_LENGTH);

    const EVP_HPKE_KEM *kemID = EVP_hpke_x25519_hkdf_sha256();
    const EVP_HPKE_KDF *kdfID = EVP_hpke_hkdf_sha256();
    const EVP_HPKE_AEAD *aeadID = EVP_hpke_aes_128_gcm();

    EVP_HPKE_KEY skey;
    if (EVP_HPKE_KEY_generate(&skey, kemID) <= 0)
    {
        handle_errors("EVP_HPKE_KEY_generate failed");
    }

    if (EVP_HPKE_KEY_public_key(&skey, pkS.data, &pkS.len, EVP_HPKE_MAX_PUBLIC_KEY_LENGTH) <= 0)
    {
        handle_errors("EVP_HPKE_KEY_public_key failed");
    }

    EVP_HPKE_KEY rkey;
    if (EVP_HPKE_KEY_generate(&rkey, kemID) <= 0)
    {
        handle_errors("EVP_HPKE_KEY_generate failed");
    }

    if (EVP_HPKE_KEY_public_key(&rkey, pkR.data, &pkR.len, EVP_HPKE_MAX_PUBLIC_KEY_LENGTH) <= 0)
    {
        handle_errors("EVP_HPKE_KEY_public_key failed");
    }

    u8_static(enc, 32);
    EVP_HPKE_CTX *sctx = EVP_HPKE_CTX_new();
    if (EVP_HPKE_CTX_setup_auth_sender(sctx, enc.data, &enc.len, 32,
                                       &skey, kdfID, aeadID,
                                       pkR.data, pkR.len,
                                       NULL, 0) <= 0)
    {
        handle_errors("EVP_HPKE_CTX_setup_auth_sender failed");
    }

    unsigned char ct[LBUFSIZE] = {0};
    size_t ctlen = sizeof(ct);
    unsigned char clear[LBUFSIZE] = {0};
    size_t clearlen = sizeof(clear);
    const unsigned char *pt = (const unsigned char *)"a message not in a bottle";
    size_t ptlen = strlen((char *)pt);

    if (EVP_HPKE_CTX_seal(sctx, ct, &ctlen, LBUFSIZE, pt, ptlen, NULL, 0) <= 0)
    {
        handle_errors("EVP_HPKE_CTX_seal failed");
    }

    EVP_HPKE_CTX *rctx = EVP_HPKE_CTX_new();
    if (EVP_HPKE_CTX_setup_auth_recipient(rctx,
                                          &rkey, kdfID, aeadID,
                                          enc.data, enc.len,
                                          NULL, 0,
                                          pkS.data, pkS.len) <= 0)
    {
        handle_errors("EVP_HPKE_CTX_setup_auth_recipient failed");
    }

    if (EVP_HPKE_CTX_open(rctx, clear, &clearlen, LBUFSIZE, ct, ctlen, NULL, 0) <= 0)
    {
        handle_errors("EVP_HPKE_CTX_open failed");
    }

    EVP_HPKE_CTX_free(sctx);
    EVP_HPKE_CTX_free(rctx);
    EVP_HPKE_KEY_cleanup(&skey);
    EVP_HPKE_KEY_cleanup(&rkey);

    printf("pt0: %s\n", pt);
    printf("pt1: %s\n", clear);
    return 0;
}

void bench_dhkem_encapdecap_bssl(void)
{
    u8_static(pkR, EVP_HPKE_MAX_PUBLIC_KEY_LENGTH);

    const EVP_HPKE_KEM *kemID = EVP_hpke_x25519_hkdf_sha256();
    const EVP_HPKE_KDF *kdfID = EVP_hpke_hkdf_sha256();
    const EVP_HPKE_AEAD *aeadID = EVP_hpke_aes_128_gcm();

    EVP_HPKE_KEY key;
    if (EVP_HPKE_KEY_generate(&key, kemID) <= 0)
    {
        handle_errors("EVP_HPKE_KEY_generate failed");
    }

    if (EVP_HPKE_KEY_public_key(&key, pkR.data, &pkR.len, EVP_HPKE_MAX_PUBLIC_KEY_LENGTH) <= 0)
    {
        handle_errors("EVP_HPKE_KEY_public_key failed");
    }

    u8_static(enc, 32);
    EVP_HPKE_CTX *sctx = EVP_HPKE_CTX_new();
    if (EVP_HPKE_CTX_setup_sender(sctx, enc.data, &enc.len, 32,
                                  kemID, kdfID, aeadID,
                                  pkR.data, pkR.len,
                                  NULL, 0) <= 0)
    {
        handle_errors("EVP_HPKE_CTX_setup_sender failed");
    }

    unsigned char ct[LBUFSIZE] = {0};
    size_t ctlen = sizeof(ct);
    unsigned char clear[LBUFSIZE] = {0};
    size_t clearlen = sizeof(clear);
    const unsigned char *pt = (const unsigned char *)"a message not in a bottle";
    size_t ptlen = strlen((char *)pt);

    if (EVP_HPKE_CTX_seal(sctx, ct, &ctlen, LBUFSIZE, pt, ptlen, NULL, 0) <= 0)
    {
        handle_errors("EVP_HPKE_CTX_seal failed");
    }

    EVP_HPKE_CTX *rctx = EVP_HPKE_CTX_new();
    if (EVP_HPKE_CTX_setup_recipient(rctx, &key,
                                     kdfID, aeadID,
                                     enc.data, enc.len,
                                     NULL, 0) <= 0)
    {
        handle_errors("EVP_HPKE_CTX_setup_recipient failed");
    }

    if (EVP_HPKE_CTX_open(rctx, clear, &clearlen, LBUFSIZE, ct, ctlen, NULL, 0) <= 0)
    {
        handle_errors("EVP_HPKE_CTX_open failed");
    }

    EVP_HPKE_CTX_free(sctx);
    EVP_HPKE_CTX_free(rctx);

    oper_second(, keygen, {
        EVP_HPKE_KEY sk;
        if (EVP_HPKE_KEY_generate(&sk, kemID) <= 0)
        {
            handle_errors("EVP_HPKE_KEY_generate failed");
        }
        EVP_HPKE_KEY_cleanup(&sk);
    });

    oper_second(, encap, {
        EVP_HPKE_CTX *sctx = EVP_HPKE_CTX_new();
        if (EVP_HPKE_CTX_setup_sender(sctx, enc.data, &enc.len, 32,
                                      kemID, kdfID, aeadID,
                                      pkR.data, pkR.len,
                                      NULL, 0) <= 0)
        {
            handle_errors("EVP_HPKE_CTX_setup_sender failed");
        }
        EVP_HPKE_CTX_free(sctx);
    });

    oper_second(, decap, {
        EVP_HPKE_CTX *rctx = EVP_HPKE_CTX_new();
        if (EVP_HPKE_CTX_setup_recipient(rctx, &key,
                                         kdfID, aeadID,
                                         enc.data, enc.len,
                                         NULL, 0) <= 0)
        {
            handle_errors("EVP_HPKE_CTX_setup_recipient failed");
        }
        EVP_HPKE_CTX_free(rctx);
    });

    EVP_HPKE_KEY_cleanup(&key);
}

void bench_dhkem_auth_encapdecap_bssl(void)
{
    u8_static(pkR, EVP_HPKE_MAX_PUBLIC_KEY_LENGTH);
    u8_static(pkS, EVP_HPKE_MAX_PUBLIC_KEY_LENGTH);

    const EVP_HPKE_KEM *kemID = EVP_hpke_x25519_hkdf_sha256();
    const EVP_HPKE_KDF *kdfID = EVP_hpke_hkdf_sha256();
    const EVP_HPKE_AEAD *aeadID = EVP_hpke_aes_128_gcm();

    EVP_HPKE_KEY skey;
    if (EVP_HPKE_KEY_generate(&skey, kemID) <= 0)
    {
        handle_errors("EVP_HPKE_KEY_generate failed");
    }

    if (EVP_HPKE_KEY_public_key(&skey, pkS.data, &pkS.len, EVP_HPKE_MAX_PUBLIC_KEY_LENGTH) <= 0)
    {
        handle_errors("EVP_HPKE_KEY_public_key failed");
    }

    EVP_HPKE_KEY rkey;
    if (EVP_HPKE_KEY_generate(&rkey, kemID) <= 0)
    {
        handle_errors("EVP_HPKE_KEY_generate failed");
    }

    if (EVP_HPKE_KEY_public_key(&rkey, pkR.data, &pkR.len, EVP_HPKE_MAX_PUBLIC_KEY_LENGTH) <= 0)
    {
        handle_errors("EVP_HPKE_KEY_public_key failed");
    }

    u8_static(enc, 32);
    EVP_HPKE_CTX *sctx = EVP_HPKE_CTX_new();
    if (EVP_HPKE_CTX_setup_auth_sender(sctx, enc.data, &enc.len, 32,
                                       &skey, kdfID, aeadID,
                                       pkR.data, pkR.len,
                                       NULL, 0) <= 0)
    {
        handle_errors("EVP_HPKE_CTX_setup_auth_sender failed");
    }

    unsigned char ct[LBUFSIZE] = {0};
    size_t ctlen = sizeof(ct);
    unsigned char clear[LBUFSIZE] = {0};
    size_t clearlen = sizeof(clear);
    const unsigned char *pt = (const unsigned char *)"a message not in a bottle";
    size_t ptlen = strlen((char *)pt);

    if (EVP_HPKE_CTX_seal(sctx, ct, &ctlen, LBUFSIZE, pt, ptlen, NULL, 0) <= 0)
    {
        handle_errors("EVP_HPKE_CTX_seal failed");
    }

    EVP_HPKE_CTX *rctx = EVP_HPKE_CTX_new();
    if (EVP_HPKE_CTX_setup_auth_recipient(rctx,
                                          &rkey, kdfID, aeadID,
                                          enc.data, enc.len,
                                          NULL, 0,
                                          pkS.data, pkS.len) <= 0)
    {
        handle_errors("EVP_HPKE_CTX_setup_auth_recipient failed");
    }

    if (EVP_HPKE_CTX_open(rctx, clear, &clearlen, LBUFSIZE, ct, ctlen, NULL, 0) <= 0)
    {
        handle_errors("EVP_HPKE_CTX_open failed");
    }

    oper_second(, keygen, {
        EVP_HPKE_KEY sk;
        if (EVP_HPKE_KEY_generate(&sk, kemID) <= 0)
        {
            handle_errors("EVP_HPKE_KEY_generate failed");
        }
        EVP_HPKE_KEY_cleanup(&sk);
    });

    oper_second(, auth_encap, {
        EVP_HPKE_CTX *sctx = EVP_HPKE_CTX_new();
        if (EVP_HPKE_CTX_setup_auth_sender(sctx, enc.data, &enc.len, 32,
                                           &skey, kdfID, aeadID,
                                           pkR.data, pkR.len,
                                           NULL, 0) <= 0)
        {
            handle_errors("EVP_HPKE_CTX_setup_sender failed");
        }
        EVP_HPKE_CTX_free(sctx);
    });

    oper_second(, auth_decap, {
        EVP_HPKE_CTX *rctx = EVP_HPKE_CTX_new();
        if (EVP_HPKE_CTX_setup_auth_recipient(rctx,
                                              &rkey, kdfID, aeadID,
                                              enc.data, enc.len,
                                              NULL, 0,
                                              pkS.data, pkS.len) <= 0)
        {
            handle_errors("EVP_HPKE_CTX_setup_recipient failed");
        }
        EVP_HPKE_CTX_free(rctx);
    });

    EVP_HPKE_KEY_cleanup(&skey);
    EVP_HPKE_KEY_cleanup(&rkey);
}