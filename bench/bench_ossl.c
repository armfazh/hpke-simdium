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
#include "x25519_ossl.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hpke.h>

#include "clocks.h"
#include "bench.h"

#define LBUFSIZE 48

int main_dhkem_ossl(void)
{
    int mode = OSSL_HPKE_MODE_BASE;
    OSSL_HPKE_SUITE suite = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_CTX *sctx = NULL, *rctx = NULL;
    EVP_PKEY *priv = NULL;
    unsigned char pub[LBUFSIZE];
    size_t publen = sizeof(pub);
    unsigned char enc[LBUFSIZE];
    size_t enclen = sizeof(enc);
    unsigned char ct[LBUFSIZE] = {0};
    size_t ctlen = sizeof(ct);
    unsigned char clear[LBUFSIZE] = {0};
    size_t clearlen = sizeof(clear);
    const unsigned char *pt = (const unsigned char *)"a message not in a bottle";
    size_t ptlen = strlen((char *)pt);
    const unsigned char *info = (const unsigned char *)"Some info";
    size_t infolen = strlen((char *)info);
    unsigned char aad[] = {1, 2, 3, 4, 5, 6, 7, 8};
    size_t aadlen = sizeof(aad);

    /*
     * Generate receiver's key pair.
     * The receiver gives this public key to the sender.
     */
    if (OSSL_HPKE_keygen(suite, pub, &publen, &priv,
                         NULL, 0, NULL, NULL) != 1)
        goto err;

    /* sender's actions - encrypt data using the receivers public key */
    if ((sctx = OSSL_HPKE_CTX_new(mode, suite,
                                  OSSL_HPKE_ROLE_SENDER,
                                  NULL, NULL)) == NULL)
        goto err;

    if (OSSL_HPKE_encap(sctx, enc, &enclen, pub, publen, info, infolen) != 1)
        goto err;

    if (OSSL_HPKE_seal(sctx, ct, &ctlen, aad, aadlen, pt, ptlen) != 1)
        goto err;

    /* receiver's actions - decrypt data using the receivers private key */
    if ((rctx = OSSL_HPKE_CTX_new(mode, suite,
                                  OSSL_HPKE_ROLE_RECEIVER,
                                  NULL, NULL)) == NULL)
        goto err;

    if (OSSL_HPKE_decap(rctx, enc, enclen, priv, info, infolen) != 1)
        goto err;

    if (OSSL_HPKE_open(rctx, clear, &clearlen, aad, aadlen, ct, ctlen) != 1)
        goto err;

err:

    OSSL_HPKE_CTX_free(rctx);
    OSSL_HPKE_CTX_free(sctx);
    EVP_PKEY_free(priv);

    printf("pt0: %s\n", pt);
    printf("pt1: %s\n", clear);

    return 0;
}

int main_auth_dhkem_ossl(void)
{
    int mode = OSSL_HPKE_MODE_AUTH;
    OSSL_HPKE_SUITE suite = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_CTX *sctx = NULL, *rctx = NULL;
    EVP_PKEY *skR = NULL;
    unsigned char pkR[LBUFSIZE];
    size_t pkRlen = sizeof(pkR);
    EVP_PKEY *skS = NULL;
    unsigned char pkS[LBUFSIZE];
    size_t pkSlen = sizeof(pkS);

    unsigned char enc[LBUFSIZE];
    size_t enclen = sizeof(enc);
    unsigned char ct[LBUFSIZE] = {0};
    size_t ctlen = sizeof(ct);
    unsigned char clear[LBUFSIZE] = {0};
    size_t clearlen = sizeof(clear);
    const unsigned char *pt = (const unsigned char *)"a message not in a bottle";
    size_t ptlen = strlen((char *)pt);
    const unsigned char *info = (const unsigned char *)"Some info";
    size_t infolen = strlen((char *)info);
    unsigned char aad[] = {1, 2, 3, 4, 5, 6, 7, 8};
    size_t aadlen = sizeof(aad);

    /* Generate receiver's key pair. */
    if (OSSL_HPKE_keygen(suite, pkR, &pkRlen, &skR,
                         NULL, 0, NULL, NULL) != 1)
        goto err;

    /* Generate sender's key pair. */
    if (OSSL_HPKE_keygen(suite, pkS, &pkSlen, &skS,
                         NULL, 0, NULL, NULL) != 1)
        goto err;

    /* sender's actions - encrypt data using the receivers public key */
    if ((sctx = OSSL_HPKE_CTX_new(mode, suite,
                                  OSSL_HPKE_ROLE_SENDER,
                                  NULL, NULL)) == NULL)
        goto err;

    if (OSSL_HPKE_CTX_set1_authpriv(sctx, skS) != 1)
        goto err;

    if (OSSL_HPKE_encap(sctx, enc, &enclen, pkR, pkRlen, info, infolen) != 1)
        goto err;

    if (OSSL_HPKE_seal(sctx, ct, &ctlen, aad, aadlen, pt, ptlen) != 1)
        goto err;

    /* receiver's actions - decrypt data using the receivers private key */
    if ((rctx = OSSL_HPKE_CTX_new(mode, suite,
                                  OSSL_HPKE_ROLE_RECEIVER,
                                  NULL, NULL)) == NULL)
        goto err;

    if (OSSL_HPKE_CTX_set1_authpub(rctx, pkS, pkSlen) != 1)
        goto err;

    if (OSSL_HPKE_decap(rctx, enc, enclen, skR, info, infolen) != 1)
        goto err;

    if (OSSL_HPKE_open(rctx, clear, &clearlen, aad, aadlen, ct, ctlen) != 1)
        goto err;

err:

    OSSL_HPKE_CTX_free(rctx);
    OSSL_HPKE_CTX_free(sctx);
    EVP_PKEY_free(skS);
    EVP_PKEY_free(skR);

    printf("pt0: %s\n", pt);
    printf("pt1: %s\n", clear);

    return 0;
}

void bench_dhkem_encapdecap_ossl(void)
{
    int mode = OSSL_HPKE_MODE_BASE;
    OSSL_HPKE_SUITE suite = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_CTX *sctx = NULL, *rctx = NULL;
    EVP_PKEY *priv = NULL;
    unsigned char pub[LBUFSIZE];
    size_t publen = sizeof(pub);
    unsigned char enc[LBUFSIZE];
    size_t enclen = sizeof(enc);
    unsigned char ct[LBUFSIZE] = {0};
    size_t ctlen = sizeof(ct);
    unsigned char clear[LBUFSIZE] = {0};
    size_t clearlen = sizeof(clear);
    const unsigned char *pt = (const unsigned char *)"a message not in a bottle";
    size_t ptlen = strlen((char *)pt);
    const unsigned char *info = (const unsigned char *)"Some info";
    size_t infolen = strlen((char *)info);
    unsigned char aad[] = {1, 2, 3, 4, 5, 6, 7, 8};
    size_t aadlen = sizeof(aad);

    /*
     * Generate receiver's key pair.
     * The receiver gives this public key to the sender.
     */
    if (OSSL_HPKE_keygen(suite, pub, &publen, &priv,
                         NULL, 0, NULL, NULL) != 1)
        goto err;

    /* sender's actions - encrypt data using the receivers public key */
    if ((sctx = OSSL_HPKE_CTX_new(mode, suite,
                                  OSSL_HPKE_ROLE_SENDER,
                                  NULL, NULL)) == NULL)
        goto err;

    if (OSSL_HPKE_encap(sctx, enc, &enclen, pub, publen, info, infolen) != 1)
        goto err;

    if (OSSL_HPKE_seal(sctx, ct, &ctlen, aad, aadlen, pt, ptlen) != 1)
        goto err;

    /* receiver's actions - decrypt data using the receivers private key */
    if ((rctx = OSSL_HPKE_CTX_new(mode, suite,
                                  OSSL_HPKE_ROLE_RECEIVER,
                                  NULL, NULL)) == NULL)
        goto err;

    if (OSSL_HPKE_decap(rctx, enc, enclen, priv, info, infolen) != 1)
        goto err;

    if (OSSL_HPKE_open(rctx, clear, &clearlen, aad, aadlen, ct, ctlen) != 1)
        goto err;

err:

    OSSL_HPKE_CTX_free(rctx);
    OSSL_HPKE_CTX_free(sctx);

    oper_second(, keygen,
                EVP_PKEY *sk = NULL;
                OSSL_HPKE_keygen(suite, pub, &publen, &sk, NULL, 0, NULL, NULL);
                EVP_PKEY_free(sk));

    oper_second(, encap,
                OSSL_HPKE_CTX *sctx = OSSL_HPKE_CTX_new(mode, suite, OSSL_HPKE_ROLE_SENDER,
                                                        NULL, NULL);
                OSSL_HPKE_encap(sctx, enc, &enclen, pub, publen, NULL, 0);
                OSSL_HPKE_CTX_free(sctx));

    oper_second(, decap,
                OSSL_HPKE_CTX *rctx = OSSL_HPKE_CTX_new(mode, suite, OSSL_HPKE_ROLE_RECEIVER,
                                                        NULL, NULL);
                OSSL_HPKE_decap(rctx, enc, enclen, priv, NULL, 0);
                OSSL_HPKE_CTX_free(rctx));

    EVP_PKEY_free(priv);
}

void bench_dhkem_auth_encapdecap_ossl(void)
{
    int mode = OSSL_HPKE_MODE_AUTH;
    OSSL_HPKE_SUITE suite = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_CTX *sctx = NULL, *rctx = NULL;
    EVP_PKEY *skR = NULL;
    unsigned char pkR[LBUFSIZE];
    size_t pkRlen = sizeof(pkR);
    EVP_PKEY *skS = NULL;
    unsigned char pkS[LBUFSIZE];
    size_t pkSlen = sizeof(pkS);

    unsigned char enc[LBUFSIZE];
    size_t enclen = sizeof(enc);
    unsigned char ct[LBUFSIZE] = {0};
    size_t ctlen = sizeof(ct);
    unsigned char clear[LBUFSIZE] = {0};
    size_t clearlen = sizeof(clear);
    const unsigned char *pt = (const unsigned char *)"a message not in a bottle";
    size_t ptlen = strlen((char *)pt);
    const unsigned char *info = (const unsigned char *)"Some info";
    size_t infolen = strlen((char *)info);
    unsigned char aad[] = {1, 2, 3, 4, 5, 6, 7, 8};
    size_t aadlen = sizeof(aad);

    /* Generate receiver's key pair. */
    if (OSSL_HPKE_keygen(suite, pkR, &pkRlen, &skR,
                         NULL, 0, NULL, NULL) != 1)
        goto err;

    /* Generate sender's key pair. */
    if (OSSL_HPKE_keygen(suite, pkS, &pkSlen, &skS,
                         NULL, 0, NULL, NULL) != 1)
        goto err;

    /* sender's actions - encrypt data using the receivers public key */
    if ((sctx = OSSL_HPKE_CTX_new(mode, suite,
                                  OSSL_HPKE_ROLE_SENDER,
                                  NULL, NULL)) == NULL)
        goto err;

    if (OSSL_HPKE_CTX_set1_authpriv(sctx, skS) != 1)
        goto err;

    if (OSSL_HPKE_encap(sctx, enc, &enclen, pkR, pkRlen, info, infolen) != 1)
        goto err;

    if (OSSL_HPKE_seal(sctx, ct, &ctlen, aad, aadlen, pt, ptlen) != 1)
        goto err;

    /* receiver's actions - decrypt data using the receivers private key */
    if ((rctx = OSSL_HPKE_CTX_new(mode, suite,
                                  OSSL_HPKE_ROLE_RECEIVER,
                                  NULL, NULL)) == NULL)
        goto err;

    if (OSSL_HPKE_CTX_set1_authpub(rctx, pkS, pkSlen) != 1)
        goto err;

    if (OSSL_HPKE_decap(rctx, enc, enclen, skR, info, infolen) != 1)
        goto err;

    if (OSSL_HPKE_open(rctx, clear, &clearlen, aad, aadlen, ct, ctlen) != 1)
        goto err;

err:

    OSSL_HPKE_CTX_free(rctx);
    OSSL_HPKE_CTX_free(sctx);

    oper_second(, keygen,
                EVP_PKEY *sk = NULL;
                unsigned char pk[LBUFSIZE];
                size_t pklen = sizeof(pk);
                OSSL_HPKE_keygen(suite, pk, &pklen, &sk, NULL, 0, NULL, NULL);
                EVP_PKEY_free(sk));

    oper_second(, auth_encap,
                OSSL_HPKE_CTX *sctx = OSSL_HPKE_CTX_new(mode, suite, OSSL_HPKE_ROLE_SENDER,
                                                        NULL, NULL);
                OSSL_HPKE_CTX_set1_authpriv(sctx, skS);
                OSSL_HPKE_encap(sctx, enc, &enclen, pkR, pkRlen, NULL, 0);
                OSSL_HPKE_CTX_free(sctx));

    oper_second(, auth_decap,
                OSSL_HPKE_CTX *rctx = OSSL_HPKE_CTX_new(mode, suite, OSSL_HPKE_ROLE_RECEIVER,
                                                        NULL, NULL);
                OSSL_HPKE_CTX_set1_authpub(rctx, pkS, pkSlen);
                OSSL_HPKE_decap(rctx, enc, enclen, skR, NULL, 0);
                OSSL_HPKE_CTX_free(rctx));

    EVP_PKEY_free(skS);
    EVP_PKEY_free(skR);
}

int main(void)
{
    info_ossl();

    printf("==== Benchmarking DH ====\n");
    printf("====== X25519 OSSL ======\n");
    bench_x25519(&XDH_ossl);

    printf("===== Benchmarking DHKEM ====\n");
    printf("====== EncapDecap OSSL ======\n");
    bench_dhkem_encapdecap(&XDH_ossl);
    printf("==== HPKE OSSL ====\n");
    bench_dhkem_encapdecap_ossl();

    printf("===== Benchmarking AuthDHKEM ====\n");
    printf("==== AuthEncapDecap OSSL ====\n");
    bench_dhkem_authencapdecap(&XDH_ossl);
    printf("==== HPKE OSSL ====\n");
    bench_dhkem_auth_encapdecap_ossl();

    return 0;
}
