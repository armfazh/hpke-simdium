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

static const uint8_t KemSuiteID[5] = {'K', 'E', 'M', 0x00, 0x20};
static const uint8_t Version[7] = {'H', 'P', 'K', 'E', '-', 'v', '1'};

static void labeled_extract(u8 *key, const u8 *secret, const u8 *salt,
                            const u8 *label)
{
    u8 labeled_ikm = u8_malloc(sizeof(Version) + sizeof(KemSuiteID) + label->len +
                               secret->len);
    uint8_t *ptr = labeled_ikm.data;
    u8_append_array(&ptr, Version, sizeof(Version));
    u8_append_array(&ptr, KemSuiteID, sizeof(KemSuiteID));
    u8_append(&ptr, label);
    u8_append(&ptr, secret);

    hkdf_extract(key, &labeled_ikm, salt);
    u8_free(&labeled_ikm);
}

static void labeled_expand(u8 *out, const u8 *key, const u8 *info,
                           const u8 *label)
{
    uint8_t length[2] = {(out->len >> 8) & 0xFF, out->len & 0xFF};
    u8 labeled_info = u8_malloc(2 + sizeof(Version) + sizeof(
                                    KemSuiteID) + label->len + info->len);

    uint8_t *ptr = labeled_info.data;
    u8_append_array(&ptr, length, 2);
    u8_append_array(&ptr, Version, sizeof(Version));
    u8_append_array(&ptr, KemSuiteID, sizeof(KemSuiteID));
    u8_append(&ptr, label);
    u8_append(&ptr, info);

    hkdf_expand(out, key, &labeled_info);
    u8_free(&labeled_info);
}

void extract_and_expand(u8 *shared_secret, const u8 *dh, const u8 *kem_context)
{
    u8 label_eae = u8_string("eae_prk");
    u8 label_shared_secret = u8_string("shared_secret");
    u8_static(eae_prk, 32);
    u8_static(empty_salt, 32);
    labeled_extract(&eae_prk, dh, &empty_salt, &label_eae);
    labeled_expand(shared_secret, &eae_prk, kem_context, &label_shared_secret);
}

void extract_and_expand_single(u8 *shared_secret, const u8 *dh,
                               const u8 *kem_context)
{
    const uint8_t label_eae[7] = {'e', 'a', 'e', '_', 'p', 'r', 'k'};
    const uint8_t label_shared_secret[13] = {'s', 'h', 'a', 'r', 'e', 'd', '_', 's', 'e', 'c', 'r', 'e', 't'};

    u8 labeled_ikm = u8_malloc(sizeof(Version) + sizeof(KemSuiteID) + sizeof(
                                   label_eae) + dh->len);
    uint8_t *ptr = labeled_ikm.data;
    u8_append_array(&ptr, Version, sizeof(Version));
    u8_append_array(&ptr, KemSuiteID, sizeof(KemSuiteID));
    u8_append_array(&ptr, label_eae, sizeof(label_eae));
    u8_append(&ptr, dh);

    uint8_t length[2] = {(shared_secret->len >> 8) & 0xFF, shared_secret->len & 0xFF};
    u8 labeled_info = u8_malloc(2 + sizeof(Version) + sizeof(KemSuiteID) + sizeof(
                                    label_shared_secret) + kem_context->len);

    ptr = labeled_info.data;
    u8_append_array(&ptr, length, 2);
    u8_append_array(&ptr, Version, sizeof(Version));
    u8_append_array(&ptr, KemSuiteID, sizeof(KemSuiteID));
    u8_append_array(&ptr, label_shared_secret, sizeof(label_shared_secret));
    u8_append(&ptr, kem_context);

    hkdf_extract_expand(shared_secret, &labeled_ikm, &labeled_info);

    u8_free(&labeled_ikm);
    u8_free(&labeled_info);
}

void derive_key(u8* key, u8 *seed)
{
    u8 label_dkp = u8_string("dkp_prk");
    u8 label_sk = u8_string("sk");
    u8_static(empty_salt, 32);
    u8_static(dkp_prk, 32);
    u8 empty_info =
    {
        .data = NULL,
        .len = 0,
    };

    labeled_extract(&dkp_prk, seed, &empty_salt, &label_dkp);
    labeled_expand(key, &dkp_prk, &empty_info, &label_sk);
}