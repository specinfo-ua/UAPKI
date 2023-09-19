/*
 * Copyright (c) 2021, The UAPKI Project Authors.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define FILE_MARKER "common/pkix/key-wrap.c"

#include "key-wrap.h"
#include "aid.h"
#include "cm-errors.h"
#include "iso15946.h"
#include "macros-internal.h"
#include "oids.h"
#include "private-key.h"
#include "uapkic.h"
#include "uapkif.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
    #define DEBUG_OUTCON(expression) expression
#endif

#define GOST28147_SBOX_SIZE    128

static int dke_to_sbox (const ByteArray* baDKE, ByteArray** baSbox)
{
    int ret = RET_OK;
    int count, i, j;
    uint8_t sbox[GOST28147_SBOX_SIZE] = { 0 };

    CHECK_PARAM(baDKE != NULL);
    CHECK_PARAM(baSbox != NULL);

    const uint8_t * dke = ba_get_buf_const(baDKE);
    if (ba_get_len(baDKE) != GOST28147_SBOX_SIZE / 2) {
        SET_ERROR(RET_INVALID_PARAM);
    }

    count = 0;
    for (i = 0; i < 8; i++) {
        for (j = 0; j < 16; j++) {
            sbox[count++] = (dke[(i << 3) + (j >> 1)] >> ((~j & 1) << 2)) & 0xf;
        }
    }

    CHECK_NOT_NULL(*baSbox = ba_alloc_from_uint8(sbox, GOST28147_SBOX_SIZE));

cleanup:
    return ret;
}

static HashAlg hash_from_oid_dhkdf (const char* oid, bool* withCofactor)
{
    HashAlg rv_hash = HASH_ALG_UNDEFINED;
    if (oid_is_equal(OID_COFACTOR_DH_DSTU7564_KDF, oid)) {
        rv_hash = HASH_ALG_DSTU7564_256;
        *withCofactor = true;
    }
    else if (oid_is_equal(OID_COFACTOR_DH_GOST34311_KDF, oid)) {
        rv_hash = HASH_ALG_GOST34311;
        *withCofactor = true;
    }
    else if (oid_is_equal(OID_DHSINGLEPASS_COFACTOR_DH_SHA1_KDF, oid)) {
        rv_hash = HASH_ALG_SHA1;
        *withCofactor = true;
    }
    else if (oid_is_equal(OID_STD_DH_DSTU7564_KDF, oid)) {
        rv_hash = HASH_ALG_DSTU7564_256;
        *withCofactor = false;
    }
    else if (oid_is_equal(OID_STD_DH_GOST34311_KDF, oid)) {
        rv_hash = HASH_ALG_GOST34311;
        *withCofactor = false;
    }
    else if (oid_is_equal(OID_DHSINGLEPASS_STD_DH_SHA1_KDF, oid)) {
        rv_hash = HASH_ALG_SHA1;
        *withCofactor = false;
    }
    else if (oid_is_equal(OID_DHSINGLEPASS_STD_DH_SHA256_KDF, oid)) {
        rv_hash = HASH_ALG_SHA256;
        *withCofactor = false;
    }

    return rv_hash;
}

int key_wrap (const ByteArray* baPrivateKeyInfo, bool isStaticKey,
        const char* oidDhKdf, const char* oidWrapAlgo,
        const size_t count, const ByteArray** baSpkis, const ByteArray** baSessionKeys,
        ByteArray*** baSalts, ByteArray*** baWrappedKeys)
{
    int ret = RET_OK;
    HashAlg hash_algo;
    bool with_cofactor;
    ByteArray** ba_salts = NULL;
    ByteArray** ba_wrappedkeys = NULL;
    ByteArray* ba_commonsecret = NULL;
    ByteArray* ba_kek = NULL;
    ByteArray* ba_dke = NULL;
    ByteArray* ba_sbox = NULL;
    AesCtx* aes = NULL;

    CHECK_PARAM(baPrivateKeyInfo != NULL);
    CHECK_PARAM(oidDhKdf != NULL);
    CHECK_PARAM(oidWrapAlgo != NULL);
    CHECK_PARAM(count > 0);
    CHECK_PARAM(baSpkis != NULL);
    CHECK_PARAM(baSessionKeys != NULL);
    CHECK_PARAM(baSalts != NULL);
    CHECK_PARAM(baWrappedKeys != NULL);

    //  Check oid-dh-kdf and set flag 'with_cofactor'
    hash_algo = hash_from_oid_dhkdf(oidDhKdf, &with_cofactor);
    if (hash_algo == HASH_ALG_UNDEFINED) {
        SET_ERROR(RET_CM_UNSUPPORTED_KEY_DERIVATION_FUNC_ALG);
    }

    //  Check oid-key-wrap
    if (!oid_is_equal(OID_DSTU7624_WRAP, oidWrapAlgo)
    &&  !oid_is_equal(OID_GOST28147_WRAP, oidWrapAlgo)
    &&  !oid_is_equal(OID_AES256_WRAP, oidWrapAlgo)) {
        SET_ERROR(RET_CM_UNSUPPORTED_CIPHER_ALG);
    }

    for (size_t i = 0; i < count; i++) {
        CHECK_PARAM(baSpkis[i] != NULL);
        CHECK_PARAM(baSessionKeys[i] != NULL);
    }

    if (isStaticKey) {
        CALLOC_CHECKED(ba_salts, sizeof(ByteArray*) * count);
    }
    CALLOC_CHECKED(ba_wrappedkeys, sizeof(ByteArray*) * count);

    for (size_t i = 0; i < count; i++) {
        DEBUG_OUTCON( printf("key_wrap_dstu() [%d]\n", (int)i); )
        DO(private_key_ecdh(with_cofactor, baPrivateKeyInfo, baSpkis[i], &ba_commonsecret));
        DEBUG_OUTCON( printf("key_wrap_dstu(), ba_commonsecret: ");ba_print(stdout, ba_commonsecret); )

        if (isStaticKey) {
            CHECK_NOT_NULL(ba_salts[i] = ba_alloc_by_len(64));
            DO(drbg_random(ba_salts[i]));
        }

        DO(iso15946_generate_secretc(hash_algo, oidWrapAlgo, isStaticKey ? ba_salts[i] : NULL, ba_commonsecret, &ba_kek));
        DEBUG_OUTCON( printf("key_wrap_dstu(), ba_kek: ");ba_print(stdout, ba_kek); )
        ba_free(ba_commonsecret);
        ba_commonsecret = NULL;

        if (oid_is_equal(OID_DSTU7624_WRAP, oidWrapAlgo)) {
            DO(key_wrap_dstu7624(ba_kek, baSessionKeys[i], &ba_wrappedkeys[i]));
        }
        else if (oid_is_equal(OID_AES256_WRAP, oidWrapAlgo)) {
            CHECK_NOT_NULL(aes = aes_alloc());
            DO(aes_init_wrap(aes, ba_kek, NULL));
            DO(aes_encrypt(aes, baSessionKeys[i], &ba_wrappedkeys[i]));
        }
        else {
            DO(spki_get_dstu_dke(baSpkis[i], &ba_dke));
            DEBUG_OUTCON( printf("key_wrap_dstu(), ba_dke: ");ba_print(stdout, ba_dke); )
            if (ba_dke) {
                DO(dke_to_sbox(ba_dke, &ba_sbox));
                DEBUG_OUTCON( printf("key_wrap_dstu(), ba_sbox: ");ba_print(stdout, ba_sbox); )
            }

            DO(key_wrap_gost28147(ba_sbox, ba_kek, baSessionKeys[i], &ba_wrappedkeys[i]));
            ba_free(ba_dke);
            ba_dke = NULL;
            ba_free(ba_sbox);
            ba_sbox = NULL;
        }

        ba_free(ba_kek);
        ba_kek = NULL;
    }

    *baSalts = ba_salts;
    ba_salts = NULL;
    *baWrappedKeys = ba_wrappedkeys;
    ba_wrappedkeys = NULL;

cleanup:
    if (ret != RET_OK) {
        for (size_t i = 0; i < count; i++) {
            if (ba_salts) ba_free(ba_salts[i]);
            if (ba_wrappedkeys) ba_free(ba_wrappedkeys[i]);
        }
    }
    free(ba_wrappedkeys);
    free(ba_salts);
    ba_free(ba_commonsecret);
    ba_free(ba_kek);
    ba_free(ba_dke);
    ba_free(ba_sbox);
    aes_free(aes);
    return ret;
}

int key_unwrap (const ByteArray* baPrivateKeyInfo,
    const char* oidDhKdf, const char* oidWrapAlgo,
    const size_t count, const ByteArray** baSpkis, const ByteArray** baSalts,
    const ByteArray** baWrappedKeys, ByteArray*** baSessionKeys)
{
    int ret = RET_OK;
    HashAlg hash_algo;
    bool with_cofactor;
    ByteArray** ba_sessionkeys = NULL;
    ByteArray* ba_commonsecret = NULL;
    ByteArray* ba_kek = NULL;
    ByteArray* ba_recip_spki = NULL;
    ByteArray* ba_dke = NULL;
    ByteArray* ba_sbox = NULL;
    AesCtx* aes = NULL;

    CHECK_PARAM(baPrivateKeyInfo != NULL);
    CHECK_PARAM(oidDhKdf != NULL);
    CHECK_PARAM(oidWrapAlgo != NULL);
    CHECK_PARAM(count > 0);
    CHECK_PARAM(baSpkis != NULL);
    CHECK_PARAM(baWrappedKeys != NULL);
    CHECK_PARAM(baSessionKeys != NULL);

    //  Check oid-dh-kdf and set flag 'with_cofactor'
    hash_algo = hash_from_oid_dhkdf(oidDhKdf, &with_cofactor);
    if (hash_algo == HASH_ALG_UNDEFINED) {
        SET_ERROR(RET_CM_UNSUPPORTED_KEY_DERIVATION_FUNC_ALG);
    }

    //  Check oid-key-wrap
    if (!oid_is_equal(OID_DSTU7624_WRAP, oidWrapAlgo)
    &&  !oid_is_equal(OID_GOST28147_WRAP, oidWrapAlgo)
    &&  !oid_is_equal(OID_AES256_WRAP, oidWrapAlgo)) {
        SET_ERROR(RET_CM_UNSUPPORTED_CIPHER_ALG);
    }

    for (size_t i = 0; i < count; i++) {
        CHECK_PARAM(baSpkis[i] != NULL);
        CHECK_PARAM(baWrappedKeys[i] != NULL);
    }

    CALLOC_CHECKED(ba_sessionkeys, sizeof(ByteArray*) * count);

    for (size_t i = 0; i < count; i++) {
        DEBUG_OUTCON(printf("key_unwrap_dstu() [%d]\n", (int)i); )

        DO(private_key_ecdh(with_cofactor, baPrivateKeyInfo, baSpkis[i], &ba_commonsecret));
        DEBUG_OUTCON(printf("key_unwrap_dstu(), ba_commonsecret: "); ba_print(stdout, ba_commonsecret); )

        DO(iso15946_generate_secretc(hash_algo, oidWrapAlgo, baSalts ? baSalts[i] : NULL, ba_commonsecret, &ba_kek));
        DEBUG_OUTCON(printf("key_unwrap_dstu(), ba_kek: "); ba_print(stdout, ba_kek); )
        ba_free(ba_commonsecret);
        ba_commonsecret = NULL;

        if (oid_is_equal(OID_DSTU7624_WRAP, oidWrapAlgo)) {
            DO(key_unwrap_dstu7624(ba_kek, baWrappedKeys[i], &ba_sessionkeys[i]));
        }
        else if (oid_is_equal(OID_AES256_WRAP, oidWrapAlgo)) {
            CHECK_NOT_NULL(aes = aes_alloc());
            DO(aes_init_wrap(aes, ba_kek, NULL));
            DO(aes_decrypt(aes, baWrappedKeys[i], &ba_sessionkeys[i]));
        }
        else {
            DO(private_key_get_spki(baPrivateKeyInfo, &ba_recip_spki));
            DO(spki_get_dstu_dke(ba_recip_spki, &ba_dke));
            DEBUG_OUTCON(printf("key_unwrap_dstu(), ba_dke: "); ba_print(stdout, ba_dke); )
                if (ba_dke) {
                    DO(dke_to_sbox(ba_dke, &ba_sbox));
                    DEBUG_OUTCON(printf("key_unwrap_dstu(), ba_sbox: "); ba_print(stdout, ba_sbox); )
                }

            DO(key_unwrap_gost28147(ba_sbox, ba_kek, baWrappedKeys[i], &ba_sessionkeys[i]));
        }

        ba_free(ba_kek);
        ba_kek = NULL;
    }

    *baSessionKeys = ba_sessionkeys;
    ba_sessionkeys = NULL;

cleanup:
    if ((ret != RET_OK) && (ba_sessionkeys != NULL)) {
        for (size_t i = 0; i < count; i++) {
            ba_free(ba_sessionkeys[i]);
        }
    }
    free(ba_sessionkeys);
    ba_free(ba_commonsecret);
    ba_free(ba_kek);
    ba_free(ba_recip_spki);
    ba_free(ba_dke);
    ba_free(ba_sbox);
    aes_free(aes);
    return ret;
}

