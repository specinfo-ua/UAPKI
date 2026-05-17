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

#define FILE_MARKER "cm-pkcs12/crypto/pkcs5.c"

#include "pkcs5.h"
#include "macros-internal.h"
#include "aid.h"
#include "oids.h"
#include "oid-utils.h"
#include "IITParams.h"
#include "cm-errors.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
  #include "ba-utils.h"
  #define DEBUG_OUTCON(expression) expression
#endif


static int gost28147_crypt(const AlgorithmIdentifier_t* aid, const ByteArray* key, CryptDirection direction, const ByteArray* data, ByteArray** crypted)
{
    int ret = RET_OK;
    ByteArray* iv = NULL;
    ByteArray* sbox = NULL;
    Gost28147Ctx* gost28147_ctx = NULL;
    int gost28147_mode = 0;
    char* alg_oid = NULL;

    DO(asn_oid_to_text(&aid->algorithm, &alg_oid));

    if (oid_is_equal(OID_GOST28147_CTR, alg_oid)) {
        gost28147_mode = 2;
    }
    else if (oid_is_equal(OID_GOST28147_CFB, alg_oid)) {
        gost28147_mode = 3;
    }
    else {
        SET_ERROR(RET_CM_UNSUPPORTED_CIPHER_ALG);
    }

    DO(aid_gost28147_get_iv_and_sbox(aid, &iv, &sbox));
    if (sbox) {
        CHECK_NOT_NULL(gost28147_ctx = gost28147_alloc_user_sbox(sbox));
    }
    else {
        CHECK_NOT_NULL(gost28147_ctx = gost28147_alloc(GOST28147_SBOX_ID_1));
    }

    if (gost28147_mode == 2) {
        DO(gost28147_init_ctr(gost28147_ctx, key, iv));
    }
    else {
        DO(gost28147_init_cfb(gost28147_ctx, key, iv));
    }

    if (direction == DIRECTION_ENCRYPT) {
        DO(gost28147_encrypt(gost28147_ctx, data, crypted));
    } 
    else {
        DO(gost28147_decrypt(gost28147_ctx, data, crypted));
    }

cleanup:
    free(alg_oid);
    ba_free(sbox);
    ba_free(iv);
    gost28147_free(gost28147_ctx);
    return ret;
}

static int aid_dstu7624_get_iv(const AlgorithmIdentifier_t* aid, ByteArray** iv)
{
    int ret = RET_OK;
    uint8_t* dke = NULL;
    //  Dstu7624Parameters_t is missed - use GOST28147ParamsOptionalDke_t without DKE instead it
    GOST28147ParamsOptionalDke_t* gost28147_params = NULL;

    CHECK_NOT_NULL(gost28147_params = asn_any2type(aid->parameters, get_GOST28147ParamsOptionalDke_desc()));
    DO(asn_OCTSTRING2ba(&gost28147_params->iv, iv));
    if (gost28147_params->dke) {
        SET_ERROR(RET_CM_UNSUPPORTED_PARAMETER);
    }

cleanup:
    free(dke);
    asn_free(get_GOST28147ParamsOptionalDke_desc(), gost28147_params);
    return ret;
}

static int dstu7624_crypt(const ByteArray* key, const ByteArray* iv, CryptDirection direction, const ByteArray* data, ByteArray** crypted)
{
    int ret = RET_OK;
    Dstu7624Ctx* ctx = NULL;

    CHECK_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    DO(dstu7624_init_cbc(ctx, key, iv));

    if (direction == DIRECTION_ENCRYPT) {
        DO(dstu7624_encrypt(ctx, data, crypted));
    }
    else {
        DO(dstu7624_decrypt(ctx, data, crypted));
    }

cleanup:
    dstu7624_free(ctx);
    return ret;
}

static int pbkdf2_dstu7564kmac(const char* pass, const ByteArray* salt, size_t iterations, size_t key_len, HashAlg hash_alg, ByteArray** dk)
{
    int ret = RET_OK;
    ByteArray* iv = NULL;
    ByteArray* pass_ba = NULL;
    ByteArray* count_ba = NULL;
    ByteArray* key = NULL;
    ByteArray* out = NULL;
    ByteArray* u = NULL;
    size_t cplen = 0;
    size_t i;
    unsigned int count = 1;
    uint8_t count_buf[4] = { 0 };
    Dstu7564Ctx* hmac_ctx = NULL;
    size_t hash_len = 0;

    CHECK_PARAM(pass != NULL);
    CHECK_PARAM(salt != NULL);
    CHECK_PARAM(dk != NULL);

    CHECK_NOT_NULL(out = ba_alloc());

    CHECK_NOT_NULL(pass_ba = ba_alloc_from_str(pass));

    /* F(P, S, c, i) = U1 xor U2 xor ... Uc
     *
     * U1 = PRF(P, S || i)
     * U2 = PRF(P, U1)
     * Uc = PRF(P, Uc-1)
     *
     * T_1 = F (P, S, c, 1) ,
     * T_2 = F (P, S, c, 2) ,
     * ...
     * T_l = F (P, S, c, l)
     */

    CHECK_NOT_NULL(hmac_ctx = dstu7564_alloc());
    hash_len = hash_get_size(hash_alg);
    DO(ba_change_len(pass_ba, hash_len));

    while (key_len) {
        if (key_len > hash_len) {
            cplen = hash_len;
        }
        else {
            cplen = key_len;
        }

        count_buf[0] = (count >> 24) & 0xff;
        count_buf[1] = (count >> 16) & 0xff;
        count_buf[2] = (count >> 8) & 0xff;
        count_buf[3] = count & 0xff;

        CHECK_NOT_NULL((count_ba = ba_alloc_from_uint8(count_buf, sizeof(count_buf))));

        if (count == 1) {
            DO(dstu7564_init_kmac(hmac_ctx, pass_ba, 32));
        }

        DO(dstu7564_update_kmac(hmac_ctx, salt));
        DO(dstu7564_update_kmac(hmac_ctx, count_ba));
        DO(dstu7564_final_kmac(hmac_ctx, &u));

        CHECK_NOT_NULL(key = ba_copy_with_alloc(u, 0, cplen));

        for (i = 1; i < iterations; i++) {
            DO(dstu7564_update_kmac(hmac_ctx, u));

            ba_free(u);
            u = NULL;

            DO(dstu7564_final_kmac(hmac_ctx, &u));
            DO(ba_xor(key, u));
        }

        //Добавляем результат в Т
        ba_append(key, 0, cplen, out);
        //Увеличиваем счетчик.
        count++;
        key_len -= cplen;

        ba_free(count_ba);
        ba_free_private(key);
        ba_free(u);
        count_ba = NULL;
        key = NULL;
        u = NULL;
    }

    *dk = out;
    out = NULL;

cleanup:
    dstu7564_free(hmac_ctx);
    ba_free_private(pass_ba);
    ba_free_private(out);
    ba_free(key);
    ba_free(u);
    ba_free(iv);
    ba_free(count_ba);

    return ret;
}

static int crypt_get_key_len_by_oid(const char* oid, size_t* key_len)
{
    int ret = RET_OK;

    if (oid_is_parent(OID_GOST28147, oid) || oid_is_equal(OID_DSTU7624_256_CBC, oid)) {
        *key_len = 32;
    }
    else if (oid_is_equal(OID_AES128_CBC_PAD, oid)) {
        *key_len = 16;
    }
    else if (oid_is_equal(OID_AES192_CBC_PAD, oid)) {
        *key_len = 24;
    }
    else if (oid_is_equal(OID_AES256_CBC_PAD, oid)) {
        *key_len = 32;
    }
    else if (oid_is_equal(OID_DES_EDE3_CBC, oid)) {
        *key_len = 24;
    }
    else {
        ret = RET_CM_UNSUPPORTED_CIPHER_ALG;
    }

    return ret;
}

static int crypt_get_iv_len_by_oid(const char* oid, size_t* iv_len)
{
    int ret = RET_OK;

    if (oid_is_equal(OID_DSTU7624_256_CBC, oid)) {
        *iv_len = 32;
    }
    else if (oid_is_parent(OID_GOST28147, oid) ||
        oid_is_equal(OID_DES_EDE3_CBC, oid)) {
        *iv_len = 8;
    }
    else if (oid_is_equal(OID_AES128_CBC_PAD, oid) ||
        oid_is_equal(OID_AES192_CBC_PAD, oid) ||
        oid_is_equal(OID_AES256_CBC_PAD, oid)) {
        *iv_len = 16;
    }
    else {
        ret = RET_CM_UNSUPPORTED_CIPHER_ALG;
    }

    return ret;
}

int pbes2_crypt(CryptDirection direction, const PBES2_params_t *params, const char *pass,
        const ByteArray *data, ByteArray **crypted)
{
    int ret = RET_OK;
    AlgorithmIdentifier_t *hmac_oid = NULL;
    const PBES2_KDFs_t *kdf_params;
    ByteArray *salt = NULL;
    unsigned long iterations = 0;
    ByteArray *dk = NULL;
    size_t key_len = 0;
    OCTET_STRING_t* iv_oct_str = NULL;
    ByteArray* iv = NULL;
    ByteArray* tmp = NULL;
    HashAlg hash_alg = HASH_ALG_UNDEFINED;
    AesCtx* aes_ctx = NULL;
    DesCtx* des_ctx = NULL;
    char* oid = NULL;
    char* crypt_oid = NULL;
    char* hash_oid = NULL;

    CHECK_PARAM(params != NULL);
    CHECK_PARAM(pass != NULL);
    CHECK_PARAM(data != NULL);
    CHECK_PARAM(crypted != NULL);

    DO(asn_oid_to_text(&params->keyDerivationFunc.algorithm, &oid));

    if (!oid_is_equal(OID_PKCS5_PBKDF2, oid)) {
        SET_ERROR(RET_CM_UNSUPPORTED_KEY_DERIVATION_FUNC_ALG);
    }

    kdf_params = &params->keyDerivationFunc;

    DO(asn_OCTSTRING2ba(&kdf_params->parameters.salt.choice.specified, &salt));
    DO(asn_INTEGER2ulong(&kdf_params->parameters.iterationCount, &iterations));

    DO(asn_oid_to_text(&kdf_params->parameters.prf->algorithm, &hash_oid));
    if ((hash_alg = hash_from_oid(hash_oid)) == HASH_ALG_UNDEFINED) {
        SET_ERROR(RET_CM_UNSUPPORTED_KEY_DERIVATION_FUNC_ALG);
    }

    DO(asn_oid_to_text(&params->encryptionScheme.algorithm, &crypt_oid));
    DO(crypt_get_key_len_by_oid(crypt_oid, &key_len));
    
    switch (hash_alg) {
    case HASH_ALG_DSTU7564_256:
    case HASH_ALG_DSTU7564_384:
    case HASH_ALG_DSTU7564_512:
        DO(pbkdf2_dstu7564kmac(pass, salt, iterations, key_len, hash_alg, &dk));
        break;
    default:
        DO(pbkdf2(pass, salt, iterations, key_len, hash_alg, &dk));
    }

    if (oid_is_parent(OID_DSTU7624_256_CBC, crypt_oid)) {
        DO(aid_dstu7624_get_iv(&params->encryptionScheme, &iv));
        if (direction == DIRECTION_ENCRYPT) {
            DO(make_pkcs7_padding(data, 32, &tmp));
            DEBUG_OUTCON( printf("pbes2_crypt(), dstu7624_crypt(ENCRYPT), padded:    "); ba_print(stdout, tmp); )
            DO(dstu7624_crypt(dk, iv, direction, tmp, crypted));
            DEBUG_OUTCON( printf("pbes2_crypt(), dstu7624_crypt(ENCRYPT), encrypted: "); ba_print(stdout, *crypted); )
        }
        else {
            DO(dstu7624_crypt(dk, iv, direction, data, &tmp));
            DEBUG_OUTCON( printf("pbes2_crypt(), dstu7624_crypt(DECRYPT), decrypted: "); ba_print(stdout, tmp); )
            DO(make_pkcs7_unpadding(tmp, crypted));
            DEBUG_OUTCON( printf("pbes2_crypt(), dstu7624_crypt(DECRYPT), unpadded:  "); ba_print(stdout, *crypted); )
        }
    }
    else if (oid_is_parent(OID_GOST28147, crypt_oid)) {
        DO(gost28147_crypt(&params->encryptionScheme, dk, direction, data, crypted));
    }
    else {
        CHECK_NOT_NULL(iv_oct_str = asn_any2type(params->encryptionScheme.parameters, get_OCTET_STRING_desc()));
        DO(asn_OCTSTRING2ba(iv_oct_str, &iv));

        if ((oid_is_equal(OID_AES128_CBC_PAD, crypt_oid)) ||
            (oid_is_equal(OID_AES192_CBC_PAD, crypt_oid)) ||
            (oid_is_equal(OID_AES256_CBC_PAD, crypt_oid))) {
            CHECK_NOT_NULL(aes_ctx = aes_alloc());
            DO(aes_init_cbc(aes_ctx, dk, iv));
            if (direction == DIRECTION_ENCRYPT) {
                DO(make_pkcs7_padding(data, 16, &tmp));
                DO(aes_encrypt(aes_ctx, tmp, crypted));
            }
            else {
                DO(aes_decrypt(aes_ctx, data, &tmp));
                DO(make_pkcs7_unpadding(tmp, crypted));
            }
        }
        else if (oid_is_equal(OID_DES_EDE3_CBC, crypt_oid)) {
            CHECK_NOT_NULL(des_ctx = des_alloc());
            DO(des_init_cbc(des_ctx, dk, iv));
            if (direction == DIRECTION_ENCRYPT) {
                DO(make_pkcs7_padding(data, 8, &tmp));
                DO(des3_encrypt(des_ctx, tmp, crypted));
            }
            else {
                DO(des3_decrypt(des_ctx, data, &tmp));
                DO(make_pkcs7_unpadding(tmp, crypted));
            }
        }
        else {
            SET_ERROR(RET_CM_UNSUPPORTED_CIPHER_ALG);
        }
    }

cleanup:
    free(oid);
    free(crypt_oid);
    free(hash_oid);
    ba_free(salt);
    ba_free(iv);
    ba_free_private(dk);
    ba_free_private(tmp);
    asn_free(get_AlgorithmIdentifier_desc(), hmac_oid);
    asn_free(get_OCTET_STRING_desc(), iv_oct_str);
    aes_free(aes_ctx);
    des_free(des_ctx);

    return ret;
}

int pbes1_crypt(CryptDirection direction, const PBKDF2_params_t* params,
        const char* pass, const ByteArray* data, ByteArray** crypted)
{
    int ret = RET_OK;

    unsigned long iterations = 0;
    ByteArray* dk = NULL;
    ByteArray* iv = NULL;
    ByteArray* salt = NULL;
    ByteArray* tmp = NULL;
    DesCtx* des_ctx = NULL;

    CHECK_PARAM(params != NULL);
    CHECK_PARAM(pass != NULL);
    CHECK_PARAM(data != NULL);
    CHECK_PARAM(crypted != NULL);

    DO(asn_INTEGER2ulong(&params->iterationCount, &iterations));
    DO(asn_OCTSTRING2ba(&params->salt.choice.specified, &salt));

    DO(pbkdf1(pass, salt, 1, iterations, 24, HASH_ALG_SHA1, &dk));
    DO(pbkdf1(pass, salt, 2, iterations, 8, HASH_ALG_SHA1, &iv));

    CHECK_NOT_NULL(des_ctx = des_alloc());
    DO(des_init_cbc(des_ctx, dk, iv));

    if (direction == DIRECTION_ENCRYPT) {
        DO(make_pkcs7_padding(data, 8, &tmp));
        DO(des3_encrypt(des_ctx, tmp, crypted));
    }
    else {
        DO(des3_decrypt(des_ctx, data, &tmp));
        DO(make_pkcs7_unpadding(tmp, crypted));
    }

cleanup:

    ba_free(iv);
    ba_free(tmp);
    ba_free(dk);
    ba_free(salt);
    des_free(des_ctx);

    return ret;
}

static int iit_hash_pass(const char *pass, ByteArray **hash_pass)
{
    int ret = RET_OK;
    int i;

    ByteArray *pass_ba = NULL;
    ByteArray *hash = NULL;
    HashCtx *hash_ctx = NULL;

    CHECK_PARAM(pass != NULL);
    CHECK_PARAM(hash_pass != NULL);

    CHECK_NOT_NULL(pass_ba = ba_alloc_from_str(pass));

    CHECK_NOT_NULL(hash_ctx = hash_alloc(HASH_ALG_GOST34311));
    DO(hash_update(hash_ctx, pass_ba));
    DO(hash_final(hash_ctx, &hash));

    for (i = 1; i < 10000; i++) {
        DO(hash_update(hash_ctx, hash));

        ba_free(hash);
        hash = NULL;

        DO(hash_final(hash_ctx, &hash));
    }

    *hash_pass = hash;
    hash = NULL;

cleanup:

    ba_free(pass_ba);
    ba_free(hash);
    hash_free(hash_ctx);
    return ret;
}

static int iit_decrypt(const IITParams_t *params, const char *pass,
                       const ByteArray *encrypted, ByteArray **decrypted)
{
    int ret = RET_OK;

    Gost28147Ctx *ctx = NULL;
    ByteArray *hash = NULL;
    ByteArray *aux = NULL;
    ByteArray *mac = NULL;
    ByteArray *calc_mac = NULL;
    ByteArray *encr = NULL;
    ByteArray *decr = NULL;
    ByteArray *decrLow = NULL;

    CHECK_PARAM(params != NULL);
    CHECK_PARAM(pass != NULL);
    CHECK_PARAM(encrypted != NULL);

    DO(iit_hash_pass(pass, &hash));

    DO(asn_OCTSTRING2ba(&params->mac, &mac));
    DO(asn_OCTSTRING2ba(&params->aux, &aux));

    CHECK_NOT_NULL(encr = ba_join(encrypted, aux));

    CHECK_NOT_NULL(ctx = gost28147_alloc(GOST28147_SBOX_ID_1));

    DO(gost28147_init_ecb(ctx, hash));
    DO(gost28147_decrypt(ctx, encr, &decr));

    CHECK_NOT_NULL(decrLow = ba_copy_with_alloc(decr, 0, ba_get_len(decr) - ba_get_len(aux)));

    DO(gost28147_init_mac(ctx, hash));
    DO(gost28147_update_mac(ctx, decrLow));
    DO(gost28147_final_mac(ctx, &calc_mac));

    if (ba_cmp(mac, calc_mac)) {
        SET_ERROR(RET_CM_INVALID_PASSWORD);
    }

    *decrypted = decrLow;
    decrLow = NULL;

cleanup:

    ba_free(hash);
    ba_free(aux);
    ba_free(mac);
    ba_free(calc_mac);
    ba_free(encr);
    ba_free(decr);
    ba_free(decrLow);

    gost28147_free(ctx);

    return ret;
}

int pkcs8_decrypt(const ByteArray * encoded, const char * pass, ByteArray ** key, char ** oidKdf, char ** oidCipher)
{
    int ret = RET_OK;
    PBES2_params_t *pbes2 = NULL;
    PBKDF2_params_t *pbkdf2 = NULL;
    IITParams_t *iitparam = NULL;
    ByteArray *encrypted = NULL;
    char* oid = NULL;
    EncryptedPrivateKeyInfo_t* container = NULL;

    CHECK_PARAM(encoded != NULL);
    CHECK_PARAM(pass != NULL);
    CHECK_PARAM(key != NULL);

    CHECK_NOT_NULL(container = asn_decode_ba_with_alloc(get_EncryptedPrivateKeyInfo_desc(), encoded));
    DO(asn_OCTSTRING2ba(&container->encryptedData, &encrypted));

    DO(asn_oid_to_text(&container->encryptionAlgorithm.algorithm, &oid));

    if (oid_is_equal(OID_PKCS5_PBES2, oid)) {
        CHECK_NOT_NULL(pbes2 = asn_any2type(container->encryptionAlgorithm.parameters, get_PBES2_params_desc()));
        DO(pbes2_crypt(DIRECTION_DECRYPT, pbes2, pass, encrypted, key));
    } else if (oid_is_equal(OID_PBE_WITH_SHA1_TDES_CBC, oid)) {
        CHECK_NOT_NULL(pbkdf2 = asn_any2type(container->encryptionAlgorithm.parameters, get_PBKDF2_params_desc()));
        DO(pbes1_crypt(DIRECTION_DECRYPT, pbkdf2, pass, encrypted, key));
    } else if (oid_is_equal(OID_IIT_KEYSTORE, oid)) {
        CHECK_NOT_NULL(iitparam = asn_any2type(container->encryptionAlgorithm.parameters, get_IITParams_desc()));
        DO(iit_decrypt(iitparam, pass, encrypted, key));
    } else {
        SET_ERROR(RET_CM_UNSUPPORTED_CIPHER_ALG);
    }

    if ((oidKdf != NULL) && (oidCipher != NULL)) {
        if (oid_is_equal(OID_PKCS5_PBES2, oid)) {
            free(oid);
            oid = NULL;
            DO(asn_oid_to_text(&pbes2->keyDerivationFunc.algorithm, &oid));
            if (oid_is_equal(OID_PKCS5_PBKDF2, oid)) {
                PBKDF2_params_t* pbkdf2_param;
                free(oid);
                oid = NULL;
                pbkdf2_param = &pbes2->keyDerivationFunc.parameters;
                if (pbkdf2_param->prf) {
                    DO(asn_oid_to_text(&pbkdf2_param->prf->algorithm, oidKdf));
                }
            }
            DO(asn_oid_to_text(&pbes2->encryptionScheme.algorithm, oidCipher));
        }
        else {
            *oidCipher = strdup(oid);
        }
    }

cleanup:
    free(oid);
    ba_free(encrypted);
    asn_free(get_PBES2_params_desc(), pbes2);
    asn_free(get_PBKDF2_params_desc(), pbkdf2);
    asn_free(get_IITParams_desc(), iitparam);
    asn_free(get_EncryptedPrivateKeyInfo_desc(), container);
    return ret;
}

int pkcs8_pbes2_encrypt(const ByteArray* key, const char* pass, size_t iterations,
    const char* kdf_oid, const char* cipher_oid, ByteArray** container)
{
    int ret = RET_OK;

    EncryptedPrivateKeyInfo_t *ecrypt_key = NULL;
    PBES2_params_t *pbes2 = NULL;
    AlgorithmIdentifier_t* encrypt_aid = NULL;
    AlgorithmIdentifier_t* kdf_aid = NULL;
    PBES2_KDFs_t* kdf_params = NULL;
    GOST28147ParamsOptionalDke_t* gost28147_params = NULL;
    NULL_t* null_params = NULL;
    ByteArray* encrypted = NULL;
    ByteArray* salt = NULL;
    ByteArray* iv = NULL;
    OCTET_STRING_t* iv_oct_str = NULL;
    size_t iv_len;

    CHECK_PARAM(key != NULL);
    CHECK_PARAM(pass != NULL);
    CHECK_PARAM(kdf_oid != NULL);
    CHECK_PARAM(cipher_oid != NULL);
    CHECK_PARAM(container != NULL);

    DO(crypt_get_iv_len_by_oid(cipher_oid, &iv_len));
    CHECK_NOT_NULL(iv = ba_alloc_by_len(iv_len));
    DO(drbg_random(iv));
    ASN_ALLOC(iv_oct_str);
    DO(asn_ba2OCTSTRING(iv, iv_oct_str));

    CHECK_NOT_NULL(salt = ba_alloc_by_len(20));
    DO(drbg_random(salt));

    ASN_ALLOC(kdf_params);
    DO(asn_set_oid_from_text(OID_PKCS5_PBKDF2, &kdf_params->algorithm));
    DO(asn_ulong2INTEGER(&kdf_params->parameters.iterationCount, (unsigned long)iterations));
    kdf_params->parameters.salt.present = PBKDF2_Salt_PR_specified;
    DO(asn_ba2OCTSTRING(salt, &kdf_params->parameters.salt.choice.specified));

    ASN_ALLOC(kdf_aid);
    DO(asn_set_oid_from_text(kdf_oid, &kdf_aid->algorithm));
    ASN_ALLOC(null_params);
    DO(asn_create_any(get_NULL_desc(), null_params, &kdf_aid->parameters));

    CHECK_NOT_NULL(kdf_params->parameters.prf = asn_copy_with_alloc(get_AlgorithmIdentifier_desc(), kdf_aid));

    ASN_ALLOC(encrypt_aid);
    DO(asn_set_oid_from_text(cipher_oid, &encrypt_aid->algorithm));
    if (oid_is_parent(OID_DSTU7624, cipher_oid) || oid_is_parent(OID_GOST28147, cipher_oid)) {
        ASN_ALLOC(gost28147_params);
        DO(asn_copy(get_OCTET_STRING_desc(), iv_oct_str, &gost28147_params->iv));
        DO(asn_create_any(get_GOST28147ParamsOptionalDke_desc(), gost28147_params, &encrypt_aid->parameters));
    }
    else {
        DO(asn_create_any(get_OCTET_STRING_desc(), iv_oct_str, &encrypt_aid->parameters));
    }

    ASN_ALLOC(pbes2);
    DO(asn_copy(get_PBES2_KDFs_desc(), kdf_params, &pbes2->keyDerivationFunc));
    DO(asn_copy(get_AlgorithmIdentifier_desc(), encrypt_aid, &pbes2->encryptionScheme));
    DO(pbes2_crypt(DIRECTION_ENCRYPT, pbes2, pass, key, &encrypted));

    ASN_ALLOC(ecrypt_key);
    DO(asn_set_oid_from_text(OID_PKCS5_PBES2, &ecrypt_key->encryptionAlgorithm.algorithm));
    DO(asn_create_any(get_PBES2_params_desc(), pbes2, &ecrypt_key->encryptionAlgorithm.parameters));
    DO(asn_ba2OCTSTRING(encrypted, &ecrypt_key->encryptedData));
    DO(asn_encode_ba(get_EncryptedPrivateKeyInfo_desc(), ecrypt_key, container));

cleanup:
    ba_free(encrypted);
    ba_free(salt);
    ba_free(iv);
    asn_free(get_OCTET_STRING_desc(), iv_oct_str);
    asn_free(get_EncryptedPrivateKeyInfo_desc(), ecrypt_key);
    asn_free(get_AlgorithmIdentifier_desc(), encrypt_aid);
    asn_free(get_AlgorithmIdentifier_desc(), kdf_aid);
    asn_free(get_PBES2_params_desc(), pbes2);
    asn_free(get_PBES2_KDFs_desc(), kdf_params);
    asn_free(get_GOST28147ParamsOptionalDke_desc(), gost28147_params);
    asn_free(get_NULL_desc(), null_params);
    return ret;
}

