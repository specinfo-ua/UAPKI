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


#define FILE_MARKER "common/pkix/key-trans.c"

#include "key-trans.h"
#include "cm-errors.h"
#include "macros-internal.h"
#include "oids.h"
#include "oid-utils.h"
#include "uapkic.h"
#include "uapkif.h"
#include <string.h>


//  One DER TLV with a definite length: the tag, the offset and the length of the value
static bool der_read (const uint8_t* buf, const size_t len, uint8_t* tag, size_t* offset, size_t* vlen)
{
    size_t pos = 2, value_len;

    if (len < 2) return false;
    *tag = buf[0];
    value_len = buf[1];
    if (value_len & 0x80) {
        size_t cnt = value_len & 0x7F;
        if ((cnt == 0) || (cnt > 4) || (len < 2 + cnt)) return false;
        value_len = 0;
        while (cnt--) {
            value_len = (value_len << 8) | buf[pos++];
        }
    }
    if (value_len > len - pos) return false;
    *offset = pos;
    *vlen = value_len;
    return true;
}

//  AlgorithmIdentifier: the OID as a text; the parameters TLV (the pointer into buf) if they are present
static int der_algid (const uint8_t* buf, const size_t len, char** oid, const uint8_t** params, size_t* paramsLen)
{
    int ret = RET_OK;
    OBJECT_IDENTIFIER_t* asn_oid = NULL;
    ByteArray* ba_oid = NULL;
    uint8_t tag;
    size_t offset, vlen, oid_offset, oid_len;

    if (!der_read(buf, len, &tag, &offset, &vlen) || (tag != 0x30)) {
        SET_ERROR(RET_CM_INVALID_PARAMETER);
    }
    buf += offset;
    if (!der_read(buf, vlen, &tag, &oid_offset, &oid_len) || (tag != 0x06)) {
        SET_ERROR(RET_CM_INVALID_PARAMETER);
    }
    CHECK_NOT_NULL(ba_oid = ba_alloc_from_uint8(buf, oid_offset + oid_len));
    CHECK_NOT_NULL(asn_oid = asn_decode_ba_with_alloc(get_OBJECT_IDENTIFIER_desc(), ba_oid));
    DO(asn_oid_to_text(asn_oid, oid));
    if (params) {
        *params = (oid_offset + oid_len < vlen) ? buf + oid_offset + oid_len : NULL;
        *paramsLen = vlen - (oid_offset + oid_len);
    }

cleanup:
    asn_free(get_OBJECT_IDENTIFIER_desc(), asn_oid);
    ba_free(ba_oid);
    return ret;
}

int key_trans_parse_algo (const char* oid, const ByteArray* baParams,
        bool* isOaep, HashAlg* hashAlgo, ByteArray** baLabel)
{
    int ret = RET_OK;
    const uint8_t* buf = ba_get_buf_const(baParams);
    const uint8_t* params;
    size_t len = ba_get_len(baParams);
    size_t offset, vlen, params_len;
    HashAlg mgf_hash = HASH_ALG_SHA1;
    char* s_oid = NULL;
    uint8_t tag;

    CHECK_PARAM(oid != NULL);
    CHECK_PARAM(isOaep != NULL);
    CHECK_PARAM(hashAlgo != NULL);
    CHECK_PARAM(baLabel != NULL);

    *baLabel = NULL;
    *hashAlgo = HASH_ALG_UNDEFINED;
    if (oid_is_equal(OID_RSA, oid)) {
        *isOaep = false;
        return RET_OK;
    }
    if (!oid_is_equal(OID_RSAES_OAEP, oid)) {
        SET_ERROR(RET_CM_UNSUPPORTED_ALG);
    }

    //  RSAES-OAEP-params ::= SEQUENCE { hashFunc [0] AlgorithmIdentifier DEFAULT sha1,
    //      maskGenFunc [1] AlgorithmIdentifier DEFAULT mgf1SHA1, pSourceFunc [2] AlgorithmIdentifier DEFAULT pSpecifiedEmpty }
    *isOaep = true;
    *hashAlgo = HASH_ALG_SHA1;
    if (len == 0) return RET_OK;

    if (!der_read(buf, len, &tag, &offset, &vlen) || (tag != 0x30)) {
        SET_ERROR(RET_CM_INVALID_PARAMETER);
    }
    buf += offset;
    len = vlen;
    while (len > 0) {
        if (!der_read(buf, len, &tag, &offset, &vlen)) {
            SET_ERROR(RET_CM_INVALID_PARAMETER);
        }
        DO(der_algid(buf + offset, vlen, &s_oid, &params, &params_len));
        switch (tag) {
        case 0xA0:
            *hashAlgo = hash_from_oid(s_oid);
            break;
        case 0xA1:
            if (!oid_is_equal(OID_PKCS1_MGF1, s_oid) || !params) {
                SET_ERROR(RET_CM_UNSUPPORTED_ALG);
            }
            free(s_oid);
            s_oid = NULL;
            DO(der_algid(params, params_len, &s_oid, NULL, NULL));
            mgf_hash = hash_from_oid(s_oid);
            break;
        case 0xA2:
            if (!oid_is_equal(OID_PKCS1_PSPECIFIED, s_oid) || !params) {
                SET_ERROR(RET_CM_UNSUPPORTED_ALG);
            }
            {
                size_t label_offset, label_len;
                if (!der_read(params, params_len, &tag, &label_offset, &label_len) || (tag != 0x04)) {
                    SET_ERROR(RET_CM_INVALID_PARAMETER);
                }
                if (label_len > 0) {
                    ba_free(*baLabel);
                    CHECK_NOT_NULL(*baLabel = ba_alloc_from_uint8(params + label_offset, label_len));
                }
            }
            break;
        default:
            SET_ERROR(RET_CM_INVALID_PARAMETER);
        }
        free(s_oid);
        s_oid = NULL;
        buf += offset + vlen;
        len -= offset + vlen;
    }

    if ((*hashAlgo == HASH_ALG_UNDEFINED) || (mgf_hash != *hashAlgo)) {
        SET_ERROR(RET_CM_UNSUPPORTED_ALG);
    }

cleanup:
    free(s_oid);
    if (ret != RET_OK) {
        ba_free(*baLabel);
        *baLabel = NULL;
    }
    return ret;
}

int key_trans_decode_algid (const ByteArray* baAlgorithmIdentifier,
        char** oid, ByteArray** baParams)
{
    int ret = RET_OK;
    const uint8_t* params = NULL;
    size_t params_len = 0;

    CHECK_PARAM(baAlgorithmIdentifier != NULL);
    CHECK_PARAM(oid != NULL);
    CHECK_PARAM(baParams != NULL);

    *baParams = NULL;
    DO(der_algid(ba_get_buf_const(baAlgorithmIdentifier), ba_get_len(baAlgorithmIdentifier), oid, &params, &params_len));
    if (params && (params_len > 0)) {
        CHECK_NOT_NULL(*baParams = ba_alloc_from_uint8(params, params_len));
    }

cleanup:
    return ret;
}

int key_trans_encode_oaep_params (const HashAlg hashAlgo, ByteArray** baParams)
{
    int ret = RET_OK;
    OBJECT_IDENTIFIER_t* asn_oid = NULL;
    ByteArray* ba_hashoid = NULL;
    ByteArray* ba_mgfoid = NULL;
    const char* s_hashoid = hash_to_oid(hashAlgo);
    uint8_t buf[96];
    size_t hash_len, mgf_len, pos = 0;

    CHECK_PARAM(baParams != NULL);
    if (!s_hashoid || (hash_get_size(hashAlgo) == 0)) {
        SET_ERROR(RET_CM_UNSUPPORTED_ALG);
    }

    //  DER: the components equal to their DEFAULT (sha1, mgf1SHA1) are absent
    if (hashAlgo != HASH_ALG_SHA1) {
        ASN_ALLOC(asn_oid);
        DO(asn_set_oid_from_text(s_hashoid, asn_oid));
        DO(asn_encode_ba(get_OBJECT_IDENTIFIER_desc(), asn_oid, &ba_hashoid));
        asn_free(get_OBJECT_IDENTIFIER_desc(), asn_oid);
        asn_oid = NULL;
        ASN_ALLOC(asn_oid);
        DO(asn_set_oid_from_text(OID_PKCS1_MGF1, asn_oid));
        DO(asn_encode_ba(get_OBJECT_IDENTIFIER_desc(), asn_oid, &ba_mgfoid));

        hash_len = ba_get_len(ba_hashoid);
        mgf_len = ba_get_len(ba_mgfoid);
        if ((hash_len > 16) || (mgf_len > 16)) {
            SET_ERROR(RET_CM_UNSUPPORTED_ALG);
        }
        //  SEQUENCE { [0] { SEQUENCE { hash, NULL } }, [1] { SEQUENCE { mgf1, SEQUENCE { hash, NULL } } } }
        buf[pos++] = 0x30;
        buf[pos++] = (uint8_t)((hash_len + 6) + (mgf_len + hash_len + 8));
        buf[pos++] = 0xA0;
        buf[pos++] = (uint8_t)(hash_len + 4);
        buf[pos++] = 0x30;
        buf[pos++] = (uint8_t)(hash_len + 2);
        memcpy(buf + pos, ba_get_buf_const(ba_hashoid), hash_len);
        pos += hash_len;
        buf[pos++] = 0x05;
        buf[pos++] = 0x00;
        buf[pos++] = 0xA1;
        buf[pos++] = (uint8_t)(mgf_len + hash_len + 6);
        buf[pos++] = 0x30;
        buf[pos++] = (uint8_t)(mgf_len + hash_len + 4);
        memcpy(buf + pos, ba_get_buf_const(ba_mgfoid), mgf_len);
        pos += mgf_len;
        buf[pos++] = 0x30;
        buf[pos++] = (uint8_t)(hash_len + 2);
        memcpy(buf + pos, ba_get_buf_const(ba_hashoid), hash_len);
        pos += hash_len;
        buf[pos++] = 0x05;
        buf[pos++] = 0x00;
    }
    else {
        buf[pos++] = 0x30;
        buf[pos++] = 0x00;
    }
    CHECK_NOT_NULL(*baParams = ba_alloc_from_uint8(buf, pos));

cleanup:
    asn_free(get_OBJECT_IDENTIFIER_desc(), asn_oid);
    ba_free(ba_hashoid);
    ba_free(ba_mgfoid);
    return ret;
}

int key_trans_encrypt (const ByteArray* baSpki, const char* oid, const ByteArray* baParams,
        const ByteArray* baKey, ByteArray** baEncryptedKey)
{
    int ret = RET_OK;
    SubjectPublicKeyInfo_t* spki = NULL;
    RSAPublicKey_t* rsa_pubkey = NULL;
    RsaCtx* rsa_ctx = NULL;
    ByteArray* ba_pubkey = NULL;
    ByteArray* ba_n = NULL;
    ByteArray* ba_e = NULL;
    ByteArray* ba_label = NULL;
    char* s_keyalgo = NULL;
    HashAlg hash_algo = HASH_ALG_UNDEFINED;
    bool is_oaep = false;

    CHECK_PARAM(baSpki != NULL);
    CHECK_PARAM(baKey != NULL);
    CHECK_PARAM(baEncryptedKey != NULL);

    DO(key_trans_parse_algo(oid, baParams, &is_oaep, &hash_algo, &ba_label));

    CHECK_NOT_NULL(spki = asn_decode_ba_with_alloc(get_SubjectPublicKeyInfo_desc(), baSpki));
    DO(asn_oid_to_text(&spki->algorithm.algorithm, &s_keyalgo));
    if (!oid_is_equal(OID_RSA, s_keyalgo)) {
        SET_ERROR(RET_CM_UNSUPPORTED_ALG);
    }
    DO(asn_BITSTRING2ba(&spki->subjectPublicKey, &ba_pubkey));
    CHECK_NOT_NULL(rsa_pubkey = asn_decode_ba_with_alloc(get_RSAPublicKey_desc(), ba_pubkey));
    DO(asn_INTEGER2ba(&rsa_pubkey->modulus, &ba_n));
    DO(asn_INTEGER2ba(&rsa_pubkey->publicExponent, &ba_e));

    CHECK_NOT_NULL(rsa_ctx = rsa_alloc());
    if (is_oaep) {
        DO(rsa_init_encrypt_oaep(rsa_ctx, hash_algo, ba_label, ba_n, ba_e));
    }
    else {
        DO(rsa_init_encrypt_pkcs1_v1_5(rsa_ctx, ba_n, ba_e));
    }
    DO(rsa_encrypt(rsa_ctx, baKey, baEncryptedKey));

cleanup:
    rsa_free(rsa_ctx);
    asn_free(get_SubjectPublicKeyInfo_desc(), spki);
    asn_free(get_RSAPublicKey_desc(), rsa_pubkey);
    ba_free(ba_pubkey);
    ba_free(ba_n);
    ba_free(ba_e);
    ba_free(ba_label);
    free(s_keyalgo);
    return ret;
}

int key_trans_decrypt (const ByteArray* baModulus, const ByteArray* baPrivateExponent,
        const char* oid, const ByteArray* baParams,
        const ByteArray* baEncryptedKey, ByteArray** baKey)
{
    int ret = RET_OK;
    RsaCtx* rsa_ctx = NULL;
    ByteArray* ba_label = NULL;
    HashAlg hash_algo = HASH_ALG_UNDEFINED;
    bool is_oaep = false;

    CHECK_PARAM(baModulus != NULL);
    CHECK_PARAM(baPrivateExponent != NULL);
    CHECK_PARAM(baEncryptedKey != NULL);
    CHECK_PARAM(baKey != NULL);

    DO(key_trans_parse_algo(oid, baParams, &is_oaep, &hash_algo, &ba_label));

    CHECK_NOT_NULL(rsa_ctx = rsa_alloc());
    if (is_oaep) {
        DO(rsa_init_decrypt_oaep(rsa_ctx, hash_algo, ba_label, baModulus, baPrivateExponent));
    }
    else {
        DO(rsa_init_decrypt_pkcs1_v1_5(rsa_ctx, baModulus, baPrivateExponent));
    }
    //  Whatever is wrong with the encrypted key, the answer is the same
    if (rsa_decrypt(rsa_ctx, baEncryptedKey, baKey) != RET_OK) {
        SET_ERROR(RET_CM_INVALID_WRAPPED_KEY);
    }

cleanup:
    rsa_free(rsa_ctx);
    ba_free(ba_label);
    return ret;
}
