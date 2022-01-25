/*
 * Copyright (c) 2022, The UAPKI Project Authors.
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

#include "private-key.h"
#include "aid.h"
#include "cm-errors.h"
#include "dstu4145-params.h"
#include "macros-internal.h"
#include "oids.h"
#include "oid-utils.h"
#include "uapkif.h"


#undef FILE_MARKER
#define FILE_MARKER "key.c"

#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
    #include "ba-utils.h"
    #define DEBUG_OUTCON(expression) expression
#endif


static const char* HEX_DKE_BY_DEFAULT = "A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17"
                                        "F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC57904";


static int private_key_generate_dstu(const char* alg, const char* curve, ByteArray** key)
{
    int ret = RET_OK;
    PrivateKeyInfo_t* privkey = NULL;
    AlgorithmIdentifier_t* aid = NULL;
    EcCtx* ec_ctx = NULL;
    ByteArray* d = NULL;
    EcParamsId ec_id;

    CHECK_PARAM(alg != NULL);
    CHECK_PARAM(key != NULL);

    if (curve == NULL) {
        curve = OID_DSTU4145_PARAM_M257_PB;
    }

    ec_id = ecid_from_oid(curve);
    if (ec_id == EC_PARAMS_ID_UNDEFINED) {
        SET_ERROR(RET_CM_UNSUPPORTED_ELLIPTIC_CURVE);
    }

    CHECK_NOT_NULL(ec_ctx = ec_alloc_default(ec_id));

    ASN_ALLOC(privkey);
    DO(asn_long2INTEGER(&privkey->version, 0));

    DO(aid_create_dstu4145_default(alg, curve, &aid));

    DO(asn_copy(get_AlgorithmIdentifier_desc(), aid, &privkey->privateKeyAlgorithm));

    DO(dstu4145_generate_privkey(ec_ctx, &d));
    DO(asn_ba2OCTSTRING(d, &privkey->privateKey));
    DO(asn_encode_ba(get_PrivateKeyInfo_desc(), privkey, key));

cleanup:
    ba_free_private(d);
    asn_free(get_PrivateKeyInfo_desc(), privkey);
    ec_free(ec_ctx);
    asn_free(get_AlgorithmIdentifier_desc(), aid);
    return ret;
}

static int private_key_generate_ec(const char* alg, const char* curve, ByteArray** key)
{
    int ret = RET_OK;
    PrivateKeyInfo_t* privkey = NULL;
    AlgorithmIdentifier_t* aid = NULL;
    ECPrivateKey_t *ec_key = NULL;
    ByteArray* ec_key_encoded = NULL;
    EcCtx* ec_ctx = NULL;
    ByteArray* d = NULL;
    EcParamsId ec_id;

    CHECK_PARAM(alg != NULL);
    CHECK_PARAM(key != NULL);

    ec_id = ecid_from_oid(curve);
    if (ec_id == EC_PARAMS_ID_UNDEFINED) {
        SET_ERROR(RET_CM_UNSUPPORTED_ELLIPTIC_CURVE);
    }

    CHECK_NOT_NULL(ec_ctx = ec_alloc_default(ec_id));

    ASN_ALLOC(privkey);
    DO(asn_long2INTEGER(&privkey->version, 0));

    DO(aid_create_ec_default(alg, curve, &aid));

    DO(asn_copy(get_AlgorithmIdentifier_desc(), aid, &privkey->privateKeyAlgorithm));

    if (oid_is_equal(alg, OID_EC_KEY)) {
        DO(ecdsa_generate_privkey(ec_ctx, &d));
    }
    else if (oid_is_equal(alg, OID_ECGDSA_KEY)) {
        DO(ecgdsa_generate_privkey(ec_ctx, &d));
    }
    else if ((oid_is_equal(alg, OID_GOST_KEY_3410_2012_256)) || (oid_is_equal(alg, OID_GOST_KEY_3410_2012_512))) {
        DO(ecrdsa_generate_privkey(ec_ctx, &d));
    }

    ASN_ALLOC(ec_key);
    DO(asn_long2INTEGER(&ec_key->version, 1));
    DO(asn_ba2OCTSTRING(d, &ec_key->privateKey));
    DO(asn_encode_ba(get_ECPrivateKey_desc(), ec_key, &ec_key_encoded));

    DO(asn_ba2OCTSTRING(ec_key_encoded, &privkey->privateKey));
    DO(asn_encode_ba(get_PrivateKeyInfo_desc(), privkey, key));

cleanup:
    ba_free_private(d);
    ba_free_private(ec_key_encoded);
    asn_free(get_ECPrivateKey_desc(), ec_key);
    asn_free(get_PrivateKeyInfo_desc(), privkey);
    ec_free(ec_ctx);
    asn_free(get_AlgorithmIdentifier_desc(), aid);
    return ret;
}

static int private_key_generate_rsa(const char* bits, ByteArray** key)
{
    int ret = RET_OK;
    AlgorithmIdentifier_t* aid = NULL;
    PrivateKeyInfo_t* privkey = NULL;
    RSAPrivateKey_t* rsaprivkey = NULL;
    ByteArray* encoded = NULL;
    ByteArray* e = NULL;
    ByteArray* n = NULL;
    ByteArray* d = NULL;
    ByteArray* p = NULL;
    ByteArray* q = NULL;
    ByteArray* dmp1 = NULL;
    ByteArray* dmq1 = NULL;
    ByteArray* iqmp = NULL;
    static const uint8_t _e[] = {0x01, 0x00, 0x01};
    unsigned long rsabits = 0;

    CHECK_PARAM(key != NULL);

    if (bits == NULL) {
        bits = "2048";
    }

    if (strcmp("1024", bits) == 0) rsabits = 1024;
    else if (strcmp("1536", bits) == 0) rsabits = 1536;
    else if (strcmp("2048", bits) == 0) rsabits = 2048;
    else if (strcmp("3072", bits) == 0) rsabits = 3072;
    else if (strcmp("4096", bits) == 0) rsabits = 4096;
    else if (strcmp("8192", bits) == 0) rsabits = 8192;

    if (rsabits == 0) {
        SET_ERROR(RET_CM_UNSUPPORTED_RSA_LEN);
    }

    CHECK_NOT_NULL(e = ba_alloc_from_uint8(_e, 3));
    DO(rsa_generate_privkey_ext(rsabits, e, &n, &d, &p, &q, &dmp1, &dmq1, &iqmp));

    ASN_ALLOC(rsaprivkey);
    DO(asn_long2INTEGER(&rsaprivkey->version, 0));

    DO(asn_ba2INTEGER(n, &rsaprivkey->modulus));
    DO(asn_ba2INTEGER(d, &rsaprivkey->privateExponent));
    DO(asn_ba2INTEGER(e, &rsaprivkey->publicExponent));
    DO(asn_ba2INTEGER(p, &rsaprivkey->prime1));
    DO(asn_ba2INTEGER(q, &rsaprivkey->prime2));
    DO(asn_ba2INTEGER(dmp1, &rsaprivkey->exponent1));
    DO(asn_ba2INTEGER(dmq1, &rsaprivkey->exponent2));
    DO(asn_ba2INTEGER(iqmp, &rsaprivkey->coefficient));

    DO(asn_encode_ba(get_RSAPrivateKey_desc(), rsaprivkey, &encoded));

    DO(aid_create_rsa(&aid));

    ASN_ALLOC(privkey);
    DO(asn_long2INTEGER(&privkey->version, 0));
    DO(asn_copy(get_AlgorithmIdentifier_desc(), aid, &privkey->privateKeyAlgorithm));
    DO(asn_ba2OCTSTRING(encoded, &privkey->privateKey));
    DO(asn_encode_ba(get_PrivateKeyInfo_desc(), privkey, key));

cleanup:

    ba_free(e);
    ba_free(n);
    ba_free_private(d);
    ba_free_private(p);
    ba_free_private(q);
    ba_free_private(dmq1);
    ba_free_private(dmp1);
    ba_free_private(iqmp);
    ba_free_private(encoded);

    asn_free(get_PrivateKeyInfo_desc(), privkey);
    asn_free(get_RSAPrivateKey_desc(), rsaprivkey);
    asn_free(get_AlgorithmIdentifier_desc(), aid);

    return ret;
}

int private_key_generate(const char *alg, const char* param, ByteArray** key)
{
    if (oid_is_parent(OID_DSTU4145_WITH_DSTU7564, alg) || 
        oid_is_parent(OID_DSTU4145_WITH_GOST3411, alg)) {
        return private_key_generate_dstu(alg, param, key);
    }

    if (oid_is_equal(OID_EC_KEY, alg)) {
        if (param == NULL) {
            param = OID_NIST_P256;
        }

        return private_key_generate_ec(OID_EC_KEY, param, key);
    }

    if (oid_is_equal(OID_ECKCDSA, alg)) {
        if (param == NULL) {
            param = OID_NIST_P256;
        }

        return private_key_generate_ec(OID_ECGDSA_KEY, param, key);
    }

    if (oid_is_parent(OID_ECGDSA_STD, alg)) {
        if (param == NULL) {
            param = OID_BRAINPOOL_P256R1;
        }

        return private_key_generate_ec(OID_ECGDSA_KEY, param, key);
    }

    if (oid_is_equal(OID_GOST_KEY_3410_2012_256, alg)) {
        if (param == NULL) {
            param = OID_ECRDSA_256A;
        }

        return private_key_generate_ec(OID_GOST_KEY_3410_2012_256, param, key);
    }

    if (oid_is_equal(OID_GOST_KEY_3410_2012_512, alg)) {
        if (param == NULL) {
            param = OID_ECRDSA_512A;
        }

        return private_key_generate_ec(OID_GOST_KEY_3410_2012_512, param, key);
    }

    if (oid_is_equal(OID_SM2, alg)) {
        if (param == NULL) {
            param = OID_SM2DSA_P256;
        }

        return private_key_generate_ec(OID_EC_KEY, param, key);
    }

    if (oid_is_equal(OID_RSA, alg)) {
        return private_key_generate_rsa(param, key);
    }

    return RET_CM_UNSUPPORTED_ALG;
}

static int private_key_get_param_dstu(ANY_t *params, char** param)
{
    int ret = RET_OK;
    DSTU4145Params_t* dstu4145_params = NULL;

    CHECK_NOT_NULL(dstu4145_params = asn_any2type(params, get_DSTU4145Params_desc()));
    DO(dstu4145_params_get_std_oid(&dstu4145_params->ellipticCurve, param));

cleanup:
    asn_free(get_DSTU4145Params_desc(), dstu4145_params);
    return ret;
}

static int private_key_get_param_ec(ANY_t* params, char** param)
{
    int ret = RET_OK;
    ECParameters_t* ec_params = NULL;

    *param = NULL;

    CHECK_NOT_NULL(ec_params = asn_any2type(params, get_ECParameters_desc()));
    if (ec_params->present == ECParameters_PR_namedCurve) {
        DO(asn_oid_to_text(&ec_params->choice.namedCurve, param));
    }

cleanup:
    asn_free(get_ECParameters_desc(), ec_params);
    return ret;
}

static int private_key_get_param_rsa(OCTET_STRING_t* key, char** param)
{
    int ret = RET_OK;
    ByteArray* encoded_priv_key = NULL;
    RSAPrivateKey_t* rsaprivkey = NULL;
    ByteArray* n = NULL;
    int r;

    DO(asn_OCTSTRING2ba(key, &encoded_priv_key));
    CHECK_NOT_NULL(rsaprivkey = asn_decode_ba_with_alloc(get_RSAPrivateKey_desc(), encoded_priv_key));
    DO(asn_INTEGER2ba(&rsaprivkey->modulus, &n));
    MALLOC_CHECKED(*param, 8);
    r = snprintf(*param, 8, "%d", (int)(ba_get_len(n) * 8));
    if ((r < 0) || (r > 7)) {
        free(*param);
        *param = NULL;
    }

cleanup:
    ba_free(n);
    ba_free_private(encoded_priv_key);
    asn_free(get_RSAPrivateKey_desc(), rsaprivkey);
    return ret;
}

static int spki_get_param_rsa(ANY_t* params, char** param)
{
    int ret = RET_OK;
    RSAPublicKey_t* rsa_pubkey = NULL;
    ByteArray* n = NULL;
    int r;

    CHECK_NOT_NULL(rsa_pubkey = asn_any2type(params, get_RSAPublicKey_desc()));
    DO(asn_INTEGER2ba(&rsa_pubkey->modulus, &n));
    MALLOC_CHECKED(*param, 8);
    r = snprintf(*param, 8, "%d", (int)(ba_get_len(n) * 8));
    if ((r < 0) || (r > 7)) {
        free(*param);
        *param = NULL;
    }

cleanup:
    ba_free(n);
    asn_free(get_RSAPublicKey_desc(), rsa_pubkey);
    return ret;
}

int private_key_get_info(const ByteArray* key, char** alg, char** param)
{
    int ret = RET_OK;
    PrivateKeyInfo_t* privkey = NULL;
    char* algo = NULL;
    char* params = NULL;

    CHECK_PARAM(key != NULL);
    CHECK_PARAM(alg != NULL || param != NULL);

    CHECK_NOT_NULL(privkey = asn_decode_ba_with_alloc(get_PrivateKeyInfo_desc(), key));
    DO(asn_oid_to_text(&privkey->privateKeyAlgorithm.algorithm, &algo));

    if (oid_is_parent(OID_DSTU4145_WITH_GOST3411, algo) ||
        oid_is_parent(OID_DSTU4145_WITH_DSTU7564, algo)) {
        DO(private_key_get_param_dstu(privkey->privateKeyAlgorithm.parameters, &params));
    }
    else if (oid_is_equal(OID_EC_KEY, algo) ||
        oid_is_equal(OID_ECKCDSA, algo) ||
        oid_is_parent(OID_ECGDSA_STD, algo) ||
        oid_is_equal(OID_GOST_KEY_3410_2012_256, algo) ||
        oid_is_equal(OID_GOST_KEY_3410_2012_512, algo) ||
        oid_is_equal(OID_SM2, algo)) {
        DO(private_key_get_param_ec(privkey->privateKeyAlgorithm.parameters, &params));
    }
    else if (oid_is_equal(OID_RSA, algo)) {
        DO(private_key_get_param_rsa(&privkey->privateKey, &params));
    }
    else {
        SET_ERROR(RET_CM_UNSUPPORTED_ALG);
    }

    if (alg) {
        *alg = algo;
        algo = NULL;
    }

    if (param) {
        *param = params;
        params = NULL;
    }

cleanup:
    free(algo);
    free(params);
    asn_free(get_PrivateKeyInfo_desc(), privkey);
    return ret;
}

static int spki_create(const AlgorithmIdentifier_t* aid, const BIT_STRING_t* pubkey, ByteArray **out)
{
    int ret = RET_OK;
    SubjectPublicKeyInfo_t* spki = NULL;

    ASN_ALLOC(spki);
    DO(asn_copy(get_AlgorithmIdentifier_desc(), aid, &spki->algorithm));
    DO(asn_copy(get_BIT_STRING_desc(), pubkey, &spki->subjectPublicKey));
    DO(asn_encode_ba(get_SubjectPublicKeyInfo_desc(), spki, out));

cleanup:
    asn_free(get_SubjectPublicKeyInfo_desc(), spki);
    return ret;
}

static int private_key_get_spki_ec(PrivateKeyInfo_t* privkey, const char* algo, ByteArray** spki)
{
    int ret = RET_OK;
    EcCtx* ec_ctx = NULL;
    ByteArray* qx = NULL;
    ByteArray* qy = NULL;
    ByteArray* d = NULL;
    ByteArray* pubkey = NULL;
    ByteArray* encoded_pubkey = NULL;
    BIT_STRING_t* pubkey_bs = NULL;
    OCTET_STRING_t* pubkey_os = NULL;
    ECPrivateKey_t* ec_key = NULL;
    ByteArray* ec_key_encoded = NULL;
    char* curve_oid = NULL;

    if (oid_is_parent(OID_DSTU4145_WITH_GOST3411, algo) ||
        oid_is_parent(OID_DSTU4145_WITH_DSTU7564, algo)) {
        DO(dstu4145_params_get_ec(&privkey->privateKeyAlgorithm, &ec_ctx));
        DO(asn_OCTSTRING2ba(&privkey->privateKey, &d));
        DO(dstu4145_get_pubkey(ec_ctx, d, &qx, &qy));
        DO(dstu4145_compress_pubkey(ec_ctx, qx, qy, &pubkey));
        ASN_ALLOC(pubkey_os);
        DO(asn_ba2OCTSTRING(pubkey, pubkey_os));
        DO(asn_encode_ba(get_OCTET_STRING_desc(), pubkey_os, &encoded_pubkey));
        DO(asn_create_bitstring_from_ba(encoded_pubkey, &pubkey_bs));
    }
    else {
        EcParamsId ec_id;
        DO(private_key_get_param_ec(privkey->privateKeyAlgorithm.parameters, &curve_oid));
        if (curve_oid == NULL) {
            SET_ERROR(RET_CM_UNSUPPORTED_ELLIPTIC_CURVE);
        }

        DO(asn_OCTSTRING2ba(&privkey->privateKey, &ec_key_encoded));
        CHECK_NOT_NULL(ec_key = asn_decode_ba_with_alloc(get_ECPrivateKey_desc(), ec_key_encoded));
        DO(asn_OCTSTRING2ba(&ec_key->privateKey, &d));

        if ((ec_id = ecid_from_oid(curve_oid)) == EC_PARAMS_ID_UNDEFINED) {
            SET_ERROR(RET_CM_UNSUPPORTED_ELLIPTIC_CURVE);
        }
        CHECK_NOT_NULL(ec_ctx = ec_alloc_default(ec_id));
        if (oid_is_equal(OID_EC_KEY, algo) || 
            oid_is_equal(OID_GOST_KEY_3410_2012_256, algo) ||
            oid_is_equal(OID_GOST_KEY_3410_2012_512, algo) ||
            oid_is_equal(OID_SM2, algo)) {
            DO(ecdsa_get_pubkey(ec_ctx, d, &qx, &qy));
        }
        else if (oid_is_equal(OID_ECGDSA_KEY, algo)) { //ec-gdsa and ec-kcdsa 
            DO(eckcdsa_get_pubkey(ec_ctx, d, &qx, &qy));
        }
        else { 
            SET_ERROR(RET_CM_UNSUPPORTED_ALG); 
        }
        
        CHECK_NOT_NULL(encoded_pubkey = ba_alloc_by_len(1));
        DO(ba_set(encoded_pubkey, 0x04));
        DO(ba_append(qx, 0, 0, encoded_pubkey));
        DO(ba_append(qy, 0, 0, encoded_pubkey));
        DO(asn_create_bitstring_from_ba(encoded_pubkey, &pubkey_bs));
    }

    DO(spki_create(&privkey->privateKeyAlgorithm, pubkey_bs, spki));

cleanup:
    free(curve_oid);
    ba_free(qx);
    ba_free(qy);
    ba_free(pubkey);
    ba_free(encoded_pubkey);
    ba_free_private(ec_key_encoded);
    ba_free_private(d);
    asn_free(get_ECPrivateKey_desc(), ec_key);
    asn_free(get_OCTET_STRING_desc(), pubkey_os);
    asn_free(get_BIT_STRING_desc(), pubkey_bs);
    ec_free(ec_ctx);
    if (ret == RET_UNSUPPORTED) ret = RET_CM_UNSUPPORTED_ELLIPTIC_CURVE;
    if (ret == RET_INVALID_EC_PARAMS) ret = RET_CM_INVALID_ELLIPTIC_CURVE;
    return ret;
}

static int private_key_get_spki_rsa(PrivateKeyInfo_t* rsaprivkey, ByteArray** spki)
{
    int ret = RET_OK;
    ByteArray* encoded_privkey = NULL;
    RSAPrivateKey_t* privkey = NULL;
    RSAPublicKey_t* pubkey = NULL;
    ByteArray* encoded_pubkey = NULL;
    BIT_STRING_t* pubkey_bs = NULL;

    DO(asn_OCTSTRING2ba(&rsaprivkey->privateKey, &encoded_privkey));
    CHECK_NOT_NULL(privkey = asn_decode_ba_with_alloc(get_RSAPrivateKey_desc(), encoded_privkey));
    ASN_ALLOC(pubkey);
    DO(asn_copy(get_INTEGER_desc(), &privkey->publicExponent, &pubkey->publicExponent));
    DO(asn_copy(get_INTEGER_desc(), &privkey->modulus, &pubkey->modulus));
    DO(asn_encode_ba(get_RSAPublicKey_desc(), pubkey, &encoded_pubkey));
    DO(asn_create_bitstring_from_ba(encoded_pubkey, &pubkey_bs));
    DO(spki_create(&rsaprivkey->privateKeyAlgorithm, pubkey_bs, spki));

cleanup:
    ba_free(encoded_pubkey);
    ba_free_private(encoded_privkey);
    asn_free(get_RSAPrivateKey_desc(), privkey);
    asn_free(get_RSAPublicKey_desc(), pubkey);
    asn_free(get_BIT_STRING_desc(), pubkey_bs);
    return ret;
}

int private_key_get_spki(const ByteArray* key, ByteArray** spki)
{
    int ret = RET_OK;
    PrivateKeyInfo_t* privkey = NULL;
    char* algo = NULL;

    CHECK_PARAM(key != NULL);
    CHECK_PARAM(spki != NULL);

    CHECK_NOT_NULL(privkey = asn_decode_ba_with_alloc(get_PrivateKeyInfo_desc(), key));
    DO(asn_oid_to_text(&privkey->privateKeyAlgorithm.algorithm, &algo));

    if (oid_is_parent(OID_DSTU4145_WITH_GOST3411, algo) ||
        oid_is_parent(OID_DSTU4145_WITH_DSTU7564, algo) ||
        oid_is_equal(OID_EC_KEY, algo) ||
        oid_is_equal(OID_ECKCDSA, algo) ||
        oid_is_parent(OID_ECGDSA_STD, algo) ||
        oid_is_equal(OID_GOST_KEY_3410_2012_256, algo) ||
        oid_is_equal(OID_GOST_KEY_3410_2012_512, algo) ||
        oid_is_equal(OID_SM2, algo)) {
        DO(private_key_get_spki_ec(privkey, algo, spki));
    }
    else if (oid_is_equal(OID_RSA, algo)) {
        DO(private_key_get_spki_rsa(privkey, spki));
    }
    else {
        SET_ERROR(RET_CM_UNSUPPORTED_ALG);
    }

cleanup:
    free(algo);
    asn_free(get_PrivateKeyInfo_desc(), privkey);
    return ret;
}

int spki_get_key_id(const ByteArray* pub_key_info, ByteArray** key_id)
{
    int ret = RET_OK;
    SubjectPublicKeyInfo_t* spki = NULL;
    HashCtx* hash_ctx = NULL;
    ByteArray* pubkey = NULL;
    char* alg_oid = NULL;
    HashAlg hash_alg = HASH_ALG_SHA1;

    CHECK_PARAM(pub_key_info != NULL);
    CHECK_PARAM(key_id != NULL);

    CHECK_NOT_NULL(spki = asn_decode_ba_with_alloc(get_SubjectPublicKeyInfo_desc(), pub_key_info));

    DO(asn_BITSTRING2ba(&spki->subjectPublicKey, &pubkey));
    DO(asn_oid_to_text(&spki->algorithm.algorithm, &alg_oid));

    if (oid_is_parent(OID_DSTU4145_WITH_DSTU7564, alg_oid)
    ||  oid_is_parent(OID_DSTU4145_WITH_GOST3411, alg_oid)) {
        hash_alg = HASH_ALG_GOST34311;
    }

    CHECK_NOT_NULL(hash_ctx = hash_alloc(hash_alg));
    DO(hash_update(hash_ctx, pubkey));
    DO(hash_final(hash_ctx, key_id));

cleanup:
    asn_free(get_SubjectPublicKeyInfo_desc(), spki);
    hash_free(hash_ctx);
    ba_free(pubkey);
    free(alg_oid);
    return ret;
}

int spki_get_algo_param(const ByteArray* baSpki, char** algo, char** algoParam)
{
    int ret = RET_OK;
    SubjectPublicKeyInfo_t* spki = NULL;
    char* s_algo = NULL;
    char* s_param = NULL;

    CHECK_PARAM(baSpki != NULL);
    CHECK_PARAM((algo != NULL) && (algoParam != NULL));

    CHECK_NOT_NULL(spki = asn_decode_ba_with_alloc(get_SubjectPublicKeyInfo_desc(), baSpki));
    DO(asn_oid_to_text(&spki->algorithm.algorithm, &s_algo));

    if (oid_is_parent(OID_DSTU4145_WITH_GOST3411, s_algo) ||
        oid_is_parent(OID_DSTU4145_WITH_DSTU7564, s_algo)) {
        DO(private_key_get_param_dstu(spki->algorithm.parameters, &s_param));
    }
    else if (oid_is_equal(OID_EC_KEY, s_algo) ||
        oid_is_equal(OID_ECKCDSA, s_algo) ||
        oid_is_parent(OID_ECGDSA_STD, s_algo) ||
        oid_is_equal(OID_GOST_KEY_3410_2012_256, s_algo) ||
        oid_is_equal(OID_GOST_KEY_3410_2012_512, s_algo) ||
        oid_is_equal(OID_SM2, s_algo)) {
        DO(private_key_get_param_ec(spki->algorithm.parameters, &s_param));
    }
    else if (oid_is_equal(OID_RSA, s_algo)) {
        DO(spki_get_param_rsa(spki->algorithm.parameters, &s_param));
    }
    else {
        SET_ERROR(RET_CM_UNSUPPORTED_ALG);
    }

    if (s_algo) {
        *algo = s_algo;
        s_algo = NULL;
    }

    if (s_param) {
        *algoParam = s_param;
        s_param = NULL;
    }

cleanup:
    asn_free(get_SubjectPublicKeyInfo_desc(), spki);
    free(s_algo);
    free(s_param);
    return ret;
}

int spki_get_pubkey(const ByteArray* baSpki, ByteArray** baPubkey)
{
    int ret = RET_OK;
    SubjectPublicKeyInfo_t* spki = NULL;
    OCTET_STRING_t* os_pubkey = NULL;//a remove it - need use decode_bitstring_encap_octet()
    char* s_algo = NULL;
    ByteArray* ba_pubkey = NULL;

    CHECK_PARAM(baSpki != NULL);
    CHECK_PARAM(baPubkey != NULL);

    CHECK_NOT_NULL(spki = asn_decode_ba_with_alloc(get_SubjectPublicKeyInfo_desc(), baSpki));
    DO(asn_BITSTRING2ba(&spki->subjectPublicKey, &ba_pubkey));

    DO(asn_oid_to_text(&spki->algorithm.algorithm, &s_algo));
    if (oid_is_parent(OID_DSTU4145_WITH_GOST3411, s_algo) || oid_is_parent(OID_DSTU4145_WITH_DSTU7564, s_algo)) {
        CHECK_NOT_NULL(os_pubkey = asn_decode_ba_with_alloc(get_OCTET_STRING_desc(), ba_pubkey));
        DO(asn_OCTSTRING2ba(os_pubkey, baPubkey));
    }
    else {
        *baPubkey = ba_pubkey;
        ba_pubkey = NULL;
    }

cleanup:
    asn_free(get_SubjectPublicKeyInfo_desc(), spki);
    asn_free(get_OCTET_STRING_desc(), os_pubkey);
    free(s_algo);
    ba_free(ba_pubkey);
    return ret;
}

int spki_get_dstu_dke(const ByteArray* baSpki, ByteArray** baDKE)
{
    int ret = RET_OK;
    SubjectPublicKeyInfo_t* spki = NULL;
    DSTU4145Params_t* dstu_params = NULL;
    ByteArray* ba_dke = NULL;
    char* s_algo = NULL;

    CHECK_PARAM(baSpki != NULL);
    CHECK_PARAM(baDKE != NULL);

    CHECK_NOT_NULL(spki = asn_decode_ba_with_alloc(get_SubjectPublicKeyInfo_desc(), baSpki));
    DO(asn_oid_to_text(&spki->algorithm.algorithm, &s_algo));
    if (oid_is_parent(OID_DSTU4145_WITH_GOST3411, s_algo)) {
        CHECK_NOT_NULL(dstu_params = asn_any2type(spki->algorithm.parameters, get_DSTU4145Params_desc()));
        if (dstu_params->dke) {
            DO(asn_OCTSTRING2ba(dstu_params->dke, &ba_dke));
        }
        else {
            ba_dke = ba_alloc_from_hex(HEX_DKE_BY_DEFAULT);
        }

        *baDKE = ba_dke;
        ba_dke = NULL;
    }

cleanup:
    asn_free(get_SubjectPublicKeyInfo_desc(), spki);
    asn_free(get_DSTU4145Params_desc(), dstu_params);
    ba_free(ba_dke);
    free(s_algo);
    return ret;
}

static int pack_ec_signature(const ByteArray* r, const ByteArray* s, ByteArray** signature)
{
    int ret = RET_OK;
    ECDSA_Sig_Value_t *ec_sig = NULL;

    ASN_ALLOC(ec_sig);
    DO(asn_ba2INTEGER(r, &ec_sig->r));
    DO(asn_ba2INTEGER(s, &ec_sig->s));

    DO(asn_encode_ba(get_ECDSA_Sig_Value_desc(), ec_sig, signature));

cleanup:
    
    ASN_FREE(get_ECDSA_Sig_Value_desc(), ec_sig);
    return ret;
}

static int private_key_sign_ec(const PrivateKeyInfo_t* privkey, SignAlg sign_alg, HashAlg hash_alg,
        const ByteArray** hashes, size_t hashes_count, ByteArray** signatures)
{
    int ret = RET_OK;
    EcCtx* ec_ctx = NULL;
    ByteArray* r = NULL;
    ByteArray* s = NULL;
    ByteArray* d = NULL;
    ECPrivateKey_t* ec_key = NULL;
    ByteArray* ec_key_encoded = NULL;
    char* curve_oid = NULL;
    size_t i;

    if (SIGN_DSTU4145 == sign_alg) {
        DO(dstu4145_params_get_ec(&privkey->privateKeyAlgorithm, &ec_ctx));
        DO(asn_OCTSTRING2ba(&privkey->privateKey, &d));
        DO(ba_swap(d));
        DO(ec_init_sign(ec_ctx, d));
        for (i = 0; i < hashes_count; i++) {
            DO(dstu4145_sign(ec_ctx, hashes[i], &r, &s));
            CHECK_NOT_NULL(signatures[i] = ba_join(r, s));
            ba_free(r);
            r = NULL;
            ba_free(s);
            s = NULL;
        }
    }
    else {
        EcParamsId ec_id;
        DO(private_key_get_param_ec(privkey->privateKeyAlgorithm.parameters, &curve_oid));
        if (curve_oid == NULL) {
            SET_ERROR(RET_CM_UNSUPPORTED_ELLIPTIC_CURVE);
        }

        DO(asn_OCTSTRING2ba(&privkey->privateKey, &ec_key_encoded));
        CHECK_NOT_NULL(ec_key = asn_decode_ba_with_alloc(get_ECPrivateKey_desc(), ec_key_encoded));
        DO(asn_OCTSTRING2ba(&ec_key->privateKey, &d));

        if ((ec_id = ecid_from_oid(curve_oid)) == EC_PARAMS_ID_UNDEFINED) {
            SET_ERROR(RET_CM_UNSUPPORTED_ELLIPTIC_CURVE);
        }
        CHECK_NOT_NULL(ec_ctx = ec_alloc_default(ec_id));
        DO(ec_init_sign(ec_ctx, d));

        for (i = 0; i < hashes_count; i++) {
            switch(sign_alg) {
            case SIGN_ECDSA:
                DO(ecdsa_sign(ec_ctx, hashes[i], &r, &s));
                DO(pack_ec_signature(r, s, &signatures[i]));
                break;
            case SIGN_ECKCDSA:
                DO(eckcdsa_sign(ec_ctx, hashes[i], hash_alg, &r, &s));
                CHECK_NOT_NULL(signatures[i] = ba_join(r, s));
                break;
            case SIGN_ECGDSA:
                DO(ecgdsa_sign(ec_ctx, hashes[i], &r, &s));
                CHECK_NOT_NULL(signatures[i] = ba_join(r, s));
                break;
            case SIGN_ECRDSA:
                DO(ecrdsa_sign(ec_ctx, hashes[i], &r, &s));
                CHECK_NOT_NULL(signatures[i] = ba_join(r, s));
                break;
            case SIGN_SM2DSA:
                DO(sm2dsa_sign(ec_ctx, hashes[i], &r, &s));
                DO(pack_ec_signature(r, s, &signatures[i]));
                break;
            default:
                SET_ERROR(RET_CM_UNSUPPORTED_ALG);
            }

            ba_free(r);
            r = NULL;
            ba_free(s);
            s = NULL;
        }
    }

cleanup:
    free(curve_oid);
    ba_free(r);
    ba_free(s);
    ba_free_private(ec_key_encoded);
    ba_free_private(d);
    asn_free(get_ECPrivateKey_desc(), ec_key);
    ec_free(ec_ctx);
    if (ret != RET_OK) {
        for (i = 0; i < hashes_count; i++) {
            ba_free(signatures[i]);
            signatures[i] = NULL;
        }

        if (ret == RET_UNSUPPORTED) ret = RET_CM_UNSUPPORTED_ELLIPTIC_CURVE;
        if (ret == RET_INVALID_EC_PARAMS) ret = RET_CM_INVALID_ELLIPTIC_CURVE;
    }
    return ret;
}

static int private_key_sign_rsa(const PrivateKeyInfo_t* rsaprivkey, SignAlg sign_alg, HashAlg hash_alg,
        const ByteArray** hashes, size_t hashes_count, ByteArray** signatures)
{
    int ret = RET_OK;
    ByteArray* encoded_privkey = NULL;
    RSAPrivateKey_t* privkey = NULL;
    ByteArray* ba_d = NULL;
    ByteArray* ba_n = NULL;
    RsaCtx *rsa_ctx = NULL;
    size_t i;

    DO(asn_OCTSTRING2ba(&rsaprivkey->privateKey, &encoded_privkey));
    CHECK_NOT_NULL(privkey = asn_decode_ba_with_alloc(get_RSAPrivateKey_desc(), encoded_privkey));
    DO(asn_INTEGER2ba(&privkey->privateExponent, &ba_d));
    DO(asn_INTEGER2ba(&privkey->modulus, &ba_n));
    CHECK_NOT_NULL(rsa_ctx = rsa_alloc());
    
    if (SIGN_RSA_PSS == sign_alg) {
        DO(rsa_init_sign_pss(rsa_ctx, hash_alg, ba_n, ba_d));
    } 
    else {
        DO(rsa_init_sign_pkcs1_v1_5(rsa_ctx, hash_alg, ba_n, ba_d));
    }

    for (i = 0; i < hashes_count; i++) {
        DEBUG_OUTCON(ba_print(stdout, ba_n));
        DO(rsa_sign(rsa_ctx, hashes[i], &signatures[i]));
        DEBUG_OUTCON(ba_print(stdout, signatures[i]);printf("\n");)
    }

cleanup:
    ba_free(ba_n);
    ba_free_private(ba_d);
    ba_free_private(encoded_privkey);
    rsa_free(rsa_ctx);
    asn_free(get_RSAPrivateKey_desc(), privkey);
    if (ret != RET_OK) {
        for (i = 0; i < hashes_count; i++) {
            ba_free(signatures[i]);
            signatures[i] = NULL;
        }
    }
    return ret;
}

static bool private_key_check_algo(const char* key_algo, SignAlg sign_alg)
{
    switch (sign_alg) {
    case SIGN_DSTU4145:
        return oid_is_parent(OID_DSTU4145_WITH_GOST3411, key_algo) ||
            oid_is_parent(OID_DSTU4145_WITH_DSTU7564, key_algo);
    case SIGN_SM2DSA:
    case SIGN_ECDSA:
        return oid_is_equal(OID_EC_KEY, key_algo);
    case SIGN_ECKCDSA:
    case SIGN_ECGDSA:
        return oid_is_parent(OID_ECGDSA_KEY, key_algo);
    case SIGN_ECRDSA:
        return oid_is_equal(OID_GOST_KEY_3410_2012_256, key_algo) ||
            oid_is_equal(OID_GOST_KEY_3410_2012_512, key_algo);
    case SIGN_RSA_PKCS_1_5:
    case SIGN_RSA_PSS:
        return oid_is_equal(OID_RSA, key_algo);
    default:
        return false;
    }
}

static int hash_from_rsa_pss (const ByteArray* encodedHash, HashAlg* hashAlgo)
{
    //  rfc8017, A.2.3. RSASSA-PSS
    int ret = RET_OK;
    OBJECT_IDENTIFIER_t* oid = NULL;
    char* s_oid = NULL;

    if (encodedHash) {
        CHECK_NOT_NULL(oid = asn_decode_ba_with_alloc(get_OBJECT_IDENTIFIER_desc(), encodedHash));
        DO(asn_oid_to_text(oid, &s_oid));
        *hashAlgo = hash_from_oid(s_oid);
    }
    else {
        //  rfc8017, A.2.3. RSASSA-PSS: DEFAULT sha1
        *hashAlgo = HASH_ALG_SHA1;
    }

cleanup:
    asn_free(get_OBJECT_IDENTIFIER_desc(), oid);
    free(s_oid);
    return ret;
}

int private_key_sign_check(const ByteArray* key, const char* signAlgo, const ByteArray* signAlgoParams, HashAlg* hashAlgo)
{
    int ret = RET_OK;
    SignAlg sign_alg = SIGN_UNDEFINED;
    PrivateKeyInfo_t* privkey = NULL;
    char* key_algo = NULL;

    CHECK_PARAM(key != NULL);
    CHECK_PARAM(signAlgo != NULL);
    CHECK_PARAM(hashAlgo != NULL);

    if ((sign_alg = signature_from_oid(signAlgo)) == SIGN_UNDEFINED) {
        SET_ERROR(RET_CM_UNSUPPORTED_ALG);
    }

    if (SIGN_RSA_PSS != sign_alg) {
        if ((*hashAlgo = hash_from_oid(signAlgo)) == HASH_ALG_UNDEFINED) {
            SET_ERROR(RET_CM_UNSUPPORTED_ALG);
        }
    }
    else {
        DO(hash_from_rsa_pss(signAlgoParams, hashAlgo));
        if (*hashAlgo == HASH_ALG_UNDEFINED) {
            SET_ERROR(RET_CM_UNSUPPORTED_ALG);
        }
    }

    CHECK_NOT_NULL(privkey = asn_decode_ba_with_alloc(get_PrivateKeyInfo_desc(), key));
    DO(asn_oid_to_text(&privkey->privateKeyAlgorithm.algorithm, &key_algo));

    if (!private_key_check_algo(key_algo, sign_alg)) {
        SET_ERROR(RET_CM_INVALID_KEY);
    }

cleanup:
    asn_free(get_PrivateKeyInfo_desc(), privkey);
    free(key_algo);
    return ret;
}

int private_key_sign_single(const ByteArray* key, const char* signAlgo, const ByteArray* signAlgoParams,
        const ByteArray* hash, ByteArray** signature)
{
    int ret = RET_OK;
    ByteArray** signatures = NULL;

    CHECK_PARAM(key != NULL);
    CHECK_PARAM(signAlgo != NULL);
    CHECK_PARAM(ba_get_len(hash) > 0);
    CHECK_PARAM(signature != NULL);

    DO(private_key_sign(key, &hash, 1, signAlgo, signAlgoParams, &signatures));
    *signature = signatures[0];

cleanup:
    free(signatures);   //  Note: private_key_sign() return array[1] of signature
    return ret;
}

int private_key_sign(const ByteArray* key, const ByteArray** hashes, size_t hashes_count,
        const char* signAlgo, const ByteArray* signAlgoParams, ByteArray*** signatures)
{
    int ret = RET_OK;
    HashAlg hash_alg = HASH_ALG_UNDEFINED;
    SignAlg sign_alg = SIGN_UNDEFINED;
    size_t i, hash_size;
    PrivateKeyInfo_t* privkey = NULL;
    char* key_algo = NULL;

    CHECK_PARAM(key != NULL);
    CHECK_PARAM(hashes != NULL);
    CHECK_PARAM(hashes_count > 0);
    CHECK_PARAM(signAlgo != NULL);
    CHECK_PARAM(signatures != NULL);

    if ((sign_alg = signature_from_oid(signAlgo)) == SIGN_UNDEFINED) {
        SET_ERROR(RET_CM_UNSUPPORTED_ALG);
    }

    if (SIGN_RSA_PSS != sign_alg) {
        if ((hash_alg = hash_from_oid(signAlgo)) == HASH_ALG_UNDEFINED) {
            SET_ERROR(RET_CM_UNSUPPORTED_ALG);
        }
    }
    else {
        DO(hash_from_rsa_pss(signAlgoParams, &hash_alg));
        if (hash_alg == HASH_ALG_UNDEFINED) {
            SET_ERROR(RET_CM_UNSUPPORTED_ALG);
        }
    }

    hash_size = hash_get_size(hash_alg);

    for (i = 0; i < hashes_count; i++) {
        if (ba_get_len(hashes[i]) != hash_size) {
            SET_ERROR(RET_CM_INVALID_HASH);
        }
    }

    CHECK_NOT_NULL(privkey = asn_decode_ba_with_alloc(get_PrivateKeyInfo_desc(), key));
    DO(asn_oid_to_text(&privkey->privateKeyAlgorithm.algorithm, &key_algo));

    if (!private_key_check_algo(key_algo, sign_alg)) {
        SET_ERROR(RET_CM_INVALID_KEY);
    }

    CALLOC_CHECKED((*signatures), sizeof(ByteArray*) * hashes_count);

    if (oid_is_parent(OID_DSTU4145_WITH_GOST3411, key_algo) ||
        oid_is_parent(OID_DSTU4145_WITH_DSTU7564, key_algo) ||
        oid_is_equal(OID_EC_KEY, key_algo) ||
        oid_is_equal(OID_ECKCDSA, key_algo) ||
        oid_is_parent(OID_ECGDSA_STD, key_algo) ||
        oid_is_equal(OID_GOST_KEY_3410_2012_256, key_algo) ||
        oid_is_equal(OID_GOST_KEY_3410_2012_512, key_algo) ||
        oid_is_equal(OID_SM2, key_algo)) {
        ret = private_key_sign_ec(privkey, sign_alg, hash_alg, hashes, hashes_count, *signatures);
    }
    else if (oid_is_equal(OID_RSA, key_algo)) {
        ret = private_key_sign_rsa(privkey, sign_alg, hash_alg, hashes, hashes_count, *signatures);
    }
    else {
        SET_ERROR(RET_CM_UNSUPPORTED_ALG);
    }

cleanup:
    if (ret != RET_OK) {
        free(*signatures);
        *signatures = NULL;
    }
    free(key_algo);
    asn_free(get_PrivateKeyInfo_desc(), privkey);
    return ret;
}

int private_key_ecdh(const bool withCofactor, const ByteArray* baSenderKey,
        const ByteArray* baRecipientSpki, ByteArray** baCommonSecret)
{
    int ret = RET_OK;
    PrivateKeyInfo_t* privkey = NULL;
    ECPrivateKey_t* ec_privkey = NULL;
    EcCtx* ec_ctx = NULL;
    char* s_algo1 = NULL;
    char* s_param1 = NULL;
    char* s_algo2 = NULL;
    char* s_param2 = NULL;
    EcParamsId ec_paramid;
    bool is_dstu = false;
    ByteArray* d = NULL;
    ByteArray* pubkey = NULL;
    ByteArray* qx = NULL;
    ByteArray* qy = NULL;
    ByteArray* zx = NULL;
    ByteArray* zy = NULL;

    CHECK_PARAM(baSenderKey != NULL);
    CHECK_PARAM(baRecipientSpki != NULL);
    CHECK_PARAM(baCommonSecret != NULL);

    DEBUG_OUTCON( printf("private_key_ecdh()\n\t baRecipientSpki: "); ba_print(stdout, baRecipientSpki); )

    DO(private_key_get_info(baSenderKey, &s_algo1, &s_param1));
    DEBUG_OUTCON( printf("\t algo1: '%s',  param1: '%s'\n", s_algo1, s_param1); );

    DO(spki_get_algo_param(baRecipientSpki, &s_algo2, &s_param2));
    DEBUG_OUTCON( printf("\t algo2: '%s',  param2: '%s'\n", s_algo2, s_param2); );

    if ((strcmp(s_algo1, s_algo2) != 0) || (strcmp(s_param1, s_param2) != 0) || oid_is_equal(OID_RSA, s_algo1)) {
        SET_ERROR(RET_CM_INVALID_PARAM_DH);
    }

    ec_paramid = ecid_from_oid(s_param2);
    if (ec_paramid == EC_PARAMS_ID_UNDEFINED) {
        SET_ERROR(RET_CM_UNSUPPORTED_ELLIPTIC_CURVE);
    }
    is_dstu = (ec_paramid <= EC_PARAMS_ID_DSTU4145_M431_ONB);

    CHECK_NOT_NULL(privkey = asn_decode_ba_with_alloc(get_PrivateKeyInfo_desc(), baSenderKey));
    DO(asn_OCTSTRING2ba(&privkey->privateKey, &d));
    if (is_dstu) {
        DO(ba_swap(d));
    }
    else {
        CHECK_NOT_NULL(ec_privkey = asn_decode_ba_with_alloc(get_ECPrivateKey_desc(), d));
        ba_free(d);
        d = NULL;
        DO(asn_OCTSTRING2ba(&ec_privkey->privateKey, &d));
    }
    DEBUG_OUTCON( printf("\t d: ");ba_print(stdout, d) );

    DO(spki_get_pubkey(baRecipientSpki, &pubkey));
    DEBUG_OUTCON( printf("\t pubkey: ");ba_print(stdout, pubkey) );

    ec_ctx = ec_alloc_default(ec_paramid);
    if (is_dstu) {
        //  Note: DSTU-key specific impl
        DO(dstu4145_decompress_pubkey(ec_ctx, pubkey, &qx, &qy));
        DEBUG_OUTCON( printf("\t qx(before swap): ");ba_print(stdout, qx);printf("\t qy(before swap): ");ba_print(stdout, qy); )
        DO(ba_swap(qx));
        DO(ba_swap(qy));
    }
    else {
        //  ���������, ������ ���� ������ �������
        //  0x04 - �������� �����,
        //  0�03 - ������ �����, ��������� ��� 1,
        //  0�02 - ������ �����, ��������� ��� 0
        size_t len = 0;
        if (ba_get_buf(pubkey)[0] == 0x04) {
            len = (ba_get_len(pubkey) - 1) / 2;
            CHECK_NOT_NULL(qx = ba_copy_with_alloc(pubkey, 1, len));
            CHECK_NOT_NULL(qy = ba_copy_with_alloc(pubkey, len + 1, 0));
        } else if (ba_get_buf(pubkey)[0] == 0x02) {
            //��������� � �� ������.
            CHECK_NOT_NULL(qx = ba_copy_with_alloc(pubkey, 1, len));
            DO(ec_point_decompress(ec_ctx, qx, 0, &qy));

        } else if (ba_get_buf(pubkey)[0] == 0x03) {
            CHECK_NOT_NULL(qx = ba_copy_with_alloc(pubkey, 1, len));
            DO(ec_point_decompress(ec_ctx, qx, 1, &qy));

        } else {
            SET_ERROR(RET_CM_UNSUPPORTED_FORMAT);
        }
    }
    DEBUG_OUTCON( printf("\t qx: ");ba_print(stdout, qx);printf("\t qy: ");ba_print(stdout, qy); )

    DO(ec_dh(ec_ctx, withCofactor, d, qx, qy, &zx, &zy));
    DEBUG_OUTCON( printf("\t zx: ");ba_print(stdout, zx); printf("\t zy: ");ba_print(stdout, zy); )

    *baCommonSecret = zx;
    zx = NULL;

cleanup:
    asn_free(get_PrivateKeyInfo_desc(), privkey);
    asn_free(get_ECPrivateKey_desc(), ec_privkey);
    ec_free(ec_ctx);
    free(s_algo1);
    free(s_param1);
    free(s_algo2);
    free(s_param2);
    ba_free(d);
    ba_free(pubkey);
    ba_free(qx);
    ba_free(qy);
    ba_free(zx);
    ba_free(zy);
    return ret;
}

int keyid_by_cert (const ByteArray * baCert, ByteArray ** baKeyId)
{
    int ret = RET_OK;
    Certificate_t *cert = NULL;
    ByteArray* ba_spki = NULL;

    CHECK_NOT_NULL(cert = asn_decode_ba_with_alloc(get_Certificate_desc(), baCert));
    DO(asn_encode_ba(get_SubjectPublicKeyInfo_desc(), &cert->tbsCertificate.subjectPublicKeyInfo, &ba_spki));
    DO(spki_get_key_id(ba_spki, baKeyId));

cleanup:
    ba_free(ba_spki);
    asn_free(get_Certificate_desc(), cert);
    return ret;
}

int keyid_by_privkeyinfo (const ByteArray * baPrivateKeyInfo, ByteArray ** baKeyId)
{
    int ret = RET_OK;
    ByteArray *ba_spki = NULL;

    DO(private_key_get_spki(baPrivateKeyInfo, &ba_spki));
    DO(spki_get_key_id(ba_spki, baKeyId));

cleanup:
    ba_free(ba_spki);
    return ret;
}

int spki_by_privkeyinfo (const ByteArray * baPrivateKeyInfo, ByteArray ** baAlgoId, ByteArray ** baPubkey)
{
    int ret = RET_OK;
    ByteArray *ba_spki = NULL;
    ByteArray *ba_tmp = NULL;
    SubjectPublicKeyInfo_t* spki = NULL;
    OCTET_STRING_t* os_pubkey = NULL;
    char *algo = NULL;

    DO(private_key_get_spki(baPrivateKeyInfo, &ba_spki));
    CHECK_NOT_NULL(spki = asn_decode_ba_with_alloc(get_SubjectPublicKeyInfo_desc(), ba_spki));

    if (baAlgoId != NULL) {
        DO(asn_encode_ba(get_AlgorithmIdentifier_desc(), &spki->algorithm, baAlgoId));
    }

    if (baPubkey != NULL) {
        DO(asn_oid_to_text(&spki->algorithm.algorithm, &algo));
        if (oid_is_parent(OID_DSTU4145_WITH_GOST3411, algo) || oid_is_parent(OID_DSTU4145_WITH_DSTU7564, algo)) {
            DO(asn_BITSTRING2ba(&spki->subjectPublicKey, &ba_tmp));
            CHECK_NOT_NULL(os_pubkey = asn_decode_ba_with_alloc(get_OCTET_STRING_desc(), ba_tmp));
            DO(asn_OCTSTRING2ba(os_pubkey, baPubkey));
        }
        else {
            DO(asn_BITSTRING2ba(&spki->subjectPublicKey, baPubkey));
        }
    }

cleanup:
    ba_free(ba_spki);
    ba_free(ba_tmp);
    asn_free(get_SubjectPublicKeyInfo_desc(), spki);
    asn_free(get_OCTET_STRING_desc(), os_pubkey);
    free(algo);
    return ret;
}

