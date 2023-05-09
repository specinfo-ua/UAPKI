/*
 * Copyright (c) 2023, The UAPKI Project Authors.
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

#include "uapki-ns-verify.h"
#include "dstu4145-params.h"
#include "macros-internal.h"
#include "oid-utils.h"
#include "uapkif.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"


namespace UapkiNS {


static int parse_dstu_signvalue (const ByteArray* baSignature, ByteArray** baR, ByteArray** baS)
{
    int ret = RET_OK;
    SmartBA sba_r, sba_s;
    size_t len = ba_get_len(baSignature) / 2;

    CHECK_PARAM(len > 0);
    CHECK_PARAM(baR != NULL);
    CHECK_PARAM(baS != NULL);

    if (
        !sba_r.set(ba_copy_with_alloc(baSignature, 0, len)) ||
        !sba_s.set(ba_copy_with_alloc(baSignature, len, len))
    ) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    *baR = sba_r.pop();
    *baS = sba_s.pop();

cleanup:
    return ret;
}

static int parse_ecdsa_pubkey (const ByteArray* baPubkey, ByteArray** baQx, ByteArray** baQy)
{
    int ret = RET_OK;
    SmartBA sba_qx, sba_qy;
    const uint8_t* buf = nullptr;
    size_t len = 0;

    CHECK_NOT_NULL(baPubkey);
    CHECK_NOT_NULL(baQx);
    CHECK_NOT_NULL(baQy);

    buf = ba_get_buf_const(baPubkey);
    len = ba_get_len(baPubkey);
    if ((len < 65) || (buf[0] != 0x04)) {
        SET_ERROR(RET_INVALID_PUBLIC_KEY);
    }
    len = (len - 1) / 2;

    if (
        !sba_qx.set(ba_alloc_from_uint8(&buf[1], len)) ||
        !sba_qy.set(ba_alloc_from_uint8(&buf[len + 1], len))
    ) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    *baQx = sba_qx.pop();
    *baQy = sba_qy.pop();

cleanup:
    return ret;
}

static int parse_ecdsa_signvalue (const ByteArray* baSignature, ByteArray** baR, ByteArray** baS)
{
    int ret = RET_OK;
    ECDSA_Sig_Value_t* ec_sig = nullptr;

    CHECK_PARAM(baSignature != NULL);
    CHECK_PARAM(baR != NULL);
    CHECK_PARAM(baS != NULL);

    CHECK_NOT_NULL(ec_sig = (ECDSA_Sig_Value_t*)asn_decode_ba_with_alloc(get_ECDSA_Sig_Value_desc(), baSignature));
    DO(asn_INTEGER2ba(&ec_sig->r, baR));
    DO(asn_INTEGER2ba(&ec_sig->s, baS));

cleanup:
    asn_free(get_ECDSA_Sig_Value_desc(), ec_sig);
    return ret;
}

int Verify::verifyEcSign (
        const SignAlg signAlgo,
        const EcParamsId ecParamId,
        const ByteArray* baPubkey,
        const ByteArray* baHash,
        const ByteArray* baSignValue
)
{
    int ret = RET_OK;
    EcCtx* ec_ctx = nullptr;
    SmartBA sba_qx, sba_qy, sba_r, sba_s;

    CHECK_NOT_NULL(baPubkey);
    CHECK_NOT_NULL(baHash);
    CHECK_NOT_NULL(baSignValue);

    CHECK_NOT_NULL(ec_ctx = ec_alloc_default(ecParamId));
    switch (signAlgo)
    {
    case SIGN_DSTU4145:
        DO(dstu4145_decompress_pubkey(ec_ctx, baPubkey, &sba_qx, &sba_qy));
        DO(ba_swap(sba_qx.get()));
        DO(ba_swap(sba_qy.get()));
        DO(parse_dstu_signvalue(baSignValue, &sba_r, &sba_s));
        DO(ec_init_verify(ec_ctx, sba_qx.get(), sba_qy.get()));
        DO(dstu4145_verify(ec_ctx, baHash, sba_r.get(), sba_s.get()));
        break;
    case SIGN_ECDSA:
        DO(parse_ecdsa_pubkey(baPubkey, &sba_qx, &sba_qy));
        DO(parse_ecdsa_signvalue(baSignValue, &sba_r, &sba_s));
        DO(ec_init_verify(ec_ctx, sba_qx.get(), sba_qy.get()));
        DO(ecdsa_verify(ec_ctx, baHash, sba_r.get(), sba_s.get()));
        break;
    default:
        SET_ERROR(RET_UNSUPPORTED);
        break;
    }

cleanup:
    ec_free(ec_ctx);
    return ret;
}

int Verify::verifyRsaV15Sign (
        const HashAlg hashAlgo,
        const ByteArray* baPubkeyN,
        const ByteArray* baPubkeyE,
        const ByteArray* baHash,
        const ByteArray* baSignValue
)
{
    int ret = RET_OK;
    RsaCtx* rsa_ctx = nullptr;

    CHECK_NOT_NULL(baPubkeyN);
    CHECK_NOT_NULL(baPubkeyE);
    CHECK_NOT_NULL(baHash);
    CHECK_NOT_NULL(baSignValue);

    CHECK_NOT_NULL(rsa_ctx = rsa_alloc());

    DO(rsa_init_verify_pkcs1_v1_5(rsa_ctx, hashAlgo, baPubkeyN, baPubkeyE));
    ret = rsa_verify(rsa_ctx, baHash, baSignValue);

cleanup:
    rsa_free(rsa_ctx);
    return ret;
}

static int dstu4145_params_get_ecparamsid (const ByteArray* baAlgoParam, EcParamsId* ecParamsId)
{
    int ret = RET_OK;
    DSTU4145Params_t* dstu_params = nullptr;
    char* s_oidcurve = nullptr;
    const DSTUEllipticCurve_t* ellipticCurve;

    CHECK_PARAM(baAlgoParam != NULL);
    CHECK_PARAM(ecParamsId != NULL);

    *ecParamsId = EC_PARAMS_ID_UNDEFINED;
    CHECK_NOT_NULL(dstu_params = (DSTU4145Params_t*)asn_decode_ba_with_alloc(get_DSTU4145Params_desc(), baAlgoParam));

    ellipticCurve = &dstu_params->ellipticCurve;
    if (ellipticCurve->present == DSTUEllipticCurve_PR_NOTHING) {
        SET_ERROR(RET_INVALID_EC_PARAMS);
    }

    DO(dstu4145_params_get_std_oid(ellipticCurve, &s_oidcurve));
    if (s_oidcurve) {
        *ecParamsId = ecid_from_oid(s_oidcurve);
    }

    if (*ecParamsId == EC_PARAMS_ID_UNDEFINED) {
        SET_ERROR(RET_UNSUPPORTED);
    }

cleanup:
    asn_free(get_DSTU4145Params_desc(), dstu_params);
    free(s_oidcurve);
    return ret;
}

static int parse_dstu_spki (const SubjectPublicKeyInfo_t* spki, EcParamsId* ecParamsId, ByteArray** baPubkey)
{
    int ret = RET_OK;
    SmartBA sba_params;

    if (!sba_params.set(ba_alloc_from_uint8(spki->algorithm.parameters->buf, spki->algorithm.parameters->size))) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }
    DO(dstu4145_params_get_ecparamsid(sba_params.get(), ecParamsId));
    DO(Util::bitStringEncapOctetFromAsn1(&spki->subjectPublicKey, baPubkey));

cleanup:
    return ret;
}

static int parse_ecdsa_spki (const SubjectPublicKeyInfo_t* spki, EcParamsId* ecParamsId, ByteArray** baPubkey)
{
    int ret = RET_OK;
    OBJECT_IDENTIFIER_t* oid_namedcurve = nullptr;

    CHECK_NOT_NULL(oid_namedcurve = (OBJECT_IDENTIFIER_t*)asn_any2type(spki->algorithm.parameters, get_OBJECT_IDENTIFIER_desc()));
    *ecParamsId = ecid_from_OID(oid_namedcurve);
    if (*ecParamsId == EC_PARAMS_ID_UNDEFINED) {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }
    DO(asn_BITSTRING2ba(&spki->subjectPublicKey, baPubkey));

cleanup:
    asn_free(get_OBJECT_IDENTIFIER_desc(), oid_namedcurve);
    return ret;
}

static int parse_rsa_spki (const SubjectPublicKeyInfo_t* spki, ByteArray** baPubkeyN, ByteArray** baPubkeyE)
{
    int ret = RET_OK;
    RSAPublicKey_t* rsa_pubkey = nullptr;
    SmartBA sba_pubkey;

    DO(asn_BITSTRING2ba(&spki->subjectPublicKey, &sba_pubkey));

    CHECK_NOT_NULL(rsa_pubkey = (RSAPublicKey_t*)asn_decode_ba_with_alloc(get_RSAPublicKey_desc(), sba_pubkey.get()));
    DO(asn_INTEGER2ba(&rsa_pubkey->modulus, baPubkeyN));
    DO(asn_INTEGER2ba(&rsa_pubkey->publicExponent, baPubkeyE));

cleanup:
    asn_free(get_RSAPublicKey_desc(), rsa_pubkey);
    return ret;
}

int Verify::parseSpki (
        const ByteArray* baSignerSPKI,
        SignAlg* keyAlgo,
        EcParamsId* ecParamsId,
        ByteArray** baPubkey,
        ByteArray** baPubkeyRsaE
)
{
    int ret = RET_OK;
    SubjectPublicKeyInfo_t* spki = nullptr;
    char* s_oid = nullptr;

    CHECK_NOT_NULL(spki = (SubjectPublicKeyInfo_t*)asn_decode_ba_with_alloc(get_SubjectPublicKeyInfo_desc(), baSignerSPKI));

    DO(asn_oid_to_text(&spki->algorithm.algorithm, &s_oid));
    if (spki->algorithm.parameters == NULL) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

    if (oid_is_parent(OID_DSTU4145_WITH_DSTU7564, s_oid) || oid_is_parent(OID_DSTU4145_WITH_GOST3411, s_oid)) {
        DO(parse_dstu_spki(spki, ecParamsId, baPubkey));
        *keyAlgo = SIGN_DSTU4145;
    }
    else if (oid_is_equal(OID_EC_KEY, s_oid)) {
        DO(parse_ecdsa_spki(spki, ecParamsId, baPubkey));
        *keyAlgo = SIGN_ECDSA;
    }
    else if (oid_is_equal(OID_RSA, s_oid)) {
        DO(parse_rsa_spki(spki, baPubkey, baPubkeyRsaE));
        *keyAlgo = SIGN_RSA_PKCS_1_5;
    }
    else {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }

cleanup:
    asn_free(get_SubjectPublicKeyInfo_desc(), spki);
    free(s_oid);
    return ret;
}

int Verify::verifySignature (
        const char* signAlgo,
        const ByteArray* baData,
        const bool isHash,
        const ByteArray* baSignerSPKI,
        const ByteArray* baSignValue
)
{
    int ret = RET_OK;
    const ByteArray* ref_ba;
    SmartBA sba_hash, sba_pubkey, sba_pubkey_rsae;
    HashAlg hash_algo = HASH_ALG_UNDEFINED;
    SignAlg key_algo = SIGN_UNDEFINED;
    SignAlg sign_algo = SIGN_UNDEFINED;
    EcParamsId ec_paramsid = EC_PARAMS_ID_UNDEFINED;

    CHECK_PARAM(signAlgo != NULL);
    CHECK_PARAM(baData != NULL);
    CHECK_PARAM(baSignerSPKI != NULL);
    CHECK_PARAM(baSignValue != NULL);

    hash_algo = hash_from_oid(signAlgo);
    sign_algo = signature_from_oid(signAlgo);
    if ((hash_algo == HASH_ALG_UNDEFINED) || (sign_algo == SIGN_UNDEFINED)) {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }

    if (!isHash) {
        DO(hash(hash_algo, baData, &sba_hash));
        ref_ba = sba_hash.get();
    }
    else {
        if (hash_get_size(hash_algo) != ba_get_len(baData)) {
            SET_ERROR(RET_UAPKI_INVALID_HASH_SIZE);
        }
        ref_ba = baData;
    }

    DO(parseSpki(baSignerSPKI, &key_algo, &ec_paramsid, &sba_pubkey, &sba_pubkey_rsae));
    if (key_algo != sign_algo) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }
    switch (sign_algo) {
    case SIGN_DSTU4145:
        DO(verifyEcSign(sign_algo, ec_paramsid, sba_pubkey.get(), ref_ba, baSignValue));
        break;
    case SIGN_ECDSA:
        DO(verifyEcSign(sign_algo, ec_paramsid, sba_pubkey.get(), ref_ba, baSignValue));
        break;
    case SIGN_RSA_PKCS_1_5:
        DO(verifyRsaV15Sign(hash_algo, sba_pubkey.get(), sba_pubkey_rsae.get(), ref_ba, baSignValue));
        break;
    default:
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
        break;
    }

cleanup:
    return ret;
}


}   //  end namespace UapkiNS
