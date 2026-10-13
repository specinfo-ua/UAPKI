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

#define FILE_MARKER "common/pkix/uapki-ns-verify.cpp"

#include "uapki-ns-verify.h"
#include "der-helper.h"
#include "dstu4145-params.h"
#include "ecdsa-params.h"
#include "macros-internal.h"
#include "oid-utils.h"
#include "uapkif.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>


namespace UapkiNS {


namespace {

struct EcVerifyKey {
    SignAlg keyAlgo;
    EcCtx*  ecCtx;

    EcVerifyKey (void)
        : keyAlgo(SIGN_UNDEFINED), ecCtx(nullptr) {}
    ~EcVerifyKey (void) {
        ec_free(ecCtx);
    }
};  //  end struct EcVerifyKey

class EcVerifyKeyCache {
    typedef std::pair<std::string, std::shared_ptr<EcVerifyKey>> Item;
    static const size_t MAX_ENTRIES = 10000;

    std::mutex      m_Mutex;
    std::list<Item> m_Lru;
    std::unordered_map<std::string, std::list<Item>::iterator> m_Index;

public:
    std::shared_ptr<EcVerifyKey> get (const std::string& spki) {
        std::lock_guard<std::mutex> lock(m_Mutex);
        auto it = m_Index.find(spki);
        if (it == m_Index.end()) return nullptr;
        m_Lru.splice(m_Lru.begin(), m_Lru, it->second);
        return it->second->second;
    }

    void put (const std::string& spki, const std::shared_ptr<EcVerifyKey>& key) {
        std::lock_guard<std::mutex> lock(m_Mutex);
        auto it = m_Index.find(spki);
        if (it != m_Index.end()) {
            m_Lru.splice(m_Lru.begin(), m_Lru, it->second);
            return;
        }
        if (m_Lru.size() >= MAX_ENTRIES) {
            m_Index.erase(m_Lru.back().first);
            m_Lru.pop_back();
        }
        m_Lru.push_front(Item(spki, key));
        m_Index[spki] = m_Lru.begin();
    }
};  //  end class EcVerifyKeyCache

EcVerifyKeyCache& ec_verify_key_cache (void)
{
    static EcVerifyKeyCache* cache = new EcVerifyKeyCache();
    return *cache;
}

}   //  end anonymous namespace


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
    SmartBA sba_Qx, sba_Qy;
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
        !sba_Qx.set(ba_alloc_from_uint8(&buf[1], len)) ||
        !sba_Qy.set(ba_alloc_from_uint8(&buf[len + 1], len))
    ) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    *baQx = sba_Qx.pop();
    *baQy = sba_Qy.pop();

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

static int ec_init_verify_key (
        const SignAlg signAlgo,
        const EcParamsId ecParamId,
        const ByteArray* baPubkey,
        EcCtx** ecCtx
)
{
    int ret = RET_OK;
    EcCtx* ec_ctx = nullptr;
    SmartBA sba_Qx, sba_Qy;

    CHECK_NOT_NULL(baPubkey);
    CHECK_NOT_NULL(ecCtx);

    CHECK_NOT_NULL(ec_ctx = ec_alloc_default(ecParamId));
    switch (signAlgo)
    {
    case SIGN_DSTU4145:
        DO(dstu4145_decompress_pubkey(ec_ctx, baPubkey, &sba_Qx, &sba_Qy));
        DO(ba_swap(sba_Qx.get()));
        DO(ba_swap(sba_Qy.get()));
        DO(ec_init_verify(ec_ctx, sba_Qx.get(), sba_Qy.get()));
        break;
    case SIGN_ECDSA:
        DO(parse_ecdsa_pubkey(baPubkey, &sba_Qx, &sba_Qy));
        DO(ec_init_verify(ec_ctx, sba_Qx.get(), sba_Qy.get()));
        break;
    default:
        SET_ERROR(RET_UNSUPPORTED);
        break;
    }

    *ecCtx = ec_ctx;
    ec_ctx = nullptr;

cleanup:
    ec_free(ec_ctx);
    return ret;
}

static int ec_verify_sign (
        const SignAlg signAlgo,
        const EcCtx* ecCtx,
        const ByteArray* baHash,
        const ByteArray* baSignValue
)
{
    int ret = RET_OK;
    SmartBA sba_r, sba_s;

    CHECK_NOT_NULL(ecCtx);
    CHECK_NOT_NULL(baHash);
    CHECK_NOT_NULL(baSignValue);

    switch (signAlgo)
    {
    case SIGN_DSTU4145:
        DO(parse_dstu_signvalue(baSignValue, &sba_r, &sba_s));
        DO(dstu4145_verify(ecCtx, baHash, sba_r.get(), sba_s.get()));
        break;
    case SIGN_ECDSA:
        DO(parse_ecdsa_signvalue(baSignValue, &sba_r, &sba_s));
        DO(ecdsa_verify(ecCtx, baHash, sba_r.get(), sba_s.get()));
        break;
    default:
        SET_ERROR(RET_UNSUPPORTED);
        break;
    }

cleanup:
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

    DO(ec_init_verify_key(signAlgo, ecParamId, baPubkey, &ec_ctx));
    DO(ec_verify_sign(signAlgo, ec_ctx, baHash, baSignValue));

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

    if (!spki->algorithm.parameters) return RET_UAPKI_UNSUPPORTED_ALG;

    *ecParamsId = EcParamsId(ecdsa_ecparams_get_ecid(spki->algorithm.parameters->buf, spki->algorithm.parameters->size));
    if (*ecParamsId == EC_PARAMS_ID_UNDEFINED) return RET_UAPKI_UNSUPPORTED_ALG;

    DO(asn_BITSTRING2ba(&spki->subjectPublicKey, baPubkey));

cleanup:
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
    //  The parameters of an id-RSASSA-PSS key may be absent (RFC 4056, 2.1)
    if ((spki->algorithm.parameters == NULL) && !oid_is_equal(OID_RSA_PSS, s_oid)) {
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
    else if (oid_is_equal(OID_RSA_PSS, s_oid)) {
        DO(parse_rsa_spki(spki, baPubkey, baPubkeyRsaE));
        *keyAlgo = SIGN_RSA_PSS;
    }
    else {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }

cleanup:
    asn_free(get_SubjectPublicKeyInfo_desc(), spki);
    free(s_oid);
    return ret;
}

//  RSASSA-PSS-params (RFC 4055, 3.1): the hash, the hash of MGF1, the salt length, the trailer field
struct RsaPssParams {
    HashAlg hashAlgo;
    HashAlg mgfHashAlgo;
    size_t  saltLength;
    size_t  trailerField;

    RsaPssParams (void)
        : hashAlgo(HASH_ALG_SHA1), mgfHashAlgo(HASH_ALG_SHA1), saltLength(20), trailerField(1)
    {}
};

static bool der_oid_to_text (
        const uint8_t* buf,
        const size_t len,
        std::string& oid
)
{
    if (!buf || (len == 0)) return false;
    oid = std::to_string(buf[0] / 40) + "." + std::to_string(buf[0] % 40);
    uint64_t arc = 0;
    for (size_t i = 1; i < len; i++) {
        if (arc >> 56) return false;
        arc = (arc << 7) | (buf[i] & 0x7F);
        if (!(buf[i] & 0x80)) {
            oid += "." + std::to_string(arc);
            arc = 0;
        }
    }
    return ((buf[len - 1] & 0x80) == 0);
}

//  The hash of AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }
static bool der_algid_to_hash (
        const uint8_t* buf,
        const size_t len,
        HashAlg& hashAlgo,
        const uint8_t** params = nullptr,
        size_t* paramsLen = nullptr
)
{
    uint32_t tag = 0;
    size_t hlen = 0, vlen = 0;
    std::string s_oid;
    if (!Util::decodeAsn1Header(buf, len, tag, hlen, vlen) || (tag != 0x30) || (hlen + vlen > len)) return false;
    const uint8_t* body = buf + hlen;
    const size_t len_body = vlen;
    if (!Util::decodeAsn1Header(body, len_body, tag, hlen, vlen) || (tag != 0x06) || (hlen + vlen > len_body)) return false;
    if (!der_oid_to_text(body + hlen, vlen, s_oid)) return false;
    hashAlgo = hash_from_oid(s_oid.c_str());
    if (params && paramsLen) {
        *params = body + hlen + vlen;
        *paramsLen = len_body - hlen - vlen;
        //  For the mask generation function the OID is checked by the caller
        hashAlgo = oid_is_equal(OID_PKCS1_MGF1, s_oid.c_str()) ? HASH_ALG_SHA1 : HASH_ALG_UNDEFINED;
    }
    return true;
}

static int parse_rsa_pss_params (
        const uint8_t* buf,
        const size_t len,
        RsaPssParams& pssParams
)
{
    uint32_t tag = 0;
    size_t hlen = 0, vlen = 0;
    if (!buf || !Util::decodeAsn1Header(buf, len, tag, hlen, vlen) || (tag != 0x30) || (hlen + vlen > len)) {
        return RET_UAPKI_INVALID_STRUCT;
    }

    const uint8_t* p = buf + hlen;
    size_t left = vlen;
    while (left > 0) {
        if (!Util::decodeAsn1Header(p, left, tag, hlen, vlen) || (hlen + vlen > left)) return RET_UAPKI_INVALID_STRUCT;
        const uint8_t* value = p + hlen;
        switch (tag) {
        case 0xA0:
            if (!der_algid_to_hash(value, vlen, pssParams.hashAlgo)) return RET_UAPKI_INVALID_STRUCT;
            if (pssParams.hashAlgo == HASH_ALG_UNDEFINED) return RET_UAPKI_UNSUPPORTED_ALG;
            break;
        case 0xA1: {
            //  MaskGenAlgorithm: id-mgf1 with the AlgorithmIdentifier of its hash
            HashAlg is_mgf1 = HASH_ALG_UNDEFINED;
            const uint8_t* mgf_params = nullptr;
            size_t len_mgfparams = 0;
            if (!der_algid_to_hash(value, vlen, is_mgf1, &mgf_params, &len_mgfparams)) return RET_UAPKI_INVALID_STRUCT;
            if (is_mgf1 == HASH_ALG_UNDEFINED) return RET_UAPKI_UNSUPPORTED_ALG;
            if (!der_algid_to_hash(mgf_params, len_mgfparams, pssParams.mgfHashAlgo)) return RET_UAPKI_INVALID_STRUCT;
            if (pssParams.mgfHashAlgo == HASH_ALG_UNDEFINED) return RET_UAPKI_UNSUPPORTED_ALG;
            break;
        }
        case 0xA2:
        case 0xA3: {
            uint32_t tag_int = 0;
            size_t hlen_int = 0, vlen_int = 0;
            if (
                !Util::decodeAsn1Header(value, vlen, tag_int, hlen_int, vlen_int) || (tag_int != 0x02) ||
                (vlen_int == 0) || (vlen_int > 4) || (hlen_int + vlen_int > vlen) || (value[hlen_int] & 0x80)
            ) return RET_UAPKI_INVALID_STRUCT;
            size_t number = 0;
            for (size_t i = 0; i < vlen_int; i++) {
                number = (number << 8) | value[hlen_int + i];
            }
            ((tag == 0xA2) ? pssParams.saltLength : pssParams.trailerField) = number;
            break;
        }
        default:
            return RET_UAPKI_INVALID_STRUCT;
        }
        p += hlen + vlen;
        left -= hlen + vlen;
    }
    return RET_OK;
}

//  The parameters of an id-RSASSA-PSS public key, if present (RFC 4055, 3.1; RFC 4056, 2.1): the algorithm of
//  SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
static int rsa_pss_key_params (
        const ByteArray* baSpki,
        bool& isPresent,
        RsaPssParams& pssParams
)
{
    const uint8_t* buf = ba_get_buf_const(baSpki);
    const size_t len = ba_get_len(baSpki);
    uint32_t tag = 0;
    size_t hlen = 0, vlen = 0;

    isPresent = false;
    if (!buf || !Util::decodeAsn1Header(buf, len, tag, hlen, vlen) || (tag != 0x30) || (hlen + vlen > len)) return RET_UAPKI_INVALID_STRUCT;
    const uint8_t* p = buf + hlen;
    size_t left = vlen;
    if (!Util::decodeAsn1Header(p, left, tag, hlen, vlen) || (tag != 0x30) || (hlen + vlen > left)) return RET_UAPKI_INVALID_STRUCT;
    p += hlen;
    left = vlen;
    if (!Util::decodeAsn1Header(p, left, tag, hlen, vlen) || (tag != 0x06) || (hlen + vlen > left)) return RET_UAPKI_INVALID_STRUCT;
    p += hlen + vlen;
    left -= hlen + vlen;
    if (left == 0) return RET_OK;

    isPresent = true;
    return parse_rsa_pss_params(p, left, pssParams);
}

static int verify_rsa_pss_sign (
        const RsaPssParams& pssParams,
        const ByteArray* baPubkeyN,
        const ByteArray* baPubkeyE,
        const ByteArray* baHash,
        const ByteArray* baSignValue
)
{
    int ret = RET_OK;
    RsaCtx* rsa_ctx = nullptr;

    CHECK_NOT_NULL(rsa_ctx = rsa_alloc());
    DO(rsa_init_verify_pss(rsa_ctx, pssParams.hashAlgo, pssParams.saltLength, baPubkeyN, baPubkeyE));
    ret = rsa_verify(rsa_ctx, baHash, baSignValue);

cleanup:
    rsa_free(rsa_ctx);
    return ret;
}

static bool der_oid_from_text (
        const char* oid,
        std::vector<uint8_t>& encoded
)
{
    std::vector<uint64_t> arcs;
    if (!oid) return false;
    for (const char* p = oid; *p; ) {
        if ((*p < '0') || (*p > '9')) return false;
        uint64_t arc = 0;
        while ((*p >= '0') && (*p <= '9')) {
            arc = arc * 10 + (uint64_t)(*p++ - '0');
        }
        arcs.push_back(arc);
        if (*p == '.') p++;
    }
    if ((arcs.size() < 2) || (arcs[0] > 2) || ((arcs[0] < 2) && (arcs[1] > 39))) return false;

    std::vector<uint8_t> body;
    arcs[1] += arcs[0] * 40;
    for (size_t i = 1; i < arcs.size(); i++) {
        uint8_t septets[10];
        size_t cnt = 0;
        uint64_t arc = arcs[i];
        do {
            septets[cnt++] = (uint8_t)(arc & 0x7F);
            arc >>= 7;
        } while (arc);
        while (cnt > 0) {
            cnt--;
            body.push_back((uint8_t)(septets[cnt] | (cnt ? 0x80 : 0x00)));
        }
    }
    encoded = Der::wrap(0x06, body);
    return true;
}

int Verify::rsaPssParamsEncode (
        const HashAlg hashAlgo,
        ByteArray** baEncoded
)
{
    if (!baEncoded) return RET_UAPKI_INVALID_PARAMETER;

    const size_t salt_len = hash_get_size(hashAlgo);
    std::vector<uint8_t> oid_hash, oid_mgf1, body;
    if ((salt_len == 0) || (salt_len > 0x7F) || !der_oid_from_text(hash_to_oid(hashAlgo), oid_hash) || !der_oid_from_text(OID_PKCS1_MGF1, oid_mgf1)) {
        return RET_UAPKI_UNSUPPORTED_ALG;
    }

    //  DER: a component equal to its DEFAULT is absent (sha1, mgf1SHA1, 20)
    if (hashAlgo != HASH_ALG_SHA1) {
        std::vector<uint8_t> aid_hash = oid_hash;
        aid_hash.push_back(0x05);
        aid_hash.push_back(0x00);
        aid_hash = Der::wrap(0x30, aid_hash);

        std::vector<uint8_t> aid_mgf = oid_mgf1;
        aid_mgf.insert(aid_mgf.end(), aid_hash.begin(), aid_hash.end());
        aid_mgf = Der::wrap(0x30, aid_mgf);

        const std::vector<uint8_t> field_hash = Der::wrap(0xA0, aid_hash);
        const std::vector<uint8_t> field_mgf = Der::wrap(0xA1, aid_mgf);
        body.insert(body.end(), field_hash.begin(), field_hash.end());
        body.insert(body.end(), field_mgf.begin(), field_mgf.end());
    }
    if (salt_len != 20) {
        const std::vector<uint8_t> field_salt = Der::wrap(0xA2, Der::wrap(0x02, std::vector<uint8_t>(1, (uint8_t)salt_len)));
        body.insert(body.end(), field_salt.begin(), field_salt.end());
    }

    const std::vector<uint8_t> encoded = Der::wrap(0x30, body);
    *baEncoded = ba_alloc_from_uint8(encoded.data(), encoded.size());
    return (*baEncoded) ? RET_OK : RET_UAPKI_GENERAL_ERROR;
}

int Verify::rsaPssParamsDecode (
        const ByteArray* baEncoded,
        HashAlg& hashAlgo,
        size_t& saltLength
)
{
    RsaPssParams pss_params;
    const int ret = parse_rsa_pss_params(ba_get_buf_const(baEncoded), ba_get_len(baEncoded), pss_params);
    if (ret != RET_OK) return ret;
    if ((pss_params.mgfHashAlgo != pss_params.hashAlgo) || (pss_params.trailerField != 1)) return RET_UAPKI_UNSUPPORTED_ALG;

    hashAlgo = pss_params.hashAlgo;
    saltLength = pss_params.saltLength;
    return RET_OK;
}

int Verify::verifySignature (
        const char* signAlgo,
        const ByteArray* baData,
        const bool isHash,
        const ByteArray* baSignerSPKI,
        const ByteArray* baSignValue,
        const char* digestAlgo,
        const ByteArray* baSignAlgoParams
)
{
    int ret = RET_OK;
    const ByteArray* ref_ba;
    SmartBA sba_hash, sba_pubkey, sba_pubkey_rsae;
    HashAlg hash_algo = HASH_ALG_UNDEFINED;
    SignAlg key_algo = SIGN_UNDEFINED;
    SignAlg sign_algo = SIGN_UNDEFINED;
    EcParamsId ec_paramsid = EC_PARAMS_ID_UNDEFINED;
    std::string spki_key;
    std::shared_ptr<EcVerifyKey> ec_key;
    RsaPssParams pss_params;

    CHECK_PARAM(signAlgo != NULL);
    CHECK_PARAM(baData != NULL);
    CHECK_PARAM(baSignerSPKI != NULL);
    CHECK_PARAM(baSignValue != NULL);

    hash_algo = hash_from_oid(signAlgo);
    sign_algo = signature_from_oid(signAlgo);
    //  rsaEncryption in SignerInfo.signatureAlgorithm: RSASSA-PKCS1-v1_5 with the digest algorithm of the SignerInfo
    //  (RFC 3370, 3.2)
    if ((hash_algo == HASH_ALG_UNDEFINED) && digestAlgo && oid_is_equal(OID_RSA, signAlgo)) {
        hash_algo = hash_from_oid(digestAlgo);
        sign_algo = SIGN_RSA_PKCS_1_5;
    }
    //  RSASSA-PSS: the hash, the mask generation function and the salt length are in the parameters of the
    //  signature algorithm, which are required (RFC 4055, 3.1; RFC 4056, 2.2, 3). The library has MGF1 with
    //  the hash of the signature only
    if (oid_is_equal(OID_RSA_PSS, signAlgo)) {
        if (!baSignAlgoParams) {
            SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
        }
        DO(parse_rsa_pss_params(ba_get_buf_const(baSignAlgoParams), ba_get_len(baSignAlgoParams), pss_params));
        if ((pss_params.mgfHashAlgo != pss_params.hashAlgo) || (pss_params.trailerField != 1)) {
            SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
        }
        hash_algo = pss_params.hashAlgo;
        sign_algo = SIGN_RSA_PSS;
    }
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

    spki_key.assign((const char*)ba_get_buf_const(baSignerSPKI), ba_get_len(baSignerSPKI));
    ec_key = ec_verify_key_cache().get(spki_key);
    if (ec_key) {
        if (ec_key->keyAlgo != sign_algo) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
        DO(ec_verify_sign(sign_algo, ec_key->ecCtx, ref_ba, baSignValue));
        goto cleanup;
    }

    DO(parseSpki(baSignerSPKI, &key_algo, &ec_paramsid, &sba_pubkey, &sba_pubkey_rsae));
    //  An rsaEncryption key signs by both schemes, an id-RSASSA-PSS key - by RSASSA-PSS only (RFC 4055, 1.2)
    if ((key_algo != sign_algo) && !((sign_algo == SIGN_RSA_PSS) && (key_algo == SIGN_RSA_PKCS_1_5))) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }
    switch (sign_algo) {
    case SIGN_DSTU4145:
    case SIGN_ECDSA:
        ec_key = std::make_shared<EcVerifyKey>();
        ec_key->keyAlgo = key_algo;
        DO(ec_init_verify_key(sign_algo, ec_paramsid, sba_pubkey.get(), &ec_key->ecCtx));
        ec_verify_key_cache().put(spki_key, ec_key);
        DO(ec_verify_sign(sign_algo, ec_key->ecCtx, ref_ba, baSignValue));
        break;
    case SIGN_RSA_PKCS_1_5:
        DO(verifyRsaV15Sign(hash_algo, sba_pubkey.get(), sba_pubkey_rsae.get(), ref_ba, baSignValue));
        break;
    case SIGN_RSA_PSS:
        if (key_algo == SIGN_RSA_PSS) {
            //  The parameters of the key restrict the signature (RFC 4056, 3): the same hash and mask generation
            //  function, the salt not shorter, the same trailer field
            bool is_present = false;
            RsaPssParams key_params;
            DO(rsa_pss_key_params(baSignerSPKI, is_present, key_params));
            if (
                is_present && (
                    (key_params.hashAlgo != pss_params.hashAlgo) || (key_params.mgfHashAlgo != pss_params.mgfHashAlgo) ||
                    (pss_params.saltLength < key_params.saltLength) || (key_params.trailerField != pss_params.trailerField)
                )
            ) {
                SET_ERROR(RET_VERIFY_FAILED);
            }
        }
        DO(verify_rsa_pss_sign(pss_params, sba_pubkey.get(), sba_pubkey_rsae.get(), ref_ba, baSignValue));
        break;
    default:
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
        break;
    }

cleanup:
    return ret;
}


}   //  end namespace UapkiNS
