/*
 * Copyright (c) 2026, The UAPKI Project Authors.
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

#include "archive-timestamp-v3.h"
#include "der-helper.h"
#include "macros-internal.h"
#include "oid-utils.h"
#include "uapkif.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"


using namespace std;


namespace UapkiNS {

namespace Pkcs7 {

namespace AtsV3 {


static ByteArray* ba_from_vector (
        const vector<uint8_t>& v
)
{
    return ba_alloc_from_uint8(v.data(), v.size());
}

//  The octets of the unsigned attributes, in their encoding as they are: each Attribute (TS 101 733), or
//  attrType || AttributeValue for each value of each Attribute (EN 319 122-1)
static bool unsigned_attr_octets (
        const IndexType indexType,
        const SignerInfo_t* signerInfo,
        vector<vector<uint8_t>>& octets
)
{
    if (!signerInfo->unsignedAttrs) return true;

    vector<vector<uint8_t>> attrs;
    if (!Der::children(signerInfo->unsignedAttrs->buf, (size_t)signerInfo->unsignedAttrs->size, attrs)) return false;
    for (const auto& it_attr : attrs) {
        if (indexType == IndexType::TS_101_733) {
            octets.push_back(it_attr);
            continue;
        }
        vector<vector<uint8_t>> type_values, values;
        if (
            !Der::children(it_attr.data(), it_attr.size(), type_values) || (type_values.size() != 2) ||
            !Der::children(type_values[1].data(), type_values[1].size(), values)
        ) return false;
        for (const auto& it_value : values) {
            vector<uint8_t> v = type_values[0];
            v.insert(v.end(), it_value.begin(), it_value.end());
            octets.push_back(v);
        }
    }
    return true;
}

static int hash_data (
        const HashAlg hashAlg,
        const uint8_t* data,
        const size_t len,
        vector<vector<uint8_t>>& hashes
)
{
    SmartBA sba_data, sba_hash;
    if (!sba_data.set(ba_alloc_from_uint8(data, len))) return RET_UAPKI_GENERAL_ERROR;
    const int ret = ::hash(hashAlg, sba_data.get(), &sba_hash);
    if (ret != RET_OK) return ret;
    hashes.push_back(vector<uint8_t>(sba_hash.buf(), sba_hash.buf() + sba_hash.size()));
    return RET_OK;
}

static int hash_all (
        const IndexType indexType,
        const HashAlg hashAlg,
        const VectorBA& certs,
        const VectorBA& crls,
        const SignerInfo_t* signerInfo,
        vector<vector<uint8_t>> hashes[3]
)
{
    int ret = RET_OK;
    vector<vector<uint8_t>> attr_octets;

    for (const auto& it : certs) {
        DO(hash_data(hashAlg, ba_get_buf_const(it), ba_get_len(it), hashes[0]));
    }
    for (const auto& it : crls) {
        DO(hash_data(hashAlg, ba_get_buf_const(it), ba_get_len(it), hashes[1]));
    }
    if (!unsigned_attr_octets(indexType, signerInfo, attr_octets)) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }
    for (const auto& it : attr_octets) {
        DO(hash_data(hashAlg, it.data(), it.size(), hashes[2]));
    }

cleanup:
    return ret;
}

static vector<uint8_t> seq_of_octet_strings (
        const vector<vector<uint8_t>>& hashes
)
{
    vector<uint8_t> body;
    for (const auto& it : hashes) {
        const vector<uint8_t> os = Der::wrap(0x04, it);
        body.insert(body.end(), os.begin(), os.end());
    }
    return Der::wrap(0x30, body);
}

const char* indexAttrType (
        const IndexType indexType
)
{
    return (indexType == IndexType::TS_101_733) ? OID_ETSI_ATS_HASH_INDEX : OID_ETSI_ATS_HASH_INDEX_V3;
}

int buildHashIndex (
        const IndexType indexType,
        const string& hashIndAlgorithm,
        const VectorBA& certs,
        const VectorBA& crls,
        const SignerInfo_t* signerInfo,
        ByteArray** baHashIndex
)
{
    const HashAlg hash_alg = hash_from_oid(hashIndAlgorithm.c_str());
    if ((hash_alg == HASH_ALG_UNDEFINED) || !signerInfo || !baHashIndex) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    SmartBA sba_aid;
    vector<vector<uint8_t>> hashes[3];
    vector<uint8_t> body;

    DO(hash_all(indexType, hash_alg, certs, crls, signerInfo, hashes));

    //  hashIndAlgorithm: DEFAULT sha256 in ATSHashIndex (TS 101 733), DER - absent if it is the default
    if ((indexType == IndexType::EN_319_122) || (hash_alg != HASH_ALG_SHA256)) {
        DO(Util::encodeAlgorithmIdentifier(hashIndAlgorithm, nullptr, &sba_aid));
        body.assign(sba_aid.buf(), sba_aid.buf() + sba_aid.size());
    }
    for (size_t i = 0; i < 3; i++) {
        const vector<uint8_t> part = seq_of_octet_strings(hashes[i]);
        body.insert(body.end(), part.begin(), part.end());
    }

    *baHashIndex = ba_from_vector(Der::wrap(0x30, body));
    if (!*baHashIndex) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

cleanup:
    return ret;
}

int checkHashIndex (
        const IndexType indexType,
        const ByteArray* baHashIndex,
        const VectorBA& certs,
        const VectorBA& crls,
        const SignerInfo_t* signerInfo,
        bool& isValid
)
{
    isValid = false;
    if (!baHashIndex || !signerInfo) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    AlgorithmIdentifier_t* aid = nullptr;
    UapkiNS::AlgorithmIdentifier hash_aid;
    HashAlg hash_alg = HASH_ALG_UNDEFINED;
    vector<vector<uint8_t>> parts, actual[3];

    if (!Der::children(ba_get_buf_const(baHashIndex), ba_get_len(baHashIndex), parts)) {
        SET_ERROR(RET_UAPKI_INVALID_ATTRIBUTE);
    }
    //  ATSHashIndex (TS 101 733) without hashIndAlgorithm: sha256 (DEFAULT)
    if ((indexType == IndexType::TS_101_733) && (parts.size() == 3)) {
        hash_alg = HASH_ALG_SHA256;
        parts.insert(parts.begin(), vector<uint8_t>());
    }
    else {
        if ((parts.size() != 4) || (parts[0][0] != 0x30)) {
            SET_ERROR(RET_UAPKI_INVALID_ATTRIBUTE);
        }
        CHECK_NOT_NULL(aid = (AlgorithmIdentifier_t*)asn_decode_with_alloc(get_AlgorithmIdentifier_desc(), parts[0].data(), parts[0].size()));
        DO(Util::algorithmIdentifierFromAsn1(*aid, hash_aid));
        hash_alg = hash_from_oid(hash_aid.algorithm.c_str());
    }
    if (hash_alg == HASH_ALG_UNDEFINED) {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }

    DO(hash_all(indexType, hash_alg, certs, crls, signerInfo, actual));

    for (size_t i = 0; i < 3; i++) {
        vector<vector<uint8_t>> octet_strings;
        if ((parts[i + 1].empty()) || !Der::children(parts[i + 1].data(), parts[i + 1].size(), octet_strings)) {
            SET_ERROR(RET_UAPKI_INVALID_ATTRIBUTE);
        }
        for (const auto& it : octet_strings) {
            size_t lh = 0, lb = 0;
            if ((it[0] != 0x04) || !Der::read(it.data(), it.size(), lh, lb)) {
                SET_ERROR(RET_UAPKI_INVALID_ATTRIBUTE);
            }
            const vector<uint8_t> hash_value(it.begin() + lh, it.end());
            bool found = false;
            for (const auto& it_actual : actual[i]) {
                found = (it_actual == hash_value);
                if (found) break;
            }
            //  A reference whose original value is not found: the index is invalid
            if (!found) goto cleanup;
        }
    }
    isValid = true;

cleanup:
    asn_free(get_AlgorithmIdentifier_desc(), aid);
    return ret;
}

int calcMessageImprint (
        const HashAlg hashAlg,
        const string& contentType,
        const ByteArray* baHashContent,
        const SignerInfo_t* signerInfo,
        const ByteArray* baHashIndex,
        ByteArray** baHash
)
{
    if (contentType.empty() || !baHashContent || !signerInfo || !baHashIndex || !baHash) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    SignerInfo_t* signer_info = nullptr;
    ANY_t* any_unsignedattrs = nullptr;
    SmartBA sba_contenttype, sba_signerinfo, sba_data;
    size_t lh = 0, lb = 0;
    vector<uint8_t> data;

    DO(Util::encodeOid(contentType.c_str(), &sba_contenttype));
    data.assign(sba_contenttype.buf(), sba_contenttype.buf() + sba_contenttype.size());
    data.insert(data.end(), ba_get_buf_const(baHashContent), ba_get_buf_const(baHashContent) + ba_get_len(baHashContent));

    //  The fields of the SignerInfo (without unsignedAttrs): the body of its SEQUENCE
    CHECK_NOT_NULL(signer_info = (SignerInfo_t*)asn_copy_with_alloc(get_SignerInfo_desc(), signerInfo));
    any_unsignedattrs = signer_info->unsignedAttrs;
    signer_info->unsignedAttrs = nullptr;
    ret = asn_encode_ba(get_SignerInfo_desc(), signer_info, &sba_signerinfo);
    signer_info->unsignedAttrs = any_unsignedattrs;
    DO(ret);
    if (!Der::read(sba_signerinfo.buf(), sba_signerinfo.size(), lh, lb)) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }
    data.insert(data.end(), sba_signerinfo.buf() + lh, sba_signerinfo.buf() + lh + lb);

    data.insert(data.end(), ba_get_buf_const(baHashIndex), ba_get_buf_const(baHashIndex) + ba_get_len(baHashIndex));

    if (!sba_data.set(ba_from_vector(data))) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }
    DO(::hash(hashAlg, sba_data.get(), baHash));

cleanup:
    asn_free(get_SignerInfo_desc(), signer_info);
    return ret;
}


}   //  end namespace AtsV3

}   //  end namespace Pkcs7

}   //  end namespace UapkiNS
