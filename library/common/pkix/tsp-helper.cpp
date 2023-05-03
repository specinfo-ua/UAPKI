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

#include "tsp-helper.h"
#include "drbg.h"
#include "macros-internal.h"
#include "oids.h"
#include "oid-utils.h"
#include "signeddata-helper.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"


#undef FILE_MARKER
#define FILE_MARKER "common/pkix/tsp-helper.c"


using namespace std;


namespace UapkiNS {

namespace Tsp {


TspHelper::TspHelper (void)
    : m_TspRequest(nullptr)
    , m_TstInfo(nullptr)
    , m_BaNonce(nullptr)
    , m_BaEncoded(nullptr)
    , m_Status(PkiStatus::UNDEFINED)
    , m_BaTsToken(nullptr)
{
}

TspHelper::~TspHelper (void)
{
    reset();
}

void TspHelper::reset (void)
{
    asn_free(get_TimeStampReq_desc(), m_TspRequest);
    asn_free(get_TSTInfo_desc(), m_TstInfo);
    ba_free(m_BaNonce);
    ba_free(m_BaEncoded);
    ba_free(m_BaTsToken);

    m_TspRequest = nullptr;
    m_TstInfo = nullptr;
    m_BaNonce = nullptr;
    m_BaEncoded = nullptr;
    m_Status = PkiStatus::UNDEFINED;
    m_BaTsToken = nullptr;
}

int TspHelper::init (void)
{
    m_TspRequest = (TimeStampReq_t*)calloc(1, sizeof(TimeStampReq_t));
    if (!m_TspRequest) return RET_UAPKI_GENERAL_ERROR;

    return asn_ulong2INTEGER(&m_TspRequest->version, 1);
}

int TspHelper::genNonce (
        const size_t nonceLen
)
{
    int ret = RET_OK;
    UapkiNS::SmartBA sba_nonce;

    if (
        !m_TspRequest ||
        (nonceLen < NONCE_MINLEN) ||
        (nonceLen > NONCE_MAXLEN)
    ) return RET_UAPKI_INVALID_PARAMETER;

    if (!sba_nonce.set(ba_alloc_by_len(nonceLen))) return RET_UAPKI_GENERAL_ERROR;

    DO(drbg_random(sba_nonce.get()));

    DO(setNonce(sba_nonce.get()));

cleanup:
    return ret;
}

int TspHelper::setCertReq (
        const bool certReq
)
{
    int ret = RET_OK;
    BOOLEAN_t cr = true;

    if (!m_TspRequest) return RET_UAPKI_INVALID_PARAMETER;

    if (certReq) {
        CHECK_NOT_NULL(m_TspRequest->certReq = (BOOLEAN_t*)asn_copy_with_alloc(get_BOOLEAN_desc(), &cr));
    }

cleanup:
    return ret;
}

int TspHelper::setMessageImprint (
        const UapkiNS::AlgorithmIdentifier& aidHashAlgo,
        const ByteArray* baHashedMessage
)
{
    int ret = RET_OK;

    if (!m_TspRequest || !baHashedMessage) return RET_UAPKI_INVALID_PARAMETER;

    DO(UapkiNS::Util::algorithmIdentifierToAsn1(m_TspRequest->messageImprint.hashAlgorithm, aidHashAlgo));
    DO(asn_ba2OCTSTRING(baHashedMessage, &m_TspRequest->messageImprint.hashedMessage));

    //m_MessageImprint.hashAlgorithm = aidHashAlgo.algorithm;
    //CHECK_NOT_NULL(m_MessageImprint.baHashedMessage = ba_copy_with_alloc(baHashedMessage, 0, 0));

cleanup:
    return ret;
}

int TspHelper::setNonce (
        const ByteArray* baNonce
)
{
    int ret = RET_OK;
    const size_t nonce_len = ba_get_len(baNonce);
    uint8_t byte = 0;

    if (
        !m_TspRequest ||
        (nonce_len < NONCE_MINLEN) ||
        (nonce_len > NONCE_MAXLEN)
    ) return RET_UAPKI_INVALID_PARAMETER;

    CHECK_NOT_NULL(m_BaNonce = ba_copy_with_alloc(baNonce, 0, 0));
    DO(ba_get_byte(m_BaNonce, 0, &byte));
    DO(ba_set_byte(m_BaNonce, 0, byte & 0x7F)); //  Integer must be a positive number

    ASN_ALLOC_TYPE(m_TspRequest->nonce, INTEGER_t);
    DO(asn_ba2INTEGER(m_BaNonce, m_TspRequest->nonce));

cleanup:
    return ret;
}

int TspHelper::setReqPolicy (
        const string& reqPolicy
)
{
    int ret = RET_OK;

    if (!m_TspRequest) return RET_UAPKI_INVALID_PARAMETER;

    if (!reqPolicy.empty()) {
        ASN_ALLOC_TYPE(m_TspRequest->reqPolicy, TSAPolicyId_t);
        DO(asn_set_oid_from_text(reqPolicy.c_str(), m_TspRequest->reqPolicy));
    }

cleanup:
    return ret;
}

int TspHelper::encodeRequest (void)
{
    if (!m_TspRequest) return RET_UAPKI_INVALID_PARAMETER;

    return asn_encode_ba(get_TimeStampReq_desc(), m_TspRequest, &m_BaEncoded);
}

ByteArray* TspHelper::getRequestEncoded (
        const bool move
)
{
    ByteArray* rv_ba = m_BaEncoded;
    if (move) {
        m_BaEncoded = nullptr;
    }
    return rv_ba;
}

int TspHelper::parseResponse (
        const ByteArray* baEncoded
)
{
    int ret = RET_OK;
    TimeStampResp_t* tsp_response = nullptr;
    unsigned long pkistatus_status = 0;

    if (!baEncoded) return RET_UAPKI_TSP_RESPONSE_INVALID;

    CHECK_NOT_NULL(tsp_response = (TimeStampResp_t*)asn_decode_ba_with_alloc(get_TimeStampResp_desc(), baEncoded));

    DO(asn_INTEGER2ulong(&tsp_response->status.status, &pkistatus_status));
    m_Status = (PkiStatus)pkistatus_status;

    if ((m_Status == PkiStatus::GRANTED) || (m_Status == PkiStatus::GRANTED_WITHMODS)) {
        if (!tsp_response->timeStampToken) {
            SET_ERROR(RET_UAPKI_TSP_RESPONSE_INVALID);
        }

        DO(asn_encode_ba(get_ContentInfo_desc(), tsp_response->timeStampToken, &m_BaTsToken));

        UapkiNS::Pkcs7::SignedDataParser sdata_parser;
        DO(sdata_parser.parse(m_BaTsToken));

        const UapkiNS::Pkcs7::EncapsulatedContentInfo& encap_cinfo = sdata_parser.getEncapContentInfo();
        if ((encap_cinfo.contentType != string(OID_PKCS9_TST_INFO)) || !encap_cinfo.baEncapContent) {
            SET_ERROR(RET_UAPKI_TSP_RESPONSE_INVALID);
        }

        CHECK_NOT_NULL(m_TstInfo = (TSTInfo_t*)asn_decode_ba_with_alloc(get_TSTInfo_desc(), encap_cinfo.baEncapContent));
    }

cleanup:
    asn_free(get_TimeStampResp_desc(), tsp_response);
    return ret;
}

ByteArray* TspHelper::getTsToken (
        const bool move
)
{
    ByteArray* rv_ba = m_BaTsToken;
    if (move) {
        m_BaTsToken = nullptr;
    }
    return rv_ba;
}

int TspHelper::tstInfoIsEqualRequest (void)
{
    int ret = RET_OK;

    if (!m_TspRequest || !m_TstInfo) return RET_UAPKI_INVALID_PARAMETER;

    const MessageImprint_t& mi_req = m_TspRequest->messageImprint;
    const MessageImprint_t& mi_resp = m_TstInfo->messageImprint;
    const OBJECT_IDENTIFIER_t& ha_req = mi_req.hashAlgorithm.algorithm;
    const OBJECT_IDENTIFIER_t& ha_resp = mi_resp.hashAlgorithm.algorithm;
    const OCTET_STRING_t& hm_req = mi_req.hashedMessage;
    const OCTET_STRING_t& hm_resp = mi_resp.hashedMessage;
    const INTEGER_t* nonce_req = m_TspRequest->nonce;
    const INTEGER_t* nonce_resp = m_TstInfo->nonce;

    //  Check hashAlgorithm
    if ((ha_req.size != ha_resp.size) || (memcmp(ha_req.buf, ha_resp.buf, ha_resp.size) != 0)) {
        SET_ERROR(RET_UAPKI_TSP_RESPONSE_NOT_EQUAL_REQUEST);
    }

    //  Check hashedMessage
    if ((hm_req.size != hm_resp.size) || (memcmp(hm_req.buf, hm_resp.buf, hm_resp.size) != 0)) {
        SET_ERROR(RET_UAPKI_TSP_RESPONSE_NOT_EQUAL_REQUEST);
    }

    //  Check nonce if present
    if (nonce_req) {
        if ((nonce_req->size != nonce_resp->size) || (memcmp(nonce_req->buf, nonce_resp->buf, nonce_resp->size) != 0)) {
            SET_ERROR(RET_UAPKI_TSP_RESPONSE_NOT_EQUAL_REQUEST);
        }
    }

cleanup:
    return ret;
}

TsTokenParser::TsTokenParser (void)
    : m_BaHashedMessage(nullptr)
    , m_GenTime(0)
{
}

TsTokenParser::~TsTokenParser (void)
{
    ba_free(m_BaHashedMessage);
}

int TsTokenParser::parse (
        const ByteArray* baEncoded
)
{
    if (!baEncoded) return RET_UAPKI_INVALID_CONTENT_INFO;

    int ret = m_SignedDataParser.parse(baEncoded);
    if (ret != RET_OK) return ret;

    TSTInfo_t* tst_info = nullptr;
    char* s_hashalgo = nullptr;
    char* s_policy = nullptr;

    const UapkiNS::Pkcs7::EncapsulatedContentInfo& encap_cinfo = m_SignedDataParser.getEncapContentInfo();
    if ((encap_cinfo.contentType != string(OID_PKCS9_TST_INFO)) || !encap_cinfo.baEncapContent) {
        SET_ERROR(RET_UAPKI_INVALID_CONTENT_INFO);
    }

    CHECK_NOT_NULL(tst_info = (TSTInfo_t*)asn_decode_ba_with_alloc(get_TSTInfo_desc(), encap_cinfo.baEncapContent));

    DO(asn_oid_to_text(&tst_info->policy, &s_policy));
    DO(asn_oid_to_text(&tst_info->messageImprint.hashAlgorithm.algorithm, &s_hashalgo));
    DO(asn_OCTSTRING2ba(&tst_info->messageImprint.hashedMessage, &m_BaHashedMessage));
    DO(UapkiNS::Util::genTimeFromAsn1(&tst_info->genTime, m_GenTime));

    m_PolicyId = string(s_policy);
    m_HashAlgo = string(s_hashalgo);
    s_policy = nullptr;
    s_hashalgo = nullptr;

cleanup:
    asn_free(get_TSTInfo_desc(), tst_info);
    ::free(s_hashalgo);
    ::free(s_policy);
    return ret;
}

ByteArray* TsTokenParser::getHashedMessage (
        const bool move
)
{
    ByteArray* rv_ba = m_BaHashedMessage;
    if (move) {
        m_BaHashedMessage = nullptr;
    }
    return rv_ba;
}


}   //  end namespace Tsp

}   //  end namespace UapkiNS

