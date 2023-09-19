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

#define FILE_MARKER "uapki/ocsp-helper.cpp"

#include "ocsp-helper.h"
#include "extension-helper.h"
#include "macros-internal.h"
#include "oid-utils.h"
#include "uapkic.h"
#include "uapkif.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"
#include "uapki-ns-verify.h"


using namespace std;


namespace UapkiNS {

namespace Ocsp {


static const char* RESPONSE_STATUS_STRINGS[8] = {
    "UNDEFINED",
    "SUCCESSFUL",
    "MALFORMED_REQUEST",
    "INTERNAL_ERROR",
    "TRY_LATER",
    "",
    "SIG_REQUIRED",
    "UNAUTHORIZED"
};

static OcspHelper::SingleResponseInfo singleresponseinfo_empty;


OcspHelper::OcspHelper (void)
    : m_OcspRequest(nullptr)
    , m_BasicOcspResp(nullptr)
    , m_BaBasicOcspResponse(nullptr)
    , m_BaNonce(nullptr)
    , m_BaRequestEncoded(nullptr)
    , m_BaTbsRequestEncoded(nullptr)
    , m_BaTbsResponseData(nullptr)
    , m_ProducedAt(0)
    , m_ResponseStatus(ResponseStatus::UNDEFINED)
{
}

OcspHelper::~OcspHelper (void)
{
    reset();
}

void OcspHelper::reset (void)
{
    asn_free(get_OCSPRequest_desc(), m_OcspRequest);
    asn_free(get_BasicOCSPResponse_desc(), m_BasicOcspResp);
    ba_free(m_BaBasicOcspResponse);
    ba_free(m_BaNonce);
    ba_free(m_BaRequestEncoded);
    ba_free(m_BaTbsRequestEncoded);
    ba_free(m_BaTbsResponseData);

    m_SingleResponseInfos.clear();
    m_OcspRequest = nullptr;
    m_BasicOcspResp = nullptr;
    m_BaBasicOcspResponse = nullptr;
    m_BaNonce = nullptr;
    m_BaRequestEncoded = nullptr;
    m_BaTbsRequestEncoded = nullptr;
    m_BaTbsResponseData = nullptr;
    m_ProducedAt = 0;
    m_ResponseStatus = ResponseStatus::UNDEFINED;
}

int OcspHelper::init (void)
{
    m_OcspRequest = (OCSPRequest_t*)calloc(1, sizeof(OCSPRequest_t));
    return (m_OcspRequest) ? RET_OK : RET_UAPKI_GENERAL_ERROR;
}

int OcspHelper::addCert (
        const Cert::CerItem* cerIssuer,
        const Cert::CerItem* cerSubject
)
{
    if (!cerSubject) return RET_UAPKI_INVALID_PARAMETER;

    return addIssuerAndSN(cerIssuer, cerSubject->getSerialNumber());
}

int OcspHelper::addCertId (
        const UapkiNS::AlgorithmIdentifier& hashAlgorithm,
        const ByteArray* baIssuerNameHash,
        const ByteArray* baIssuerKeyHash,
        const ByteArray* baSerialNumber
)
{
    int ret = RET_OK;
    Request_t* request = nullptr;

    if (
        !m_OcspRequest ||
        !hashAlgorithm.isPresent() ||
        !baIssuerNameHash ||
        !baIssuerKeyHash ||
        !baSerialNumber
    ) return RET_UAPKI_INVALID_PARAMETER;

    ASN_ALLOC_TYPE(request, Request_t);

    DO(Util::algorithmIdentifierToAsn1(request->reqCert.hashAlgorithm, hashAlgorithm));
    DO(asn_ba2OCTSTRING(baIssuerNameHash, &request->reqCert.issuerNameHash));
    DO(asn_ba2OCTSTRING(baIssuerKeyHash, &request->reqCert.issuerKeyHash));
    DO(asn_ba2INTEGER(baSerialNumber, &request->reqCert.serialNumber));

    DO(ASN_SEQUENCE_ADD(&m_OcspRequest->tbsRequest.requestList.list, request));
    request = nullptr;

cleanup:
    asn_free(get_Request_desc(), request);
    return ret;
}

int OcspHelper::addIssuerAndSN (
        const Cert::CerItem* cerIssuer,
        const ByteArray* baSerialNumber
)
{
    int ret = RET_OK;
    UapkiNS::AlgorithmIdentifier aid_hashalgo;
    SmartBA sba_subject, sba_issuernamehash;

    if (!m_OcspRequest || !cerIssuer || !baSerialNumber) return RET_UAPKI_INVALID_PARAMETER;

    DO(asn_encode_ba(get_Name_desc(), &cerIssuer->getCert()->tbsCertificate.subject, &sba_subject));

    aid_hashalgo.algorithm = string(hash_to_oid(cerIssuer->getAlgoKeyId()));
    DO(::hash(cerIssuer->getAlgoKeyId(), sba_subject.get(), &sba_issuernamehash));

    DO(addCertId(
        aid_hashalgo,
        sba_issuernamehash.get(),
        cerIssuer->getKeyId(),
        baSerialNumber
    ));

cleanup:
    return ret;
}

int OcspHelper::genNonce (
        const size_t nonceLen
)
{
    int ret = RET_OK;
    UapkiNS::SmartBA sba_nonce;

    if ((nonceLen < NONCE_MINLEN) || (nonceLen > NONCE_MAXLEN)) return RET_UAPKI_INVALID_PARAMETER;

    if (!sba_nonce.set(ba_alloc_by_len(nonceLen))) return RET_UAPKI_GENERAL_ERROR;

    DO(drbg_random(sba_nonce.get()));

    DO(setNonce(sba_nonce.get()));

cleanup:
    return ret;
}

int OcspHelper::setNonce (
        const ByteArray* baNonce
)
{
    int ret = RET_OK;
    const size_t nonce_len = ba_get_len(baNonce);

    if ((nonce_len < NONCE_MINLEN) || (nonce_len > NONCE_MAXLEN)) return RET_UAPKI_INVALID_PARAMETER;

    CHECK_NOT_NULL(m_BaNonce = ba_copy_with_alloc(baNonce, 0, 0));

    DO(addNonceToExtension());

cleanup:
    return ret;
}

int OcspHelper::addNonceToExtension (void)
{
    int ret = RET_OK;

    if (!m_OcspRequest || !m_BaNonce) return RET_UAPKI_INVALID_PARAMETER;

    TBSRequest_t* tbs_request = &m_OcspRequest->tbsRequest;
    if (!tbs_request->requestExtensions) {
        ASN_ALLOC_TYPE(tbs_request->requestExtensions, Extensions_t);
    }

    DO(ExtensionHelper::addOcspNonce(tbs_request->requestExtensions, m_BaNonce));

cleanup:
    return ret;
}

int OcspHelper::parseOcspResponse (
        const ByteArray* baEncoded
)
{
    m_ResponseStatus = ResponseStatus::UNDEFINED;
    if (!baEncoded) return RET_UAPKI_OCSP_RESPONSE_INVALID;

    OCSPResponse_t* ocsp_resp = (OCSPResponse_t*)asn_decode_ba_with_alloc(get_OCSPResponse_desc(), baEncoded);
    if (!ocsp_resp) return RET_UAPKI_OCSP_RESPONSE_INVALID;

    int ret = RET_OK;
    BasicOCSPResponse_t* basic_ocspresp = nullptr;
    uint32_t status = 0;
    DO(Util::enumeratedFromAsn1(&ocsp_resp->responseStatus, &status));

    m_ResponseStatus = static_cast<ResponseStatus>(status);
    if (m_ResponseStatus == ResponseStatus::SUCCESSFUL) {
        ResponseBytes_t* resp_bytes = ocsp_resp->responseBytes;
        if (!resp_bytes || (!OID_is_equal_oid(&resp_bytes->responseType, OID_PKIX_OcspBasic))) {
            SET_ERROR(RET_UAPKI_OCSP_RESPONSE_INVALID);
        }

        basic_ocspresp = (BasicOCSPResponse_t*)asn_decode_with_alloc(
            get_BasicOCSPResponse_desc(), resp_bytes->response.buf, resp_bytes->response.size);
        if (!basic_ocspresp) {
            SET_ERROR(RET_UAPKI_OCSP_RESPONSE_INVALID);
        }

        m_BaBasicOcspResponse = ba_alloc_from_uint8(resp_bytes->response.buf, (size_t)resp_bytes->response.size);
        if (!m_BaBasicOcspResponse) {
            SET_ERROR(RET_UAPKI_OCSP_RESPONSE_INVALID);
        }

        DO(asn_encode_ba(get_ResponseData_desc(), &basic_ocspresp->tbsResponseData, &m_BaTbsResponseData));

        m_BasicOcspResp = basic_ocspresp;
        basic_ocspresp = nullptr;
    }

cleanup:
    asn_free(get_BasicOCSPResponse_desc(), basic_ocspresp);
    asn_free(get_OCSPResponse_desc(), ocsp_resp);
    return ret;
}

int OcspHelper::encodeTbsRequest (void)
{
    if (!m_OcspRequest) return RET_UAPKI_INVALID_PARAMETER;

    return asn_encode_ba(get_TBSRequest_desc(), &m_OcspRequest->tbsRequest, &m_BaTbsRequestEncoded);
}

int OcspHelper::setSignature (
        const UapkiNS::AlgorithmIdentifier& aidSignature,
        const ByteArray* baSignValue,
        const vector<ByteArray*>& certs
)
{
    int ret = RET_OK;
    Certificate_t* cert = nullptr;
    Signature_t* sign = nullptr;

    if (!m_OcspRequest || !aidSignature.isPresent() || !baSignValue) return RET_UAPKI_INVALID_PARAMETER;

    ASN_ALLOC_TYPE(sign, Signature_t);

    //  =signatureAlgorithm=
    DO(Util::algorithmIdentifierToAsn1(sign->signatureAlgorithm, aidSignature));

    //  =signature=
    DO(asn_ba2BITSTRING(baSignValue, &sign->signature));

    //  =certs= (optional)
    if (!certs.empty() && !sign->certs) {
        ASN_ALLOC_TYPE(sign->certs, Certificates_t);
    }
    for (const auto& it : certs) {
        CHECK_NOT_NULL(cert = (Certificate_t*)asn_decode_ba_with_alloc(get_Certificate_desc(), it));
        DO(ASN_SEQUENCE_ADD(&sign->certs->list, cert));
        cert = nullptr;
    }

    m_OcspRequest->optionalSignature = sign;
    sign = nullptr;

cleanup:
    asn_free(get_Certificate_desc(), cert);
    asn_free(get_Signature_desc(), sign);
    return ret;
}

int OcspHelper::encodeRequest (void)
{
    if (!m_OcspRequest || (m_OcspRequest->tbsRequest.requestList.list.count <= 0)) return RET_UAPKI_INVALID_PARAMETER;

    return asn_encode_ba(get_OCSPRequest_desc(), m_OcspRequest, &m_BaRequestEncoded);
}

ByteArray* OcspHelper::getRequestEncoded (
        const bool move
)
{
    ByteArray* rv_ba = m_BaRequestEncoded;
    if (move) {
        m_BaRequestEncoded = nullptr;
    }
    return rv_ba;
}

int OcspHelper::parseBasicOcspResponse (
        const ByteArray* baEncoded
)
{
    int ret = RET_OK;

    if (!baEncoded) return RET_UAPKI_INVALID_PARAMETER;

    CHECK_NOT_NULL(m_BasicOcspResp = (BasicOCSPResponse_t*)asn_decode_ba_with_alloc(get_BasicOCSPResponse_desc(), baEncoded));

    DO(asn_encode_ba(get_ResponseData_desc(), &m_BasicOcspResp->tbsResponseData, &m_BaTbsResponseData));

    DO(Util::genTimeFromAsn1(&m_BasicOcspResp->tbsResponseData.producedAt, m_ProducedAt));

cleanup:
    return ret;
}

int OcspHelper::parseResponse (
        const ByteArray* baEncoded
)
{
    int ret = RET_OK;

    DO(parseOcspResponse(baEncoded));

    if (m_ResponseStatus == ResponseStatus::SUCCESSFUL) {
        DO(Util::genTimeFromAsn1(&m_BasicOcspResp->tbsResponseData.producedAt, m_ProducedAt));
    }

cleanup:
    return ret;
}

int OcspHelper::checkNonce (void)
{
    if (!m_BaNonce) return RET_OK;
    if (!m_BasicOcspResp) return RET_UAPKI_INVALID_PARAMETER;

    UapkiNS::SmartBA sba_nonce;
    int ret = ExtensionHelper::getOcspNonce(m_BasicOcspResp->tbsResponseData.responseExtensions, &sba_nonce);
    if (ret == RET_OK) {
        DO(ba_cmp(m_BaNonce, sba_nonce.get()));
    }

cleanup:
    ret = (ret == RET_OK) ? RET_OK : RET_UAPKI_OCSP_RESPONSE_INVALID_NONCE;
    return ret;
}

ByteArray* OcspHelper::getBasicOcspResponseEncoded (
        const bool move
)
{
    ByteArray* rv_ba = m_BaBasicOcspResponse;
    if (move) {
        m_BaBasicOcspResponse = nullptr;
    }
    return rv_ba;
}

int OcspHelper::getCerts (
        vector<ByteArray*>& certs
)
{
    int ret = RET_OK;
    ByteArray* ba_cert = nullptr;

    if (!m_BasicOcspResp) return RET_UAPKI_INVALID_PARAMETER;

    if (m_BasicOcspResp->certs != nullptr) {
        const Certificates* resp_certs = m_BasicOcspResp->certs;
        if (resp_certs->list.size == 0) {
            SET_ERROR(RET_UAPKI_INVALID_STRUCT);
        }
        for (int i = 0; i < resp_certs->list.count; i++) {
            DO(asn_encode_ba(get_Certificate_desc(), resp_certs->list.array[i], &ba_cert));
            certs.push_back(ba_cert);
            ba_cert = nullptr;
        }
    }

cleanup:
    ba_free(ba_cert);
    return ret;
}

int OcspHelper::getOcspIdentifier (
        ByteArray** baOcspIdentifier
)
{
    int ret = RET_OK;
    OcspIdentifier_t* ocsp_identifier = nullptr;

    if (!m_BasicOcspResp || !baOcspIdentifier) return RET_UAPKI_INVALID_PARAMETER;

    const ResponseData_t* response_data = &m_BasicOcspResp->tbsResponseData;

    ASN_ALLOC_TYPE(ocsp_identifier, OcspIdentifier_t);

    //  =ocspResponderID=
    DO(asn_copy(get_ResponderID_desc(), &response_data->responderID, &ocsp_identifier->ocspResponderID));

    //  =producedAt=
    DO(asn_copy(get_GeneralizedTime_desc(), &response_data->producedAt, &ocsp_identifier->producedAt));

    DO(asn_encode_ba(get_OcspIdentifier_desc(), ocsp_identifier, baOcspIdentifier));

cleanup:
    asn_free(get_OcspIdentifier_desc(), ocsp_identifier);
    return ret;
}

const OcspHelper::SingleResponseInfo& OcspHelper::getSingleResponseInfo (
        const size_t index
) const
{
    if (index >= m_SingleResponseInfos.size()) return singleresponseinfo_empty;

    return m_SingleResponseInfos[index];
}

int OcspHelper::getResponderId (
        ResponderIdType& responderIdType,
        ByteArray** baResponderId
)
{
    int ret = RET_OK;

    responderIdType = ResponderIdType::UNDEFINED;
    if (!m_BasicOcspResp) return RET_UAPKI_INVALID_PARAMETER;

    const ResponderID_t* responder_id = &m_BasicOcspResp->tbsResponseData.responderID;
    switch (responder_id->present) {
    case ResponderID_PR_byName:
        DO(asn_encode_ba(get_Name_desc(), &responder_id->choice.byName, baResponderId));
        responderIdType = ResponderIdType::BY_NAME;
        break;
    case ResponderID_PR_byKey:
        DO(asn_OCTSTRING2ba(&responder_id->choice.byKey, baResponderId));
        responderIdType = ResponderIdType::BY_KEY;
        break;
    default:
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

cleanup:
    return ret;
}

int OcspHelper::getSerialNumberFromCertId (
        const size_t index,
        ByteArray** baSerialNumber
)
{
    if (!m_BasicOcspResp) return RET_UAPKI_INVALID_PARAMETER;

    const ResponseData_t* tbs_respdata = &m_BasicOcspResp->tbsResponseData;
    if (index >= (size_t)tbs_respdata->responses.list.count) return RET_UAPKI_INVALID_PARAMETER;

    const SingleResponse_t* resp = tbs_respdata->responses.list.array[index];
    return asn_INTEGER2ba(&resp->certID.serialNumber, baSerialNumber);
}

int OcspHelper::scanSingleResponses (void)
{
    int ret = RET_OK;
    const TBSRequest_t* tbs_req = nullptr;
    const ResponseData_t* tbs_respdata = nullptr;
    const RevokedInfo_t* revoked_info = nullptr;

    if (!m_BasicOcspResp) return RET_UAPKI_INVALID_PARAMETER;

    tbs_respdata = &m_BasicOcspResp->tbsResponseData;
    const int cnt_responses = tbs_respdata->responses.list.count;
    if (cnt_responses <= 0) return RET_UAPKI_INVALID_COUNT_ITEMS;

    m_SingleResponseInfos.resize((size_t)cnt_responses);
    if (m_OcspRequest) {
        tbs_req = &m_OcspRequest->tbsRequest;
        if (tbs_req->requestList.list.count != cnt_responses) {
            SET_ERROR(RET_UAPKI_OCSP_RESPONSE_INVALID);
        }
    }

    for (size_t i = 0; i < m_SingleResponseInfos.size(); i++) {
        const SingleResponse_t* resp = tbs_respdata->responses.list.array[i];
        SingleResponseInfo& ocsp_item = m_SingleResponseInfos[i];
        uint32_t crl_reason = 0;

        if (m_OcspRequest) {
            const CertID_t& req_certid = tbs_req->requestList.list.array[i]->reqCert;
            if (
                !Util::equalValuePrimitiveType(req_certid.hashAlgorithm.algorithm, resp->certID.hashAlgorithm.algorithm) ||
                !Util::equalValueOctetString(req_certid.issuerNameHash, resp->certID.issuerNameHash) ||
                !Util::equalValueOctetString(req_certid.issuerKeyHash, resp->certID.issuerKeyHash) ||
                !Util::equalValuePrimitiveType(req_certid.serialNumber, resp->certID.serialNumber)
            ) {
                SET_ERROR(RET_UAPKI_OCSP_RESPONSE_INVALID);
            }
        }

        switch (resp->certStatus.present) {
        case CertStatus_PR_good:
            ocsp_item.certStatus = UapkiNS::CertStatus::GOOD;
            break;
        case CertStatus_PR_revoked:
            ocsp_item.certStatus = UapkiNS::CertStatus::REVOKED;
            revoked_info = &resp->certStatus.choice.revoked;
            DO(Util::genTimeFromAsn1(&revoked_info->revocationTime, ocsp_item.msRevocationTime));
            if (revoked_info->revocationReason != nullptr) {
                DO(Util::enumeratedFromAsn1(revoked_info->revocationReason, &crl_reason));
                ocsp_item.revocationReason = (UapkiNS::CrlReason)crl_reason;
            }
            break;
        case CertStatus_PR_unknown:
            ocsp_item.certStatus = UapkiNS::CertStatus::UNKNOWN;
            break;
        default:
            SET_ERROR(RET_UAPKI_OCSP_RESPONSE_INVALID);
        }

        DO(Util::genTimeFromAsn1(&resp->thisUpdate, ocsp_item.msThisUpdate));
        if (resp->nextUpdate != nullptr) {
            DO(Util::genTimeFromAsn1(resp->nextUpdate, ocsp_item.msNextUpdate));
        }
    }

cleanup:
    return ret;
}

int OcspHelper::verifyTbsResponseData (
        const Cert::CerItem* cerResponder,
        SignatureVerifyStatus& statusSign
)
{
    int ret = RET_OK;
    ByteArray* ba_signature = nullptr;
    char* s_signalgo = nullptr;

    statusSign = SignatureVerifyStatus::UNDEFINED;
    if (!m_BasicOcspResp) return RET_UAPKI_INVALID_PARAMETER;

    DO(asn_oid_to_text(&m_BasicOcspResp->signatureAlgorithm.algorithm, &s_signalgo));

    if (cerResponder->getAlgoKeyId() == HASH_ALG_GOST34311) {
        DO(Util::bitStringEncapOctetFromAsn1(&m_BasicOcspResp->signature, &ba_signature));
    }
    else {
        DO(asn_BITSTRING2ba(&m_BasicOcspResp->signature, &ba_signature));
    }

    ret = Verify::verifySignature(s_signalgo, m_BaTbsResponseData, false, cerResponder->getSpki(), ba_signature);
    switch (ret) {
    case RET_OK:
        statusSign = SignatureVerifyStatus::VALID;
        break;
    case RET_VERIFY_FAILED:
        statusSign = SignatureVerifyStatus::INVALID;
        break;
    default:
        statusSign = SignatureVerifyStatus::FAILED;
    }

cleanup:
    ba_free(ba_signature);
    free(s_signalgo);
    return ret;
}

int generateOtherHash (
        const ByteArray* baOcspResponseEncoded,
        const UapkiNS::AlgorithmIdentifier& aidHash,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    OtherHash_t* other_hash = nullptr;
    UapkiNS::SmartBA sba_hashvalue;

    if (!baOcspResponseEncoded) return RET_UAPKI_INVALID_PARAMETER;

    const HashAlg hash_alg = aidHash.isPresent() ? hash_from_oid(aidHash.algorithm.c_str()) : HASH_ALG_SHA1;
    if (hash_alg == HashAlg::HASH_ALG_UNDEFINED) return RET_UAPKI_UNSUPPORTED_ALG;

    ASN_ALLOC_TYPE(other_hash, OtherHash_t);

    DO(::hash(hash_alg, baOcspResponseEncoded, &sba_hashvalue));

    if (hash_alg != HashAlg::HASH_ALG_SHA1) {
        other_hash->present = OtherHash_PR_otherHash;
        DO(Util::algorithmIdentifierToAsn1(other_hash->choice.otherHash.hashAlgorithm, aidHash));
        DO(asn_ba2OCTSTRING(sba_hashvalue.get(), &other_hash->choice.otherHash.hashValue));
    }
    else {
        other_hash->present = OtherHash_PR_sha1Hash;
        DO(asn_ba2OCTSTRING(sba_hashvalue.get(), &other_hash->choice.sha1Hash));
    }

    DO(asn_encode_ba(get_OtherHash_desc(), other_hash, baEncoded));

cleanup:
    asn_free(get_OtherHash_desc(), other_hash);
    return ret;
}


const char* responseStatusToStr (
        const ResponseStatus status
)
{
    int32_t idx = (int32_t)status + 1;
    return RESPONSE_STATUS_STRINGS[(idx < 8) ? idx : 0];
}


}   //  end namespace Ocsp

}   //  end namespace UapkiNS
