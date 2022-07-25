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

#include "ocsp-helper.h"
#include "asn1-ba-utils.h"
#include "extension-utils.h"
#include "macros-internal.h"
#include "oid-utils.h"
#include "uapkic.h"
#include "uapkif.h"
#include "uapki-errors.h"
#include "verify-utils.h"


static const size_t NONCE_MAXLEN = 64;

static const char* RESPONSE_STATUS_STRINGS[8] = {
    "UNDEFINED", "SUCCESSFUL", "MALFORMED_REQUEST", "INTERNAL_ERROR", "TRY_LATER",
    "", "SIG_REQUIRED", "UNAUTHORIZED"
};


static int certid_hashed_issuer (OCSPCertID& certId, const CerStore::Item* cerIssuer)
{
    int ret = RET_OK;
    ByteArray* ba_encoded = nullptr;

    DO(asn_encode_ba(get_Name_desc(), &cerIssuer->cert->tbsCertificate.subject, &ba_encoded));

    certId.hashAlgo = hash_to_oid(cerIssuer->algoKeyId);
    DO(::hash(cerIssuer->algoKeyId, ba_encoded, &certId.issuerNameHash));
    CHECK_NOT_NULL(certId.issuerKeyHash = ba_copy_with_alloc(cerIssuer->baKeyId, 0, 0));

cleanup:
    ba_free(ba_encoded);
    return ret;
}


OcspClientHelper::OcspClientHelper (void)
    : m_OcspRequest(nullptr), m_BasicOcspResp(nullptr)
    , m_Nonce(nullptr), m_ResponseData(nullptr), m_ProducedAt(0)
{
}

OcspClientHelper::~OcspClientHelper (void)
{
    reset();
}

void OcspClientHelper::reset (void)
{
    ocsp_request_free(m_OcspRequest);
    asn_free(get_BasicOCSPResponse_desc(), m_BasicOcspResp);
    ba_free(m_Nonce);
    ba_free(m_ResponseData);

    m_OcspRecords.clear();
    m_OcspRequest = nullptr;
    m_BasicOcspResp = nullptr;
    m_Nonce = nullptr;
    m_ResponseData = nullptr;
    m_ProducedAt = 0;
}

int OcspClientHelper::createRequest (void)
{
    int ret = RET_OK;

    CHECK_NOT_NULL(m_OcspRequest = ocsp_request_alloc());

cleanup:
    return ret;
}

int OcspClientHelper::addCert (const CerStore::Item* cerIssuer, const CerStore::Item* cerSubject)
{
    int ret = RET_OK;

    CHECK_PARAM(cerSubject != nullptr);

    DO(addSN(cerIssuer, cerSubject->baSerialNumber));

cleanup:
    return ret;
}

int OcspClientHelper::addSN (const CerStore::Item* cerIssuer, const ByteArray* baSerialNumber)
{
    int ret = RET_OK;
    OCSPCertID cert_id;

    memset(&cert_id, 0, sizeof(OCSPCertID));
    cert_id.hashAlgoParam_isNULL = false;

    CHECK_PARAM(m_OcspRequest != nullptr);
    CHECK_PARAM(cerIssuer != nullptr);
    CHECK_PARAM(baSerialNumber != nullptr);

    DO(certid_hashed_issuer(cert_id, cerIssuer));
    cert_id.serialNumber = (ByteArray*)baSerialNumber;

    DO(ocsp_request_add_certid(m_OcspRequest, &cert_id));
    m_OcspRecords.push_back(OcspRecord());

cleanup:
    ba_free(cert_id.issuerNameHash);
    ba_free(cert_id.issuerKeyHash);
    return ret;
}

int OcspClientHelper::setNonce (size_t nonceLen)
{
    int ret = RET_OK;
    ByteArray* ba_nonce = nullptr;

    CHECK_PARAM(m_OcspRequest != nullptr);

    nonceLen = (nonceLen < NONCE_MAXLEN) ? nonceLen : NONCE_MAXLEN;

    CHECK_NOT_NULL(ba_nonce = ba_alloc_by_len(nonceLen));
    DO(drbg_random(ba_nonce));
    DO(ocsp_request_set_nonce(m_OcspRequest, ba_nonce));

    m_Nonce = ba_nonce;
    ba_nonce = nullptr;

cleanup:
    ba_free(ba_nonce);
    return ret;
}

int OcspClientHelper::setNonce (const ByteArray* baNonce)
{
    int ret = RET_OK;

    CHECK_PARAM(m_OcspRequest != nullptr);
    CHECK_PARAM(baNonce != nullptr);

    DO(ocsp_request_set_nonce(m_OcspRequest, baNonce));

    CHECK_NOT_NULL(m_Nonce = ba_copy_with_alloc(baNonce, 0, 0));

cleanup:
    return ret;
}

int OcspClientHelper::encodeRequest (ByteArray** baEncoded)
{
    int ret = RET_OK;

    CHECK_PARAM(m_OcspRequest != nullptr);
    CHECK_PARAM(baEncoded != nullptr);
    CHECK_PARAM(m_OcspRecords.size() > 0);

    DO(asn_encode_ba(get_OCSPRequest_desc(), m_OcspRequest, baEncoded));

cleanup:
    return ret;
}

const OcspClientHelper::OcspRecord* OcspClientHelper::getOcspRecord (const size_t index) const
{
    const OcspRecord* rv_record = nullptr;
    if (index < m_OcspRecords.size()) {
        rv_record = &m_OcspRecords[index];
    }
    return rv_record;
}

int OcspClientHelper::parseResponse (const ByteArray* baEncoded, ResponseStatus& responseStatus)
{
    int ret = RET_OK;
    uint32_t status = (uint32_t)ResponseStatus::UNDEFINED;

    responseStatus = ResponseStatus::UNDEFINED;
    DO(ocsp_response_parse(baEncoded, &status, &m_BasicOcspResp, &m_ResponseData));

    responseStatus = (ResponseStatus)status;
    if (responseStatus == ResponseStatus::SUCCESSFUL) {
        DO(asn_decodevalue_gentime(&m_BasicOcspResp->tbsResponseData.producedAt, &m_ProducedAt));
    }

cleanup:
    return ret;
}

int OcspClientHelper::getCerts (vector<ByteArray*>& certs)
{
    int ret = RET_OK;
    ByteArray* ba_cert = nullptr;

    if (!m_BasicOcspResp) return RET_UAPKI_INVALID_PARAMETER;

    if (m_BasicOcspResp->certs != nullptr) {
        const Certificates* resp_certs = m_BasicOcspResp->certs;
        if (resp_certs->list.size == 0) {
            SET_ERROR(RET_UAPKI_INVALID_STRUCT);
        }
        for (size_t i = 0; i < resp_certs->list.count; i++) {
            DO(asn_encode_ba(get_Certificate_desc(), resp_certs->list.array[i], &ba_cert));
            certs.push_back(ba_cert);
            ba_cert = nullptr;
        }
    }

cleanup:
    ba_free(ba_cert);
    return ret;
}

int OcspClientHelper::getResponderId (ResponderIdType& responderIdType, ByteArray** baResponderId)
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

int OcspClientHelper::verifyTbsResponseData (const CerStore::Item* cerResponder, SIGNATURE_VERIFY::STATUS& statusSign)
{
    int ret = RET_OK;
    ByteArray* ba_signature = nullptr;
    char* s_signalgo = nullptr;

    statusSign = SIGNATURE_VERIFY::STATUS::UNDEFINED;
    if (!m_BasicOcspResp) return RET_UAPKI_INVALID_PARAMETER;

    DO(asn_oid_to_text(&m_BasicOcspResp->signatureAlgorithm.algorithm, &s_signalgo));

    if (cerResponder->algoKeyId == HASH_ALG_GOST34311) {
        DO(asn_decodevalue_bitstring_encap_octet(&m_BasicOcspResp->signature, &ba_signature));
    }
    else {
        DO(asn_BITSTRING2ba(&m_BasicOcspResp->signature, &ba_signature));
    }

    ret = verify_signature(s_signalgo, m_ResponseData, false, cerResponder->baSPKI, ba_signature);
    switch (ret) {
    case RET_OK:
        statusSign = SIGNATURE_VERIFY::STATUS::VALID;
        break;
    case RET_VERIFY_FAILED:
        statusSign = SIGNATURE_VERIFY::STATUS::INVALID;
        break;
    default:
        statusSign = SIGNATURE_VERIFY::STATUS::FAILED;
    }

cleanup:
    ba_free(ba_signature);
    free(s_signalgo);
    return ret;
}

int OcspClientHelper::checkNonce (void)
{
    int ret = RET_OK;
    ByteArray* ba_nonce = nullptr;

    if (m_Nonce == nullptr) return ret;

    CHECK_PARAM(m_BasicOcspResp != nullptr);

    ret = extns_get_ocsp_nonce(m_BasicOcspResp->tbsResponseData.responseExtensions, &ba_nonce);
    if (ret == RET_OK) {
        DO(ba_cmp(m_Nonce, ba_nonce));
    }

cleanup:
    ba_free(ba_nonce);
    ret = (ret == RET_OK) ? RET_OK : RET_UAPKI_OCSP_INVALID_NONCE;
    return ret;
}

int OcspClientHelper::scanSingleResponses (void)
{
    int ret = RET_OK;
    const TBSRequest_t* tbs_req = nullptr;
    const ResponseData_t* tbs_respdata = nullptr;
    const RevokedInfo_t* revoked_info = nullptr;
    uint32_t crl_reason = 0;

    CHECK_PARAM(m_OcspRequest != nullptr);
    CHECK_PARAM(m_BasicOcspResp != nullptr);

    tbs_req = &m_OcspRequest->tbsRequest;
    tbs_respdata = &m_BasicOcspResp->tbsResponseData;
    if ((m_OcspRecords.size() != (size_t)tbs_respdata->responses.list.count)
        || (tbs_req->requestList.list.count != tbs_respdata->responses.list.count)) {
        SET_ERROR(RET_UAPKI_OCSP_RESPONSE_INVALID_CONTENT);
    }

    for (size_t i = 0; i < m_OcspRecords.size(); i++) {
        OcspRecord& ocsp_item = m_OcspRecords[i];
        const CertID_t* req_certid = &tbs_req->requestList.list.array[i]->reqCert;
        const SingleResponse_t* resp = tbs_respdata->responses.list.array[i];
        if (!asn_primitive_data_is_equals(&req_certid->hashAlgorithm.algorithm, &resp->certID.hashAlgorithm.algorithm)
            || !asn_octetstring_data_is_equals(&req_certid->issuerNameHash, &resp->certID.issuerNameHash)
            || !asn_octetstring_data_is_equals(&req_certid->issuerKeyHash, &resp->certID.issuerKeyHash)
            || !asn_primitive_data_is_equals(&req_certid->serialNumber, &resp->certID.serialNumber)) {
            SET_ERROR(RET_UAPKI_OCSP_RESPONSE_INVALID_CONTENT);
        }

        switch (resp->certStatus.present) {
        case CertStatus_PR_good:
            ocsp_item.status = UapkiNS::CertStatus::GOOD;
            break;
        case CertStatus_PR_revoked:
            ocsp_item.status = UapkiNS::CertStatus::REVOKED;
            revoked_info = &resp->certStatus.choice.revoked;
            DO(asn_decodevalue_gentime(&revoked_info->revocationTime, &ocsp_item.msRevocationTime));
            if (revoked_info->revocationReason != nullptr) {
                DO(asn_decodevalue_enumerated(revoked_info->revocationReason, &crl_reason));
                ocsp_item.revocationReason = (UapkiNS::CrlReason)crl_reason;
            }
            break;
        case CertStatus_PR_unknown:
            ocsp_item.status = UapkiNS::CertStatus::UNKNOWN;
            break;
        default:
            SET_ERROR(RET_UAPKI_OCSP_RESPONSE_INVALID_CONTENT);
        }

        DO(asn_decodevalue_gentime(&resp->thisUpdate, &ocsp_item.msThisUpdate));
        if (resp->nextUpdate != nullptr) {
            DO(asn_decodevalue_gentime(resp->nextUpdate, &ocsp_item.msNextUpdate));
        }
    }

cleanup:
    return ret;
}

const char* OcspClientHelper::responseStatusToStr (const ResponseStatus status)
{
    int32_t idx = (int32_t)status + 1;
    return RESPONSE_STATUS_STRINGS[(idx < 8) ? idx : 0];
}

