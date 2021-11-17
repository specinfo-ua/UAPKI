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

#include "api-json-internal.h"
#include "asn1-ba-utils.h"
#include "common.h"
#include "global-objects.h"
#include "http-helper.h"
#include "ocsp-helper.h"
#include "ocsp-utils.h"
#include "parson-helper.h"
#include "store-utils.h"
#include "time-utils.h"
#include "uapki-errors.h"
#include "verify-signer-info.h"
#include "verify-status.h"
#include "verify-utils.h"


#undef FILE_MARKER
#define FILE_MARKER "api/verify-cert.c"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


static int check_signature_to_json (JSON_Object* joResult, const CerStore::Item* cerIssuer, const CerStore::Item* cerSubject)
{
    int ret = RET_OK;
    bool is_digitalsign = false;
    CERTIFICATE_VERIFY::STATUS status = CERTIFICATE_VERIFY::STATUS::UNDEFINED;

    ret = CerStoreUtils::verify(cerSubject, cerIssuer);
    status = (ret == RET_OK) ? CERTIFICATE_VERIFY::STATUS::VALID
        : ((ret == RET_VERIFY_FAILED) ? CERTIFICATE_VERIFY::STATUS::INVALID : CERTIFICATE_VERIFY::STATUS::FAILED);
    if (status == CERTIFICATE_VERIFY::STATUS::VALID) {
        DO(cerIssuer->keyUsageByBit(KeyUsage_digitalSignature, is_digitalsign));
        status = (is_digitalsign) ? CERTIFICATE_VERIFY::STATUS::VALID : CERTIFICATE_VERIFY::STATUS::VALID_WITHOUT_KEYUSAGE;
    }

    DO_JSON(json_object_set_string(joResult, "statusSignature", CERTIFICATE_VERIFY::toStr(status)));

cleanup:
    return ret;
}

static bool check_validity_time (const CerStore::Item* cerIssuer, const CerStore::Item* cerSubject, const uint64_t validateTime)
{
    const bool issuer_is_expired = (cerIssuer->checkValidity(validateTime) != RET_OK);
    const bool subject_is_expired = (cerSubject->checkValidity(validateTime) != RET_OK);
    return (issuer_is_expired || subject_is_expired);
}

static int process_crl (JSON_Object* joResult, const CerStore::Item* cerIssuer, const CerStore::Item* cerSubject, CrlStore& crlStore,
        const ByteArray** baCrlNumber, const uint64_t validateTime, vector<const CrlStore::RevokedCertItem*>& revokedItems)
{
    int ret = RET_OK;
    const CrlStore::CrlType crl_type = (*baCrlNumber == nullptr) ? CrlStore::CrlType::FULL : CrlStore::CrlType::DELTA;
    CrlStore::Item* crl = nullptr;
    ByteArray* ba_crl = nullptr;
    char* s_url = nullptr;

    ret = (crl_type == CrlStore::CrlType::FULL) ? cerSubject->getCrlFull(&s_url) : cerSubject->getCrlDelta(&s_url);
    if ((ret != RET_OK) && (ret != RET_UAPKI_EXTENSION_NOT_PRESENT)) {
        SET_ERROR(ret);
    }

    if (s_url) {
        DO_JSON(json_object_set_string(joResult, "url", s_url));
    }

    crl = crlStore.getCrl(cerIssuer->baKeyId, crl_type);
    if (crl) {
        if (crl->nextUpdate < validateTime) {
            DEBUG_OUTCON(puts("process_crl(), Need get newest CRL"));
            crl = nullptr;
        }
    }
    
    if (!crl) {
        if (!s_url) {
            SET_ERROR(RET_UAPKI_CRL_URL_NOT_PRESENT);
        }

        DEBUG_OUTCON(printf("process_crl(CrlType: %i), download CRL", crl_type));
        ret = HttpHelper::get(s_url, &ba_crl);
        if (ret != RET_OK) {
            SET_ERROR((ret == RET_UAPKI_OFFLINE_MODE) ? RET_UAPKI_OFFLINE_MODE : RET_UAPKI_CRL_NOT_DOWNLOADED);
        }

        DEBUG_OUTCON(printf("process_crl(), url: '%s',  size: %d\n", s_url, (int)ba_get_len(ba_crl)));
        DEBUG_OUTCON(if (ba_get_len(ba_crl) < 1024) { ba_print(stdout, ba_crl); });

        bool is_unique;//a5
        DO(crlStore.addCrl(ba_crl, false, is_unique, nullptr));
        ba_crl = nullptr;

        crl = crlStore.getCrl(cerIssuer->baKeyId, crl_type);
        if (!crl) {
            SET_ERROR(RET_UAPKI_CRL_NOT_FOUND);
        }

        if (crl->nextUpdate < validateTime) {
            DEBUG_OUTCON(puts("process_crl(), Need get newest CRL. Again... stop it!"));
            SET_ERROR(RET_UAPKI_CRL_NOT_FOUND);
        }
    }

    //  Check CrlNumber and DeltaCrl
    if (!crl->baCrlNumber) {
        SET_ERROR(RET_UAPKI_CRL_NOT_FOUND);
    }
    if (crl_type == CrlStore::CrlType::FULL) {  
        *baCrlNumber = crl->baCrlNumber;
    }
    else {
        if (ba_cmp(*baCrlNumber, crl->baDeltaCrl) != RET_OK) {
            SET_ERROR(RET_UAPKI_CRL_NOT_FOUND);
        }
    }

    DO(json_object_set_base64(joResult, "crlId", crl->baCrlId));

    ret = crl->verify(cerIssuer);
    DO_JSON(json_object_set_string(joResult, "statusSignature", SIGNATURE_VERIFY::toStr(crl->statusSign)));
    if (ret != RET_OK) {
        SET_ERROR(ret);
    }

    DO(crl->revokedCerts(cerSubject, revokedItems));

cleanup:
    ba_free(ba_crl);
    ::free(s_url);
    return ret;
}

static int validate_by_crl (JSON_Object* joResult, const CerStore::Item* cerIssuer, const CerStore::Item* cerSubject, const uint64_t validateTime)
{
    int ret = RET_OK;
    CrlStore* crl_store = nullptr;
    const ByteArray* ba_crlnumber = nullptr;
    vector<const CrlStore::RevokedCertItem*> revoked_items;
    const CrlStore::RevokedCertItem* revcert_before = nullptr;
    CrlStore::CertStatus cert_status = CrlStore::CertStatus::UNDEFINED;
    const bool cfg_crldelta_enabled = true;

    DO_JSON(json_object_set_string(joResult, "status", CrlStore::certStatusToStr(cert_status)));

    crl_store = get_crlstore();
    if (!crl_store) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    DO_JSON(json_object_set_value(joResult, "full", json_value_init_object()));
    DO(process_crl(json_object_get_object(joResult, "full"), cerIssuer, cerSubject, *crl_store, &ba_crlnumber, validateTime, revoked_items));
    DEBUG_OUTCON(printf("validate_by_crl_to_json() ba_crlnumber: "); ba_print(stdout, ba_crlnumber));

    if (cfg_crldelta_enabled) {
        DO_JSON(json_object_set_value(joResult, "delta", json_value_init_object()));
        DO(process_crl(json_object_get_object(joResult, "delta"), cerIssuer, cerSubject, *crl_store, &ba_crlnumber, validateTime, revoked_items));
    }

    DEBUG_OUTCON(for (auto& it : revoked_items) {
        printf("[%lld] revocationDate: %lld  crlReason: %i  invalidityDate: %lld\n", it->index, it->revocationDate, it->crlReason, it->invalidityDate);
    });

    if (revoked_items.empty()) {
        cert_status = CrlStore::CertStatus::GOOD;
    }
    else {
        revcert_before = CrlStore::foundNearBefore(revoked_items, validateTime);
        if (revcert_before) {
            DEBUG_OUTCON(printf("revcert_before: [%lld]  revocationDate: %lld  crlReason: %i  invalidityDate: %lld\n",
                revcert_before->index, revcert_before->revocationDate, revcert_before->crlReason, revcert_before->invalidityDate));
            switch (revcert_before->crlReason)
            {
            case CrlStore::CrlReason::REMOVE_FROM_CRL:
                cert_status = CrlStore::CertStatus::GOOD;
                break;
            case CrlStore::CrlReason::UNDEFINED:
                cert_status = CrlStore::CertStatus::UNDEFINED;
                break;
            case CrlStore::CrlReason::UNSPECIFIED:
                cert_status = CrlStore::CertStatus::UNKNOWN;
                break;
            default:
                cert_status = CrlStore::CertStatus::REVOKED;
                break;
            }
            DO_JSON(json_object_set_string(joResult, "revocationReason", CrlStore::crlReasonToStr((CrlStore::CrlReason)revcert_before->crlReason)));
            const string s_time = TimeUtils::mstimeToFormat(revcert_before->getDate());
            DO_JSON(json_object_set_string(joResult, "revocationTime", s_time.c_str()));
        }
        else {
            cert_status = CrlStore::CertStatus::GOOD;
        }
    }

    DO_JSON(json_object_set_string(joResult, "status", CrlStore::certStatusToStr(cert_status)));

cleanup:
    for (auto& it : revoked_items) {
        delete it;
    }
    revoked_items.clear();
    return ret;
}

static int verify_response_data (JSON_Object* joResult, OcspClientHelper& ocspClient, CerStore& cerStore)
{
    int ret = RET_OK;
    vector<ByteArray*> certs;
    OcspClientHelper::ResponderIdType responder_idtype = OcspClientHelper::ResponderIdType::UNDEFINED;
    SIGNATURE_VERIFY::STATUS status_sign = SIGNATURE_VERIFY::STATUS::UNDEFINED;
    ByteArray* ba_keyid = nullptr;
    const CerStore::Item* cer_responder = nullptr;

    DO(ocspClient.getCerts(certs));
    for (auto& it : certs) {
        bool is_unique;
        DO(cerStore.addCert(it, false, false, false, is_unique, nullptr));
        it = nullptr;
    }

    DO(ocspClient.getResponderId(responder_idtype, &ba_keyid));
    if (responder_idtype == OcspClientHelper::ResponderIdType::BY_KEY) {
        DO(cerStore.getCertByKeyId(ba_keyid, &cer_responder));
    }

    ret = ocspClient.verifyTbsResponseData(cer_responder, status_sign);
    if ((ret == RET_OK) && cer_responder) {
        DO_JSON(json_object_set_hex(joResult, "responderId", cer_responder->baKeyId));
    }
    DO_JSON(json_object_set_string(joResult, "statusSignature", SIGNATURE_VERIFY::toStr(status_sign)));
    if (ret == RET_VERIFY_FAILED) {
        SET_ERROR(RET_UAPKI_OCSP_VERIFY_RESPONSE_FAILED);
    }
    else if (ret != RET_OK) {
        SET_ERROR(RET_UAPKI_OCSP_VERIFY_RESPONSE_ERROR);
    }

cleanup:
    for (auto& it : certs) {
        ba_free(it);
    }
    ba_free(ba_keyid);
    return ret;
}

static int validate_by_ocsp (JSON_Object* joResult, const CerStore::Item* cerIssuer, const CerStore::Item* cerSubject, CerStore& cerStore)
{
    int ret = RET_OK;
    OcspClientHelper ocsp_client;
    OcspClientHelper::ResponseStatus resp_status = OcspClientHelper::ResponseStatus::UNDEFINED;
    const OcspClientHelper::OcspRecord* ocsp_record = nullptr;
    ByteArray* ba_req = nullptr;
    ByteArray* ba_resp = nullptr;
    char* s_url = nullptr;
    string s_time;

    DO_JSON(json_object_set_string(joResult, "status", CrlStore::certStatusToStr(CrlStore::CertStatus::UNDEFINED)));

    DO(cerSubject->getOcsp(&s_url));

    DO(ocsp_client.createRequest());
    DO(ocsp_client.addCert(cerIssuer, cerSubject));
    DO(ocsp_client.setNonce(20));
    DO(ocsp_client.encodeRequest(&ba_req));

    DEBUG_OUTCON(printf("OCSP-REQUEST, hex: "); ba_print(stdout, ba_req));

    ret = HttpHelper::post(s_url, HttpHelper::CONTENT_TYPE_OCSP_REQUEST, ba_req, &ba_resp);
    if (ret != RET_OK) {
        SET_ERROR(ret);
    }

    DEBUG_OUTCON(printf("OCSP-RESPONSE, hex: "); ba_print(stdout, ba_resp));

    ret = ocsp_client.parseResponse(ba_resp, resp_status);
    DO_JSON(json_object_set_string(joResult, "responseStatus", OcspClientHelper::responseStatusToStr(resp_status)));

    if ((ret == RET_OK) && (resp_status == OcspClientHelper::ResponseStatus::SUCCESSFUL)) {
        DO(verify_response_data(joResult, ocsp_client, cerStore));

        DO(ocsp_client.checkNonce());

        s_time = TimeUtils::mstimeToFormat(ocsp_client.getProducedAt());
        DO_JSON(json_object_set_string(joResult, "producedAt", s_time.c_str()));

        DO(ocsp_client.scanSingleResponses());
        ocsp_record = ocsp_client.getOcspRecord(0);
        if (ocsp_record) {
            DO_JSON(json_object_set_string(joResult, "status", CrlStore::certStatusToStr(ocsp_record->status)));
            s_time = TimeUtils::mstimeToFormat(ocsp_record->msThisUpdate);
            DO_JSON(json_object_set_string(joResult, "thisUpdate", s_time.c_str()));
            if (ocsp_record->msNextUpdate > 0) {
                s_time = TimeUtils::mstimeToFormat(ocsp_record->msNextUpdate);
                DO_JSON(json_object_set_string(joResult, "nextUpdate", s_time.c_str()));
            }
            if (ocsp_record->status == CrlStore::CertStatus::REVOKED) {
                DO_JSON(json_object_set_string(joResult, "revocationReason", CrlStore::crlReasonToStr(ocsp_record->revocationReason)));
                s_time = TimeUtils::mstimeToFormat(ocsp_record->msRevocationTime);
                DO_JSON(json_object_set_string(joResult, "revocationTime", s_time.c_str()));
            }
        }
    }

cleanup:
    if (ret == RET_UAPKI_CONNECTION_ERROR) {
        ret = RET_UAPKI_OCSP_NOT_RESPONDING;
    }
    ba_free(ba_req);
    ba_free(ba_resp);
    ::free(s_url);
    return ret;
}


int uapki_verify_cert (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    CerStore* cer_store = nullptr;
    CerStore::Item* cer_parsed = nullptr;
    ByteArray* ba_certid = nullptr;
    ByteArray* ba_encoded = nullptr;
    const CerStore::Item* cer_issuer = nullptr;
    const CerStore::Item* cer_subject = nullptr;
    string s_validatetime, s_validationtype;
    bool is_expired = false, is_selfsigned = false;
    uint64_t validate_time = 0;

    s_validationtype = ParsonHelper::jsonObjectGetString(joParams, "validationType");
    if (!s_validationtype.empty() && (s_validationtype != "OCSP") && (s_validationtype != "CRL")) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    cer_store = get_cerstore();
    if (!cer_store) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    ba_encoded = json_object_get_base64(joParams, "bytes");
    if (ba_encoded) {
        DO(CerStore::parseCert(ba_encoded, &cer_parsed));
        ba_encoded = nullptr;
        cer_subject = (const CerStore::Item*)cer_parsed;
    }
    else {
        ba_certid = json_object_get_base64(joParams, "certId");
        if (ba_certid) {
            DO(cer_store->getCertByCertId(ba_certid, &cer_subject));
        }
        else {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
    }

    s_validatetime = ParsonHelper::jsonObjectGetString(joParams, "validateTime");
    if (!s_validatetime.empty()) {
        DO(TimeUtils::stimeToMstime(s_validatetime.c_str(), validate_time));
    }
    else {
        validate_time = TimeUtils::nowMsTime();
    }
    s_validatetime = TimeUtils::mstimeToFormat(validate_time);
    DO_JSON(json_object_set_string(joResult, "validateTime", s_validatetime.c_str()));

    DO(json_object_set_base64(joResult, "subjectCertId", cer_subject->baCertId));
    DO(CerStoreUtils::validityToJson(joResult, cer_subject));

    DO(cer_store->getIssuerCert(cer_subject, &cer_issuer, is_selfsigned));
    is_expired = check_validity_time(cer_issuer, cer_subject, validate_time);
    DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "expired", is_expired));
    DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "selfSigned", is_selfsigned));
    DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "trusted", cer_subject->trusted));
    DO(check_signature_to_json(joResult, cer_issuer, cer_subject));

    if (!is_selfsigned) {
        DO(json_object_set_base64(joResult, "issuerCertId", cer_issuer->baCertId));
    }
 
    if (!is_expired) {
        if ((s_validationtype == "OCSP")) {
            DO_JSON(json_object_set_value(joResult, "validateByOCSP", json_value_init_object()));
            JSON_Object* jo_ocsp = json_object_get_object(joResult, "validateByOCSP");
            DO(validate_by_ocsp(jo_ocsp, cer_issuer, cer_subject, *cer_store));
        }

        if ((s_validationtype == "CRL")) {
            DO_JSON(json_object_set_value(joResult, "validateByCRL", json_value_init_object()));
            JSON_Object* jo_crl = json_object_get_object(joResult, "validateByCRL");
            DO(validate_by_crl(jo_crl, cer_issuer, cer_subject, validate_time));
        }
    }

cleanup:
    delete cer_parsed;
    ba_free(ba_certid);
    ba_free(ba_encoded);
    return ret;
}
