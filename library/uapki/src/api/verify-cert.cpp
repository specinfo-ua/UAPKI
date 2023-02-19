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

#include "api-json-internal.h"
#include "asn1-ba-utils.h"
#include "global-objects.h"
#include "http-helper.h"
#include "ocsp-helper.h"
#include "parson-helper.h"
#include "store-utils.h"
#include "time-utils.h"
#include "uapki-errors.h"
#include "uapki-ns.h"
#include "verify-status.h"
#include "verify-utils.h"
#include "uapki-debug.h"


#undef FILE_MARKER
#define FILE_MARKER "api/verify-cert.cpp"

#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif

#define DEBUG_OUTPUT_OUTSTREAM(msg,baData)
#ifndef DEBUG_OUTPUT_OUTSTREAM
DEBUG_OUTPUT_OUTSTREAM_FUNC
#define DEBUG_OUTPUT_OUTSTREAM(msg,baData) debug_output_stream(DEBUG_OUTSTREAM_FOPEN,"VERIFY_CERT",msg,baData)
#endif


using namespace std;


static bool check_validity_time (const CerStore::Item* cerIssuer, const CerStore::Item* cerSubject, const uint64_t validateTime)
{
    const bool issuer_is_expired = (cerIssuer->checkValidity(validateTime) != RET_OK);
    const bool subject_is_expired = (cerSubject->checkValidity(validateTime) != RET_OK);
    return (issuer_is_expired || subject_is_expired);
}

static int process_crl (JSON_Object* joResult, const CerStore::Item* cerIssuer, const CerStore::Item* cerSubject, CrlStore& crlStore,
                    const ByteArray** baCrlNumber, const uint64_t validateTime, CrlStore::Item** crlItem)
{
    int ret = RET_OK;
    const CrlStore::CrlType crl_type = (*baCrlNumber == nullptr) ? CrlStore::CrlType::FULL : CrlStore::CrlType::DELTA;
    CrlStore::Item* crl = nullptr;
    UapkiNS::SmartBA sba_crl;
    vector<string> uris;

    ret = cerSubject->getCrlUris((crl_type == CrlStore::CrlType::FULL), uris);
    if ((ret != RET_OK) && (ret != RET_UAPKI_EXTENSION_NOT_PRESENT)) {
        SET_ERROR(ret);
    }

    if (!uris.empty()) {
        DO_JSON(json_object_set_string(joResult, "url", uris[0].c_str()));//TODO: need added support array uris
    }

    crl = crlStore.getCrl(cerIssuer->baKeyId, crl_type);
    if (crl) {
        if (crl->nextUpdate < validateTime) {
            DEBUG_OUTCON(puts("process_crl(), Need get newest CRL"));
            crl = nullptr;
        }
    }

    if (!crl) {
        if (HttpHelper::isOfflineMode()) {
            SET_ERROR(RET_UAPKI_OFFLINE_MODE);
        }
        if (uris.empty()) {
            SET_ERROR(RET_UAPKI_CRL_URL_NOT_PRESENT);
        }

        const vector<string> shuffled_uris = HttpHelper::randomURIs(uris);
        DEBUG_OUTCON(printf("process_crl(CrlType: %d), download CRL", crl_type));
        for (auto& it : shuffled_uris) {
            DEBUG_OUTCON(printf("process_crl(), HttpHelper::get('%s')\n", it.c_str()));
            ret = HttpHelper::get(it.c_str(), &sba_crl);
            if (ret == RET_OK) {
                DEBUG_OUTCON(printf("process_crl(), url: '%s', size: %zu\n", it.c_str(), sba_crl.size()));
                DEBUG_OUTCON(if (sba_crl.size() < 1024) { ba_print(stdout, sba_crl.get()); });
                break;
            }
        }
        if (ret != RET_OK) {
            SET_ERROR(RET_UAPKI_CRL_NOT_DOWNLOADED);
        }

        bool is_unique;
        DO(crlStore.addCrl(sba_crl.get(), true, is_unique, nullptr));
        sba_crl.set(nullptr);

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
    DO_JSON(json_object_set_string(joResult, "statusSignature", CerStore::verifyStatusToStr(crl->statusSign)));
    if (ret != RET_OK) {
        SET_ERROR(ret);
    }

    *crlItem = crl;

cleanup:
    return ret;
}

static int validate_by_crl (JSON_Object* joResult, const CerStore::Item* cerIssuer,
                    CerStore::Item* cerSubject, const uint64_t validateTime, const bool needUpdateCert)
{
    int ret = RET_OK;
    CrlStore* crl_store = nullptr;
    CrlStore::Item* crl_item = nullptr;
    vector<const CrlStore::RevokedCertItem*> revoked_items;
    const CrlStore::RevokedCertItem* revcert_before = nullptr;
    const ByteArray* ba_crlnumber = nullptr;
    UapkiNS::CertStatus cert_status = UapkiNS::CertStatus::UNDEFINED;
    const bool cfg_crldelta_enabled = true;

    DO_JSON(json_object_set_string(joResult, "status", CrlStore::certStatusToStr(cert_status)));

    crl_store = get_crlstore();
    if (!crl_store) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    DO_JSON(json_object_set_value(joResult, "full", json_value_init_object()));
    DO(process_crl(json_object_get_object(joResult, "full"), cerIssuer, cerSubject, *crl_store, &ba_crlnumber, validateTime, &crl_item));
    DEBUG_OUTCON(printf("validate_by_crl() ba_crlnumber: "); ba_print(stdout, ba_crlnumber));
    DO(crl_item->revokedCerts(cerSubject, revoked_items));

    if (cfg_crldelta_enabled) {
        DO_JSON(json_object_set_value(joResult, "delta", json_value_init_object()));
        DO(process_crl(json_object_get_object(joResult, "delta"), cerIssuer, cerSubject, *crl_store, &ba_crlnumber, validateTime, &crl_item));
        DO(crl_item->revokedCerts(cerSubject, revoked_items));
    }

    DEBUG_OUTCON(for (auto& it : revoked_items) {
        printf("[%lld] revocationDate: %lld  crlReason: %i  invalidityDate: %lld\n", it->index, it->revocationDate, it->crlReason, it->invalidityDate);
    });

    if (revoked_items.empty()) {
        cert_status = UapkiNS::CertStatus::GOOD;
    }
    else {
        revcert_before = CrlStore::foundNearBefore(revoked_items, validateTime);
        if (revcert_before) {
            DEBUG_OUTCON(printf("revcert_before: [%lld]  revocationDate: %lld  crlReason: %i  invalidityDate: %lld\n",
                revcert_before->index, revcert_before->revocationDate, revcert_before->crlReason, revcert_before->invalidityDate));
            switch (revcert_before->crlReason)
            {
            case UapkiNS::CrlReason::REMOVE_FROM_CRL:
                cert_status = UapkiNS::CertStatus::GOOD;
                break;
            case UapkiNS::CrlReason::UNDEFINED:
                cert_status = UapkiNS::CertStatus::UNDEFINED;
                break;
            case UapkiNS::CrlReason::UNSPECIFIED:
                cert_status = UapkiNS::CertStatus::UNKNOWN;
                break;
            default:
                cert_status = UapkiNS::CertStatus::REVOKED;
                break;
            }
            DO_JSON(json_object_set_string(joResult, "revocationReason", CrlStore::crlReasonToStr((UapkiNS::CrlReason)revcert_before->crlReason)));
            const string s_time = TimeUtils::mstimeToFormat(revcert_before->getDate());
            DO_JSON(json_object_set_string(joResult, "revocationTime", s_time.c_str()));
        }
        else {
            cert_status = UapkiNS::CertStatus::GOOD;
        }
    }

    DO_JSON(json_object_set_string(joResult, "status", CrlStore::certStatusToStr(cert_status)));

    if (needUpdateCert) {
        cerSubject->certStatusByCrl.set(
            cert_status,
            crl_item->nextUpdate,
            crl_item->baCrlId
        );
    }

cleanup:
    for (auto& it : revoked_items) {
        delete it;
    }
    revoked_items.clear();
    return ret;
}

static int responderid_to_json (JSON_Object* joResult, const UapkiNS::Ocsp::ResponderIdType responderIdType, const ByteArray* baResponderId)
{
    int ret = RET_OK;
    Name_t* name = nullptr;

    switch (responderIdType) {
    case UapkiNS::Ocsp::ResponderIdType::BY_NAME:
        CHECK_NOT_NULL(name = (Name_t*)asn_decode_ba_with_alloc(get_Name_desc(), baResponderId));
        DO_JSON(json_object_set_value(joResult, "responderId", json_value_init_object()));
        DO(CerStoreUtils::nameToJson(json_object_get_object(joResult, "responderId"), *name));
        break;
    case UapkiNS::Ocsp::ResponderIdType::BY_KEY:
        DO(json_object_set_hex(joResult, "responderId", baResponderId));
        break;
    default:
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

cleanup:
    asn_free(get_Name_desc(), name);
    return ret;
}

static int verify_cert_sign (const CerStore::Item* cerIssuer, CerStore::Item* cerSubject)
{
    int ret = RET_OK;
    bool is_digitalsign = false;
    CerStore::VerifyStatus status = CerStore::VerifyStatus::UNDEFINED;

    ret = CerStoreUtils::verify(cerSubject, cerIssuer);
    status = (ret == RET_OK) ? CerStore::VerifyStatus::VALID
        : ((ret == RET_VERIFY_FAILED) ? CerStore::VerifyStatus::INVALID : CerStore::VerifyStatus::FAILED);
    if (status == CerStore::VerifyStatus::VALID) {
        DO(cerIssuer->keyUsageByBit(KeyUsage_keyCertSign, is_digitalsign));
        status = (is_digitalsign) ? CerStore::VerifyStatus::VALID : CerStore::VerifyStatus::VALID_WITHOUT_KEYUSAGE;
    }

    cerSubject->verifyStatus = status;

cleanup:
    return ret;
}

static int verify_response_data (JSON_Object* joResult, UapkiNS::Ocsp::OcspHelper& ocspClient, CerStore& cerStore)
{
    int ret = RET_OK;
    UapkiNS::SmartBA sba_responderid;
    UapkiNS::VectorBA vba_certs;
    UapkiNS::Ocsp::ResponderIdType responder_idtype = UapkiNS::Ocsp::ResponderIdType::UNDEFINED;
    UapkiNS::SignatureVerifyStatus status_sign = UapkiNS::SignatureVerifyStatus::UNDEFINED;
    CerStore::Item* cer_responder = nullptr;

    DO(ocspClient.getCerts(vba_certs));
    for (auto& it : vba_certs) {
        bool is_unique;
        DO(cerStore.addCert(it, false, false, false, is_unique, nullptr));
        it = nullptr;
    }

    DO(ocspClient.getResponderId(responder_idtype, &sba_responderid));
    DO(responderid_to_json(joResult, responder_idtype, sba_responderid.get()));
    if (responder_idtype == UapkiNS::Ocsp::ResponderIdType::BY_NAME) {
        DO(cerStore.getCertBySubject(sba_responderid.get(), &cer_responder));
    }
    else {
        //  responder_idtype == OcspHelper::ResponderIdType::BY_KEY
        DO(cerStore.getCertByKeyId(sba_responderid.get(), &cer_responder));
    }

    ret = ocspClient.verifyTbsResponseData(cer_responder, status_sign);
    DO_JSON(json_object_set_string(joResult, "statusSignature", UapkiNS::verifyStatusToStr(status_sign)));
    if (ret == RET_VERIFY_FAILED) {
        SET_ERROR(RET_UAPKI_OCSP_RESPONSE_VERIFY_FAILED);
    }
    else if (ret != RET_OK) {
        SET_ERROR(RET_UAPKI_OCSP_RESPONSE_VERIFY_ERROR);
    }

cleanup:
    return ret;
}

static int validate_by_ocsp (JSON_Object* joResult, const CerStore::Item* cerIssuer, CerStore::Item* cerSubject, CerStore& cerStore)
{
    int ret = RET_OK;
    const LibraryConfig::OcspParams& ocsp_params = get_config()->getOcsp();
    UapkiNS::Ocsp::OcspHelper ocsp_helper;
    UapkiNS::SmartBA sba_resp;
    vector<string> shuffled_uris, uris;
    bool need_update;
    string s_time;

    DO_JSON(json_object_set_string(joResult, "status", CrlStore::certStatusToStr(UapkiNS::CertStatus::UNDEFINED)));

    if (HttpHelper::isOfflineMode()) {
        SET_ERROR(RET_UAPKI_OFFLINE_MODE);
    }

    ret = cerSubject->getOcspUris(uris);
    if ((ret != RET_OK) && (ret != RET_UAPKI_EXTENSION_NOT_PRESENT)) {
        SET_ERROR(RET_UAPKI_OCSP_URL_NOT_PRESENT);
    }

    need_update = cerSubject->certStatusByOcsp.isExpired(TimeUtils::nowMsTime());
    if (need_update) {
        DO(ocsp_helper.init());
        DO(ocsp_helper.addCert(cerIssuer, cerSubject));
        if (ocsp_params.nonceLen > 0) {
            DO(ocsp_helper.genNonce(ocsp_params.nonceLen));
        }
        DO(ocsp_helper.encodeRequest());

        shuffled_uris = HttpHelper::randomURIs(uris);
        for (auto& it : shuffled_uris) {
            DEBUG_OUTPUT_OUTSTREAM(string("OCSP-request, url=") + it, ocsp_helper.getRequestEncoded());
            ret = HttpHelper::post(
                it.c_str(),
                HttpHelper::CONTENT_TYPE_OCSP_REQUEST,
                ocsp_helper.getRequestEncoded(),
                &sba_resp
            );
            DEBUG_OUTPUT_OUTSTREAM(string("OCSP-response, url=") + it, sba_resp.get());
            if (ret == RET_OK) {
                DEBUG_OUTCON(printf("validate_by_ocsp(), url: '%s', size: %zu\n", it.c_str(), sba_resp.size()));
                DEBUG_OUTCON(if (sba_resp.size() < 1024) { ba_print(stdout, sba_resp.get()); });
                break;
            }
        }
        if (ret != RET_OK) {
            SET_ERROR(ret);
        }
        else if (sba_resp.size() == 0) {
            SET_ERROR(RET_UAPKI_OCSP_RESPONSE_INVALID);
        }
    }

    ret = ocsp_helper.parseResponse(need_update ? sba_resp.get() : cerSubject->certStatusByOcsp.baResult);
    DO_JSON(json_object_set_string(joResult, "responseStatus", UapkiNS::Ocsp::responseStatusToStr(ocsp_helper.getResponseStatus())));

    if ((ret == RET_OK) && (ocsp_helper.getResponseStatus() == UapkiNS::Ocsp::ResponseStatus::SUCCESSFUL)) {
        DO(verify_response_data(joResult, ocsp_helper, cerStore));
        DO(ocsp_helper.checkNonce());

        s_time = TimeUtils::mstimeToFormat(ocsp_helper.getProducedAt());
        DO_JSON(json_object_set_string(joResult, "producedAt", s_time.c_str()));

        DO(ocsp_helper.scanSingleResponses());

        const UapkiNS::Ocsp::OcspHelper::OcspRecord& ocsp_record = ocsp_helper.getOcspRecord(0); //  Work with one OCSP request that has one certificate
        DO_JSON(json_object_set_string(joResult, "status", CrlStore::certStatusToStr(ocsp_record.status)));
        s_time = TimeUtils::mstimeToFormat(ocsp_record.msThisUpdate);
        DO_JSON(json_object_set_string(joResult, "thisUpdate", s_time.c_str()));
        if (ocsp_record.msNextUpdate > 0) {
            s_time = TimeUtils::mstimeToFormat(ocsp_record.msNextUpdate);
            DO_JSON(json_object_set_string(joResult, "nextUpdate", s_time.c_str()));
        }
        if (ocsp_record.status == UapkiNS::CertStatus::REVOKED) {
            DO_JSON(json_object_set_string(joResult, "revocationReason", CrlStore::crlReasonToStr(ocsp_record.revocationReason)));
            s_time = TimeUtils::mstimeToFormat(ocsp_record.msRevocationTime);
            DO_JSON(json_object_set_string(joResult, "revocationTime", s_time.c_str()));
        }

        if (need_update) {
            DO(cerSubject->certStatusByOcsp.set(
                ocsp_record.status,
                ocsp_record.msThisUpdate + UapkiNS::Ocsp::OFFSET_EXPIRE_DEFAULT,
                sba_resp.get()
            ));
        }
    }

cleanup:
    return ret;
}


int uapki_verify_cert (JSON_Object* joParams, JSON_Object* joResult)
{
    CerStore* cer_store = get_cerstore();
    LibraryConfig* config = get_config();
    if (!cer_store || !config) return RET_UAPKI_GENERAL_ERROR;

    int ret = RET_OK;
    CerStore::Item* cer_issuer = nullptr;
    CerStore::Item* cer_parsed = nullptr;
    CerStore::Item* cer_subject = nullptr;
    ByteArray* ba_certid = nullptr;
    ByteArray* ba_encoded = nullptr;
    string s_validatetime;
    const CerStore::ValidationType validation_type = CerStore::validationTypeFromStr(
        ParsonHelper::jsonObjectGetString(joParams, "validationType")
    );
    bool is_expired = false, is_selfsigned = false, need_updatecert = false;
    uint64_t validate_time = 0;

    if (validation_type == CerStore::ValidationType::UNDEFINED) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    ba_encoded = json_object_get_base64(joParams, "bytes");
    if (ba_encoded) {
        DO(CerStore::parseCert(ba_encoded, &cer_parsed));
        ba_encoded = nullptr;
        cer_subject = cer_parsed;
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
    need_updatecert = s_validatetime.empty();
    if (need_updatecert || (validation_type == CerStore::ValidationType::OCSP)) {
        validate_time = TimeUtils::nowMsTime();
    }
    else {
        DO(TimeUtils::stimeToMstime(s_validatetime.c_str(), validate_time));
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
    if (cer_subject->verifyStatus == CerStore::VerifyStatus::UNDEFINED) {
        DO(verify_cert_sign(cer_issuer, cer_subject));
    }
    DO_JSON(json_object_set_string(joResult, "statusSignature", CerStore::verifyStatusToStr(cer_subject->verifyStatus)));

    if (!is_selfsigned) {
        DO(json_object_set_base64(joResult, "issuerCertId", cer_issuer->baCertId));
    }
 
    if (!is_expired) {
        JSON_Object* jo;
        if (validation_type == CerStore::ValidationType::CRL) {
            DO_JSON(json_object_set_value(joResult, "validateByCRL", json_value_init_object()));
            jo = json_object_get_object(joResult, "validateByCRL");
            DO(validate_by_crl(jo, cer_issuer, cer_subject, validate_time, need_updatecert));
        }
        else if (validation_type == CerStore::ValidationType::OCSP) {
            DO_JSON(json_object_set_value(joResult, "validateByOCSP", json_value_init_object()));
            jo = json_object_get_object(joResult, "validateByOCSP");
            DO(validate_by_ocsp(jo, cer_issuer, cer_subject, *cer_store));
        }
    }

cleanup:
    delete cer_parsed;
    ba_free(ba_certid);
    ba_free(ba_encoded);
    return ret;
}
