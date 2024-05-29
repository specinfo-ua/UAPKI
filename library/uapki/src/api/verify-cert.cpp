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

#define FILE_MARKER "uapki/api/verify-cert.cpp"

#include "api-json-internal.h"
#include "cert-validator.h"
#include "global-objects.h"
#include "parson-helper.h"
#include "store-json.h"
#include "time-util.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"
#include "verify-status.h"
#include "uapki-debug.h"


#define DEBUG_OUTPUT_OUTSTREAM(msg,baData)
#ifndef DEBUG_OUTPUT_OUTSTREAM
DEBUG_OUTPUT_OUTSTREAM_FUNC
#define DEBUG_OUTPUT_OUTSTREAM(msg,baData) debug_output_stream(DEBUG_OUTSTREAM_FOPEN,"VERIFY_CERT",msg,baData)
#endif


using namespace std;
using namespace UapkiNS;


static bool check_validity_time (
        const Cert::CerItem* cerIssuer,
        const Cert::CerItem* cerSubject,
        const uint64_t validateTime
)
{
    const bool issuer_is_expired = (cerIssuer->checkValidity(validateTime) != RET_OK);
    const bool subject_is_expired = (cerSubject->checkValidity(validateTime) != RET_OK);
    return (issuer_is_expired || subject_is_expired);
}   //  check_validity_time


int uapki_verify_cert (JSON_Object* joParams, JSON_Object* joResult)
{
    CertValidator::CertValidator cert_validator;
    if (!cert_validator.init(get_config(), get_cerstore(), get_crlstore())) return RET_UAPKI_GENERAL_ERROR;
    if (!cert_validator.getLibConfig()->isInitialized()) return RET_UAPKI_NOT_INITIALIZED;

    int ret = RET_OK;
    Cert::CerItem* cer_issuer = nullptr;
    Cert::CerItem* cer_parsed = nullptr;
    Cert::CerItem* cer_subject = nullptr;
    SmartBA sba_encoded;
    string s_validatetime;
    const Cert::ValidationType validation_type = Cert::validationTypeFromStr(
        ParsonHelper::jsonObjectGetString(joParams, "validationType")
    );
    bool is_expired = false, is_selfsigned = false, need_updatecert = false;
    uint64_t validate_time = 0;

    if (
        (validation_type == Cert::ValidationType::UNDEFINED) ||
        (validation_type == Cert::ValidationType::CHAIN)
    ) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    if (sba_encoded.set(json_object_get_base64(joParams, "bytes"))) {
        DO(Cert::parseCert(sba_encoded.get(), &cer_parsed));
        cer_subject = cer_parsed;
    }
    else {
        SmartBA sba_certid;
        if (sba_certid.set(json_object_get_base64(joParams, "certId"))) {
            //  Note: if cert not found the just return RET_UAPKI_CERT_NOT_FOUND without 'expectedCerts'
            DO(cert_validator.getCerStore()->getCertByCertId(sba_certid.get(), &cer_subject));
        }
        else {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
    }

    s_validatetime = ParsonHelper::jsonObjectGetString(joParams, "validateTime");
    need_updatecert = s_validatetime.empty();
    if (need_updatecert || (validation_type == Cert::ValidationType::OCSP)) {
        validate_time = TimeUtil::mtimeNow();
    }
    else {
        DO(TimeUtil::ftimeToMtime(s_validatetime, validate_time));
    }
    s_validatetime = TimeUtil::mtimeToFtime(validate_time);
    DO_JSON(json_object_set_string(joResult, "validateTime", s_validatetime.c_str()));

    DO(json_object_set_base64(joResult, "subjectCertId", cer_subject->getCertId()));
    DO(Cert::validityToJson(joResult, cer_subject));

    DO(cert_validator.getIssuerCert(cer_subject, &cer_issuer, is_selfsigned));
    is_expired = check_validity_time(cer_issuer, cer_subject, validate_time);
    DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "expired", is_expired));
    DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "selfSigned", is_selfsigned));
    DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "trusted", cer_subject->isTrusted()));
    if (cer_subject->getVerifyStatus() == Cert::VerifyStatus::UNDEFINED) {
        DO(cer_subject->verify(cer_issuer));
    }
    DO_JSON(json_object_set_string(joResult, "statusSignature", Cert::verifyStatusToStr(cer_subject->getVerifyStatus())));

    if (!is_selfsigned) {
        DO(json_object_set_base64(joResult, "issuerCertId", cer_issuer->getCertId()));
    }
 
    if (validation_type == Cert::ValidationType::CRL) {
        CertValidator::ResultValidationByCrl result_valbycrl;
        DO_JSON(json_object_set_value(joResult, "validateByCRL", json_value_init_object()));
        DO(cert_validator.validateByCrl(
            cer_subject,
            cer_issuer,
            validate_time,
            need_updatecert,
            result_valbycrl,
            json_object_get_object(joResult, "validateByCRL")
        ));
    }
    else if (validation_type == Cert::ValidationType::OCSP) {
        CertValidator::ResultValidationByOcsp result_valbyocsp;
        DO_JSON(json_object_set_value(joResult, "validateByOCSP", json_value_init_object()));
        DO(cert_validator.validateByOcsp(
            cer_subject,
            cer_issuer,
            result_valbyocsp,
            json_object_get_object(joResult, "validateByOCSP")
        ));
    }

cleanup:
    if (ret != RET_OK) {
        (void)cert_validator.expectedCertItemsToJson(joResult, "expectedCerts");
        (void)cert_validator.expectedCrlItemsToJson(joResult, "expectedCrls");
    }
    delete cer_parsed;
    DEBUG_OUTPUT_OUTSTREAM("OCSP-request=", cert_validator.getOcspRequest());
    DEBUG_OUTPUT_OUTSTREAM("OCSP-response=", cert_validator.getOcspResponse());
    return ret;
}
