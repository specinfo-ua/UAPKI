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

#define FILE_MARKER "uapki/api/verify.cpp"

#include "api-json-internal.h"
#include "archive-timestamp-helper.h"
#include "attribute-helper.h"
#include "content-hasher.h"
#include "doc-verify.h"
#include "http-helper.h"
#include "parson-helper.h"
#include "ocsp-helper.h"
#include "signature-format.h"
#include "signeddata-helper.h"
#include "store-json.h"
#include "time-util.h"
#include "tsp-helper.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"
#include "uapki-ns-verify.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif

#define DEBUG_OUTPUT_OUTSTREAM(msg,baData)
#ifndef DEBUG_OUTPUT_OUTSTREAM
DEBUG_OUTPUT_OUTSTREAM_FUNC
#define DEBUG_OUTPUT_OUTSTREAM(msg,baData) debug_output_stream(DEBUG_OUTSTREAM_FOPEN,"VERIFY",msg,baData)
#endif


using namespace std;
using namespace UapkiNS;


//  =validationPolicy= (FULL-ETSI): the name of a policy, or an object with the values that differ from the
//  policy "basedOn". A name or a field the library does not know is an error: a policy is not applied in part
static int parse_validation_policy (
        JSON_Object* joParams,
        Doc::Verify::ValidationPolicy& policy
)
{
    if (!ParsonHelper::jsonObjectHasValue(joParams, "validationPolicy")) return RET_OK;

    if (ParsonHelper::jsonObjectHasValue(joParams, "validationPolicy", JSONString)) {
        const string s_name = ParsonHelper::jsonObjectGetString(joParams, "validationPolicy");
        return policy.setNamed(s_name) ? RET_OK : RET_UAPKI_INVALID_PARAMETER;
    }

    JSON_Object* jo_policy = json_object_get_object(joParams, "validationPolicy");
    if (!jo_policy) return RET_UAPKI_INVALID_PARAMETER;

    //  The named policy first: the other fields change its values, whatever their order in the object
    policy.basedOn = ParsonHelper::jsonObjectHasValue(jo_policy, "basedOn", JSONString)
        ? ParsonHelper::jsonObjectGetString(jo_policy, "basedOn") : string(Doc::Verify::ValidationPolicy::NAME_UKRAINE_DEFAULT);
    {
        const string s_basedon = policy.basedOn;
        if (!policy.setNamed(s_basedon)) return RET_UAPKI_INVALID_PARAMETER;
        policy.basedOn = s_basedon;
    }
    policy.name = Doc::Verify::ValidationPolicy::NAME_CUSTOM;
    for (size_t i = 0; i < json_object_get_count(jo_policy); i++) {
        const string s_key = json_object_get_name(jo_policy, i);
        const JSON_Value* jv = json_object_get_value_at(jo_policy, i);
        const JSON_Value_Type type = json_value_get_type(jv);
        const string s_value = (type == JSONString) ? string(json_value_get_string(jv)) : string();
        if (s_key == "basedOn") {
            if (type != JSONString) return RET_UAPKI_INVALID_PARAMETER;
        }
        else if (s_key == "revocationFreshness") {
            const double value = (type == JSONNumber) ? json_value_get_number(jv) : -1;
            if ((value < 0) || (value > 525600) || (value != (double)(uint32_t)value)) return RET_UAPKI_INVALID_PARAMETER;
            //  0 - the strict freshness: the data is issued after the best signature time
            policy.revocationFreshnessStrict = (value == 0);
            if (value > 0) policy.revocationFreshness = (uint32_t)value;
        }
        else if (s_key == "tsaExtendedKeyUsage") {
            if (s_value == "allowAdditional") policy.tsaAdditionalKeyPurposes = true;
            else if (s_value == "strict") policy.tsaAdditionalKeyPurposes = false;
            else return RET_UAPKI_INVALID_PARAMETER;
        }
        else if (s_key == "cryptographicConstraints") {
            if (s_value == "off") policy.cryptoLevel = Doc::Verify::CryptoLevel::OFF;
            else if (s_value == "warning") policy.cryptoLevel = Doc::Verify::CryptoLevel::WARNING;
            else if (s_value == "fail") policy.cryptoLevel = Doc::Verify::CryptoLevel::FAIL;
            else return RET_UAPKI_INVALID_PARAMETER;
        }
        else if (s_key == "cryptographicAlgorithms") {
            //  [{"algorithm", "keySizeBelow" (a key), "reliableUntil": "YYYY-MM-DD", or "" - no end date}]: replaces the constraint
            //  of the same algorithm and key size, or adds one
            if (type != JSONArray) return RET_UAPKI_INVALID_PARAMETER;
            const JSON_Array* ja_rules = json_value_get_array(jv);
            for (size_t j = 0; j < json_array_get_count(ja_rules); j++) {
                JSON_Object* jo_rule = json_array_get_object(ja_rules, j);
                if (!jo_rule) return RET_UAPKI_INVALID_PARAMETER;
                Doc::Verify::CryptoRule rule{ ParsonHelper::jsonObjectGetString(jo_rule, "algorithm"), 0, 0, false };
                if (rule.algorithm.empty()) return RET_UAPKI_INVALID_PARAMETER;
                if (json_object_has_value(jo_rule, "keySizeBelow")) {
                    const double size = ParsonHelper::jsonObjectHasValue(jo_rule, "keySizeBelow", JSONNumber) ? json_object_get_number(jo_rule, "keySizeBelow") : -1;
                    if ((size < 1) || (size > 65536) || (size != (double)(uint32_t)size)) return RET_UAPKI_INVALID_PARAMETER;
                    rule.keySizeBelow = (uint32_t)size;
                }
                if (ParsonHelper::jsonObjectHasValue(jo_rule, "reliableUntil", JSONString)) {
                    const string s_date = json_object_get_string(jo_rule, "reliableUntil");
                    if (!s_date.empty() && ((s_date.length() != 10) || (TimeUtil::ftimeToMtime(s_date + " 00:00:00", rule.msEnd) != RET_OK))) {
                        return RET_UAPKI_INVALID_PARAMETER;
                    }
                }
                else {
                    return RET_UAPKI_INVALID_PARAMETER;
                }
                bool replaced = false;
                for (auto& it : policy.cryptoRules) {
                    if ((it.algorithm == rule.algorithm) && (it.keySizeBelow == rule.keySizeBelow)) {
                        it.msEnd = rule.msEnd;
                        replaced = true;
                    }
                }
                if (!replaced) policy.cryptoRules.push_back(rule);
            }
        }
        else if (s_key == "timeStampDelay") {
            const double value = (type == JSONNumber) ? json_value_get_number(jv) : -1;
            if ((value < 0) || (value > 525600) || (value != (double)(uint32_t)value)) return RET_UAPKI_INVALID_PARAMETER;
            policy.timeStampDelay = (uint32_t)value;
        }
        else if (s_key == "certificatePathModel") {
            if (s_value == "shell") policy.chainModel = false;
            else if (s_value == "chain") policy.chainModel = true;
            else return RET_UAPKI_INVALID_PARAMETER;
        }
        else if (s_key == "pastValidation") {
            if (s_value == "bestSignatureTime") policy.pastValidationByPoe = false;
            else if (s_value == "proofOfExistence") policy.pastValidationByPoe = true;
            else return RET_UAPKI_INVALID_PARAMETER;
        }
        else if (s_key == "tsaTrust") {
            if (s_value == "timeStampTime") policy.tsaTrustByProofOfExistence = false;
            else if (s_value == "proofOfExistence") policy.tsaTrustByProofOfExistence = true;
            else return RET_UAPKI_INVALID_PARAMETER;
        }
        else if (s_key == "signerKeyUsage") {
            if (s_value == "digitalSignatureOrNonRepudiation") policy.signerNonRepudiation = false;
            else if (s_value == "nonRepudiation") policy.signerNonRepudiation = true;
            else return RET_UAPKI_INVALID_PARAMETER;
        }
        else if ((s_key == "caRemovesExpiredCerts") || (s_key == "checkCriticalExtensions")) {
            if (type != JSONBoolean) return RET_UAPKI_INVALID_PARAMETER;
            const bool value = (json_value_get_boolean(jv) != 0);
            if (s_key == "caRemovesExpiredCerts") policy.caRemovesExpiredCerts = value;
            else policy.checkCriticalExtensions = value;
        }
        else {
            return RET_UAPKI_INVALID_PARAMETER;
        }
    }

    return RET_OK;
}   //  parse_validation_policy

static int parse_verify_options (
        JSON_Object* joParams,
        Doc::Verify::VerifyOptions& verifyOptions
)
{
    if (joParams) {
        verifyOptions.validationType = Doc::Verify::validationTypeFromStr(
            ParsonHelper::jsonObjectGetString(joParams, "validationType")
        );
        if (verifyOptions.validationType == Doc::Verify::VerifyOptions::ValidationType::UNDEFINED) return RET_UAPKI_INVALID_PARAMETER;
        //  By default as in the library config (INIT: validationByCrl)
        verifyOptions.onlyCrl = ParsonHelper::jsonObjectGetBoolean(joParams, "onlyCrl", verifyOptions.onlyCrl);
        //  FULL-ETSI: the time the caller attests the signature existed at
        if (ParsonHelper::jsonObjectHasValue(joParams, "proofOfExistenceTime")) {
            const string s_time = ParsonHelper::jsonObjectGetString(joParams, "proofOfExistenceTime");
            if (s_time.empty() || (TimeUtil::ftimeToMtime(s_time, verifyOptions.msProvidedPoe) != RET_OK) || (verifyOptions.msProvidedPoe == 0)) {
                return RET_UAPKI_INVALID_PARAMETER;
            }
        }
        verifyOptions.verifySignerInfoIndex = ParsonHelper::jsonObjectGetInt32(joParams, "verifySignerInfoIndex", -1);
        //  FULL-ETSI: an unknown critical extension makes a certificate unusable (RFC 5280, 4.2), unless switched off
        verifyOptions.checkCriticalExtensions = ParsonHelper::jsonObjectGetBoolean(joParams, "checkCriticalExtensions",
            verifyOptions.validationType == Doc::Verify::VerifyOptions::ValidationType::FULL_ETSI);
        verifyOptions.caRemovesExpiredCerts = ParsonHelper::jsonObjectGetBoolean(joParams, "caRemovesExpiredCerts", false);
        if (verifyOptions.verifySignerInfoIndex < 0) {
            verifyOptions.verifySignerInfoIndex = -1;
        }
        if (verifyOptions.validationType == Doc::Verify::VerifyOptions::ValidationType::FULL_ETSI) {
            //  The constraints are the ones of the validation policy. onlyCrl stays an option of the request: the
            //  revocation data of the signature is used as it is (CRL, OCSP); when it is absent or does not meet the
            //  requirements, the request to an OCSP responder is skipped and the status is looked for by CRL
            const int ret = parse_validation_policy(joParams, verifyOptions.policy);
            if (ret != RET_OK) return ret;
            verifyOptions.checkCriticalExtensions = verifyOptions.policy.checkCriticalExtensions;
            verifyOptions.caRemovesExpiredCerts = verifyOptions.policy.caRemovesExpiredCerts;
        }
    }

    return RET_OK;
}   //  parse_verify_options

static int result_attr_timestamp_to_json (
        JSON_Object* joResult,
        const char* attrName,
        const Doc::Verify::AttrTimeStamp& attrTS
)
{
    int ret = RET_OK;

    if (attrTS.isPresent()) {
        JSON_Object* jo_attr = joResult;
        if (attrName) {
            json_object_set_value(joResult, attrName, json_value_init_object());
            jo_attr = json_object_get_object(joResult, attrName);
        }
        DO_JSON(json_object_set_string(jo_attr, "genTime", TimeUtil::mtimeToFtime(attrTS.msGenTime).c_str()));
        DO_JSON(json_object_set_string(jo_attr, "policyId", attrTS.policy.c_str()));
        DO_JSON(json_object_set_string(jo_attr, "hashAlgo", attrTS.hashAlgo.c_str()));
        DO(json_object_set_base64(jo_attr, "hashedMessage", attrTS.hashedMessage.get()));
        DO_JSON(json_object_set_string(jo_attr, "statusDigest", verifyStatusToStr(attrTS.statusDigest)));
        DO_JSON(json_object_set_string(jo_attr, "statusSignature", verifyStatusToStr(attrTS.statusSignature)));
        if (attrTS.cerSigner) {
            DO(json_object_set_base64(jo_attr, "signerCertId", attrTS.cerSigner->getCertId()));
        }
    }

cleanup:
    return ret;
}   //  result_attr_timestamp_to_json

static int result_attributes_to_json (
        JSON_Object* joResult,
        const char* key,
        const vector<UapkiNS::Attribute>& attrs
)
{
    if (attrs.empty()) return RET_OK;

    int ret = RET_OK;
    json_object_set_value(joResult, key, json_value_init_array());
    JSON_Array* ja_attrs = json_object_get_array(joResult, key);
    for (size_t i = 0; i < attrs.size(); i++) {
        const UapkiNS::Attribute& attr = attrs[i];
        json_array_append_value(ja_attrs, json_value_init_object());
        JSON_Object* jo_attr = json_array_get_object(ja_attrs, i);
        DO_JSON(json_object_set_string(jo_attr, "type", attr.type.c_str()));
        DO(json_object_set_base64(jo_attr, "bytes", attr.baValues));
    }

cleanup:
    return ret;
}   //  result_attributes_to_json

static int result_certchainitem_valbycrl_to_json (
        JSON_Object* joResult,
        const Doc::Verify::ResultValidationByCrl& resultValByCrl,
        string& statusValidation
)
{
    int ret = RET_OK;
    const Crl::CrlItem* crl_item = resultValByCrl.crlItem;
    const Crl::RevokedCertItem& revcert_item = resultValByCrl.revokedCertItem;

    if (crl_item) {
        string s_commonname;
        DO(rdnameFromName(crl_item->getTbsCrl()->issuer, OID_X520_CommonName, s_commonname));
        DO(json_object_set_base64(joResult, "crlId", crl_item->getCrlId()));
        DO_JSON(json_object_set_string(joResult, "CN", s_commonname.c_str()));
        DO_JSON(json_object_set_string(joResult, "thisUpdate", TimeUtil::mtimeToFtime(crl_item->getThisUpdate()).c_str()));
        DO_JSON(json_object_set_string(joResult, "nextUpdate", TimeUtil::mtimeToFtime(crl_item->getNextUpdate()).c_str()));
        DO(json_object_set_hex(joResult, "crlNumber", crl_item->getCrlNumber()));
        if (crl_item->getDeltaCrl()) {
            DO(json_object_set_hex(joResult, "deltaCrlIndicator", crl_item->getDeltaCrl()));
        }
        if (resultValByCrl.cerIssuer) {
            DO(json_object_set_base64(joResult, "issuerCertId", resultValByCrl.cerIssuer->getCertId()));
        }
        DO_JSON(json_object_set_string(joResult, "statusSignature", Cert::verifyStatusToStr(crl_item->getStatusSign())));
    }

    DO_JSON(json_object_set_string(joResult, "status", Crl::certStatusToStr(resultValByCrl.certStatus)));

    if (revcert_item.crlReason != UapkiNS::CrlReason::UNDEFINED) {
        DO_JSON(json_object_set_string(joResult, "revocationReason", Crl::crlReasonToStr(revcert_item.crlReason)));
        const string s_revoktime = TimeUtil::mtimeToFtime(revcert_item.getDate());
        DO_JSON(json_object_set_string(joResult, "revocationTime", s_revoktime.c_str()));
    }

    statusValidation = verifyStatusToStr((
        crl_item &&
        (crl_item->getStatusSign() == Cert::VerifyStatus::VALID) &&
        (resultValByCrl.certStatus == UapkiNS::CertStatus::GOOD)
    ) ? SignatureVerifyStatus::VALID : SignatureVerifyStatus::INVALID);

cleanup:
    return ret;
}   //  result_certchainitem_valbycrl_to_json

static int result_certchainitem_valbyocsp_to_json (
        JSON_Object* joResult,
        const Doc::Verify::ResultValidationByOcsp& resultValByOcsp,
        const uint64_t bestSignatureTime,
        string& statusValidation
)
{
    int ret = RET_OK;
    const Ocsp::OcspHelper::SingleResponseInfo& singleresp_info = resultValByOcsp.singleResponseInfo;

    DO_JSON(json_object_set_string(joResult, "source", CertValidator::dataSourceToStr(resultValByOcsp.dataSource)));
    DO_JSON(json_object_set_string(joResult, "responseStatus", Ocsp::responseStatusToStr(resultValByOcsp.responseStatus)));
    DO_JSON(json_object_set_string(joResult, "producedAt", TimeUtil::mtimeToFtime(resultValByOcsp.msProducedAt).c_str()));
    DO_JSON(json_object_set_string(joResult, "statusSignature", verifyStatusToStr(resultValByOcsp.statusSignature)));
    if (resultValByOcsp.cerResponder) {
        DO(json_object_set_base64(joResult, "signerCertId", resultValByOcsp.cerResponder->getCertId()));
    }
    if (resultValByOcsp.responderByTrustList) {
        DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "responderByTrustList", true));
    }

    DO_JSON(json_object_set_string(joResult, "status", Crl::certStatusToStr(singleresp_info.certStatus)));

    DO_JSON(json_object_set_string(joResult, "thisUpdate", TimeUtil::mtimeToFtime(singleresp_info.msThisUpdate).c_str()));
    if (singleresp_info.msNextUpdate > 0) {
        DO_JSON(json_object_set_string(joResult, "nextUpdate", TimeUtil::mtimeToFtime(singleresp_info.msNextUpdate).c_str()));
    }
    if (singleresp_info.revocationReason != UapkiNS::CrlReason::UNDEFINED) {
        DO_JSON(json_object_set_string(joResult, "revocationReason", Crl::crlReasonToStr(singleresp_info.revocationReason)));
        DO_JSON(json_object_set_string(joResult, "revocationTime", TimeUtil::mtimeToFtime(singleresp_info.msRevocationTime).c_str()));
    }

    //  Revoked after the best signature time: valid when signed (as by a CRL at that time)
    statusValidation = verifyStatusToStr((
        (resultValByOcsp.statusSignature == SignatureVerifyStatus::VALID) && (
            (singleresp_info.certStatus == UapkiNS::CertStatus::GOOD) || (
                (singleresp_info.certStatus == UapkiNS::CertStatus::REVOKED) &&
                (bestSignatureTime > 0) &&
                (singleresp_info.msRevocationTime > bestSignatureTime)
            )
        )
    ) ? SignatureVerifyStatus::VALID : SignatureVerifyStatus::INVALID);

cleanup:
    return ret;
}   //  result_certchainitem_valbyocsp_to_json

static int result_certchainitem_to_json (
        JSON_Object* joResult,
        const Doc::Verify::CertChainItem& certChainItem,
        const Doc::Verify::VerifyOptions& verifyOptions,
        const uint64_t bestSignatureTime
)
{
    (void)verifyOptions;
    int ret = RET_OK;
    string s_statusvalidation;

    DO(json_object_set_base64(joResult, "subjectCertId", certChainItem.getSubjectCertId()));
    DO_JSON(json_object_set_string(joResult, "CN", certChainItem.getCommonName().c_str()));
    DO_JSON(json_object_set_string(joResult, "entity", CertValidator::certEntityToStr(certChainItem.getCertEntity())));
    DO_JSON(json_object_set_string(joResult, "source", CertValidator::dataSourceToStr(certChainItem.getDataSource())));
    DO(Cert::validityToJson(joResult, certChainItem.getSubject()));
    DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "expired", certChainItem.isExpired()));
    DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "selfSigned", certChainItem.isSelfSigned()));
    DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "trusted", certChainItem.isTrusted()));
    if (certChainItem.getIssuerCertId()) {
        DO(json_object_set_base64(joResult, "issuerCertId", certChainItem.getIssuerCertId()));
        DO_JSON(json_object_set_string(joResult, "statusSignature", Cert::verifyStatusToStr(certChainItem.getVerifyStatus())));
    }

    if (!certChainItem.isExpired()) {
        switch (certChainItem.getValidationType()) {
        case Cert::ValidationType::UNDEFINED:
            s_statusvalidation = string("UNDEFINED");
            break;
        case Cert::ValidationType::NONE:
            s_statusvalidation = string("NONE");
            break;
        case Cert::ValidationType::CRL:
            DO_JSON(json_object_set_value(joResult, "validateByCRL", json_value_init_object()));
            DO(result_certchainitem_valbycrl_to_json(
                json_object_get_object(joResult, "validateByCRL"),
                certChainItem.getResultValidationByCrl(),
                s_statusvalidation
            ));
            break;
        case Cert::ValidationType::OCSP:
            DO_JSON(json_object_set_value(joResult, "validateByOCSP", json_value_init_object()));
            DO(result_certchainitem_valbyocsp_to_json(
                json_object_get_object(joResult, "validateByOCSP"),
                certChainItem.getResultValidationByOcsp(),
                bestSignatureTime,
                s_statusvalidation
            ));
            break;
        default:
            break;
        }
    }
    else {
        s_statusvalidation = string("EXPIRED");
    }
    DO_JSON(json_object_set_string(joResult, "statusValidation", s_statusvalidation.c_str()));

cleanup:
    return ret;
}

static int result_otherhash_to_json (
        JSON_Object* joOtherHash,
        const UapkiNS::OtherHash& otherHash
)
{
    int ret = RET_OK;

    DO_JSON(json_object_set_string(joOtherHash, "hashAlgo", otherHash.hashAlgorithm.algorithm.c_str()));
    if (otherHash.hashAlgorithm.baParameters) {
        DO(json_object_set_base64(joOtherHash, "hashAlgoParams", otherHash.hashAlgorithm.baParameters));
    }
    DO(json_object_set_base64(joOtherHash, "hashValue", otherHash.baHashValue));

cleanup:
    return ret;
}   //  result_otherhash_to_json

static int result_certificaterefs_to_json (
        JSON_Object* joResult,
        const Doc::Verify::CadesXlInfo& cadesXlInfo
)
{
    int ret = RET_OK;

    if (!cadesXlInfo.certRefs.empty()) {
        json_object_set_value(joResult, "certificateRefs", json_value_init_array());
        JSON_Array* ja_certrefs = json_object_get_array(joResult, "certificateRefs");
        for (size_t i = 0; i < cadesXlInfo.certRefs.size(); i++) {
            const UapkiNS::OtherCertId& cert_ref = cadesXlInfo.certRefs[i];
            SmartBA sba_issuer;

            DO_JSON(json_array_append_value(ja_certrefs, json_value_init_object()));
            JSON_Object* jo_certref = json_array_get_object(ja_certrefs, i);
            DO_JSON(json_object_set_value(jo_certref, "certHash", json_value_init_object()));
            DO(result_otherhash_to_json(json_object_get_object(jo_certref, "certHash"), cert_ref));
            //  issuerSerial of OtherCertID is optional (ETSI TS 101 733, 6.2.1)
            if (cert_ref.issuerSerial.baIssuer && cert_ref.issuerSerial.baSerialNumber) {
                DO_JSON(json_object_set_value(jo_certref, "issuer", json_value_init_object()));
                DO(Cert::issuerFromGeneralNames(cert_ref.issuerSerial.baIssuer, &sba_issuer));
                DO(nameToJson(json_object_get_object(jo_certref, "issuer"), sba_issuer.get()));
                DO(json_object_set_hex(jo_certref, "serialNumber", cert_ref.issuerSerial.baSerialNumber));
            }
            DO_JSON(json_object_set_string(jo_certref, "status",
                verifyStatusToStr((i < cadesXlInfo.statusesCertRefs.size()) ? cadesXlInfo.statusesCertRefs[i] : VerifyStatus::UNDEFINED)));
        }
    }

cleanup:
    return ret;
}   //  result_certificaterefs_to_json

static int result_crlocspref_to_json (
        JSON_Object* joCrlOcspRef,
        const AttributeHelper::RevocationRefsParser::CrlOcspRef& crlOcspRef
)
{
    int ret = RET_OK;

    //  =crlIds= (optional)
    if (!crlOcspRef.getCrlIds().empty()) {
        size_t idx = 0;
        json_object_set_value(joCrlOcspRef, "crlIds", json_value_init_array());
        JSON_Array* ja_crlids = json_object_get_array(joCrlOcspRef, "crlIds");
        for (const auto& it : crlOcspRef.getCrlIds()) {
            json_array_append_value(ja_crlids, json_value_init_object());
            JSON_Object* jo_crlid = json_array_get_object(ja_crlids, idx++);
            //  =crlHash=
            UapkiNS::OtherHash crl_hash;
            DO(AttributeHelper::decodeOtherHash(it.baHash, crl_hash));
            DO_JSON(json_object_set_value(jo_crlid, "crlHash", json_value_init_object()));
            DO(result_otherhash_to_json(json_object_get_object(jo_crlid, "crlHash"), crl_hash));
            //  =crlIdentifier= (optional)
            if (it.baId) {
                DO_JSON(json_object_set_value(jo_crlid, "crlIdentifier", json_value_init_object()));
                DO(Crl::crlIdentifierToJson(json_object_get_object(jo_crlid, "crlIdentifier"), it.baId));
            }
        }
    }

    //  =ocspIds= (optional)
    if (!crlOcspRef.getOcspIds().empty()) {
        size_t idx = 0;
        json_object_set_value(joCrlOcspRef, "ocspIds", json_value_init_array());
        JSON_Array* ja_ocspids = json_object_get_array(joCrlOcspRef, "ocspIds");
        for (const auto& it : crlOcspRef.getOcspIds()) {
            json_array_append_value(ja_ocspids, json_value_init_object());
            JSON_Object* jo_ocspid = json_array_get_object(ja_ocspids, idx++);
            //  =ocspIdentifier=
            DO_JSON(json_object_set_value(jo_ocspid, "ocspIdentifier", json_value_init_object()));
            DO(Cert::ocspIdentifierToJson(json_object_get_object(jo_ocspid, "ocspIdentifier"), it.baId));
            //  =ocspHash= (optional)
            if (it.baHash) {
                UapkiNS::OtherHash ocsp_hash;
                DO(AttributeHelper::decodeOtherHash(it.baHash, ocsp_hash));
                DO_JSON(json_object_set_value(jo_ocspid, "ocspHash", json_value_init_object()));
                DO(result_otherhash_to_json(json_object_get_object(jo_ocspid, "ocspHash"), ocsp_hash));
            }
        }
    }

    //  =otherRev= (optional)
    if (crlOcspRef.getOtherRevRefs().isPresent()) {
        const UapkiNS::Attribute& other_revrefs = crlOcspRef.getOtherRevRefs();
        json_object_set_value(joCrlOcspRef, "otherRev", json_value_init_object());
        JSON_Object* jo_otherrev = json_object_get_object(joCrlOcspRef, "otherRev");
        DO_JSON(json_object_set_string(jo_otherrev, "type", other_revrefs.type.c_str()));
        DO(json_object_set_base64(jo_otherrev, "bytes", other_revrefs.baValues));
    }

cleanup:
    return ret;
}   //  result_crlocspref_to_json

static int result_revocationrefs_to_json (
        JSON_Object* joResult,
        AttributeHelper::RevocationRefsParser& revocationRefs
)
{
    int ret = RET_OK;
    const size_t cnt_refs = revocationRefs.getCountCrlOcspRefs();
    if (cnt_refs == 0) return RET_OK;

    json_object_set_value(joResult, "revocationRefs", json_value_init_array());
    JSON_Array* ja_revocationrefs = json_object_get_array(joResult, "revocationRefs");
    for (size_t idx = 0; idx < cnt_refs; idx++) {
        AttributeHelper::RevocationRefsParser::CrlOcspRef crlocsp_ref;
        DO(revocationRefs.parseCrlOcspRef(idx, crlocsp_ref));
        DO_JSON(json_array_append_value(ja_revocationrefs, json_value_init_object()));
        DO(result_crlocspref_to_json(json_array_get_object(ja_revocationrefs, idx), crlocsp_ref));
    }

cleanup:
    return ret;
}   //  result_revocationrefs_to_json

static int result_verifyinfo_to_json (
        JSON_Object* joSignInfo,
        Doc::Verify::VerifiedSignerInfo& verifyInfo,
        const Doc::Verify::VerifyOptions& verifyOptions
)
{
    int ret = RET_OK;
    vector<string> warns = verifyInfo.getWarningMessages();
    //  The status of the validation types that do not check everything says what was not checked
    if (verifyOptions.validationType == Doc::Verify::VerifyOptions::ValidationType::STRUCT) {
        warns.push_back("THE CERTIFICATE CHAIN AND THE REVOCATION STATUS ARE NOT CHECKED (VALIDATION TYPE STRUCT)");
    }
    else if (verifyOptions.validationType == Doc::Verify::VerifyOptions::ValidationType::CHAIN) {
        warns.push_back("THE REVOCATION STATUS OF THE CERTIFICATES IS NOT CHECKED (VALIDATION TYPE CHAIN)");
    }

    if (verifyInfo.getSignerCertId()) {
        DO(json_object_set_base64(joSignInfo, "signerCertId", verifyInfo.getSignerCertId()));
    }

    DO_JSON(json_object_set_string(joSignInfo, "signatureFormat", signatureFormatToStr(verifyInfo.getSignatureFormat())));
    DO_JSON(json_object_set_string(joSignInfo, "status", verifyInfo.getValidationStatus()));
    DO_JSON(ParsonHelper::jsonObjectSetBoolean(joSignInfo, "validSignatures", verifyInfo.isValidSignatures()));
    DO_JSON(ParsonHelper::jsonObjectSetBoolean(joSignInfo, "validDigests", verifyInfo.isValidDigests()));
    DO_JSON(json_object_set_string(joSignInfo, "bestSignatureTime", TimeUtil::mtimeToFtime(verifyInfo.getBestSignatureTime()).c_str()));
    DO_JSON(json_object_set_string(joSignInfo, "signAlgo", verifyInfo.getSignerInfo().getSignatureAlgorithm().algorithm.c_str()));
    DO_JSON(json_object_set_string(joSignInfo, "statusSignature", verifyStatusToStr(verifyInfo.getStatusSignature())));
    DO_JSON(json_object_set_string(joSignInfo, "digestAlgo", verifyInfo.getSignerInfo().getDigestAlgorithm().algorithm.c_str()));
    DO_JSON(json_object_set_string(joSignInfo, "statusMessageDigest", verifyStatusToStr(verifyInfo.getStatusMessageDigest())));
    if (verifyInfo.getSigningTime() > 0) {
        DO_JSON(json_object_set_string(joSignInfo, "signingTime", TimeUtil::mtimeToFtime(verifyInfo.getSigningTime()).c_str()));
    }
    if (!verifyInfo.getSigPolicyId().empty()) {
        DO_JSON(json_object_dotset_string(joSignInfo, "signaturePolicy.sigPolicyId", verifyInfo.getSigPolicyId().c_str()));
    }
    DO_JSON(json_object_set_string(joSignInfo, "statusEssCert", verifyStatusToStr(verifyInfo.getStatusEssCert())));
    DO(result_attr_timestamp_to_json(joSignInfo, "contentTS", verifyInfo.getContentTS()));
    DO(result_attr_timestamp_to_json(joSignInfo, "signatureTS", verifyInfo.getSignatureTS()));
    DO_JSON(json_object_set_string(joSignInfo, "statusCertificateRefs", verifyStatusToStr(verifyInfo.getCadesXlInfo().statusCertRefs)));
    DO(result_certificaterefs_to_json(joSignInfo, verifyInfo.getCadesXlInfo()));
    if (!verifyInfo.getListAddedCerts().certValues.empty()) {
        DO_JSON(json_object_set_value(joSignInfo, "certValues", json_value_init_array()));
        JSON_Array* ja_certids = json_object_get_array(joSignInfo, "certValues");
        for (const auto& it : verifyInfo.getListAddedCerts().certValues) {
            DO(json_array_append_base64(ja_certids, it->getCertId()));
        }
    }
    DO(result_revocationrefs_to_json(joSignInfo, verifyInfo.getRevocationRefs()));
    DO(result_attr_timestamp_to_json(joSignInfo, "archiveTS", verifyInfo.getArchiveTS()));
    if (!verifyInfo.getArchiveTSsNext().empty()) {
        //  All the archive time-stamps (re-archiving), archiveTS is the first one
        DO_JSON(json_object_set_value(joSignInfo, "archiveTimeStamps", json_value_init_array()));
        JSON_Array* ja_archivets = json_object_get_array(joSignInfo, "archiveTimeStamps");
        DO_JSON(json_array_append_value(ja_archivets, json_value_init_object()));
        DO(result_attr_timestamp_to_json(json_array_get_object(ja_archivets, 0), nullptr, verifyInfo.getArchiveTS()));
        for (const auto& it : verifyInfo.getArchiveTSsNext()) {
            DO_JSON(json_array_append_value(ja_archivets, json_value_init_object()));
            DO(result_attr_timestamp_to_json(
                json_array_get_object(ja_archivets, json_array_get_count(ja_archivets) - 1), nullptr, *it
            ));
        }
    }

    DO(result_attributes_to_json(joSignInfo, "signedAttributes", verifyInfo.getSignerInfo().getSignedAttrs()));
    DO(result_attributes_to_json(joSignInfo, "unsignedAttributes", verifyInfo.getSignerInfo().getUnsignedAttrs()));

    if ((verifyOptions.validationType >= Doc::Verify::VerifyOptions::ValidationType::CHAIN)) {
        DO_JSON(json_object_set_value(joSignInfo, "certificateChain", json_value_init_array()));
        JSON_Array* ja_certchainitems = json_object_get_array(joSignInfo, "certificateChain");
        size_t idx = 0;
        for (const auto& it : verifyInfo.getCertChainItems()) {
            DO_JSON(json_array_append_value(ja_certchainitems, json_value_init_object()));
            DO(result_certchainitem_to_json(json_array_get_object(ja_certchainitems, idx++), *it, verifyOptions, verifyInfo.getBestSignatureTime()));
        }
    }

    if (!verifyInfo.getExpectedCerts().empty()) {
        DO_JSON(json_object_set_value(joSignInfo, "expectedCerts", json_value_init_array()));
        JSON_Array* ja_expcertitems = json_object_get_array(joSignInfo, "expectedCerts");
        size_t idx = 0;
        for (const auto& it : verifyInfo.getExpectedCerts()) {
            DO_JSON(json_array_append_value(ja_expcertitems, json_value_init_object()));
            DO(CertValidator::expectedCertItemToJson(json_array_get_object(ja_expcertitems, idx++), *it));
        }
    }

    if (!verifyInfo.getExpectedCrls().empty()) {
        DO_JSON(json_object_set_value(joSignInfo, "expectedCrls", json_value_init_array()));
        JSON_Array* ja_expcrlitems = json_object_get_array(joSignInfo, "expectedCrls");
        size_t idx = 0;
        for (const auto& it : verifyInfo.getExpectedCrls()) {
            DO_JSON(json_array_append_value(ja_expcrlitems, json_value_init_object()));
            DO(CertValidator::expectedCrlItemToJson(json_array_get_object(ja_expcrlitems, idx++), *it));
        }
    }

    if (!warns.empty()) {
        DO_JSON(json_object_set_value(joSignInfo, "warnings", json_value_init_array()));
        JSON_Array* ja_warns = json_object_get_array(joSignInfo, "warnings");
        for (const auto& it : warns) {
            DO_JSON(json_array_append_string(ja_warns, it.c_str()));
        }
    }

cleanup:
    return ret;
}   //  result_verifyinfo_to_json

static int result_to_json (
        JSON_Object* joResult,
        Doc::Verify::VerifySignedDoc& verifySignedDoc,
        const bool returnContent
)
{
    int ret = RET_OK;

    {   //  =content=
        const Pkcs7::EncapsulatedContentInfo& encap_cinfo = verifySignedDoc.sdataParser.getEncapContentInfo();
        json_object_set_value(joResult, "content", json_value_init_object());
        JSON_Object* jo_content = json_object_get_object(joResult, "content");
        DO_JSON(json_object_set_string(jo_content, "type", encap_cinfo.contentType.c_str()));
        if (returnContent && encap_cinfo.baEncapContent) {
            DO(json_object_set_base64(jo_content, "bytes", encap_cinfo.baEncapContent));
        }
    }

    {   //  =certIds=
        json_object_set_value(joResult, "certIds", json_value_init_array());
        JSON_Array* ja_certids = json_object_get_array(joResult, "certIds");
        for (const auto& it : verifySignedDoc.addedCerts) {
            DO(json_array_append_base64(ja_certids, it->getCertId()));
        }
    }

    {   //  =signatureInfos=
        DO_JSON(json_object_set_value(joResult, "signatureInfos", json_value_init_array()));
        JSON_Array* ja_signinfos = json_object_get_array(joResult, "signatureInfos");
        for (size_t i = 0; i < verifySignedDoc.verifiedSignerInfos.size(); i++) {
            DO_JSON(json_array_append_value(ja_signinfos, json_value_init_object()));
            DO(result_verifyinfo_to_json(
                json_array_get_object(ja_signinfos, i),
                verifySignedDoc.verifiedSignerInfos[i],
                verifySignedDoc.verifyOptions
            ));
        }
    }

cleanup:
    return ret;
}   //  result_to_json

static int validate_by_crl (
        Doc::Verify::VerifiedSignerInfo& verifiedSignerInfo,
        Doc::Verify::CertChainItem& certChainItem
)
{
    int ret = RET_OK;
    Doc::Verify::ResultValidationByCrl& result_valbycrl = certChainItem.getResultValidationByCrl();

    DO(verifiedSignerInfo.validateByCrl(
        certChainItem.getSubject(),
        verifiedSignerInfo.getBestSignatureTime(),
        false,
        result_valbycrl
    ));
    certChainItem.setValidationType(Cert::ValidationType::CRL);

cleanup:
    return ret;
}   //  validate_by_crl

static int validate_by_ocsp (
        Doc::Verify::VerifiedSignerInfo& verifiedSignerInfo,
        Doc::Verify::CertChainItem& certChainItem
)
{
    int ret = RET_OK;
    CertValidator::ResultValidationByOcsp& result_valbyocsp = certChainItem.getResultValidationByOcsp();

    //  The response is checked by validateByOcsp(): CertID of this certificate, signature, responder authority
    DO(verifiedSignerInfo.validateByOcsp(
        certChainItem.getSubject(),
        certChainItem.getIssuer(),
        result_valbyocsp
    ));
    result_valbyocsp.dataSource = CertValidator::DataSource::STORE;
    result_valbyocsp.responseStatus = Ocsp::ResponseStatus::SUCCESSFUL;
    if (result_valbyocsp.cerResponder) {
        verifiedSignerInfo.getListAddedCerts().ocsp.push_back(result_valbyocsp.cerResponder);
    }
    certChainItem.setValidationType(Cert::ValidationType::OCSP);

cleanup:
    return ret;
}   //  validate_by_ocsp

//  The status of the signers of the OCSP responses and CRLs without id-pkix-ocsp-nocheck (and of the CA certificates
//  of their chains), after the status of the other certificates (RFC 6960, 4.2.2.2.1; as EU DSS): by OCSP if the
//  certificate has its OCSP responder and the response is not signed by the certificate itself (it proves nothing
//  about itself), else by CRL - of any size (the CRL cache keeps it up to nextUpdate). A responder (a CRL signer)
//  that is a service of a trusted list provided at the time needs no status of its own, as with
//  id-pkix-ocsp-nocheck: nothing is requested for it. Not determined - the result is INDETERMINATE
//  (validateStatusCerts()), the CRL that would determine it is among the expected ones
static void validate_status_signers (
        Doc::Verify::VerifiedSignerInfo& verifiedSignerInfo,
        const bool onlyCrl
)
{
    const uint64_t status_time = (verifiedSignerInfo.getBestSignatureTime() > 0)
        ? verifiedSignerInfo.getBestSignatureTime() : TimeUtil::mtimeNow();
    for (auto& it : verifiedSignerInfo.getCertChainItems()) {
        if (
            it->isExpired() ||
            (it->getCertEntity() == CertValidator::CertEntity::ROOT) ||
            (it->getValidationType() != Cert::ValidationType::UNDEFINED)
        ) continue;

        if (
            ((it->getCertEntity() == CertValidator::CertEntity::OCSP) && it->getSubject()->hasActiveTrustService("OCSP", status_time)) ||
            ((it->getCertEntity() == CertValidator::CertEntity::CRL) && it->getSubject()->hasActiveTrustService("CRL", status_time))
        ) {
            it->setValidationType(Cert::ValidationType::NONE);
            continue;
        }

        if (!onlyCrl && !it->getSubject()->getUris().ocsp.empty() && it->getIssuer()) {
            if (
                (validate_by_ocsp(verifiedSignerInfo, *it) == RET_OK) &&
                (it->getResultValidationByOcsp().cerResponder != it->getSubject())
            ) continue;
            it->setValidationType(Cert::ValidationType::UNDEFINED);
        }
        if (validate_by_crl(verifiedSignerInfo, *it) != RET_OK) {
            it->setValidationType(Cert::ValidationType::UNDEFINED);
        }
    }
}

static int validate_certs (
        Doc::Verify::VerifySignedDoc& verifySignedDoc,
        Doc::Verify::VerifiedSignerInfo& verifiedSignerInfo
)
{
    int ret = RET_OK;
    const Doc::Verify::VerifyOptions& verify_options = verifySignedDoc.verifyOptions;
    const uint64_t bestsign_time = verifiedSignerInfo.getBestSignatureTime();
    //  The strict freshness of the policy: the status is issued after the best signature time
    if (verify_options.policy.revocationFreshnessStrict) {
        verifiedSignerInfo.setStrictFreshnessTime(bestsign_time);
    }

    if (verify_options.validationType == Doc::Verify::VerifyOptions::ValidationType::CHAIN) {
        verifiedSignerInfo.validateValidityTimeCerts(bestsign_time);
        for (auto& it : verifiedSignerInfo.getCertChainItems()) {
            it->setValidationType(Cert::ValidationType::NONE);
        }
    }
    else if (verify_options.validationType >= Doc::Verify::VerifyOptions::ValidationType::FULL) {
        //  By the revocation data the signature has: values (XL, baseline LT/LTA), references (C)
        SignatureFormat sign_format = verifiedSignerInfo.getSignatureFormat();
        if (verifiedSignerInfo.hasRevocationValues()) {
            sign_format = SignatureFormat::CADES_XL;
        }
        else if (verifiedSignerInfo.getCadesXlInfo().isPresentCadesC()) {
            sign_format = SignatureFormat::CADES_C;
        }
        else if (sign_format > SignatureFormat::CADES_T) {
            sign_format = SignatureFormat::CADES_T;
        }
        switch (sign_format) {
        case SignatureFormat::CMS_SID_KEYID:
        case SignatureFormat::CADES_BES:
        case SignatureFormat::CADES_T:
            verifiedSignerInfo.validateValidityTimeCerts(bestsign_time);
            for (auto& it : verifiedSignerInfo.getCertChainItems()) {
                if (!it->isExpired()) {
                    if (it->getValidationType() == Cert::ValidationType::UNDEFINED) {
                        if (!verify_options.onlyCrl) {
                            ret = validate_by_ocsp(verifiedSignerInfo, *it);
                            if (ret != RET_OK) {
                                it->setValidationType(Cert::ValidationType::UNDEFINED);
                                (void)validate_by_crl(verifiedSignerInfo, *it);
                            }
                        }
                        else {
                            ret = validate_by_crl(verifiedSignerInfo, *it);
                        }
                    }
                }
            }
            DO(verifiedSignerInfo.addOcspCertsToChain(bestsign_time));
            DO(verifiedSignerInfo.addCrlCertsToChain(bestsign_time));
            validate_status_signers(verifiedSignerInfo, verify_options.onlyCrl);
            break;
        case SignatureFormat::CADES_C:
            verifiedSignerInfo.validateValidityTimeCerts(bestsign_time);
            for (auto& it : verifiedSignerInfo.getCertChainItems()) {
                if (!it->isExpired()) {
                    if (it->getValidationType() == Cert::ValidationType::UNDEFINED) {
                        ret = validate_by_crl(verifiedSignerInfo, *it);
                        if ((ret != RET_OK) && !verify_options.onlyCrl) {
                            it->setValidationType(Cert::ValidationType::UNDEFINED);
                            (void)validate_by_ocsp(verifiedSignerInfo, *it);
                        }
                    }
                }
            }
            DO(verifiedSignerInfo.addOcspCertsToChain(bestsign_time));
            DO(verifiedSignerInfo.addCrlCertsToChain(bestsign_time));
            validate_status_signers(verifiedSignerInfo, verify_options.onlyCrl);
            break;
        case SignatureFormat::CADES_XL:
        case SignatureFormat::CADES_A:
            DO(verifiedSignerInfo.setRevocationValuesForChain(bestsign_time));
            //  Loop for validation for case if OCSP-response missed
            for (auto& it : verifiedSignerInfo.getCertChainItems()) {
                if (!it->isExpired()) {
                    if (it->getValidationType() == Cert::ValidationType::UNDEFINED) {
                        ret = validate_by_crl(verifiedSignerInfo, *it);
                        if ((ret != RET_OK) && !verify_options.onlyCrl) {
                            it->setValidationType(Cert::ValidationType::UNDEFINED);
                            (void)validate_by_ocsp(verifiedSignerInfo, *it);
                        }
                    }
                }
            }
            DO(verifiedSignerInfo.addOcspCertsToChain(bestsign_time));
            DO(verifiedSignerInfo.addCrlCertsToChain(bestsign_time));
            validate_status_signers(verifiedSignerInfo, verify_options.onlyCrl);
            break;
        default:
            break;
        }
    }

cleanup:
    return ret;
}   //  validate_certs

//  One SignerInfo: an error stops its verification only, see VerifiedSignerInfo::setNotProcessed()
static int verify_signer_info (
        Doc::Verify::VerifySignedDoc& verifySdoc,
        Doc::Verify::VerifiedSignerInfo& verified_sinfo,
        const size_t idx
)
{
    int ret = RET_OK;

    {
        DO(verifySdoc.sdataParser.parseSignerInfo(idx, verified_sinfo.getSignerInfo()));
        if (!verifySdoc.sdataParser.isContainDigestAlgorithm(verified_sinfo.getSignerInfo().getDigestAlgorithm())) {
            SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
        }

        DO(verified_sinfo.parseAttributes());
        if (
            (verifySdoc.verifyOptions.verifySignerInfoIndex < 0) ||
            (verifySdoc.verifyOptions.verifySignerInfoIndex == (int)idx)
        ) {
            DO(verified_sinfo.verifySignedAttribute(verifySdoc.addedCerts));
            DO(verified_sinfo.verifyMessageDigest(*verifySdoc.refContentHasher));
            DO(verified_sinfo.verifySigningCertificateV2());
            DO(verified_sinfo.setSignedDataRevocation(verifySdoc.sdataParser.getCrls()));

            verified_sinfo.determineSignFormat();
            DO(verified_sinfo.tspCertToStore());
            DO(verified_sinfo.certValuesToStore());
            DO(verified_sinfo.crlValuesToStore());
            DO(verified_sinfo.verifyContentTimeStamp(*verifySdoc.refContentHasher));
            DO(verified_sinfo.verifySignatureTimeStamp());
            DO(verified_sinfo.verifyCertificateRefs());
            DO(verified_sinfo.verifyArchiveTimeStamp(verifySdoc.addedCerts, verifySdoc.sdataParser.getCerts(), verifySdoc.sdataParser.getCrls(), *verifySdoc.refContentHasher));

            //  AUGMENT_CMS: the revocation data obtained for a signature without them is fresh enough
            if ((verifySdoc.verifyOptions.revocationMinThisUpdate > 0) && !verified_sinfo.hasRevocationValues()) {
                verified_sinfo.setRevocationMinThisUpdate(verifySdoc.verifyOptions.revocationMinThisUpdate);
            }
            verified_sinfo.validateSignFormat(verifySdoc.validateTime);
            //  The cryptographic verification failed: it is not a signature of this content (or the value is wrong),
            //  TOTAL-FAILED whatever the certificates (ETSI EN 319 102-1, 5.3.4 5); the steps may be done in any
            //  order giving the same result, NOTE 1). Their chain and status are not looked for - no requests
            //  to the OCSP responders and the distribution points of CRLs for a signature already failed
            if (!verified_sinfo.isCryptoFailed()) {
                if (verifySdoc.verifyOptions.validationType >= Doc::Verify::VerifyOptions::ValidationType::CHAIN) {
                    DO(verified_sinfo.buildCertChain());
                }
                DO(validate_certs(verifySdoc, verified_sinfo));
                DO(verified_sinfo.verifyRevocationRefs());
                verified_sinfo.validateStatusCerts(verifySdoc.verifyOptions.checkCriticalExtensions);
            }
        }
    }

cleanup:
    return ret;
}   //  verify_signer_info

int Doc::Verify::verifySignedDocument (
        Doc::Verify::VerifySignedDoc& verifySdoc,
        const ByteArray* baSignature,
        ContentHasher& contentHasher,
        const bool isDigest
)
{
    int ret = RET_OK;

    if (!verifySdoc.isInitialized()) return RET_UAPKI_GENERAL_ERROR;

    DO(verifySdoc.parse(baSignature));
    DO(verifySdoc.getContent(contentHasher));
    DO(verifySdoc.addCertsToStore());

    //  For each signer_info
    verifySdoc.verifiedSignerInfos.resize(verifySdoc.sdataParser.getCountSignerInfos());
    for (size_t idx = 0; idx < verifySdoc.sdataParser.getCountSignerInfos(); idx++) {
        Doc::Verify::VerifiedSignerInfo& verified_sinfo = verifySdoc.verifiedSignerInfos[idx];

        DO(verified_sinfo.init(
            verifySdoc.libConfig,
            verifySdoc.cerStore,
            verifySdoc.crlStore,
            isDigest
        ));
        verified_sinfo.setCaRemovesExpiredCerts(verifySdoc.verifyOptions.caRemovesExpiredCerts);
        verified_sinfo.setTimeStampOrderTolerance(verifySdoc.libConfig->getTimeStampOrderTolerance());
        if (verifySdoc.verifyOptions.validationType == Doc::Verify::VerifyOptions::ValidationType::FULL_ETSI) {
            verified_sinfo.setRevocationFreshness(verifySdoc.verifyOptions.policy.revocationFreshness);
            verified_sinfo.setTsaTrustByProofOfExistence(verifySdoc.verifyOptions.policy.tsaTrustByProofOfExistence);
            verified_sinfo.setRevocationFreshnessStrict(verifySdoc.verifyOptions.policy.revocationFreshnessStrict);
        }
        ret = verify_signer_info(verifySdoc, verified_sinfo, idx);
        if ((ret == RET_MEMORY_ALLOC_ERROR) || (ret == RET_UAPKI_GENERAL_ERROR)) {
            goto cleanup;
        }
        if (ret != RET_OK) {
            //  A report for every signature: this one is not verified completely, the others are
            verified_sinfo.setNotProcessed(ret);
            ret = RET_OK;
        }
    }

    verifySdoc.detectCertSources();
    if (verifySdoc.verifyOptions.validationType >= Doc::Verify::VerifyOptions::ValidationType::FULL) {
        for (size_t idx = 0; idx < verifySdoc.verifiedSignerInfos.size(); idx++) {
            if (
                (verifySdoc.verifyOptions.verifySignerInfoIndex < 0) ||
                (verifySdoc.verifyOptions.verifySignerInfoIndex == (int)idx)
            ) {
                verifySdoc.verifiedSignerInfos[idx].lowerSignFormatByValidationData();
            }
        }
    }

cleanup:
    return ret;
}   //  verifySignedDocument

int UapkiNS::Doc::Verify::verifiedSignerInfoToJson (
        JSON_Object* joSignInfo,
        Doc::Verify::VerifiedSignerInfo& verifyInfo,
        const Doc::Verify::VerifyOptions& verifyOptions
)
{
    return result_verifyinfo_to_json(joSignInfo, verifyInfo, verifyOptions);
}

int UapkiNS::Doc::Verify::attrTimeStampToJson (
        JSON_Object* joResult,
        const char* attrName,
        const Doc::Verify::AttrTimeStamp& attrTS
)
{
    return result_attr_timestamp_to_json(joResult, attrName, attrTS);
}

int UapkiNS::Doc::Verify::attributesToJson (
        JSON_Object* joResult,
        const char* key,
        const vector<UapkiNS::Attribute>& attrs
)
{
    return result_attributes_to_json(joResult, key, attrs);
}

int UapkiNS::Doc::Verify::certChainItemToJson (
        JSON_Object* joResult,
        const Doc::Verify::CertChainItem& certChainItem,
        const Doc::Verify::VerifyOptions& verifyOptions,
        const uint64_t bestSignatureTime
)
{
    return result_certchainitem_to_json(joResult, certChainItem, verifyOptions, bestSignatureTime);
}

static int verify_p7s (
        Context& context,
        const ByteArray* baSignature,
        ContentHasher& contentHasher,
        const bool isDigest,
        const Doc::Verify::VerifyOptions& verifyOptions,
        const bool returnContent,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    Doc::Verify::VerifySignedDoc verify_sdoc(
        context.config(),
        context.cerStore(),
        context.crlStore(),
        verifyOptions
    );

    DO(Doc::Verify::verifySignedDocument(verify_sdoc, baSignature, contentHasher, isDigest));

    if (verifyOptions.validationType == Doc::Verify::VerifyOptions::ValidationType::FULL_ETSI) {
        //  What was met for a signature is in its report; the error of the method is what stops the whole verification
        DO(Doc::Verify::etsiReportToJson(joResult, verify_sdoc, returnContent));
    }
    else {
        DO(result_to_json(joResult, verify_sdoc, returnContent));
        ret = verify_sdoc.getLastError();
    }

cleanup:
    return ret;
}   //  verify_p7s

static int verify_raw (
        Context& context,
        const ByteArray* baSignature,
        ContentHasher& contentHasher,
        const bool isDigest,
        JSON_Object* joSignParams,
        JSON_Object* joSignerPubkey,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    Cert::CerItem* cer_item = nullptr;
    Cert::CerItem* cer_parsed = nullptr;
    SmartBA sba_pubdata, sba_signparams;
    HashAlg hash_signalgo = HashAlg::HASH_ALG_UNDEFINED;
    SignatureVerifyStatus status_sign = SignatureVerifyStatus::UNDEFINED;
    const ByteArray* content = contentHasher.getContentBytes();
    bool is_hash = isDigest;

    const string s_signalgo = ParsonHelper::jsonObjectGetString(joSignParams, "signAlgo");
    if (s_signalgo.empty()) return RET_UAPKI_INVALID_PARAMETER;

    if (sba_pubdata.set(json_object_get_base64(joSignerPubkey, "certificate"))) {
        DO(Cert::parseCert(sba_pubdata.get(), &cer_parsed));
        sba_pubdata.clear();
        cer_item = cer_parsed;
    }
    else {
        if (sba_pubdata.set(json_object_get_base64(joSignerPubkey, "certId"))) {
            Cert::CerStore* cer_store = context.cerStore();
            if (!cer_store) {
                SET_ERROR(RET_UAPKI_GENERAL_ERROR);
            }
            DO(cer_store->getCertByCertId(sba_pubdata.get(), &cer_item));
        }
        else {
            if (!sba_pubdata.set(json_object_get_base64(joSignerPubkey, "spki"))) {
                SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
            }
        }
    }

    if (oid_is_equal(OID_RSA_PSS, s_signalgo.c_str())) {
        //  RSASSA-PSS does not name the hash: "digestAlgo" (SHA-256 by default), as in the SIGN method
        const string s_digestalgo = ParsonHelper::jsonObjectGetString(joSignParams, "digestAlgo");
        hash_signalgo = s_digestalgo.empty() ? HashAlg::HASH_ALG_SHA256 : hash_from_oid(s_digestalgo.c_str());
        if (hash_signalgo == HashAlg::HASH_ALG_UNDEFINED) {
            SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
        }
        DO(Verify::rsaPssParamsEncode(hash_signalgo, &sba_signparams));
    }
    else {
        hash_signalgo = hash_from_oid(s_signalgo.c_str());
    }

    if (!content && !isDigest) {
        DO(contentHasher.digest(hash_signalgo));
        content = contentHasher.getHashValue();
        is_hash = true;
    }

    ret = Verify::verifySignature(
        s_signalgo.c_str(),
        content,
        is_hash,
        (cer_item) ? cer_item->getSpki() : sba_pubdata.get(),
        baSignature,
        nullptr,
        sba_signparams.get()
    );
    switch (ret) {
    case RET_OK:
        status_sign = SignatureVerifyStatus::VALID;
        break;
    case RET_VERIFY_FAILED:
        status_sign = SignatureVerifyStatus::INVALID;
        break;
    default:
        status_sign = SignatureVerifyStatus::FAILED;
    }
    DO_JSON(json_object_set_string(joResult, "statusSignature", verifyStatusToStr(status_sign)));

    ret = RET_OK;

cleanup:
    delete cer_parsed;
    return ret;
}   //  verify_raw


int uapki_verify_signature (
        Context& context,
        JSON_Object* joParams,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    SmartBA sba_signature;
    ContentHasher content_hasher;
    JSON_Object* jo_signature = nullptr;
    JSON_Object* jo_signparams = nullptr;
    JSON_Object* jo_signerpubkey = nullptr;

    jo_signature = json_object_get_object(joParams, "signature");
    jo_signparams = json_object_get_object(joParams, "signParams");
    jo_signerpubkey = json_object_get_object(joParams, "signerPubkey");
    const bool is_digest = ParsonHelper::jsonObjectGetBoolean(jo_signature, "isDigest", false);
    if (!sba_signature.set(json_object_get_base64(jo_signature, "bytes"))) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    if (ParsonHelper::jsonObjectHasValue(jo_signature, "content", JSONString)) {
        DO(content_hasher.setContent(json_object_get_base64(jo_signature, "content"), true));
    }
    else if (ParsonHelper::jsonObjectHasValue(jo_signature, "file", JSONString)) {
        DO(content_hasher.setContent(json_object_get_string(jo_signature, "file")));
    }
    else if (
        ParsonHelper::jsonObjectHasValue(jo_signature, "ptr", JSONString) &&
        ParsonHelper::jsonObjectHasValue(jo_signature, "size", JSONNumber)
    ) {
        SmartBA sba_ptr;
        (void)sba_ptr.set(json_object_get_hex(jo_signature, "ptr"));
        const uint8_t* ptr = ContentHasher::baToPtr(sba_ptr.get());
        size_t size = 0;
        if (!ptr || !ContentHasher::numberToSize(json_object_get_number(jo_signature, "size"), size)) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
        DO(content_hasher.setContent(ptr, size));
    }

    if (!jo_signparams && !jo_signerpubkey) {
        //  Is P7S-signature(CMS/CAdES)
        Doc::Verify::VerifyOptions verify_options;
        verify_options.onlyCrl = context.config()->getValidationByCrl();
        DO(parse_verify_options(json_object_get_object(joParams, "options"), verify_options));
        DO(verify_p7s(
            context,
            sba_signature.get(),
            content_hasher,
            is_digest,
            verify_options,
            ParsonHelper::jsonObjectGetBoolean(joParams, "returnContent", true),
            joResult
        ));
    }
    else if (jo_signparams && jo_signerpubkey) {
        //  Is RAW-signature
        if (!content_hasher.isPresent() || (is_digest && !content_hasher.getContentBytes())) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
        DO(verify_raw(
            context,
            sba_signature.get(),
            content_hasher,
            is_digest,
            jo_signparams,
            jo_signerpubkey,
            joResult
        ));
    }
    else {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

cleanup:
    return ret;
}
