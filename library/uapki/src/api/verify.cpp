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

#define FILE_MARKER "uapki/api/verify.cpp"

#include "api-json-internal.h"
#include "archive-timestamp-helper.h"
#include "attribute-helper.h"
#include "content-hasher.h"
#include "doc-verify.h"
#include "global-objects.h"
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
        verifyOptions.onlyCrl = ParsonHelper::jsonObjectGetBoolean(joParams, "onlyCrl", false);
        verifyOptions.verifySignerInfoIndex = ParsonHelper::jsonObjectGetInt32(joParams, "verifySignerInfoIndex", -1);
        if (verifyOptions.verifySignerInfoIndex < 0) {
            verifyOptions.verifySignerInfoIndex = -1;
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
        json_object_set_value(joResult, attrName, json_value_init_object());
        JSON_Object* jo_attr = json_object_get_object(joResult, attrName);
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

    DO_JSON(json_object_set_string(joResult, "status", Crl::certStatusToStr(singleresp_info.certStatus)));

    DO_JSON(json_object_set_string(joResult, "thisUpdate", TimeUtil::mtimeToFtime(singleresp_info.msThisUpdate).c_str()));
    if (singleresp_info.msNextUpdate > 0) {
        DO_JSON(json_object_set_string(joResult, "nextUpdate", TimeUtil::mtimeToFtime(singleresp_info.msNextUpdate).c_str()));
    }
    if (singleresp_info.revocationReason != UapkiNS::CrlReason::UNDEFINED) {
        DO_JSON(json_object_set_string(joResult, "revocationReason", Crl::crlReasonToStr(singleresp_info.revocationReason)));
        DO_JSON(json_object_set_string(joResult, "revocationTime", TimeUtil::mtimeToFtime(singleresp_info.msRevocationTime).c_str()));
    }

    statusValidation = verifyStatusToStr((
        (resultValByOcsp.statusSignature == SignatureVerifyStatus::VALID) &&
        (singleresp_info.certStatus == UapkiNS::CertStatus::GOOD)
    ) ? SignatureVerifyStatus::VALID : SignatureVerifyStatus::INVALID);

cleanup:
    return ret;
}   //  result_certchainitem_valbyocsp_to_json

static int result_certchainitem_to_json (
        JSON_Object* joResult,
        const Doc::Verify::CertChainItem& certChainItem,
        const Doc::Verify::VerifyOptions& verifyOptions
)
{
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
            DO_JSON(json_object_set_value(jo_certref, "issuer", json_value_init_object()));
            DO(Cert::issuerFromGeneralNames(cert_ref.issuerSerial.baIssuer, &sba_issuer));
            DO(nameToJson(json_object_get_object(jo_certref, "issuer"), sba_issuer.get()));
            DO(json_object_set_hex(jo_certref, "serialNumber", cert_ref.issuerSerial.baSerialNumber));
            DO_JSON(json_object_set_string(jo_certref, "status", verifyStatusToStr(cadesXlInfo.statusesCertRefs[i])));
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
    const vector<string> warns = verifyInfo.getWarningMessages();

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

    DO(result_attributes_to_json(joSignInfo, "signedAttributes", verifyInfo.getSignerInfo().getSignedAttrs()));
    DO(result_attributes_to_json(joSignInfo, "unsignedAttributes", verifyInfo.getSignerInfo().getUnsignedAttrs()));

    if ((verifyOptions.validationType >= Doc::Verify::VerifyOptions::ValidationType::CHAIN)) {
        DO_JSON(json_object_set_value(joSignInfo, "certificateChain", json_value_init_array()));
        JSON_Array* ja_certchainitems = json_object_get_array(joSignInfo, "certificateChain");
        size_t idx = 0;
        for (const auto& it : verifyInfo.getCertChainItems()) {
            DO_JSON(json_array_append_value(ja_certchainitems, json_value_init_object()));
            DO(result_certchainitem_to_json(json_array_get_object(ja_certchainitems, idx++), *it, verifyOptions));
        }
    }

    if (!verifyInfo.getExpectedCertItems().empty()) {
        DO_JSON(json_object_set_value(joSignInfo, "expectedCerts", json_value_init_array()));
        JSON_Array* ja_expcertitems = json_object_get_array(joSignInfo, "expectedCerts");
        size_t idx = 0;
        for (const auto& it : verifyInfo.getExpectedCertItems()) {
            DO_JSON(json_array_append_value(ja_expcertitems, json_value_init_object()));
            DO(CertValidator::expectedCertItemToJson(json_array_get_object(ja_expcertitems, idx++), *it));
        }
    }

    if (!verifyInfo.getExpectedCrlItems().empty()) {
        DO_JSON(json_object_set_value(joSignInfo, "expectedCrls", json_value_init_array()));
        JSON_Array* ja_expcrlitems = json_object_get_array(joSignInfo, "expectedCrls");
        size_t idx = 0;
        for (const auto& it : verifyInfo.getExpectedCrlItems()) {
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
        Doc::Verify::VerifySignedDoc& verifySignedDoc
)
{
    int ret = RET_OK;

    {   //  =content=
        const Pkcs7::EncapsulatedContentInfo& encap_cinfo = verifySignedDoc.sdataParser.getEncapContentInfo();
        json_object_set_value(joResult, "content", json_value_init_object());
        JSON_Object* jo_content = json_object_get_object(joResult, "content");
        DO_JSON(json_object_set_string(jo_content, "type", encap_cinfo.contentType.c_str()));
        if (encap_cinfo.baEncapContent) {
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

    result_valbycrl.cerIssuer = certChainItem.getIssuer();
    DO(verifiedSignerInfo.validateByCrl(
        certChainItem.getSubject(),
        result_valbycrl.cerIssuer,
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
    Ocsp::OcspHelper ocsp_helper;
    SmartBA sba_sn;

    DO(verifiedSignerInfo.validateByOcsp(
        certChainItem.getSubject(),
        certChainItem.getIssuer(),
        certChainItem.getResultValidationByOcsp()
    ));

    DO(ocsp_helper.parseBasicOcspResponse(certChainItem.getResultValidationByOcsp().basicOcspResponse.get()));
    DO(ocsp_helper.scanSingleResponses());
    DO(ocsp_helper.getSerialNumberFromCertId(0, &sba_sn));  //  Work with one OCSP request that has one certificate
    if (ba_cmp(sba_sn.get(), certChainItem.getSubject()->getSerialNumber()) == 0) {
        CertValidator::ResultValidationByOcsp& result_valbyocsp = certChainItem.getResultValidationByOcsp();
        result_valbyocsp.dataSource = CertValidator::DataSource::STORE;
        result_valbyocsp.responseStatus = Ocsp::ResponseStatus::SUCCESSFUL;
        result_valbyocsp.statusSignature = SignatureVerifyStatus::VALID; // Previous check is passed
        result_valbyocsp.msProducedAt = ocsp_helper.getProducedAt();
        result_valbyocsp.singleResponseInfo = ocsp_helper.getSingleResponseInfo(0); //  Work with one OCSP request that has one certificate
    }
    certChainItem.setValidationType(Cert::ValidationType::OCSP);

cleanup:
    return ret;
}   //  validate_by_ocsp

static int validate_certs (
        Doc::Verify::VerifySignedDoc& verifySignedDoc,
        Doc::Verify::VerifiedSignerInfo& verifiedSignerInfo
)
{
    int ret = RET_OK;
    const Doc::Verify::VerifyOptions& verify_options = verifySignedDoc.verifyOptions;
    const uint64_t bestsign_time = verifiedSignerInfo.getBestSignatureTime();

    if (verify_options.validationType == Doc::Verify::VerifyOptions::ValidationType::CHAIN) {
        verifiedSignerInfo.validateValidityTimeCerts(bestsign_time);
        for (auto& it : verifiedSignerInfo.getCertChainItems()) {
            it->setValidationType(Cert::ValidationType::NONE);
        }
    }
    else if (verify_options.validationType == Doc::Verify::VerifyOptions::ValidationType::FULL) {
        switch (verifiedSignerInfo.getSignatureFormat()) {
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
            break;
        }
    }

cleanup:
    return ret;
}   //  validate_certs

static int verify_p7s (
        const ByteArray* baSignature,
        ContentHasher& contentHasher,
        const bool isDigest,
        const Doc::Verify::VerifyOptions& verifyOptions,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    Doc::Verify::VerifySignedDoc verify_sdoc(
        get_config(),
        get_cerstore(),
        get_crlstore(),
        verifyOptions
    );

    if (!verify_sdoc.isInitialized()) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    DO(verify_sdoc.parse(baSignature));
    DO(verify_sdoc.getContent(contentHasher));
    DO(verify_sdoc.addCertsToStore());

    //  For each signer_info
    verify_sdoc.verifiedSignerInfos.resize(verify_sdoc.sdataParser.getCountSignerInfos());
    for (size_t idx = 0; idx < verify_sdoc.sdataParser.getCountSignerInfos(); idx++) {
        Doc::Verify::VerifiedSignerInfo& verified_sinfo = verify_sdoc.verifiedSignerInfos[idx];

        DO(verified_sinfo.init(
            verify_sdoc.libConfig,
            verify_sdoc.cerStore,
            verify_sdoc.crlStore,
            isDigest
        ));
        DO(verify_sdoc.sdataParser.parseSignerInfo(idx, verified_sinfo.getSignerInfo()));
        if (!verify_sdoc.sdataParser.isContainDigestAlgorithm(verified_sinfo.getSignerInfo().getDigestAlgorithm())) {
            SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
        }

        DO(verified_sinfo.parseAttributes());
        if (
            (verifyOptions.verifySignerInfoIndex < 0) ||
            (verifyOptions.verifySignerInfoIndex == idx)
        ) {
            DO(verified_sinfo.verifySignedAttribute());
            DO(verified_sinfo.verifyMessageDigest(*verify_sdoc.refContentHasher));
            DO(verified_sinfo.verifySigningCertificateV2());

            verified_sinfo.determineSignFormat();
            DO(verified_sinfo.certValuesToStore());
            DO(verified_sinfo.verifyContentTimeStamp(*verify_sdoc.refContentHasher));
            DO(verified_sinfo.verifySignatureTimeStamp());
            DO(verified_sinfo.verifyCertificateRefs());
            DO(verified_sinfo.verifyArchiveTimeStamp(verify_sdoc.addedCerts, verify_sdoc.addedCrls));

            verified_sinfo.validateSignFormat(verify_sdoc.validateTime, verify_sdoc.refContentHasher->isPresent());
            if (verifyOptions.validationType >= Doc::Verify::VerifyOptions::ValidationType::CHAIN) {
                DO(verified_sinfo.buildCertChain());
            }
            DO(validate_certs(verify_sdoc, verified_sinfo));
            verified_sinfo.validateStatusCerts();
        }
    }

    verify_sdoc.detectCertSources();

    DO(result_to_json(joResult, verify_sdoc));
    ret = verify_sdoc.getLastError();

cleanup:
    return ret;
}   //  verify_p7s

static int verify_raw (
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
    SmartBA sba_pubdata;
    SignatureVerifyStatus status_sign = SignatureVerifyStatus::UNDEFINED;
    bool is_digitalsign = true;

    const string s_signalgo = ParsonHelper::jsonObjectGetString(joSignParams, "signAlgo");
    if (s_signalgo.empty()) return RET_UAPKI_INVALID_PARAMETER;

    if (sba_pubdata.set(json_object_get_base64(joSignerPubkey, "certificate"))) {
        DO(Cert::parseCert(sba_pubdata.get(), &cer_parsed));
        (void)sba_pubdata.set(nullptr);
        cer_item = cer_parsed;
    }
    else {
        if (sba_pubdata.set(json_object_get_base64(joSignerPubkey, "certId"))) {
            Cert::CerStore* cer_store = get_cerstore();
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

    ret = Verify::verifySignature(
        s_signalgo.c_str(),
        contentHasher.getContentBytes(),
        isDigest,
        (cer_item) ? cer_item->getSpki() : sba_pubdata.get(),
        baSignature
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
        verify_options.onlyCrl = get_config()->getValidationByCrl();
        DO(parse_verify_options(json_object_get_object(joParams, "options"), verify_options));
        DO(verify_p7s(
            sba_signature.get(),
            content_hasher,
            is_digest,
            verify_options,
            joResult
        ));
    }
    else if (jo_signparams && jo_signerpubkey) {
        //  Is RAW-signature
        if (!content_hasher.getContentBytes() || !jo_signparams || !jo_signerpubkey) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
        DO(verify_raw(
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
