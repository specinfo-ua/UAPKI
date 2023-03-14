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
#include "archive-timestamp-helper.h"
#include "attribute-helper.h"
#include "doc-verify.h"
#include "global-objects.h"
#include "http-helper.h"
#include "parson-helper.h"
#include "ocsp-helper.h"
#include "signature-format.h"
#include "signeddata-helper.h"
#include "store-utils.h"
#include "time-utils.h"
#include "tsp-helper.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"
#include "verify-utils.h"


#undef FILE_MARKER
#define FILE_MARKER "api/verify.cpp"


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


static int name_to_json (
        JSON_Object* joResult,
        const char* keyName,
        const ByteArray* baEncoded
)
{
    int ret = RET_OK;
    Name_t* name = nullptr;

    CHECK_NOT_NULL(name = (Name_t*)asn_decode_ba_with_alloc(get_Name_desc(), baEncoded));

    DO_JSON(json_object_set_value(joResult, keyName, json_value_init_object()));
    DO(CerStoreUtils::nameToJson(json_object_get_object(joResult, keyName), *name));

cleanup:
    asn_free(get_Name_desc(), name);
    return ret;
}   //  name_to_json

static int parse_verify_options (
        JSON_Object* joParams,
        UapkiNS::Doc::Verify::VerifyOptions& verifyOptions
)
{
    verifyOptions.validationType = CerStore::validationTypeFromStr(
        ParsonHelper::jsonObjectGetString(joParams, "validationType")
    );
    if (verifyOptions.validationType == CerStore::ValidationType::UNDEFINED) return RET_UAPKI_INVALID_PARAMETER;

    const string s_validatetime = ParsonHelper::jsonObjectGetString(joParams, "validateTime");
    if (s_validatetime.empty() || (verifyOptions.validationType == CerStore::ValidationType::OCSP)) {
        verifyOptions.validateTime = TimeUtils::nowMsTime();
    }
    else {
        const int ret = TimeUtils::stimeToMstime(s_validatetime.c_str(), verifyOptions.validateTime);
        if (ret != RET_OK) return RET_UAPKI_INVALID_PARAMETER;
        verifyOptions.forcedValidateTime = true;
    }

    JSON_Object* jo_options = json_object_get_object(joParams, "options");
    if (jo_options) {
        verifyOptions.forceOcsp = ParsonHelper::jsonObjectGetBoolean(jo_options, "forceOCSP", false);
        verifyOptions.offlineCrl = ParsonHelper::jsonObjectGetBoolean(jo_options, "offlineCRL", false);
    }

    return RET_OK;
}   //  parse_verify_options

static int result_attr_timestamp_to_json (
        JSON_Object* joResult,
        const char* attrName,
        const UapkiNS::Doc::Verify::AttrTimeStamp& attrTS
)
{
    int ret = RET_OK;

    if (attrTS.isPresent()) {
        json_object_set_value(joResult, attrName, json_value_init_object());
        JSON_Object* jo_attrts = json_object_get_object(joResult, attrName);
        DO_JSON(json_object_set_string(jo_attrts, "genTime", TimeUtils::mstimeToFormat(attrTS.msGenTime).c_str()));
        DO_JSON(json_object_set_string(jo_attrts, "policyId", attrTS.policy.c_str()));
        DO_JSON(json_object_set_string(jo_attrts, "hashAlgo", attrTS.hashAlgo.c_str()));
        DO(json_object_set_base64(jo_attrts, "hashedMessage", attrTS.hashedMessage.get()));
        DO_JSON(json_object_set_string(jo_attrts, "statusDigest", UapkiNS::verifyStatusToStr(attrTS.statusDigest)));
        DO_JSON(json_object_set_string(jo_attrts, "statusSignature", UapkiNS::verifyStatusToStr(attrTS.statusSignature)));
        if (attrTS.csiSigner) {
            DO(json_object_set_base64(jo_attrts, "signerCertId", attrTS.csiSigner->baCertId));
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
        const bool isExpired,
        const UapkiNS::Doc::Verify::ResultValidationByCrl& resultValByCrl
)
{
    int ret = RET_OK;

    if (!isExpired) {
        if (resultValByCrl.isUsed) {
            const CrlStore::Item* crlstore_item = resultValByCrl.crlStoreItem;
            const CrlStore::RevokedCertItem& revcert_item = resultValByCrl.revokedCertItem;
            if (crlstore_item) {
                string s_commonname;
                DO(CerStoreUtils::rdnameFromName(crlstore_item->crl->tbsCertList.issuer, OID_X520_CommonName, s_commonname));
                DO(json_object_set_base64(joResult, "crlId", crlstore_item->baCrlId));
                DO_JSON(json_object_set_string(joResult, "CN", s_commonname.c_str()));
                DO_JSON(json_object_set_string(joResult, "thisUpdate", TimeUtils::mstimeToFormat(crlstore_item->thisUpdate).c_str()));
                DO_JSON(json_object_set_string(joResult, "nextUpdate", TimeUtils::mstimeToFormat(crlstore_item->nextUpdate).c_str()));
                DO(json_object_set_hex(joResult, "crlNumber", crlstore_item->baCrlNumber));
                if (crlstore_item->baDeltaCrl) {
                    DO(json_object_set_hex(joResult, "deltaCrlIndicator", crlstore_item->baDeltaCrl));
                }
                if (resultValByCrl.cerIssuer) {
                    DO(json_object_set_base64(joResult, "issuerCertId", resultValByCrl.cerIssuer->baCertId));
                }
                DO_JSON(json_object_set_string(joResult, "statusSignature", CerStore::verifyStatusToStr(crlstore_item->statusSign)));
            }
            DO_JSON(json_object_set_string(joResult, "status", CrlStore::certStatusToStr(resultValByCrl.certStatus)));
            if (revcert_item.crlReason != UapkiNS::CrlReason::UNDEFINED) {
                DO_JSON(json_object_set_string(joResult, "revocationReason", CrlStore::crlReasonToStr(revcert_item.crlReason)));
                const string s_revoktime = TimeUtils::mstimeToFormat(revcert_item.getDate());
                DO_JSON(json_object_set_string(joResult, "revocationTime", s_revoktime.c_str()));
            }
        }
        else {
            DO_JSON(json_object_set_string(joResult, "status", "NOT USED"));
        }
    }
    else {
        DO_JSON(json_object_set_string(joResult, "status", "EXPIRED"));
    }

cleanup:
    return ret;
}   //  result_certchainitem_valbycrl_to_json

static int result_certchainitem_valbyocsp_to_json (
        JSON_Object* joResult,
        const bool isExpired,
        const UapkiNS::Doc::Verify::ResultValidationByOcsp& resultValByOcsp
)
{
    int ret = RET_OK;

    if (!isExpired) {
        if (resultValByOcsp.isUsed) {
            DO_JSON(json_object_set_string(joResult, "source", UapkiNS::Doc::Verify::dataSourceToStr(resultValByOcsp.dataSource)));
            DO_JSON(json_object_set_string(joResult, "responseStatus", UapkiNS::Ocsp::responseStatusToStr(resultValByOcsp.responseStatus)));
            DO_JSON(json_object_set_string(joResult, "producedAt", TimeUtils::mstimeToFormat(resultValByOcsp.msProducedAt).c_str()));
            DO_JSON(json_object_set_string(joResult, "statusSignature", UapkiNS::verifyStatusToStr(resultValByOcsp.statusSignature)));
            if (resultValByOcsp.csiResponder) {
                DO(json_object_set_base64(joResult, "signerCertId", resultValByOcsp.csiResponder->baCertId));
            }

            const UapkiNS::Ocsp::OcspHelper::SingleResponseInfo& singleresp_info = resultValByOcsp.singleResponseInfo;
            DO_JSON(json_object_set_string(joResult, "status", CrlStore::certStatusToStr(singleresp_info.certStatus)));
            DO_JSON(json_object_set_string(joResult, "thisUpdate", TimeUtils::mstimeToFormat(singleresp_info.msThisUpdate).c_str()));
            if (singleresp_info.msNextUpdate > 0) {
                DO_JSON(json_object_set_string(joResult, "nextUpdate", TimeUtils::mstimeToFormat(singleresp_info.msNextUpdate).c_str()));
            }
            if (singleresp_info.certStatus == UapkiNS::CertStatus::REVOKED) {
                DO_JSON(json_object_set_string(joResult, "revocationReason", CrlStore::crlReasonToStr(singleresp_info.revocationReason)));
                DO_JSON(json_object_set_string(joResult, "revocationTime", TimeUtils::mstimeToFormat(singleresp_info.msRevocationTime).c_str()));
            }
        }
        else {
            DO_JSON(json_object_set_string(joResult, "status", "NOT USED"));
        }
    }
    else {
        DO_JSON(json_object_set_string(joResult, "status", "EXPIRED"));
    }

cleanup:
    return ret;
}   //  result_certchainitem_valbyocsp_to_json

static int result_certchainitem_to_json (
        JSON_Object* joResult,
        const UapkiNS::Doc::Verify::CertChainItem& certChainItem,
        const UapkiNS::Doc::Verify::VerifyOptions& verifyOptions
)
{
    int ret = RET_OK;

    DO(json_object_set_base64(joResult, "subjectCertId", certChainItem.getSubjectCertId()));
    DO_JSON(json_object_set_string(joResult, "CN", certChainItem.getCommonName().c_str()));
    DO_JSON(json_object_set_string(joResult, "entity", UapkiNS::Doc::Verify::certEntityToStr(certChainItem.getCertEntity())));
    DO_JSON(json_object_set_string(joResult, "source", UapkiNS::Doc::Verify::dataSourceToStr(certChainItem.getDataSource())));
    DO(CerStoreUtils::validityToJson(joResult, certChainItem.getSubject()));
    DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "expired", certChainItem.isExpired()));
    DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "selfSigned", certChainItem.isSelfSigned()));
    DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "trusted", certChainItem.isTrusted()));
    if (certChainItem.getIssuerCertId()) {
        DO(json_object_set_base64(joResult, "issuerCertId", certChainItem.getIssuerCertId()));
        DO_JSON(json_object_set_string(joResult, "statusSignature", CerStore::verifyStatusToStr(certChainItem.getVerifyStatus())));
    }

    if (verifyOptions.validationType == CerStore::ValidationType::CRL) {
        DO_JSON(json_object_set_value(joResult, "validateByCRL", json_value_init_object()));
        DO(result_certchainitem_valbycrl_to_json(
            json_object_get_object(joResult, "validateByCRL"),
            certChainItem.isExpired(),
            certChainItem.getResultValidationByCrl()
        ));
    }
    else if (verifyOptions.validationType == CerStore::ValidationType::OCSP) {
        DO_JSON(json_object_set_value(joResult, "validateByOCSP", json_value_init_object()));
        DO(result_certchainitem_valbyocsp_to_json(
            json_object_get_object(joResult, "validateByOCSP"),
            certChainItem.isExpired(),
            certChainItem.getResultValidationByOcsp()
        ));
    }

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
        const UapkiNS::Doc::Verify::CadesXlInfo& cadesXlInfo
)
{
    int ret = RET_OK;

    if (!cadesXlInfo.certRefs.empty()) {
        json_object_set_value(joResult, "certificateRefs", json_value_init_array());
        JSON_Array* ja_certrefs = json_object_get_array(joResult, "certificateRefs");
        for (size_t i = 0; i < cadesXlInfo.certRefs.size(); i++) {
            const UapkiNS::OtherCertId& cert_ref = cadesXlInfo.certRefs[i];
            UapkiNS::SmartBA sba_issuer;

            DO_JSON(json_array_append_value(ja_certrefs, json_value_init_object()));
            JSON_Object* jo_certref = json_array_get_object(ja_certrefs, i);
            DO_JSON(json_object_set_value(jo_certref, "certHash", json_value_init_object()));
            DO(result_otherhash_to_json(json_object_get_object(jo_certref, "certHash"), cert_ref));
            DO_JSON(json_object_set_value(jo_certref, "issuer", json_value_init_object()));
            DO(CerStore::issuerFromGeneralNames(cert_ref.issuerSerial.baIssuer, &sba_issuer));
            DO(CerStoreUtils::nameToJson(json_object_get_object(jo_certref, "issuer"), sba_issuer.get()));
            DO(json_object_set_hex(jo_certref, "serialNumber", cert_ref.issuerSerial.baSerialNumber));
            DO_JSON(json_object_set_string(jo_certref, "status", UapkiNS::verifyStatusToStr(cadesXlInfo.statusesCertRefs[i])));
        }
    }

cleanup:
    return ret;
}   //  result_certificaterefs_to_json

static int result_expectedcertitem_to_json (
        JSON_Object* joResult,
        const UapkiNS::Doc::Verify::ExpectedCertItem& expectedCertItem
)
{
    int ret = RET_OK;

    DO_JSON(json_object_set_string(joResult, "entity", UapkiNS::Doc::Verify::certEntityToStr(expectedCertItem.getCertEntity())));
    switch (expectedCertItem.getIdType()) {
    case UapkiNS::Doc::Verify::ExpectedCertItem::IdType::CER_IDTYPE:
        if (!expectedCertItem.getKeyId()) {
            DO(name_to_json(joResult, "issuer", expectedCertItem.getName()));
            DO(json_object_set_hex(joResult, "serialNumber", expectedCertItem.getSerialNumber()));
        }
        else {
            DO(json_object_set_hex(joResult, "keyId", expectedCertItem.getKeyId()));
        }
        break;
    case UapkiNS::Doc::Verify::ExpectedCertItem::IdType::ORS_IDTYPE:
        if (!expectedCertItem.getKeyId()) {
            DO(name_to_json(joResult, "responderId", expectedCertItem.getName()));
        }
        else {
            DO(json_object_set_hex(joResult, "responderId", expectedCertItem.getKeyId()));
        }
        break;
    default: break;
    }

cleanup:
    return ret;
}   //  result_expectedcertitem_to_json

static int result_expectedcrlitem_to_json (
        JSON_Object* joResult,
        const UapkiNS::Doc::Verify::ExpectedCrlItem& expectedCrlItem
)
{
    int ret = RET_OK;

    DO(json_object_set_hex(joResult, "authorityKeyId", expectedCrlItem.getAuthorityKeyId()));
    if (expectedCrlItem.getName()) {
        DO(name_to_json(joResult, "issuer", expectedCrlItem.getName()));
    }
    if (!expectedCrlItem.getUrl().empty()) {
        DO_JSON(json_object_set_string(joResult, "url", expectedCrlItem.getUrl().c_str()));
    }
    if (expectedCrlItem.isPresentFullCrl()) {
        DO_JSON(json_object_set_value(joResult, "full", json_value_init_object()));
        JSON_Object* jo_crlinfo = json_object_get_object(joResult, "full");
        DO_JSON(json_object_set_string(jo_crlinfo, "thisUpdate", TimeUtils::mstimeToFormat(expectedCrlItem.getThisUpdate()).c_str()));
        DO_JSON(json_object_set_string(jo_crlinfo, "nextUpdate", TimeUtils::mstimeToFormat(expectedCrlItem.getNextUpdate()).c_str()));
        DO(json_object_set_hex(jo_crlinfo, "crlNumber", expectedCrlItem.getCrlNumber()));
    }

cleanup:
    return ret;
}   //  result_expectedcrlitem_to_json

static int result_crlocspref_to_json (
        JSON_Object* joCrlOcspRef,
        const UapkiNS::AttributeHelper::RevocationRefsParser::CrlOcspRef& crlOcspRef
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
            DO(UapkiNS::AttributeHelper::decodeOtherHash(it.baHash, crl_hash));
            DO_JSON(json_object_set_value(jo_crlid, "crlHash", json_value_init_object()));
            DO(result_otherhash_to_json(json_object_get_object(jo_crlid, "crlHash"), crl_hash));
            //  =crlIdentifier= (optional)
            if (it.baId) {
                DO_JSON(json_object_set_value(jo_crlid, "crlIdentifier", json_value_init_object()));
                DO(CrlStoreUtils::crlIdentifierToJson(json_object_get_object(jo_crlid, "crlIdentifier"), it.baId));
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
            DO(CerStoreUtils::ocspIdentifierToJson(json_object_get_object(jo_ocspid, "ocspIdentifier"), it.baId));
            //  =ocspHash= (optional)
            if (it.baHash) {
                UapkiNS::OtherHash ocsp_hash;
                DO(UapkiNS::AttributeHelper::decodeOtherHash(it.baHash, ocsp_hash));
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
        UapkiNS::AttributeHelper::RevocationRefsParser& revocationRefs
)
{
    int ret = RET_OK;
    const size_t cnt_refs = revocationRefs.getCountCrlOcspRefs();
    if (cnt_refs == 0) return RET_OK;

    json_object_set_value(joResult, "revocationRefs", json_value_init_array());
    JSON_Array* ja_revocationrefs = json_object_get_array(joResult, "revocationRefs");
    for (size_t idx = 0; idx < cnt_refs; idx++) {
        UapkiNS::AttributeHelper::RevocationRefsParser::CrlOcspRef crlocsp_ref;
        DO(revocationRefs.parseCrlOcspRef(idx, crlocsp_ref));
        DO_JSON(json_array_append_value(ja_revocationrefs, json_value_init_object()));
        DO(result_crlocspref_to_json(json_array_get_object(ja_revocationrefs, idx), crlocsp_ref));
    }

cleanup:
    return ret;
}   //  result_revocationrefs_to_json

static int result_verifyinfo_to_json (
        JSON_Object* joSignInfo,
        UapkiNS::Doc::Verify::VerifiedSignerInfo& verifyInfo,
        const UapkiNS::Doc::Verify::VerifyOptions& verifyOptions
)
{
    int ret = RET_OK;

    if (verifyInfo.getSignerCertId()) {
        DO(json_object_set_base64(joSignInfo, "signerCertId", verifyInfo.getSignerCertId()));
    }

    DO_JSON(json_object_set_string(joSignInfo, "signatureFormat", UapkiNS::signatureFormatToStr(verifyInfo.getSignatureFormat())));
    DO_JSON(json_object_set_string(joSignInfo, "status", verifyInfo.getValidationStatus()));
    DO_JSON(ParsonHelper::jsonObjectSetBoolean(joSignInfo, "validSignatures", verifyInfo.isValidSignatures()));
    DO_JSON(ParsonHelper::jsonObjectSetBoolean(joSignInfo, "validDigests", verifyInfo.isValidDigests()));
    if (verifyInfo.getBestSignatureTime() > 0) {
        DO_JSON(json_object_set_string(joSignInfo, "bestSignatureTime", TimeUtils::mstimeToFormat(verifyInfo.getBestSignatureTime()).c_str()));
    }

    DO_JSON(json_object_set_string(joSignInfo, "statusSignature", UapkiNS::verifyStatusToStr(verifyInfo.getStatusSignature())));
    DO_JSON(json_object_set_string(joSignInfo, "statusMessageDigest", UapkiNS::verifyStatusToStr(verifyInfo.getStatusMessageDigest())));
    if (verifyInfo.getSigningTime() > 0) {
        DO_JSON(json_object_set_string(joSignInfo, "signingTime", TimeUtils::mstimeToFormat(verifyInfo.getSigningTime()).c_str()));
    }
    if (!verifyInfo.getSigPolicyId().empty()) {
        DO_JSON(json_object_dotset_string(joSignInfo, "signaturePolicy.sigPolicyId", verifyInfo.getSigPolicyId().c_str()));
    }
    DO_JSON(json_object_set_string(joSignInfo, "statusEssCert", UapkiNS::verifyStatusToStr(verifyInfo.getStatusEssCert())));
    DO(result_attr_timestamp_to_json(joSignInfo, "contentTS", verifyInfo.getContentTS()));
    DO(result_attr_timestamp_to_json(joSignInfo, "signatureTS", verifyInfo.getSignatureTS()));
    DO_JSON(json_object_set_string(joSignInfo, "statusCertificateRefs", UapkiNS::verifyStatusToStr(verifyInfo.getCadesXlInfo().statusCertRefs)));
    DO(result_certificaterefs_to_json(joSignInfo, verifyInfo.getCadesXlInfo()));
    if (!verifyInfo.getListAddedCerts().certValues.empty()) {
        DO_JSON(json_object_set_value(joSignInfo, "certValues", json_value_init_array()));
        JSON_Array* ja_certids = json_object_get_array(joSignInfo, "certValues");
        for (const auto& it : verifyInfo.getListAddedCerts().certValues) {
            DO_JSON(json_array_append_base64(ja_certids, it->baCertId));
        }
    }
    DO(result_revocationrefs_to_json(joSignInfo, verifyInfo.getRevocationRefs()));
    DO(result_attr_timestamp_to_json(joSignInfo, "archiveTS", verifyInfo.getArchiveTS()));

    DO(result_attributes_to_json(joSignInfo, "signedAttributes", verifyInfo.getSignerInfo().getSignedAttrs()));
    DO(result_attributes_to_json(joSignInfo, "unsignedAttributes", verifyInfo.getSignerInfo().getUnsignedAttrs()));

    if (
        (verifyOptions.validationType != CerStore::ValidationType::UNDEFINED) &&
        !verifyInfo.getCertChainItems().empty()
    ) {
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
            DO(result_expectedcertitem_to_json(json_array_get_object(ja_expcertitems, idx++), *it));
        }
    }

    if (!verifyInfo.getExpectedCrlItems().empty()) {
        DO_JSON(json_object_set_value(joSignInfo, "expectedCrls", json_value_init_array()));
        JSON_Array* ja_expcrlitems = json_object_get_array(joSignInfo, "expectedCrls");
        size_t idx = 0;
        for (const auto& it : verifyInfo.getExpectedCrlItems()) {
            DO_JSON(json_array_append_value(ja_expcrlitems, json_value_init_object()));
            DO(result_expectedcrlitem_to_json(json_array_get_object(ja_expcrlitems, idx++), *it));
        }
    }

cleanup:
    return ret;
}   //  result_verifyinfo_to_json

static int result_to_json (
        JSON_Object* joResult,
        UapkiNS::Doc::Verify::VerifySignedDoc& verifySignedDoc
)
{
    int ret = RET_OK;

    {   //  =content=
        const UapkiNS::Pkcs7::EncapsulatedContentInfo& encap_cinfo = verifySignedDoc.sdataParser.getEncapContentInfo();
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
            DO_JSON(json_array_append_base64(ja_certids, it->baCertId));
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

    //  =validateTime=
    DO_JSON(json_object_set_string(joResult, "validateTime",
        TimeUtils::mstimeToFormat(verifySignedDoc.verifyOptions.validateTime).c_str())
    );

cleanup:
    return ret;
}   //  result_to_json

static int process_crl (
        CrlStore& crlStore,
        const CerStore::Item* cerSubject,
        const CerStore::Item* cerIssuer,
        const ByteArray** baCrlNumber,
        const uint64_t validateTime,
        CrlStore::Item** crlItem
)
{
    int ret = RET_OK;
    const CrlStore::CrlType crl_type = (*baCrlNumber == nullptr) ? CrlStore::CrlType::FULL : CrlStore::CrlType::DELTA;
    CrlStore::Item* crl = nullptr;
    UapkiNS::SmartBA sba_crl;

    crl = crlStore.getCrl(cerSubject->baAuthorityKeyId, crl_type);
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

        vector<string> uris;
        ret = cerSubject->getCrlUris((crl_type == CrlStore::CrlType::FULL), uris);
        if (ret != RET_OK) {
            if (ret == RET_UAPKI_EXTENSION_NOT_PRESENT) {
                ret = RET_UAPKI_CRL_URL_NOT_PRESENT;
            }
            SET_ERROR(ret);
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

        crl = crlStore.getCrl(cerSubject->baAuthorityKeyId, crl_type);
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

    if (cerIssuer) {
        ret = crl->verify(cerIssuer);
        if (crl->statusSign == CerStore::VerifyStatus::FAILED) {
            SET_ERROR(ret);
        }
    }
    else {
        crl->statusSign = CerStore::VerifyStatus::INDETERMINATE;
    }

    *crlItem = crl;

cleanup:
    return ret;
}   //  process_crl

static int validate_by_crl (
        UapkiNS::Doc::Verify::VerifySignedDoc& verifySignedDoc,
        UapkiNS::Doc::Verify::VerifiedSignerInfo& verifiedSignerInfo,
        UapkiNS::Doc::Verify::CertChainItem& certChainItem
)
{
    int ret = RET_OK;
    const UapkiNS::Doc::Verify::VerifyOptions& verify_options = verifySignedDoc.verifyOptions;
    UapkiNS::Doc::Verify::ResultValidationByCrl& result_valbycrl = certChainItem.getResultValidationByCrl();
    CrlStore::Item* crl_item = nullptr;
    vector<const CrlStore::RevokedCertItem*> revoked_items;
    const ByteArray* ba_crlnumber = nullptr;
    const bool cfg_crldelta_enabled = true;
    const uint64_t validate_time = verifiedSignerInfo.getBestSignatureTime();

    result_valbycrl.cerIssuer = certChainItem.getIssuer();

    DO(process_crl(
        *verifySignedDoc.crlStore,
        certChainItem.getSubject(),
        result_valbycrl.cerIssuer,
        &ba_crlnumber,
        validate_time,
        &crl_item
    ));
    DEBUG_OUTCON(printf("validate_by_crl() ba_crlnumber: "); ba_print(stdout, ba_crlnumber));
    DO(crl_item->revokedCerts(certChainItem.getSubject(), revoked_items));
    result_valbycrl.crlStoreItem = crl_item;

    if (cfg_crldelta_enabled) {
        DO(process_crl(
            *verifySignedDoc.crlStore,
            certChainItem.getSubject(),
            result_valbycrl.cerIssuer,
            &ba_crlnumber,
            validate_time,
            &crl_item
        ));
        DO(crl_item->revokedCerts(certChainItem.getSubject(), revoked_items));
        result_valbycrl.crlStoreItem = crl_item;
    }

    DEBUG_OUTCON(for (auto& it : revoked_items) {
        printf("[%lld] revocationDate: %lld  crlReason: %i  invalidityDate: %lld\n", it->index, it->revocationDate, it->crlReason, it->invalidityDate);
    });
    (void)CrlStore::findRevokedCert(
        revoked_items,
        validate_time,
        result_valbycrl.certStatus,
        result_valbycrl.revokedCertItem
    );

cleanup:
    for (auto& it : revoked_items) {
        delete it;
    }
    revoked_items.clear();

    switch (ret) {
    case RET_UAPKI_OFFLINE_MODE:
    case RET_UAPKI_CRL_NOT_DOWNLOADED:
    case RET_UAPKI_CRL_NOT_FOUND:
        (void)verifiedSignerInfo.addExpectedCrlItem(certChainItem.getSubject(), crl_item);
        break;
    default: break;
    }
    return ret;
}   //  validate_by_crl

static int validate_by_ocsp (
        UapkiNS::Doc::Verify::VerifiedSignerInfo& verifiedSignerInfo,
        UapkiNS::Doc::Verify::CertChainItem& certChainItem
)
{
    int ret = RET_OK;
    const LibraryConfig::OcspParams& ocsp_params = get_config()->getOcsp();
    CerStore::Item* csi_subject = certChainItem.getSubject();
    UapkiNS::Doc::Verify::ResultValidationByOcsp& result_valbyocsp = certChainItem.getResultValidationByOcsp();
    UapkiNS::Ocsp::OcspHelper ocsp_helper;
    UapkiNS::SmartBA sba_resp;
    vector<string> shuffled_uris, uris;

    bool need_update = csi_subject->certStatusByOcsp.isExpired(TimeUtils::nowMsTime());
    if (need_update) {
        const CerStore::Item* csi_issuer = certChainItem.getIssuer();

        if (HttpHelper::isOfflineMode()) {
            SET_ERROR(RET_UAPKI_OFFLINE_MODE);
        }

        if (!csi_issuer) {
            SET_ERROR(RET_UAPKI_CERT_ISSUER_NOT_FOUND);
        }

        ret = csi_subject->getOcspUris(uris);
        if ((ret != RET_OK) && (ret != RET_UAPKI_EXTENSION_NOT_PRESENT)) {
            SET_ERROR(RET_UAPKI_OCSP_URL_NOT_PRESENT);
        }

        DO(ocsp_helper.init());
        DO(ocsp_helper.addCert(csi_issuer, csi_subject));
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
        else if (sba_resp.empty()) {
            SET_ERROR(RET_UAPKI_OCSP_RESPONSE_INVALID);
        }
    }

    ret = ocsp_helper.parseResponse(need_update ? sba_resp.get() : csi_subject->certStatusByOcsp.baResult);
    result_valbyocsp.responseStatus = ocsp_helper.getResponseStatus();

    if ((ret == RET_OK) && (ocsp_helper.getResponseStatus() == UapkiNS::Ocsp::ResponseStatus::SUCCESSFUL)) {
        result_valbyocsp.dataSource = UapkiNS::Doc::Verify::DataSource::STORE;
        (void)verifiedSignerInfo.verifyOcspResponse(ocsp_helper, result_valbyocsp);
        DO(ocsp_helper.checkNonce());
        DO(ocsp_helper.scanSingleResponses());

        result_valbyocsp.msProducedAt = ocsp_helper.getProducedAt();
        result_valbyocsp.singleResponseInfo = ocsp_helper.getSingleResponseInfo(0); //  Work with one OCSP request that has one certificate
        if (need_update) {
            DO(csi_subject->certStatusByOcsp.set(
                result_valbyocsp.singleResponseInfo.certStatus,
                result_valbyocsp.singleResponseInfo.msThisUpdate + UapkiNS::Ocsp::OFFSET_EXPIRE_DEFAULT,
                sba_resp.get()
            ));
        }
    }

cleanup:
    return ret;
}   //  validate_by_ocsp

static int validate_certs (
        UapkiNS::Doc::Verify::VerifySignedDoc& verifySignedDoc,
        UapkiNS::Doc::Verify::VerifiedSignerInfo& verifiedSignerInfo
)
{
    int ret = RET_OK;
    const UapkiNS::Doc::Verify::VerifyOptions& verify_options = verifySignedDoc.verifyOptions;
    const uint64_t bestsign_time = verifiedSignerInfo.getBestSignatureTime();

    if (verify_options.validationType == CerStore::ValidationType::CRL) {
        if (verifiedSignerInfo.getSignatureFormat() >= UapkiNS::SignatureFormat::CADES_XL) {
            //TODO
        }
        verifiedSignerInfo.validateValidityTimeCerts(bestsign_time);
        for (auto& it_cci : verifiedSignerInfo.getCertChainItems()) {
            if (!it_cci->isExpired() && it_cci->getResultValidationByCrl().isUsed) {
                (void)validate_by_crl(verifySignedDoc, verifiedSignerInfo, *it_cci);
            }
        }
        DO(verifiedSignerInfo.addCrlCertsToChain());
    }
    else if (verify_options.validationType == CerStore::ValidationType::OCSP) {
        if (verifiedSignerInfo.getSignatureFormat() < UapkiNS::SignatureFormat::CADES_XL) {
            verifiedSignerInfo.validateValidityTimeCerts(verify_options.validateTime);
            for (auto& it_cci : verifiedSignerInfo.getCertChainItems()) {
                if (!it_cci->isExpired() && it_cci->getResultValidationByOcsp().isUsed) {
                    (void)validate_by_ocsp(verifiedSignerInfo, *it_cci);
                }
            }
            DO(verifiedSignerInfo.addOcspCertsToChain(verify_options.validateTime));
        }
        else {
            DO(verifiedSignerInfo.setRevocationValuesForChain(bestsign_time));
            DO(verifiedSignerInfo.addOcspCertsToChain(bestsign_time));
        }
    }

cleanup:
    return ret;
}   //  validate_certs

static int verify_p7s (
        const ByteArray* baSignature,
        const ByteArray* baContent,
        const bool isDigest,
        const UapkiNS::Doc::Verify::VerifyOptions& verifyOptions,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    UapkiNS::Doc::Verify::VerifySignedDoc verify_sdoc(
        get_cerstore(),
        get_crlstore(),
        verifyOptions
    );

    if (!verify_sdoc.cerStore || !verify_sdoc.crlStore) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    DO(verify_sdoc.parse(baSignature));

    verify_sdoc.getContent(baContent);

    DO(verify_sdoc.addCertsToStore());

    //  For each signer_info
    verify_sdoc.verifiedSignerInfos.resize(verify_sdoc.sdataParser.getCountSignerInfos());
    for (size_t idx = 0; idx < verify_sdoc.sdataParser.getCountSignerInfos(); idx++) {
        UapkiNS::Doc::Verify::VerifiedSignerInfo& verified_sinfo = verify_sdoc.verifiedSignerInfos[idx];

        DO(verified_sinfo.init(verify_sdoc.cerStore, isDigest));
        DO(verify_sdoc.sdataParser.parseSignerInfo(idx, verified_sinfo.getSignerInfo()));
        if (!verify_sdoc.sdataParser.isContainDigestAlgorithm(verified_sinfo.getSignerInfo().getDigestAlgorithm())) {
            SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
        }

        DO(verified_sinfo.parseAttributes());
        DO(verified_sinfo.verifySignedAttribute());
        DO(verified_sinfo.verifyMessageDigest(verify_sdoc.refContent));
        DO(verified_sinfo.verifySigningCertificateV2());

        verified_sinfo.determineSignFormat();
        DO(verified_sinfo.certValuesToStore());
        DO(verified_sinfo.verifyContentTimeStamp(verify_sdoc.refContent));
        DO(verified_sinfo.verifySignatureTimeStamp());
        DO(verified_sinfo.verifyCertificateRefs());
        DO(verified_sinfo.verifyArchiveTimeStamp(verify_sdoc.addedCerts, verify_sdoc.addedCrls));

        verified_sinfo.validateSignFormat(verifyOptions);
        if (verifyOptions.validationType >= CerStore::ValidationType::CHAIN) {
            DO(verified_sinfo.buildCertChain());
        }
        DO(validate_certs(verify_sdoc, verified_sinfo));
        verified_sinfo.validateStatusCerts();
    }

    verify_sdoc.detectCertSources();

    DO(result_to_json(joResult, verify_sdoc));

    ret = verify_sdoc.getLastError();

cleanup:
    return ret;
}   //  verify_p7s

static int verify_raw (
        const ByteArray* baSignature,
        const ByteArray* baContent,
        const bool isDigest,
        JSON_Object* joSignParams,
        JSON_Object* joSignerPubkey,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    CerStore::Item* cer_item = nullptr;
    CerStore::Item* cer_parsed = nullptr;
    UapkiNS::SmartBA sba_pubdata;
    UapkiNS::SignatureVerifyStatus status_sign = UapkiNS::SignatureVerifyStatus::UNDEFINED;
    bool is_digitalsign = true;

    const string s_signalgo = ParsonHelper::jsonObjectGetString(joSignParams, "signAlgo");
    if (s_signalgo.empty()) return RET_UAPKI_INVALID_PARAMETER;

    if (sba_pubdata.set(json_object_get_base64(joSignerPubkey, "certificate"))) {
        DO(CerStore::parseCert(sba_pubdata.get(), &cer_parsed));
        (void)sba_pubdata.set(nullptr);
        cer_item = cer_parsed;
    }
    else {
        if (sba_pubdata.set(json_object_get_base64(joSignerPubkey, "certId"))) {
            CerStore* cer_store = get_cerstore();
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

    ret = verify_signature(s_signalgo.c_str(), baContent, isDigest,
        (cer_item) ? cer_item->baSPKI : sba_pubdata.get(), baSignature);
    switch (ret) {
    case RET_OK:
        status_sign = UapkiNS::SignatureVerifyStatus::VALID;
        break;
    case RET_VERIFY_FAILED:
        status_sign = UapkiNS::SignatureVerifyStatus::INVALID;
        break;
    default:
        status_sign = UapkiNS::SignatureVerifyStatus::FAILED;
    }
    DO_JSON(json_object_set_string(joResult, "statusSignature", UapkiNS::verifyStatusToStr(status_sign)));

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
    UapkiNS::SmartBA sba_content;
    UapkiNS::SmartBA sba_signature;
    JSON_Object* jo_signature = nullptr;
    JSON_Object* jo_signparams = nullptr;
    JSON_Object* jo_signerpubkey = nullptr;
    bool is_digest, is_raw = false;

    jo_signature = json_object_get_object(joParams, "signature");
    is_digest = ParsonHelper::jsonObjectGetBoolean(jo_signature, "isDigest", false);
    (void)sba_content.set(json_object_get_base64(jo_signature, "content"));
    if (!sba_signature.set(json_object_get_base64(jo_signature, "bytes"))) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    jo_signparams = json_object_get_object(joParams, "signParams");
    jo_signerpubkey = json_object_get_object(joParams, "signerPubkey");
    is_raw = (jo_signparams != nullptr) || (jo_signerpubkey != nullptr);

    if (!is_raw) {
        UapkiNS::Doc::Verify::VerifyOptions verify_options;
        DO(parse_verify_options(joParams, verify_options));
        DO(verify_p7s(sba_signature.get(), sba_content.get(), is_digest, verify_options, joResult));
    }
    else {
        if (sba_content.empty() || (jo_signparams == nullptr) || (jo_signerpubkey == nullptr)) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
        DO(verify_raw(sba_signature.get(), sba_content.get(), is_digest, jo_signparams, jo_signerpubkey, joResult));
    }

cleanup:
    return ret;
}
