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
#include "parson-helper.h"
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


using namespace std;


struct VerifyOptions {
    bool    encodeCert;
    bool    validateCertByOCSP;
    bool    validateCertByCRL;
    VerifyOptions (void)
        : encodeCert(true), validateCertByOCSP(false), validateCertByCRL(false) {}
};  //  end struct VerifyOptions


static int add_certs_to_store (
        CerStore& cerStore,
        UapkiNS::VectorBA& vbaCerts,
        vector<const CerStore::Item*>& certs
)
{
    int ret = RET_OK;

    DEBUG_OUTCON(size_t cnt_certs = 0; cerStore.getCount(cnt_certs);
        printf("add_certs_to_store(), count added_certs in cert-store (before): %zu\n", cnt_certs));
    for (size_t i = 0; i < vbaCerts.size(); i++) {
        bool is_unique;
        const CerStore::Item* cer_item = nullptr;
        DO(cerStore.addCert(vbaCerts[i], false, false, false, is_unique, &cer_item));
        vbaCerts[i] = nullptr;
        certs.push_back(cer_item);
    }
    DEBUG_OUTCON(cerStore.getCount(cnt_certs);
        printf("add_certs_to_store(), count added_certs in cert-store (after): %zu\n", cnt_certs));

cleanup:
    return ret;
}   //  add_certs_to_store

static void parse_verify_options (
        JSON_Object* joOptions,
        VerifyOptions& options
)
{
    options.encodeCert = ParsonHelper::jsonObjectGetBoolean(joOptions, "encodeCert", true);
    options.validateCertByOCSP = ParsonHelper::jsonObjectGetBoolean(joOptions, "validateCertByOCSP", false);
    options.validateCertByCRL = ParsonHelper::jsonObjectGetBoolean(joOptions, "validateCertByCRL", false);
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
        if (attrTS.signerCertId) {
            DO(json_object_set_base64(jo_attrts, "signerCertId", attrTS.signerCertId->baCertId));
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
        DO_JSON(json_object_set_base64(jo_attr, "bytes", attr.baValues));
    }

cleanup:
    return ret;
}   //  result_attributes_to_json

static int result_sign_info_to_json (
        JSON_Object* joSignInfo,
        UapkiNS::Doc::Verify::VerifiedSignerInfo& verifyInfo
)
{
    int ret = RET_OK;

    DO(json_object_set_base64(joSignInfo, "signerCertId", verifyInfo.getSignerCertId()));

    DO(verifyInfo.validate());

    DO_JSON(json_object_set_string(joSignInfo, "signatureFormat", UapkiNS::signatureFormatToStr(verifyInfo.getSignatureFormat())));
    DO_JSON(json_object_set_string(joSignInfo, "status", verifyInfo.getValidationStatus()));
    DO_JSON(json_object_set_string(joSignInfo, "statusSignature", UapkiNS::verifyStatusToStr(verifyInfo.getStatusSignature())));
    DO_JSON(json_object_set_string(joSignInfo, "statusMessageDigest", UapkiNS::verifyStatusToStr(verifyInfo.getStatusMessageDigest())));
    DO_JSON(json_object_set_string(joSignInfo, "statusEssCert", UapkiNS::verifyStatusToStr(verifyInfo.getStatusEssCert())));
    if (verifyInfo.getSigningTime() > 0) {
        DO_JSON(json_object_set_string(joSignInfo, "signingTime", TimeUtils::mstimeToFormat(verifyInfo.getSigningTime()).c_str()));
    }
    if (!verifyInfo.getSigPolicyId().empty()) {
        DO_JSON(json_object_dotset_string(joSignInfo, "signaturePolicy.sigPolicyId", verifyInfo.getSigPolicyId().c_str()));
    }
    DO_JSON(result_attr_timestamp_to_json(joSignInfo, "contentTS", verifyInfo.getContentTS()));
    DO_JSON(result_attr_timestamp_to_json(joSignInfo, "signatureTS", verifyInfo.getSignatureTS()));
    DO_JSON(result_attr_timestamp_to_json(joSignInfo, "archiveTS", verifyInfo.getArchiveTS()));
    DO(result_attributes_to_json(joSignInfo, "signedAttributes", verifyInfo.getSignerInfo().getSignedAttrs()));
    DO(result_attributes_to_json(joSignInfo, "unsignedAttributes", verifyInfo.getSignerInfo().getUnsignedAttrs()));

cleanup:
    return ret;
}   //  result_sign_info_to_json

static int result_to_json (
        JSON_Object* joResult,
        const UapkiNS::Pkcs7::SignedDataParser& signedData,
        vector<const CerStore::Item*>& certs,
        vector<UapkiNS::Doc::Verify::VerifiedSignerInfo>& verifyInfos
)
{
    int ret = RET_OK;

    {   //  =content=
        const UapkiNS::Pkcs7::EncapsulatedContentInfo& encap_cinfo = signedData.getEncapContentInfo();
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
        for (const auto& it : certs) {
            DO_JSON(json_array_append_base64(ja_certids, it->baCertId));
        }
    }

    {
        //  =signatureInfos=
        DO_JSON(json_object_set_value(joResult, "signatureInfos", json_value_init_array()));
        JSON_Array* ja_signinfos = json_object_get_array(joResult, "signatureInfos");
        for (size_t i = 0; i < verifyInfos.size(); i++) {
            DO_JSON(json_array_append_value(ja_signinfos, json_value_init_object()));
            DO(result_sign_info_to_json(json_array_get_object(ja_signinfos, i), verifyInfos[i]));
        }
    }

cleanup:
    return ret;
}   //  result_to_json

static int verify_p7s (
        const ByteArray* baSignature,
        const ByteArray* baContent,
        const bool isDigest,
        JSON_Object* joOptions,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    UapkiNS::Pkcs7::SignedDataParser sdata_parser;
    CerStore* cer_store = nullptr;
    //VerifyOptions options;
    const ByteArray* ref_content = nullptr;
    vector<const CerStore::Item*> added_certs;
    vector<const CrlStore::Item*> added_crls;
    vector<UapkiNS::Doc::Verify::VerifiedSignerInfo> verified_sinfos;

    cer_store = get_cerstore();
    if (!cer_store) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    //parse_verify_options(joOptions, options);

    DO(sdata_parser.parse(baSignature));
    if (sdata_parser.getCountSignerInfos() == 0) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

    ref_content = (sdata_parser.getEncapContentInfo().baEncapContent)
        ? sdata_parser.getEncapContentInfo().baEncapContent : baContent;
    
    DO(add_certs_to_store(*cer_store, sdata_parser.getCerts(), added_certs));

    //  For each signer_info
    verified_sinfos.resize(sdata_parser.getCountSignerInfos());
    for (size_t idx = 0; idx < sdata_parser.getCountSignerInfos(); idx++) {
        UapkiNS::Doc::Verify::VerifiedSignerInfo& verified_sinfo = verified_sinfos[idx];

        DO(verified_sinfo.init(cer_store, isDigest));

        DO(sdata_parser.parseSignerInfo(idx, verified_sinfo.getSignerInfo()));

        if (!sdata_parser.isContainDigestAlgorithm(verified_sinfo.getSignerInfo().getDigestAlgorithm())) {
            SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
        }

        DO(verified_sinfo.verifySignerInfo(ref_content));
        if (verified_sinfo.getSignatureFormat() == UapkiNS::SignatureFormat::CADES_A) {
            DO(verified_sinfo.verifyArchiveTS(added_certs, added_crls));
        }
    }

    DO(result_to_json(joResult, sdata_parser, added_certs, verified_sinfos));

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
    JSON_Object* jo_options = nullptr;
    JSON_Object* jo_signature = nullptr;
    JSON_Object* jo_signparams = nullptr;
    JSON_Object* jo_signerpubkey = nullptr;
    bool is_digest, is_raw = false;

    jo_options = json_object_get_object(joParams, "options");
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
        DO(verify_p7s(sba_signature.get(), sba_content.get(), is_digest, jo_options, joResult));
    }
    else {
        if ((sba_content.size() == 0) || (jo_signparams == nullptr) || (jo_signerpubkey == nullptr)) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
        DO(verify_raw(sba_signature.get(), sba_content.get(), is_digest, jo_signparams, jo_signerpubkey, joResult));
    }

cleanup:
    return ret;
}
