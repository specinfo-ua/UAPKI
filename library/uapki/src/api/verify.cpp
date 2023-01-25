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


struct AttrTimeStamp {
    string      policy;
    string      hashAlgo;
    UapkiNS::SmartBA
                hashedMessage;
    uint64_t    msGenTime;
    CerStore::Item*
                signerCertId;
    SIGNATURE_VERIFY::STATUS
                statusDigest;
    SIGNATURE_VERIFY::STATUS
                statusSignature;

    AttrTimeStamp (void)
        : msGenTime(0)
        , signerCertId(0)
        , statusDigest(SIGNATURE_VERIFY::STATUS::UNDEFINED)
        , statusSignature(SIGNATURE_VERIFY::STATUS::UNDEFINED)
    {}

    ~AttrTimeStamp (void)
    {}

    bool isPresent (void) const
    {
        return (!policy.empty() && !hashAlgo.empty() && (hashedMessage.size() > 0));
    }

    int verifyDigest (const ByteArray* baData)
    {
        UapkiNS::SmartBA sba_hash;

        const int ret = ::hash(hash_from_oid(hashAlgo.c_str()), baData, &sba_hash);
        if (ret != RET_OK) {
            statusDigest = SIGNATURE_VERIFY::STATUS::FAILED;
            return RET_OK;
        }

        statusDigest = (ba_cmp(hashedMessage.get(), sba_hash.get()) == 0)
            ? SIGNATURE_VERIFY::STATUS::VALID : SIGNATURE_VERIFY::STATUS::INVALID;
        return RET_OK;
    }

    int verifySignature (void) {
        return RET_OK;
    }
};  //  end struct AttrTimeStamp


struct VerifyInfo {
    UapkiNS::Pkcs7::SignedDataParser::SignerInfo
                signerInfo;
    CerStore::Item*
                cerStoreItem;
    SIGNATURE_VERIFY::STATUS
                statusSignature;
    SIGNATURE_VERIFY::STATUS
                statusMessageDigest;
    bool        isDigest;
    uint64_t    signingTime;
    UapkiNS::SignatureFormat
                signatureFormat;
    vector<UapkiNS::EssCertId>
                essCerts;
    SIGNATURE_VERIFY::STATUS
                statusEssCert;
    string      sigPolicyId;
    AttrTimeStamp
                contentTS;
    AttrTimeStamp
                signatureTS;
    AttrTimeStamp
                archiveTS;

    VerifyInfo (void)
        : cerStoreItem(nullptr)
        , statusSignature(SIGNATURE_VERIFY::STATUS::UNDEFINED)
        , statusMessageDigest(SIGNATURE_VERIFY::STATUS::UNDEFINED)
        , statusEssCert(SIGNATURE_VERIFY::STATUS::UNDEFINED)
        , isDigest(false)
        , signingTime(0)
        , signatureFormat(UapkiNS::SignatureFormat::UNDEFINED)
    {}
    ~VerifyInfo (void)
    {
        cerStoreItem = nullptr;
    }
};  //  end struct VerifyInfo


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
        printf("add_certs_to_store(), count certs in cert-store (before): %zu\n", cnt_certs));
    for (size_t i = 0; i < vbaCerts.size(); i++) {
        bool is_unique;
        const CerStore::Item* cer_item = nullptr;
        DO(cerStore.addCert(vbaCerts[i], false, false, false, is_unique, &cer_item));
        vbaCerts[i] = nullptr;
        certs.push_back(cer_item);
    }
    DEBUG_OUTCON(cerStore.getCount(cnt_certs);
        printf("add_certs_to_store(), count certs in cert-store (after): %zu\n", cnt_certs));

cleanup:
    return ret;
}   //  add_certs_to_store

static int verify_signeddata (
        CerStore& cerStore,
        UapkiNS::Pkcs7::SignedDataParser& sdata_parser,
        CerStore::Item** cerSigner
)
{
    int ret = RET_OK;
    UapkiNS::Pkcs7::SignedDataParser::SignerInfo signer_info;

    if (sdata_parser.getCountSignerInfos() == 0) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

    for (auto& it : sdata_parser.getCerts()) {
        bool is_unique;
        DO(cerStore.addCert(it, false, false, false, is_unique, nullptr));
        it = nullptr;
    }

    DO(sdata_parser.parseSignerInfo(0, signer_info));
    if (!sdata_parser.isContainDigestAlgorithm(signer_info.getDigestAlgorithm())) {
        SET_ERROR(RET_UAPKI_NOT_SUPPORTED);
    }

    switch (signer_info.getSidType()) {
    case UapkiNS::Pkcs7::SignerIdentifierType::ISSUER_AND_SN:
        DO(cerStore.getCertBySID(signer_info.getSid(), cerSigner));
        break;
    case UapkiNS::Pkcs7::SignerIdentifierType::SUBJECT_KEYID:
        DO(cerStore.getCertByKeyId(signer_info.getSid(), cerSigner));
        break;
    default:
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

    ret = verify_signature(
        signer_info.getSignatureAlgorithm().algorithm.c_str(),
        signer_info.getSignedAttrsEncoded(),
        false,
        (*cerSigner)->baSPKI,
        signer_info.getSignature()
    );

cleanup:
    return ret;
}   //  verify_signeddata

static int decode_attr_timestamp (
        const ByteArray* baValues,
        AttrTimeStamp& attrTS
)
{
    int ret = RET_OK;
    UapkiNS::Tsp::TsTokenParser tstoken_parser;

    DO(tstoken_parser.parse(baValues));
    attrTS.policy = tstoken_parser.getPolicyId();
    attrTS.hashAlgo = tstoken_parser.getHashAlgo();
    (void)attrTS.hashedMessage.set(tstoken_parser.getHashedMessage(true));
    attrTS.msGenTime = tstoken_parser.getGenTime();

    ret = verify_signeddata(
        *get_cerstore(),
        tstoken_parser.getSignedDataParser(),
        &attrTS.signerCertId
    );
    switch (ret) {
    case RET_OK:
        attrTS.statusSignature = SIGNATURE_VERIFY::STATUS::VALID;
        break;
    case RET_VERIFY_FAILED:
        attrTS.statusSignature = SIGNATURE_VERIFY::STATUS::INVALID;
        break;
    case RET_UAPKI_CERT_NOT_FOUND:
        attrTS.statusSignature = SIGNATURE_VERIFY::STATUS::NOT_PRESENT;
        break;
    default:
        attrTS.statusSignature = SIGNATURE_VERIFY::STATUS::FAILED;
    }

cleanup:
    return ret;
}   //  decode_attr_timestamp

static int decode_signed_attrs (
        const vector<UapkiNS::Attribute>& signedAattrs,
        VerifyInfo& verifyInfo
)
{
    int ret = RET_OK;

    verifyInfo.statusEssCert = SIGNATURE_VERIFY::STATUS::NOT_PRESENT;
    for (const auto& it : signedAattrs) {
        if (it.type == string(OID_PKCS9_SIGNING_TIME)) {
            DO(UapkiNS::AttributeHelper::decodeSigningTime(it.baValues, verifyInfo.signingTime));
        }
        else if (it.type == string(OID_PKCS9_SIG_POLICY_ID)) {
            DO(UapkiNS::AttributeHelper::decodeSignaturePolicy(it.baValues, verifyInfo.sigPolicyId));
        }
        else if (it.type == string(OID_PKCS9_CONTENT_TIMESTAMP)) {
            DO(decode_attr_timestamp(it.baValues, verifyInfo.contentTS));
        }
        else if (it.type == string(OID_PKCS9_SIGNING_CERTIFICATE_V2)) {
            DO(UapkiNS::AttributeHelper::decodeSigningCertificate(it.baValues, verifyInfo.essCerts));
        }
    }

cleanup:
    return ret;
}   //  decode_signed_attrs

static int decode_unsigned_attrs (
        const vector<UapkiNS::Attribute>& unsignedAttrs,
        VerifyInfo& verifyInfo
)
{
    int ret = RET_OK;

    for (const auto& it : unsignedAttrs) {
        if (it.type == string(OID_PKCS9_TIMESTAMP_TOKEN)) {
            DO(decode_attr_timestamp(it.baValues, verifyInfo.signatureTS));
        }
        else if (it.type == string(OID_ETSI_ARCHIVE_TIMESTAMP_V3)) {
            DO(decode_attr_timestamp(it.baValues, verifyInfo.archiveTS));
        }
    }

cleanup:
    return ret;
}   //  decode_unsigned_attrs

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
        const AttrTimeStamp& attrTS
)
{
    int ret = RET_OK;

    if (attrTS.isPresent()) {
        json_object_set_value(joResult, attrName, json_value_init_object());
        JSON_Object* jo_attrts = json_object_get_object(joResult, attrName);
        DO_JSON(json_object_set_string(jo_attrts, "genTime", TimeUtils::mstimeToFormat(attrTS.msGenTime).c_str()));
        DO_JSON(json_object_set_string(jo_attrts, "policyId", attrTS.policy.c_str()));
        DO_JSON(json_object_set_string(jo_attrts, "hashAlgo", attrTS.hashAlgo.c_str()));
        DO_JSON(json_object_set_base64(jo_attrts, "hashedMessage", attrTS.hashedMessage.get()));
        DO_JSON(json_object_set_string(jo_attrts, "statusDigest", SIGNATURE_VERIFY::toStr(attrTS.statusDigest)));
        DO_JSON(json_object_set_string(jo_attrts, "statusSignature", SIGNATURE_VERIFY::toStr(attrTS.statusSignature)));//aa
        DO(json_object_set_base64(jo_attrts, "signerCertId", attrTS.signerCertId->baCertId));
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
        VerifyInfo& verifyInfo
)
{
    int ret = RET_OK;
    SIGNATURE_VALIDATION::STATUS status = SIGNATURE_VALIDATION::STATUS::UNDEFINED;
    bool is_valid = false;

    DO(json_object_set_base64(joSignInfo, "signerCertId", verifyInfo.cerStoreItem->baCertId));

    is_valid = (verifyInfo.statusSignature == SIGNATURE_VERIFY::STATUS::VALID)
        && (verifyInfo.statusMessageDigest == SIGNATURE_VERIFY::STATUS::VALID);
    if (is_valid && (verifyInfo.statusEssCert != SIGNATURE_VERIFY::STATUS::NOT_PRESENT)) {
        is_valid = (verifyInfo.statusEssCert == SIGNATURE_VERIFY::STATUS::VALID);
    }
    if (is_valid && verifyInfo.contentTS.isPresent()) {
        is_valid = (verifyInfo.contentTS.statusDigest == SIGNATURE_VERIFY::STATUS::VALID);
        //TODO: verifyInfo.contentTS->statusSignature
    }
    if (is_valid && verifyInfo.signatureTS.isPresent()) {
        is_valid = (verifyInfo.signatureTS.statusDigest == SIGNATURE_VERIFY::STATUS::VALID);
        //TODO: verifyInfo.signatureTS->statusSignature
    }

    status = is_valid ? SIGNATURE_VALIDATION::STATUS::TOTAL_VALID : SIGNATURE_VALIDATION::STATUS::TOTAL_FAILED;
    //TODO: check options.validateCertByCRL and options.validateCertByOCSP
    //      added status SIGNATURE_VALIDATION::STATUS::INDETERMINATE

    DO_JSON(json_object_set_string(joSignInfo, "signatureFormat", UapkiNS::signatureFormatToStr(verifyInfo.signatureFormat)));
    DO_JSON(json_object_set_string(joSignInfo, "status", SIGNATURE_VALIDATION::toStr(status)));
    DO_JSON(json_object_set_string(joSignInfo, "statusSignature", SIGNATURE_VERIFY::toStr(verifyInfo.statusSignature)));
    DO_JSON(json_object_set_string(joSignInfo, "statusMessageDigest", SIGNATURE_VERIFY::toStr(verifyInfo.statusMessageDigest)));
    DO_JSON(json_object_set_string(joSignInfo, "statusEssCert", SIGNATURE_VERIFY::toStr(verifyInfo.statusEssCert)));
    if (verifyInfo.signingTime > 0) {
        DO_JSON(json_object_set_string(joSignInfo, "signingTime", TimeUtils::mstimeToFormat(verifyInfo.signingTime).c_str()));
    }
    if (!verifyInfo.sigPolicyId.empty()) {
        DO_JSON(json_object_dotset_string(joSignInfo, "signaturePolicy.sigPolicyId", verifyInfo.sigPolicyId.c_str()));
    }
    DO_JSON(result_attr_timestamp_to_json(joSignInfo, "contentTS", verifyInfo.contentTS));
    DO_JSON(result_attr_timestamp_to_json(joSignInfo, "signatureTS", verifyInfo.signatureTS));
    DO_JSON(result_attr_timestamp_to_json(joSignInfo, "archiveTS", verifyInfo.archiveTS));
    DO(result_attributes_to_json(joSignInfo, "signedAttributes", verifyInfo.signerInfo.getSignedAttrs()));
    DO(result_attributes_to_json(joSignInfo, "unsignedAttributes", verifyInfo.signerInfo.getUnsignedAttrs()));

cleanup:
    return ret;
}   //  result_sign_info_to_json

static int result_to_json (
        JSON_Object* joResult,
        const UapkiNS::Pkcs7::SignedDataParser& signedData,
        vector<const CerStore::Item*>& certs,
        vector<VerifyInfo>& verifyInfos
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

static int verify_signing_certificate_v2(
        VerifyInfo& verifyInfo
)
{
    if (verifyInfo.essCerts.empty()) return RET_OK;

    //  Process simple case: present only the one ESSCertIDv2
    int ret = RET_OK;
    UapkiNS::SmartBA sba_certhash;

    const UapkiNS::EssCertId& ess_certid = verifyInfo.essCerts[0];
    const HashAlg hash_algo = hash_from_oid(ess_certid.hashAlgorithm.algorithm.c_str());
    if (hash_algo == HASH_ALG_UNDEFINED) {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }

    DO(::hash(hash_algo, verifyInfo.cerStoreItem->baEncoded, &sba_certhash));
    verifyInfo.statusEssCert = (ba_cmp(sba_certhash.get(), ess_certid.baHashValue) == 0)
        ? SIGNATURE_VERIFY::STATUS::VALID : SIGNATURE_VERIFY::STATUS::INVALID;

cleanup:
    return ret;
}   //  verify_signing_certificate_v2

static int verify_signerinfo (
        CerStore& cerStore,
        const ByteArray* baContent,
        VerifyInfo& verifyInfo
)
{
    int ret = RET_OK;
    UapkiNS::Pkcs7::SignedDataParser::SignerInfo& signer_info = verifyInfo.signerInfo;
    UapkiNS::SmartBA sba_calcdigest;

    switch (signer_info.getSidType()) {
    case UapkiNS::Pkcs7::SignerIdentifierType::ISSUER_AND_SN:
        DO(cerStore.getCertBySID(signer_info.getSid(), &verifyInfo.cerStoreItem));
        break;
    case UapkiNS::Pkcs7::SignerIdentifierType::SUBJECT_KEYID:
        DO(cerStore.getCertByKeyId(signer_info.getSid(), &verifyInfo.cerStoreItem));
        verifyInfo.signatureFormat = UapkiNS::SignatureFormat::CMS_SID_KEYID;
        break;
    default:
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

    //  Verify signed attributes
    ret = verify_signature(
        signer_info.getSignatureAlgorithm().algorithm.c_str(),
        signer_info.getSignedAttrsEncoded(),
        false,
        verifyInfo.cerStoreItem->baSPKI,
        signer_info.getSignature()
    );
    switch (ret) {
    case RET_OK:
        verifyInfo.statusSignature = SIGNATURE_VERIFY::STATUS::VALID;
        break;
    case RET_VERIFY_FAILED:
        verifyInfo.statusSignature = SIGNATURE_VERIFY::STATUS::INVALID;
        break;
    default:
        verifyInfo.statusSignature = SIGNATURE_VERIFY::STATUS::FAILED;
    }

    //  Validity messageDigest
    if (!verifyInfo.isDigest) {
        DO(::hash(hash_from_oid(
            signer_info.getDigestAlgorithm().algorithm.c_str()),
            baContent,
            &sba_calcdigest)
        );
        verifyInfo.statusMessageDigest = (ba_cmp(sba_calcdigest.get(), signer_info.getMessageDigest()) == 0)
            ? SIGNATURE_VERIFY::STATUS::VALID : SIGNATURE_VERIFY::STATUS::INVALID;
    }
    else {
        verifyInfo.statusMessageDigest = (ba_cmp(baContent, signer_info.getMessageDigest()) == 0)
            ? SIGNATURE_VERIFY::STATUS::VALID : SIGNATURE_VERIFY::STATUS::INVALID;
    }

    //  Decode attributes
    DO(decode_signed_attrs(signer_info.getSignedAttrs(), verifyInfo));
    DO(decode_unsigned_attrs(signer_info.getUnsignedAttrs(), verifyInfo));

    //  Process attributes
    if (!verifyInfo.essCerts.empty()) {
        DO(verify_signing_certificate_v2(verifyInfo));
        if (verifyInfo.signatureFormat != UapkiNS::SignatureFormat::CMS_SID_KEYID) {
            verifyInfo.signatureFormat = UapkiNS::SignatureFormat::CADES_BES;
        }
    }
    if (verifyInfo.contentTS.isPresent()) {
        DO(verifyInfo.contentTS.verifyDigest(baContent));
    }
    if (verifyInfo.signatureTS.isPresent()) {
        DO(verifyInfo.signatureTS.verifyDigest(signer_info.getSignature()));
    }

    //  Determine signatureFormat for CAdES
    if (verifyInfo.signatureFormat == UapkiNS::SignatureFormat::CADES_BES) {
        if (verifyInfo.contentTS.isPresent() && verifyInfo.signatureTS.isPresent()) {
            verifyInfo.signatureFormat = UapkiNS::SignatureFormat::CADES_T;

            bool detect_certrefs = false, detect_revocrefs = false;
            bool detect_certvals = false, detect_revocvals = false;
            bool detect_atsv3 = false;
            for (const auto& it : signer_info.getUnsignedAttrs()) {
                if (it.type == string(OID_PKCS9_CERTIFICATE_REFS)) detect_certrefs = true;
                else if (it.type == string(OID_PKCS9_REVOCATION_REFS)) detect_revocrefs = true;
                else if (it.type == string(OID_PKCS9_CERT_VALUES)) detect_certvals = true;
                else if (it.type == string(OID_PKCS9_REVOCATION_VALUES)) detect_revocvals = true;
                else if (it.type == string(OID_ETSI_ARCHIVE_TIMESTAMP_V3)) detect_atsv3 = true;
            }

            if (detect_certrefs && detect_revocrefs) {
                verifyInfo.signatureFormat = UapkiNS::SignatureFormat::CADES_C;
            }

            if ((verifyInfo.signatureFormat == UapkiNS::SignatureFormat::CADES_C) && detect_certvals && detect_revocvals) {
                verifyInfo.signatureFormat = UapkiNS::SignatureFormat::CADES_LT;
            }

            if ((verifyInfo.signatureFormat == UapkiNS::SignatureFormat::CADES_LT) && detect_atsv3) {
                verifyInfo.signatureFormat = UapkiNS::SignatureFormat::CADES_LTA;
                //a DO(verifyInfo.archiveTS.verifyDigest(todo));
            }
        }
    }

cleanup:
    return ret;
}   //  verify_signerinfo

static int verify_cms (
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
    vector<const CerStore::Item*> certs;
    vector<VerifyInfo> verify_infos;

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
    
    DO(add_certs_to_store(*cer_store, sdata_parser.getCerts(), certs));

    //  For each signer_info
    verify_infos.resize(sdata_parser.getCountSignerInfos());
    for (size_t idx = 0; idx < sdata_parser.getCountSignerInfos(); idx++) {
        VerifyInfo& verify_info = verify_infos[idx];

        DO(sdata_parser.parseSignerInfo(idx, verify_info.signerInfo));

        if (!sdata_parser.isContainDigestAlgorithm(verify_info.signerInfo.getDigestAlgorithm())) {
            SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
        }

        verify_info.isDigest = isDigest;
        DO(verify_signerinfo(*cer_store, ref_content, verify_info));
    }

    DO(result_to_json(joResult, sdata_parser, certs, verify_infos));

cleanup:
    return ret;
}   //  verify_cms

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
    SIGNATURE_VERIFY::STATUS status_sign = SIGNATURE_VERIFY::STATUS::UNDEFINED;
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
        status_sign = SIGNATURE_VERIFY::STATUS::VALID;
        break;
    case RET_VERIFY_FAILED:
        status_sign = SIGNATURE_VERIFY::STATUS::INVALID;
        break;
    default:
        status_sign = SIGNATURE_VERIFY::STATUS::FAILED;
    }
    DO_JSON(json_object_set_string(joResult, "statusSignature", SIGNATURE_VERIFY::toStr(status_sign)));

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
    sba_content.set(json_object_get_base64(jo_signature, "content"));
    if (!sba_signature.set(json_object_get_base64(jo_signature, "bytes"))) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    jo_signparams = json_object_get_object(joParams, "signParams");
    jo_signerpubkey = json_object_get_object(joParams, "signerPubkey");
    is_raw = (jo_signparams != nullptr) || (jo_signerpubkey != nullptr);

    if (!is_raw) {
        DO(verify_cms(sba_signature.get(), sba_content.get(), is_digest, jo_options, joResult));
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
