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

#define FILE_MARKER "uapki/api/build-cms-2pass.cpp"

#include "api-json-internal.h"
#include "cert-validator.h"
#include "doc-sign.h"
#include "global-objects.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include "store-json.h"
#include "time-util.h"
#include "uapki-ns.h"
#include "uapki-debug.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;
using namespace UapkiNS;


static int parse_docattrs_from_json (
        Doc::Sign::SigningDoc& sdoc,
        JSON_Object* joDoc,
        const string& keyAttributes
)
{
    const JSON_Array* ja_attrs = json_object_get_array(joDoc, keyAttributes.c_str());
    const size_t cnt_attrs = json_array_get_count(ja_attrs);
    if (cnt_attrs == 0) return RET_OK;

    int ret = RET_OK;
    const bool is_signedattrs = (keyAttributes == string("signedAttributes"));
    for (size_t i = 0; i < cnt_attrs; i++) {
        SmartBA sba_values;
        JSON_Object* jo_attr = json_array_get_object(ja_attrs, i);
        const string s_type = ParsonHelper::jsonObjectGetString(jo_attr, "type");
        sba_values.set(json_object_get_base64(jo_attr, "bytes"));
        if (s_type.empty() || !oid_is_valid(s_type.c_str()) || sba_values.empty()) {
            return RET_UAPKI_INVALID_PARAMETER;
        }
        if (is_signedattrs) {
            DO(sdoc.addSignedAttribute(s_type, sba_values.get()));
        }
        else {
            DO(sdoc.addUnsignedAttribute(s_type, sba_values.get()));
        }
        sba_values.set(nullptr);
    }

cleanup:
    return RET_OK;
}   //  parse_docattr_from_json

static int step1_encodesa (
        CertValidator::CertValidator& certValidator,
        JSON_Object* joStep1Params,
        JSON_Object* joResult
)
{
    Doc::Sign::SharedData shared_data;
    CertValidator::CertValidator& cert_validator = shared_data.certValidator;
    if (!cert_validator.init(get_config(), get_cerstore(), get_crlstore())) return RET_UAPKI_GENERAL_ERROR;
    if (!cert_validator.getLibConfig()->isInitialized()) return RET_UAPKI_NOT_INITIALIZED;

    int ret = RET_OK;
    LibraryConfig& config = *cert_validator.getLibConfig();
    Doc::Sign::SigningDoc sdoc;
    SmartBA sba_certid, sba_messagedigest;
    uint64_t signing_time = 0;

    shared_data.aidDigest.algorithm = ParsonHelper::jsonObjectGetString(joStep1Params, "digestAlgo");
    shared_data.aidDigest.baParameters = json_object_get_base64(joStep1Params, "digestAlgoParams");
    shared_data.includeContentTS = ParsonHelper::jsonObjectGetBoolean(joStep1Params, "includeContentTS", false);
    const string s_contenttype = ParsonHelper::jsonObjectGetString(joStep1Params, "contentType", string(OID_PKCS7_DATA));
    sba_messagedigest.set(json_object_get_base64(joStep1Params, "messageDigest"));
    if (!shared_data.aidDigest.isPresent() || s_contenttype.empty() || sba_messagedigest.empty()) return RET_UAPKI_INVALID_PARAMETER;

    shared_data.hashDigest = hash_from_oid(shared_data.aidDigest.algorithm.c_str());
    shared_data.hashSignature = shared_data.hashDigest;
    if (shared_data.hashDigest == HashAlg::HASH_ALG_UNDEFINED) {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }
    if (hash_get_size(shared_data.hashDigest) != sba_messagedigest.size()) {
        SET_ERROR(RET_UAPKI_INVALID_HASH_SIZE);
    }
    if (!oid_is_valid(s_contenttype.c_str())) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    if (ParsonHelper::jsonObjectHasValue(joStep1Params, "signingTime", JSONString)) {
        const string s_signingtime = ParsonHelper::jsonObjectGetString(joStep1Params, "signingTime");
        DO(TimeUtil::ftimeToMtime(s_signingtime, signing_time));
        shared_data.includeTime = true;
    }
    else if (ParsonHelper::jsonObjectGetBoolean(joStep1Params, "includeTime", false)) {
        shared_data.includeTime = true;
    }

    if (ParsonHelper::jsonObjectHasValue(joStep1Params, "certId", JSONString)) {
        SmartBA sba_certid;
        if (!sba_certid.set(json_object_get_base64(joStep1Params, "certId"))) return RET_UAPKI_INVALID_PARAMETER;
        DO(cert_validator.getCerStore()->getCertByCertId(sba_certid.get(), &shared_data.cerSigner));
    }
    if (ParsonHelper::jsonObjectGetBoolean(joStep1Params, "includeSigningCert", false)) {
        //  is CAdES-signature
        if (!shared_data.cerSigner->keyUsageByBit(KeyUsage_digitalSignature)) {
            SET_ERROR(RET_UAPKI_INVALID_KEY_USAGE);
        }
        DO(shared_data.encodeSigningCertificate());
    }
    else {
        //  is CMS-signature
        shared_data.sidUseKeyId = true;
    }

    shared_data.ocsp = config.getOcsp();
    if (shared_data.includeContentTS && config.getOffline()) {
        SET_ERROR(RET_UAPKI_OFFLINE_MODE);
    }

    if (shared_data.includeContentTS) {
        DO(shared_data.setupTsp(config.getTsp()));
    }

    DO(sdoc.init(&shared_data));
    sdoc.contentType = s_contenttype;
    (void)sdoc.messageDigest.set(sba_messagedigest.pop());
    DO(parse_docattrs_from_json(sdoc, joStep1Params, string("signedAttributes")));
    if (shared_data.includeContentTS) {
        //  After digestMessage and before buildSignedAttributes
        DO(sdoc.addTimestamp(Doc::Sign::TsAttr::CONTENT_TIMESTAMP));
    }
    sdoc.signingTime = signing_time;
    DO(sdoc.buildSignedAttributes());
    DO(sdoc.digestSignedAttributes());

    DO(json_object_set_base64(joResult, "bytes", sdoc.signerInfo->getSignedAttrsEncoded()));
    DO(json_object_set_base64(joResult, "digestBytes", sdoc.hashSignedAttrs.get()));
    DO(json_object_set_string(joResult, "contentType", s_contenttype.c_str()));
    if (signing_time > 0) {
        DO(json_object_set_string(joResult, "signingTime", TimeUtil::mtimeToFtime(signing_time).c_str()));
    }

cleanup:
    return ret;
}   //  step1_encodesa

static int step2_encodesd (
        CertValidator::CertValidator& certValidator,
        JSON_Object* joStep2Params,
        JSON_Object* joResult
)
{
    Doc::Sign::SharedData shared_data;
    CertValidator::CertValidator& cert_validator = shared_data.certValidator;
    if (!cert_validator.init(get_config(), get_cerstore(), get_crlstore())) return RET_UAPKI_GENERAL_ERROR;
    if (!cert_validator.getLibConfig()->isInitialized()) return RET_UAPKI_NOT_INITIALIZED;

    int ret = RET_OK;
    LibraryConfig& config = *cert_validator.getLibConfig();
    Doc::Sign::SigningDoc sdoc;
    SmartBA sba_content, sba_encodedsa, sba_signvalue;

    shared_data.signatureFormat = signatureFormatFromString(
        ParsonHelper::jsonObjectGetString(joStep2Params, "signatureFormat")
    );
    switch (shared_data.signatureFormat) {
    case SignatureFormat::CADES_BES:
    case SignatureFormat::CADES_T:
    case SignatureFormat::CADES_XL:
    case SignatureFormat::CADES_A:
        // without CADES_C
        break;
    case SignatureFormat::CMS_SID_KEYID:
        break;
    default:
        return RET_UAPKI_INVALID_PARAMETER;
    }
    DO(shared_data.paramsBySignatureFormat());

    sba_encodedsa.set(json_object_get_base64(joStep2Params, "bytes"));
    shared_data.aidSignature.algorithm = ParsonHelper::jsonObjectGetString(joStep2Params, "signAlgo");
    shared_data.aidSignature.baParameters = json_object_get_base64(joStep2Params, "signAlgoParams");
    sba_signvalue.set(json_object_get_base64(joStep2Params, "signBytes"));
    shared_data.aidDigest.algorithm = ParsonHelper::jsonObjectGetString(joStep2Params, "digestAlgo");
    shared_data.aidDigest.baParameters = json_object_get_base64(joStep2Params, "digestAlgoParams");
    shared_data.includeCert = ParsonHelper::jsonObjectGetBoolean(joStep2Params, "includeCert", false);
    shared_data.options.ignoreCertStatus = ParsonHelper::jsonObjectGetBoolean(json_object_get_object(joStep2Params, "options"), "ignoreCertStatus", false);
    if (sba_encodedsa.empty() || !shared_data.aidSignature.isPresent() || sba_signvalue.empty() || !shared_data.aidDigest.isPresent()) return RET_UAPKI_INVALID_PARAMETER;

    shared_data.hashSignature = hash_from_oid(shared_data.aidSignature.algorithm.c_str());
    if (shared_data.hashSignature == HashAlg::HASH_ALG_UNDEFINED) {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }
    shared_data.hashDigest = hash_from_oid(shared_data.aidDigest.algorithm.c_str());
    if (shared_data.hashDigest == HashAlg::HASH_ALG_UNDEFINED) {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }

    if (ParsonHelper::jsonObjectHasValue(joStep2Params, "contentBytes", JSONString)) {
        if (!sba_content.set(json_object_get_base64(joStep2Params, "contentBytes"))) return RET_UAPKI_INVALID_PARAMETER;
    }
    if (ParsonHelper::jsonObjectHasValue(joStep2Params, "certId", JSONString)) {
        SmartBA sba_certid;
        if (!sba_certid.set(json_object_get_base64(joStep2Params, "certId"))) return RET_UAPKI_INVALID_PARAMETER;
        DO(cert_validator.getCerStore()->getCertByCertId(sba_certid.get(), &shared_data.cerSigner));
    }
    if (ParsonHelper::jsonObjectHasValue(joStep2Params, "keyId", JSONString)) {
        if (!shared_data.keyId.set(json_object_get_base64(joStep2Params, "keyId"))) return RET_UAPKI_INVALID_PARAMETER;
    }

    if ((shared_data.signatureFormat != SignatureFormat::CMS_SID_KEYID) || shared_data.includeCert) {
        if (!shared_data.cerSigner) return RET_UAPKI_CERT_NOT_FOUND;
    }

    shared_data.ocsp = config.getOcsp();
    if (shared_data.includeSignatureTS && config.getOffline()) {
        SET_ERROR(RET_UAPKI_OFFLINE_MODE);
    }

    if (shared_data.includeSignatureTS) {
        DO(shared_data.setupTsp(config.getTsp()));
    }

    if (shared_data.cerSigner) {
        if (!shared_data.options.ignoreCertStatus) {
            const Cert::ValidationType validation_type = (
                ((shared_data.signatureFormat == SignatureFormat::CADES_BES) && config.getOffline())
                ) ? Cert::ValidationType::CRL : Cert::ValidationType::OCSP;
            cert_validator.setValidationType(validation_type);
        }
        DO(cert_validator.getStatus(
            shared_data.cerSigner,
            CertValidator::CertEntity::SIGNER,
            TimeUtil::mtimeNow()
        ));
    }

    DO(sdoc.init(&shared_data));
    if (!sba_content.empty()) {
        shared_data.detachedData = false;
        DO(sdoc.contentHasher.setContent(sba_content.pop(), true));
    }
    DO(sdoc.setupSignerIdentifier());
    DO(sdoc.importSignedAttributes(sba_encodedsa.get()));
    DO(sdoc.digestSignedAttributes());
    DO(sdoc.setSignature(sba_signvalue.pop()));

    //  Add unsigned attrs before call buildSignedData
    if (shared_data.includeSignatureTS) {
        DO(sdoc.addTimestamp(Doc::Sign::TsAttr::TIMESTAMP_TOKEN));
    }

    DO(parse_docattrs_from_json(sdoc, joStep2Params, string("unsignedAttributes")));
    DO(sdoc.buildUnsignedAttributes());

    if (shared_data.signatureFormat == SignatureFormat::CADES_A) {
        DO(sdoc.addTimestamp(Doc::Sign::TsAttr::ARCHIVE_TIMESTAMP));
    }
    DO(sdoc.buildSignedData());

    DO(json_object_set_base64(joResult, "bytes", sdoc.getEncoded()));

cleanup:

    return ret;
}   //  step2_encodesd

int uapki_build_cms_2pass (
        JSON_Object* joParams,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    CertValidator::CertValidator cert_validator;
    if (!cert_validator.init(get_config(), get_cerstore(), get_crlstore())) return RET_UAPKI_GENERAL_ERROR;
    if (!cert_validator.getLibConfig()->isInitialized()) return RET_UAPKI_NOT_INITIALIZED;

    if (ParsonHelper::jsonObjectHasValue(joParams, "step1", JSONObject)) {
        DO_JSON(json_object_set_value(joResult, "step1", json_value_init_object()));
        DO(step1_encodesa(
            cert_validator,
            json_object_get_object(joParams, "step1"),
            json_object_get_object(joResult, "step1")
        ));
    }
    else if (ParsonHelper::jsonObjectHasValue(joParams, "step2", JSONObject)) {
        DO_JSON(json_object_set_value(joResult, "step2", json_value_init_object()));
        DO(step2_encodesd(
            cert_validator,
            json_object_get_object(joParams, "step2"),
            json_object_get_object(joResult, "step2"))
        );
    }

cleanup:
    return ret;
}
