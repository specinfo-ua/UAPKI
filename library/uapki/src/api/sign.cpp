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

#define FILE_MARKER "uapki/api/sign.cpp"

#include "api-json-internal.h"
#include "cert-validator.h"
#include "cm-providers.h"
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


static int get_info_signalgo_and_keyid (
        CmStorageProxy& storage,
        Doc::Sign::SharedData& sharedData
)
{
    string s_keyinfo;

    int ret = storage.keyGetInfo(s_keyinfo, nullptr);
    if (ret != RET_OK) return ret;

    ParsonHelper json;
    if (!json.parse(s_keyinfo.c_str(), false)) return RET_UAPKI_INVALID_JSON_FORMAT;

    JSON_Array* ja_signalgos = nullptr;
    bool is_found = false;
    ja_signalgos = json.getArray("signAlgo");
    if (json_array_get_count(ja_signalgos) == 0) return RET_UAPKI_UNSUPPORTED_ALG;

    if (sharedData.aidSignature.algorithm.empty()) {
        //  Set first signAlgo from list
        sharedData.aidSignature.algorithm = ParsonHelper::jsonArrayGetString(ja_signalgos, 0);
        is_found = (!sharedData.aidSignature.algorithm.empty());
    }
    else {
        //  Check signAlgo in list
        for (size_t i = 0; i < json_array_get_count(ja_signalgos); i++) {
            const string s = ParsonHelper::jsonArrayGetString(ja_signalgos, i);
            is_found = (s == sharedData.aidSignature.algorithm);
            if (is_found) break;
        }
    }
    if (!is_found) return RET_UAPKI_UNSUPPORTED_ALG;

    if (!sharedData.keyId.set(ba_copy_with_alloc(storage.getSelectedKeyId(), 0, 0))) return RET_UAPKI_GENERAL_ERROR;

    return RET_OK;
}   //  get_info_signalgo_and_keyid

static int parse_sign_params (
        JSON_Object* joSignParams,
        JSON_Object* joSignOptions,
        Doc::Sign::SharedData& sharedData
)
{
    int ret = RET_OK;

    sharedData.signatureFormat = signatureFormatFromString(
        ParsonHelper::jsonObjectGetString(joSignParams, "signatureFormat")
    );
    sharedData.aidSignature.algorithm = ParsonHelper::jsonObjectGetString(joSignParams, "signAlgo");
    sharedData.aidDigest.algorithm = ParsonHelper::jsonObjectGetString(joSignParams, "digestAlgo");
    sharedData.detachedData = ParsonHelper::jsonObjectGetBoolean(joSignParams, "detachedData", true);
    sharedData.includeCert = ParsonHelper::jsonObjectGetBoolean(joSignParams, "includeCert", false);
    sharedData.includeTime = ParsonHelper::jsonObjectGetBoolean(joSignParams, "includeTime", false);
    sharedData.includeContentTS = ParsonHelper::jsonObjectGetBoolean(joSignParams, "includeContentTS", false);

    if (
        (sharedData.signatureFormat == SignatureFormat::CADES_BES) ||
        (sharedData.signatureFormat == SignatureFormat::CADES_T)
    ) {
        sharedData.options.ignoreCertStatus = ParsonHelper::jsonObjectGetBoolean(joSignOptions, "ignoreCertStatus", false);
    }

    DO(sharedData.paramsBySignatureFormat());

    if (ParsonHelper::jsonObjectHasValue(joSignParams, "signaturePolicy", JSONObject)) {
        JSON_Object* jo_sigpolicy = json_object_get_object(joSignParams, "signaturePolicy");
        DO(sharedData.encodeSignaturePolicy(ParsonHelper::jsonObjectGetString(jo_sigpolicy, "sigPolicyId")));
    }

cleanup:
    return ret;
}   //  parse_sign_params

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

static int parse_doc_from_json (
        Doc::Sign::SigningDoc& sdoc,
        JSON_Object* joDoc
)
{
    if (!joDoc) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    ContentHasher& content_hasher = sdoc.contentHasher;

    sdoc.id = ParsonHelper::jsonObjectGetString(joDoc, "id");
    sdoc.isDigest = ParsonHelper::jsonObjectGetBoolean(joDoc, "isDigest", false);

    if (ParsonHelper::jsonObjectHasValue(joDoc, "bytes", JSONString)) {
        DO(content_hasher.setContent(json_object_get_base64(joDoc, "bytes"), true));
    }
    else if (ParsonHelper::jsonObjectHasValue(joDoc, "file", JSONString)) {
        DO(content_hasher.setContent(json_object_get_string(joDoc, "file")));
    }
    else if (
        ParsonHelper::jsonObjectHasValue(joDoc, "ptr", JSONString) &&
        ParsonHelper::jsonObjectHasValue(joDoc, "size", JSONNumber)
    ) {
        SmartBA sba_ptr;
        (void)sba_ptr.set(json_object_get_hex(joDoc, "ptr"));
        const uint8_t* ptr = ContentHasher::baToPtr(sba_ptr.get());
        size_t size = 0;
        if (!ptr || !ContentHasher::numberToSize(json_object_get_number(joDoc, "size"), size)) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
        DO(content_hasher.setContent(ptr, size));
    }
    else {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    if (sdoc.sharedData->signatureFormat != SignatureFormat::RAW) {
        sdoc.contentType = ParsonHelper::jsonObjectGetString(joDoc, "type", string(OID_PKCS7_DATA));
        if (!oid_is_valid(sdoc.contentType.c_str())) return RET_UAPKI_INVALID_PARAMETER;
        DO(parse_docattrs_from_json(sdoc, joDoc, string("signedAttributes")));
        DO(parse_docattrs_from_json(sdoc, joDoc, string("unsignedAttributes")));
    }

cleanup:
    return ret;
}   //  parse_doc_from_json

static int resultdoc_to_json (
        JSON_Object* joResultDoc,
        Doc::Sign::SigningDoc& sDoc
)
{
    int ret = RET_OK;

    if (!joResultDoc) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    DO_JSON(json_object_set_string(joResultDoc, "id", sDoc.id.c_str()));
    DO(json_object_set_base64(joResultDoc, "bytes", sDoc.getEncoded()));
    if (!sDoc.contentType.empty()) {
        DO_JSON(json_object_set_string(joResultDoc, "contentType", sDoc.contentType.c_str()));
    }
    DO(json_object_set_base64(joResultDoc, "messageDigest", sDoc.messageDigest.get()));

    if (sDoc.signingTime > 0) {
        DO_JSON(json_object_set_string(joResultDoc, "signingTime", TimeUtil::mtimeToFtime(sDoc.signingTime).c_str()));
    }
    if (sDoc.contentTimeStamp > 0) {
        DO_JSON(json_object_set_string(joResultDoc, "contentTimeStamp", TimeUtil::mtimeToFtime(sDoc.contentTimeStamp).c_str()));
    }
    if (sDoc.signatureTimeStamp > 0) {
        DO_JSON(json_object_set_string(joResultDoc, "signatureTimeStamp", TimeUtil::mtimeToFtime(sDoc.signatureTimeStamp).c_str()));
    }
    if (sDoc.archiveTimeStamp > 0) {
        DO_JSON(json_object_set_string(joResultDoc, "archiveTimeStamp", TimeUtil::mtimeToFtime(sDoc.archiveTimeStamp).c_str()));
    }

cleanup:
    return ret;
}   //  resultdoc_to_json

int uapki_sign (
        JSON_Object* joParams,
        JSON_Object* joResult
)
{
    Doc::Sign::SharedData shared_data;
    CertValidator::CertValidator& cert_validator = shared_data.certValidator;
    if (!cert_validator.init(get_config(), get_cerstore(), get_crlstore())) return RET_UAPKI_GENERAL_ERROR;
    if (!cert_validator.getLibConfig()->isInitialized()) return RET_UAPKI_NOT_INITIALIZED;

    CmStorageProxy* storage = CmProviders::openedStorage();
    if (!storage) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!storage->keyIsSelected()) return RET_UAPKI_KEY_NOT_SELECTED;

    int ret = RET_OK;
    Cert::CerStore& cer_store = *cert_validator.getCerStore();
    LibraryConfig& config = *cert_validator.getLibConfig();
    size_t cnt_docs = 0;
    JSON_Array* ja_results = nullptr;
    JSON_Array* ja_sources = nullptr;
    vector<Doc::Sign::SigningDoc> signing_docs;
    vector<ByteArray*> refba_hashes;
    VectorBA vba_signatures;

    DO(parse_sign_params(
        json_object_get_object(joParams, "signParams"),
        json_object_get_object(joParams, "options"),
        shared_data
    ));

    shared_data.ocsp = config.getOcsp();
    if (shared_data.includeContentTS || shared_data.includeSignatureTS) {
        if (config.getOffline()) {
            SET_ERROR(RET_UAPKI_OFFLINE_MODE);
        }
    }

    ja_sources = json_object_get_array(joParams, "dataTbs");
    cnt_docs = json_array_get_count(ja_sources);
    if ((cnt_docs == 0) || (cnt_docs > Doc::Sign::MAX_COUNT_DOCS)) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    DO(get_info_signalgo_and_keyid(*storage, shared_data));

    shared_data.hashSignature = hash_from_oid(shared_data.aidSignature.algorithm.c_str());
    if (shared_data.hashSignature == HashAlg::HASH_ALG_UNDEFINED) {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }

    if (shared_data.aidDigest.algorithm.empty() || (shared_data.signatureFormat == SignatureFormat::RAW)) {
        shared_data.hashDigest = shared_data.hashSignature;
        shared_data.aidDigest.algorithm = string(hash_to_oid(shared_data.hashDigest));
    }
    else {
        shared_data.hashDigest = hash_from_oid(shared_data.aidDigest.algorithm.c_str());
    }
    if (shared_data.hashDigest == HashAlg::HASH_ALG_UNDEFINED) {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }
    DO_JSON(json_object_set_string(joResult, "digestAlgo", hash_to_oid(shared_data.hashDigest)));

    if ((shared_data.signatureFormat != SignatureFormat::RAW) && ((!shared_data.sidUseKeyId || shared_data.includeCert))) {
        if (storage->getPairedCertId()) {
            DO(cer_store.getCertByCertId(storage->getPairedCertId(), &shared_data.cerSigner));
        }
        else {
            DO(cer_store.getCertByKeyId(storage->getSelectedKeyId(), &shared_data.cerSigner));
        }
        DO(json_object_set_base64(joResult, "signerCertId", shared_data.cerSigner->getCertId()));
        if (!shared_data.cerSigner->keyUsageByBit(KeyUsage_digitalSignature)) {
            SET_ERROR(RET_UAPKI_INVALID_KEY_USAGE);
        }

        if (shared_data.isCadesFormat) {
            if (!shared_data.options.ignoreCertStatus) {
                const Cert::ValidationType validation_type = (
                        (shared_data.signatureFormat == SignatureFormat::CADES_C) ||
                        ((shared_data.signatureFormat == SignatureFormat::CADES_BES) && config.getOffline())
                    ) ? Cert::ValidationType::CRL : Cert::ValidationType::OCSP;
                cert_validator.setValidationType(validation_type);
            }
            DO(cert_validator.getStatus(
                shared_data.cerSigner,
                CertValidator::CertEntity::SIGNER,
                TimeUtil::mtimeNow()
            ));

            DO(shared_data.encodeSigningCertificate());
        }
    }

    if (shared_data.includeContentTS || shared_data.includeSignatureTS) {
        DO(shared_data.setupTsp(config.getTsp()));
    }

    signing_docs.resize(cnt_docs);
    //  Parse and load all TBS-data
    for (size_t i = 0; i < signing_docs.size(); i++) {
        Doc::Sign::SigningDoc& sdoc = signing_docs[i];
        DO(sdoc.init(&shared_data));
        DO(parse_doc_from_json(sdoc, json_array_get_object(ja_sources, i)));
        if (
            (sdoc.contentHasher.getSourceType() != ContentHasher::SourceType::BYTEARRAY) &&
            (shared_data.detachedData == false)
        ) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
    }

    if (shared_data.signatureFormat != SignatureFormat::RAW) {
        for (size_t i = 0; i < signing_docs.size(); i++) {
            Doc::Sign::SigningDoc& sdoc = signing_docs[i];

            DO(sdoc.setupSignerIdentifier());

            DO(sdoc.digestMessage());
            if (shared_data.includeContentTS) {
                //  After digestMessage and before buildSignedAttributes
                DO(sdoc.addTimestamp(Doc::Sign::TsAttr::CONTENT_TIMESTAMP));
            }

            DO(sdoc.buildSignedAttributes());
            DO(sdoc.digestSignedAttributes());
            refba_hashes.push_back(sdoc.hashSignedAttrs.get());
        }

        DO(storage->keySign(
            shared_data.aidSignature.algorithm,
            nullptr,
            refba_hashes,
            vba_signatures
        ));

        for (size_t i = 0; i < signing_docs.size(); i++) {
            Doc::Sign::SigningDoc& sdoc = signing_docs[i];
            DO(sdoc.setSignature(vba_signatures[i]));
            vba_signatures[i] = nullptr;
            //  Add unsigned attrs before call buildSignedData
            if (shared_data.includeSignatureTS) {
                DO(sdoc.addTimestamp(Doc::Sign::TsAttr::TIMESTAMP_TOKEN));
            }

            DO(sdoc.buildUnsignedAttributes());
            if (shared_data.signatureFormat == SignatureFormat::CADES_A) {
                DO(sdoc.addTimestamp(Doc::Sign::TsAttr::ARCHIVE_TIMESTAMP));
            }
            DO(sdoc.buildSignedData());
        }
    }
    else {
        for (size_t i = 0; i < signing_docs.size(); i++) {
            Doc::Sign::SigningDoc& sdoc = signing_docs[i];
            DO(sdoc.digestMessage());
            refba_hashes.push_back(sdoc.messageDigest.get());
        }

        DO(storage->keySign(
            shared_data.aidSignature.algorithm,
            nullptr,
            refba_hashes,
            vba_signatures
        ));

        for (size_t i = 0; i < signing_docs.size(); i++) {
            (void)signing_docs[i].signature.set(vba_signatures[i]);
            vba_signatures[i] = nullptr;
        }
    }

    DO_JSON(json_object_set_value(joResult, "signatures", json_value_init_array()));
    ja_results = json_object_get_array(joResult, "signatures");
    for (size_t i = 0; i < signing_docs.size(); i++) {
        DO_JSON(json_array_append_value(ja_results, json_value_init_object()));
        DO(resultdoc_to_json(json_array_get_object(ja_results, i), signing_docs[i]));
    }

cleanup:
    if (ret != RET_OK) {
        for (const auto& it : signing_docs) {
            (void)it.collectExpectedItems(cert_validator);
        }
        (void)cert_validator.expectedCertsToJson(joResult, "expectedCerts");
        (void)cert_validator.expectedCrlsToJson(joResult, "expectedCrls");
    }
    return ret;
}
