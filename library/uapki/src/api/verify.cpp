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
#include "content-info.h"
#include "global-objects.h"
#include "parson-helper.h"
#include "store-utils.h"
#include "time-utils.h"
#include "uapki-errors.h"
#include "verify-signer-info.h"
#include "verify-utils.h"
#include <vector>


#undef FILE_MARKER
#define FILE_MARKER "api/verify.c"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


typedef struct VerifyOptions_S {
    bool    encodeCert;
    bool    validateCertByOCSP;
    bool    validateCertByCRL;
    VerifyOptions_S (void)
        : encodeCert(true), validateCertByOCSP(false), validateCertByCRL(false) {}
} VerifyOptions;


static int decode_signed_data (const ByteArray* baEncoded, SignedData_t** signedData, ByteArray** baEncapContent)
{
    int ret = RET_OK;
    ContentInfo_t* cinfo = nullptr;
    SignedData_t* sdata = nullptr;
    long version = 0;

    CHECK_NOT_NULL(cinfo = (ContentInfo_t*)asn_decode_ba_with_alloc(get_ContentInfo_desc(), baEncoded));
    DO(cinfo_get_signed_data(cinfo, &sdata));

    DO(asn_INTEGER2long(&sdata->version, &version));
    if ((version < 1) || (version > 5) || (version == 2)) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT_VERSION);
    }

    if (sdata->signerInfos.list.count == 0) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

    if (sdata->encapContentInfo.eContent != nullptr) {
        DO(asn_OCTSTRING2ba(sdata->encapContentInfo.eContent, baEncapContent));
    }

    *signedData = sdata;
    sdata = nullptr;

cleanup:
    asn_free(get_ContentInfo_desc(), cinfo);
    asn_free(get_SignedData_desc(), sdata);
    return ret;
}

static int get_digest_algorithms (SignedData_t* signedData, vector<char*>& dgstAlgos)
{
    int ret = RET_OK;
    char* s_dgstalgo = nullptr;

    if (signedData->digestAlgorithms.list.count == 0) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

    for (size_t i = 0; i < signedData->digestAlgorithms.list.count; i++) {
        DO(asn_oid_to_text(&signedData->digestAlgorithms.list.array[i]->algorithm, &s_dgstalgo));
        dgstAlgos.push_back(s_dgstalgo);
        s_dgstalgo = nullptr;
    }

cleanup:
    if (ret != RET_OK) {
        for (size_t i = 0; i < dgstAlgos.size(); i++) {
            ::free(dgstAlgos[i]);
        }
        dgstAlgos.clear();
    }
    ::free(s_dgstalgo);
    return ret;
}

static int get_certs_to_store (SignedData_t* signedData, vector<const CerStore::Item*>& certs)
{
    int ret = RET_OK;
    CerStore* cer_store = nullptr;
    ByteArray* ba_cert = nullptr;

    cer_store = get_cerstore();
    if (!cer_store) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    DEBUG_OUTCON(printf("get_certs_to_store(), count certs in cert-store (before): %d\n", (int)cer_store->count()));
    if (signedData->certificates) {
        if (signedData->certificates->list.count == 0) {
            SET_ERROR(RET_UAPKI_INVALID_STRUCT);
        }

        for (size_t i = 0; i < signedData->certificates->list.count; i++) {
            bool is_unique;
            const CerStore::Item* cer_item = nullptr;
            DO(asn_encode_ba(get_CertificateChoices_desc(), signedData->certificates->list.array[i], &ba_cert));
            DO(cer_store->addCert(ba_cert, false, false, false, is_unique, &cer_item));
            ba_cert = nullptr;
            certs.push_back(cer_item);
        }
    }
    DEBUG_OUTCON(printf("get_certs_to_store(), count certs in cert-store (after) : %d\n", (int)cer_store->count()));

cleanup:
    ba_free(ba_cert);
    return ret;
}

static int result_set_content (JSON_Object* joContent, const OBJECT_IDENTIFIER_t* eContentType, ByteArray* baContent)
{
    if (joContent == nullptr) return RET_UAPKI_GENERAL_ERROR;

    int ret = RET_OK;
    char* s_contype = nullptr;

    DO(asn_oid_to_text(eContentType, &s_contype));

    ret = (json_object_set_string(joContent, "type", s_contype) == JSONSuccess) ? RET_OK : RET_UAPKI_GENERAL_ERROR;
    if ((ret == RET_OK) && (baContent != nullptr)) {
        DO(json_object_set_base64(joContent, "bytes", baContent));
    }

cleanup:
    free(s_contype);
    return ret;
}

static int result_set_list_attrs (JSON_Object* joResult, const char* key, const vector<AttrItem>& attrItems)
{
    if (attrItems.empty()) return RET_OK;

    int ret = RET_OK;
    json_object_set_value(joResult, key, json_value_init_array());
    JSON_Array* ja_attrs = json_object_get_array(joResult, key);
    for (size_t i = 0; i < attrItems.size(); i++) {
        const AttrItem& attr_item = attrItems[i];
        json_array_append_value(ja_attrs, json_value_init_object());
        JSON_Object* jo_attr = json_array_get_object(ja_attrs, i);
        DO_JSON(json_object_set_string(jo_attr, "type", attr_item.attrType));
        DO_JSON(json_object_set_base64(jo_attr, "bytes", attr_item.baAttrValue));
    }

cleanup:
    return ret;
}

static int parse_attr_sigpolicy (JSON_Object* joResult, const ByteArray* baEncoded)
{
    int ret = RET_OK;
    SignaturePolicyIdentifier_t* spi = nullptr;
    char* s_policyid = nullptr;

    CHECK_NOT_NULL(spi = (SignaturePolicyIdentifier_t*)asn_decode_ba_with_alloc(get_SignaturePolicyIdentifier_desc(), baEncoded));
    if (spi->present == SignaturePolicyIdentifier_PR_signaturePolicyId) {
        DO(asn_oid_to_text(&spi->choice.signaturePolicyId.sigPolicyId, &s_policyid));
        DO_JSON(json_object_set_string(joResult, "sigPolicyId", s_policyid));
    }

cleanup:
    asn_free(get_SignaturePolicyIdentifier_desc(), spi);
    free(s_policyid);
    return ret;
}

static int result_set_parsed_signedattrs (JSON_Object* joResult, const vector<AttrItem>& attrItems)
{
    int ret = RET_OK;

    for (auto& it : attrItems) {
        if (strcmp(it.attrType, OID_PKCS9_SIG_POLICY_ID) == 0) {
            DO_JSON(json_object_set_value(joResult, "signaturePolicy", json_value_init_object()));
            DO(parse_attr_sigpolicy(json_object_get_object(joResult, "signaturePolicy"), it.baAttrValue));
        }
    }

cleanup:
    return ret;
}

static int result_set_parsed_unsignedattrs (JSON_Object* joResult, const vector<AttrItem>& attrItems)
{
    int ret = RET_OK;

    //TODO: here process unsigned attrs
    //for (auto& it : attrItems) {
        //if (strcmp(it.attrType, OID_any_attr) == 0) {}
    //}

//cleanup:
    return ret;
}

static void parse_verify_options (JSON_Object* joOptions, VerifyOptions& options)
{
    options.encodeCert = ParsonHelper::jsonObjectGetBoolean(joOptions, "encodeCert", true);
    options.validateCertByOCSP = ParsonHelper::jsonObjectGetBoolean(joOptions, "validateCertByOCSP", false);
    options.validateCertByCRL = ParsonHelper::jsonObjectGetBoolean(joOptions, "validateCertByCRL", false);
}

static int attr_timestamp_to_json (JSON_Object* joSignerInfo, const char* attrName, const AttrTimeStamp* attrTS)
{
    int ret = RET_OK;
    JSON_Object* jo_attrts = nullptr;

    if (attrTS == nullptr) return ret;

    DO_JSON(json_object_set_value(joSignerInfo, attrName, json_value_init_object()));
    jo_attrts = json_object_get_object(joSignerInfo, attrName);
    DO_JSON(json_object_set_string(jo_attrts, "genTime", TimeUtils::mstimeToFormat(attrTS->msGenTime).c_str()));
    DO_JSON(json_object_set_string(jo_attrts, "policyId", attrTS->policy));
    DO_JSON(json_object_set_string(jo_attrts, "hashAlgo", attrTS->hashAlgo));
    DO_JSON(json_object_set_base64(jo_attrts, "hashedMessage", attrTS->baHashedMessage));
    DO_JSON(json_object_set_string(jo_attrts, "statusDigest", SIGNATURE_VERIFY::toStr(attrTS->statusDigest)));
    //TODO: need impl "statusSign" (statusSignedData)

cleanup:
    return ret;
}

static int verify_cms (const ByteArray* baSignature, const ByteArray* baContent, const bool isDigest,
                    JSON_Object* joOptions, JSON_Object* joResult)
{
    int ret = RET_OK;
    CerStore* cer_store = nullptr;
    VerifyOptions options;
    uint32_t version = 0;
    SignedData_t* sdata = nullptr;
    ByteArray* ba_content = nullptr;
    const ByteArray* ref_content = nullptr;
    vector<char*> dgst_algos;
    vector<const CerStore::Item*> certs;
    vector<const VerifyInfo*> verify_infos;
    JSON_Array* ja = nullptr;
    JSON_Object* jo = nullptr;

    cer_store = get_cerstore();
    if (!cer_store) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    parse_verify_options(joOptions, options);

    DO(decode_signed_data(baSignature, &sdata, &ba_content));
    ref_content = (ba_content != nullptr) ? ba_content : baContent;

    DO(get_digest_algorithms(sdata, dgst_algos));
    DO(get_certs_to_store(sdata, certs));

    //  For each signerInfo
    for (size_t i = 0; i < sdata->signerInfos.list.count; i++) {
        VerifyInfo* verify_info = new VerifyInfo();
        if (!verify_info) {
            SET_ERROR(RET_UAPKI_GENERAL_ERROR);
        }
        DO(verify_signer_info(sdata->signerInfos.list.array[i], dgst_algos, ref_content, isDigest, verify_info));
        verify_infos.push_back(verify_info);
    }

    //  Out param 'content', object
    DO_JSON(json_object_set_value(joResult, "content", json_value_init_object()));
    DO(result_set_content(json_object_get_object(joResult, "content"), &sdata->encapContentInfo.eContentType, ba_content));

    //  Out param 'certIds' (certificates), array
    DO_JSON(json_object_set_value(joResult, "certIds", json_value_init_array()));
    ja = json_object_get_array(joResult, "certIds");
    for (auto& it: certs) {
        DO_JSON(json_array_append_base64(ja, it->baCertId));
    }

    //  Out param 'signatureInfos', array
    DO_JSON(json_object_set_value(joResult, "signatureInfos", json_value_init_array()));
    ja = json_object_get_array(joResult, "signatureInfos");
    for (size_t i = 0; i < verify_infos.size(); i++) {
        bool is_valid = false;

        DO_JSON(json_array_append_value(ja, json_value_init_object()));
        jo = json_array_get_object(ja, i);

        const VerifyInfo* verify_info = verify_infos[i];
        DO(json_object_set_base64(jo, "signerCertId", verify_info->cerStoreItem->baCertId));

        is_valid = (verify_info->statusSignature == SIGNATURE_VERIFY::STATUS::VALID)
            && (verify_info->statusMessageDigest == SIGNATURE_VERIFY::STATUS::VALID);
        if (is_valid && (verify_info->statusEssCert != SIGNATURE_VERIFY::STATUS::NOT_PRESENT)) {
            is_valid = (verify_info->statusEssCert == SIGNATURE_VERIFY::STATUS::VALID);
        }
        if (is_valid && verify_info->contentTS) {
            is_valid = (verify_info->contentTS->statusDigest == SIGNATURE_VERIFY::STATUS::VALID);
            //TODO: verify_info->contentTS->statusSign
        }
        if (is_valid && verify_info->signatureTS) {
            is_valid = (verify_info->signatureTS->statusDigest == SIGNATURE_VERIFY::STATUS::VALID);
            //TODO: verify_info->signatureTS->statusSign
        }

        SIGNATURE_VALIDATION::STATUS status = is_valid ? SIGNATURE_VALIDATION::STATUS::TOTAL_VALID : SIGNATURE_VALIDATION::STATUS::TOTAL_FAILED;
        //TODO: check options.validateCertByCRL and options.validateCertByOCSP
        //      added status SIGNATURE_VALIDATION::STATUS::INDETERMINATE

        DO_JSON(json_object_set_string(jo, "status", SIGNATURE_VALIDATION::toStr(status)));
        DO_JSON(json_object_set_string(jo, "statusSignature", SIGNATURE_VERIFY::toStr(verify_info->statusSignature)));
        DO_JSON(json_object_set_string(jo, "statusMessageDigest", SIGNATURE_VERIFY::toStr(verify_info->statusMessageDigest)));
        DO_JSON(json_object_set_string(jo, "statusEssCert", SIGNATURE_VERIFY::toStr(verify_info->statusEssCert)));
        if (verify_info->signingTime > 0) {
            DO_JSON(json_object_set_string(jo, "signingTime", TimeUtils::mstimeToFormat(verify_info->signingTime).c_str()));
        }
        DO(result_set_parsed_signedattrs(jo, verify_info->signedAttrs));
        DO(result_set_parsed_unsignedattrs(jo, verify_info->unsignedAttrs));
        DO_JSON(attr_timestamp_to_json(jo, "contentTS", verify_info->contentTS));
        DO_JSON(attr_timestamp_to_json(jo, "signatureTS", verify_info->signatureTS));
        DO(result_set_list_attrs(jo, "signedAttributes", verify_info->signedAttrs));
        DO(result_set_list_attrs(jo, "unsignedAttributes", verify_info->unsignedAttrs));
    }

cleanup:
    for (size_t i = 0; i < dgst_algos.size(); i++) {
        ::free(dgst_algos[i]);
    }
    for (size_t i = 0; i < verify_infos.size(); i++) {
        delete verify_infos[i];
    }
    asn_free(get_SignedData_desc(), sdata);
    ba_free(ba_content);
    return ret;
}

static int verify_raw (const ByteArray* baSignature, const ByteArray* baContent, const bool isDigest,
                    JSON_Object* joSignParams, JSON_Object* joSignerPubkey, JSON_Object* joResult)
{
    int ret = RET_OK;
    CerStore::Item* cer_parsed = nullptr;
    ByteArray* ba_certid = nullptr;
    ByteArray* ba_encoded = nullptr;
    ByteArray* ba_spki = nullptr;
    const CerStore::Item* cer_item = nullptr;
    const char* s_signalgo = nullptr;
    SIGNATURE_VERIFY::STATUS status_sign = SIGNATURE_VERIFY::STATUS::UNDEFINED;
    bool is_digitalsign = true;

    s_signalgo = json_object_get_string(joSignParams, "signAlgo");
    if (s_signalgo == nullptr) return RET_UAPKI_INVALID_PARAMETER;

    ba_encoded = json_object_get_base64(joSignerPubkey, "certificate");
    if (ba_encoded) {
        DO(CerStore::parseCert(ba_encoded, &cer_parsed));
        ba_encoded = nullptr;
        cer_item = (const CerStore::Item*)cer_parsed;
    }
    else {
        ba_certid = json_object_get_base64(joSignerPubkey, "certId");
        if (ba_certid) {
            CerStore* cer_store = get_cerstore();
            if (!cer_store) {
                SET_ERROR(RET_UAPKI_GENERAL_ERROR);
            }
            DO(cer_store->getCertByCertId(ba_certid, &cer_item));
        }
        else {
            ba_spki = json_object_get_base64(joSignerPubkey, "spki");
            if (!ba_spki) {
                SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
            }
        }
    }

    ret = verify_signature(s_signalgo, baContent, isDigest,
        (cer_item != nullptr) ? cer_item->baSPKI : ba_spki, baSignature);
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
    ba_free(ba_certid);
    ba_free(ba_encoded);
    ba_free(ba_spki);
    return ret;
}


int uapki_verify_signature (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    ByteArray* ba_content = nullptr;
    ByteArray* ba_signature = nullptr;
    JSON_Object* jo_options = nullptr;
    JSON_Object* jo_signature = nullptr;
    JSON_Object* jo_signparams = nullptr;
    JSON_Object* jo_signerpubkey = nullptr;
    bool is_digest, is_raw = false;

    jo_options = json_object_get_object(joParams, "options");
    jo_signature = json_object_get_object(joParams, "signature");
    ba_signature = json_object_get_base64(jo_signature, "bytes");
    ba_content = json_object_get_base64(jo_signature, "content");
    is_digest = ParsonHelper::jsonObjectGetBoolean(jo_signature, "isDigest", false);
    if (!ba_signature) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    jo_signparams = json_object_get_object(joParams, "signParams");
    jo_signerpubkey = json_object_get_object(joParams, "signerPubkey");
    is_raw = (jo_signparams != nullptr) || (jo_signerpubkey != nullptr);

    if (!is_raw) {
        DO(verify_cms(ba_signature, ba_content, is_digest, jo_options, joResult));
    }
    else {
        if ((ba_content == nullptr) || (jo_signparams == nullptr) || (jo_signerpubkey == nullptr)) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
        DO(verify_raw(ba_signature, ba_content, is_digest, jo_signparams, jo_signerpubkey, joResult));
    }

cleanup:
    ba_free(ba_content);
    ba_free(ba_signature);
    return ret;
}
