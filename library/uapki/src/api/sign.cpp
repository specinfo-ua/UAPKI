/*
 * Copyright (c) 2022, The UAPKI Project Authors.
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
#include "attribute-helper.h"
#include "cm-providers.h"
#include "doc-signflow.h"
#include "global-objects.h"
#include "http-helper.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include "store-utils.h"
#include "tsp-utils.h"
#include "uapki-ns.h"


#undef FILE_MARKER
#define FILE_MARKER "api/sign.cpp"

#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif

#define CADES_A_V3_STR "CAdES-Av3"
#define CADES_BES_STR "CAdES-BES"
#define CADES_C_STR "CAdES-C"
#define CADES_T_STR "CAdES-T"
#define CMS_STR "CMS"
#define RAW_STR "RAW"
#define SIGN_MAX_DOCS 100


using namespace  std;


static SigningDoc::SignatureFormat signature_format_to_enum (const string& signFormat)
{
    SigningDoc::SignatureFormat rv = SigningDoc::SignatureFormat::UNDEFINED;
    if ((signFormat == string(CADES_BES_STR)) || signFormat.empty()) {
        rv = SigningDoc::SignatureFormat::CADES_BES;
    }
    else if (signFormat == string(CADES_T_STR)) {
        rv = SigningDoc::SignatureFormat::CADES_T;
    }
    else if (signFormat == string(CADES_C_STR)) {
        rv = SigningDoc::SignatureFormat::CADES_C;
    }
    else if (signFormat == string(CADES_A_V3_STR)) {
        rv = SigningDoc::SignatureFormat::CADES_Av3;
    }
    else if (signFormat == string(CMS_STR)) {
        rv = SigningDoc::SignatureFormat::CMS_SID_KEYID;
    }
    else if (signFormat == string(RAW_STR)) {
        rv = SigningDoc::SignatureFormat::RAW;
    }
    return rv;
}   //  signature_format_to_enum

static int encode_attrvalue_signingcert (SigningDoc::SignParams& signParams)
{
    int ret = RET_OK;
    vector<UapkiNS::EssCertId> ess_certids;

    if (!signParams.cerStoreItem) return RET_UAPKI_INVALID_PARAMETER;

    //  Now simple case: one cert
    ess_certids.resize(1);
    DO(signParams.cerStoreItem->generateEssCertId(signParams.aidDigest, ess_certids[0]));
    DO(UapkiNS::AttributeHelper::encodeSigningCertificate(ess_certids, &signParams.attrSigningCert.baValues));
    signParams.attrSigningCert.type = string(OID_PKCS9_SIGNING_CERTIFICATE_V2);

cleanup:
    return ret;
}   //  encode_attrvalue_signingcert

static int get_info_signalgo_and_keyid (CmStorageProxy& storage, string& signAlgo, ByteArray** baKeyId)
{
    string s_keyinfo;
    UapkiNS::SmartBA sba_keyid;

    int ret = storage.keyGetInfo(s_keyinfo, &sba_keyid);
    if (ret != RET_OK) return ret;

    ParsonHelper json;
    if (!json.parse(s_keyinfo.c_str(), false)) return RET_UAPKI_INVALID_JSON_FORMAT;

    JSON_Array* ja_signalgos = nullptr;
    bool is_found = false;
    ja_signalgos = json.getArray("signAlgo");
    if (json_array_get_count(ja_signalgos) == 0) return RET_UAPKI_UNSUPPORTED_ALG;

    if (signAlgo.empty()) {
        //  Set first signAlgo from list
        signAlgo = ParsonHelper::jsonArrayGetString(ja_signalgos, 0);
        is_found = (!signAlgo.empty());
    }
    else {
        //  Check signAlgo in list
        for (size_t i = 0; i < json_array_get_count(ja_signalgos); i++) {
            const string s = ParsonHelper::jsonArrayGetString(ja_signalgos, i);
            is_found = (s == signAlgo);
            if (is_found) break;
        }
    }
    if (!is_found) return RET_UAPKI_UNSUPPORTED_ALG;

    *baKeyId = sba_keyid.get();
    sba_keyid.set(nullptr);

    ret = (*baKeyId) ? RET_OK : RET_UAPKI_GENERAL_ERROR;
    return ret;
}

static int parse_sign_params (JSON_Object* joSignParams, SigningDoc::SignParams& signParams)
{
    int ret = RET_OK;

    signParams.signatureFormat = signature_format_to_enum(
        ParsonHelper::jsonObjectGetString(joSignParams, "signatureFormat")
    );
    signParams.aidSignature.algorithm = ParsonHelper::jsonObjectGetString(joSignParams, "signAlgo");
    signParams.aidDigest.algorithm = ParsonHelper::jsonObjectGetString(joSignParams, "digestAlgo");
    signParams.detachedData = ParsonHelper::jsonObjectGetBoolean(joSignParams, "detachedData", true);
    signParams.includeCert = ParsonHelper::jsonObjectGetBoolean(joSignParams, "includeCert", false);
    signParams.includeTime = ParsonHelper::jsonObjectGetBoolean(joSignParams, "includeTime", false);
    signParams.includeContentTS = ParsonHelper::jsonObjectGetBoolean(joSignParams, "includeContentTS", false);

    switch (signParams.signatureFormat) {
    case SigningDoc::SignatureFormat::CADES_Av3:
    case SigningDoc::SignatureFormat::CADES_C:
    case SigningDoc::SignatureFormat::CADES_T:
        signParams.includeContentTS = true;
        signParams.includeSignatureTS = true;
    case SigningDoc::SignatureFormat::CADES_BES:
        signParams.sidUseKeyId = false;
        break;
    case SigningDoc::SignatureFormat::CMS_SID_KEYID:
        signParams.sidUseKeyId = true;
        break;
    case SigningDoc::SignatureFormat::RAW:
        break;
    default:
        ret = RET_UAPKI_INVALID_PARAMETER;
    }

    if (ParsonHelper::jsonObjectHasValue(joSignParams, "signaturePolicy", JSONObject)) {
        JSON_Object* jo_sigpolicy = json_object_get_object(joSignParams, "signaturePolicy");
        const string sig_policyid = ParsonHelper::jsonObjectGetString(jo_sigpolicy, "sigPolicyId");
        DO(UapkiNS::AttributeHelper::encodeSignaturePolicy(sig_policyid, &signParams.attrSignPolicy.baValues));
        signParams.attrSignPolicy.type = string(OID_PKCS9_SIG_POLICY_ID);
    }

cleanup:
    return ret;
}   //  parse_sign_params

static vector<string> rand_uris (const vector<string>& uris)
{
    if (uris.size() < 2) return uris;

    UapkiNS::SmartBA sba_randoms;
    if (!sba_randoms.set(ba_alloc_by_len(uris.size() - 1))) return uris;

    if (drbg_random(sba_randoms.get()) != RET_OK) return uris;

    vector<string> rv_uris, src = uris;
    const uint8_t* buf = sba_randoms.buf();
    for (size_t i = 0; i < uris.size() - 1; i++) {
        const size_t rnd = buf[i] % src.size();
        rv_uris.push_back(src[rnd]);
        src.erase(src.begin() + rnd);
    }
    rv_uris.push_back(src[0]);
    return rv_uris;
}   //  rand_uris

static int tsp_process (SigningDoc& sdoc, MessageImprintParams& msgimParams, ByteArray **baTsToken)
{
    int ret = RET_OK;
    TspRequestParams tsp_params;
    UapkiNS::SmartBA sba_req, sba_resp, sba_tstinfo, sba_tstoken;
    uint32_t status = 0;
    uint8_t byte = 0;

    CHECK_PARAM(baTsToken != nullptr);

    CHECK_NOT_NULL(tsp_params.nonce = ba_alloc_by_len(8));
    DO(drbg_random(tsp_params.nonce));
    DO(ba_get_byte(tsp_params.nonce, 0, &byte));
    DO(ba_set_byte(tsp_params.nonce, 0, byte & 0x7F));  //  Integer must be a positive number
    tsp_params.certReq = false;
    tsp_params.reqPolicy = sdoc.signParams->tspPolicy;

    DO(tsp_request_encode(&msgimParams, &tsp_params, &sba_req));
    DEBUG_OUTCON(printf("tsp_process(), request: "); ba_print(stdout, sba_req.get()));

    if (sdoc.tspUri.empty()) {
        const vector<string> shuffled_uris = rand_uris(sdoc.signParams->tspUris);
        for (auto& it : shuffled_uris) {
            ret = HttpHelper::post(it.c_str(), HttpHelper::CONTENT_TYPE_TSP_REQUEST, sba_req.get(), &sba_resp);
            if (ret == RET_OK) {
                sdoc.tspUri = it.c_str();
                break;
            }
        }
    }
    else {
        ret = HttpHelper::post(sdoc.tspUri.c_str(), HttpHelper::CONTENT_TYPE_TSP_REQUEST, sba_req.get(), &sba_resp);
    }
    if (ret != RET_OK) {
        SET_ERROR(RET_UAPKI_TSP_NOT_RESPONDING);
    }

    DEBUG_OUTCON(printf("tsp_process(), response: "); ba_print(stdout, sba_resp.get()));
    DO(tsp_response_parse(sba_resp.get(), &status, &sba_tstoken, &sba_tstinfo));
    if ((status != PKIStatus_granted) && (status != PKIStatus_grantedWithMods)) {
        //ret = parse_tsp_response_statusinfo(ba_tsr, &status, &s_statusString, &failInfo);
        SET_ERROR(RET_UAPKI_TSP_RESPONSE_NOT_GRANTED);
    }

    DO(tsp_tstinfo_is_equal_request(sba_req.get(), sba_tstinfo.get()));

    *baTsToken = sba_tstoken.get();
    sba_tstoken.set(nullptr);

cleanup:
    return ret;
}   //  tsp_process

static int add_timestamp_to_attrs (SigningDoc& sdoc, const string& attrType)
{
    int ret = RET_OK;
    const bool is_contentts = (attrType == string(OID_PKCS9_CONTENT_TIMESTAMP));
    MessageImprintParams msgim_params;
    UapkiNS::SmartBA sba_hash, sba_tstoken;

    msgim_params.hashAlgo = sdoc.signParams->aidDigest.algorithm.c_str();
    msgim_params.hashAlgoParam_isNULL = false;
    if (is_contentts) {
        msgim_params.hashedMessage = sdoc.baMessageDigest;
    }
    else {
        DO(sdoc.digestSignature(&sba_hash));
        msgim_params.hashedMessage = sba_hash.get();
    }

    DO(tsp_process(sdoc, msgim_params, &sba_tstoken));

    if (is_contentts) {
        DO(sdoc.addSignedAttribute(attrType, sba_tstoken.get()));
    }
    else {
        DO(sdoc.addUnsignedAttribute(attrType, sba_tstoken.get()));
    }
    sba_tstoken.set(nullptr);

cleanup:
    return ret;
}   //  add_timestamp_to_attrs

static int parse_docattrs_from_json (SigningDoc& sdoc, JSON_Object* joDoc, const string& keyAttributes)
{
    const JSON_Array* ja_attrs = json_object_get_array(joDoc, keyAttributes.c_str());
    if (!ja_attrs) return RET_OK;

    const size_t cnt_attrs = json_array_get_count(ja_attrs);
    if (cnt_attrs == 0) return RET_OK;

    int ret = RET_OK;
    const bool is_signedattrs = (keyAttributes == string("signedAttributes"));
    for (size_t i = 0; i < cnt_attrs; i++) {
        UapkiNS::SmartBA sba_values;
        JSON_Object* jo_attr = json_array_get_object(ja_attrs, i);
        const string s_type = ParsonHelper::jsonObjectGetString(jo_attr, "type");
        sba_values.set(json_object_get_base64(jo_attr, "bytes"));
        if (s_type.empty() || !oid_is_valid(s_type.c_str()) || (sba_values.size() == 0)) {
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

static int parse_doc_from_json (SigningDoc& sdoc, JSON_Object* joDoc)
{
    if (!joDoc) return RET_UAPKI_INVALID_PARAMETER;

    sdoc.id = ParsonHelper::jsonObjectGetString(joDoc, "id");
    sdoc.isDigest = ParsonHelper::jsonObjectGetBoolean(joDoc, "isDigest", false);
    sdoc.baData = json_object_get_base64(joDoc, "bytes");
    if (sdoc.id.empty() || (ba_get_len(sdoc.baData) == 0)) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    if (sdoc.signParams->signatureFormat != SigningDoc::SignatureFormat::RAW) {
        sdoc.contentType = ParsonHelper::jsonObjectGetString(joDoc, "type", string(OID_PKCS7_DATA));
        if (!oid_is_valid(sdoc.contentType.c_str())) return RET_UAPKI_INVALID_PARAMETER;
        DO(parse_docattrs_from_json(sdoc, joDoc, string("signedAttributes")));
        DO(parse_docattrs_from_json(sdoc, joDoc, string("unsignedAttributes")));
    }

cleanup:
    return ret;
}   //  parse_doc_from_json


int uapki_sign (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    LibraryConfig* config = nullptr;
    CerStore* cer_store = nullptr;
    SigningDoc::SignParams sign_params;
    size_t cnt_docs = 0;
    JSON_Array* ja_results = nullptr;
    JSON_Array* ja_sources = nullptr;
    vector<SigningDoc> signing_docs;
    vector<ByteArray*> refba_hashes;
    UapkiNS::VectorBA vba_signatures;

    CmStorageProxy* storage = CmProviders::openedStorage();
    if (!storage) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!storage->keyIsSelected()) return RET_UAPKI_KEY_NOT_SELECTED;

    config = get_config();
    cer_store = get_cerstore();
    if (!config || !cer_store) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    DO(parse_sign_params(json_object_get_object(joParams, "signParams"), sign_params));

    if (sign_params.includeContentTS || sign_params.includeSignatureTS) {
        if (config->getOffline()) {
            SET_ERROR(RET_UAPKI_OFFLINE_MODE);
        }
    }

    ja_sources = json_object_get_array(joParams, "dataTbs");
    cnt_docs = json_array_get_count(ja_sources);
    if ((cnt_docs == 0) || (cnt_docs > SIGN_MAX_DOCS)) { 
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    DO(get_info_signalgo_and_keyid(*storage, sign_params.aidSignature.algorithm, &sign_params.baKeyId));
    sign_params.hashSignature = hash_from_oid(sign_params.aidSignature.algorithm.c_str());
    if (sign_params.hashSignature == HashAlg::HASH_ALG_UNDEFINED) {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }

    if (sign_params.aidDigest.algorithm.empty() || (sign_params.signatureFormat == SigningDoc::SignatureFormat::RAW)) {
        sign_params.hashDigest = sign_params.hashSignature;
        sign_params.aidDigest.algorithm = string(hash_to_oid(sign_params.hashDigest));
    }
    else {
        sign_params.hashDigest = hash_from_oid(sign_params.aidDigest.algorithm.c_str());
    }
    if (sign_params.hashDigest == HashAlg::HASH_ALG_UNDEFINED) {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }

    if ((sign_params.signatureFormat != SigningDoc::SignatureFormat::RAW) && ((!sign_params.sidUseKeyId || sign_params.includeCert))) {
        DO(cer_store->getCertByKeyId(sign_params.baKeyId, &sign_params.cerStoreItem));
    }

    if (sign_params.includeContentTS || sign_params.includeSignatureTS) {
        const LibraryConfig::TspParams& tsp_config = config->getTsp();
        sign_params.tspPolicy = (!tsp_config.policyId.empty()) ? tsp_config.policyId.c_str() : nullptr;
        if (sign_params.cerStoreItem) {
            if (tsp_config.forced && !tsp_config.uris.empty()) {
                sign_params.tspUris = tsp_config.uris;
            }
            else {
                ret = sign_params.cerStoreItem->getTspUris(sign_params.tspUris);
                if (ret != RET_OK) {
                    sign_params.tspUris = tsp_config.uris;
                    ret = RET_OK;
                }
            }
        }
        else {
            sign_params.tspUris = tsp_config.uris;
        }

        if (sign_params.tspUris.empty()) {
            SET_ERROR(RET_UAPKI_TSP_URL_NOT_PRESENT);
        }
    }

    switch (sign_params.signatureFormat) {
    case SigningDoc::SignatureFormat::CADES_BES:
    case SigningDoc::SignatureFormat::CADES_T:
        DO(encode_attrvalue_signingcert(sign_params));
        break;
    case SigningDoc::SignatureFormat::CADES_C:
        DO(encode_attrvalue_signingcert(sign_params));
        //DO(encode_attrvalue_certificaterefs(sign_params));
        //DO(encode_attrvalue_revocationrefs(sign_params));
        break;
    case SigningDoc::SignatureFormat::CADES_Av3:
        DO(encode_attrvalue_signingcert(sign_params));
        //DO(encode_attrvalue_certificaterefs(sign_params));
        //DO(encode_attrvalue_revocationrefs(sign_params));
        //DO(encode_attrvalue_certificatevalues(sign_params));
        //DO(encode_attrvalue_revocationvalues(sign_params));
        break;
    default:
        break;
    }

    signing_docs.resize(cnt_docs);
    //  Parse and load all TBS-data
    for (size_t i = 0; i < signing_docs.size(); i++) {
        SigningDoc& sdoc = signing_docs[i];
        DO(sdoc.init(&sign_params));
        DO(parse_doc_from_json(sdoc, json_array_get_object(ja_sources, i)));
    }

    if (sign_params.signatureFormat != SigningDoc::SignatureFormat::RAW) {
        for (size_t i = 0; i < signing_docs.size(); i++) {
            SigningDoc& sdoc = signing_docs[i];

            DO(sdoc.digestMessage());
            if (sign_params.includeContentTS) {
                //  After digestMessage and before buildSignedAttributes
                DO(add_timestamp_to_attrs(sdoc, string(OID_PKCS9_CONTENT_TIMESTAMP)));
            }

            DO(sdoc.buildSignedAttributes());
            DO(sdoc.digestSignedAttributes());
            refba_hashes.push_back(sdoc.baHashSignedAttrs);
        }

        DO(storage->keySign(
            sign_params.aidSignature.algorithm,
            nullptr,
            refba_hashes,
            vba_signatures
        ));

        for (size_t i = 0; i < signing_docs.size(); i++) {
            SigningDoc& sdoc = signing_docs[i];
            DO(sdoc.setSignature(vba_signatures[i]));
            vba_signatures[i] = nullptr;
            //  Add unsigned attrs before call buildSignedData
            if (sign_params.includeSignatureTS) {
                DO(add_timestamp_to_attrs(sdoc, string(OID_PKCS9_TIMESTAMP_TOKEN)));
            }
            DO(sdoc.buildSignedData());
        }
    }
    else {
        for (size_t i = 0; i < signing_docs.size(); i++) {
            SigningDoc& sdoc = signing_docs[i];
            DO(sdoc.digestMessage());
            refba_hashes.push_back(sdoc.baMessageDigest);
        }

        DO(storage->keySign(
            sign_params.aidSignature.algorithm,
            nullptr,
            refba_hashes,
            vba_signatures
        ));

        for (size_t i = 0; i < signing_docs.size(); i++) {
            signing_docs[i].baSignature = vba_signatures[i];
            vba_signatures[i] = nullptr;
        }
    }

    DO_JSON(json_object_set_value(joResult, "signatures", json_value_init_array()));
    ja_results = json_object_get_array(joResult, "signatures");
    for (size_t i = 0; i < signing_docs.size(); i++) {
        JSON_Object* jo_doc = nullptr;
        SigningDoc& sdoc = signing_docs[i];
        DO_JSON(json_array_append_value(ja_results, json_value_init_object()));
        if ((jo_doc = json_array_get_object(ja_results, i)) == nullptr) {
            SET_ERROR(RET_UAPKI_GENERAL_ERROR);
        }
        DO_JSON(json_object_set_string(jo_doc, "id", sdoc.id.c_str()));
        DO_JSON(json_object_set_base64(jo_doc, "bytes", sdoc.getEncoded()));
    }

cleanup:
    return ret;
}
