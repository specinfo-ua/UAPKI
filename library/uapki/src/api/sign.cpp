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
#include "cm-providers.h"
#include "cms-utils.h"
#include "doc-signflow.h"
#include "global-objects.h"
#include "http-helper.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include "store-utils.h"
#include "time-utils.h"
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


static SIGNATURE_FORMAT cades_str_to_enum (const char* str_format, const SIGNATURE_FORMAT format_by_default)
{
    SIGNATURE_FORMAT rv = SIGNATURE_FORMAT::CADES_UNDEFINED;
    if (str_format == nullptr) {
        rv = format_by_default;
    }
    else if (strcmp(str_format, CADES_BES_STR) == 0) {
        rv = SIGNATURE_FORMAT::CADES_BES;
    }
    else if (strcmp(str_format, CADES_T_STR) == 0) {
        rv = SIGNATURE_FORMAT::CADES_T;
    }
    else if (strcmp(str_format, CADES_C_STR) == 0) {
        rv = SIGNATURE_FORMAT::CADES_C;
    }
    else if (strcmp(str_format, CADES_A_V3_STR) == 0) {
        rv = SIGNATURE_FORMAT::CADES_Av3;
    }
    else if (strcmp(str_format, CMS_STR) == 0) {
        rv = SIGNATURE_FORMAT::CMS_SID_KEYID;
    }
    else if (strcmp(str_format, RAW_STR) == 0) {
        rv = SIGNATURE_FORMAT::RAW;
    }
    return rv;
}

static int doc_get_docattrs (JSON_Array* jaAttrs, vector<DocAttr*>& attrs)
{
    int ret = RET_OK;
    DocAttr* doc_attr = nullptr;
    ByteArray* ba_bytes = nullptr;
    const char* s_type = nullptr;
    const size_t cnt_attrs = json_array_get_count(jaAttrs);

    for (size_t i = 0; i < cnt_attrs; i++) {
        JSON_Object* jo_attr = json_array_get_object(jaAttrs, i);
        s_type = json_object_get_string(jo_attr, "type");
        ba_bytes = json_object_get_base64(jo_attr, "bytes");
        if (!s_type || !ba_bytes) {
            return RET_UAPKI_INVALID_PARAMETER;
        }

        CHECK_NOT_NULL(doc_attr = new DocAttr(s_type, ba_bytes));
        ba_bytes = nullptr;

        attrs.push_back(doc_attr);
        doc_attr = nullptr;
    }

cleanup:
    delete doc_attr;
    ba_free(ba_bytes);
    return RET_OK;
}

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

static int parse_sign_params (JSON_Object* joSignParams, SignParams& signParams)
{
    int ret = RET_OK;

    signParams.signatureFormat = cades_str_to_enum(json_object_get_string(joSignParams, "signatureFormat"), SIGNATURE_FORMAT::CADES_BES);
    signParams.signAlgo = ParsonHelper::jsonObjectGetString(joSignParams, "signAlgo");
    signParams.digestAlgo = ParsonHelper::jsonObjectGetString(joSignParams, "digestAlgo");
    signParams.detachedData = ParsonHelper::jsonObjectGetBoolean(joSignParams, "detachedData", true);
    signParams.includeCert = ParsonHelper::jsonObjectGetBoolean(joSignParams, "includeCert", false);
    signParams.includeTime = ParsonHelper::jsonObjectGetBoolean(joSignParams, "includeTime", false);
    signParams.includeContentTS = ParsonHelper::jsonObjectGetBoolean(joSignParams, "includeContentTS", false);

    switch (signParams.signatureFormat) {
    case SIGNATURE_FORMAT::CADES_T:
        signParams.includeContentTS = true;
        signParams.includeSignatureTS = true;
    case SIGNATURE_FORMAT::CADES_BES:
        signParams.sidUseKeyId = false;
        break;
    case SIGNATURE_FORMAT::CMS_SID_KEYID:
        signParams.sidUseKeyId = true;
        break;
    case SIGNATURE_FORMAT::RAW:
        break;
    case SIGNATURE_FORMAT::CADES_Av3:
    case SIGNATURE_FORMAT::CADES_C:
    default:
        ret = RET_UAPKI_INVALID_PARAMETER;
    }

    return ret;
}

static int parse_sigpolicy_and_encode_attrvalue (JSON_Object* joSignPolicyParams, ByteArray** baEncoded)
{
    if (!joSignPolicyParams) return RET_OK;

    const string sig_policyid = ParsonHelper::jsonObjectGetString(joSignPolicyParams, "sigPolicyId");
    if (sig_policyid.empty()) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    SignaturePolicyIdentifier_t* spi = nullptr;

    ASN_ALLOC_TYPE(spi, SignaturePolicyIdentifier_t);

    spi->present = SignaturePolicyIdentifier_PR_signaturePolicyId;
    DO(asn_set_oid_from_text(sig_policyid.c_str(), &spi->choice.signaturePolicyId.sigPolicyId));

    DO(asn_encode_ba(get_SignaturePolicyIdentifier_desc(), spi, baEncoded));

cleanup:
    asn_free(get_SignaturePolicyIdentifier_desc(), spi);
    return ret;
}

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
}

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
}

static int docattr_add (const char* type, const ByteArray* baEncoded, vector<DocAttr*>& attrs)
{
    int ret = RET_OK;
    DocAttr* doc_attr = nullptr;
    ByteArray* ba_value = nullptr;

    CHECK_NOT_NULL(ba_value = ba_copy_with_alloc(baEncoded, 0, 0));

    CHECK_NOT_NULL(doc_attr = new DocAttr(type, ba_value));
    ba_value = nullptr;

    attrs.push_back(doc_attr);
    doc_attr = nullptr;

cleanup:
    delete doc_attr;
    ba_free(ba_value);
    return ret;
}

static int sattr_add_content_ts (SigningDoc& sdoc)
{
    int ret = RET_OK;
    MessageImprintParams msgim_params;
    UapkiNS::SmartBA sba_tstoken;

    msgim_params.hashAlgo = sdoc.signParams->digestAlgo.c_str();
    msgim_params.hashAlgoParam_isNULL = false;
    msgim_params.hashedMessage = sdoc.baMessageDigest;

    DO(tsp_process(sdoc, msgim_params, &sba_tstoken));

    docattr_add(OID_PKCS9_CONTENT_TIMESTAMP, sba_tstoken.get(), sdoc.signedAttrs);
    sba_tstoken.set(nullptr);

cleanup:
    return ret;
}

static int unsattr_add_signature_ts (SigningDoc& sdoc)
{
    int ret = RET_OK;
    MessageImprintParams msgim_params;
    UapkiNS::SmartBA sba_hash, sba_tstoken;

    DO(sdoc.digestSignature(&sba_hash));

    msgim_params.hashAlgo = sdoc.signParams->digestAlgo.c_str();
    msgim_params.hashAlgoParam_isNULL = false;
    msgim_params.hashedMessage = sba_hash.get();

    DO(tsp_process(sdoc, msgim_params, &sba_tstoken));

    docattr_add(OID_PKCS9_TIMESTAMP_TOKEN, sba_tstoken.get(), sdoc.unsignedAttrs);
    sba_tstoken.set(nullptr);

cleanup:
    return ret;
}


int uapki_sign (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    LibraryConfig* config = nullptr;
    CerStore* cer_store = nullptr;
    SignParams sign_params;
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
    DO(parse_sigpolicy_and_encode_attrvalue(json_object_dotget_object(joParams, "signParams.signaturePolicy"), &sign_params.baSignPolicy));

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

    DO(get_info_signalgo_and_keyid(*storage, sign_params.signAlgo, &sign_params.baKeyId));
    sign_params.signHashAlgo = hash_from_oid(sign_params.signAlgo.c_str());
    if (sign_params.signHashAlgo == HashAlg::HASH_ALG_UNDEFINED) {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }

    if (sign_params.digestAlgo.empty() || (sign_params.signatureFormat == SIGNATURE_FORMAT::RAW)) {
        sign_params.digestHashAlgo = sign_params.signHashAlgo;
        sign_params.digestAlgo = string(hash_to_oid(sign_params.digestHashAlgo));
    }
    else {
        sign_params.digestHashAlgo = hash_from_oid(sign_params.digestAlgo.c_str());
    }
    if (sign_params.digestHashAlgo == HashAlg::HASH_ALG_UNDEFINED) {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }

    if ((sign_params.signatureFormat != SIGNATURE_FORMAT::RAW) && ((!sign_params.sidUseKeyId || sign_params.includeCert))) {
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

    if ((sign_params.signatureFormat >= SIGNATURE_FORMAT::CADES_BES) && (sign_params.signatureFormat <= SIGNATURE_FORMAT::CADES_Av3)) {
        DO(gen_attrvalue_ess_certid_v2(sign_params.digestHashAlgo, sign_params.cerStoreItem->baEncoded, &sign_params.baEssCertId));
    }

    signing_docs.resize(cnt_docs);
    //  Parse and load all TBS-data
    for (size_t i = 0; i < signing_docs.size(); i++) {
        SigningDoc& sdoc = signing_docs[i];
        JSON_Object* jo_doc = json_array_get_object(ja_sources, i);

        DO(sdoc.init(&sign_params, json_object_get_string(jo_doc, "id"), json_object_get_base64(jo_doc, "bytes")));
        sdoc.isDigest = ParsonHelper::jsonObjectGetBoolean(jo_doc, "isDigest", false);
        if (sign_params.signatureFormat != SIGNATURE_FORMAT::RAW) {
            DO(doc_get_docattrs(json_object_get_array(jo_doc, "signedAttributes"), sdoc.signedAttrs));
            DO(doc_get_docattrs(json_object_get_array(jo_doc, "unsignedAttributes"), sdoc.unsignedAttrs));
        }
    }

    if (sign_params.signatureFormat != SIGNATURE_FORMAT::RAW) {
        for (size_t i = 0; i < signing_docs.size(); i++) {
            SigningDoc& sdoc = signing_docs[i];

            if (sign_params.baEssCertId) {
                DO(docattr_add(OID_PKCS9_SIGNING_CERTIFICATE_V2, sign_params.baEssCertId, sdoc.signedAttrs));
            }
            if (sign_params.baSignPolicy) {
                DO(docattr_add(OID_PKCS9_SIG_POLICY_ID, sign_params.baSignPolicy, sdoc.signedAttrs));
            }

            DO(sdoc.digestMessage());

            //  Add signed-attribute before call buildSignedAttributes
            if (sign_params.includeContentTS) {
                DO(sattr_add_content_ts(sdoc));
            }

            DO(sdoc.buildSignedAttributes());
            DO(sdoc.digestSignedAttributes());
            refba_hashes.push_back(sdoc.baHashSignedAttrs);
        }

        DO(storage->keySign(sign_params.signAlgo, nullptr, refba_hashes, vba_signatures));

        for (size_t i = 0; i < signing_docs.size(); i++) {
            SigningDoc& sdoc = signing_docs[i];
            signing_docs[i].baSignature = vba_signatures[i];
            vba_signatures[i] = nullptr;
            //  Add unsigned attrs before call buildSignedData
            if (sign_params.includeSignatureTS) {
                DO(unsattr_add_signature_ts(sdoc));
            }
            DO(sdoc.buildUnsignedAttributes());
            DO(sdoc.buildSignedData());
        }
    }
    else {
        for (size_t i = 0; i < signing_docs.size(); i++) {
            SigningDoc& sdoc = signing_docs[i];
            DO(sdoc.digestMessage());
            refba_hashes.push_back(sdoc.baMessageDigest);
        }

        DO(storage->keySign(sign_params.signAlgo, nullptr, refba_hashes, vba_signatures));

        for (size_t i = 0; i < signing_docs.size(); i++) {
            signing_docs[i].baEncoded = vba_signatures[i];
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
        DO_JSON(json_object_set_string(jo_doc, "id", sdoc.id));
        DO_JSON(json_object_set_base64(jo_doc, "bytes", sdoc.baEncoded));
    }

cleanup:
    return ret;
}
