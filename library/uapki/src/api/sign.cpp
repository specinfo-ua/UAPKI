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
#include "ocsp-helper.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include "store-utils.h"
#include "time-utils.h"
#include "tsp-helper.h"
#include "uapki-ns.h"
#include "uapki-debug.h"


#undef FILE_MARKER
#define FILE_MARKER "api/sign.cpp"

#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif

#define DEBUG_OUTPUT_OUTSTREAM(msg,baData)
#ifndef DEBUG_OUTPUT_OUTSTREAM
DEBUG_OUTPUT_OUTSTREAM_FUNC
#define DEBUG_OUTPUT_OUTSTREAM(msg,baData) debug_output_stream(DEBUG_OUTSTREAM_FOPEN,"SIGN",msg,baData)
#endif


using namespace std;


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

    const UapkiNS::SignatureFormat signature_format = UapkiNS::signatureFormatFromString(
        ParsonHelper::jsonObjectGetString(joSignParams, "signatureFormat")
    );
    signParams.aidSignature.algorithm = ParsonHelper::jsonObjectGetString(joSignParams, "signAlgo");
    signParams.aidDigest.algorithm = ParsonHelper::jsonObjectGetString(joSignParams, "digestAlgo");
    signParams.detachedData = ParsonHelper::jsonObjectGetBoolean(joSignParams, "detachedData", true);
    signParams.includeCert = ParsonHelper::jsonObjectGetBoolean(joSignParams, "includeCert", false);
    signParams.includeTime = ParsonHelper::jsonObjectGetBoolean(joSignParams, "includeTime", false);
    signParams.includeContentTS = ParsonHelper::jsonObjectGetBoolean(joSignParams, "includeContentTS", false);

    DO(signParams.setSignatureFormat(signature_format));

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

static int tsp_process (SigningDoc& sdoc, UapkiNS::Tsp::TspHelper& tspHelper)
{
    int ret = RET_OK;
    UapkiNS::SmartBA sba_resp, sba_tstinfo, sba_tstoken;

    DO(tspHelper.genNonce(8));
    //DO(tspHelper.setCertReq(param_certreq));
    if (sdoc.signParams->tspPolicy) {
        DO(tspHelper.setReqPolicy(string(sdoc.signParams->tspPolicy)));
    }

    DO(tspHelper.encodeRequest());

    if (sdoc.tspUri.empty()) {
        const vector<string> shuffled_uris = rand_uris(sdoc.signParams->tspUris);
        for (auto& it : shuffled_uris) {
            DEBUG_OUTPUT_OUTSTREAM(string("TSP-request, url[]=") + it, tspHelper.getRequestEncoded());
            ret = HttpHelper::post(
                it.c_str(),
                HttpHelper::CONTENT_TYPE_TSP_REQUEST,
                tspHelper.getRequestEncoded(),
                &sba_resp
            );
            DEBUG_OUTPUT_OUTSTREAM(string("TSP-response, url=") + it, sba_resp.get());
            if (ret == RET_OK) {
                sdoc.tspUri = it.c_str();
                break;
            }
        }
    }
    else {
        DEBUG_OUTPUT_OUTSTREAM(string("TSP-request, url=") + sdoc.tspUri, tspHelper.getRequestEncoded());
        ret = HttpHelper::post(
            sdoc.tspUri.c_str(),
            HttpHelper::CONTENT_TYPE_TSP_REQUEST,
            tspHelper.getRequestEncoded(),
            &sba_resp
        );
        DEBUG_OUTPUT_OUTSTREAM(string("TSP-response, url=") + sdoc.tspUri, sba_resp.get());
    }
    if (ret != RET_OK) {
        SET_ERROR(RET_UAPKI_TSP_NOT_RESPONDING);
    }

    DO(tspHelper.parseResponse(sba_resp.get()));
    if (
        (tspHelper.getStatus() != UapkiNS::Tsp::PkiStatus::GRANTED) &&
        (tspHelper.getStatus() != UapkiNS::Tsp::PkiStatus::GRANTED_WITHMODS)
    ) {
        SET_ERROR(RET_UAPKI_TSP_RESPONSE_NOT_GRANTED);
    }

    DO(tspHelper.tstInfoIsEqualRequest());

cleanup:
    return ret;
}   //  tsp_process

static int add_timestamp_to_attrs (SigningDoc& sdoc, const string& attrType)
{
    int ret = RET_OK;
    const bool is_contentts = (attrType == string(OID_PKCS9_CONTENT_TIMESTAMP));
    UapkiNS::Tsp::TspHelper tsp_helper;

    DO(tsp_helper.init());

    if (is_contentts) {
        DO(tsp_helper.setMessageImprint(sdoc.signParams->aidDigest, sdoc.baMessageDigest));
    }
    else {
        UapkiNS::SmartBA sba_hash;
        DO(sdoc.digestSignature(&sba_hash));
        DO(tsp_helper.setMessageImprint(sdoc.signParams->aidDigest, sba_hash.get()));
    }

    DO(tsp_process(sdoc, tsp_helper));

    if (is_contentts) {
        DO(sdoc.addSignedAttribute(attrType, tsp_helper.getTsToken(true)));
    }
    else {
        DO(sdoc.addUnsignedAttribute(attrType, tsp_helper.getTsToken(true)));
    }

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
    if (sdoc.signParams->signatureFormat != UapkiNS::SignatureFormat::RAW) {
        sdoc.contentType = ParsonHelper::jsonObjectGetString(joDoc, "type", string(OID_PKCS7_DATA));
        if (!oid_is_valid(sdoc.contentType.c_str())) return RET_UAPKI_INVALID_PARAMETER;
        DO(parse_docattrs_from_json(sdoc, joDoc, string("signedAttributes")));
        DO(parse_docattrs_from_json(sdoc, joDoc, string("unsignedAttributes")));
    }

cleanup:
    return ret;
}   //  parse_doc_from_json

static int verify_ocsp_responsedata (UapkiNS::Ocsp::OcspHelper& ocspClient, CerStore& cerStore)
{
    int ret = RET_OK;
    UapkiNS::SmartBA sba_responderid;
    UapkiNS::VectorBA vba_certs;
    UapkiNS::Ocsp::ResponderIdType responder_idtype = UapkiNS::Ocsp::ResponderIdType::UNDEFINED;
    SIGNATURE_VERIFY::STATUS status_sign = SIGNATURE_VERIFY::STATUS::UNDEFINED;
    CerStore::Item* cer_responder = nullptr;

    DO(ocspClient.getCerts(vba_certs));
    for (auto& it : vba_certs) {
        bool is_unique;
        DO(cerStore.addCert(it, false, false, false, is_unique, nullptr));
        it = nullptr;
    }

    DO(ocspClient.getResponderId(responder_idtype, &sba_responderid));
    if (responder_idtype == UapkiNS::Ocsp::ResponderIdType::BY_NAME) {
        DO(cerStore.getCertBySubject(sba_responderid.get(), &cer_responder));
    }
    else {
        //  responder_idtype == OcspHelper::ResponderIdType::BY_KEY
        DO(cerStore.getCertByKeyId(sba_responderid.get(), &cer_responder));
    }

    ret = ocspClient.verifyTbsResponseData(cer_responder, status_sign);
    if (ret == RET_VERIFY_FAILED) {
        SET_ERROR(RET_UAPKI_OCSP_RESPONSE_VERIFY_FAILED);
    }
    else if (ret != RET_OK) {
        SET_ERROR(RET_UAPKI_OCSP_RESPONSE_VERIFY_ERROR);
    }

cleanup:
    return ret;
}

static int get_cert_status (SigningDoc::CadesBuilder& cadesBuilder, CerStore::Item* cerSubject)
{
    int ret = RET_OK;
    CerStore& cer_store = *cadesBuilder.getCerStore();
    SigningDoc::SignParams& sign_params = cadesBuilder.getSignParams();
    UapkiNS::Ocsp::OcspHelper ocsp_helper;
    CerStore::Item* cer_issuer = nullptr;
    UapkiNS::SmartBA sba_resp;
    vector<string> shuffled_uris, uris;
    bool is_selfsigned, need_update;

    DO(cer_store.getIssuerCert(cerSubject, &cer_issuer, is_selfsigned));
    if (is_selfsigned) return RET_OK;

    ret = cerSubject->getOcspUris(uris);
    if ((ret != RET_OK) && (ret != RET_UAPKI_EXTENSION_NOT_PRESENT)) {
        SET_ERROR(RET_UAPKI_OCSP_URL_NOT_PRESENT);
    }

    need_update = cerSubject->certStatusByOcsp.isExpired(TimeUtils::nowMsTime());
    if (need_update) {
        DO(ocsp_helper.init());
        DO(ocsp_helper.addCert(cer_issuer, cerSubject));
        DO(ocsp_helper.genNonce(20));
        DO(ocsp_helper.encodeRequest());

        shuffled_uris = rand_uris(uris);
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
                DEBUG_OUTCON(printf("get_cert_status(), url: '%s', size: %zu\n", it.c_str(), sba_resp.size()));
                DEBUG_OUTCON(if (sba_resp.size() < 1024) { ba_print(stdout, sba_resp.get()); });
                break;
            }
        }
        if (ret != RET_OK) {
            SET_ERROR(ret);
        }
        else if (sba_resp.size() == 0) {
            SET_ERROR(RET_UAPKI_OCSP_RESPONSE_INVALID);
        }
    }

    DO(ocsp_helper.parseResponse(need_update ? sba_resp.get() : cerSubject->certStatusByOcsp.baResult));

    if (ocsp_helper.getResponseStatus() == UapkiNS::Ocsp::ResponseStatus::SUCCESSFUL) {
        DO(verify_ocsp_responsedata(ocsp_helper, cer_store));
        DO(ocsp_helper.checkNonce());
        DO(ocsp_helper.scanSingleResponses());

        const UapkiNS::Ocsp::OcspHelper::OcspRecord& ocsp_record = ocsp_helper.getOcspRecord(0); //  Work with one OCSP request that has one certificate
        if (need_update) {
            DO(cerSubject->certStatusByOcsp.set(
                ocsp_record.status,
                ocsp_record.msThisUpdate + UapkiNS::Ocsp::OFFSET_EXPIRE_DEFAULT,
                sba_resp.get()
            ));
        }

        SigningDoc::OcspResponseItem* ocsp_respitem = nullptr;
        switch (ocsp_record.status) {
        case UapkiNS::CertStatus::GOOD:
            ocsp_respitem = cadesBuilder.addOcspResponseItem();
            if (!ocsp_respitem) {
                SET_ERROR(RET_UAPKI_GENERAL_ERROR);
            }
            ocsp_respitem->baBasicOcspResponse = ocsp_helper.getBasicOcspResponseEncoded(true);
            DO(ocsp_helper.getOcspIdentifier(&ocsp_respitem->baOcspIdentifier));
            DO(UapkiNS::Ocsp::generateOtherHash(
                need_update ? sba_resp.get() : cerSubject->certStatusByOcsp.baResult,
                sign_params.aidDigest,
                &ocsp_respitem->baOcspRespHash
            ));
            break;
        case UapkiNS::CertStatus::REVOKED:
            SET_ERROR(RET_UAPKI_CERT_STATUS_REVOKED);
            break;
        default:
            SET_ERROR(RET_UAPKI_CERT_STATUS_UNKNOWN);
            break;
        }
    }

cleanup:
    return ret;
}   //  get_cert_status

static int get_cert_status_for_chain_certs (SigningDoc::CadesBuilder& cadesBuilder)
{
    int ret = RET_OK;
    const UapkiNS::SignatureFormat signature_format = cadesBuilder.getSignParams().signatureFormat;

    //  Now use OCSP for CADES_C and CADES_Av3, later for all
    switch (signature_format) {
    case UapkiNS::SignatureFormat::CADES_C:
    case UapkiNS::SignatureFormat::CADES_Av3:
        break;
    default:
        return RET_OK;
    }

    if (HttpHelper::isOfflineMode()) {
        SET_ERROR(RET_UAPKI_OFFLINE_MODE);
    }

    for (auto& it : cadesBuilder.getChainCerts()) {
        DO(get_cert_status(cadesBuilder, it));
    }

cleanup:
    return ret;
}   //  get_cert_status_for_chain_certs

int uapki_sign (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    LibraryConfig* config = nullptr;
    SigningDoc::CadesBuilder cades_builder(get_cerstore());
    SigningDoc::SignParams& sign_params = cades_builder.getSignParams();
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
    if (!config || !cades_builder.getCerStore()) {
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
    if ((cnt_docs == 0) || (cnt_docs > SigningDoc::MAX_COUNT_DOCS)) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    DO(get_info_signalgo_and_keyid(*storage, sign_params.aidSignature.algorithm, &sign_params.baKeyId));
    sign_params.hashSignature = hash_from_oid(sign_params.aidSignature.algorithm.c_str());
    if (sign_params.hashSignature == HashAlg::HASH_ALG_UNDEFINED) {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }

    if (sign_params.aidDigest.algorithm.empty() || (sign_params.signatureFormat == UapkiNS::SignatureFormat::RAW)) {
        sign_params.hashDigest = sign_params.hashSignature;
        sign_params.aidDigest.algorithm = string(hash_to_oid(sign_params.hashDigest));
    }
    else {
        sign_params.hashDigest = hash_from_oid(sign_params.aidDigest.algorithm.c_str());
    }
    if (sign_params.hashDigest == HashAlg::HASH_ALG_UNDEFINED) {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }

    if ((sign_params.signatureFormat != UapkiNS::SignatureFormat::RAW) && ((!sign_params.sidUseKeyId || sign_params.includeCert))) {
        DO(cades_builder.getCerStore()->getCertByKeyId(sign_params.baKeyId, &sign_params.cerStoreItem));
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

    DO(cades_builder.init());
    if (cades_builder.isCadesFormat()) {
        DO(cades_builder.buildChainCerts());
        DO(get_cert_status_for_chain_certs(cades_builder));
        DO(cades_builder.process());
    }

    signing_docs.resize(cnt_docs);
    //  Parse and load all TBS-data
    for (size_t i = 0; i < signing_docs.size(); i++) {
        SigningDoc& sdoc = signing_docs[i];
        DO(sdoc.init(&sign_params));
        DO(parse_doc_from_json(sdoc, json_array_get_object(ja_sources, i)));
    }

    if (sign_params.signatureFormat != UapkiNS::SignatureFormat::RAW) {
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
