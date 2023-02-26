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
#include "attribute-helper.h"
#include "cm-providers.h"
#include "doc-sign.h"
#include "global-objects.h"
#include "http-helper.h"
#include "ocsp-helper.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include "signeddata-helper.h"
#include "store-utils.h"
#include "time-utils.h"
#include "tsp-helper.h"
#include "uapki-ns.h"
#include "uapki-debug.h"
#include "verify-utils.h"


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


enum class TsAttrType : uint32_t {
    UNDEFINED           = 0,
    CONTENT_TIMESTAMP   = 1,
    TIMESTAMP_TOKEN     = 2,
    ARCHIVE_TIMESTAMP   = 3
};


struct SignOptions {
    bool ignoreCertStatus;

    SignOptions (void)
        : ignoreCertStatus(false)
    {}

};  //  end struct SignOptions


static int get_info_signalgo_and_keyid (
        CmStorageProxy& storage,
        string& signAlgo,
        ByteArray** baKeyId
)
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
}   //  get_info_signalgo_and_keyid

static void parse_sign_options (
        JSON_Object* joSignOptions,
        UapkiNS::Doc::Sign::SigningDoc::SignParams& signParams,
        SignOptions& signOptions
)
{
    if (joSignOptions) {
        if (
            (signParams.signatureFormat == UapkiNS::SignatureFormat::CADES_BES) ||
            (signParams.signatureFormat == UapkiNS::SignatureFormat::CADES_T)
        ) {
            signOptions.ignoreCertStatus = ParsonHelper::jsonObjectGetBoolean(joSignOptions, "ignoreCertStatus", false);
        }
    }
}   //  parse_sign_options

static int parse_sign_params (
        JSON_Object* joSignParams,
        UapkiNS::Doc::Sign::SigningDoc::SignParams& signParams
)
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
        DO(UapkiNS::Doc::Sign::SigningDoc::encodeSignaturePolicy(
            ParsonHelper::jsonObjectGetString(jo_sigpolicy, "sigPolicyId"),
            signParams.attrSignPolicy
        ));
    }

cleanup:
    return ret;
}   //  parse_sign_params

static int verify_signeddata (
        CerStore& cerStore,
        const ByteArray* baEncoded,
        CerStore::Item** cerSigner
)
{
    int ret = RET_OK;
    UapkiNS::Pkcs7::SignedDataParser sdata_parser;
    UapkiNS::Pkcs7::SignedDataParser::SignerInfo signer_info;

    DO(sdata_parser.parse(baEncoded));
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
        DO(cerStore.getCertBySID(signer_info.getSidEncoded(), cerSigner));
        break;
    case UapkiNS::Pkcs7::SignerIdentifierType::SUBJECT_KEYID:
        DO(cerStore.getCertByKeyId(signer_info.getSidEncoded(), cerSigner));
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

static int tsp_process (
        CerStore& cerStore,
        UapkiNS::Doc::Sign::SigningDoc& sdoc,
        UapkiNS::Tsp::TspHelper& tspHelper
)
{
    int ret = RET_OK;
    const LibraryConfig::TspParams& tsp_params = sdoc.signParams->tsp;
    UapkiNS::SmartBA sba_resp, sba_tstinfo, sba_tstoken;
    CerStore::Item* cer_signer = nullptr;

    if (tsp_params.nonceLen > 0) {
        DO(tspHelper.genNonce(tsp_params.nonceLen));
    }
    DO(tspHelper.setCertReq(tsp_params.certReq));
    DO(tspHelper.setReqPolicy(tsp_params.policyId));

    DO(tspHelper.encodeRequest());

    if (sdoc.tspUri.empty()) {
        const vector<string> shuffled_uris = HttpHelper::randomURIs(tsp_params.uris);
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

    DO(verify_signeddata(cerStore, tspHelper.getTsToken(), &cer_signer));
    sdoc.addCert(cer_signer);

    DO(tspHelper.tstInfoIsEqualRequest());

cleanup:
    return ret;
}   //  tsp_process

static int add_timestamp_to_attrs (
        const TsAttrType tsAttrType,
        CerStore& cerStore,
        UapkiNS::Doc::Sign::SigningDoc& sdoc
)
{
    int ret = RET_OK;
    UapkiNS::Tsp::TspHelper tsp_helper;
    UapkiNS::SmartBA sba_hash;

    DO(tsp_helper.init());

    switch (tsAttrType) {
    case TsAttrType::CONTENT_TIMESTAMP:
        DO(tsp_helper.setMessageImprint(sdoc.signParams->aidDigest, sdoc.messageDigest.get()));
        break;
    case TsAttrType::TIMESTAMP_TOKEN:
        DO(sdoc.digestSignature(&sba_hash));
        DO(tsp_helper.setMessageImprint(sdoc.signParams->aidDigest, sba_hash.get()));
        break;
    case TsAttrType::ARCHIVE_TIMESTAMP:
        DO(tsp_helper.setMessageImprint(sdoc.signParams->aidDigest, sdoc.getAtsHash()));
        break;
    default:
        break;
    }

    DO(tsp_process(cerStore, sdoc, tsp_helper));

    switch (tsAttrType) {
    case TsAttrType::CONTENT_TIMESTAMP:
        DO(sdoc.addSignedAttribute(string(OID_PKCS9_CONTENT_TIMESTAMP), tsp_helper.getTsToken(true)));
        break;
    case TsAttrType::TIMESTAMP_TOKEN:
        DO(sdoc.addUnsignedAttribute(OID_PKCS9_TIMESTAMP_TOKEN, tsp_helper.getTsToken(true)));
        break;
    case TsAttrType::ARCHIVE_TIMESTAMP:
        DO(sdoc.addArchiveAttribute(OID_ETSI_ARCHIVE_TIMESTAMP_V3, tsp_helper.getTsToken(true)));
        break;
    default:
        break;
    }
    

cleanup:
    return ret;
}   //  add_timestamp_to_attrs

static int parse_docattrs_from_json (
        UapkiNS::Doc::Sign::SigningDoc& sdoc,
        JSON_Object* joDoc,
        const string& keyAttributes
)
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

static int parse_doc_from_json (
        UapkiNS::Doc::Sign::SigningDoc& sdoc,
        JSON_Object* joDoc
)
{
    if (!joDoc) return RET_UAPKI_INVALID_PARAMETER;

    sdoc.id = ParsonHelper::jsonObjectGetString(joDoc, "id");
    sdoc.isDigest = ParsonHelper::jsonObjectGetBoolean(joDoc, "isDigest", false);
    if (sdoc.id.empty() || !sdoc.data.set(json_object_get_base64(joDoc, "bytes"))) return RET_UAPKI_INVALID_PARAMETER;

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

static int verify_ocsp_responsedata (
        CerStore& cerStore,
        UapkiNS::Ocsp::OcspHelper& ocspClient,
        CerStore::Item** cerResponder
)
{
    int ret = RET_OK;
    UapkiNS::SmartBA sba_responderid;
    UapkiNS::VectorBA vba_certs;
    UapkiNS::Ocsp::ResponderIdType responderid_type = UapkiNS::Ocsp::ResponderIdType::UNDEFINED;
    UapkiNS::SignatureVerifyStatus status_sign = UapkiNS::SignatureVerifyStatus::UNDEFINED;

    DO(ocspClient.getCerts(vba_certs));
    for (auto& it : vba_certs) {
        bool is_unique;
        DO(cerStore.addCert(it, false, false, false, is_unique, nullptr));
        it = nullptr;
    }

    DO(ocspClient.getResponderId(responderid_type, &sba_responderid));
    if (responderid_type == UapkiNS::Ocsp::ResponderIdType::BY_NAME) {
        DO(cerStore.getCertBySubject(sba_responderid.get(), cerResponder));
    }
    else {
        //  responderid_type == OcspHelper::ResponderIdType::BY_KEY
        DO(cerStore.getCertByKeyId(sba_responderid.get(), cerResponder));
    }

    ret = ocspClient.verifyTbsResponseData(*cerResponder, status_sign);
    if (ret == RET_VERIFY_FAILED) {
        SET_ERROR(RET_UAPKI_OCSP_RESPONSE_VERIFY_FAILED);
    }
    else if (ret != RET_OK) {
        SET_ERROR(RET_UAPKI_OCSP_RESPONSE_VERIFY_ERROR);
    }

cleanup:
    return ret;
}   //  verify_ocsp_responsedata

static int process_crl (
        CrlStore& crlStore,
        const CerStore::Item* cerIssuer,
        const CerStore::Item* cerSubject,
        const ByteArray** baCrlNumber,
        const uint64_t validateTime,
        CrlStore::Item** crlItem
)
{
    int ret = RET_OK;
    const CrlStore::CrlType crl_type = (*baCrlNumber == nullptr) ? CrlStore::CrlType::FULL : CrlStore::CrlType::DELTA;
    CrlStore::Item* crl = nullptr;
    UapkiNS::SmartBA sba_crl;
    vector<string> uris;

    ret = cerSubject->getCrlUris((crl_type == CrlStore::CrlType::FULL), uris);
    if ((ret != RET_OK) && (ret != RET_UAPKI_EXTENSION_NOT_PRESENT)) {
        SET_ERROR(ret);
    }

    //TODO: need added support array uris

    crl = crlStore.getCrl(cerIssuer->baKeyId, crl_type);
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
        if (uris.empty()) {
            SET_ERROR(RET_UAPKI_CRL_URL_NOT_PRESENT);
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

        crl = crlStore.getCrl(cerIssuer->baKeyId, crl_type);
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

    DO(crl->verify(cerIssuer));

    *crlItem = crl;

cleanup:
    return ret;
}   //  process_crl

static int get_cert_status_by_crl (
        UapkiNS::Doc::Sign::SigningDoc::CerDataItem& cerDataItem
)
{
    int ret = RET_OK;
    CerStore& cer_store = *get_cerstore();
    CrlStore& crl_store = *get_crlstore();
    const uint64_t validate_time = TimeUtils::nowMsTime();
    CrlStore::Item* crl_item = nullptr;
    vector<const CrlStore::RevokedCertItem*> revoked_items;
    const ByteArray* ba_crlnumber = nullptr;
    bool is_expired = false;
    UapkiNS::CertStatus cert_status = UapkiNS::CertStatus::UNDEFINED;
    const bool cfg_crldelta_enabled = true;

    DO(cerDataItem.pcsiSubject->checkValidity(TimeUtils::nowMsTime()));

    DO(cer_store.getIssuerCert(cerDataItem.pcsiSubject, &cerDataItem.pcsiIssuer, cerDataItem.isSelfSigned));
    if (cerDataItem.isSelfSigned) return RET_OK;

    DO(process_crl(crl_store, cerDataItem.pcsiIssuer, cerDataItem.pcsiSubject, &ba_crlnumber, validate_time, &crl_item));
    DEBUG_OUTCON(printf("validate_by_crl() ba_crlnumber: "); ba_print(stdout, ba_crlnumber));
    DO(crl_item->revokedCerts(cerDataItem.pcsiSubject, revoked_items));

    if (cfg_crldelta_enabled) {
        DO(process_crl(crl_store, cerDataItem.pcsiIssuer, cerDataItem.pcsiSubject, &ba_crlnumber, validate_time, &crl_item));
        DO(crl_item->revokedCerts(cerDataItem.pcsiSubject, revoked_items));
    }

    DEBUG_OUTCON(for (auto& it : revoked_items) {
        printf("[%lld] revocationDate: %lld  crlReason: %i  invalidityDate: %lld\n", it->index, it->revocationDate, it->crlReason, it->invalidityDate);
    });

    if (revoked_items.empty()) {
        cert_status = UapkiNS::CertStatus::GOOD;
    }
    else {
        const CrlStore::RevokedCertItem* revcert_before = CrlStore::foundNearBefore(revoked_items, validate_time);
        if (revcert_before) {
            DEBUG_OUTCON(printf("revcert_before: [%lld]  revocationDate: %lld  crlReason: %i  invalidityDate: %lld\n",
                revcert_before->index, revcert_before->revocationDate, revcert_before->crlReason, revcert_before->invalidityDate));
            switch (revcert_before->crlReason)
            {
            case UapkiNS::CrlReason::REMOVE_FROM_CRL:
                cert_status = UapkiNS::CertStatus::GOOD;
                break;
            case UapkiNS::CrlReason::UNDEFINED:
                cert_status = UapkiNS::CertStatus::UNDEFINED;
                break;
            case UapkiNS::CrlReason::UNSPECIFIED:
                cert_status = UapkiNS::CertStatus::UNKNOWN;
                break;
            default:
                cert_status = UapkiNS::CertStatus::REVOKED;
                break;
            }
        }
        else {
            cert_status = UapkiNS::CertStatus::GOOD;
        }
    }

    cerDataItem.pcsiSubject->certStatusByCrl.set(
        cert_status,
        crl_item->nextUpdate,
        crl_item->baCrlId
    );
    cerDataItem.pcsiCrl = crl_item;

cleanup:
    return ret;
}   //  get_cert_status_by_crl

static int get_cert_status_by_ocsp (
        UapkiNS::Doc::Sign::SigningDoc::SignParams& signParams,
        UapkiNS::Doc::Sign::SigningDoc::CerDataItem& cerDataItem
)
{
    int ret = RET_OK;
    CerStore& cer_store = *get_cerstore();
    const LibraryConfig::OcspParams& ocsp_params = signParams.ocsp;
    UapkiNS::Ocsp::OcspHelper ocsp_helper;
    UapkiNS::SmartBA sba_resp;
    vector<string> shuffled_uris, uris;
    bool need_update;

    DO(cerDataItem.pcsiSubject->checkValidity(TimeUtils::nowMsTime()));

    DO(cer_store.getIssuerCert(cerDataItem.pcsiSubject, &cerDataItem.pcsiIssuer, cerDataItem.isSelfSigned));
    if (cerDataItem.isSelfSigned) return RET_OK;

    ret = cerDataItem.pcsiSubject->getOcspUris(uris);
    if (ret == RET_OK) {
        if (uris.empty()) {
            SET_ERROR(RET_UAPKI_OCSP_URL_NOT_PRESENT);
        }
    }
    else {
        ret = (ret == RET_UAPKI_EXTENSION_NOT_PRESENT) ? RET_UAPKI_OCSP_URL_NOT_PRESENT : ret;
        SET_ERROR(ret);
    }

    need_update = cerDataItem.pcsiSubject->certStatusByOcsp.isExpired(TimeUtils::nowMsTime());
    if (need_update) {
        DO(ocsp_helper.init());
        DO(ocsp_helper.addCert(cerDataItem.pcsiIssuer, cerDataItem.pcsiSubject));
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
                DEBUG_OUTCON(printf("get_cert_status_by_ocsp(), url: '%s', size: %zu\n", it.c_str(), sba_resp.size()));
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

    DO(ocsp_helper.parseResponse(need_update ? sba_resp.get() : cerDataItem.pcsiSubject->certStatusByOcsp.baResult));

    if (ocsp_helper.getResponseStatus() == UapkiNS::Ocsp::ResponseStatus::SUCCESSFUL) {
        DO(verify_ocsp_responsedata(cer_store, ocsp_helper, &cerDataItem.pcsiResponder));
        DO(ocsp_helper.checkNonce());
        DO(ocsp_helper.scanSingleResponses());

        const UapkiNS::Ocsp::OcspHelper::OcspRecord& ocsp_record = ocsp_helper.getOcspRecord(0); //  Work with one OCSP request that has one certificate
        if (need_update) {
            DO(cerDataItem.pcsiSubject->certStatusByOcsp.set(
                ocsp_record.status,
                ocsp_record.msThisUpdate + UapkiNS::Ocsp::OFFSET_EXPIRE_DEFAULT,
                sba_resp.get()
            ));
        }

        switch (ocsp_record.status) {
        case UapkiNS::CertStatus::GOOD:
            (void)cerDataItem.basicOcspResponse.set(ocsp_helper.getBasicOcspResponseEncoded(true));
            DO(ocsp_helper.getOcspIdentifier(&cerDataItem.ocspIdentifier));
            DO(UapkiNS::Ocsp::generateOtherHash(
                need_update ? sba_resp.get() : cerDataItem.pcsiSubject->certStatusByOcsp.baResult,
                signParams.aidDigest,
                &cerDataItem.ocspRespHash
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
    else {
        SET_ERROR(RET_UAPKI_OCSP_RESPONSE_NOT_SUCCESSFUL);
    }

cleanup:
    return ret;
}   //  get_cert_status_by_ocsp

int uapki_sign (
        JSON_Object* joParams,
        JSON_Object* joResult
)
{
    LibraryConfig* config = get_config();
    if (!config->isInitialized()) return RET_UAPKI_NOT_INITIALIZED;

    CerStore* cer_store = get_cerstore();
    CrlStore* crl_store = get_crlstore();
    if (!cer_store || !crl_store) return RET_UAPKI_GENERAL_ERROR;

    CmStorageProxy* storage = CmProviders::openedStorage();
    if (!storage) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!storage->keyIsSelected()) return RET_UAPKI_KEY_NOT_SELECTED;

    int ret = RET_OK;
    SignOptions sign_options;
    UapkiNS::Doc::Sign::SigningDoc::SignParams sign_params;
    size_t cnt_docs = 0;
    JSON_Array* ja_results = nullptr;
    JSON_Array* ja_sources = nullptr;
    vector<UapkiNS::Doc::Sign::SigningDoc> signing_docs;
    vector<ByteArray*> refba_hashes;
    UapkiNS::VectorBA vba_signatures;

    DO(parse_sign_params(json_object_get_object(joParams, "signParams"), sign_params));
    parse_sign_options(json_object_get_object(joParams, "options"), sign_params, sign_options);

    sign_params.ocsp = config->getOcsp();
    if (sign_params.includeContentTS || sign_params.includeSignatureTS) {
        if (config->getOffline()) {
            SET_ERROR(RET_UAPKI_OFFLINE_MODE);
        }
    }

    ja_sources = json_object_get_array(joParams, "dataTbs");
    cnt_docs = json_array_get_count(ja_sources);
    if ((cnt_docs == 0) || (cnt_docs > UapkiNS::Doc::Sign::SigningDoc::MAX_COUNT_DOCS)) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    DO(get_info_signalgo_and_keyid(*storage, sign_params.aidSignature.algorithm, &sign_params.keyId));
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
        DO(cer_store->getCertByKeyId(sign_params.keyId.get(), &sign_params.signer.pcsiSubject));
        if (sign_params.isCadesFormat) {
            if (!sign_options.ignoreCertStatus) {
                if (sign_params.signatureFormat != UapkiNS::SignatureFormat::CADES_C) {
                    DO(get_cert_status_by_ocsp(sign_params, sign_params.signer));
                }
                else {
                    DO(get_cert_status_by_crl(sign_params.signer));
                }
            }

            UapkiNS::EssCertId ess_certid;
            DO(sign_params.signer.pcsiSubject->generateEssCertId(sign_params.aidDigest, ess_certid));
            DO(UapkiNS::Doc::Sign::SigningDoc::encodeSigningCertificate(ess_certid, sign_params.attrSigningCert));
            if (sign_params.isCadesCXA) {
                vector<CerStore::Item*> service_certs;
                DO(cer_store->getChainCerts(sign_params.signer.pcsiSubject, service_certs));
                for (auto& it : service_certs) {
                    DO(sign_params.addCert(it));
                }
                for (auto& it : sign_params.chainCerts) {
                    if (sign_params.signatureFormat != UapkiNS::SignatureFormat::CADES_C) {
                        DO(get_cert_status_by_ocsp(sign_params, *it));
                    }
                    else {
                        DO(get_cert_status_by_crl(*it));
                    }
                }

                if (sign_params.signer.pcsiResponder) {
                    sign_params.addCert(sign_params.signer.pcsiResponder);
                }
            }
        }
    }

    if (sign_params.includeContentTS || sign_params.includeSignatureTS) {
        const LibraryConfig::TspParams& tsp_config = config->getTsp();
        LibraryConfig::TspParams& tsp_params = sign_params.tsp;
        tsp_params.certReq = tsp_config.certReq;
        tsp_params.nonceLen = tsp_config.nonceLen;
        tsp_params.policyId = tsp_config.policyId;
        if (sign_params.signer.pcsiSubject) {
            if (tsp_config.forced && !tsp_config.uris.empty()) {
                tsp_params.uris = tsp_config.uris;
            }
            else {
                ret = sign_params.signer.pcsiSubject->getTspUris(tsp_params.uris);
                if (ret != RET_OK) {
                    tsp_params.uris = tsp_config.uris;
                    ret = RET_OK;
                }
            }
        }
        else {
            tsp_params.uris = tsp_config.uris;
        }

        if (tsp_params.uris.empty()) {
            SET_ERROR(RET_UAPKI_TSP_URL_NOT_PRESENT);
        }
    }

    signing_docs.resize(cnt_docs);
    //  Parse and load all TBS-data
    for (size_t i = 0; i < signing_docs.size(); i++) {
        UapkiNS::Doc::Sign::SigningDoc& sdoc = signing_docs[i];
        DO(sdoc.init(&sign_params));
        DO(parse_doc_from_json(sdoc, json_array_get_object(ja_sources, i)));
    }

    if (sign_params.signatureFormat != UapkiNS::SignatureFormat::RAW) {
        for (size_t i = 0; i < signing_docs.size(); i++) {
            UapkiNS::Doc::Sign::SigningDoc& sdoc = signing_docs[i];

            DO(sdoc.setupSignerIdentifier());

            DO(sdoc.digestMessage());
            if (sign_params.includeContentTS) {
                //  After digestMessage and before buildSignedAttributes
                DO(add_timestamp_to_attrs(TsAttrType::CONTENT_TIMESTAMP, *cer_store, sdoc));
            }

            DO(sdoc.buildSignedAttributes());
            DO(sdoc.digestSignedAttributes());
            refba_hashes.push_back(sdoc.hashSignedAttrs.get());
        }

        DO(storage->keySign(
            sign_params.aidSignature.algorithm,
            nullptr,
            refba_hashes,
            vba_signatures
        ));

        for (size_t i = 0; i < signing_docs.size(); i++) {
            UapkiNS::Doc::Sign::SigningDoc& sdoc = signing_docs[i];
            DO(sdoc.setSignature(vba_signatures[i]));
            vba_signatures[i] = nullptr;
            //  Add unsigned attrs before call buildSignedData
            if (sign_params.includeSignatureTS) {
                DO(add_timestamp_to_attrs(TsAttrType::TIMESTAMP_TOKEN, *cer_store, sdoc));
            }

            if (sign_params.isCadesCXA) {
                vector<CerStore::Item*> chain_certs;
                for (auto& it : sdoc.getCerts()) {
                    DO(cer_store->getChainCerts(it->pcsiSubject, chain_certs));
                }
                for (auto& it : chain_certs) {
                    DO(sdoc.addCert(it));
                }

                const vector<UapkiNS::Doc::Sign::SigningDoc::CerDataItem*> certs = sdoc.getCerts();
                for (auto& it : certs) {
                    if (sign_params.signatureFormat != UapkiNS::SignatureFormat::CADES_C) {
                        ret = get_cert_status_by_ocsp(sign_params, *it);
                        if (ret == RET_OK) {
                            DO(sdoc.addCert(it->pcsiResponder));
                        }
                        else if (ret == RET_UAPKI_OCSP_URL_NOT_PRESENT) {
                            //  It's a nornal case - nothing
                        }
                        else {
                            SET_ERROR(ret);
                        }
                    }
                    else {
                        DO(get_cert_status_by_crl(*it));
                    }
                }
            }

            DO(sdoc.buildUnsignedAttributes());
            if (sign_params.signatureFormat == UapkiNS::SignatureFormat::CADES_A) {
                DO(add_timestamp_to_attrs(TsAttrType::ARCHIVE_TIMESTAMP, *cer_store, sdoc));
            }
            DO(sdoc.buildSignedData());
        }
    }
    else {
        for (size_t i = 0; i < signing_docs.size(); i++) {
            UapkiNS::Doc::Sign::SigningDoc& sdoc = signing_docs[i];
            DO(sdoc.digestMessage());
            refba_hashes.push_back(sdoc.messageDigest.get());
        }

        DO(storage->keySign(
            sign_params.aidSignature.algorithm,
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
        JSON_Object* jo_doc = nullptr;
        UapkiNS::Doc::Sign::SigningDoc& sdoc = signing_docs[i];
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
