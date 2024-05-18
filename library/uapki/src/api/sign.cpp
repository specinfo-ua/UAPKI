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
#include "attribute-helper.h"
#include "cert-validator.h"
#include "cm-providers.h"
#include "doc-sign.h"
#include "global-objects.h"
#include "http-helper.h"
#include "ocsp-helper.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include "signeddata-helper.h"
#include "store-json.h"
#include "time-util.h"
#include "tsp-helper.h"
#include "uapki-ns.h"
#include "uapki-debug.h"
#include "uapki-ns-verify.h"


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
using namespace UapkiNS;


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
    SmartBA sba_keyid;

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
        Doc::Sign::SigningDoc::SignParams& signParams,
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
        Doc::Sign::SigningDoc::SignParams& signParams
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
        DO(Doc::Sign::SigningDoc::encodeSignaturePolicy(
            ParsonHelper::jsonObjectGetString(jo_sigpolicy, "sigPolicyId"),
            signParams.attrSignPolicy
        ));
    }

cleanup:
    return ret;
}   //  parse_sign_params

static int verify_signeddata (
        CertValidator::CertValidator& certValidator,
        const ByteArray* baEncoded,
        Cert::CerItem** cerSigner
)
{
    int ret = RET_OK;
    Cert::CerStore& cer_store = *certValidator.getCerStore();
    Pkcs7::SignedDataParser sdata_parser;
    Pkcs7::SignedDataParser::SignerInfo signer_info;
    vector<Cert::CerStore::AddedCerItem> added_ceritems;
    SmartBA sba_hashtstinfo;
    HashAlg hash_alg = HASH_ALG_UNDEFINED;

    DO(sdata_parser.parse(baEncoded));
    if (
        (!sdata_parser.getEncapContentInfo().baEncapContent) ||
        (sdata_parser.getCountSignerInfos() == 0)
    ) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

    DO(cer_store.addCerts(
        Cert::NOT_TRUSTED,
        Cert::NOT_PERMANENT,
        sdata_parser.getCerts(),
        added_ceritems
    ));

    DO(sdata_parser.parseSignerInfo(0, signer_info));
    if (!sdata_parser.isContainDigestAlgorithm(signer_info.getDigestAlgorithm())) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }
    hash_alg = hash_from_oid(signer_info.getDigestAlgorithm().algorithm.c_str());
    if (hash_alg == HASH_ALG_UNDEFINED) {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }
    DO(::hash(hash_alg, sdata_parser.getEncapContentInfo().baEncapContent, &sba_hashtstinfo));
    if (ba_cmp(signer_info.getMessageDigest(), sba_hashtstinfo.get()) != 0) {
        SET_ERROR(RET_UAPKI_TSP_RESPONSE_INVALID);
    }

    ret = certValidator.verifySignatureSignerInfo(CertValidator::CertEntity::TSP, signer_info, cerSigner);

cleanup:
    return ret;
}   //  verify_signeddata

static int tsp_process (
        CertValidator::CertValidator& certValidator,
        Tsp::TspHelper& tspHelper,
        Doc::Sign::SigningDoc& sdoc
)
{
    int ret = RET_OK;
    const LibraryConfig::TspParams& tsp_params = sdoc.signParams->tsp;
    SmartBA sba_resp, sba_tstinfo, sba_tstoken;
    Cert::CerItem* cer_signer = nullptr;

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
                it,
                HttpHelper::CONTENT_TYPE_TSP_REQUEST,
                tspHelper.getRequestEncoded(),
                &sba_resp
            );
            DEBUG_OUTPUT_OUTSTREAM(string("TSP-response, url=") + it, sba_resp.get());
            if (ret == RET_OK) {
                sdoc.tspUri = it;
                break;
            }
        }
    }
    else {
        DEBUG_OUTPUT_OUTSTREAM(string("TSP-request, url=") + sdoc.tspUri, tspHelper.getRequestEncoded());
        ret = HttpHelper::post(
            sdoc.tspUri,
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
        (tspHelper.getStatus() != Tsp::PkiStatus::GRANTED) &&
        (tspHelper.getStatus() != Tsp::PkiStatus::GRANTED_WITHMODS)
    ) {
        SET_ERROR(RET_UAPKI_TSP_RESPONSE_NOT_GRANTED);
    }

    DO(verify_signeddata(
        certValidator,
        tspHelper.getTsToken(),
        &cer_signer
    ));
    sdoc.addCert(cer_signer);

    DO(tspHelper.tstInfoIsEqualRequest());

cleanup:
    return ret;
}   //  tsp_process

static int add_timestamp_to_attrs (
        CertValidator::CertValidator& certValidator,
        const TsAttrType tsAttrType,
        Doc::Sign::SigningDoc& sdoc
)
{
    int ret = RET_OK;
    Tsp::TspHelper tsp_helper;
    SmartBA sba_hash;

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

    DO(tsp_process(certValidator, tsp_helper, sdoc));

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
        Doc::Sign::SigningDoc& sdoc,
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

    if (sdoc.signParams->signatureFormat != UapkiNS::SignatureFormat::RAW) {
        sdoc.contentType = ParsonHelper::jsonObjectGetString(joDoc, "type", string(OID_PKCS7_DATA));
        if (!oid_is_valid(sdoc.contentType.c_str())) return RET_UAPKI_INVALID_PARAMETER;
        DO(parse_docattrs_from_json(sdoc, joDoc, string("signedAttributes")));
        DO(parse_docattrs_from_json(sdoc, joDoc, string("unsignedAttributes")));
    }

cleanup:
    return ret;
}   //  parse_doc_from_json

static int get_cert_status_by_crl (
        CertValidator::CertValidator& certValidator,
        Doc::Sign::SigningDoc::CerDataItem& cerDataItem
)
{
    int ret = RET_OK;
    const uint64_t validate_time = TimeUtil::mtimeNow();
    CertValidator::ResultValidationByCrl result_valbycrl;

    DO(cerDataItem.pCerSubject->checkValidity(TimeUtil::mtimeNow()));

    DO(certValidator.getIssuerCert(cerDataItem.pCerSubject, &cerDataItem.pCerIssuer, cerDataItem.isSelfSigned));
    if (cerDataItem.isSelfSigned) return RET_OK;

    DO(certValidator.validateByCrl(
        cerDataItem.pCerSubject,
        cerDataItem.pCerIssuer,
        validate_time,
        true,
        result_valbycrl
    ));
    cerDataItem.pCrl = result_valbycrl.crlItem;

cleanup:
    return ret;
}   //  get_cert_status_by_crl

static int get_cert_status_by_ocsp (
        CertValidator::CertValidator& certValidator,
        Doc::Sign::SigningDoc::SignParams& signParams,
        Doc::Sign::SigningDoc::CerDataItem& cerDataItem
)
{
    int ret = RET_OK;
    const bool need_ocspresp = (signParams.signatureFormat > SignatureFormat::CADES_T);
    CertValidator::ResultValidationByOcsp result_valbyocsp(need_ocspresp);

    DO(cerDataItem.pCerSubject->checkValidity(TimeUtil::mtimeNow()));

    DO(certValidator.getIssuerCert(cerDataItem.pCerSubject, &cerDataItem.pCerIssuer, cerDataItem.isSelfSigned));
    if (cerDataItem.isSelfSigned) return RET_OK;

    DO(certValidator.validateByOcsp(
        cerDataItem.pCerSubject,
        cerDataItem.pCerIssuer,
        result_valbyocsp
    ));

    switch (result_valbyocsp.singleResponseInfo.certStatus) {
    case UapkiNS::CertStatus::GOOD:
        if (need_ocspresp) {
            (void)cerDataItem.basicOcspResponse.set(result_valbyocsp.basicOcspResponse.pop());
            (void)cerDataItem.ocspIdentifier.set(result_valbyocsp.ocspIdentifier.pop());
            DO(Ocsp::generateOtherHash(
                result_valbyocsp.ocspResponse.get(),
                signParams.aidDigest,
                &cerDataItem.ocspRespHash
            ));
        }
        break;
    case UapkiNS::CertStatus::REVOKED:
        SET_ERROR(RET_UAPKI_CERT_STATUS_REVOKED);
        break;
    default:
        SET_ERROR(RET_UAPKI_CERT_STATUS_UNKNOWN);
        break;
    }

cleanup:
    return ret;
}   //  get_cert_status_by_ocsp

int uapki_sign (
        JSON_Object* joParams,
        JSON_Object* joResult
)
{
    CertValidator::CertValidator cert_validator;
    if (!cert_validator.init(get_config(), get_cerstore(), get_crlstore())) return RET_UAPKI_GENERAL_ERROR;
    if (!cert_validator.getLibConfig()->isInitialized()) return RET_UAPKI_NOT_INITIALIZED;

    CmStorageProxy* storage = CmProviders::openedStorage();
    if (!storage) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!storage->keyIsSelected()) return RET_UAPKI_KEY_NOT_SELECTED;

    int ret = RET_OK;
    Cert::CerStore& cer_store = *cert_validator.getCerStore();
    LibraryConfig& config = *cert_validator.getLibConfig();
    SignOptions sign_options;
    Doc::Sign::SigningDoc::SignParams sign_params;
    size_t cnt_docs = 0;
    JSON_Array* ja_results = nullptr;
    JSON_Array* ja_sources = nullptr;
    vector<Doc::Sign::SigningDoc> signing_docs;
    vector<ByteArray*> refba_hashes;
    UapkiNS::VectorBA vba_signatures;

    DO(parse_sign_params(json_object_get_object(joParams, "signParams"), sign_params));
    parse_sign_options(json_object_get_object(joParams, "options"), sign_params, sign_options);

    sign_params.ocsp = config.getOcsp();
    if (sign_params.includeContentTS || sign_params.includeSignatureTS) {
        if (config.getOffline()) {
            SET_ERROR(RET_UAPKI_OFFLINE_MODE);
        }
    }

    ja_sources = json_object_get_array(joParams, "dataTbs");
    cnt_docs = json_array_get_count(ja_sources);
    if ((cnt_docs == 0) || (cnt_docs > Doc::Sign::SigningDoc::MAX_COUNT_DOCS)) {
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
        DO(cer_store.getCertByKeyId(sign_params.keyId.get(), &sign_params.signer.pCerSubject));
        if (sign_params.isCadesFormat) {
            if (!sign_options.ignoreCertStatus) {
                if (
                    (sign_params.signatureFormat == UapkiNS::SignatureFormat::CADES_C) ||
                    ((sign_params.signatureFormat == UapkiNS::SignatureFormat::CADES_BES) && config.getOffline())
                ) {
                    DO(get_cert_status_by_crl(cert_validator, sign_params.signer));
                }
                else {
                    DO(get_cert_status_by_ocsp(cert_validator, sign_params, sign_params.signer));
                }
            }

            const UapkiNS::EssCertId* ess_certid;
            DO(sign_params.signer.pCerSubject->generateEssCertId(sign_params.aidDigest, &ess_certid));
            DO(Doc::Sign::SigningDoc::encodeSigningCertificate(*ess_certid, sign_params.attrSigningCert));
            if (sign_params.isCadesCXA) {
                vector<Cert::CerItem*> service_certs;
                DO(cer_store.getChainCerts(sign_params.signer.pCerSubject, service_certs));
                for (auto& it : service_certs) {
                    DO(sign_params.addCert(it));
                }
                for (auto& it : sign_params.chainCerts) {
                    if (sign_params.signatureFormat != UapkiNS::SignatureFormat::CADES_C) {
                        DO(get_cert_status_by_ocsp(cert_validator, sign_params, *it));
                    }
                    else {
                        DO(get_cert_status_by_crl(cert_validator, *it));
                    }
                }

                if (sign_params.signer.pCerResponder) {
                    sign_params.addCert(sign_params.signer.pCerResponder);
                }
            }
        }
    }

    if (sign_params.includeContentTS || sign_params.includeSignatureTS) {
        const LibraryConfig::TspParams& tsp_config = config.getTsp();
        LibraryConfig::TspParams& tsp_params = sign_params.tsp;
        tsp_params.certReq = tsp_config.certReq;
        tsp_params.nonceLen = tsp_config.nonceLen;
        tsp_params.policyId = tsp_config.policyId;
        if (sign_params.signer.pCerSubject) {
            if (tsp_config.forced && !tsp_config.uris.empty()) {
                tsp_params.uris = tsp_config.uris;
            }
            else {
                tsp_params.uris = sign_params.signer.pCerSubject->getUris().tsp;
                if (tsp_params.uris.empty()) {
                    tsp_params.uris = tsp_config.uris;
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
        Doc::Sign::SigningDoc& sdoc = signing_docs[i];
        DO(sdoc.init(&sign_params));
        DO(parse_doc_from_json(sdoc, json_array_get_object(ja_sources, i)));
        if (
            (sdoc.contentHasher.getSourceType() != ContentHasher::SourceType::BYTEARRAY) &&
            (sign_params.detachedData == false)
        ) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
    }

    if (sign_params.signatureFormat != UapkiNS::SignatureFormat::RAW) {
        for (size_t i = 0; i < signing_docs.size(); i++) {
            Doc::Sign::SigningDoc& sdoc = signing_docs[i];

            DO(sdoc.setupSignerIdentifier());

            DO(sdoc.digestMessage());
            if (sign_params.includeContentTS) {
                //  After digestMessage and before buildSignedAttributes
                DO(add_timestamp_to_attrs(cert_validator, TsAttrType::CONTENT_TIMESTAMP, sdoc));
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
            Doc::Sign::SigningDoc& sdoc = signing_docs[i];
            DO(sdoc.setSignature(vba_signatures[i]));
            vba_signatures[i] = nullptr;
            //  Add unsigned attrs before call buildSignedData
            if (sign_params.includeSignatureTS) {
                DO(add_timestamp_to_attrs(cert_validator, TsAttrType::TIMESTAMP_TOKEN, sdoc));
            }

            if (sign_params.isCadesCXA) {
                vector<Cert::CerItem*> chain_certs;
                for (auto& it : sdoc.getCerts()) {
                    DO(cer_store.getChainCerts(it->pCerSubject, chain_certs));
                }
                for (auto& it : chain_certs) {
                    DO(sdoc.addCert(it));
                }

                const vector<Doc::Sign::SigningDoc::CerDataItem*> certs = sdoc.getCerts();
                for (auto& it : certs) {
                    if (sign_params.signatureFormat != UapkiNS::SignatureFormat::CADES_C) {
                        ret = get_cert_status_by_ocsp(cert_validator, sign_params, *it);
                        if (ret == RET_OK) {
                            DO(sdoc.addCert(it->pCerResponder));
                        }
                        else if (ret == RET_UAPKI_OCSP_URL_NOT_PRESENT) {
                            //  It's a nornal case - nothing
                        }
                        else {
                            SET_ERROR(ret);
                        }
                    }
                    else {
                        DO(get_cert_status_by_crl(cert_validator, *it));
                    }
                }
            }

            DO(sdoc.buildUnsignedAttributes());
            if (sign_params.signatureFormat == UapkiNS::SignatureFormat::CADES_A) {
                DO(add_timestamp_to_attrs(cert_validator, TsAttrType::ARCHIVE_TIMESTAMP, sdoc));
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
        Doc::Sign::SigningDoc& sdoc = signing_docs[i];
        DO_JSON(json_array_append_value(ja_results, json_value_init_object()));
        if ((jo_doc = json_array_get_object(ja_results, i)) == nullptr) {
            SET_ERROR(RET_UAPKI_GENERAL_ERROR);
        }
        DO_JSON(json_object_set_string(jo_doc, "id", sdoc.id.c_str()));
        DO_JSON(json_object_set_base64(jo_doc, "bytes", sdoc.getEncoded()));
    }

cleanup:
    if (ret != RET_OK) {
        (void)cert_validator.expectedCertItemsToJson(joResult, "expectedCerts");
        (void)cert_validator.expectedCrlItemsToJson(joResult, "expectedCrls");
    }
    return ret;
}
