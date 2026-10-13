/*
 * Copyright (c) 2026, The UAPKI Project Authors.
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

#define FILE_MARKER "uapki/doc-sign.cpp"

#include "doc-sign.h"
#include "der-helper.h"
#include "api-json-internal.h"
#include "attribute-helper.h"
#include "oid-utils.h"
#include "time-util.h"
#include "uapki-ns-util.h"
#include <algorithm>


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif

#define DEBUG_OUTPUT_OUTSTREAM(msg,baData)
#ifndef DEBUG_OUTPUT_OUTSTREAM
DEBUG_OUTPUT_OUTSTREAM_FUNC
#define DEBUG_OUTPUT_OUTSTREAM(msg,baData) debug_output_stream(DEBUG_OUTSTREAM_FOPEN,"DOC-SIGN",msg,baData)
#endif

#if __cplusplus >= 201703L
    #define UAPKI_FALLTHROUGH [[fallthrough]]
#elif defined(__clang__)
    #define UAPKI_FALLTHROUGH [[clang::fallthrough]]
#elif defined(__GNUC__) && (__GNUC__ >= 7)
    #define UAPKI_FALLTHROUGH [[gnu::fallthrough]]
#elif defined(_MSC_VER)
    #define UAPKI_FALLTHROUGH __fallthrough
#else
    #define UAPKI_FALLTHROUGH ((void)0)
#endif

using namespace std;


namespace UapkiNS {

namespace Doc {

namespace Sign {


static void add_unique_cert (
        vector<CertValidator::CertChainItem*>& certs,
        CertValidator::CertChainItem* item
)
{
    if (!item) return;

    for (const auto& it : certs) {
        if (item->getSubject()->equalCertId(it->getSubjectCertId())) {
            return;
        }
    }

    certs.push_back(item);
}   //  add_unique_cert


SharedData::SharedData (void)
    : cerSigner(nullptr)
{
}

int SharedData::encodeSignaturePolicy (
        const string& sigPolicyiId
)
{
    return AttributeHelper::encodeSignaturePolicy(sigPolicyiId, &encodedSignPolicy);
}

int SharedData::encodeSigningCertificate (void)
{
    int ret = RET_OK;
    const UapkiNS::EssCertId* ess_certid = nullptr;

    CHECK_PARAM(cerSigner != nullptr);

    DO(cerSigner->generateEssCertId(aidDigest, &ess_certid));
    DO(AttributeHelper::encodeSigningCertificate(*ess_certid, &encodedSigningCert));

cleanup:
    return ret;
}

int SharedData::paramsBySignatureFormat (void)
{
    switch (signatureFormat) {
    case SignatureFormat::CADES_B_LTA:
    case SignatureFormat::CADES_B_LT:
        //  B-T with signing-time and the signing certificate (EN 319 122-1, table 1), then its validation data
        //  (and archive-time-stamp-v3) by Augment::augmentCms
        //  The content time-stamp is optional in every format (EN 319 122-1, table 1): includeContentTS
        includeCert = true;
        includeTime = true;
        includeSignatureTS = true;
        isCadesFormat = true;
        sidUseKeyId = false;
        break;
    case SignatureFormat::CADES_A:      //  CADES_A  >  CADES_XL
        UAPKI_FALLTHROUGH;
    case SignatureFormat::CADES_XL:     //  CADES_XL >  CADES_C
        UAPKI_FALLTHROUGH;
    case SignatureFormat::CADES_C:      //  CADES_C  >  CADES_T
        includeCert = true;
        isCadesCXA = true;
        UAPKI_FALLTHROUGH;
    case SignatureFormat::CADES_T:      //  CADES_T  >  CADES_BES
        includeSignatureTS = true;
        UAPKI_FALLTHROUGH;
    case SignatureFormat::CADES_BES:
        isCadesFormat = true;
        sidUseKeyId = false;
        break;
    case SignatureFormat::CMS_SID_KEYID:
        sidUseKeyId = true;
        break;
    case SignatureFormat::RAW:
        break;
    default:
        return RET_UAPKI_INVALID_PARAMETER;
    }

    return RET_OK;
}

int SharedData::setupTsp (
        const LibraryConfig::TspParams& tspParams
)
{
    tsp.certReq = tspParams.certReq;
    tsp.nonceLen = tspParams.nonceLen;
    tsp.policyId = tspParams.policyId;
    tspUris(tspParams, cerSigner, tsp.uris, tspFallbackUris);

    if (tsp.uris.empty() && tspFallbackUris.empty()) return RET_UAPKI_TSP_URL_NOT_PRESENT;

    return RET_OK;
}


SigningDoc::SigningDoc (void)
    : sharedData(nullptr)
    , signerInfo(nullptr)
    , isDigest(false)
    , signingTime(0)
    , contentTimeStamp(0)
    , signatureTimeStamp(0)
    , archiveTimeStamp(0)
{
    DEBUG_OUTCON(puts("SigningDoc::SigningDoc()"));
}

SigningDoc::~SigningDoc (void)
{
    DEBUG_OUTCON(puts("SigningDoc::~SigningDoc()"));
    for (auto& it : m_SignedAttrs) {
        delete it;
    }
    for (auto& it : m_UnsignedAttrs) {
        delete it;
    }
}

int SigningDoc::init (
        SharedData* iSharedData
)
{
    sharedData = iSharedData;
    if (!sharedData) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    if (sharedData->signatureFormat != SignatureFormat::RAW) {
        ret = builder.init();
        if (ret != RET_OK) return ret;

        for (size_t i = 0; i < MAX_TIMESTAMPS; i++) {
            (void)certValidatorTs[i].init(sharedData->certValidator);
        }

        ret = builder.addSignerInfo();
        if (ret != RET_OK) return ret;

        signerInfo = builder.getSignerInfo(0);
        signerInfo->setDigestAlgorithm(sharedData->aidDigest);

        //  CAdES-A: the archive time-stamp is added to the encoded signature by Augment::addArchiveTimeStamp
        DO(m_ArchiveTsHelper.init(nullptr));

        if (sharedData->includeCert) {
            const ByteArray* ba_certencoded = sharedData->cerSigner->getEncoded();
            DO(builder.addCertificate(ba_certencoded));
            if (m_ArchiveTsHelper.isEnabled()) {
                DO(m_ArchiveTsHelper.addCertificate(ba_certencoded));
            }
        }
    }

cleanup:
    return ret;
}

int SigningDoc::addArchiveAttribute (
        const string& type,
        const ByteArray* baValues
)
{
    const Attribute attr_atsv3(type, baValues);
    return signerInfo->addUnsignedAttr(attr_atsv3);
}

int SigningDoc::addSignedAttribute (
        const string& type,
        const ByteArray* baValues
)
{
    Attribute* attr = new Attribute(type, baValues);
    if (!attr) return RET_UAPKI_GENERAL_ERROR;

    m_SignedAttrs.push_back(attr);
    return RET_OK;
}

int SigningDoc::addTimestamp (
        const TsAttr tsAttr
)
{
    int ret = RET_OK;
    Tsp::TspHelper tsp_helper;
    SmartBA sba_hashvalue;

    DO(tsp_helper.init());

    switch (tsAttr) {
    case TsAttr::CONTENT_TIMESTAMP:
        DO(tsp_helper.setMessageImprint(sharedData->aidDigest, messageDigest.get()));
        break;
    case TsAttr::TIMESTAMP_TOKEN:
        DO(digestSignature(&sba_hashvalue));
        DO(tsp_helper.setMessageImprint(sharedData->aidDigest, sba_hashvalue.get()));
        break;
    case TsAttr::ARCHIVE_TIMESTAMP:
        DO(tsp_helper.setMessageImprint(sharedData->aidDigest, getAtsHash()));
        break;
    default:
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        break;
    }

    DO(getTimestamp(certValidatorTs[(uint32_t)tsAttr], tsp_helper));

    switch (tsAttr) {
    case TsAttr::CONTENT_TIMESTAMP:
        DO(addSignedAttribute(string(OID_PKCS9_CONTENT_TIMESTAMP), tsp_helper.getTsToken(true)));
        contentTimeStamp = tsp_helper.getGenTime();
        break;
    case TsAttr::TIMESTAMP_TOKEN:
        DO(addUnsignedAttribute(OID_PKCS9_TIMESTAMP_TOKEN, tsp_helper.getTsToken(true)));
        signatureTimeStamp = tsp_helper.getGenTime();
        break;
    case TsAttr::ARCHIVE_TIMESTAMP:
        DO(addArchiveAttribute(OID_ETSI_ARCHIVE_TIMESTAMP_V3, tsp_helper.getTsToken(true)));
        archiveTimeStamp = tsp_helper.getGenTime();
        break;
    default:
        break;
    }

cleanup:
    return ret;
}

int SigningDoc::addUnsignedAttribute (
        const string& type,
        const ByteArray* baValues
)
{
    Attribute* attr = new Attribute(type, baValues);
    if (!attr) return RET_UAPKI_GENERAL_ERROR;

    m_UnsignedAttrs.push_back(attr);
    return RET_OK;
}

int SigningDoc::buildSignedAttributes (void)
{
    int ret = RET_OK;

    //  Add mandatory attrs (CMS/CAdES)
    DO(signerInfo->addSignedAttrContentType(contentType));
    DO(signerInfo->addSignedAttrMessageDigest(messageDigest.get()));
    if (sharedData->includeTime) {
        if (signingTime == 0) {
            signingTime = TimeUtil::mtimeNow();
        }
        DO(signerInfo->addSignedAttrSigningTime(signingTime));
    }

    //  Add CAdES-signed attrs
    if (!sharedData->encodedSigningCert.empty()) {
        DO(signerInfo->addSignedAttr(OID_PKCS9_SIGNING_CERTIFICATE_V2, sharedData->encodedSigningCert.get()));
    }
    if (!sharedData->encodedSignPolicy.empty()) {
        DO(signerInfo->addSignedAttr(OID_PKCS9_SIG_POLICY_ID, sharedData->encodedSignPolicy.get()));
    }

    //  Add other signed attrs
    for (auto& it : m_SignedAttrs) {
        DO(signerInfo->addSignedAttr(*it));
    }

    DO(signerInfo->encodeSignedAttrs());

    if (m_ArchiveTsHelper.isEnabled()) {
        DO(m_ArchiveTsHelper.setHashContent(contentType, messageDigest.get()));
    }

cleanup:
    return ret;
}

int SigningDoc::buildSignedData (void)
{
    if (!signerInfo) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;

    DO(builder.setVersion(signerInfo->getSidType() == Pkcs7::SignerIdentifierType::ISSUER_AND_SN ? 1u : 3u));
    DO(builder.setEncapContentInfo(contentType, (sharedData->detachedData) ? nullptr : contentHasher.getContentBytes()));
    DO(signerInfo->encodeUnsignedAttrs());

    DO(builder.encode());

cleanup:
    return ret;
}

int SigningDoc::buildUnsignedAttributes (void)
{
    int ret = RET_OK;

    const vector<CertValidator::CertChainItem*> collected_certs = collectCerts();
    SmartBA sba_certificaterefs, sba_revocationrefs;
    SmartBA sba_certvalues, sba_revocationvalues;

    //  The references and values are of the signer path; the revocation ones: the signing certificate first
    CertValidator::CertChainItem* signer_item = nullptr;
    const vector<CertValidator::CertChainItem*> ca_certs = collectSignerCerts(&signer_item);
    vector<CertValidator::CertChainItem*> revoc_certs;
    if (signer_item) {
        revoc_certs.push_back(signer_item);
    }
    revoc_certs.insert(revoc_certs.end(), ca_certs.begin(), ca_certs.end());
    (void)collected_certs;

    switch (sharedData->signatureFormat) {
    case SignatureFormat::CADES_C:
        if (!ca_certs.empty()) {
            DO(encodeCertificateRefs(ca_certs, &sba_certificaterefs));
        }
        DO(encodeRevocationRefs(revoc_certs, &sba_revocationrefs));
        break;
    case SignatureFormat::CADES_XL:
    case SignatureFormat::CADES_A:
        if (!ca_certs.empty()) {
            DO(encodeCertificateRefs(ca_certs, &sba_certificaterefs));
            DO(encodeCertValues(ca_certs, &sba_certvalues));
        }
        DO(encodeRevocationRefs(revoc_certs, &sba_revocationrefs));
        DO(encodeRevocationValues(revoc_certs, &sba_revocationvalues));
        DO(addTspValidationData());
        break;
    default:
        break;
    }

    //  Add CAdES-unsigned attrs
    if (!sba_certificaterefs.empty()) {
        DO(signerInfo->addUnsignedAttr(OID_PKCS9_CERTIFICATE_REFS, sba_certificaterefs.get()));
    }
    if (!sba_revocationrefs.empty()) {
        DO(signerInfo->addUnsignedAttr(OID_PKCS9_REVOCATION_REFS, sba_revocationrefs.get()));
    }
    if (!sba_certvalues.empty()) {
        DO(signerInfo->addUnsignedAttr(OID_PKCS9_CERT_VALUES, sba_certvalues.get()));
    }
    if (!sba_revocationvalues.empty()) {
        DO(signerInfo->addUnsignedAttr(OID_PKCS9_REVOCATION_VALUES, sba_revocationvalues.get()));
    }

    //  Add other unsigned attrs
    for (const auto& it : m_UnsignedAttrs) {
        DO(signerInfo->addUnsignedAttr(*it));
    }

    if (m_ArchiveTsHelper.isEnabled()) {
        DO(m_ArchiveTsHelper.setSignerInfo(signerInfo->getAsn1Data()));
        DO(m_ArchiveTsHelper.setUnsignedAttrs(signerInfo->getUnsignedAttrs()));
        DO(m_ArchiveTsHelper.calcHash());
    }

cleanup:
    return ret;
}

int SigningDoc::digestMessage (void)
{
    int ret = RET_OK;

    if (!isDigest) {
        DO(contentHasher.digest(sharedData->hashDigest));
        if (!messageDigest.set(ba_copy_with_alloc(contentHasher.getHashValue(), 0, 0))) {
            ret = RET_UAPKI_GENERAL_ERROR;
        }
    }
    else {
        const size_t hashsize_expected = hash_get_size(sharedData->hashDigest);
        if (hashsize_expected == ba_get_len(contentHasher.getContentBytes())) {
            if (!messageDigest.set(ba_copy_with_alloc(contentHasher.getContentBytes(), 0, 0))) {
                ret = RET_UAPKI_GENERAL_ERROR;
            }
        }
        else {
            ret = RET_UAPKI_INVALID_PARAMETER;
        }
    }

cleanup:
    return ret;
}

int SigningDoc::digestSignature (
        ByteArray** baHash
)
{
    int ret = RET_OK;

    CHECK_PARAM(baHash != nullptr);

    DO(::hash(sharedData->hashDigest, signature.get(), baHash));

cleanup:
    return ret;
}

int SigningDoc::digestSignedAttributes (void)
{
    int ret = RET_OK;

    DO(::hash(sharedData->hashSignature, signerInfo->getSignedAttrsEncoded(), &hashSignedAttrs));

cleanup:
    return ret;
}

int SigningDoc::getTimestamp (
        CertValidator::CertValidator& certValidator,
        Tsp::TspHelper& tspHelper
)
{
    int ret = RET_OK;
    const LibraryConfig::TspParams& tsp_params = sharedData->tsp;
    SmartBA sba_resp, sba_tstinfo, sba_tstoken;
    Cert::CerItem* cer_signer = nullptr;

    if (tsp_params.nonceLen > 0) {
        DO(tspHelper.genNonce(tsp_params.nonceLen));
    }
    DO(tspHelper.setCertReq(tsp_params.certReq));
    DO(tspHelper.setReqPolicy(tsp_params.policyId));

    DO(tspHelper.encodeRequest());

    DO(requestTimestamp(
        certValidator.getLibConfig()->getHttp(),
        tsp_params.uris,
        sharedData->tspFallbackUris,
        tspHelper,
        tspUri
    ));

    DO(verifySignedData(
        certValidator,
        tspHelper.getTsToken(),
        &cer_signer
    ));

    DO(certValidator.getStatus(
        cer_signer,
        CertValidator::CertEntity::TSP,
        TimeUtil::mtimeNow()
    ));

    DO(tspHelper.tstInfoIsEqualRequest());

cleanup:
    return ret;
}

int SigningDoc::importSignedAttributes (
        const ByteArray* baEncoded
)
{
    int ret = RET_OK;
    vector<UapkiNS::Attribute> signed_attrs;
    Attributes_t* attrs = (Attributes_t*)asn_decode_ba_with_alloc(get_Attributes_desc(), baEncoded);
    bool present_signingcertv2 = false;

    if ((!attrs) || (attrs->list.count < 2)) {
        SET_ERROR(RET_UAPKI_INVALID_ATTRIBUTE);
    }

    signed_attrs.resize(attrs->list.count);
    for (int i = 0; i < attrs->list.count; i++) {
        DO(Util::attributeFromAsn1(*attrs->list.array[i], signed_attrs[i]));
    }

    for (const auto& it : signed_attrs) {
        if (it.type == string(OID_PKCS9_CONTENT_TYPE)) {
            DO(AttributeHelper::decodeContentType(it.baValues, contentType));
        }
        else if (it.type == string(OID_PKCS9_MESSAGE_DIGEST)) {
            messageDigest.clear();
            DO(AttributeHelper::decodeMessageDigest(it.baValues, &messageDigest));
        }
        else if (it.type == string(OID_PKCS9_SIGNING_TIME)) {
            DO(AttributeHelper::decodeSigningTime(it.baValues, signingTime));
        }
        else if (it.type == string(OID_PKCS9_SIGNING_CERTIFICATE_V2)) {
            present_signingcertv2 = true;
        }
    }

    if (contentType.empty() || messageDigest.empty()) {
        SET_ERROR(RET_UAPKI_ATTRIBUTE_NOT_PRESENT);
    }
    if (hash_get_size(sharedData->hashDigest) != messageDigest.size()) {
        SET_ERROR(RET_UAPKI_INVALID_HASH_SIZE);
    }
    if ((sharedData->signatureFormat >= SignatureFormat::CADES_BES) && !present_signingcertv2) {
        SET_ERROR(RET_UAPKI_ATTRIBUTE_NOT_PRESENT);
    }

    //  B-LT, B-LTA: signing-time is mandatory (EN 319 122-1, table 1)
    if (
        ((sharedData->signatureFormat == SignatureFormat::CADES_B_LT) || (sharedData->signatureFormat == SignatureFormat::CADES_B_LTA)) &&
        (signingTime == 0)
    ) {
        SET_ERROR(RET_UAPKI_ATTRIBUTE_NOT_PRESENT);
    }

    DO(signerInfo->setSignedAttrs(signed_attrs));
    DO(signerInfo->encodeSignedAttrs());
    if (m_ArchiveTsHelper.isEnabled()) {
        DO(m_ArchiveTsHelper.setHashContent(contentType, messageDigest.get()));
    }

cleanup:
    asn_free(get_Attributes_desc(), attrs);
    return ret;
}

int SigningDoc::setSignature (
        const ByteArray* baSignValue
)
{
    int ret = RET_OK;

    DO(signerInfo->setSignature(sharedData->aidSignature, baSignValue));
    (void)signature.set((ByteArray*)baSignValue);

cleanup:
    return ret;
}

int SigningDoc::setupSignerIdentifier (void)
{
    int ret = RET_OK;
    SmartBA sba_sid;
    uint32_t version = 0;

    if (!sharedData->sidUseKeyId) {
        DO(sharedData->cerSigner->getIssuerAndSN(&sba_sid));
        DO(signerInfo->setSid(Pkcs7::SignerIdentifierType::ISSUER_AND_SN, sba_sid.get()));
        version = 1;
    }
    else {
        //  subjectKeyIdentifier of the signing certificate (RFC 5652, 5.3): for DSTU 4145 it may be the hash
        //  DSTU 7564 of the key while the key id of the storage is the hash GOST 34.311; the key id without
        //  a certificate
        const ByteArray* ba_keyid = (sharedData->cerSigner) ? sharedData->cerSigner->getKeyId() : sharedData->keyId.get();
        DEBUG_OUTCON(printf("sid keyId, hex:"); ba_print(stdout, ba_keyid));
        DO(signerInfo->setSid(Pkcs7::SignerIdentifierType::SUBJECT_KEYID, ba_keyid));
        version = 3;
    }
    DEBUG_OUTCON(printf("SigningDoc::setupSignerIdentifier(), sba_sid, hex:"); ba_print(stdout, sba_sid.get()));
    DO(signerInfo->setVersion(version));

cleanup:
    return ret;
}

ByteArray* SigningDoc::getEncoded (void)
{
    if (!augmented.empty()) return augmented.get();
    return (sharedData->signatureFormat != SignatureFormat::RAW)
        ? builder.getEncoded() : signature.get();
}

int SigningDoc::collectExpectedItems (
        CertValidator::CertValidator& certValidator
) const
{
    int ret = RET_OK;
    for (size_t i = 0; i < MAX_TIMESTAMPS; i++) {
        DO(certValidator.addExpectedCerts(certValidatorTs[i].getExpectedCerts()));
        DO(certValidator.addExpectedCrls(certValidatorTs[i].getExpectedCrls()));
    }

cleanup:
    return ret;
}

vector<CertValidator::CertChainItem*> SigningDoc::collectSignerCerts (
        CertValidator::CertChainItem** signerItem
) const
{
    vector<CertValidator::CertChainItem*> rv_certs;
    *signerItem = nullptr;
    for (const auto it : sharedData->certValidator.getCertChain()) {
        if (!*signerItem && (it->getSubject() == sharedData->cerSigner)) {
            *signerItem = it;
            continue;
        }
        add_unique_cert(rv_certs, it);
    }
    for (const auto it : sharedData->certValidator.getObtainedCerts()) {
        if (it->getSubject() != sharedData->cerSigner) {
            add_unique_cert(rv_certs, it);
        }
    }
    return rv_certs;
}

vector<CertValidator::CertChainItem*> SigningDoc::collectTspCerts (void) const
{
    vector<CertValidator::CertChainItem*> rv_certs;
    for (const auto ts_attr : { TsAttr::CONTENT_TIMESTAMP, TsAttr::TIMESTAMP_TOKEN }) {
        const CertValidator::CertValidator& cert_validator = certValidatorTs[(uint32_t)ts_attr];
        for (const auto it : cert_validator.getCertChain()) {
            add_unique_cert(rv_certs, it);
        }
        for (const auto it : cert_validator.getObtainedCerts()) {
            add_unique_cert(rv_certs, it);
        }
    }
    return rv_certs;
}

void tspUris (
        const LibraryConfig::TspParams& tspParams,
        const Cert::CerItem* cerSigner,
        vector<string>& certUris,
        vector<string>& configUris
)
{
    certUris.clear();
    configUris.clear();
    if (cerSigner && !(tspParams.forced && !tspParams.uris.empty())) {
        certUris = cerSigner->getUris().tsp;
    }
    for (const auto& it : tspParams.uris) {
        if (std::find(certUris.begin(), certUris.end(), it) == certUris.end()) {
            configUris.push_back(it);
        }
    }
}

int requestTimestamp (
        const HttpHelper::Params& httpParams,
        const vector<string>& certUris,
        const vector<string>& configUris,
        Tsp::TspHelper& tspHelper,
        string& tspUri
)
{
    vector<string> candidates;
    auto add = [&candidates](const string& uri) {
        if (std::find(candidates.begin(), candidates.end(), uri) == candidates.end()) {
            candidates.push_back(uri);
        }
    };
    if (!tspUri.empty()) {
        add(tspUri);
    }
    for (const auto& it : HttpHelper::randomURIs(certUris)) {
        add(it);
    }
    for (const auto& it : configUris) {
        add(it);
    }
    if (candidates.empty()) return RET_UAPKI_TSP_URL_NOT_PRESENT;

    int rv = RET_UAPKI_TSP_NOT_RESPONDING;
    for (const auto& it : candidates) {
        SmartBA sba_resp;
        DEBUG_OUTPUT_OUTSTREAM(string("TSP-request, url=") + it, tspHelper.getRequestEncoded());
        int ret = HttpHelper::post(
            httpParams,
            it,
            HttpHelper::CONTENT_TYPE_TSP_REQUEST,
            tspHelper.getRequestEncoded(),
            &sba_resp
        );
        DEBUG_OUTPUT_OUTSTREAM(string("TSP-response, url=") + it, sba_resp.get());
        if (ret != RET_OK) continue;

        //  A TSA that refuses (e.g. an unsupported hash algorithm) or answers wrongly: the next one
        ret = tspHelper.parseResponse(sba_resp.get());
        if (ret != RET_OK) {
            rv = ret;
            continue;
        }
        if (
            (tspHelper.getStatus() != Tsp::PkiStatus::GRANTED) &&
            (tspHelper.getStatus() != Tsp::PkiStatus::GRANTED_WITHMODS)
        ) {
            rv = RET_UAPKI_TSP_RESPONSE_NOT_GRANTED;
            continue;
        }
        tspUri = it;
        return RET_OK;
    }
    return rv;
}

//  Unsigned attributes added to the (first) SignerInfo of a CMS ContentInfo, the other bytes kept as they are
//  (the TSA signature covers TSTInfo and the signed attributes only). DER with definite lengths only
int addUnsignedAttrsToToken (
        const ByteArray* baToken,
        const vector<vector<uint8_t>>& encodedAttrs,
        ByteArray** baResult
)
{
    vector<vector<uint8_t>> ci, wrap, sdata, sinfos, sinfo;
    if (
        !Der::children(ba_get_buf_const(baToken), ba_get_len(baToken), ci) || (ci.size() != 2) ||
        !Der::children(ci[1].data(), ci[1].size(), wrap) || (wrap.size() != 1) ||
        !Der::children(wrap[0].data(), wrap[0].size(), sdata) || sdata.empty() || (sdata.back()[0] != 0x31) ||
        !Der::children(sdata.back().data(), sdata.back().size(), sinfos) || sinfos.empty() ||
        !Der::children(sinfos[0].data(), sinfos[0].size(), sinfo) || sinfo.empty()
    ) {
        return RET_UAPKI_INVALID_STRUCT;
    }

    vector<uint8_t> unsigned_attrs;
    if (sinfo.back()[0] == 0xA1) {
        size_t lh = 0, lb = 0;
        (void)Der::read(sinfo.back().data(), sinfo.back().size(), lh, lb);
        unsigned_attrs.assign(sinfo.back().begin() + lh, sinfo.back().end());
        sinfo.pop_back();
    }
    for (const auto& it : encodedAttrs) {
        unsigned_attrs.insert(unsigned_attrs.end(), it.begin(), it.end());
    }
    sinfo.push_back(Der::wrap(0xA1, unsigned_attrs));

    auto concat = [](const vector<vector<uint8_t>>& items) {
        vector<uint8_t> rv;
        for (const auto& it : items) rv.insert(rv.end(), it.begin(), it.end());
        return rv;
    };
    sinfos[0] = Der::wrap(0x30, concat(sinfo));
    sdata.back() = Der::wrap(0x31, concat(sinfos));
    wrap[0] = Der::wrap(0x30, concat(sdata));
    ci[1] = Der::wrap(ci[1][0], concat(wrap));
    const vector<uint8_t> rv = Der::wrap(0x30, concat(ci));

    *baResult = ba_alloc_from_uint8(rv.data(), rv.size());
    return (*baResult) ? RET_OK : RET_UAPKI_GENERAL_ERROR;
}

int SigningDoc::addTspValidationData (void)
{
    int ret = RET_OK;
    Attribute* attr_ts = nullptr;
    for (auto& it : m_UnsignedAttrs) {
        if (it->type == string(OID_PKCS9_TIMESTAMP_TOKEN)) {
            attr_ts = it;
            break;
        }
    }
    if (!attr_ts) return RET_OK;

    const vector<CertValidator::CertChainItem*> tsp_certs = collectTspCerts();
    if (tsp_certs.empty()) return RET_OK;

    //  The certificates not already in the time-stamp token (TS 101 733, 6.3.3)
    Pkcs7::SignedDataParser token_parser;
    vector<CertValidator::CertChainItem*> cert_values;
    DO(token_parser.parse(attr_ts->baValues));
    for (const auto it : tsp_certs) {
        bool present = false;
        for (const auto& it_cert : token_parser.getCerts()) {
            if (ba_cmp(it_cert, it->getSubject()->getEncoded()) == 0) {
                present = true;
                break;
            }
        }
        if (!present) {
            cert_values.push_back(it);
        }
    }

    {
        vector<vector<uint8_t>> encoded_attrs;
        SmartBA sba_values, sba_revocvalues;
        if (!cert_values.empty()) {
            DO(encodeCertValues(cert_values, &sba_values));
            Attribute attr(OID_PKCS9_CERT_VALUES, sba_values.pop());
            SmartBA sba_attr;
            DO(AttributeHelper::encodeAttribute(attr, &sba_attr));
            encoded_attrs.push_back(vector<uint8_t>(sba_attr.buf(), sba_attr.buf() + sba_attr.size()));
        }
        DO(encodeRevocationValues(tsp_certs, &sba_revocvalues));
        {
            Attribute attr(OID_PKCS9_REVOCATION_VALUES, sba_revocvalues.pop());
            SmartBA sba_attr;
            DO(AttributeHelper::encodeAttribute(attr, &sba_attr));
            encoded_attrs.push_back(vector<uint8_t>(sba_attr.buf(), sba_attr.buf() + sba_attr.size()));
        }

        ByteArray* ba_token = nullptr;
        DO(addUnsignedAttrsToToken(attr_ts->baValues, encoded_attrs, &ba_token));
        ba_free(attr_ts->baValues);
        attr_ts->baValues = ba_token;
    }

cleanup:
    return ret;
}

vector<CertValidator::CertChainItem*> SigningDoc::collectCerts (void) const
{
    vector<CertValidator::CertChainItem*> rv_certs;
    if (sharedData->signatureFormat >= SignatureFormat::CADES_C) {
        size_t cnt = sharedData->certValidator.getCountAllCerts();
        for (size_t i = 0; i < MAX_TIMESTAMPS; i++) {
            cnt += certValidatorTs[i].getCountAllCerts();
        }
        rv_certs.reserve(cnt);

        for (const auto it : sharedData->certValidator.getCertChain()) {
            add_unique_cert(rv_certs, it);
        }
        for (const auto it : sharedData->certValidator.getObtainedCerts()) {
            add_unique_cert(rv_certs, it);
        }

        for (size_t i = 0; i < MAX_TIMESTAMPS; i++) {
            for (const auto it : certValidatorTs[i].getCertChain()) {
                add_unique_cert(rv_certs, it);
            }
            for (const auto it : certValidatorTs[i].getObtainedCerts()) {
                add_unique_cert(rv_certs, it);
            }
        }
    }

    return rv_certs;
}

int SigningDoc::encodeCertValues (
        const vector<CertValidator::CertChainItem*>& certs,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    vector<const ByteArray*> cert_values;

    if (certs.empty()) return RET_UAPKI_INVALID_PARAMETER;

    for (const auto it : certs) {
        cert_values.push_back(it->getSubject()->getEncoded());
    }

    DO(AttributeHelper::encodeCertValues(cert_values, baEncoded));
    DEBUG_OUTCON(puts("encodeCertValues:"); ba_print(stdout, *baEncoded));

cleanup:
    return ret;
}

int SigningDoc::encodeCertificateRefs (
        const vector<CertValidator::CertChainItem*>& certs,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    vector<OtherCertId> other_certids;
    size_t idx = 0;

    if (certs.empty()) return RET_UAPKI_INVALID_PARAMETER;

    other_certids.resize(certs.size());
    for (const auto it : certs) {
        const Cert::CerItem& cer_item = *it->getSubject();
        OtherCertId& dst_othercertid = other_certids[idx++];

        DO(::hash(sharedData->hashDigest, cer_item.getEncoded(), &dst_othercertid.baHashValue));
        if (!dst_othercertid.hashAlgorithm.copy(sharedData->aidDigest)) return RET_UAPKI_GENERAL_ERROR;

        DO(Cert::issuerToGeneralNames(cer_item.getIssuer(), &dst_othercertid.issuerSerial.baIssuer));
        CHECK_NOT_NULL(dst_othercertid.issuerSerial.baSerialNumber = ba_copy_with_alloc(cer_item.getSerialNumber(), 0, 0));
    }

    DO(AttributeHelper::encodeCertificateRefs(other_certids, baEncoded));
    DEBUG_OUTCON(puts("encodeCertificateRefs:"); ba_print(stdout, *baEncoded));

cleanup:
    return ret;
}

int SigningDoc::encodeRevocationRefs (
        const vector<CertValidator::CertChainItem*>& certs,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    AttributeHelper::RevocationRefsBuilder revocrefs_builder;
    AttributeHelper::RevocationRefsBuilder::CrlOcspRef* p_crlocspref = nullptr;
    Crl::CrlItem* pcrl_item = nullptr;
    const UapkiNS::OtherHash* pcrl_hash = nullptr;
    size_t idx = 0;

    DO(revocrefs_builder.init());

    for (const auto it : certs) {
        DO(revocrefs_builder.addCrlOcspRef());
        p_crlocspref = revocrefs_builder.getCrlOcspRef(idx++);
        switch (sharedData->signatureFormat) {
        case SignatureFormat::CADES_C:
            pcrl_item = it->getResultValidationByCrl().crlItem;
            if (pcrl_item) {
                DO(pcrl_item->generateHash(sharedData->aidDigest, &pcrl_hash));
                DO(p_crlocspref->addCrlValidatedId(*pcrl_hash, pcrl_item->getCrlIdentifier()));
            }
            break;
        case SignatureFormat::CADES_XL:
        case SignatureFormat::CADES_A:
            if (!it->getResultValidationByOcsp().ocspIdentifier.empty()) {
                SmartBA sba_ocspresphash;
                if (!it->getResultValidationByOcsp().ocspResponse.empty()) {
                    DO(Ocsp::generateOtherHash(
                        it->getResultValidationByOcsp().ocspResponse.get(),
                        sharedData->aidDigest,
                        &sba_ocspresphash
                    ));
                }
                DO(p_crlocspref->addOcspResponseId(
                    it->getResultValidationByOcsp().ocspIdentifier.get(),
                    sba_ocspresphash.get()
                ));
            }
            break;
        default:
            break;
        }
    }

    DO(revocrefs_builder.encode());

    *baEncoded = revocrefs_builder.getEncoded(true);
    DEBUG_OUTCON(puts("encodeRevocationRefs:"); ba_print(stdout, *baEncoded));

cleanup:
    return ret;
}

int SigningDoc::encodeRevocationValues (
        const vector<CertValidator::CertChainItem*>& certs,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    AttributeHelper::RevocationValuesBuilder revocvalues_builder;

    DO(revocvalues_builder.init());

    switch (sharedData->signatureFormat) {
    case SignatureFormat::CADES_XL:
    case SignatureFormat::CADES_A:
        for (const auto it : certs) {
            if (!it->getResultValidationByOcsp().basicOcspResponse.empty()) {
                DO(revocvalues_builder.addOcspValue(it->getResultValidationByOcsp().basicOcspResponse.get()));
            }
        }
        break;
    default:
        break;
    }

    DO(revocvalues_builder.encode());

    *baEncoded = revocvalues_builder.getEncoded(true);
    DEBUG_OUTCON(puts("encodeRevocationValues:"); ba_print(stdout, *baEncoded));

cleanup:
    return ret;
}

int verifySignedData (
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
}


}   //  end namespace Sign

}   //  end namespace Doc

}   //  end namespace UapkiNS
