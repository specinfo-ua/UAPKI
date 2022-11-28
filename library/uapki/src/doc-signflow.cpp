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
#include "attribute-utils.h"
#include "cer-store.h"
#include "cms-utils.h"
#include "doc-signflow.h"
#include "oid-utils.h"
#include "time-utils.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


SigningDoc::SignParams::SignParams (void)
    : signatureFormat(SignatureFormat::UNDEFINED)
    , hashDigest(HashAlg::HASH_ALG_UNDEFINED)
    , hashSignature(HashAlg::HASH_ALG_UNDEFINED)
    , cerStoreItem(nullptr)
    , baKeyId(nullptr)
    , detachedData(true)
    , includeCert(false)
    , includeTime(false)
    , includeContentTS(false)
    , includeSignatureTS(false)
    , sidUseKeyId(false)
    , tspPolicy(nullptr)
{
}

SigningDoc::SignParams::~SignParams (void)
{
    signatureFormat = SignatureFormat::UNDEFINED;
    cerStoreItem = nullptr; //  This ref
    ba_free(baKeyId);
}

int SigningDoc::SignParams::setSignatureFormat (const SignatureFormat aSignatureFormat)
{
    switch (aSignatureFormat) {
    case SignatureFormat::CADES_Av3:
    case SignatureFormat::CADES_C:
    case SignatureFormat::CADES_T:
        includeContentTS = true;
        includeSignatureTS = true;
    case SignatureFormat::CADES_BES:
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

    signatureFormat = aSignatureFormat;
    return RET_OK;
}


SigningDoc::CadesBuilder::CadesBuilder (CerStore* iCerStore)
    : m_CerStore(iCerStore)
    , m_IsCadesFormat(false)
{
    DEBUG_OUTCON(puts("SigningDoc::CadesBuilder::CadesBuilder()"));
}

SigningDoc::CadesBuilder::~CadesBuilder (void)
{
    DEBUG_OUTCON(puts("SigningDoc::CadesBuilder::~CadesBuilder()"));
}

int SigningDoc::CadesBuilder::init (void)
{
    switch (m_SignParams.signatureFormat) {
    case SignatureFormat::CADES_BES:
    case SignatureFormat::CADES_T:
    case SignatureFormat::CADES_C:
    case SignatureFormat::CADES_Av3:
        m_IsCadesFormat = true;
        break;
    default:
        m_IsCadesFormat = false;
        break;
    }

    if (m_IsCadesFormat) {
        if (!m_SignParams.cerStoreItem) return RET_UAPKI_INVALID_PARAMETER;
    }

    return RET_OK;
}

int SigningDoc::CadesBuilder::buildChainCerts (void)
{
    int ret = RET_OK;
    CerStore::Item* cer_subject = m_SignParams.cerStoreItem;
    CerStore::Item* cer_issuer = nullptr;
    bool is_selfsigned = false;

    while (!is_selfsigned) {
        DO(m_CerStore->getIssuerCert(cer_subject, &cer_issuer, is_selfsigned));
        if (!is_selfsigned) {
            m_ChainCerts.push_back(cer_issuer);
        }
        cer_subject = cer_issuer;
    }

cleanup:
    DEBUG_OUTCON(printf("SigningDoc::CadesBuilder::buildChainCerts(), ret: %d  chain len: %zu\n", ret, m_ChainCerts.size()));
    return ret;
}

int SigningDoc::CadesBuilder::process (void)
{
    int ret = RET_OK;

    //  Now simple case: one cert
    m_EssCertids.resize(1);
    DO(m_SignParams.cerStoreItem->generateEssCertId(m_SignParams.aidDigest, m_EssCertids[0]));

    switch (m_SignParams.signatureFormat) {
    case SignatureFormat::CADES_BES:
    case SignatureFormat::CADES_T:
        DO(encodeSigningCertificate(m_SignParams.attrSigningCert));
        break;
    case SignatureFormat::CADES_C:
        DO(encodeSigningCertificate(m_SignParams.attrSigningCert));
        DO(encodeCertificateRefs(m_SignParams.attrCertificateRefs));
        DO(encodeRevocationRefs(m_SignParams.attrRevocationRefs));
        break;
    case SignatureFormat::CADES_Av3:
        DO(encodeSigningCertificate(m_SignParams.attrSigningCert));
        DO(encodeCertificateRefs(m_SignParams.attrCertificateRefs));
        DO(encodeRevocationRefs(m_SignParams.attrRevocationRefs));
        //DO(encode_attrvalue_certificatevalues(sign_params));
        //DO(encode_attrvalue_revocationvalues(sign_params));
        break;
    default:
        break;
    }

cleanup:
    return ret;
}

int SigningDoc::CadesBuilder::encodeCertificateRefs (UapkiNS::Attribute& attr)
{
    int ret = RET_OK;
    vector<UapkiNS::OtherCertId> other_certids;
    size_t idx = 0;

    if (m_ChainCerts.empty()) return RET_UAPKI_INVALID_PARAMETER;

    other_certids.resize(m_ChainCerts.size());
    for (const auto& it : m_ChainCerts) {
        UapkiNS::OtherCertId& dst_othercertid = other_certids[idx++];

        DO(::hash(m_SignParams.hashDigest, it->baEncoded, &dst_othercertid.baHashValue));
        if (!dst_othercertid.hashAlgorithm.copy(m_SignParams.aidDigest)) return RET_UAPKI_GENERAL_ERROR;

        DO(CerStore::issuerToGeneralNames(it->baIssuer, &dst_othercertid.issuerSerial.baIssuer));
        CHECK_NOT_NULL(dst_othercertid.issuerSerial.baSerialNumber = ba_copy_with_alloc(it->baSerialNumber, 0, 0));
    }

    attr.type = string(OID_PKCS9_CERTIFICATE_REFS);
    DO(UapkiNS::AttributeHelper::encodeCertificateRefs(other_certids, &attr.baValues));
    DEBUG_OUTCON(puts("encodeCertificateRefs:"); ba_print(stdout, attr.baValues));

cleanup:
    return ret;
}

int SigningDoc::CadesBuilder::encodeRevocationRefs (UapkiNS::Attribute& attr)
{
    int ret = RET_OK;
    UapkiNS::AttributeHelper::RevocationRefsBuilder revocrefs_builder;

    //check

    DO(revocrefs_builder.init());
    //  Now is empty: 3 empty CrlOcspRef's
    DO(revocrefs_builder.addCrlOcspRef());
    DO(revocrefs_builder.addCrlOcspRef());
    DO(revocrefs_builder.addCrlOcspRef());
    DO(revocrefs_builder.encode());

    attr.type = string(OID_PKCS9_REVOCATION_REFS);
    attr.baValues = revocrefs_builder.getEncoded(true);
    DEBUG_OUTCON(puts("encodeRevocationRefs:"); ba_print(stdout, attr.baValues));

cleanup:
    return ret;
}

int SigningDoc::CadesBuilder::encodeSigningCertificate (UapkiNS::Attribute& attr)
{
    int ret = RET_OK;

    if (m_EssCertids.empty()) return RET_UAPKI_INVALID_PARAMETER;

    attr.type = string(OID_PKCS9_SIGNING_CERTIFICATE_V2);
    DO(UapkiNS::AttributeHelper::encodeSigningCertificate(m_EssCertids, &attr.baValues));
    DEBUG_OUTCON(puts("encodeSigningCertificate:"); ba_print(stdout, attr.baValues));

cleanup:
    return ret;
}


SigningDoc::SigningDoc (void)
    : signParams(nullptr)
    , signerInfo(nullptr)
    , isDigest(false)
    , baData(nullptr)
    , baMessageDigest(nullptr)
    , baHashSignedAttrs(nullptr)
    , baSignature(nullptr)
{
    DEBUG_OUTCON(puts("SigningDoc::SigningDoc()"));
}

SigningDoc::~SigningDoc (void)
{
    DEBUG_OUTCON(puts("SigningDoc::~SigningDoc()"));
    ba_free(baData);
    ba_free(baMessageDigest);
    ba_free(baHashSignedAttrs);
    ba_free(baSignature);
    for (auto& it : m_SignedAttrs) {
        delete it;
    }
    for (auto& it : m_UnsignedAttrs) {
        delete it;
    }
}

int SigningDoc::init (const SignParams* aSignParams)
{
    signParams = aSignParams;
    if (!signParams) return RET_UAPKI_INVALID_PARAMETER;

    if (signParams->signatureFormat != SignatureFormat::RAW) {
        int ret = builder.init();
        if (ret != RET_OK) return ret;

        ret = builder.addSignerInfo();
        if (ret != RET_OK) return ret;

        signerInfo = builder.getSignerInfo(0);
        signerInfo->setDigestAlgorithm(signParams->aidDigest);
    }
    return RET_OK;
}

int SigningDoc::addSignedAttribute (const string& type, ByteArray* baValues)
{
    UapkiNS::Attribute* attr = new UapkiNS::Attribute(type, baValues);
    if (!attr) return RET_UAPKI_GENERAL_ERROR;

    m_SignedAttrs.push_back(attr);
    return RET_OK;
}

int SigningDoc::addUnsignedAttribute (const string& type, ByteArray* baValues)
{
    UapkiNS::Attribute* attr = new UapkiNS::Attribute(type, baValues);
    if (!attr) return RET_UAPKI_GENERAL_ERROR;

    m_UnsignedAttrs.push_back(attr);
    return RET_OK;
}

int SigningDoc::buildSignedAttributes (void)
{
    int ret = RET_OK;

    //  Add mandatory attrs (CMS/CAdES)
    DO(signerInfo->addSignedAttrContentType(contentType));
    DO(signerInfo->addSignedAttrMessageDigest(baMessageDigest));
    if (signParams->includeTime) {
        DO(signerInfo->addSignedAttrSigningTime(TimeUtils::nowMsTime()));
    }

    //  Add CAdES-signed attrs
    if (signParams->attrSigningCert.isPresent()) {
        DO(signerInfo->addSignedAttr(signParams->attrSigningCert));
    }
    if (signParams->attrSignPolicy.isPresent()) {
        DO(signerInfo->addSignedAttr(signParams->attrSignPolicy));
    }

    //  Add other signed attrs
    for (auto& it : m_SignedAttrs) {
        DO(signerInfo->addSignedAttr(*it));
    }

    DO(signerInfo->encodeSignedAttrs());

cleanup:
    return ret;
}

int SigningDoc::buildSignedData (void)
{
    int ret = RET_OK;
    UapkiNS::SmartBA sba_sid;
    uint32_t version = 0;

    if (!signParams->sidUseKeyId) {
        DO(signParams->cerStoreItem->getIssuerAndSN(&sba_sid));
        DO(signerInfo->setSid(sba_sid.get()));
        version = 1;
    }
    else {
        DEBUG_OUTCON(printf("signParams->baKeyId, hex:"); ba_print(stdout, signParams->baKeyId));
        DO(keyid_to_sid_subjectkeyid(signParams->baKeyId, &sba_sid));
        DO(signerInfo->setSidByKeyId(sba_sid.get()));
        version = 3;
    }
    DEBUG_OUTCON(printf("SigningDoc::buildSignedData(), ba_sid, hex:"); ba_print(stdout, sba_sid.get()));
    DO(signerInfo->setVersion(version));

    //  Add CAdES-unsigned attrs
    if (signParams->attrCertificateRefs.isPresent()) {
        DO(signerInfo->addUnsignedAttr(signParams->attrCertificateRefs));
    }
    if (signParams->attrRevocationRefs.isPresent()) {
        DO(signerInfo->addUnsignedAttr(signParams->attrRevocationRefs));
    }
    if (signParams->attrCertValues.isPresent()) {
        DO(signerInfo->addUnsignedAttr(signParams->attrCertValues));
    }
    if (signParams->attrRevocationValues.isPresent()) {
        DO(signerInfo->addUnsignedAttr(signParams->attrRevocationValues));
    }

    //  Add other unsigned attrs
    for (const auto& it : m_UnsignedAttrs) {
        DO(signerInfo->addUnsignedAttr(*it));
    }

    DO(builder.setVersion(version));
    DO(builder.setEncapContentInfo(contentType, (signParams->detachedData) ? nullptr : baData));
    if (signParams->includeCert) {
        DO(builder.addCertificate(signParams->cerStoreItem->baEncoded));
    }

    DO(builder.encode());

cleanup:
    return ret;
}

int SigningDoc::digestMessage (void)
{
    int ret = RET_OK;

    if (!isDigest) {
        DO(::hash(signParams->hashDigest, baData, &baMessageDigest));
    }
    else {
        const size_t hashsize_expected = hash_get_size(signParams->hashDigest);
        if (hashsize_expected == ba_get_len(baData)) {
            baMessageDigest = baData;
            baData = nullptr;
        }
        else {
            ret = RET_UAPKI_INVALID_PARAMETER;
        }
    }

cleanup:
    return ret;
}

int SigningDoc::digestSignature (ByteArray** baHash)
{
    int ret = RET_OK;

    CHECK_PARAM(baHash != nullptr);

    DO(::hash(signParams->hashDigest, baSignature, baHash));

cleanup:
    return ret;
}

int SigningDoc::digestSignedAttributes (void)
{
    int ret = RET_OK;

    DO(::hash(signParams->hashSignature, signerInfo->getSignedAttrsEncoded(), &baHashSignedAttrs));

cleanup:
    return ret;
}

int SigningDoc::setSignature (const ByteArray* baSignValue)
{
    int ret = RET_OK;

    CHECK_PARAM(baSignValue != nullptr);

    DO(signerInfo->setSignature(signParams->aidSignature, baSignValue));
    baSignature = (ByteArray*)baSignValue;

cleanup:
    return ret;
}

ByteArray* SigningDoc::getEncoded (void)
{
    return (signParams->signatureFormat != SignatureFormat::RAW)
        ? builder.getEncoded() : baSignature;
}
