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

#include "doc-sign.h"
#include "api-json-internal.h"
#include "attribute-helper.h"
#include "attribute-utils.h"
#include "oid-utils.h"
#include "time-utils.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


namespace UapkiNS {

namespace Doc {

namespace Sign {


static int add_unique_cert (
        vector<SigningDoc::CerDataItem*>& certs,
        CerStore::Item* cerStoreItem
)
{
    if (!cerStoreItem) return RET_OK;

    for (const auto& it : certs) {
        if (ba_cmp(cerStoreItem->baCertId, it->pcsiSubject->baCertId) == RET_OK) {
            return RET_OK;
        }
    }

    SigningDoc::CerDataItem* cdi = new SigningDoc::CerDataItem();
    if (!cdi) return RET_UAPKI_GENERAL_ERROR;

    certs.push_back(cdi);
    cdi->pcsiSubject = cerStoreItem;
    return RET_OK;
}   //  add_unique_cert


SigningDoc::CerDataItem::CerDataItem (void)
    : pcsiSubject(nullptr)
    , pcsiIssuer(nullptr)
    , isSelfSigned(false)
    , pcsiCrl(nullptr)
    , pcsiResponder(nullptr)
{
}

SigningDoc::CerDataItem::~CerDataItem (void)
{
}

int SigningDoc::CerDataItem::set (const CerDataItem& src)
{
    pcsiSubject = src.pcsiSubject;
    pcsiIssuer = src.pcsiIssuer;
    isSelfSigned = src.isSelfSigned;
    if (src.pcsiResponder) {
        pcsiResponder = src.pcsiResponder;
        if (
            !basicOcspResponse.set(ba_copy_with_alloc(src.basicOcspResponse.get(), 0, 0)) ||
            !ocspIdentifier.set(ba_copy_with_alloc(src.ocspIdentifier.get(), 0, 0)) ||
            !ocspRespHash.set(ba_copy_with_alloc(src.ocspRespHash.get(), 0, 0))
        ) return RET_UAPKI_GENERAL_ERROR;
    }
    return RET_OK;
}


SigningDoc::SignParams::SignParams (void)
    : signatureFormat(SignatureFormat::UNDEFINED)
    , isCadesCXA(false)
    , isCadesFormat(false)
    , hashDigest(HashAlg::HASH_ALG_UNDEFINED)
    , hashSignature(HashAlg::HASH_ALG_UNDEFINED)
    , detachedData(true)
    , includeCert(false)
    , includeTime(false)
    , includeContentTS(false)
    , includeSignatureTS(false)
    , sidUseKeyId(false)
{
}

SigningDoc::SignParams::~SignParams (void)
{
    signatureFormat = SignatureFormat::UNDEFINED;
    for (auto& it : chainCerts) {
        delete it;
    }
}

int SigningDoc::SignParams::addCert (
    CerStore::Item* cerStoreItem
)
{
    return add_unique_cert(chainCerts, cerStoreItem);
}

int SigningDoc::SignParams::setSignatureFormat (
        const SignatureFormat aSignatureFormat
)
{
    switch (aSignatureFormat) {
    case SignatureFormat::CADES_A:      //  CADES_A  >  CADES_XL
    case SignatureFormat::CADES_XL:     //  CADES_XL >  CADES_C
    case SignatureFormat::CADES_C:      //  CADES_C  >  CADES_T
        includeCert = true;
        isCadesCXA = true;
    case SignatureFormat::CADES_T:      //  CADES_T  >  CADES_BES
        includeContentTS = true;
        includeSignatureTS = true;
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

    signatureFormat = aSignatureFormat;
    return RET_OK;
}


SigningDoc::SigningDoc (void)
    : signParams(nullptr)
    , signerInfo(nullptr)
    , isDigest(false)
{
    DEBUG_OUTCON(puts("SigningDoc::SigningDoc()"));
}

SigningDoc::~SigningDoc (void)
{
    DEBUG_OUTCON(puts("SigningDoc::~SigningDoc()"));
    for (auto& it : m_Certs) {
        delete it;
    }
    for (auto& it : m_SignedAttrs) {
        delete it;
    }
    for (auto& it : m_UnsignedAttrs) {
        delete it;
    }
}

int SigningDoc::init (
        const SignParams* iSignParams
)
{
    signParams = iSignParams;
    if (!signParams) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    if (signParams->signatureFormat != SignatureFormat::RAW) {
        int ret = builder.init();
        if (ret != RET_OK) return ret;

        ret = builder.addSignerInfo();
        if (ret != RET_OK) return ret;

        signerInfo = builder.getSignerInfo(0);
        signerInfo->setDigestAlgorithm(signParams->aidDigest);

        for (const auto& it : iSignParams->chainCerts) {
            CerDataItem* cdi = new CerDataItem();
            if (!cdi) return RET_UAPKI_GENERAL_ERROR;

            m_Certs.push_back(cdi);
            DO(cdi->set(*it));
        }

        DO(m_ArchiveTsHelper.init(
            (signParams->signatureFormat == SignatureFormat::CADES_A)
                ? &signParams->aidDigest : nullptr
        ));

        if (signParams->includeCert) {
            const ByteArray* ba_certencoded = signParams->signer.pcsiSubject->baEncoded;
            DO(builder.addCertificate(ba_certencoded));
            if (m_ArchiveTsHelper.isEnabled()) {
                DO(m_ArchiveTsHelper.addCertificate(ba_certencoded));
            }
        }
    }

cleanup:
    return ret;
}

int SigningDoc::addCert (
        CerStore::Item* cerStoreItem
)
{
    return add_unique_cert(m_Certs, cerStoreItem);
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
    DO(builder.setEncapContentInfo(contentType, (signParams->detachedData) ? nullptr : data.get()));
    DO(signerInfo->encodeUnsignedAttrs());

    DO(builder.encode());

cleanup:
    return ret;
}

int SigningDoc::buildUnsignedAttributes (void)
{
    int ret = RET_OK;

    Attribute attr_certificaterefs, attr_revocationrefs;
    Attribute attr_certvalues, attr_revocationvalues;

    switch (signParams->signatureFormat) {
    case SignatureFormat::CADES_C:
        DO(encodeCertificateRefs(attr_certificaterefs));
        DO(encodeRevocationRefs(attr_revocationrefs));
        break;
    case SignatureFormat::CADES_XL:
    case SignatureFormat::CADES_A:
        DO(encodeCertificateRefs(attr_certificaterefs));
        DO(encodeRevocationRefs(attr_revocationrefs));
        DO(encodeCertValues(attr_certvalues));
        DO(encodeRevocationValues(attr_revocationvalues));
        break;
    default:
        break;
    }

    //  Add CAdES-unsigned attrs
    if (attr_certificaterefs.isPresent()) {
        DO(signerInfo->addUnsignedAttr(attr_certificaterefs));
    }
    if (attr_revocationrefs.isPresent()) {
        DO(signerInfo->addUnsignedAttr(attr_revocationrefs));
    }
    if (attr_certvalues.isPresent()) {
        DO(signerInfo->addUnsignedAttr(attr_certvalues));
    }
    if (attr_revocationvalues.isPresent()) {
        DO(signerInfo->addUnsignedAttr(attr_revocationvalues));
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
        DO(::hash(signParams->hashDigest, data.get(), &messageDigest));
    }
    else {
        const size_t hashsize_expected = hash_get_size(signParams->hashDigest);
        if (hashsize_expected == data.size()) {
            messageDigest = data;
            (void)data.set(nullptr);
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

    DO(::hash(signParams->hashDigest, signature.get(), baHash));

cleanup:
    return ret;
}

int SigningDoc::digestSignedAttributes (void)
{
    int ret = RET_OK;

    DO(::hash(signParams->hashSignature, signerInfo->getSignedAttrsEncoded(), &hashSignedAttrs));

cleanup:
    return ret;
}

int SigningDoc::setSignature (
        const ByteArray* baSignValue
)
{
    int ret = RET_OK;

    CHECK_PARAM(baSignValue != nullptr);

    DO(signerInfo->setSignature(signParams->aidSignature, baSignValue));
    (void)signature.set((ByteArray*)baSignValue);

cleanup:
    return ret;
}

int SigningDoc::setupSignerIdentifier (void)
{
    int ret = RET_OK;
    SmartBA sba_sid;
    uint32_t version = 0;

    if (!signParams->sidUseKeyId) {
        DO(signParams->signer.pcsiSubject->getIssuerAndSN(&sba_sid));
        DO(signerInfo->setSid(Pkcs7::SignerIdentifierType::ISSUER_AND_SN, sba_sid.get()));
        version = 1;
    }
    else {
        DEBUG_OUTCON(printf("signParams->keyId, hex:"); ba_print(stdout, signParams->keyId.get()));
        DO(signerInfo->setSid(Pkcs7::SignerIdentifierType::SUBJECT_KEYID, signParams->keyId.get()));
        version = 3;
    }
    DEBUG_OUTCON(printf("SigningDoc::setupSignerIdentifier(), sba_sid, hex:"); ba_print(stdout, sba_sid.get()));
    DO(signerInfo->setVersion(version));

cleanup:
    return ret;
}

ByteArray* SigningDoc::getEncoded (void)
{
    return (signParams->signatureFormat != SignatureFormat::RAW)
        ? builder.getEncoded() : signature.get();
}

int SigningDoc::encodeSignaturePolicy (
        const string& sigPolicyiId,
        Attribute& attr
)
{
    int ret = RET_OK;

    DO(AttributeHelper::encodeSignaturePolicy(sigPolicyiId, &attr.baValues));
    attr.type = string(OID_PKCS9_SIG_POLICY_ID);

cleanup:
    return ret;
}

int SigningDoc::encodeSigningCertificate (
        const EssCertId& essCertId,
        Attribute& attr
)
{
    int ret = RET_OK;

    DO(AttributeHelper::encodeSigningCertificate(essCertId, &attr.baValues));
    attr.type = string(OID_PKCS9_SIGNING_CERTIFICATE_V2);

cleanup:
    return ret;
}

int SigningDoc::encodeCertValues (
        Attribute& attr
)
{
    int ret = RET_OK;
    vector<const ByteArray*> cert_values;

    if (m_Certs.empty()) return RET_UAPKI_INVALID_PARAMETER;

    for (const auto& it : m_Certs) {
        cert_values.push_back(it->pcsiSubject->baEncoded);
    }

    attr.type = string(OID_PKCS9_CERT_VALUES);
    DO(AttributeHelper::encodeCertValues(cert_values, &attr.baValues));
    DEBUG_OUTCON(puts("encodeCertValues:"); ba_print(stdout, attr.baValues));

cleanup:
    return ret;
}

int SigningDoc::encodeCertificateRefs (
        Attribute& attr
)
{
    int ret = RET_OK;
    vector<OtherCertId> other_certids;
    size_t idx = 0;

    if (m_Certs.empty()) return RET_UAPKI_INVALID_PARAMETER;

    other_certids.resize(m_Certs.size());
    for (const auto& it : m_Certs) {
        const CerStore::Item& src_cer = *it->pcsiSubject;
        OtherCertId& dst_othercertid = other_certids[idx++];

        DO(::hash(signParams->hashDigest, src_cer.baEncoded, &dst_othercertid.baHashValue));
        if (!dst_othercertid.hashAlgorithm.copy(signParams->aidDigest)) return RET_UAPKI_GENERAL_ERROR;

        DO(CerStore::issuerToGeneralNames(src_cer.baIssuer, &dst_othercertid.issuerSerial.baIssuer));
        CHECK_NOT_NULL(dst_othercertid.issuerSerial.baSerialNumber = ba_copy_with_alloc(src_cer.baSerialNumber, 0, 0));
    }

    attr.type = string(OID_PKCS9_CERTIFICATE_REFS);
    DO(AttributeHelper::encodeCertificateRefs(other_certids, &attr.baValues));
    DEBUG_OUTCON(puts("encodeCertificateRefs:"); ba_print(stdout, attr.baValues));

cleanup:
    return ret;
}

int SigningDoc::encodeRevocationRefs (
        Attribute& attr
)
{
    int ret = RET_OK;
    const SigningDoc::CerDataItem& signer = signParams->signer;
    AttributeHelper::RevocationRefsBuilder revocrefs_builder;
    AttributeHelper::RevocationRefsBuilder::CrlOcspRef* p_crlocspref = nullptr;
    CrlStore::Item* p_crl = nullptr;
    size_t idx = 0;

    DO(revocrefs_builder.init());

    //  First item - cert of signer
    DO(revocrefs_builder.addCrlOcspRef());
    p_crlocspref = revocrefs_builder.getCrlOcspRef(idx++);
    switch (signParams->signatureFormat) {
    case SignatureFormat::CADES_C:
        p_crl = signer.pcsiCrl;
        if (p_crl) {
            DO(p_crl->getHash(signParams->aidDigest));
            DO(p_crlocspref->addCrlValidatedId(p_crl->crlHash, p_crl->baCrlIdentifier));
        }
        break;
    case SignatureFormat::CADES_XL:
    case SignatureFormat::CADES_A:
        if (signer.ocspIdentifier.buf()) {
            DO(p_crlocspref->addOcspResponseId(signer.ocspIdentifier.get(), signer.ocspRespHash.get()));
        }
        break;
    default:
        break;
    }

    //  Next certs
    for (const auto& it : getCerts()) {
        DO(revocrefs_builder.addCrlOcspRef());
        p_crlocspref = revocrefs_builder.getCrlOcspRef(idx++);
        switch (signParams->signatureFormat) {
        case SignatureFormat::CADES_C:
            p_crl = it->pcsiCrl;
            if (p_crl) {
                DO(p_crl->getHash(signParams->aidDigest));
                DO(p_crlocspref->addCrlValidatedId(p_crl->crlHash, p_crl->baCrlIdentifier));
            }
            break;
        case SignatureFormat::CADES_XL:
        case SignatureFormat::CADES_A:
            if (it->ocspIdentifier.buf()) {
                DO(p_crlocspref->addOcspResponseId(it->ocspIdentifier.get(), it->ocspRespHash.get()));
            }
            break;
        default:
            break;
        }
    }

    DO(revocrefs_builder.encode());

    attr.type = string(OID_PKCS9_REVOCATION_REFS);
    attr.baValues = revocrefs_builder.getEncoded(true);
    DEBUG_OUTCON(puts("encodeRevocationRefs:"); ba_print(stdout, attr.baValues));

cleanup:
    return ret;
}

int SigningDoc::encodeRevocationValues (
        Attribute& attr
)
{
    int ret = RET_OK;
    const SigningDoc::CerDataItem& signer = signParams->signer;
    AttributeHelper::RevocationValuesBuilder revocvalues_builder;

    DO(revocvalues_builder.init());

    switch (signParams->signatureFormat) {
    case SignatureFormat::CADES_XL:
    case SignatureFormat::CADES_A:
        //  First item - cert of signer
        DO(revocvalues_builder.addOcspValue(signer.basicOcspResponse.get()));
        //  Next certs
        for (const auto& it : m_Certs) {
            DO(revocvalues_builder.addOcspValue(it->basicOcspResponse.get()));
        }
        break;
    default:
        break;
    }

    DO(revocvalues_builder.encode());

    attr.type = string(OID_PKCS9_REVOCATION_VALUES);
    attr.baValues = revocvalues_builder.getEncoded(true);
    DEBUG_OUTCON(puts("encodeRevocationValues:"); ba_print(stdout, attr.baValues));

cleanup:
    return ret;
}


}   //  end namespace Sign

}   //  end namespace Doc

}   //  end namespace UapkiNS

