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
#include "attribute-utils.h"
#include "cer-store.h"
#include "doc-signflow.h"
#include "oid-utils.h"
#include "time-utils.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


static int add_service_cert (
        vector<CerStore::Item*>& serviceCerts,
        CerStore::Item* cerStoreItem
)
{
    for (const auto& it : serviceCerts) {
        if (ba_cmp(cerStoreItem->baCertId, it->baCertId) == RET_OK) {
            return false;
        }
    }

    serviceCerts.push_back(cerStoreItem);
    return true;
}   //  add_service_cert

static int keyid_to_sid_subjectkeyid (const ByteArray* baKeyId, ByteArray** baSubjectKeyId)
{
    int ret = RET_OK;
    //  Note:   SignerIdentifierIm_t - is SignerIdentifier IMPLICIT (use tag 0x80),
    //          SignerIdentifierEx_t - is SignerIdentifier EXPLICIT (use tag 0xA0),
    //          Here we need use implicit case SignerIdentifier
    SignerIdentifierIm_t* sid_im = NULL;

    CHECK_PARAM(baKeyId != NULL);
    CHECK_PARAM(baSubjectKeyId != NULL);

    ASN_ALLOC_TYPE(sid_im, SignerIdentifierIm_t);
    sid_im->present = SignerIdentifierIm_PR_subjectKeyIdentifier;
    DO(asn_ba2OCTSTRING(baKeyId, &sid_im->choice.subjectKeyIdentifier));

    DO(asn_encode_ba(get_SignerIdentifierIm_desc(), sid_im, baSubjectKeyId));

cleanup:
    asn_free(get_SignerIdentifierIm_desc(), sid_im);
    return ret;
}   //  keyid_to_sid_subjectkeyid


SigningDoc::OcspResponseItem::OcspResponseItem (void)
    : baBasicOcspResponse(nullptr)
    , baOcspIdentifier(nullptr)
    , baOcspRespHash(nullptr)
{
}

SigningDoc::OcspResponseItem::~OcspResponseItem (void)
{
    ba_free(baBasicOcspResponse);
    ba_free(baOcspIdentifier);
    ba_free(baOcspRespHash);
}

int SigningDoc::OcspResponseItem::set (const OcspResponseItem& src)
{
    baBasicOcspResponse = ba_copy_with_alloc(src.baBasicOcspResponse, 0, 0);
    baOcspIdentifier = ba_copy_with_alloc(src.baOcspIdentifier, 0, 0);
    baOcspRespHash = ba_copy_with_alloc(src.baOcspRespHash, 0, 0);

    return (baBasicOcspResponse && baOcspIdentifier && baOcspRespHash) ? RET_OK : RET_UAPKI_GENERAL_ERROR;
}


SigningDoc::SignParams::SignParams (void)
    : signatureFormat(UapkiNS::SignatureFormat::UNDEFINED)
    , isCadesFormat(false)
    , hashDigest(HashAlg::HASH_ALG_UNDEFINED)
    , hashSignature(HashAlg::HASH_ALG_UNDEFINED)
    , cerSigner(nullptr)
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
    signatureFormat = UapkiNS::SignatureFormat::UNDEFINED;
    cerSigner = nullptr; //  This ref
    ba_free(baKeyId);
    for (auto& it : ocspRespItems) {
        delete it;
    }
}

bool SigningDoc::SignParams::addServiceCert (
        CerStore::Item* cerStoreItem
)
{
    return add_service_cert(serviceCerts, cerStoreItem);
}

int SigningDoc::SignParams::setSignatureFormat (
        const UapkiNS::SignatureFormat aSignatureFormat
)
{
    switch (aSignatureFormat) {
    case UapkiNS::SignatureFormat::CADES_A_V3:      //  CADES_A_V3 > CADES_X_LONG
    case UapkiNS::SignatureFormat::CADES_X_LONG:    //  CADES_X_LONG > CADES_C
    case UapkiNS::SignatureFormat::CADES_C:         //  CADES_C > CADES_T
        includeCert = true;
    case UapkiNS::SignatureFormat::CADES_T:         //  CADES_T > CADES_BES
        includeContentTS = true;
        includeSignatureTS = true;
    case UapkiNS::SignatureFormat::CADES_BES:
        sidUseKeyId = false;
        isCadesFormat = true;
        break;
    case UapkiNS::SignatureFormat::CMS_SID_KEYID:
        sidUseKeyId = true;
        break;
    case UapkiNS::SignatureFormat::RAW:
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
    for (auto& it : m_OcspRespItems) {
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
        const SignParams* aSignParams
)
{
    signParams = aSignParams;
    if (!signParams) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    if (signParams->signatureFormat != UapkiNS::SignatureFormat::RAW) {
        int ret = builder.init();
        if (ret != RET_OK) return ret;

        ret = builder.addSignerInfo();
        if (ret != RET_OK) return ret;

        signerInfo = builder.getSignerInfo(0);
        signerInfo->setDigestAlgorithm(signParams->aidDigest);

        for (const auto& it : aSignParams->chainCerts) {
            m_ChainCerts.push_back(it);
        }

        for (const auto& it : aSignParams->ocspRespItems) {
            SigningDoc::OcspResponseItem* ocspresp_item = new SigningDoc::OcspResponseItem();
            if (!ocspresp_item) return RET_UAPKI_GENERAL_ERROR;

            m_OcspRespItems.push_back(ocspresp_item);
            DO(ocspresp_item->set(*it));
        }
    }

cleanup:
    return ret;
}

bool SigningDoc::addServiceCert (
        CerStore::Item* cerStoreItem
)
{
    return add_service_cert(m_ServiceCerts, cerStoreItem);
}

int SigningDoc::addSignedAttribute (
        const string& type,
        ByteArray* baValues
)
{
    UapkiNS::Attribute* attr = new UapkiNS::Attribute(type, baValues);
    if (!attr) return RET_UAPKI_GENERAL_ERROR;

    m_SignedAttrs.push_back(attr);
    return RET_OK;
}

int SigningDoc::addUnsignedAttribute (
        const string& type,
        ByteArray* baValues
)
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
        DO(signParams->cerSigner->getIssuerAndSN(&sba_sid));
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
    if (m_AttrCertificateRefs.isPresent()) {
        DO(signerInfo->addUnsignedAttr(m_AttrCertificateRefs));
    }
    if (m_AttrRevocationRefs.isPresent()) {
        DO(signerInfo->addUnsignedAttr(m_AttrRevocationRefs));
    }
    if (m_AttrCertValues.isPresent()) {
        DO(signerInfo->addUnsignedAttr(m_AttrCertValues));
    }
    if (m_AttrRevocationValues.isPresent()) {
        DO(signerInfo->addUnsignedAttr(m_AttrRevocationValues));
    }

    //  Add other unsigned attrs
    for (const auto& it : m_UnsignedAttrs) {
        DO(signerInfo->addUnsignedAttr(*it));
    }

    DO(builder.setVersion(version));
    DO(builder.setEncapContentInfo(contentType, (signParams->detachedData) ? nullptr : baData));
    if (signParams->includeCert) {
        DO(builder.addCertificate(signParams->cerSigner->baEncoded));
    }

    DO(builder.encode());

cleanup:
    return ret;
}

int SigningDoc::buildUnsignedAttributes (void)
{
    int ret = RET_OK;

    switch (signParams->signatureFormat) {
    case UapkiNS::SignatureFormat::CADES_C:
        DO(encodeCertificateRefs(m_AttrCertificateRefs));
        DO(encodeRevocationRefs(m_AttrRevocationRefs));
        break;
    case UapkiNS::SignatureFormat::CADES_X_LONG:
    case UapkiNS::SignatureFormat::CADES_A_V3:
        DO(encodeCertificateRefs(m_AttrCertificateRefs));
        DO(encodeRevocationRefs(m_AttrRevocationRefs));
        DO(encodeCertValues(m_AttrCertValues));
        DO(encodeRevocationValues(m_AttrRevocationValues));
        break;
    default:
        break;
    }

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

int SigningDoc::digestSignature (
        ByteArray** baHash
)
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

int SigningDoc::setSignature (
        const ByteArray* baSignValue
)
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
    return (signParams->signatureFormat != UapkiNS::SignatureFormat::RAW)
        ? builder.getEncoded() : baSignature;
}

int SigningDoc::encodeSignaturePolicy (
        const string& sigPolicyiId,
        UapkiNS::Attribute& attr
)
{
    int ret = RET_OK;

    DO(UapkiNS::AttributeHelper::encodeSignaturePolicy(sigPolicyiId, &attr.baValues));
    attr.type = string(OID_PKCS9_SIG_POLICY_ID);

cleanup:
    return ret;
}

int SigningDoc::encodeSigningCertificate (
        const UapkiNS::EssCertId& essCertId,
        UapkiNS::Attribute& attr
)
{
    int ret = RET_OK;

    DO(UapkiNS::AttributeHelper::encodeSigningCertificate(essCertId, &attr.baValues));
    attr.type = string(OID_PKCS9_SIGNING_CERTIFICATE_V2);

cleanup:
    return ret;
}

int SigningDoc::encodeCertValues (
        UapkiNS::Attribute& attr
)
{
    int ret = RET_OK;
    vector<const ByteArray*> cert_values;

    if (m_ChainCerts.empty()) return RET_UAPKI_INVALID_PARAMETER;

    for (const auto& it : m_ChainCerts) {
        cert_values.push_back(it->baEncoded);
    }

    attr.type = string(OID_PKCS9_CERT_VALUES);
    DO(UapkiNS::AttributeHelper::encodeCertValues(cert_values, &attr.baValues));
    DEBUG_OUTCON(puts("encodeCertValues:"); ba_print(stdout, attr.baValues));

cleanup:
    return ret;
}

int SigningDoc::encodeCertificateRefs (
        UapkiNS::Attribute& attr
)
{
    int ret = RET_OK;
    vector<UapkiNS::OtherCertId> other_certids;
    size_t idx = 0;

    if (m_ChainCerts.empty()) return RET_UAPKI_INVALID_PARAMETER;

    other_certids.resize(m_ChainCerts.size());
    for (const auto& it : m_ChainCerts) {
        UapkiNS::OtherCertId& dst_othercertid = other_certids[idx++];

        DO(::hash(signParams->hashDigest, it->baEncoded, &dst_othercertid.baHashValue));
        if (!dst_othercertid.hashAlgorithm.copy(signParams->aidDigest)) return RET_UAPKI_GENERAL_ERROR;

        DO(CerStore::issuerToGeneralNames(it->baIssuer, &dst_othercertid.issuerSerial.baIssuer));
        CHECK_NOT_NULL(dst_othercertid.issuerSerial.baSerialNumber = ba_copy_with_alloc(it->baSerialNumber, 0, 0));
    }

    attr.type = string(OID_PKCS9_CERTIFICATE_REFS);
    DO(UapkiNS::AttributeHelper::encodeCertificateRefs(other_certids, &attr.baValues));
    DEBUG_OUTCON(puts("encodeCertificateRefs:"); ba_print(stdout, attr.baValues));

cleanup:
    return ret;
}

int SigningDoc::encodeRevocationRefs (
        UapkiNS::Attribute& attr
)
{
    int ret = RET_OK;
    UapkiNS::AttributeHelper::RevocationRefsBuilder revocrefs_builder;
    size_t idx = 0;

    DO(revocrefs_builder.init());
    for (const auto& it : m_OcspRespItems) {
        DO(revocrefs_builder.addCrlOcspRef());
        UapkiNS::AttributeHelper::RevocationRefsBuilder::CrlOcspRef* crlocsp_ref = revocrefs_builder.getCrlOcspRef(idx);
        if (!crlocsp_ref) {
            SET_ERROR(RET_UAPKI_GENERAL_ERROR);
        }
        DO(crlocsp_ref->addOcspResponseId(it->baOcspIdentifier, it->baOcspRespHash));
        idx++;
    }
    DO(revocrefs_builder.encode());

    attr.type = string(OID_PKCS9_REVOCATION_REFS);
    attr.baValues = revocrefs_builder.getEncoded(true);
    DEBUG_OUTCON(puts("encodeRevocationRefs:"); ba_print(stdout, attr.baValues));

cleanup:
    return ret;
}

int SigningDoc::encodeRevocationValues (
        UapkiNS::Attribute& attr
)
{
    int ret = RET_OK;
    UapkiNS::AttributeHelper::RevocationValuesBuilder revocvalues_builder;

    DO(revocvalues_builder.init());
    for (const auto& it : m_OcspRespItems) {
        DO(revocvalues_builder.addOcspValue(it->baBasicOcspResponse));
        //            (const vector<const ByteArray*>&)m_OcspValues);
    }
    DO(revocvalues_builder.encode());

    attr.type = string(OID_PKCS9_REVOCATION_VALUES);
    attr.baValues = revocvalues_builder.getEncoded(true);
    DEBUG_OUTCON(puts("encodeRevocationValues:"); ba_print(stdout, attr.baValues));

cleanup:
    return ret;
}
