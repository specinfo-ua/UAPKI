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

//  Last update: 2023-05-02


#include "signeddata-helper.h"
#include "api-json-internal.h"
#include "attribute-helper.h"
#include "oid-utils.h"
#include "uapki-ns-util.h"
#include <stdio.h>


#undef FILE_MARKER
#define FILE_MARKER "common/pkix/signeddata-helper.cpp"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


namespace UapkiNS {

namespace Pkcs7 {


SignedDataBuilder::SignedDataBuilder (void)
    : m_SignedData(nullptr)
    , m_BaEncoded(nullptr)
{
    DEBUG_OUTCON(puts("SignedDataBuilder::SignedDataBuilder()"));
}

SignedDataBuilder::~SignedDataBuilder (void)
{
    DEBUG_OUTCON(puts("SignedDataBuilder::~SignedDataBuilder()"));
    asn_free(get_SignedData_desc(), m_SignedData);
    for (auto& it : m_SignerInfos) {
        delete it;
    }
    ba_free(m_BaEncoded);
}

int SignedDataBuilder::init (void)
{
    m_SignedData = (SignedData_t*)calloc(1, sizeof(SignedData_t));
    return (m_SignedData) ? RET_OK : RET_UAPKI_GENERAL_ERROR;
}

int SignedDataBuilder::setVersion (
        const uint32_t version
)
{
    if (!m_SignedData) return RET_UAPKI_INVALID_PARAMETER;

    return asn_ulong2INTEGER(&m_SignedData->version, (unsigned long)version);
}

int SignedDataBuilder::setEncapContentInfo (
        const char* eContentType,
        const ByteArray* baEncapContent
)
{
    int ret = RET_OK;

    if (!m_SignedData || !eContentType) return RET_UAPKI_INVALID_PARAMETER;

    DO(asn_set_oid_from_text(eContentType, &m_SignedData->encapContentInfo.eContentType));
    if (baEncapContent) {
        ASN_ALLOC_TYPE(m_SignedData->encapContentInfo.eContent, OCTET_STRING_t);
        DO(asn_ba2OCTSTRING(baEncapContent, m_SignedData->encapContentInfo.eContent));
    }

cleanup:
    return ret;
}

int SignedDataBuilder::setEncapContentInfo (
        const string& eContentType,
        const ByteArray* baEncapContent
)
{
    if (eContentType.empty()) return RET_UAPKI_INVALID_PARAMETER;

    return setEncapContentInfo(eContentType.c_str(), baEncapContent);
}

int SignedDataBuilder::setEncapContentInfo (
        const EncapsulatedContentInfo& encapContentInfo
)
{
    if (encapContentInfo.contentType.empty()) return RET_UAPKI_INVALID_PARAMETER;

    return setEncapContentInfo(encapContentInfo.contentType.c_str(), encapContentInfo.baEncapContent);
}

int SignedDataBuilder::addCertificate (
        const ByteArray* baCertEncoded
)
{
    int ret = RET_OK;
    CertificateChoices_t* cert = nullptr;

    if (!m_SignedData || !baCertEncoded) return RET_UAPKI_INVALID_PARAMETER;

    if (!m_SignedData->certificates) {
        ASN_ALLOC_TYPE(m_SignedData->certificates, CertificateSet);
    }

    ASN_ALLOC_TYPE(cert, CertificateChoices_t);
    cert->present = CertificateChoices_PR_certificate;
    DO(asn_decode_ba(get_Certificate_desc(), &cert->choice.certificate, baCertEncoded));

    ASN_SET_ADD(m_SignedData->certificates, cert);
    cert = nullptr;

cleanup:
    asn_free(get_CertificateChoices_desc(), cert);
    return ret;
}

int SignedDataBuilder::addCrl (
        const ByteArray* baCrlEncoded
)
{
    int ret = RET_OK;
    RevocationInfoChoice_t* crl = nullptr;

    if (!m_SignedData || !baCrlEncoded) return RET_UAPKI_INVALID_PARAMETER;

    if (!m_SignedData->crls) {
        ASN_ALLOC_TYPE(m_SignedData->crls, RevocationInfoChoices);
    }

    ASN_ALLOC_TYPE(crl, RevocationInfoChoice_t);
    crl->present = RevocationInfoChoice_PR_crl;
    DO(asn_decode_ba(get_CertificateList_desc(), &crl->choice.crl, baCrlEncoded));

    ASN_SET_ADD(m_SignedData->crls, crl);
    crl = nullptr;

cleanup:
    asn_free(get_RevocationInfoChoice_desc(), crl);
    return ret;
}

int SignedDataBuilder::addSignerInfo (void)
{
    int ret = RET_OK;
    SignerInfo_t* signer_info = nullptr;

    if (!m_SignedData) return RET_UAPKI_INVALID_PARAMETER;

    ASN_ALLOC_TYPE(signer_info, SignerInfo_t);

    ASN_SET_ADD(&m_SignedData->signerInfos, signer_info);
    m_SignerInfos.push_back(new SignerInfo(signer_info));
    signer_info = nullptr;

cleanup:
    asn_free(get_SignerInfo_desc(), signer_info);
    return ret;
}

SignedDataBuilder::SignerInfo* SignedDataBuilder::getSignerInfo (
        const size_t index
) const
{
    if (index >= m_SignerInfos.size()) return nullptr;

    return m_SignerInfos[index];
}

int SignedDataBuilder::encode (
        const char* contentType
)
{
    int ret = RET_OK;
    ContentInfo_t* content_info = nullptr;

    if (!m_SignedData || !contentType) return RET_UAPKI_INVALID_PARAMETER;

    DO(collectDigestAlgorithms());

    ASN_ALLOC_TYPE(content_info, ContentInfo_t);
    DO(asn_set_oid_from_text(contentType, &content_info->contentType));
    DO(asn_set_any(get_SignedData_desc(), (void*)m_SignedData, &content_info->content));

    DO(asn_encode_ba(get_ContentInfo_desc(), content_info, &m_BaEncoded));

cleanup:
    asn_free(get_ContentInfo_desc(), content_info);
    return ret;
}

int SignedDataBuilder::encode (
        const string& contentType
)
{
    if (contentType.empty()) return RET_UAPKI_INVALID_PARAMETER;

    return encode(contentType.c_str());
}

ByteArray* SignedDataBuilder::getEncoded (
        const bool move
)
{
    ByteArray* rv_ba = m_BaEncoded;
    if (move) {
        m_BaEncoded = nullptr;
    }
    return rv_ba;
}

int SignedDataBuilder::collectDigestAlgorithms (void)
{
    vector<const ByteArray*> collected_refba;
    for (auto& it : m_SignerInfos) {
        bool is_present = false;
        const ByteArray* refba_encoded = it->getDigestAlgoEncoded();
        for (size_t i = 0; i < collected_refba.size(); i++) {
            is_present = (ba_cmp(refba_encoded, collected_refba[i]) == 0);
            if (is_present) break;
        }
        if (!is_present) {
            collected_refba.push_back(refba_encoded);
        }
    }

    int ret = RET_OK;
    AlgorithmIdentifier_t* aid_digestalgo = nullptr;

    for (auto& it : collected_refba) {
        CHECK_NOT_NULL(aid_digestalgo = (AlgorithmIdentifier_t*)asn_decode_ba_with_alloc(get_AlgorithmIdentifier_desc(), it));
        DO(ASN_SET_ADD(&m_SignedData->digestAlgorithms.list, aid_digestalgo));
        aid_digestalgo = nullptr;
    }

cleanup:
    asn_free(get_AlgorithmIdentifier_desc(), aid_digestalgo);
    return ret;
}


SignedDataBuilder::SignerInfo::SignerInfo (
        SignerInfo_t* iSignerInfo
)
    : m_SignerInfo(iSignerInfo)
    , m_SignedAttrs(nullptr)
    , m_UnsignedAttrs(nullptr)
    , m_SidType(SignerIdentifierType::UNDEFINED)
    , m_BaDigestAlgoEncoded(nullptr)
    , m_BaSignedAttrsEncoded(nullptr)
{
    DEBUG_OUTCON(puts("SignedDataBuilder::SignerInfo::SignerInfo()"));
}

SignedDataBuilder::SignerInfo::~SignerInfo (void)
{
    DEBUG_OUTCON(puts("SignedDataBuilder::SignerInfo::~SignerInfo()"));
    asn_free(get_Attributes_desc(), m_SignedAttrs);
    asn_free(get_Attributes_desc(), m_UnsignedAttrs);
    ba_free(m_BaDigestAlgoEncoded);
    ba_free(m_BaSignedAttrsEncoded);
}

int SignedDataBuilder::SignerInfo::setVersion (
        const uint32_t version
)
{
    return asn_ulong2INTEGER(&m_SignerInfo->version, (unsigned long)version);
}

int SignedDataBuilder::SignerInfo::setSid (
        const ByteArray* baSidEncoded
)
{
    int ret = RET_OK;
    uint8_t tag = 0x00;

    if (!baSidEncoded) return RET_UAPKI_INVALID_PARAMETER;

    DO(ba_get_byte(baSidEncoded, 0, &tag));
    if (tag == 0x30) m_SidType = SignerIdentifierType::ISSUER_AND_SN;
    else if (tag == 0x80) m_SidType = SignerIdentifierType::SUBJECT_KEYID;
    else {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

    DO(asn_decode_ba(get_ANY_desc(), &m_SignerInfo->sid, baSidEncoded));

cleanup:
    return ret;
}

int SignedDataBuilder::SignerInfo::setSid (
        const SignerIdentifierType sidType,
        const ByteArray* baData
)
{
    int ret = RET_OK;
    SmartBA sba_encoded;

    if (!baData) return RET_UAPKI_INVALID_PARAMETER;

    switch (sidType) {
    case SignerIdentifierType::ISSUER_AND_SN:
        DO(asn_decode_ba(get_ANY_desc(), &m_SignerInfo->sid, baData));
        break;
    case SignerIdentifierType::SUBJECT_KEYID:
        DO(keyIdToSid(baData, &sba_encoded));
        DO(asn_decode_ba(get_ANY_desc(), &m_SignerInfo->sid, sba_encoded.get()));
        break;
    default:
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        break;
    }

    m_SidType = sidType;

cleanup:
    return ret;
}

int SignedDataBuilder::SignerInfo::setDigestAlgorithm (
        const AlgorithmIdentifier& aidDigest
)
{
    int ret = RET_OK;

    if (!aidDigest.isPresent()) return RET_UAPKI_INVALID_PARAMETER;

    DO(Util::algorithmIdentifierToAsn1(m_SignerInfo->digestAlgorithm, aidDigest));

    DO(asn_encode_ba(get_AlgorithmIdentifier_desc(), &m_SignerInfo->digestAlgorithm, &m_BaDigestAlgoEncoded));

cleanup:
    return ret;
}

int SignedDataBuilder::SignerInfo::addSignedAttr (
        const char* type,
        const ByteArray* baValues
)
{
    int ret = RET_OK;

    if (!type || !oid_is_valid(type) || !baValues) return RET_UAPKI_INVALID_PARAMETER;

    if (!m_SignedAttrs) {
        ASN_ALLOC_TYPE(m_SignedAttrs, Attributes_t);
    }

    DO(Util::addToAttributes(m_SignedAttrs, type, baValues));

cleanup:
    return ret;
}

int SignedDataBuilder::SignerInfo::addSignedAttr (
        const Attribute& signedAttr
)
{
    return addSignedAttr(signedAttr.type.c_str(), signedAttr.baValues);
}

int SignedDataBuilder::SignerInfo::setSignedAttrs (
        const vector<Attribute>& signedAttrs
)
{
    int ret = RET_OK;

    if (!signedAttrs.empty()) {
        if (!m_SignedAttrs) {
            ASN_ALLOC_TYPE(m_SignedAttrs, Attributes_t);
        }

        for (const auto& it : signedAttrs) {
            if (!it.isPresent()) return RET_UAPKI_INVALID_PARAMETER;
            DO(Util::addToAttributes(m_SignedAttrs, it));
        }
    }

cleanup:
    return ret;
}

int SignedDataBuilder::SignerInfo::encodeSignedAttrs (void)
{
    if (!m_SignerInfo || !m_SignedAttrs) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;

    DO(asn_encode_ba(get_Attributes_desc(), m_SignedAttrs, &m_BaSignedAttrsEncoded));

    DO(ba_set_byte(m_BaSignedAttrsEncoded, 0, 0xA0));
    DO(asn_decode_ba(get_ANY_desc(), &m_SignerInfo->signedAttrs, m_BaSignedAttrsEncoded));
    DO(ba_set_byte(m_BaSignedAttrsEncoded, 0, 0x31));

cleanup:
    return ret;
}

int SignedDataBuilder::SignerInfo::setSignature (
        const AlgorithmIdentifier& aidSignature,
        const ByteArray* baSignValue
)
{
    int ret = RET_OK;

    if (!aidSignature.isPresent() || !baSignValue) return RET_UAPKI_INVALID_PARAMETER;

    //  =signatureAlgorithm=
    DO(Util::algorithmIdentifierToAsn1(m_SignerInfo->signatureAlgorithm, aidSignature));
    m_SignAlgo = aidSignature.algorithm;

    //  =signature=
    DO(asn_ba2OCTSTRING(baSignValue, &m_SignerInfo->signature));

cleanup:
    return ret;
}

int SignedDataBuilder::SignerInfo::addUnsignedAttr (
        const Attribute& unsignedAttr
)
{
    int ret = RET_OK;

    if (!unsignedAttr.isPresent()) return RET_UAPKI_INVALID_PARAMETER;

    if (!m_UnsignedAttrs) {
        ASN_ALLOC_TYPE(m_UnsignedAttrs, Attributes_t);
    }

    DO(Util::addToAttributes(m_UnsignedAttrs, unsignedAttr));

cleanup:
    return ret;
}

int SignedDataBuilder::SignerInfo::setUnsignedAttrs (
        const vector<Attribute>& unsignedAttrs
)
{
    int ret = RET_OK;

    if (!unsignedAttrs.empty()) {
        if (!m_UnsignedAttrs) {
            ASN_ALLOC_TYPE(m_UnsignedAttrs, Attributes_t);
        }

        for (const auto& it : unsignedAttrs) {
            if (!it.isPresent()) return RET_UAPKI_INVALID_PARAMETER;
            DO(Util::addToAttributes(m_UnsignedAttrs, it));
        }
    }

cleanup:
    return ret;
}

int SignedDataBuilder::SignerInfo::encodeUnsignedAttrs (void)
{
    if (!m_SignerInfo) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;

    if (m_UnsignedAttrs) {
        SmartBA sba_encoded;
        DO(asn_encode_ba(get_Attributes_desc(), m_UnsignedAttrs, &sba_encoded));
        DO(ba_set_byte(sba_encoded.get(), 0, 0xA1));
        CHECK_NOT_NULL(m_SignerInfo->unsignedAttrs = (ANY_t*)asn_decode_ba_with_alloc(get_ANY_desc(), sba_encoded.get()));
    }

cleanup:
    return ret;
}

int SignedDataBuilder::SignerInfo::addSignedAttrContentType (
        const char* contentType
)
{
    if (!contentType || !oid_is_valid(contentType)) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    SmartBA sba_encoded;

    DO(Util::encodeOid(OID_PKCS7_DATA, &sba_encoded));
    DO(addSignedAttr(OID_PKCS9_CONTENT_TYPE, sba_encoded.get()));

cleanup:
    return ret;
}

int SignedDataBuilder::SignerInfo::addSignedAttrContentType (
        const string& contentType
)
{
    return addSignedAttrContentType(contentType.c_str());
}

int SignedDataBuilder::SignerInfo::addSignedAttrMessageDigest (
        const ByteArray* baMessageDigest
)
{
    if (!baMessageDigest) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    Attribute attr = Attribute(string(OID_PKCS9_MESSAGE_DIGEST));

    DO(Util::encodeOctetString(baMessageDigest, &attr.baValues));
    DO(addSignedAttr(attr));

cleanup:
    return ret;
}

int SignedDataBuilder::SignerInfo::addSignedAttrSigningTime (
        const uint64_t signingTime
)
{
    int ret = RET_OK;
    Attribute attr = Attribute(string(OID_PKCS9_SIGNING_TIME));

    DO(Util::encodePkixTime(PKIXTime_PR_NOTHING, signingTime, &attr.baValues));
    DO(addSignedAttr(attr));

cleanup:
    return ret;
}


SignedDataParser::SignedDataParser (void)
    : m_SignedData(nullptr)
    , m_Version(0)
    , m_CountSignerInfos(0)
{
    DEBUG_OUTCON(puts("SignedDataParser::SignedDataParser()"));
}

SignedDataParser::~SignedDataParser (void)
{
    DEBUG_OUTCON(puts("SignedDataParser::~SignedDataParser()"));
    asn_free(get_SignedData_desc(), m_SignedData);
}

int SignedDataParser::parse (
        const ByteArray* baEncoded
)
{
    int ret = RET_OK;
    ContentInfo_t* cinfo = nullptr;
    long version = 0;

    CHECK_NOT_NULL(cinfo = (ContentInfo_t*)asn_decode_ba_with_alloc(get_ContentInfo_desc(), baEncoded));

    if (!OID_is_equal_oid(&cinfo->contentType, OID_PKCS7_SIGNED_DATA)) {
        SET_ERROR(RET_UAPKI_INVALID_CONTENT_INFO);
    }

    if (!cinfo->content.buf || !cinfo->content.size) {
        SET_ERROR(RET_UAPKI_INVALID_CONTENT_INFO);
    }

    CHECK_NOT_NULL(m_SignedData = (SignedData_t*)asn_any2type(&cinfo->content, get_SignedData_desc()));

    //  =version=
    DO(asn_INTEGER2long(&m_SignedData->version, &version));
    m_Version = (uint32_t)version;
    if ((version < 1) || (version > 5) || (version == 2)) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT_VERSION);
    }

    //  =digestAlgorithms= (may be empty)
    DO(decodeDigestAlgorithms(m_SignedData->digestAlgorithms, m_DigestAlgorithms));

    //  =encapContentInfo=
    DO(decodeEncapContentInfo(m_SignedData->encapContentInfo, m_EncapContentInfo));

    //  =certificates= (optional)
    if (m_SignedData->certificates && (m_SignedData->certificates->list.count > 0)) {
        const CertificateSet_t* sdata_certs = m_SignedData->certificates;
        m_Certs.resize((size_t)sdata_certs->list.count);
        for (size_t i = 0; i < m_Certs.size(); i++) {
            DO(asn_encode_ba(get_CertificateChoices_desc(), sdata_certs->list.array[i], &m_Certs[i]));
        }
    }

    //  =crls= (optional)
    if (m_SignedData->crls && (m_SignedData->crls->list.count > 0)) {
        const RevocationInfoChoices_t* sdata_crls = m_SignedData->crls;
        m_Crls.resize((size_t)sdata_crls->list.count);
        for (size_t i = 0; i < m_Crls.size(); i++) {
            DO(asn_encode_ba(get_RevocationInfoChoice_desc(), sdata_crls->list.array[i], &m_Crls[i]));
        }
    }

    //  =signerInfos= (may be empty)
    m_CountSignerInfos = static_cast<size_t>(m_SignedData->signerInfos.list.count);

cleanup:
    asn_free(get_ContentInfo_desc(), cinfo);
    return ret;
}

int SignedDataParser::parseSignerInfo (
        const size_t index,
        SignerInfo& signerInfo
)
{
    if (index >= m_CountSignerInfos) return RET_INDEX_OUT_OF_RANGE;

    return signerInfo.parse(m_SignedData->signerInfos.list.array[index]);
}

bool SignedDataParser::isContainDigestAlgorithm (
        const AlgorithmIdentifier& digestAlgorithm
)
{
    for (const auto& it : m_DigestAlgorithms) {
        if (digestAlgorithm.algorithm == it) return true;
    }
    return false;
}

int SignedDataParser::decodeDigestAlgorithms (
        const DigestAlgorithmIdentifiers_t& digestAlgorithms,
        vector<string>& decodedDigestAlgos
)
{
    int ret = RET_OK;
    char* s_dgstalgo = nullptr;

    for (int i = 0; i < digestAlgorithms.list.count; i++) {
        DO(asn_oid_to_text(&digestAlgorithms.list.array[i]->algorithm, &s_dgstalgo));
        decodedDigestAlgos.push_back(string(s_dgstalgo));
        s_dgstalgo = nullptr;
    }

cleanup:
    ::free(s_dgstalgo);
    return ret;
}

int SignedDataParser::decodeEncapContentInfo (
        const EncapsulatedContentInfo_t& encapContentInfo,
        EncapsulatedContentInfo& decodedEncapContentInfo
)
{
    int ret = RET_OK;
    char* s_contype = nullptr;

    DO(asn_oid_to_text(&encapContentInfo.eContentType, &s_contype));
    decodedEncapContentInfo.contentType = string(s_contype);
    s_contype = nullptr;

    if (encapContentInfo.eContent) {
        DO(asn_OCTSTRING2ba(encapContentInfo.eContent, &decodedEncapContentInfo.baEncapContent));
    }

cleanup:
    ::free(s_contype);
    return ret;
}


SignedDataParser::SignerInfo::SignerInfo (void)
    : m_SignerInfo(nullptr)
    , m_Version(0)
    , m_SidType(SignerIdentifierType::UNDEFINED)
{
    DEBUG_OUTCON(puts("SignedDataParser::SignerInfo::SignerInfo()"));
}

SignedDataParser::SignerInfo::~SignerInfo (void)
{
    DEBUG_OUTCON(puts("SignedDataParser::SignerInfo::~SignerInfo()"));
}

int SignedDataParser::SignerInfo::parse (const SignerInfo_t* signerInfo)
{
    int ret = RET_OK;
    long version = 0;
    Attributes_t* signed_attrs = nullptr;
    Attributes_t* unsigned_attrs = nullptr;

    if (!signerInfo) return RET_UAPKI_INVALID_PARAMETER;

    //  =version=
    DO(asn_INTEGER2long(&signerInfo->version, &version));
    m_Version = (uint32_t)version;
    if ((version != 1) && (version != 3)) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT_VERSION);
    }

    //  =sid=
    if (signerInfo->sid.size < 7) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }
    if (signerInfo->sid.buf[0] == 0x30) {
        //  It's issuerAndSerialNumber
        m_SidType = SignerIdentifierType::ISSUER_AND_SN;
    }
    else {
        //  It's subjectKeyIdentifier
        if ((signerInfo->sid.size < 18) || (signerInfo->sid.size > 66)) {
            SET_ERROR(RET_UAPKI_INVALID_KEY_ID);
        }
        m_SidType = SignerIdentifierType::SUBJECT_KEYID;
    }
    if (!m_SidEncoded.set(ba_alloc_from_uint8(signerInfo->sid.buf, (size_t)signerInfo->sid.size))) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    //  =digestAlgorithm=
    DO(Util::algorithmIdentifierFromAsn1(signerInfo->digestAlgorithm, m_DigestAlgorithm));

    //  =signedAttrs=
    if ((signerInfo->signedAttrs.size == 0) || (signerInfo->signedAttrs.buf[0] != 0xA0)) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }
    if (!m_SignedAttrsEncoded.set(ba_alloc_from_uint8(signerInfo->signedAttrs.buf, signerInfo->signedAttrs.size))) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }
    DO(ba_set_byte(m_SignedAttrsEncoded.get(), 0, 0x31));
    CHECK_NOT_NULL(signed_attrs = (Attributes_t*)asn_decode_ba_with_alloc(get_Attributes_desc(), m_SignedAttrsEncoded.get()));
    DO(decodeAttributes(*signed_attrs, m_SignedAttrs));
    DO(decodeMandatoryAttrs());

    //  =signatureAlgorithm=
    DO(Util::algorithmIdentifierFromAsn1(signerInfo->signatureAlgorithm, m_SignatureAlgorithm));

    //  =signature=
    DO(asn_OCTSTRING2ba(&signerInfo->signature, &m_Signature));

    //  =unsignedAttrs= (optional)
    if (signerInfo->unsignedAttrs) {
        SmartBA sba_encoded;
        if ((signerInfo->unsignedAttrs->size == 0) || (signerInfo->unsignedAttrs->buf[0] != 0xA1)) {
            SET_ERROR(RET_UAPKI_INVALID_STRUCT);
        }
        if (!sba_encoded.set(ba_alloc_from_uint8(signerInfo->unsignedAttrs->buf, signerInfo->unsignedAttrs->size))) {
            SET_ERROR(RET_UAPKI_GENERAL_ERROR);
        }
        DO(ba_set_byte(sba_encoded.get(), 0, 0x31));
        CHECK_NOT_NULL(unsigned_attrs = (Attributes_t*)asn_decode_ba_with_alloc(get_Attributes_desc(), sba_encoded.get()));
        DO(decodeAttributes(*unsigned_attrs, m_UnsignedAttrs));
    }

    m_SignerInfo = signerInfo;

cleanup:
    asn_free(get_Attributes_desc(), signed_attrs);
    asn_free(get_Attributes_desc(), unsigned_attrs);
    return ret;
}

int SignedDataParser::SignerInfo::decodeMandatoryAttrs (void)
{
    int ret = RET_OK;

    for (const auto& it : m_SignedAttrs) {
        if (it.type == string(OID_PKCS9_CONTENT_TYPE)) {
            DO(AttributeHelper::decodeContentType(it.baValues, m_MandatoryAttrs.contentType));
        }
        else if (it.type == string(OID_PKCS9_MESSAGE_DIGEST)) {
            DO(AttributeHelper::decodeMessageDigest(it.baValues, &m_MandatoryAttrs.messageDigest));
        }
    }
    if (m_MandatoryAttrs.contentType.empty() || m_MandatoryAttrs.messageDigest.empty()) {
        SET_ERROR(RET_UAPKI_INVALID_ATTRIBUTE);
    }

cleanup:
    return ret;
}

int SignedDataParser::SignerInfo::decodeAttributes (
        const Attributes_t& attrs,
        vector<Attribute>& decodedAttrs
)
{
    int ret = RET_OK;

    if (attrs.list.count > 0) {
        decodedAttrs.resize(attrs.list.count);
        for (int i = 0; i < attrs.list.count; i++) {
            DO(Util::attributeFromAsn1(*attrs.list.array[i], decodedAttrs[i]));
        }
    }

cleanup:
    return ret;
}

int keyIdToSid (
        const ByteArray* baKeyId,
        ByteArray** baSidEncoded
)
{
    int ret = RET_OK;
    SignerIdentifier_t* sid = nullptr;

    if ((ba_get_len(baKeyId) == 0) || !baSidEncoded) return RET_UAPKI_INVALID_PARAMETER;

    ASN_ALLOC_TYPE(sid, SignerIdentifier_t);
    sid->present = SignerIdentifier_PR_subjectKeyIdentifier;
    DO(asn_ba2OCTSTRING(baKeyId, &sid->choice.subjectKeyIdentifier));

    DO(asn_encode_ba(get_SignerIdentifier_desc(), sid, baSidEncoded));

cleanup:
    asn_free(get_SignerIdentifier_desc(), sid);
    return ret;
}


}   //  end namespace Pkcs7

}   //  end namespace UapkiNS
