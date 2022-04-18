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

//  Last update: 2022-04-18


#include "envelopeddata-helper.h"
#include "api-json-internal.h"
#include "asn1-ba-utils.h"
#include "attribute-utils.h"
#include "oid-utils.h"
#include <stdio.h>


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


namespace UapkiNS {

namespace Pkcs7 {

EnvelopedDataBuilder::EnvelopedDataBuilder (void)
{
    DEBUG_OUTCON(puts("EnvelopedDataBuilder::EnvelopedDataBuilder()"));
}

EnvelopedDataBuilder::~EnvelopedDataBuilder (void)
{
    DEBUG_OUTCON(puts("EnvelopedDataBuilder::~EnvelopedDataBuilder()"));
    asn_free(get_EnvelopedData_desc(), m_EnvData);
    for (size_t i = 0; i < m_RecipientInfos.size(); i++) {
        RecipientInfoBase* recip_info = m_RecipientInfos[i];
        switch (recip_info->getRecipientInfoType()) {
        case RecipientInfo_PR_kari:
            delete (KeyAgreeRecipientInfo*)recip_info;
            break;
        default:
            break;
        }
        recip_info = nullptr;
    }
    ba_free(m_BaEncoded);
}

int EnvelopedDataBuilder::init (const uint32_t version)
{
    if (version > 5) return RET_UAPKI_INVALID_PARAMETER;

    m_EnvData = (EnvelopedData_t*)calloc(1, sizeof(EnvelopedData_t));
    if (!m_EnvData) return RET_UAPKI_GENERAL_ERROR;

    const int ret = asn_ulong2INTEGER(&m_EnvData->version, (unsigned long)version);
    return ret;
}

int EnvelopedDataBuilder::addOriginatorCert (const ByteArray* baCertEncoded)
{
    int ret = RET_OK;
    CertificateChoices_t* cert = nullptr;

    if (!m_EnvData || !baCertEncoded) return RET_UAPKI_INVALID_PARAMETER;

    if (!m_EnvData->originatorInfo) {
        ASN_ALLOC_TYPE(m_EnvData->originatorInfo, OriginatorInfo_t);
    }
    if (!m_EnvData->originatorInfo->certs) {
        ASN_ALLOC_TYPE(m_EnvData->originatorInfo->certs, CertificateSet);
    }

    ASN_ALLOC_TYPE(cert, CertificateChoices_t);
    cert->present = CertificateChoices_PR_certificate;
    DO(asn_decode_ba(get_Certificate_desc(), &cert->choice.certificate, baCertEncoded));

    ASN_SET_ADD(m_EnvData->originatorInfo->certs, cert);
    cert = nullptr;

cleanup:
    asn_free(get_CertificateChoices_desc(), cert);
    return ret;
}

int EnvelopedDataBuilder::addOriginatorCrl (const ByteArray* baCrlEncoded)
{
    int ret = RET_OK;
    RevocationInfoChoice_t* crl = nullptr;

    if (!m_EnvData || !baCrlEncoded) return RET_UAPKI_INVALID_PARAMETER;

    if (!m_EnvData->originatorInfo) {
        ASN_ALLOC_TYPE(m_EnvData->originatorInfo, OriginatorInfo_t);
    }
    if (!m_EnvData->originatorInfo->crls) {
        ASN_ALLOC_TYPE(m_EnvData->originatorInfo->crls, RevocationInfoChoices);
    }

    ASN_ALLOC_TYPE(crl, RevocationInfoChoice_t);
    crl->present = RevocationInfoChoice_PR_crl;
    DO(asn_decode_ba(get_CertificateList_desc(), &crl->choice.crl, baCrlEncoded));

    ASN_SET_ADD(m_EnvData->originatorInfo->crls, crl);
    crl = nullptr;

cleanup:
    asn_free(get_RevocationInfoChoice_desc(), crl);
    return ret;
}

int EnvelopedDataBuilder::addRecipientInfo (const RecipientInfo_PR recipInfoType)
{
    int ret = RET_OK;
    RecipientInfo_t* recip_info = nullptr;
    RecipientInfoBase* recipinfo_item = nullptr;

    ASN_ALLOC_TYPE(recip_info, RecipientInfo_t);

    recip_info->present = recipInfoType;
    switch (recipInfoType) {
    case RecipientInfo_PR_kari:
        recipinfo_item = new KeyAgreeRecipientInfo(&recip_info->choice.kari);
        break;
    //case RecipientInfo_PR_ktri: case RecipientInfo_PR_kekri: case RecipientInfo_PR_pwri: case RecipientInfo_PR_ori:
    default:
        SET_ERROR(RET_UAPKI_NOT_SUPPORTED);
    }
    if (!recipinfo_item) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    ASN_SET_ADD(&m_EnvData->recipientInfos, recip_info);
    recip_info = nullptr;

    m_RecipientInfos.push_back(recipinfo_item);
    recipinfo_item = nullptr;

cleanup:
    asn_free(get_RecipientInfo_desc(), recip_info);
    if (recipinfo_item) {
        switch (recipInfoType) {
        case RecipientInfo_PR_kari:
            delete (KeyAgreeRecipientInfo*)recipinfo_item;
            break;
        default:
            //TODO:
            break;
        }
    }
    return ret;
}

EnvelopedDataBuilder::KeyAgreeRecipientInfo* EnvelopedDataBuilder::getKeyAgreeRecipientInfo (const size_t index) const
{
    if (index >= m_RecipientInfos.size()) return nullptr;

    if (m_RecipientInfos[index]->getRecipientInfoType() != RecipientInfo_PR_kari) return nullptr;

    return (KeyAgreeRecipientInfo*)m_RecipientInfos[index];
}

int EnvelopedDataBuilder::setEncryptedContentInfo (const char* contentType,
                    const UapkiNS::AlgorithmIdentifier& aidContentEncryptionAlgoId, const ByteArray* baEncryptedContent)
{
    int ret = RET_OK;

    if (!m_EnvData || !contentType) return RET_UAPKI_INVALID_PARAMETER;

    //  =contentType=
    DO(asn_set_oid_from_text(contentType, &m_EnvData->encryptedContentInfo.contentType));

    //  =contentEncryptionAlgorithm=
    DO(asn_set_oid_from_text(aidContentEncryptionAlgoId.algorithm.c_str(),
        &m_EnvData->encryptedContentInfo.contentEncryptionAlgorithm.algorithm));
    if (aidContentEncryptionAlgoId.baParameters) {
        CHECK_NOT_NULL(m_EnvData->encryptedContentInfo.contentEncryptionAlgorithm.parameters =
            (ANY_t*)asn_decode_ba_with_alloc(get_ANY_desc(), aidContentEncryptionAlgoId.baParameters));
    }

    //  =encryptedContent=
    if (baEncryptedContent) {
        ASN_ALLOC_TYPE(m_EnvData->encryptedContentInfo.encryptedContent, OCTET_STRING_t);
        DO(asn_ba2OCTSTRING(baEncryptedContent, m_EnvData->encryptedContentInfo.encryptedContent));
    }

cleanup:
    return ret;
}

int EnvelopedDataBuilder::setEncryptedContentInfo (const string& contentType,
                    const UapkiNS::AlgorithmIdentifier& aidContentEncryptionAlgoId, const ByteArray* baEncryptedContent)
{
    if (!m_EnvData || contentType.empty()) return RET_UAPKI_INVALID_PARAMETER;

    return setEncryptedContentInfo(contentType.c_str(), aidContentEncryptionAlgoId, baEncryptedContent);
}

int EnvelopedDataBuilder::addUnprotectedAttr (const UapkiNS::Attribute& unprotectedAttrs)
{
    int ret = RET_OK;

    if (!m_EnvData || !unprotectedAttrs.isPresent()) return RET_UAPKI_INVALID_PARAMETER;

    if (!m_EnvData->unprotectedAttrs) {
        ASN_ALLOC_TYPE(m_EnvData->unprotectedAttrs, Attributes_t);
    }

    DO(attrs_add_attribute(m_EnvData->unprotectedAttrs, unprotectedAttrs.type.c_str(), unprotectedAttrs.baValues));

cleanup:
    return ret;
}

int EnvelopedDataBuilder::encode (const char* contentType)
{
    int ret = RET_OK;
    ContentInfo_t* content_info = nullptr;

    if (!m_EnvData || !contentType) return RET_UAPKI_INVALID_PARAMETER;

    ASN_ALLOC_TYPE(content_info, ContentInfo_t);
    DO(asn_set_oid_from_text(contentType, &content_info->contentType));
    DO(asn_set_any(get_EnvelopedData_desc(), (void*)m_EnvData, &content_info->content));

    DO(asn_encode_ba(get_ContentInfo_desc(), content_info, &m_BaEncoded));

cleanup:
    asn_free(get_ContentInfo_desc(), content_info);
    return ret;
}

int EnvelopedDataBuilder::encode (const string& contentType)
{
    if (contentType.empty()) return RET_UAPKI_INVALID_PARAMETER;

    return encode(contentType.c_str());
}

ByteArray* EnvelopedDataBuilder::getEncoded (const bool move)
{
    ByteArray* rv_ba = m_BaEncoded;
    if (move) {
        m_BaEncoded = nullptr;
    }
    return rv_ba;
}



EnvelopedDataBuilder::RecipientInfoBase::RecipientInfoBase (const RecipientInfo_PR iRecipInfoType)
    : m_RecipInfoType(iRecipInfoType)
{
    DEBUG_OUTCON(printf("EnvelopedDataBuilder::RecipientInfoBase::RecipientInfoBase(%d)\n", m_RecipInfoType));
}

EnvelopedDataBuilder::RecipientInfoBase::~RecipientInfoBase (void)
{
    DEBUG_OUTCON(puts("EnvelopedDataBuilder::RecipientInfoBase::~RecipientInfoBase()"));
}



EnvelopedDataBuilder::KeyAgreeRecipientInfo::KeyAgreeRecipientInfo (KeyAgreeRecipientInfo_t* iRefKari)
    : RecipientInfoBase(RecipientInfo_PR_kari)
    , m_RefKari(iRefKari)
{
    DEBUG_OUTCON(puts("EnvelopedDataBuilder::KeyAgreeRecipientInfo::KeyAgreeRecipientInfo()"));
}

EnvelopedDataBuilder::KeyAgreeRecipientInfo::~KeyAgreeRecipientInfo (void)
{
    DEBUG_OUTCON(puts("EnvelopedDataBuilder::KeyAgreeRecipientInfo::KeyAgreeRecipientInfo()"));
}

int EnvelopedDataBuilder::KeyAgreeRecipientInfo::setVersion (const uint32_t version)
{
    if (!m_RefKari) return RET_UAPKI_INVALID_PARAMETER;

    return asn_ulong2INTEGER(&m_RefKari->version, (unsigned long)version);
}

int EnvelopedDataBuilder::KeyAgreeRecipientInfo::setOriginatorByIssuerAndSN (const ByteArray* baIssuerAndSN)
{
    if (!m_RefKari || !baIssuerAndSN) return RET_UAPKI_INVALID_PARAMETER;

    m_RefKari->originator.present = OriginatorIdentifierOrKey_PR_issuerAndSerialNumber;
    return asn_decode_ba(get_IssuerAndSerialNumber_desc(), &m_RefKari->originator.choice.issuerAndSerialNumber, baIssuerAndSN);
}

int EnvelopedDataBuilder::KeyAgreeRecipientInfo::setOriginatorBySubjectKeyId (const ByteArray* baSubjectKeyId)
{
    if (!m_RefKari || !baSubjectKeyId) return RET_UAPKI_INVALID_PARAMETER;

    m_RefKari->originator.present = OriginatorIdentifierOrKey_PR_subjectKeyIdentifier;
    return asn_ba2OCTSTRING(baSubjectKeyId, &m_RefKari->originator.choice.subjectKeyIdentifier);
}

int EnvelopedDataBuilder::KeyAgreeRecipientInfo::setOriginatorByPublicKey (const UapkiNS::AlgorithmIdentifier& aidOriginator, const ByteArray* baPublicKey)
{
    if (!m_RefKari || !aidOriginator.isPresent() || !baPublicKey) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    OriginatorPublicKey_t& origin_pubkey = m_RefKari->originator.choice.originatorKey;
    m_RefKari->originator.present = OriginatorIdentifierOrKey_PR_originatorKey;

    //  =algorithm(algorithm, parameters)=
    DO(asn_set_oid_from_text(aidOriginator.algorithm.c_str(), &origin_pubkey.algorithm.algorithm));
    if (aidOriginator.baParameters) {
        CHECK_NOT_NULL(origin_pubkey.algorithm.parameters =
            (ANY_t*)asn_decode_ba_with_alloc(get_ANY_desc(), aidOriginator.baParameters));
    }

    //  =publicKey=
    DO(asn_ba2BITSTRING(baPublicKey, &origin_pubkey.publicKey));

cleanup:
    return ret;
}

int EnvelopedDataBuilder::KeyAgreeRecipientInfo::setUkm (const ByteArray* baUkm)
{
    if (!m_RefKari) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;

    ASN_ALLOC_TYPE(m_RefKari->ukm, UserKeyingMaterial_t);

    DO(asn_ba2OCTSTRING(baUkm, m_RefKari->ukm));

cleanup:
    return ret;
}

int EnvelopedDataBuilder::KeyAgreeRecipientInfo::setKeyEncryptionAlgorithm (const UapkiNS::AlgorithmIdentifier& aidKeyEncryptionAlgoId)
{
    if (!m_RefKari || !aidKeyEncryptionAlgoId.isPresent()) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;

    //  =algorithm=
    DO(asn_set_oid_from_text(aidKeyEncryptionAlgoId.algorithm.c_str(), &m_RefKari->keyEncryptionAlgorithm.algorithm));

    //  =parameters=
    if (aidKeyEncryptionAlgoId.baParameters) {
        CHECK_NOT_NULL(m_RefKari->keyEncryptionAlgorithm.parameters =
            (ANY_t*)asn_decode_ba_with_alloc(get_ANY_desc(), aidKeyEncryptionAlgoId.baParameters));
    }

cleanup:
    return ret;
}

int EnvelopedDataBuilder::KeyAgreeRecipientInfo::addRecipientEncryptedKey (const RecipientEncryptedKey& recipEncryptedKey)
{
    if (!m_RefKari || !recipEncryptedKey.baRid || !recipEncryptedKey.baEncryptedKey) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    RecipientEncryptedKey_t* recip_encrkey = nullptr;

    ASN_ALLOC_TYPE(recip_encrkey, RecipientEncryptedKey_t);

    //  =rid=
    DO(asn_decode_ba(get_KeyAgreeRecipientIdentifier_desc(), &recip_encrkey->rid, recipEncryptedKey.baRid));

    //  =encryptedKey=
    DO(asn_ba2OCTSTRING(recipEncryptedKey.baEncryptedKey, &recip_encrkey->encryptedKey));

    ASN_SEQUENCE_ADD(&m_RefKari->recipientEncryptedKeys, recip_encrkey);
    recip_encrkey = nullptr;

cleanup:
    asn_free(get_RecipientEncryptedKey_desc(), recip_encrkey);
    return ret;
}

int EnvelopedDataBuilder::KeyAgreeRecipientInfo::addRecipientEncryptedKeyByIssuerAndSN (const ByteArray* baIssuerAndSN, const ByteArray* baEncryptedKey)
{
    if (!m_RefKari || !baIssuerAndSN || !baEncryptedKey) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    RecipientEncryptedKey_t* recip_encrkey = nullptr;

    ASN_ALLOC_TYPE(recip_encrkey, RecipientEncryptedKey_t);

    //  =rid.issuerAndSerialNumber=
    recip_encrkey->rid.present = KeyAgreeRecipientIdentifier_PR_issuerAndSerialNumber;
    DO(asn_decode_ba(get_IssuerAndSerialNumber_desc(), &recip_encrkey->rid.choice.issuerAndSerialNumber, baIssuerAndSN));

    //  =encryptedKey=
    DO(asn_ba2OCTSTRING(baEncryptedKey, &recip_encrkey->encryptedKey));

    ASN_SEQUENCE_ADD(&m_RefKari->recipientEncryptedKeys, recip_encrkey);
    recip_encrkey = nullptr;

cleanup:
    asn_free(get_RecipientEncryptedKey_desc(), recip_encrkey);
    return ret;
}

int EnvelopedDataBuilder::KeyAgreeRecipientInfo::addRecipientEncryptedKeyByRecipientKeyId (const ByteArray* baSubjectKeyId, const ByteArray* baEncryptedKey,
                    const std::string& date, const ByteArray* baOtherKeyAttribute)
{
    if (!m_RefKari || !baSubjectKeyId || !baEncryptedKey || (!date.empty() && (date.size() != 14))) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    RecipientEncryptedKey_t* recip_encrkey = nullptr;

    ASN_ALLOC_TYPE(recip_encrkey, RecipientEncryptedKey_t);

    recip_encrkey->rid.present = KeyAgreeRecipientIdentifier_PR_rKeyId;
    {   //  =rid.rKeyId=
        RecipientKeyIdentifier_t& recip_keyid = recip_encrkey->rid.choice.rKeyId;

        //  =subjectKeyIdentifier=
        DO(asn_ba2OCTSTRING(baSubjectKeyId, &recip_keyid.subjectKeyIdentifier));

        //  =date= (optional)
        if (!date.empty()) {
            ASN_ALLOC_TYPE(recip_keyid.date, GeneralizedTime_t);
            DO(asn_encodevalue_gentime(recip_keyid.date, date.c_str()));
        }

        //  =other= (optional)
        if (baOtherKeyAttribute) {
            CHECK_NOT_NULL(recip_keyid.other = (OtherKeyAttribute_t*)asn_decode_ba_with_alloc(get_OtherKeyAttribute_desc(), baOtherKeyAttribute));
        }
    }

    //  =encryptedKey=
    DO(asn_ba2OCTSTRING(baEncryptedKey, &recip_encrkey->encryptedKey));

    ASN_SEQUENCE_ADD(&m_RefKari->recipientEncryptedKeys, recip_encrkey);
    recip_encrkey = nullptr;

cleanup:
    asn_free(get_RecipientEncryptedKey_desc(), recip_encrkey);
    return ret;
}



EnvelopedDataParser::EnvelopedDataParser (void)
    : m_EnvData(nullptr)
    , m_Version(0)
{
    DEBUG_OUTCON(puts("EnvelopedDataParser::EnvelopedDataParser()"));
}

EnvelopedDataParser::~EnvelopedDataParser (void)
{
    DEBUG_OUTCON(puts("EnvelopedDataParser::~EnvelopedDataParser()"));
    asn_free(get_EnvelopedData_desc(), m_EnvData);
}

int EnvelopedDataParser::parse (const ByteArray* baEncoded)
{
    int ret = RET_OK;
    ContentInfo_t* cinfo = nullptr;
    long version = 0;

    CHECK_NOT_NULL(cinfo = (ContentInfo_t*)asn_decode_ba_with_alloc(get_ContentInfo_desc(), baEncoded));

    if (!OID_is_equal_oid(&cinfo->contentType, OID_PKCS7_ENVELOPED_DATA)) {
        SET_ERROR(RET_UAPKI_INVALID_CONTENT_INFO);
    }

    if (!cinfo->content.buf || !cinfo->content.size) {
        SET_ERROR(RET_UAPKI_INVALID_CONTENT_INFO);
    }

    CHECK_NOT_NULL(m_EnvData = (EnvelopedData_t*)asn_any2type(&cinfo->content, get_EnvelopedData_desc()));

    //  =version=
    DO(asn_INTEGER2long(&m_EnvData->version, &version));
    m_Version = (uint32_t)version;

    //  =originatorInfo= (optional)
    if (m_EnvData->originatorInfo) {
        DO(parseOriginatorInfo(*m_EnvData->originatorInfo, m_OriginatorInfo));
    }

    //  =recipientInfos=
    if (m_EnvData->recipientInfos.list.count > 0) {
        m_RecipientInfoTypes.resize((size_t)m_EnvData->recipientInfos.list.count);
        for (size_t i = 0; i < m_RecipientInfoTypes.size(); i++) {
            RecipientInfo_t* recip_info = m_EnvData->recipientInfos.list.array[i];
            m_RecipientInfoTypes[i] = recip_info->present;
        }
    }
    else {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

    //  =encryptedContentInfo=
    DO(parseEncryptedContentInfo(m_EnvData->encryptedContentInfo, m_EncryptedContentInfo));

    //  =unprotectedAttrs= (optional)
    if (m_EnvData->unprotectedAttrs && (m_EnvData->unprotectedAttrs->list.count > 0)) {
        DO(parseUnprotectedAttrs(m_EnvData->unprotectedAttrs, m_UnprotectedAttrs));
    }

cleanup:
    asn_free(get_ContentInfo_desc(), cinfo);
    return ret;
}

int EnvelopedDataParser::parseKeyAgreeRecipientInfo (const size_t index, KeyAgreeRecipientInfo& kari)
{
    if (index >= m_EnvData->recipientInfos.list.count) return RET_INDEX_OUT_OF_RANGE;

    const RecipientInfo_t* recip_info = m_EnvData->recipientInfos.list.array[index];
    if (recip_info->present != RecipientInfo_PR_kari) return RET_UAPKI_INVALID_STRUCT;

    return kari.parse(recip_info->choice.kari);
}

int EnvelopedDataParser::parseEncryptedContentInfo (const EncryptedContentInfo_t& encryptedContentInfo, EncryptedContentInfo& parsedECI)
{
    int ret = RET_OK;
    char* s_contype = nullptr;
    char* s_encalgo = nullptr;

    DO(asn_oid_to_text(&encryptedContentInfo.contentType, &s_contype));
    parsedECI.contentType = string(s_contype);

    DO(asn_oid_to_text(&encryptedContentInfo.contentEncryptionAlgorithm.algorithm, &s_encalgo));
    parsedECI.contentEncryptionAlgo.algorithm = string(s_encalgo);

    if (encryptedContentInfo.contentEncryptionAlgorithm.parameters) {
        const ANY_t* any_param = encryptedContentInfo.contentEncryptionAlgorithm.parameters;
        parsedECI.contentEncryptionAlgo.baParameters = ba_alloc_from_uint8(any_param->buf, any_param->size);
        if (!parsedECI.contentEncryptionAlgo.baParameters) {
            SET_ERROR(RET_UAPKI_GENERAL_ERROR);
        }
    }

    if (encryptedContentInfo.encryptedContent) {
        DO(asn_OCTSTRING2ba(encryptedContentInfo.encryptedContent, &parsedECI.baEncryptedContent));
    }

cleanup:
    ::free(s_contype);
    ::free(s_encalgo);
    return ret;
}

int EnvelopedDataParser::parseOriginatorInfo (const OriginatorInfo_t& originatorInfo, OriginatorInfo& parsedOriginatorInfo)
{
    int ret = RET_OK;

    //  =certs= (optional)
    if (originatorInfo.certs) {
        parsedOriginatorInfo.certs.resize((size_t)originatorInfo.certs->list.count);
        for (size_t i = 0; i < parsedOriginatorInfo.certs.size(); i++) {
            DO(asn_encode_ba(get_CertificateChoices_desc(), originatorInfo.certs->list.array[i], &parsedOriginatorInfo.certs[i]));
        }
    }

    //  =crls= (optional)
    if (originatorInfo.crls) {
        parsedOriginatorInfo.crls.resize((size_t)originatorInfo.crls->list.count);
        for (size_t i = 0; i < parsedOriginatorInfo.crls.size(); i++) {
            DO(asn_encode_ba(get_RevocationInfoChoices_desc(), originatorInfo.crls->list.array[i], &parsedOriginatorInfo.crls[i]));
        }
    }

cleanup:
    return ret;
}

int EnvelopedDataParser::parseUnprotectedAttrs (const Attributes_t* attrs, std::vector<UapkiNS::Attribute>& parsedAttrs)
{
    int ret = RET_OK;
    char* s_type = nullptr;

    if (attrs && (attrs->list.count > 0)) {
        parsedAttrs.resize(attrs->list.count);

        for (size_t i = 0; i < attrs->list.count; i++) {
            const Attribute_t* src_attr = attrs->list.array[i];
            UapkiNS::Attribute& dst_attr = parsedAttrs[i];

            //  =attrType=
            DO(asn_oid_to_text(&src_attr->type, &s_type));
            dst_attr.type = string(s_type);
            ::free(s_type);
            s_type = nullptr;

            //  =attrValues=
            if (src_attr->value.list.count > 0) {
                const AttributeValue_t* attr_value = src_attr->value.list.array[0];
                dst_attr.baValues = ba_alloc_from_uint8(attr_value->buf, attr_value->size);
            }
            else {
                dst_attr.baValues = ba_alloc();
            }
            if (!dst_attr.baValues) {
                SET_ERROR(RET_MEMORY_ALLOC_ERROR);
            }
        }
    }

cleanup:
    ::free(s_type);
    return ret;
}



EnvelopedDataParser::KeyAgreeRecipientIdentifier::KeyAgreeRecipientIdentifier (void)
    : m_KarId(nullptr)
{
    DEBUG_OUTCON(puts("EnvelopedDataParser::KeyAgreeRecipientIdentifier::KeyAgreeRecipientIdentifier()"));
}

EnvelopedDataParser::KeyAgreeRecipientIdentifier::~KeyAgreeRecipientIdentifier (void)
{
    DEBUG_OUTCON(puts("EnvelopedDataParser::KeyAgreeRecipientIdentifier::~KeyAgreeRecipientIdentifier()"));
    asn_free(get_KeyAgreeRecipientIdentifier_desc(), m_KarId);
}

KeyAgreeRecipientIdentifier_PR EnvelopedDataParser::KeyAgreeRecipientIdentifier::getType (void) const
{
    if (!m_KarId) return KeyAgreeRecipientIdentifier_PR_NOTHING;
    return m_KarId->present;
}

int EnvelopedDataParser::KeyAgreeRecipientIdentifier::parse (const ByteArray* baEncoded)
{
    m_KarId = (KeyAgreeRecipientIdentifier_t*)asn_decode_ba_with_alloc(get_KeyAgreeRecipientIdentifier_desc(), baEncoded);
    return (m_KarId) ? RET_OK : RET_INVALID_PARAM;
}

int EnvelopedDataParser::KeyAgreeRecipientIdentifier::toIssuerAndSN (ByteArray** baIssuerAndSN)
{
    if (m_KarId->present != KeyAgreeRecipientIdentifier_PR_issuerAndSerialNumber) return RET_UAPKI_INVALID_STRUCT;

    return asn_encode_ba(get_IssuerAndSerialNumber_desc(), &m_KarId->choice.issuerAndSerialNumber, baIssuerAndSN);
}

int EnvelopedDataParser::KeyAgreeRecipientIdentifier::toRecipientKeyId (ByteArray** baSubjectKeyId)
{
    if (m_KarId->present != KeyAgreeRecipientIdentifier_PR_rKeyId) return RET_UAPKI_INVALID_STRUCT;

    int ret = RET_OK;

    //  =subjectKeyIdentifier=
    DO(asn_OCTSTRING2ba(&m_KarId->choice.rKeyId.subjectKeyIdentifier, baSubjectKeyId));

    //  =date= (optional) - ignored
    //  =other= (optional) - ignored

cleanup:
    return ret;
}

int EnvelopedDataParser::KeyAgreeRecipientIdentifier::toRecipientKeyId (ByteArray** baSubjectKeyId, std::string& date, ByteArray** baOtherKeyAttribute)
{
    if (m_KarId->present != KeyAgreeRecipientIdentifier_PR_rKeyId) return RET_UAPKI_INVALID_STRUCT;

    int ret = RET_OK;
    const RecipientKeyIdentifier_t& recip_keyid = m_KarId->choice.rKeyId;
    char* s_date = nullptr;

    //  =subjectKeyIdentifier=
    DO(asn_OCTSTRING2ba(&recip_keyid.subjectKeyIdentifier, baSubjectKeyId));

    //  =date= (optional)
    if (recip_keyid.date) {//TODO: need check
        DO(asn_decodevalue_octetstring_to_stime(recip_keyid.date, &s_date));
        date = string(s_date);
    }

    //  =other= (optional)
    if (recip_keyid.other) {//TODO: need check
        DO(asn_encode_ba(get_OtherKeyAttribute_desc(), &recip_keyid.other, baOtherKeyAttribute));
    }

cleanup:
    ::free(s_date);
    return ret;
}



EnvelopedDataParser::KeyAgreeRecipientInfo::KeyAgreeRecipientInfo (void)
    : m_Version(0)
    , m_OriginatorType(OriginatorIdentifierOrKey_PR_NOTHING)
    , m_BaOriginator(nullptr)
    , m_BaUkm(nullptr)
{
    DEBUG_OUTCON(puts("EnvelopedDataParser::KeyAgreeRecipientInfo::KeyAgreeRecipientInfo()"));
}

EnvelopedDataParser::KeyAgreeRecipientInfo::~KeyAgreeRecipientInfo (void)
{
    DEBUG_OUTCON(puts("EnvelopedDataParser::KeyAgreeRecipientInfo::~KeyAgreeRecipientInfo()"));
    ba_free(m_BaOriginator);
    ba_free(m_BaUkm);
}

int EnvelopedDataParser::KeyAgreeRecipientInfo::parse (const KeyAgreeRecipientInfo_t& kari)
{
    int ret = RET_OK;
    char* s_encralgo = nullptr;
    long version = 0;

    //  =version=
    DO(asn_INTEGER2long(&kari.version, &version));
    m_Version = (uint32_t)version;
    if (m_Version != 3) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT_VERSION);
    }

    //  =originator=
    m_OriginatorType = kari.originator.present;
    DO(parseOriginator(kari.originator, &m_BaOriginator));

    //  =ukm= (optional)
    if (kari.ukm) {
        DO(asn_OCTSTRING2ba(kari.ukm, &m_BaUkm));
    }

    //  =keyEncryptionAlgorithm=
    DO(asn_oid_to_text(&kari.keyEncryptionAlgorithm.algorithm, &s_encralgo));
    m_KeyEncryptionAlgorithm.algorithm = string(s_encralgo);
    if (kari.keyEncryptionAlgorithm.parameters) {
        const ANY_t* any_param = kari.keyEncryptionAlgorithm.parameters;
        m_KeyEncryptionAlgorithm.baParameters = ba_alloc_from_uint8(any_param->buf, any_param->size);
        if (!m_KeyEncryptionAlgorithm.baParameters) {
            SET_ERROR(RET_UAPKI_GENERAL_ERROR);
        }
    }

    //  =recipientEncryptedKeys=
    m_RecipientEncryptedKeys.resize((size_t)kari.recipientEncryptedKeys.list.count);
    for (size_t i = 0; i < m_RecipientEncryptedKeys.size(); i++) {
        const RecipientEncryptedKey_t* recip_ekey = kari.recipientEncryptedKeys.list.array[i];
        DO(asn_encode_ba(get_KeyAgreeRecipientIdentifier_desc(), &recip_ekey->rid, &m_RecipientEncryptedKeys[i].baRid));
        DO(asn_OCTSTRING2ba(&recip_ekey->encryptedKey, &m_RecipientEncryptedKeys[i].baEncryptedKey));
    }

cleanup:
    ::free(s_encralgo);
    return ret;
}

int EnvelopedDataParser::KeyAgreeRecipientInfo::parseOriginator (const OriginatorIdentifierOrKey_t& originatorIdOrKey, ByteArray** baEncodedOriginator)
{
    int ret = RET_OK;

    switch (originatorIdOrKey.present) {
    case OriginatorIdentifierOrKey_PR_issuerAndSerialNumber:
        DO(asn_encode_ba(get_IssuerAndSerialNumber_desc(), &originatorIdOrKey.choice.issuerAndSerialNumber, baEncodedOriginator));
        break;
    case OriginatorIdentifierOrKey_PR_subjectKeyIdentifier:
        DO(asn_OCTSTRING2ba(&originatorIdOrKey.choice.subjectKeyIdentifier, baEncodedOriginator));
        break;
    case OriginatorIdentifierOrKey_PR_originatorKey:
        DO(asn_encode_ba(get_OriginatorPublicKey_desc(), &originatorIdOrKey.choice.originatorKey, baEncodedOriginator));
        break;
    default:
        break;
    }

cleanup:
    return ret;
}


}   //  end namespace Pkcs7

}   //  end namespace UapkiNS