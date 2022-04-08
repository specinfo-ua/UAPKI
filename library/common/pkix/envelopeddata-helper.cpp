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

//  Last update: 2022-04-08


#include "envelopeddata-helper.h"
#include "api-json-internal.h"
#include "asn1-ba-utils.h"
#include "attribute-utils.h"
#include "oid-utils.h"
#include <stdio.h>


//#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


namespace UapkiNS {

namespace Pkcs7 {


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
    if (m_EnvData->unprotectedAttrs) {
        //TODO:
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
        DO(asn_encode_ba(get_SubjectKeyIdentifier_desc(), &originatorIdOrKey.choice.subjectKeyIdentifier, baEncodedOriginator));
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