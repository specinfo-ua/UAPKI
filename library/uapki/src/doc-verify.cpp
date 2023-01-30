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

#include "doc-verify.h"
#include "api-json-internal.h"
#include "attribute-helper.h"
#include "attribute-utils.h"
#include "global-objects.h"
#include "hash.h"
#include "oid-utils.h"
#include "signature-format.h"
#include "signeddata-helper.h"
#include "store-utils.h"
#include "time-utils.h"
#include "tsp-helper.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"
#include "verify-utils.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


namespace UapkiNS {

namespace Doc {

namespace Verify {


AttrTimeStamp::AttrTimeStamp (void)
    : msGenTime(0)
    , signerCertId(0)
    , statusDigest(SIGNATURE_VERIFY::STATUS::UNDEFINED)
    , statusSignature(SIGNATURE_VERIFY::STATUS::UNDEFINED)
{}

AttrTimeStamp::~AttrTimeStamp (void)
{}

bool AttrTimeStamp::isPresent (void) const
{
    return (!policy.empty() && !hashAlgo.empty() && (hashedMessage.size() > 0));
}

int AttrTimeStamp::verifyDigest (const ByteArray* baData)
{
    SmartBA sba_hash;

    const int ret = ::hash(hash_from_oid(hashAlgo.c_str()), baData, &sba_hash);
    if (ret != RET_OK) {
        statusDigest = SIGNATURE_VERIFY::STATUS::FAILED;
        return RET_OK;
    }

    statusDigest = (ba_cmp(hashedMessage.get(), sba_hash.get()) == 0)
        ? SIGNATURE_VERIFY::STATUS::VALID : SIGNATURE_VERIFY::STATUS::INVALID;
    return RET_OK;
}


VerifiedSignerInfo::VerifiedSignerInfo (void)
    : m_CerStore(nullptr)
    , m_CerStoreItem(nullptr)
    , m_StatusSignature(SIGNATURE_VERIFY::STATUS::UNDEFINED)
    , m_StatusMessageDigest(SIGNATURE_VERIFY::STATUS::UNDEFINED)
    , m_StatusEssCert(SIGNATURE_VERIFY::STATUS::UNDEFINED)
    , m_IsDigest(false)
    , m_SigningTime(0)
    , m_SignatureFormat(SignatureFormat::UNDEFINED)
{}

VerifiedSignerInfo::~VerifiedSignerInfo (void)
{
    m_CerStoreItem = nullptr;
}

int VerifiedSignerInfo::init (
        CerStore* iCerStore,
        const bool isDigest
)
{
    m_CerStore = iCerStore;
    m_IsDigest = isDigest;
    return (m_CerStore) ? RET_OK : RET_UAPKI_INVALID_PARAMETER;
}

int VerifiedSignerInfo::verifyArchiveTS (
        vector<const CerStore::Item*>& certs,
        vector<const CrlStore::Item*>& crls
)
{
    int ret = RET_OK;

    DO(m_ArchiveTsHelper.init((const AlgorithmIdentifier*)&m_SignerInfo.getDigestAlgorithm()));

    DO(m_ArchiveTsHelper.setHashContent(m_SignerInfo.getContentType(), m_SignerInfo.getMessageDigest()));

    DO(m_ArchiveTsHelper.setSignerInfo(m_SignerInfo.getAsn1Data()));

    for (const auto& it : certs) {
        DO(m_ArchiveTsHelper.addCertificate(it->baEncoded));
    }
    for (const auto& it : crls) {
        DO(m_ArchiveTsHelper.addCrl(it->baEncoded));
    }
    for (const auto& it : m_SignerInfo.getUnsignedAttrs()) {
        if (it.type != string(OID_ETSI_ARCHIVE_TIMESTAMP_V3)) {
            SmartBA sba_encoded;
            DO(AttributeHelper::encodeAttribute(it, &sba_encoded));
            DO(m_ArchiveTsHelper.addUnsignedAttr(sba_encoded.get()));
        }
    }

    DO(m_ArchiveTsHelper.calcHash());
    DEBUG_OUTCON(printf("VerifiedSignerInfo::verifyArchiveTS(), calculated hash-value, hex: ");  ba_print(stdout, m_ArchiveTsHelper.getHashValue()));

    m_ArchiveTS.statusDigest = (ba_cmp(m_ArchiveTS.hashedMessage.get(), m_ArchiveTsHelper.getHashValue()) == 0)
        ? SIGNATURE_VERIFY::STATUS::VALID : SIGNATURE_VERIFY::STATUS::INVALID;

cleanup:
    return ret;
}

int VerifiedSignerInfo::verifySignerInfo (
        const ByteArray* baContent
)
{
    int ret = RET_OK;
    SmartBA sba_calcdigest;

    switch (m_SignerInfo.getSidType()) {
    case Pkcs7::SignerIdentifierType::ISSUER_AND_SN:
        DO(m_CerStore->getCertBySID(m_SignerInfo.getSidEncoded(), &m_CerStoreItem));
        break;
    case Pkcs7::SignerIdentifierType::SUBJECT_KEYID:
        DO(m_CerStore->getCertByKeyId(m_SignerInfo.getSidEncoded(), &m_CerStoreItem));
        m_SignatureFormat = SignatureFormat::CMS_SID_KEYID;
        break;
    default:
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

    //  Verify signed attributes
    ret = verify_signature(
        m_SignerInfo.getSignatureAlgorithm().algorithm.c_str(),
        m_SignerInfo.getSignedAttrsEncoded(),
        false,
        m_CerStoreItem->baSPKI,
        m_SignerInfo.getSignature()
    );
    switch (ret) {
    case RET_OK:
        m_StatusSignature = SIGNATURE_VERIFY::STATUS::VALID;
        break;
    case RET_VERIFY_FAILED:
        m_StatusSignature = SIGNATURE_VERIFY::STATUS::INVALID;
        break;
    default:
        m_StatusSignature = SIGNATURE_VERIFY::STATUS::FAILED;
    }

    //  Validity messageDigest
    if (!m_IsDigest) {
        DO(::hash(hash_from_oid(
            m_SignerInfo.getDigestAlgorithm().algorithm.c_str()),
            baContent,
            &sba_calcdigest)
        );
        m_StatusMessageDigest = (ba_cmp(sba_calcdigest.get(), m_SignerInfo.getMessageDigest()) == 0)
            ? SIGNATURE_VERIFY::STATUS::VALID : SIGNATURE_VERIFY::STATUS::INVALID;
    }
    else {
        m_StatusMessageDigest = (ba_cmp(baContent, m_SignerInfo.getMessageDigest()) == 0)
            ? SIGNATURE_VERIFY::STATUS::VALID : SIGNATURE_VERIFY::STATUS::INVALID;
    }

    //  Decode attributes
    DO(decodeSignedAttrs(m_SignerInfo.getSignedAttrs()));
    DO(decodeUnsignedAttrs(m_SignerInfo.getUnsignedAttrs()));

    //  Process attributes
    if (!m_EssCerts.empty()) {
        DO(verifySigningCertificateV2());
        if (m_SignatureFormat != SignatureFormat::CMS_SID_KEYID) {
            m_SignatureFormat = SignatureFormat::CADES_BES;
        }
    }
    if (m_ContentTS.isPresent()) {
        DO(m_ContentTS.verifyDigest(baContent));
    }
    if (m_SignatureTS.isPresent()) {
        DO(m_SignatureTS.verifyDigest(m_SignerInfo.getSignature()));
    }

    //  Determine signatureFormat for CAdES
    if (m_SignatureFormat == SignatureFormat::CADES_BES) {
        if (m_ContentTS.isPresent() && m_SignatureTS.isPresent()) {
            m_SignatureFormat = SignatureFormat::CADES_T;

            bool detect_certrefs = false, detect_revocrefs = false;
            bool detect_certvals = false, detect_revocvals = false;
            bool detect_atsv3 = false;
            for (const auto& it : m_SignerInfo.getUnsignedAttrs()) {
                if (it.type == string(OID_PKCS9_CERTIFICATE_REFS)) detect_certrefs = true;
                else if (it.type == string(OID_PKCS9_REVOCATION_REFS)) detect_revocrefs = true;
                else if (it.type == string(OID_PKCS9_CERT_VALUES)) detect_certvals = true;
                else if (it.type == string(OID_PKCS9_REVOCATION_VALUES)) detect_revocvals = true;
                else if (it.type == string(OID_ETSI_ARCHIVE_TIMESTAMP_V3)) detect_atsv3 = true;
            }

            if (detect_certrefs && detect_revocrefs) {
                m_SignatureFormat = SignatureFormat::CADES_C;
            }

            if ((m_SignatureFormat == SignatureFormat::CADES_C) && detect_certvals && detect_revocvals) {
                m_SignatureFormat = SignatureFormat::CADES_XL;
            }

            if ((m_SignatureFormat == SignatureFormat::CADES_XL) && detect_atsv3) {
                m_SignatureFormat = SignatureFormat::CADES_A;
            }
        }
    }

cleanup:
    return ret;
}

int VerifiedSignerInfo::decodeSignedAttrs (
        const vector<Attribute>& signedAattrs
)
{
    int ret = RET_OK;

    m_StatusEssCert = SIGNATURE_VERIFY::STATUS::NOT_PRESENT;
    for (const auto& it : signedAattrs) {
        if (it.type == string(OID_PKCS9_SIGNING_TIME)) {
            DO(AttributeHelper::decodeSigningTime(it.baValues, m_SigningTime));
        }
        else if (it.type == string(OID_PKCS9_SIG_POLICY_ID)) {
            DO(AttributeHelper::decodeSignaturePolicy(it.baValues, m_SigPolicyId));
        }
        else if (it.type == string(OID_PKCS9_CONTENT_TIMESTAMP)) {
            DO(decodeAttrTimestamp(it.baValues, m_ContentTS));
        }
        else if (it.type == string(OID_PKCS9_SIGNING_CERTIFICATE_V2)) {
            DO(AttributeHelper::decodeSigningCertificate(it.baValues, m_EssCerts));
        }
    }

cleanup:
    return ret;
}

int VerifiedSignerInfo::decodeUnsignedAttrs (
        const vector<Attribute>& unsignedAttrs
)
{
    int ret = RET_OK;

    for (const auto& it : unsignedAttrs) {
        if (it.type == string(OID_PKCS9_TIMESTAMP_TOKEN)) {
            DO(decodeAttrTimestamp(it.baValues, m_SignatureTS));
        }
        else if (it.type == string(OID_ETSI_ARCHIVE_TIMESTAMP_V3)) {
            DO(decodeAttrTimestamp(it.baValues, m_ArchiveTS));
        }
    }

cleanup:
    return ret;
}

int VerifiedSignerInfo::verifySigningCertificateV2 (void)
{
    if (m_EssCerts.empty()) return RET_OK;

    //  Process simple case: present only the one ESSCertIDv2
    int ret = RET_OK;
    SmartBA sba_certhash;

    const EssCertId& ess_certid = m_EssCerts[0];
    const HashAlg hash_algo = hash_from_oid(ess_certid.hashAlgorithm.algorithm.c_str());
    if (hash_algo == HASH_ALG_UNDEFINED) {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }

    DO(::hash(hash_algo, m_CerStoreItem->baEncoded, &sba_certhash));
    m_StatusEssCert = (ba_cmp(sba_certhash.get(), ess_certid.baHashValue) == 0)
        ? SIGNATURE_VERIFY::STATUS::VALID : SIGNATURE_VERIFY::STATUS::INVALID;

cleanup:
    return ret;
}


int decodeAttrTimestamp (
        const ByteArray* baValues,
        AttrTimeStamp& attrTS
)
{
    int ret = RET_OK;
    Tsp::TsTokenParser tstoken_parser;

    DO(tstoken_parser.parse(baValues));
    attrTS.policy = tstoken_parser.getPolicyId();
    attrTS.hashAlgo = tstoken_parser.getHashAlgo();
    (void)attrTS.hashedMessage.set(tstoken_parser.getHashedMessage(true));
    attrTS.msGenTime = tstoken_parser.getGenTime();

    ret = verifySignedData(
        *get_cerstore(),
        tstoken_parser.getSignedDataParser(),
        &attrTS.signerCertId
    );
    switch (ret) {
    case RET_OK:
        attrTS.statusSignature = SIGNATURE_VERIFY::STATUS::VALID;
        break;
    case RET_VERIFY_FAILED:
        attrTS.statusSignature = SIGNATURE_VERIFY::STATUS::INVALID;
        break;
    case RET_UAPKI_CERT_NOT_FOUND:
        attrTS.statusSignature = SIGNATURE_VERIFY::STATUS::NOT_PRESENT;
        break;
    default:
        attrTS.statusSignature = SIGNATURE_VERIFY::STATUS::FAILED;
    }

cleanup:
    return ret;
}   //  decodeAttrTimestamp

int verifySignedData (
        CerStore& cerStore,
        Pkcs7::SignedDataParser& sdataParser,
        CerStore::Item** cerSigner
)
{
    int ret = RET_OK;
    Pkcs7::SignedDataParser::SignerInfo signer_info;

    if (sdataParser.getCountSignerInfos() == 0) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

    for (auto& it : sdataParser.getCerts()) {
        bool is_unique;
        DO(cerStore.addCert(it, false, false, false, is_unique, nullptr));
        it = nullptr;
    }

    DO(sdataParser.parseSignerInfo(0, signer_info));
    if (!sdataParser.isContainDigestAlgorithm(signer_info.getDigestAlgorithm())) {
        SET_ERROR(RET_UAPKI_NOT_SUPPORTED);
    }

    switch (signer_info.getSidType()) {
    case Pkcs7::SignerIdentifierType::ISSUER_AND_SN:
        DO(cerStore.getCertBySID(signer_info.getSidEncoded(), cerSigner));
        break;
    case Pkcs7::SignerIdentifierType::SUBJECT_KEYID:
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
}   //  verifySignedData


}   //  end namespace Verify

}   //  end namespace Doc

}   //  end namespace UapkiNS
