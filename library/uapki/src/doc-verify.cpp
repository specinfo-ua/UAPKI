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


struct CollectVerifyStatus {
    bool    values[6];

    CollectVerifyStatus (void) {
        values[0] = values[1] = values[2] = values[3] = values[4] = values[5] = false;
    }

    bool isDeterminate (void) {
        return (
            !values[(uint32_t)VerifyStatus::UNDEFINED] &&
            !values[(uint32_t)VerifyStatus::NOT_PRESENT] &&
            !values[(uint32_t)VerifyStatus::FAILED] &&
            !values[(uint32_t)VerifyStatus::INVALID] &&
            values[(uint32_t)VerifyStatus::INDETERMINATE]
            );
    }

    bool isValid (void) {
        return (
            !values[(uint32_t)VerifyStatus::UNDEFINED] &&
            !values[(uint32_t)VerifyStatus::NOT_PRESENT] &&
            !values[(uint32_t)VerifyStatus::INDETERMINATE] &&
            !values[(uint32_t)VerifyStatus::FAILED] &&
            !values[(uint32_t)VerifyStatus::INVALID] &&
            values[(uint32_t)VerifyStatus::VALID]
            );
    }

    void set (const VerifyStatus status) {
        values[(uint32_t)status] = true;
    }
};  //  end class CollectVerifyStatus


AttrTimeStamp::AttrTimeStamp (void)
    : msGenTime(0)
    , csiSigner(nullptr)
    , statusDigest(DigestVerifyStatus::UNDEFINED)
    , statusSignature(SignatureVerifyStatus::UNDEFINED)
{}

AttrTimeStamp::~AttrTimeStamp (void)
{}

bool AttrTimeStamp::isPresent (void) const
{
    return (
        !policy.empty() && 
        !hashAlgo.empty() &&
        (hashedMessage.size() > 0)
    );
}

int AttrTimeStamp::parse (
        const ByteArray* baEncoded
)
{
    const int ret = tsTokenParser.parse(baEncoded);
    if (ret != RET_OK) return ret;

    policy = tsTokenParser.getPolicyId();
    hashAlgo = tsTokenParser.getHashAlgo();
    (void)hashedMessage.set(tsTokenParser.getHashedMessage(true));
    msGenTime = tsTokenParser.getGenTime();
    return RET_OK;
}

int AttrTimeStamp::verifyDigest (
        const ByteArray* baData,
        const bool isDigest
)
{
    if (!baData) {
        statusDigest = DigestVerifyStatus::INDETERMINATE;
        return RET_OK;
    }

    if (!isDigest) {
        const HashAlg hash_alg = hash_from_oid(hashAlgo.c_str());
        if (hash_alg == HASH_ALG_UNDEFINED) {
            statusDigest = DigestVerifyStatus::FAILED;
            return RET_UAPKI_UNSUPPORTED_ALG;
        }

        SmartBA sba_hash;
        const int ret = ::hash(hash_alg, baData, &sba_hash);
        if (ret != RET_OK) {
            statusDigest = DigestVerifyStatus::FAILED;
            return ret;
        }

        statusDigest = (ba_cmp(hashedMessage.get(), sba_hash.get()) == 0)
            ? DigestVerifyStatus::VALID : DigestVerifyStatus::INVALID;
    }
    else {
        statusDigest = (ba_cmp(hashedMessage.get(), baData) == 0)
            ? DigestVerifyStatus::VALID : DigestVerifyStatus::INVALID;
    }

    return (statusDigest == DigestVerifyStatus::VALID) ? RET_OK : RET_UAPKI_INVALID_DIGEST;
}


CadesXlInfo::CadesXlInfo (void)
    : isPresentCertRefs(false)
    , isPresentRevocRefs(false)
    , isPresentCertVals(false)
    , isPresentRevocVals(false)
    , statusCertRefs(DigestVerifyStatus::UNDEFINED)
{
}

int CadesXlInfo::parseCertValues (
        const ByteArray* baValues
)
{
    const int ret = AttributeHelper::decodeCertValues(baValues, certValues);
    isPresentCertVals = (ret == RET_OK);
    return ret;
}

int CadesXlInfo::parseCertificateRefs (
        const ByteArray* baValues
)
{
    const int ret = AttributeHelper::decodeCertificateRefs(baValues, certRefs);
    isPresentCertRefs = (ret == RET_OK);
    statusCertRefs = (isPresentCertRefs) ? DataVerifyStatus::INDETERMINATE : DataVerifyStatus::FAILED;
    return ret;
}

int CadesXlInfo::parseRevocationRefs (
        const ByteArray* baValues
)
{
    const int ret = revocationRefsParser.parse(baValues);
    isPresentRevocRefs = (ret == RET_OK);
    return ret;
}

int CadesXlInfo::parseRevocationValues (
        const ByteArray* baValues
)
{
    const int ret = revocationValuesParser.parse(baValues);
    isPresentRevocVals = (ret == RET_OK);
    return ret;
}

int CadesXlInfo::verifyCertRefs (
        CerStore* cerStore
)
{
    if (!isPresentCertRefs) return RET_OK;

    if (isPresentCertVals) {
        if (certValues.size() != certRefs.size()) {
            statusCertRefs = DigestVerifyStatus::INVALID;
            return RET_UAPKI_INVALID_COUNT_ITEMS;
        }
    }

    statusesCertRefs.resize(certRefs.size());
    for (auto& it : statusesCertRefs) {
        it = DigestVerifyStatus::UNDEFINED;
    }

    size_t cnt_passed = 0, idx = 0;
    for (const auto& it : certRefs) {
        DigestVerifyStatus& status = statusesCertRefs[idx];

        const HashAlg hash_alg = hash_from_oid(it.hashAlgorithm.algorithm.c_str());
        if (hash_alg == HASH_ALG_UNDEFINED) {
            statusCertRefs = status = DigestVerifyStatus::FAILED;
            return RET_UAPKI_UNSUPPORTED_ALG;
        }

        int ret = RET_OK;
        const ByteArray* refba_cert = nullptr;
        CerStore::Item* cer_item = nullptr;
        if (isPresentCertVals) {
            refba_cert = certValues[idx];
        }
        else {
            UapkiNS::SmartBA sba_issuer;
            ret = CerStore::issuerFromGeneralNames(it.issuerSerial.baIssuer, &sba_issuer);
            if (ret != RET_OK) {
                statusCertRefs = status = DigestVerifyStatus::FAILED;
                return ret;
            }

            ret = cerStore->getCertByIssuerAndSn(sba_issuer.get(), it.issuerSerial.baSerialNumber, &cer_item);
            if (ret == RET_OK) {
                refba_cert = cer_item->baEncoded;
            }
            else if (ret == RET_UAPKI_CERT_NOT_FOUND) {
                ByteArray* ba_iasn = nullptr;
                ret = CerStore::encodeIssuerAndSN(sba_issuer.get(), it.issuerSerial.baSerialNumber, &ba_iasn);
                if (ret != RET_OK) {
                    statusCertRefs = status = DigestVerifyStatus::FAILED;
                    return ret;
                }

                status = DigestVerifyStatus::INDETERMINATE;
                expectedCertsByIssuerAndSN.push_back(ba_iasn);
                continue;
            }
            else {
                statusCertRefs = status = DigestVerifyStatus::FAILED;
                return ret;
            }
        }

        UapkiNS::SmartBA sba_hash;
        ret = ::hash(hash_alg, refba_cert, &sba_hash);
        if (ret != RET_OK) {
            statusCertRefs = status = DigestVerifyStatus::FAILED;
            return ret;
        }

        if (ba_cmp(it.baHashValue, sba_hash.get()) == 0) {
            status = DigestVerifyStatus::VALID;
            cnt_passed++;
        }
        else {
            statusCertRefs = status = DigestVerifyStatus::INVALID;
        }

        idx++;
    }

    if (certRefs.size() == cnt_passed) {
        statusCertRefs = DigestVerifyStatus::VALID;
    }
    return RET_OK;
}


CertChainItem::CertChainItem (
        const CertEntity iCertEntity,
        CerStore::Item* iCsiSubject
)
    : m_CertEntity(iCertEntity)
    , m_CsiSubject(iCsiSubject)
    , m_DataSource(DataSource::UNDEFINED)
    , m_CsiIssuer(nullptr)
    , m_IsExpired(true)
    , m_IsSelfSigned(false)
    , m_CertStatus(UapkiNS::CertStatus::UNDEFINED)
{
}

CertChainItem::~CertChainItem (void)
{
}

int CertChainItem::checkValidityTime (
        const uint64_t validateTime
)
{
    const int ret = m_CsiSubject->checkValidity(validateTime);
    m_IsExpired = (ret != RET_OK);
    return ret;
}

int CertChainItem::decodeName (void)
{
    return CerStoreUtils::rdnameFromName(
        m_CsiSubject->cert->tbsCertificate.subject,
        OID_X520_CommonName,
        m_CommonName
    );
}

void CertChainItem::setDataSource (
        const DataSource dataSource
)
{
    m_DataSource = dataSource;
}

void CertChainItem::setCertStatus (
        const UapkiNS::CertStatus certStatus
)
{
    m_CertStatus = certStatus;
}

void CertChainItem::setIssuerAndVerify (
        CerStore::Item* csiIssuer
)
{
    if (csiIssuer) {
        m_CsiIssuer = csiIssuer;
    }
    else {
        m_CertEntity = CertEntity::ROOT;
        m_CsiIssuer = m_CsiSubject;
        m_IsSelfSigned = true;
        m_ResultValidationByCrl.isUsed = false;
        m_ResultValidationByOcsp.isUsed = false;
    }
    (void)m_CsiSubject->verify(m_CsiIssuer);
}


ExpectedCertItem::ExpectedCertItem (
        const CertEntity iCertEntity
)
    : m_CertEntity(iCertEntity)
    , m_IdType(IdType::UNDEFINED)
{
}

int ExpectedCertItem::setResponderId (
        const bool isKeyId,
        const ByteArray* baResponderId
)
{
    if (!baResponderId) return RET_UAPKI_INVALID_PARAMETER;

    SmartBA& rsba_dst = (isKeyId) ? m_KeyId : m_Name;
    if (!rsba_dst.set(ba_copy_with_alloc(baResponderId, 0, 0))) return RET_UAPKI_GENERAL_ERROR;

    m_IdType = IdType::ORS_IDTYPE;
    return RET_OK;
}

int ExpectedCertItem::setSignerIdentifier (
        const ByteArray* baKeyIdOrSN,
        const ByteArray* baName
)
{
    if (!baKeyIdOrSN) return RET_UAPKI_INVALID_PARAMETER;

    if (!baName) {
        if (!m_KeyId.set(ba_copy_with_alloc(baKeyIdOrSN, 0, 0))) return RET_UAPKI_GENERAL_ERROR;
    }
    else {
        if (
            !m_SerialNumber.set(ba_copy_with_alloc(baKeyIdOrSN, 0, 0)) ||
            !m_Name.set(ba_copy_with_alloc(baName, 0, 0))
        ) return RET_UAPKI_GENERAL_ERROR;
    }

    m_IdType = IdType::CER_IDTYPE;
    return RET_OK;
}


ExpectedCrlItem::ExpectedCrlItem (void)
    : m_ThisUpdate(0)
    , m_NextUpdate(0)
{
}

int ExpectedCrlItem::set (
        const CerStore::Item* cerSubject,
        const CrlStore::Item* crlFull
)
{
    if (!cerSubject) return RET_UAPKI_INVALID_PARAMETER;

    if (!m_AuthorityKeyId.set(ba_copy_with_alloc(cerSubject->baAuthorityKeyId, 0, 0))) return RET_UAPKI_GENERAL_ERROR;
    if (!m_Name.set(ba_copy_with_alloc(cerSubject->baIssuer, 0, 0))) return RET_UAPKI_GENERAL_ERROR;

    vector<string> uris;
    if (!crlFull) {
        (void)cerSubject->getCrlUris(true, uris);
    }
    else {
        (void)cerSubject->getCrlUris(false, uris);
        m_ThisUpdate = crlFull->thisUpdate;
        m_NextUpdate = crlFull->nextUpdate;
        if (!m_BaCrlNumber.set(ba_copy_with_alloc(crlFull->baCrlNumber, 0, 0))) return RET_UAPKI_GENERAL_ERROR;
    }
    for (const auto& it : uris) {
        m_Url += it + ";";
    }
    if (!m_Url.empty()) {
        m_Url.pop_back();
    }

    return RET_OK;
}


VerifiedSignerInfo::VerifiedSignerInfo (void)
    : m_CerStore(nullptr)
    , m_IsDigest(false)
    , m_LastError(RET_OK)
    , m_CsiSigner(nullptr)
    , m_ValidationStatus(ValidationStatus::UNDEFINED)
    , m_StatusSignature(SignatureVerifyStatus::UNDEFINED)
    , m_StatusMessageDigest(DigestVerifyStatus::UNDEFINED)
    , m_StatusEssCert(DataVerifyStatus::UNDEFINED)
    , m_SigningTime(0)
    , m_SignatureFormat(SignatureFormat::UNDEFINED)
    , m_IsValidSignatures(false)
    , m_IsValidDigests(false)
    , m_BestSignatureTime(0)
{}

VerifiedSignerInfo::~VerifiedSignerInfo (void)
{
    m_CsiSigner = nullptr;
    for (auto& it : m_CertChainItems) {
        delete it;
    }
    for (auto& it : m_ExpectedCertItems) {
        delete it;
    }
    for (auto& it : m_ExpectedCrlItems) {
        delete it;
    }
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

int VerifiedSignerInfo::addCertChainItem (
        const CertEntity certEntity,
        CerStore::Item* cerStoreItem,
        CertChainItem** certChainItem
)
{
    bool is_newitem;
    return addCertChainItem(certEntity, cerStoreItem, certChainItem, is_newitem);
}

int VerifiedSignerInfo::addCertChainItem (
        const CertEntity certEntity,
        CerStore::Item* cerStoreItem,
        CertChainItem** certChainItem,
        bool& isNewItem
)
{
    for (const auto& it : m_CertChainItems) {
        if (ba_cmp(cerStoreItem->baCertId, it->getSubjectCertId()) == 0) {
            *certChainItem = it;
            isNewItem = false;
            return RET_OK;
        }
    }

    CertChainItem* certchain_item = new CertChainItem(certEntity, cerStoreItem);
    *certChainItem = certchain_item;
    if (!certchain_item) return RET_UAPKI_GENERAL_ERROR;

    isNewItem = true;
    m_CertChainItems.push_back(certchain_item);
    return certchain_item->decodeName();
}

int VerifiedSignerInfo::addCrlCertsToChain (void)
{
    vector<CerStore::Item*> crl_certs;
    for (const auto& it : m_CertChainItems) {
        (void)CerStore::addCertIfUnique(crl_certs, it->getResultValidationByCrl().cerIssuer);
    }
    for (const auto& it_csi : crl_certs) {
        CertChainItem* added_cci = nullptr;
        bool is_newitem;
        const int ret = addCertChainItem(CertEntity::CRL, it_csi, &added_cci, is_newitem);
        if (ret != RET_OK) return ret;
        if (is_newitem) {
            added_cci->getResultValidationByCrl().isUsed = false;
        }
    }
    return RET_OK;
}

int VerifiedSignerInfo::addExpectedCertItem (
        const CertEntity certEntity,
        const ByteArray* baSidEncoded
)
{
    SmartBA sba_keyid, sba_name, sba_serialnumber;
    const int ret = CerStore::parseSid(baSidEncoded, &sba_name, &sba_serialnumber, &sba_keyid);
    if (ret != RET_OK) return ret;

    const bool is_keyid = (sba_keyid.size() > 0);
    for (const auto& it : m_ExpectedCertItems) {
        if (is_keyid) {
            if (ba_cmp(sba_keyid.get(), it->getKeyId()) == 0) return RET_OK;
        }
        else {
            switch (it->getIdType()) {
            case ExpectedCertItem::IdType::CER_IDTYPE:
                if (
                    (ba_cmp(sba_name.get(), it->getName()) == 0) &&
                    (ba_cmp(sba_serialnumber.get(), it->getSerialNumber()) == 0)
                ) return RET_OK;
                break;
            case ExpectedCertItem::IdType::ORS_IDTYPE:
                if ((ba_cmp(sba_name.get(), it->getName()) == 0)) return RET_OK;
                break;
            default:
                break;
            }
        }
    }

    ExpectedCertItem* expcert_item = new ExpectedCertItem(certEntity);
    if (!expcert_item) return RET_UAPKI_GENERAL_ERROR;

    m_ExpectedCertItems.push_back(expcert_item);
    return expcert_item->setSignerIdentifier((is_keyid) ? sba_keyid.get() : sba_serialnumber.get(), sba_name.get());
}

int VerifiedSignerInfo::addExpectedCrlItem (
        CerStore::Item* cerSubject,
        CrlStore::Item* crlFull
)
{
    if (!cerSubject) return RET_UAPKI_INVALID_PARAMETER;

    for (const auto& it : m_ExpectedCrlItems) {
        if (ba_cmp(cerSubject->baAuthorityKeyId, it->getAuthorityKeyId()) == 0) return RET_OK;
    }

    ExpectedCrlItem* expcrl_item = new ExpectedCrlItem();
    if (!expcrl_item) return RET_UAPKI_GENERAL_ERROR;

    m_ExpectedCrlItems.push_back(expcrl_item);
    return expcrl_item->set(cerSubject, crlFull);
}

int VerifiedSignerInfo::addOcspCertsToChain (void)
{
    vector<CerStore::Item*> ocsp_certs;
    for (const auto& it : m_ListAddedCerts.ocsp) {
        (void)CerStore::addCertIfUnique(ocsp_certs, it);
    }
    for (const auto& it_csi : ocsp_certs) {
        CertChainItem* added_cci = nullptr;
        bool is_newitem;
        const int ret = addCertChainItem(CertEntity::OCSP, it_csi, &added_cci, is_newitem);
        if (ret != RET_OK) return ret;
        if (is_newitem) {
            added_cci->getResultValidationByOcsp().isUsed = false;
        }
    }
    return RET_OK;
}

int VerifiedSignerInfo::buildCertChain (void)
{
    int ret = RET_OK;
    vector<CerStore::Item*> tsp_certs;

    //  Build chain for Singer
    if (m_CsiSigner) {
        const ByteArray* ba_keyid_certnotfound = nullptr;
        vector<CerStore::Item*> chain_certs;
        CertChainItem* added_cci = nullptr;

        DO(addCertChainItem(CertEntity::SIGNER, m_CsiSigner, &added_cci));
        ret = m_CerStore->getChainCerts(m_CsiSigner, chain_certs, &ba_keyid_certnotfound);
        if (ret == RET_OK) {
            for (const auto& it : chain_certs) {
                added_cci->setIssuerAndVerify(it);
                DO(addCertChainItem(CertEntity::INTERMEDIATE, it, &added_cci));
            }
            added_cci->setIssuerAndVerify(nullptr);
        }
        else {
            m_LastError = ret;
            if (ret == RET_UAPKI_CERT_ISSUER_NOT_FOUND) {
                UapkiNS::SmartBA sba_sid;
                DO(CerStore::keyIdToSid(ba_keyid_certnotfound, &sba_sid));
                DO(addExpectedCertItem(CertEntity::INTERMEDIATE, sba_sid.get()));
                for (const auto& it : chain_certs) {
                    added_cci->setIssuerAndVerify(it);
                    DO(addCertChainItem(CertEntity::INTERMEDIATE, it, &added_cci));
                }
            }
        }
    }

    //  Build chain for TSP
    for (const auto& it : m_ListAddedCerts.tsp) {
        (void)CerStore::addCertIfUnique(tsp_certs, it);
    }
    for (const auto& it_tsp : tsp_certs) {
        const ByteArray* ba_keyid_certnotfound = nullptr;
        vector<CerStore::Item*> chain_certs;
        CertChainItem* added_cci = nullptr;

        DO(addCertChainItem(CertEntity::TSP, it_tsp, &added_cci));
        ret = m_CerStore->getChainCerts(it_tsp, chain_certs, &ba_keyid_certnotfound);
        if (ret == RET_OK) {
            for (const auto& it : chain_certs) {
                added_cci->setIssuerAndVerify(it);
                DO(addCertChainItem(CertEntity::INTERMEDIATE, it, &added_cci));
            }
            added_cci->setIssuerAndVerify(nullptr);
        }
        else {
            m_LastError = ret;
            if (ret == RET_UAPKI_CERT_ISSUER_NOT_FOUND) {
                UapkiNS::SmartBA sba_sid;
                DO(CerStore::keyIdToSid(ba_keyid_certnotfound, &sba_sid));
                DO(addExpectedCertItem(CertEntity::INTERMEDIATE, sba_sid.get()));
                for (const auto& it : chain_certs) {
                    added_cci->setIssuerAndVerify(it);
                    DO(addCertChainItem(CertEntity::INTERMEDIATE, it, &added_cci));
                }
            }
        }
    }

cleanup:
    return ret;
}

int VerifiedSignerInfo::certValuesToStore (void)
{
    for (const auto& it : m_CadesXlInfo.certValues) {
        bool is_unique;
        CerStore::Item* cer_item = nullptr;
        const int ret = m_CerStore->addCert(it, true, false, false, is_unique, &cer_item);
        if (ret != RET_OK) return ret;

        m_ListAddedCerts.certValues.push_back(cer_item);
        m_ListAddedCerts.fromSignature.push_back(cer_item);
    }
    return RET_OK;
}

void VerifiedSignerInfo::determineSignatureFormat (void)
{
    if (m_SignatureFormat == SignatureFormat::CADES_BES) {
        if (m_ContentTS.isPresent() && m_SignatureTS.isPresent()) {
            m_SignatureFormat = SignatureFormat::CADES_T;
            if (m_CadesXlInfo.isPresentCadesC()) {
                m_SignatureFormat = SignatureFormat::CADES_C;
                if (m_CadesXlInfo.isPresentCadesXL()) {
                    m_SignatureFormat = SignatureFormat::CADES_XL;
                    if (m_ArchiveTS.isPresent()) {
                        m_SignatureFormat = SignatureFormat::CADES_A;
                    }
                }
            }
        }
    }
}

const char* VerifiedSignerInfo::getValidationStatus (void) const {
    return validationStatusToStr(m_ValidationStatus);
}

int VerifiedSignerInfo::parseAttributes (void)
{
    int ret = parseSignedAttrs(m_SignerInfo.getSignedAttrs());
    if (ret != RET_OK) return ret;

    ret = parseUnsignedAttrs(m_SignerInfo.getUnsignedAttrs());
    return ret;
}

int VerifiedSignerInfo::setRevocationValuesForChain (void)
{
    int ret = RET_OK;

    for (const auto& it_ocspval : m_CadesXlInfo.revocationValuesParser.getOcspVals()) {
        Ocsp::OcspHelper ocsp_helper;
        ret = ocsp_helper.parseBasicOcspResponse(it_ocspval);
        if (ret == RET_OK) {
            SmartBA sba_sn;
            DO(ocsp_helper.scanSingleResponses());
            DO(ocsp_helper.getSerialNumberFromCertId(0, &sba_sn));  //  Work with one OCSP request that has one certificate

            for (const auto& it_cci : m_CertChainItems) {
                if (ba_cmp(sba_sn.get(), it_cci->getSubject()->baSerialNumber) == 0) {
                    ResultValidationByOcsp& result_valbyocsp = it_cci->getResultValidationByOcsp();
                    result_valbyocsp.dataSource = DataSource::SIGNATURE;
                    result_valbyocsp.responseStatus = Ocsp::ResponseStatus::SUCCESSFUL;
                    (void)verifyOcspResponse(ocsp_helper, result_valbyocsp);
                    result_valbyocsp.msProducedAt = ocsp_helper.getProducedAt();
                    result_valbyocsp.singleResponseInfo = ocsp_helper.getSingleResponseInfo(0); //  Work with one OCSP request that has one certificate
                    break;
                }
            }
        }
    }

cleanup:
    return ret;
}

int VerifiedSignerInfo::validateStatuses (void)
{
    CollectVerifyStatus collect_digests, collect_signatures;

    //  Check mandatory elements
    collect_signatures.set(getStatusSignature());
    collect_digests.set(getStatusMessageDigest());
    if (collect_signatures.isValid() && collect_digests.isValid()) {
        m_BestSignatureTime = m_SigningTime;
    }

    //  Check attribute EssCert
    if (getStatusEssCert() != DataVerifyStatus::NOT_PRESENT) {
        collect_digests.set(getStatusEssCert());
    }

    //  Check Content-Timestamp
    if (m_ContentTS.isPresent()) {
        collect_signatures.set(m_ContentTS.statusSignature);
        collect_digests.set(m_ContentTS.statusDigest);
        if (collect_signatures.isValid() && collect_digests.isValid()) {
            m_BestSignatureTime = m_ContentTS.msGenTime;
        }
    }

    //  Check Signature-Timestamp
    if (m_SignatureTS.isPresent()) {
        collect_signatures.set(m_SignatureTS.statusSignature);
        collect_digests.set(m_SignatureTS.statusDigest);
        if (collect_signatures.isValid() && collect_digests.isValid()) {
            m_BestSignatureTime = m_SignatureTS.msGenTime;
        }
    }

    //  Check attributes for CADES-C and higher
    if (m_SignatureFormat >= SignatureFormat::CADES_C) {
        collect_digests.set(m_CadesXlInfo.statusCertRefs);
    }

    //  Check Archive-Timestamp
    if (m_ArchiveTS.isPresent()) {
        collect_signatures.set(m_ArchiveTS.statusSignature);
        collect_digests.set(m_ArchiveTS.statusDigest);
    }

    m_IsValidSignatures = collect_signatures.isValid();
    m_IsValidDigests = collect_digests.isValid();
    if (m_IsValidSignatures && m_IsValidDigests) {
        bool is_signvalid_allcerts = true;
        for (const auto& it : m_CertChainItems) {
            if (it->getVerifyStatus() != CerStore::VerifyStatus::VALID) {
                is_signvalid_allcerts = false;
                break;
            }
        }
        m_ValidationStatus = (is_signvalid_allcerts)
            ? ValidationStatus::TOTAL_VALID : ValidationStatus::INDETERMINATE;
    }
    else if (collect_signatures.isDeterminate() || collect_digests.isDeterminate()) {
        m_ValidationStatus = ValidationStatus::INDETERMINATE;
    }
    else {
        m_ValidationStatus = ValidationStatus::TOTAL_FAILED;
    }

    return RET_OK;
}

int VerifiedSignerInfo::verifyArchiveTimeStamp (
        const vector<CerStore::Item*>& certs,
        const vector<CrlStore::Item*>& crls
)
{
    int ret = RET_OK;

    if (m_SignatureFormat == SignatureFormat::CADES_A) {
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
        DEBUG_OUTCON(printf("VerifiedSignerInfo::verifyArchiveTimeStamp(), calculated hash-value, hex: ");  ba_print(stdout, m_ArchiveTsHelper.getHashValue()));

        m_ArchiveTS.statusDigest = (ba_cmp(m_ArchiveTS.hashedMessage.get(), m_ArchiveTsHelper.getHashValue()) == 0)
            ? SignatureVerifyStatus::VALID : SignatureVerifyStatus::INVALID;
        if (m_ArchiveTS.statusDigest == SignatureVerifyStatus::INVALID) {
            m_LastError = RET_UAPKI_INVALID_DIGEST;
        }

        ret = verifyAttrTimestamp(m_ArchiveTS);
        if (ret != RET_OK) {
            m_LastError = ret;
            ret = (ret == RET_UAPKI_CERT_NOT_FOUND) ? RET_OK : ret;
        }
    }

cleanup:
    return ret;
}

int VerifiedSignerInfo::verifyCertificateRefs (void)
{
    if (m_SignatureFormat < SignatureFormat::CADES_C) return RET_OK;

    int ret = m_CadesXlInfo.verifyCertRefs(m_CerStore);
    if (ret != RET_OK) {
        m_LastError = ret;
    }
    else {
        if (!m_CadesXlInfo.expectedCertsByIssuerAndSN.empty()) {
            m_LastError = RET_UAPKI_CERT_NOT_FOUND;
        }
    }

    for (const auto& it : m_CadesXlInfo.expectedCertsByIssuerAndSN) {
        ret = addExpectedCertItem(CertEntity::UNDEFINED, it);
        if (ret != RET_OK) break;
    }

    return ret;
}

int VerifiedSignerInfo::verifyContentTimeStamp (
        const ByteArray* baContent
)
{
    int ret = RET_OK;
    if (m_ContentTS.isPresent()) {
        ret = m_ContentTS.verifyDigest(baContent, m_IsDigest);
        if (ret != RET_OK) {
            m_LastError = ret;
        }
        ret = verifyAttrTimestamp(m_ContentTS);
        if (ret != RET_OK) {
            m_LastError = ret;
        }
    }

    if ((ret == RET_UAPKI_CERT_NOT_FOUND) || (ret == RET_UAPKI_INVALID_DIGEST)) {
        ret = RET_OK;
    }
    return ret;
}

int VerifiedSignerInfo::verifyMessageDigest (
        const ByteArray* baContent
)
{
    if (!baContent) {
        m_LastError = RET_UAPKI_CONTENT_NOT_PRESENT;
        m_StatusMessageDigest = DigestVerifyStatus::INDETERMINATE;
        return RET_OK;
    }

    if (!m_IsDigest) {
        const HashAlg hash_alg = hash_from_oid(m_SignerInfo.getDigestAlgorithm().algorithm.c_str());
        if (hash_alg == HASH_ALG_UNDEFINED) {
            m_LastError = RET_UAPKI_UNSUPPORTED_ALG;
            m_StatusMessageDigest = DigestVerifyStatus::FAILED;
            return RET_OK;
        }

        SmartBA sba_hash;
        const int ret = ::hash(hash_alg, baContent, &sba_hash);
        if (ret != RET_OK) {
            m_StatusMessageDigest = DigestVerifyStatus::FAILED;
            return ret;
        }

        m_StatusMessageDigest = (ba_cmp(m_SignerInfo.getMessageDigest(), sba_hash.get()) == 0)
            ? DigestVerifyStatus::VALID : DigestVerifyStatus::INVALID;
    }
    else {
        m_StatusMessageDigest = (ba_cmp(m_SignerInfo.getMessageDigest(), baContent) == 0)
            ? DigestVerifyStatus::VALID : DigestVerifyStatus::INVALID;
    }

    return RET_OK;
}

int VerifiedSignerInfo::verifyOcspResponse (
        Ocsp::OcspHelper& ocspClient,
        ResultValidationByOcsp& resultValByOcsp
)
{
    int ret = RET_OK;
    UapkiNS::VectorBA vba_certs;
    vector<CerStore::Item*>& added_certs = (resultValByOcsp.dataSource == DataSource::SIGNATURE)
        ? m_ListAddedCerts.fromSignature : m_ListAddedCerts.fromOnline;

    DO(ocspClient.getCerts(vba_certs));
    for (auto& it : vba_certs) {
        bool is_unique;
        CerStore::Item* cer_item = nullptr;
        DO(m_CerStore->addCert(it, false, false, false, is_unique, &cer_item));
        it = nullptr;
        added_certs.push_back(cer_item);
    }

    DO(ocspClient.getResponderId(resultValByOcsp.responderIdType, &resultValByOcsp.baResponderId));
    if (resultValByOcsp.responderIdType == UapkiNS::Ocsp::ResponderIdType::BY_NAME) {
        ret = m_CerStore->getCertBySubject(resultValByOcsp.baResponderId.get(), &resultValByOcsp.csiResponder);
    }
    else {
        //  responder_idtype == OcspHelper::ResponderIdType::BY_KEY
        ret = m_CerStore->getCertByKeyId(resultValByOcsp.baResponderId.get(), &resultValByOcsp.csiResponder);
    }

    if (ret == RET_OK) {
        m_ListAddedCerts.ocsp.push_back(resultValByOcsp.csiResponder);
        ret = ocspClient.verifyTbsResponseData(resultValByOcsp.csiResponder, resultValByOcsp.statusSignature);
        if (ret == RET_VERIFY_FAILED) {
            ret = RET_UAPKI_OCSP_RESPONSE_VERIFY_FAILED;
        }
        else if (ret != RET_OK) {
            ret = RET_UAPKI_OCSP_RESPONSE_VERIFY_ERROR;
        }
    }
    else if (ret == RET_UAPKI_CERT_NOT_FOUND) {
        resultValByOcsp.statusSignature = UapkiNS::VerifyStatus::INDETERMINATE;
    }

cleanup:
    return ret;
}

int VerifiedSignerInfo::verifySignatureTimeStamp (void)
{
    int ret = RET_OK;
    if (m_SignatureTS.isPresent()) {
        ret = m_SignatureTS.verifyDigest(m_SignerInfo.getSignature());
        if (ret != RET_OK) {
            m_LastError = ret;
        }
        ret = verifyAttrTimestamp(m_SignatureTS);
        if (ret != RET_OK) {
            m_LastError = ret;
        }
    }

    if ((ret == RET_UAPKI_CERT_NOT_FOUND) || (ret == RET_UAPKI_INVALID_DIGEST)) {
        ret = RET_OK;
    }
    return ret;
}

int VerifiedSignerInfo::verifySignedAttribute (void)
{
    int ret = RET_OK;

    //  Get signer certificate
    switch (m_SignerInfo.getSidType()) {
    case Pkcs7::SignerIdentifierType::ISSUER_AND_SN:
        m_SignatureFormat = (m_StatusEssCert == DataVerifyStatus::INDETERMINATE)
            ? SignatureFormat::CADES_BES : SignatureFormat::CMS_SID_KEYID;
        break;
    case Pkcs7::SignerIdentifierType::SUBJECT_KEYID:
        m_SignatureFormat = SignatureFormat::CMS_SID_KEYID;
        break;
    default:
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }
    ret = m_CerStore->getCertBySID(m_SignerInfo.getSidEncoded(), &m_CsiSigner);

    //  Verify signed attributes
    if (ret == RET_OK) {
        ret = verify_signature(
            m_SignerInfo.getSignatureAlgorithm().algorithm.c_str(),
            m_SignerInfo.getSignedAttrsEncoded(),
            false,
            m_CsiSigner->baSPKI,
            m_SignerInfo.getSignature()
        );
    }
    switch (ret) {
    case RET_OK:
        m_StatusSignature = SignatureVerifyStatus::VALID;
        break;
    case RET_VERIFY_FAILED:
        m_StatusSignature = SignatureVerifyStatus::INVALID;
        break;
    case RET_UAPKI_CERT_NOT_FOUND:
        m_LastError = RET_UAPKI_CERT_NOT_FOUND;
        m_StatusSignature = SignatureVerifyStatus::INDETERMINATE;
        DO(addExpectedCertItem(CertEntity::SIGNER, m_SignerInfo.getSidEncoded()));
        break;
    default:
        m_StatusSignature = SignatureVerifyStatus::FAILED;
    }

cleanup:
    return ret;
}

int VerifiedSignerInfo::verifySigningCertificateV2 (void)
{
    if (m_StatusEssCert == DataVerifyStatus::NOT_PRESENT) return RET_OK;

    //  Process simple case: present only the one ESSCertIDv2
    const EssCertId& ess_certid = m_EssCerts[0];
    const HashAlg hash_alg = hash_from_oid(ess_certid.hashAlgorithm.algorithm.c_str());
    if (hash_alg == HASH_ALG_UNDEFINED) {
        m_StatusEssCert = DigestVerifyStatus::FAILED;
        return RET_UAPKI_UNSUPPORTED_ALG;
    }

    if (m_CsiSigner) {
        SmartBA sba_hash;
        const int ret = ::hash(hash_alg, m_CsiSigner->baEncoded, &sba_hash);
        if (ret != RET_OK) {
            m_StatusEssCert = DigestVerifyStatus::FAILED;
            return ret;
        }
        m_StatusEssCert = (ba_cmp(sba_hash.get(), ess_certid.baHashValue) == 0)
            ? DataVerifyStatus::VALID : DataVerifyStatus::INVALID;
    }
    else {
        m_StatusEssCert = DataVerifyStatus::INDETERMINATE;
    }

    return RET_OK;
}

int VerifiedSignerInfo::parseSignedAttrs (
        const vector<Attribute>& signedAattrs
)
{
    int ret = RET_OK;

    m_StatusEssCert = DataVerifyStatus::NOT_PRESENT;
    for (const auto& it : signedAattrs) {
        if (it.type == string(OID_PKCS9_SIGNING_TIME)) {
            DO(AttributeHelper::decodeSigningTime(it.baValues, m_SigningTime));
        }
        else if (it.type == string(OID_PKCS9_SIG_POLICY_ID)) {
            DO(AttributeHelper::decodeSignaturePolicy(it.baValues, m_SigPolicyId));
        }
        else if (it.type == string(OID_PKCS9_CONTENT_TIMESTAMP)) {
            DO(m_ContentTS.parse(it.baValues));
        }
        else if (it.type == string(OID_PKCS9_SIGNING_CERTIFICATE_V2)) {
            DO(AttributeHelper::decodeSigningCertificate(it.baValues, m_EssCerts));
            m_StatusEssCert = DataVerifyStatus::INDETERMINATE;
        }
    }

cleanup:
    return ret;
}

int VerifiedSignerInfo::parseUnsignedAttrs (
        const vector<Attribute>& unsignedAttrs
)
{
    int ret = RET_OK;

    m_CadesXlInfo.statusCertRefs = DataVerifyStatus::NOT_PRESENT;
    for (const auto& it : unsignedAttrs) {
        if (it.type == string(OID_PKCS9_TIMESTAMP_TOKEN)) {
            DO(m_SignatureTS.parse(it.baValues));
        }
        else if (it.type == string(OID_PKCS9_CERTIFICATE_REFS)) {
            DO(m_CadesXlInfo.parseCertificateRefs(it.baValues));
        }
        else if (it.type == string(OID_PKCS9_REVOCATION_REFS)) {
            DO(m_CadesXlInfo.parseRevocationRefs(it.baValues));
        }
        else if (it.type == string(OID_PKCS9_CERT_VALUES)) {
            DO(m_CadesXlInfo.parseCertValues(it.baValues));
        }
        else if (it.type == string(OID_PKCS9_REVOCATION_VALUES)) {
            DO(m_CadesXlInfo.parseRevocationValues(it.baValues));
        }
        else if (it.type == string(OID_ETSI_ARCHIVE_TIMESTAMP_V3)) {
            DO(m_ArchiveTS.parse(it.baValues));
        }
    }

cleanup:
    return ret;
}

int VerifiedSignerInfo::verifyAttrTimestamp (
        AttrTimeStamp& attrTS
)
{
    int ret = RET_OK;
    Pkcs7::SignedDataParser& sdata_parser = attrTS.tsTokenParser.getSignedDataParser();
    Pkcs7::SignedDataParser::SignerInfo signer_info;

    if (sdata_parser.getCountSignerInfos() == 0) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

    for (auto& it : sdata_parser.getCerts()) {
        bool is_unique;
        CerStore::Item* cer_item = nullptr;
        DO(m_CerStore->addCert(it, false, false, false, is_unique, &cer_item));
        it = nullptr;
        m_ListAddedCerts.fromSignature.push_back(cer_item);
    }

    DO(sdata_parser.parseSignerInfo(0, signer_info));
    if (!sdata_parser.isContainDigestAlgorithm(signer_info.getDigestAlgorithm())) {
        SET_ERROR(RET_UAPKI_NOT_SUPPORTED);
    }

    switch (signer_info.getSidType()) {
    case Pkcs7::SignerIdentifierType::ISSUER_AND_SN:
        ret = m_CerStore->getCertBySID(signer_info.getSidEncoded(), &attrTS.csiSigner);
        break;
    case Pkcs7::SignerIdentifierType::SUBJECT_KEYID:
        ret = m_CerStore->getCertByKeyId(signer_info.getSidEncoded(), &attrTS.csiSigner);
        break;
    default:
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

    if (ret == RET_OK) {
        m_ListAddedCerts.tsp.push_back(attrTS.csiSigner);
        ret = verify_signature(
            signer_info.getSignatureAlgorithm().algorithm.c_str(),
            signer_info.getSignedAttrsEncoded(),
            false,
            attrTS.csiSigner->baSPKI,
            signer_info.getSignature()
        );
    }
    switch (ret) {
    case RET_OK:
        attrTS.statusSignature = SignatureVerifyStatus::VALID;
        break;
    case RET_VERIFY_FAILED:
        attrTS.statusSignature = SignatureVerifyStatus::INVALID;
        break;
    case RET_UAPKI_CERT_NOT_FOUND:
        m_LastError = RET_UAPKI_CERT_NOT_FOUND;
        attrTS.statusSignature = SignatureVerifyStatus::INDETERMINATE;
        DO(addExpectedCertItem(CertEntity::SIGNER, signer_info.getSidEncoded()));
        break;
    default:
        attrTS.statusSignature = SignatureVerifyStatus::FAILED;
    }

cleanup:
    return ret;
}


VerifySignedDoc::VerifySignedDoc (
        CerStore* iCerStore,
        CrlStore* iCrlStore,
        const UapkiNS::Doc::Verify::VerifyOptions& iVerifyOptions
)
    : cerStore(iCerStore)
    , crlStore(iCrlStore)
    , verifyOptions(iVerifyOptions)
    , refContent(nullptr)
{
}

VerifySignedDoc::~VerifySignedDoc (void)
{
}

int VerifySignedDoc::parse (const ByteArray* baSignature)
{
    const int ret = sdataParser.parse(baSignature);
    if (ret != RET_OK) return ret;
    return (sdataParser.getCountSignerInfos() > 0) ? RET_OK : RET_UAPKI_INVALID_STRUCT;
}

void VerifySignedDoc::getContent (const ByteArray* baContent)
{
    refContent = (sdataParser.getEncapContentInfo().baEncapContent)
        ? sdataParser.getEncapContentInfo().baEncapContent : baContent;
}

int VerifySignedDoc::addCertsToStore (void)
{
    int ret = RET_OK;
    UapkiNS::VectorBA& vba_certs = sdataParser.getCerts();

    for (size_t i = 0; i < vba_certs.size(); i++) {
        bool is_unique;
        CerStore::Item* cer_item = nullptr;
        DO(cerStore->addCert(vba_certs[i], false, false, false, is_unique, &cer_item));
        vba_certs[i] = nullptr;
        addedCerts.push_back(cer_item);
    }

cleanup:
    return ret;
}

void VerifySignedDoc::detectCertSources (void)
{
    for (auto& it_vsi : verifiedSignerInfos) {
        for (auto& it_cci : it_vsi.getCertChainItems()) {
            const ByteArray* cert_id = it_cci->getSubjectCertId();
            const bool is_found = (
                CerStore::findCertByCertId(addedCerts, cert_id) ||
                CerStore::findCertByCertId(it_vsi.getListAddedCerts().fromSignature, cert_id)
            );
            it_cci->setDataSource((is_found) ? DataSource::SIGNATURE : DataSource::STORE);
        }
    }
}

int VerifySignedDoc::getLastError (void)
{
    for (const auto& it : verifiedSignerInfos) {
        const int ret = it.getLastError();
        if (ret != RET_OK) return ret;
    }
    return RET_OK;
}


const char* certEntityToStr (
        const CertEntity certEntity
)
{
    static const char* CERT_ENTITY_STRINGS[8] = {
        "UNDEFINED",
        "SIGNER",
        "INDETERMINATE",
        "CRL",
        "OCSP",
        "TSP",
        "CA",
        "ROOT"
    };
    return CERT_ENTITY_STRINGS[((uint32_t)certEntity < 8) ? (uint32_t)certEntity : 0];
}   //  certEntityToStr

const char* dataSourceToStr (
        const DataSource dataSource
)
{
    static const char* CERT_SOURCE_STRINGS[3] = {
        "UNDEFINED",
        "SIGNATURE",
        "STORE"
    };
    return CERT_SOURCE_STRINGS[((uint32_t)dataSource < 3) ? (uint32_t)dataSource : 0];
}   //  dataSourceToStr

const char* validationStatusToStr (
        const ValidationStatus status
)
{
    static const char* VALIDATION_STATUS_STRINGS[4] = {
        "UNDEFINED",
        "INDETERMINATE",
        "TOTAL-FAILED",
        "TOTAL-VALID"
    };
    return VALIDATION_STATUS_STRINGS[((uint32_t)status < 4) ? (uint32_t)status : 0];
}   //  validationStatusToStr


}   //  end namespace Verify

}   //  end namespace Doc

}   //  end namespace UapkiNS
