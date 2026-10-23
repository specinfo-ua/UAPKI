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

#define FILE_MARKER "uapki/cert-validator.cpp"

#include "cert-validator.h"
#include <algorithm>
#include "ba-utils.h"
#include "macros-internal.h"
#include "oid-utils.h"
#include "parson-ba-utils.h"
#include "parson-helper.h"
#include "store-json.h"
#include "time-util.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"
#include "uapki-ns-verify.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


namespace UapkiNS {

namespace CertValidator {


CertChainItem::CertChainItem (
        const CertEntity iCertEntity,
        Cert::CerItem* iCerSubject
)
    : m_CertEntity(iCertEntity)
    , m_CerSubject(iCerSubject)
    , m_DataSource(DataSource::UNDEFINED)
    , m_CerIssuer(nullptr)
    , m_Trusted(iCerSubject ? iCerSubject->isTrusted() : false)
    , m_Expired(true)
    , m_ValidationType(Cert::ValidationType::UNDEFINED)
{
}

CertChainItem::~CertChainItem (void)
{
}

bool CertChainItem::checkValidityTime (
        const uint64_t validateTime
)
{
    const int ret = m_CerSubject->checkValidity(validateTime);
    m_Expired = (ret != RET_OK);
    return (!m_Expired);
}

int CertChainItem::decodeName (void)
{
    return rdnameFromName(
        m_CerSubject->getCert()->tbsCertificate.subject,
        OID_X520_CommonName,
        m_CommonName
    );
}

void CertChainItem::setCerItem (
        const CertEntity certEntity,
        Cert::CerItem* cerItem
)
{
    m_CertEntity = certEntity;
    m_CerSubject = cerItem;
}

void CertChainItem::setDataSource (
        const DataSource dataSource
)
{
    m_DataSource = dataSource;
}

void CertChainItem::setIssuer (
        Cert::CerItem* cerIssuer
)
{
    m_CerIssuer = cerIssuer;
    (void)m_CerSubject->verify(m_CerIssuer);
}

void CertChainItem::setRoot (void)
{
    m_CertEntity = CertEntity::ROOT;
    m_CerIssuer = m_CerSubject;
    m_ValidationType = Cert::ValidationType::NONE;
    (void)m_CerSubject->verify(m_CerIssuer);
}

TsaKeyTrust tsaKeyTrust (
        const CertChainItem& tsaItem
)
{
    bool is_revoked = false;
    CrlReason reason = CrlReason::UNDEFINED;
    switch (tsaItem.getValidationType()) {
    case Cert::ValidationType::CRL: {
        const ResultValidationByCrl& by_crl = tsaItem.getResultValidationByCrl();
        if (by_crl.certStatus == CertStatus::REVOKED) {
            is_revoked = true;
            reason = by_crl.revokedCertItem.crlReason;
        }
        else if (by_crl.hasRevokedLater) {
            is_revoked = true;
            reason = by_crl.revokedLater.crlReason;
        }
        break;
    }
    case Cert::ValidationType::OCSP: {
        const ResultValidationByOcsp& by_ocsp = tsaItem.getResultValidationByOcsp();
        if (
            (by_ocsp.statusSignature == SignatureVerifyStatus::VALID) &&
            (by_ocsp.singleResponseInfo.certStatus == CertStatus::REVOKED)
        ) {
            is_revoked = true;
            reason = by_ocsp.singleResponseInfo.revocationReason;
        }
        break;
    }
    default:
        break;
    }
    if (!is_revoked) return TsaKeyTrust::OK;

    switch (reason) {
    case CrlReason::KEY_COMPROMISE:
    case CrlReason::CA_COMPROMISE:
    case CrlReason::AA_COMPROMISE:
        return TsaKeyTrust::COMPROMISED;
    case CrlReason::UNDEFINED:
    case CrlReason::UNSPECIFIED:
        return TsaKeyTrust::REASON_NOT_GIVEN;
    default:
        return TsaKeyTrust::OK;
    }
}

void CertChainItem::setTrustAnchor (void)
{
    m_CerIssuer = m_CerSubject;
    m_ValidationType = Cert::ValidationType::NONE;
    m_Trusted = true;
    (void)m_CerSubject->verify(m_CerIssuer);
}

void CertChainItem::setValidationType (
        const Cert::ValidationType validationType
)
{
    m_ValidationType = validationType;
}


ExpectedCertItem::ExpectedCertItem (
        const CertEntity iCertEntity
)
    : m_CertEntity(iCertEntity)
    , m_IdType(IdType::UNDEFINED)
{
}

int ExpectedCertItem::copyFrom (
        const ExpectedCertItem* item
)
{
    if (!item) return RET_UAPKI_INVALID_PARAMETER;

    m_CertEntity = item->getCertEntity();
    m_IdType = item->getIdType();
    if (item->getKeyId()) {
        if (!m_KeyId.set(ba_copy_with_alloc(item->getKeyId(), 0, 0))) return RET_UAPKI_GENERAL_ERROR;
    }
    if (item->getIssuerName()) {
        if (!m_IssuerName.set(ba_copy_with_alloc(item->getIssuerName(), 0, 0))) return RET_UAPKI_GENERAL_ERROR;
    }
    if (item->getSerialNumber()) {
        if (!m_SerialNumber.set(ba_copy_with_alloc(item->getSerialNumber(), 0, 0))) return RET_UAPKI_GENERAL_ERROR;
    }

    return RET_OK;
}

int ExpectedCertItem::setResponderId (
        const bool isKeyId,
        const ByteArray* baResponderId
)
{
    if (!baResponderId) return RET_UAPKI_INVALID_PARAMETER;

    SmartBA& rsba_dst = (isKeyId) ? m_KeyId : m_IssuerName;
    if (!rsba_dst.set(ba_copy_with_alloc(baResponderId, 0, 0))) return RET_UAPKI_GENERAL_ERROR;

    m_IdType = IdType::ORS_IDTYPE;

    return RET_OK;
}

int ExpectedCertItem::setSignerIdentifier (
        const ByteArray* baKeyIdOrSN,
        const ByteArray* baIssuerName
)
{
    if (!baKeyIdOrSN) return RET_UAPKI_INVALID_PARAMETER;

    if (!baIssuerName) {
        if (!m_KeyId.set(ba_copy_with_alloc(baKeyIdOrSN, 0, 0))) return RET_UAPKI_GENERAL_ERROR;
    }
    else {
        if (
            !m_SerialNumber.set(ba_copy_with_alloc(baKeyIdOrSN, 0, 0)) ||
            !m_IssuerName.set(ba_copy_with_alloc(baIssuerName, 0, 0))
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

int ExpectedCrlItem::copyFrom (
        const ExpectedCrlItem* item
)
{
    if (!item) return RET_UAPKI_INVALID_PARAMETER;

    if (item->getAuthorityKeyId()) {
        if (!m_AuthorityKeyId.set(ba_copy_with_alloc(item->getAuthorityKeyId(), 0, 0))) return RET_UAPKI_GENERAL_ERROR;
    }
    if (item->getName()) {
        if (!m_Name.set(ba_copy_with_alloc(item->getName(), 0, 0))) return RET_UAPKI_GENERAL_ERROR;
    }
    m_Url = item->getUrl();
    m_ThisUpdate = item->getThisUpdate();
    m_NextUpdate = item->getNextUpdate();
    if (item->getCrlNumber()) {
        if (!m_CrlNumber.set(ba_copy_with_alloc(item->getCrlNumber(), 0, 0))) return RET_UAPKI_GENERAL_ERROR;
    }

    return RET_OK;
}

int ExpectedCrlItem::set (
        const Cert::CerItem* cerSubject,
        const Crl::CrlItem* crlFull
)
{
    if (!cerSubject) return RET_UAPKI_INVALID_PARAMETER;

    if (!m_AuthorityKeyId.set(ba_copy_with_alloc(cerSubject->getAuthorityKeyId(), 0, 0))) return RET_UAPKI_GENERAL_ERROR;
    if (!m_Name.set(ba_copy_with_alloc(cerSubject->getIssuer(), 0, 0))) return RET_UAPKI_GENERAL_ERROR;

    const Cert::CerItem::Uris& uris = cerSubject->getUris();
    const vector<string>& uris_crl = (crlFull) ? uris.deltaCrl : uris.fullCrl;
    if (crlFull) {
        m_ThisUpdate = crlFull->getThisUpdate();
        m_NextUpdate = crlFull->getNextUpdate();
        if (!m_CrlNumber.set(ba_copy_with_alloc(crlFull->getCrlNumber(), 0, 0))) return RET_UAPKI_GENERAL_ERROR;
    }
    m_Url = Util::joinStrings(uris_crl);

    return RET_OK;
}


CertValidator::CertValidator (void)
    : m_LibConfig(nullptr)
    , m_CerStore(nullptr)
    , m_CrlStore(nullptr)
    , m_ValidationType(Cert::ValidationType::UNDEFINED)
    , m_CheckTrustedRoot(false)
    , m_CaRemovesExpiredCerts(false)
    , m_RevocationMinThisUpdate(0)
    , m_StrictFreshnessTime(0)
{
}

CertValidator::~CertValidator (void)
{
    for (auto it : m_CertChain) {
        delete it;
    }
    for (auto it : m_ObtainedCerts) {
        delete it;
    }

    for (auto it : m_ExpectedCerts) {
        delete it;
    }
    for (auto it : m_ExpectedCrls) {
        delete it;
    }
}

bool CertValidator::init (
        CertValidator& iCertValidator
)
{
    m_LibConfig = iCertValidator.getLibConfig();
    m_CerStore = iCertValidator.getCerStore();
    m_CrlStore = iCertValidator.getCrlStore();
    m_ValidationType = iCertValidator.getValidationType();
    m_CheckTrustedRoot = iCertValidator.getCheckTrustedRoot();
    m_CaRemovesExpiredCerts = iCertValidator.getCaRemovesExpiredCerts();
    m_RevocationMinThisUpdate = iCertValidator.getRevocationMinThisUpdate();
    m_StrictFreshnessTime = iCertValidator.m_StrictFreshnessTime;

    return (m_LibConfig && m_CerStore && m_CrlStore);
}

bool CertValidator::init (
        CertValidator* iCertValidator
)
{
    if (iCertValidator) {
        m_LibConfig = iCertValidator->getLibConfig();
        m_CerStore = iCertValidator->getCerStore();
        m_CrlStore = iCertValidator->getCrlStore();
        m_ValidationType = iCertValidator->getValidationType();
        m_CheckTrustedRoot = iCertValidator->getCheckTrustedRoot();
        m_CaRemovesExpiredCerts = iCertValidator->getCaRemovesExpiredCerts();
        m_RevocationMinThisUpdate = iCertValidator->getRevocationMinThisUpdate();
        m_StrictFreshnessTime = iCertValidator->m_StrictFreshnessTime;
    }

    return (m_LibConfig && m_CerStore && m_CrlStore);
}

bool CertValidator::init (
        LibraryConfig* iLibConfig,
        Cert::CerStore* iCerStore,
        Crl::CrlStore* iCrlStore
)
{
    m_LibConfig = iLibConfig;
    m_CerStore = iCerStore;
    m_CrlStore = iCrlStore;

    return (m_LibConfig && m_CerStore && m_CrlStore);
}

void CertValidator::setValidationType (
        const Cert::ValidationType validationType
)
{
    m_ValidationType = validationType;
}

void CertValidator::setCheckTrustedRoot (
        const bool checkTrustedRoot
)
{
    m_CheckTrustedRoot = checkTrustedRoot;
}

void CertValidator::setCaRemovesExpiredCerts (
        const bool caRemovesExpiredCerts
)
{
    m_CaRemovesExpiredCerts = caRemovesExpiredCerts;
}

int CertValidator::addChainItem (
        vector<CertChainItem*>& chainItems,
        const CertEntity certEntity,
        Cert::CerItem* cerItem,
        CertChainItem** chainItem,
        bool& isNewItem
)
{
    for (const auto& it : chainItems) {
        if (cerItem->equalCertId(it->getSubjectCertId())) {
            *chainItem = it;
            isNewItem = false;
            return RET_OK;
        }
    }

    CertChainItem* new_item = new CertChainItem(certEntity, cerItem);
    *chainItem = new_item;
    if (!new_item) return RET_UAPKI_GENERAL_ERROR;
    //  No revocation status is looked for (the chain above it is checked as usual, EN 319 412-1 5.2.1 NOTE 2).
    //  id-pkix-ocsp-nocheck is for OCSP responders (RFC 6960, 4.2.2.2.1): in a TSA certificate it is forbidden
    //  (checkChainConstraints) and does not hide a revocation - the status is checked as usual
    if (
        cerItem->isNoRevocationCheck() &&
        !((certEntity == CertEntity::TSP) && cerItem->hasOcspNoCheckExtension())
    ) {
        new_item->setValidationType(Cert::ValidationType::NONE);
    }

    isNewItem = true;
    chainItems.push_back(new_item);
    return new_item->decodeName();
}

int CertValidator::buildCertChain (
        const CertEntity certEntity,
        Cert::CerItem* cerItem,
        vector<CertChainItem*>& chainItems,
        CertChainItem** subjectItem,
        const uint64_t msTrustTime
)
{
    if (!cerItem) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    const uint64_t trust_time = (msTrustTime > 0) ? msTrustTime : TimeUtil::mtimeNow();
    const ByteArray* ba_authkeyid_notfound = nullptr;
    vector<Cert::CerItem*> chain_certs;
    CertChainItem* added_cci = nullptr;
    bool is_newitem = false;

    ret = addChainItem(chainItems, certEntity, cerItem, &added_cci, is_newitem);
    if (ret != RET_OK) return ret;
    if (subjectItem) {
        *subjectItem = added_cci;
    }
    if (is_newitem) {
        added_cci->setTrustAt(cerItem->isTrustedAt(trust_time));
    }
    //  The certificate is trusted itself at the time: it is the trust anchor of its path, its issuers are not needed
    if (!cerItem->isSelfSigned() && cerItem->isTrustedAt(trust_time)) {
        added_cci->setTrustAnchor();
        return RET_OK;
    }

    //  Issuers by the authority key id, up to a trusted or a self-signed certificate. Each link verifies the signature
    //  of its issuer; whether the root is trusted is decided by the caller (checkTrustedRoot, VERIFY)
    const int ret_chain = m_CerStore->getChainCerts(cerItem, chain_certs, &ba_authkeyid_notfound);
    if ((ret_chain != RET_OK) && (ret_chain != RET_UAPKI_CERT_ISSUER_NOT_FOUND)) return ret_chain;

    for (const auto& it : chain_certs) {
        added_cci->setIssuer(it);
        ret = addChainItem(chainItems, CertEntity::INTERMEDIATE, it, &added_cci, is_newitem);
        if (ret != RET_OK) return ret;
        //  The chain ends at the first certificate trusted at the time: the trust anchor (RFC 5280, 6.1), whether
        //  it is self-signed or not. What is above it is not a part of the path
        const bool is_trusted = it->isTrustedAt(trust_time);
        if (is_newitem) {
            added_cci->setTrustAt(is_trusted);
        }
        else {
            added_cci->addTrust(is_trusted);
        }
        if (is_trusted) {
            added_cci->setRoot();
            return RET_OK;
        }
    }

    if (ret_chain == RET_OK) {
        if (added_cci->isSelfSigned()) {
            added_cci->setRoot();
        }
        return RET_OK;
    }

    //  The issuer of the last certificate is missing: it stays unverified, the issuer is expected. A certificate
    //  without the key identifier in authorityKeyIdentifier does not name its issuer by a key identifier
    if (!ba_authkeyid_notfound) return RET_UAPKI_CERT_ISSUER_NOT_FOUND;
    ret = addExpectedCertByKeyId(CertEntity::INTERMEDIATE, ba_authkeyid_notfound);
    return (ret == RET_OK) ? RET_UAPKI_CERT_ISSUER_NOT_FOUND : ret;
}

int CertValidator::getStatus (
        Cert::CerItem* cerItem,
        const CertEntity certEntity,
        const uint64_t validateTime
)
{
    if (!cerItem) return RET_UAPKI_INVALID_PARAMETER;

    if (m_ValidationType <= Cert::ValidationType::NONE) {
        CertChainItem* entity = new CertChainItem(certEntity, cerItem);
        if (!entity) return RET_UAPKI_GENERAL_ERROR;
        m_CertChain.push_back(entity);
        return RET_OK;
    }

    int ret = RET_OK;
    vector<CertChainItem*> chain;
    vector<Cert::CerItem*> obtained_certs;
    CertChainItem* root = nullptr;

    //  Build a chain of certs: [cerItem, its issuer, ..., root]
    ret = buildCertChain(certEntity, cerItem, chain, nullptr, validateTime);
    for (const auto it : chain) {
        //  The items are owned by m_CertChain
        m_CertChain.push_back(it);
    }
    DO(ret);
    root = chain.back();
    if (root->getCertEntity() != CertEntity::ROOT) {
        SET_ERROR(RET_UAPKI_CERT_ISSUER_NOT_FOUND);
    }

    //  Check signature in chain-certs (the verdicts are cached, see setIssuer() and setRoot())
    for (const auto it : chain) {
        DO(it->getSubject()->verify(it->getIssuer()));
    }

    //  The root must be trusted only if asked: who to trust is decided by the one who verifies a signature
    if (m_CheckTrustedRoot && !root->isTrusted()) {
        SET_ERROR(RET_UAPKI_CERT_NOT_TRUSTED);
    }

    //  check validity in chain-certs
    for (const auto it : chain) {
        DO(it->getSubject()->checkValidity(validateTime));
    }

    //  check status in chain-certs (the root has no status, nor a certificate without revocation check)
    for (const auto it : chain) {
        if ((it == root) || it->getSubject()->isNoRevocationCheck()) continue;
        if (m_ValidationType == Cert::ValidationType::OCSP) {
            //  The responder is checked in validateByOcsp(): authorized for the issuer (RFC 6960)
            DO(validateByOcsp(
                it->getSubject(),
                it->getIssuer(),
                it->getResultValidationByOcsp()
            ));
            DO(addUniqueItem(obtained_certs, it->getResultValidationByOcsp().cerResponder));
        }
        else if (m_ValidationType == Cert::ValidationType::CRL) {
            DO(validateByCrl(
                it->getSubject(),
                validateTime,
                true,
                it->getResultValidationByCrl()
            ));
            DO(addUniqueItem(obtained_certs, it->getResultValidationByCrl().cerIssuer));
        }
    }

    //  check restrictions
    if (!checkCertUsage(certEntity, cerItem)) {
        SET_ERROR(RET_UAPKI_INVALID_KEY_USAGE);
    }
    for (const auto it : chain) {
        if (checkChainConstraints(*it, chain, false) != ChainConstraint::NONE) {
            SET_ERROR(RET_UAPKI_INVALID_KEY_USAGE);
        }
    }
    if (!root->getSubject()->getCertExtKeyUsage().isCa()) {
        SET_ERROR(RET_UAPKI_INVALID_KEY_USAGE);
    }

    //  check obtained certs: the status of a delegated OCSP responder (unless id-pkix-ocsp-nocheck)
    for (auto it_obtcert : obtained_certs) {
        if (findItemByCertId(chain, it_obtcert)) continue;
        if (
            (m_ValidationType == Cert::ValidationType::OCSP) &&
            !it_obtcert->isNoRevocationCheck() &&
            !it_obtcert->getUris().ocsp.empty()
        ) {
            Cert::CerItem* cer_issuer = nullptr;
            bool is_selfsigned;
            ResultValidationByOcsp result_validation;
            DO(m_CerStore->getIssuerCert(it_obtcert, &cer_issuer, is_selfsigned));
            DO(validateByOcsp(it_obtcert, cer_issuer, result_validation));
        }
        DO(addUniqueItem(
            m_ObtainedCerts,
            (m_ValidationType == Cert::ValidationType::OCSP) ? CertEntity::OCSP : CertEntity::CRL,
            it_obtcert
        ));
    }

cleanup:
    return ret;
}

int CertValidator::getCertByIssuerAndSN (
        const CertEntity certEntity,
        const ByteArray* baIssuerAndSN,
        Cert::CerItem** cerItem
)
{
    const int ret = m_CerStore->getCertByIssuerAndSN(baIssuerAndSN, cerItem);
    if (ret == RET_UAPKI_CERT_NOT_FOUND) {
        if (addExpectedCertByIssuerAndSN(certEntity, baIssuerAndSN) != RET_OK) return RET_UAPKI_GENERAL_ERROR;
    }
    return ret;
}

int CertValidator::getCertByKeyId (
        const CertEntity certEntity,
        const ByteArray* baKeyId,
        Cert::CerItem** cerItem
)
{
    const int ret = m_CerStore->getCertByKeyId(baKeyId, cerItem);
    if (ret == RET_UAPKI_CERT_NOT_FOUND) {
        if (addExpectedCertByKeyId(certEntity, baKeyId) != RET_OK) return RET_UAPKI_GENERAL_ERROR;
    }
    return ret;
}

int CertValidator::getCertBySID (
        const CertEntity certEntity,
        const ByteArray* baSID,
        Cert::CerItem** cerItem
)
{
    const int ret = m_CerStore->getCertBySID(baSID, cerItem);
    if (ret == RET_UAPKI_CERT_NOT_FOUND) {
        if (addExpectedCertBySID(certEntity, baSID) != RET_OK) return RET_UAPKI_GENERAL_ERROR;
    }
    return ret;
}

int CertValidator::getIssuerCert (
        Cert::CerItem* cerSubject,
        Cert::CerItem** cerIssuer,
        bool& isSelfSigned
)
{
    const int ret = m_CerStore->getIssuerCert(cerSubject, cerIssuer, isSelfSigned);
    if (ret == RET_UAPKI_CERT_ISSUER_NOT_FOUND) {
        if (addExpectedCertByKeyId(CertEntity::CA, cerSubject->getAuthorityKeyId()) != RET_OK) return RET_UAPKI_GENERAL_ERROR;
    }
    return ret;
}

int CertValidator::validateByCrl (
        Cert::CerItem* cerSubject,
        const uint64_t validateTime,
        const bool needUpdateCert,
        ResultValidationByCrl& resultValidation,
        JSON_Object* joResult
)
{
    if (!cerSubject) return RET_UAPKI_INVALID_PARAMETER;

    lock_guard<mutex> lock(cerSubject->getStatusMutex());

    int ret = RET_OK;
    Crl::CrlItem* crl_item = nullptr;
    Crl::CrlItem* crl_full = nullptr;
    CertStatus cert_status = CertStatus::UNDEFINED;
    vector<const Crl::RevokedCertItem*> revoked_items;
    JSON_Object* joDelta = nullptr;
    JSON_Object* joFull = nullptr;
    const ByteArray* ba_crlnumber = nullptr;

    if (joResult) {
        DO_JSON(json_object_set_string(joResult, "status", Crl::certStatusToStr(resultValidation.certStatus)));
        DO_JSON(json_object_set_value(joResult, "full", json_value_init_object()));
        joFull = json_object_get_object(joResult, "full");
    }
    DO(getCrl(
        *m_CrlStore,
        *m_CerStore,
        cerSubject,
        validateTime,
        &ba_crlnumber,
        &crl_item,
        &resultValidation.cerIssuer,
        joFull
    ));
    DEBUG_OUTCON(printf("validateByCrl(), ba_crlnumber: "); ba_print(stdout, ba_crlnumber));
    DO(crl_item->revokedCerts(cerSubject, revoked_items));
    resultValidation.crlItem = crl_item;
    resultValidation.issuedAfterExpiration = false;
    crl_full = crl_item;
    resultValidation.crlFull = crl_full;

    if (
        m_CrlStore->useDeltaCrl() &&
        !cerSubject->getUris().deltaCrl.empty()
    ) {
        Cert::CerItem* cer_crlsigner = nullptr;
        if (joResult) {
            DO_JSON(json_object_set_value(joResult, "delta", json_value_init_object()));
            joDelta = json_object_get_object(joResult, "delta");
        }
        DO(getCrl(
            *m_CrlStore,
            *m_CerStore,
            cerSubject,
            validateTime,
            &ba_crlnumber,
            &crl_item,
            &cer_crlsigner,
            joDelta
        ));
        DO(crl_item->revokedCerts(cerSubject, revoked_items));
        resultValidation.crlItem = crl_item;
    }

    DEBUG_OUTCON(for (auto& it : revoked_items) {
        printf("revocationDate: %lld  crlReason: %i  invalidityDate: %lld\n", it->revocationDate, it->crlReason, it->invalidityDate);
    });
    (void)Crl::findRevokedCert(
        revoked_items,
        validateTime,
        resultValidation.certStatus,
        resultValidation.revokedCertItem
    );
    cert_status = resultValidation.certStatus;
    //  Good at the time, revoked later: the entry is kept (the time-stamps of a TSA, see tsaKeyTrust())
    resultValidation.hasRevokedLater = false;
    if (resultValidation.certStatus == CertStatus::GOOD) {
        for (const auto& it : revoked_items) {
            if ((it->crlReason == CrlReason::REMOVE_FROM_CRL) || (it->revocationDate <= validateTime)) continue;
            //  the entry of a compromise, or without a reason, is the one that matters
            const bool is_bad = (it->crlReason == CrlReason::UNDEFINED) || (it->crlReason == CrlReason::UNSPECIFIED) ||
                (it->crlReason == CrlReason::KEY_COMPROMISE) || (it->crlReason == CrlReason::CA_COMPROMISE) ||
                (it->crlReason == CrlReason::AA_COMPROMISE);
            if (!resultValidation.hasRevokedLater || is_bad) {
                resultValidation.revokedLater = *it;
                resultValidation.hasRevokedLater = true;
            }
            if (is_bad) break;
        }
    }
    //  Not in a CRL (full or delta) issued after the certificate expired: not proven not revoked
    if (
        (resultValidation.certStatus == CertStatus::GOOD) && (
            !revocationCoversCert(cerSubject, crl_full->getThisUpdate(), crl_full->getExpiredCertsOnCrl(), m_CaRemovesExpiredCerts) ||
            !revocationCoversCert(cerSubject, crl_item->getThisUpdate(), crl_item->getExpiredCertsOnCrl(), m_CaRemovesExpiredCerts)
        )
    ) {
        resultValidation.certStatus = CertStatus::UNDEFINED;
        resultValidation.issuedAfterExpiration = true;
    }

    if (joResult) {
        DO_JSON(json_object_set_string(joResult, "status", Crl::certStatusToStr(resultValidation.certStatus)));
        if (resultValidation.certStatus == CertStatus::REVOKED) {
            DO_JSON(json_object_set_string(joResult, "revocationReason", Crl::crlReasonToStr(resultValidation.revokedCertItem.crlReason)));
            if (resultValidation.revokedCertItem.revocationDate > 0) {
                const string s_time = TimeUtil::mtimeToFtime(resultValidation.revokedCertItem.revocationDate);
                DO_JSON(json_object_set_string(joResult, "revocationTime", s_time.c_str()));
            }
        }
    }

    if (needUpdateCert) {
        cerSubject->getCertStatusByCrl().set(
            cert_status,
            crl_item->getNextUpdate(),
            crl_item->getCrlId()
        );
    }

cleanup:
    for (auto& it : revoked_items) {
        delete it;
    }
    revoked_items.clear();

    switch (ret) {
    case RET_UAPKI_OFFLINE_MODE:
    case RET_UAPKI_CRL_NOT_DOWNLOADED:
    case RET_UAPKI_CRL_NOT_FOUND:
        (void)addExpectedCrl(cerSubject, crl_item);
        break;
    default: break;
    }
    return ret;
}

int CertValidator::validateByOcsp (
        Cert::CerItem* cerSubject,
        Cert::CerItem* cerIssuer,
        ResultValidationByOcsp& resultValidation,
        JSON_Object* joResult
)
{
    if (!cerSubject) return RET_UAPKI_INVALID_PARAMETER;

    lock_guard<mutex> lock(cerSubject->getStatusMutex());

    int ret = RET_OK;
    const LibraryConfig::OcspParams& ocsp_params = m_LibConfig->getOcsp();
    Cert::CertStatusInfo& certstatusinfo_by_ocsp = cerSubject->getCertStatusByOcsp();
    Ocsp::OcspHelper ocsp_helper;
    SmartBA sba_ocsprequest, sba_ocspresponse;
    const ByteArray* pba_ocspresponse = nullptr;

    if (joResult) {
        DO_JSON(json_object_set_string(joResult, "status", Crl::certStatusToStr(UapkiNS::CertStatus::UNDEFINED)));
    }

    if (m_LibConfig->getOffline()) {
        SET_ERROR(RET_UAPKI_OFFLINE_MODE);
    }

    //  A cached response issued before the required time is obtained again (AUGMENT_CMS: revocationFreshness)
    if (
        !certstatusinfo_by_ocsp.isExpired(TimeUtil::mtimeNow()) &&
        (
            ((m_RevocationMinThisUpdate > 0) && (certstatusinfo_by_ocsp.thisUpdate < m_RevocationMinThisUpdate)) ||
            ((m_StrictFreshnessTime > 0) && (certstatusinfo_by_ocsp.thisUpdate < m_StrictFreshnessTime))
        )
    ) {
        certstatusinfo_by_ocsp.needUpdate = true;
    }
    if (certstatusinfo_by_ocsp.needUpdate) {
        vector<string> shuffled_uris;

        if (cerSubject->getUris().ocsp.empty()) {
            SET_ERROR(RET_UAPKI_OCSP_URL_NOT_PRESENT);
        }

        DO(ocsp_helper.init());
        if (!cerIssuer) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
        DO(ocsp_helper.addIssuerAndSN(
            cerIssuer->getAlgoKeyId(),
            cerIssuer->getSubject(),
            cerIssuer->getKeyId(),
            cerSubject->getSerialNumber()
        ));
        if (ocsp_params.nonceLen > 0) {
            DO(ocsp_helper.genNonce(ocsp_params.nonceLen));
        }
        DO(ocsp_helper.encodeRequest());
        (void)sba_ocsprequest.set(ocsp_helper.getRequestEncoded(true));

        //  All the OCSP responders of the certificate: the next one if a responder does not respond, refuses
        //  (responseStatus not successful) or answers not an OCSP response
        shuffled_uris = HttpHelper::randomURIs(cerSubject->getUris().ocsp);
        int err_last = RET_UAPKI_OCSP_NOT_RESPONDING;
        for (auto& it : shuffled_uris) {
            sba_ocspresponse.clear();
            ret = HttpHelper::post(
                m_LibConfig->getHttp(),
                it,
                HttpHelper::CONTENT_TYPE_OCSP_REQUEST,
                sba_ocsprequest.get(),
                &sba_ocspresponse
            );
            if (ret != RET_OK) {
                err_last = ret;
                continue;
            }
            DEBUG_OUTCON(printf("validateByOcsp(), url: '%s', size: %zu\n", it.c_str(), sba_ocspresponse.size()));
            Ocsp::OcspHelper ocsp_probe;
            if (ocsp_probe.parseResponse(sba_ocspresponse.get()) != RET_OK) {
                err_last = RET_UAPKI_OCSP_RESPONSE_INVALID;
            }
            else if (ocsp_probe.getResponseStatus() != Ocsp::ResponseStatus::SUCCESSFUL) {
                err_last = RET_UAPKI_OCSP_RESPONSE_NOT_SUCCESSFUL;
            }
            else {
                ret = RET_OK;
                break;
            }
            ret = err_last;
        }
        if (ret != RET_OK) {
            ret = err_last;
        }
        if (ret != RET_OK) {
            SET_ERROR(ret);
        }
        else if (sba_ocspresponse.empty()) {
            SET_ERROR(RET_UAPKI_OCSP_RESPONSE_INVALID);
        }
    }

    pba_ocspresponse = certstatusinfo_by_ocsp.needUpdate ? sba_ocspresponse.get() : certstatusinfo_by_ocsp.baResult;
    ret = ocsp_helper.parseResponse(pba_ocspresponse);
    if (joResult) {
        DO_JSON(json_object_set_string(joResult, "responseStatus", Ocsp::responseStatusToStr(ocsp_helper.getResponseStatus())));
    }

    if (ret == RET_OK) {
        if (ocsp_helper.getResponseStatus() == Ocsp::ResponseStatus::SUCCESSFUL) {
            DO(processResponseData(
                ocsp_helper,
                cerSubject->getSerialNumber(),
                cerIssuer,
                resultValidation,
                nullptr,
                joResult
            ));

            (void)resultValidation.basicOcspResponse.set(ocsp_helper.getBasicOcspResponseEncoded(true));
            DO(ocsp_helper.getOcspIdentifier(&resultValidation.ocspIdentifier));
            if (!resultValidation.ocspResponse.set(ba_copy_with_alloc(pba_ocspresponse, 0, 0))) {
                SET_ERROR(RET_UAPKI_GENERAL_ERROR);
            }

            const uint64_t time_now = TimeUtil::mtimeNow();
            const Ocsp::OcspHelper::SingleResponseInfo& single_resp = resultValidation.singleResponseInfo;
            //  A response from the server that is not fresh now (no later nextUpdate, thisUpdate older than
            //  maxFreshness) is rejected
            if (certstatusinfo_by_ocsp.needUpdate && !ocsp_params.isFresh(single_resp.msThisUpdate, single_resp.msNextUpdate, time_now)) {
                SET_ERROR(RET_UAPKI_OCSP_RESPONSE_INVALID);
            }
            //  Cached only while it may be used from the cache (a response older than cacheTime is not cached)
            if (
                certstatusinfo_by_ocsp.needUpdate &&
                (ocsp_params.cacheValidTime(single_resp.msThisUpdate, single_resp.msNextUpdate) > time_now)
            ) {
                DO(certstatusinfo_by_ocsp.set(
                    resultValidation.singleResponseInfo.certStatus,
                    ocsp_params.cacheValidTime(
                        resultValidation.singleResponseInfo.msThisUpdate,
                        resultValidation.singleResponseInfo.msNextUpdate
                    ),
                    sba_ocspresponse.get(),
                    resultValidation.singleResponseInfo.msThisUpdate
                ));
            }
            //  "Good" by a response issued after the certificate expired: not proven (the cache keeps the response)
            resultValidation.issuedAfterExpiration = (
                (single_resp.certStatus == CertStatus::GOOD) &&
                !revocationCoversCert(cerSubject, single_resp.msThisUpdate, single_resp.msArchiveCutoff, m_CaRemovesExpiredCerts)
            );
            if (resultValidation.issuedAfterExpiration) {
                resultValidation.singleResponseInfo.certStatus = CertStatus::UNDEFINED;
                if (joResult) {
                    DO_JSON(json_object_set_string(joResult, "status", Crl::certStatusToStr(CertStatus::UNDEFINED)));
                }
            }
        }
        else {
            SET_ERROR(RET_UAPKI_OCSP_RESPONSE_NOT_SUCCESSFUL);
        }
    }

cleanup:
    return ret;
}

int CertValidator::addExpectedCert (
        const CertEntity certEntity,
        Cert::CerItem* cerItem
)
{
    ExpectedCertItem* expcert_item = new ExpectedCertItem(certEntity);
    if (!expcert_item) return RET_UAPKI_GENERAL_ERROR;

    m_ExpectedCerts.push_back(expcert_item);
    return expcert_item->setSignerIdentifier(cerItem->getSerialNumber(), cerItem->getIssuer());
}

int CertValidator::addExpectedCertByIssuerAndSN (
        const CertEntity certEntity,
        const ByteArray* baIssuerAndSN
)
{
    SmartBA sba_issuername, sba_serialnumber;
    const int ret = Cert::parseIssuerAndSN(baIssuerAndSN, &sba_issuername, &sba_serialnumber);
    if (ret != RET_OK) return ret;

    for (const auto& it : m_ExpectedCerts) {
        if (
            (ba_cmp(sba_issuername.get(), it->getIssuerName()) == 0) &&
            (ba_cmp(sba_serialnumber.get(), it->getSerialNumber()) == 0)
        ) return RET_OK;
    }

    ExpectedCertItem* expcert_item = new ExpectedCertItem(certEntity);
    if (!expcert_item) return RET_UAPKI_GENERAL_ERROR;

    m_ExpectedCerts.push_back(expcert_item);
    return expcert_item->setSignerIdentifier(sba_serialnumber.get(), sba_issuername.get());
}

int CertValidator::addExpectedCertByKeyId (
        const CertEntity certEntity,
        const ByteArray* baKeyId
)
{
    for (const auto& it : m_ExpectedCerts) {
        if (ba_cmp(baKeyId, it->getKeyId()) == 0) return RET_OK;
    }

    ExpectedCertItem* expcert_item = new ExpectedCertItem(certEntity);
    if (!expcert_item) return RET_UAPKI_GENERAL_ERROR;

    m_ExpectedCerts.push_back(expcert_item);
    return expcert_item->setSignerIdentifier(baKeyId, nullptr);
}

int CertValidator::addExpectedCertBySID (
        const CertEntity certEntity,
        const ByteArray* baSID
)
{
    SmartBA sba_keyid, sba_name, sba_serialnumber;
    const int ret = Cert::parseSID(baSID, &sba_name, &sba_serialnumber, &sba_keyid);
    if (ret != RET_OK) return ret;

    const bool is_keyid = (sba_keyid.size() > 0);
    for (const auto& it : m_ExpectedCerts) {
        if (is_keyid) {
            if (ba_cmp(sba_keyid.get(), it->getKeyId()) == 0) return RET_OK;
        }
        else {
            if (
                (ba_cmp(sba_name.get(), it->getIssuerName()) == 0) &&
                (ba_cmp(sba_serialnumber.get(), it->getSerialNumber()) == 0)
            ) return RET_OK;
        }
    }

    ExpectedCertItem* expcert_item = new ExpectedCertItem(certEntity);
    if (!expcert_item) return RET_UAPKI_GENERAL_ERROR;

    m_ExpectedCerts.push_back(expcert_item);
    return expcert_item->setSignerIdentifier((is_keyid) ? sba_keyid.get() : sba_serialnumber.get(), sba_name.get());
}

int CertValidator::addExpectedCerts (
        const vector<ExpectedCertItem*>& expectedCerts
)
{
    for (const auto it : expectedCerts) {
        ExpectedCertItem* expcert_item = new ExpectedCertItem(CertEntity::UNDEFINED);
        if (!expcert_item) return RET_UAPKI_GENERAL_ERROR;

        m_ExpectedCerts.push_back(expcert_item);
        if (expcert_item->copyFrom(it) != RET_OK) return RET_UAPKI_GENERAL_ERROR;
    }

    return RET_OK;
}

int CertValidator::addExpectedCrl (
        Cert::CerItem* cerSubject,
        Crl::CrlItem* crlFull
)
{
    if (!cerSubject) return RET_UAPKI_INVALID_PARAMETER;

    for (const auto& it : m_ExpectedCrls) {
        if (ba_cmp(cerSubject->getAuthorityKeyId(), it->getAuthorityKeyId()) == 0) return RET_OK;
    }

    ExpectedCrlItem* expcrl_item = new ExpectedCrlItem();
    if (!expcrl_item) return RET_UAPKI_GENERAL_ERROR;

    m_ExpectedCrls.push_back(expcrl_item);
    return expcrl_item->set(cerSubject, crlFull);
}

int CertValidator::addExpectedCrls (
        const vector<ExpectedCrlItem*>& expectedCrls
)
{
    for (const auto it : expectedCrls) {
        ExpectedCrlItem* expcrl_item = new ExpectedCrlItem();
        if (!expcrl_item) return RET_UAPKI_GENERAL_ERROR;

        m_ExpectedCrls.push_back(expcrl_item);
        if (expcrl_item->copyFrom(it) != RET_OK) return RET_UAPKI_GENERAL_ERROR;
    }

    return RET_OK;
}

int CertValidator::addExpectedOcspCert (
        const bool isKeyId,
        const ByteArray* baResponderId
)
{
    for (const auto& it : m_ExpectedCerts) {
        if (ba_cmp(baResponderId, isKeyId ? it->getKeyId() : it->getIssuerName()) == 0) return RET_OK;
    }

    ExpectedCertItem* expcert_item = new ExpectedCertItem(CertEntity::OCSP);
    if (!expcert_item) return RET_UAPKI_GENERAL_ERROR;

    m_ExpectedCerts.push_back(expcert_item);
    return expcert_item->setResponderId(isKeyId, baResponderId);
}

int CertValidator::expectedCertsToJson (
        JSON_Object* joResult,
        const char* keyName
)
{
    if (m_ExpectedCerts.empty()) return RET_OK;

    int ret = RET_OK;
    JSON_Array* ja_expcertitems = nullptr;
    size_t idx = 0;

    DO_JSON(json_object_set_value(joResult, keyName, json_value_init_array()));
    ja_expcertitems = json_object_get_array(joResult, keyName);

    for (const auto& it : m_ExpectedCerts) {
        DO_JSON(json_array_append_value(ja_expcertitems, json_value_init_object()));
        DO(expectedCertItemToJson(json_array_get_object(ja_expcertitems, idx++), *it));
    }

cleanup:
    return ret;
}

int CertValidator::expectedCrlsToJson (
        JSON_Object* joResult,
        const char* keyName
)
{
    if (m_ExpectedCrls.empty()) return RET_OK;

    int ret = RET_OK;
    JSON_Array* ja_expcrlitems = nullptr;
    size_t idx = 0;

    DO_JSON(json_object_set_value(joResult, keyName, json_value_init_array()));
    ja_expcrlitems = json_object_get_array(joResult, keyName);

    for (const auto& it : m_ExpectedCrls) {
        DO_JSON(json_array_append_value(ja_expcrlitems, json_value_init_object()));
        DO(expectedCrlItemToJson(json_array_get_object(ja_expcrlitems, idx++), *it));
    }

cleanup:
    return ret;
}

int CertValidator::getCrl (
        Crl::CrlStore& crlStore,
        Cert::CerStore& cerStore,
        const Cert::CerItem* cerSubject,
        const uint64_t validateTime,
        const ByteArray** baCrlNumber,
        Crl::CrlItem** crlItem,
        Cert::CerItem** cerCrlSigner,
        JSON_Object* joResult
)
{
    int ret = RET_OK, err_crl = RET_OK;
    const bool is_full = (*baCrlNumber == nullptr);
    Crl::CrlItem* crl_item = nullptr;
    const Cert::CerItem::Uris& uris = cerSubject->getUris();
    vector<string> uris_crl;
    SmartBA sba_crl;

    uris_crl = (is_full) ? uris.fullCrl : uris.deltaCrl;
    if (joResult) {
        const string s_url = Util::joinStrings(uris_crl);
        DO_JSON(json_object_set_string(joResult, "url", s_url.c_str()));
    }
    if (uris_crl.empty()) {
        SET_ERROR(RET_UAPKI_CRL_URL_NOT_PRESENT);
    }

    crl_item = crlStore.getCrl(
        cerSubject->getAuthorityKeyId(),
        is_full ? Crl::Type::FULL : Crl::Type::DELTA,
        uris.deltaCrl,
        cerSubject
    );

    {   // Download coordination is separate from the item and store locks.
        // Recheck after acquiring it: another request may have refreshed the CRL.
        const auto download_gate = crlStore.getDownloadMutex(cerSubject->getAuthorityKeyId());
        lock_guard<mutex> lock(*download_gate);
        crl_item = crlStore.getCrl(cerSubject->getAuthorityKeyId(),
            is_full ? Crl::Type::FULL : Crl::Type::DELTA, uris.deltaCrl, cerSubject);

        if (crl_item) {
            if (crl_item->getNextUpdate() < validateTime) {
                DEBUG_OUTCON(puts("CertValidator::getCrl(), need get newest CRL"));
                err_crl = RET_UAPKI_CRL_EXPIRED;
                crl_item = nullptr;
            }
            //  Issued before the required time: downloaded again (AUGMENT_CMS: revocationFreshness)
            else if ((m_RevocationMinThisUpdate > 0) && (crl_item->getThisUpdate() < m_RevocationMinThisUpdate)) {
                err_crl = RET_UAPKI_CRL_EXPIRED;
                crl_item = nullptr;
            }
            //  The strict freshness: issued before the required time and its nextUpdate is reached - a newer one
            //  is issued by now (a CRL of the signature is not expired at the time the signature is validated for)
            else if (
                (m_StrictFreshnessTime > 0) && (crl_item->getThisUpdate() < m_StrictFreshnessTime) &&
                (crl_item->getNextUpdate() <= TimeUtil::mtimeNow())
            ) {
                err_crl = RET_UAPKI_CRL_EXPIRED;
                crl_item = nullptr;
            }
        }
        else {
            err_crl = RET_UAPKI_CRL_NOT_FOUND;
        }

#ifdef TEST_SIM_BREAKDOWN_CRL
        crl_item = nullptr;
#endif
        if (!crl_item) {
            if (m_LibConfig->getOffline()) {
                SET_ERROR(err_crl);
            }
            if (uris_crl.empty()) {
                SET_ERROR(RET_UAPKI_CRL_URL_NOT_PRESENT);
            }

            //  All the distribution points of the certificate: the next one if a point does not respond, gives
            //  not a CRL of the issuer of this certificate or an expired one
            const vector<string> shuffled_uris = HttpHelper::randomURIs(uris_crl);
            int err_last = RET_UAPKI_CRL_NOT_DOWNLOADED;
            DEBUG_OUTCON(printf("CertValidator::getCrl(is full=%d), download CRL", is_full));
            for (auto& it : shuffled_uris) {
                sba_crl.clear();
                crl_item = nullptr;
                DEBUG_OUTCON(printf("CertValidator::getCrl(), HttpHelper::get('%s')\n", it.c_str()));
                ret = HttpHelper::get(m_LibConfig->getHttp(), it, &sba_crl);
                if (ret != RET_OK) {
                    err_last = RET_UAPKI_CRL_NOT_DOWNLOADED;
                    continue;
                }
                DEBUG_OUTCON(printf("CertValidator::getCrl(), url: '%s', size: %zu\n", it.c_str(), sba_crl.size()));

                //  The same way into the cache as ADD_CRL, plus: signed by the issuer of this certificate
                bool is_unique;
                ret = addCrlToStore(
                    crlStore,
                    cerStore,
                    sba_crl.get(),
                    true,
                    cerSubject,
                    is_unique,
                    &crl_item
                );
                if (ret != RET_OK) {
                    err_last = ret;
                }
                else if (!crl_item) {
                    err_last = RET_UAPKI_CRL_NOT_FOUND;
                }
                else if (crl_item->getNextUpdate() < validateTime) {
                    DEBUG_OUTCON(puts("CertValidator::getCrl(), the CRL is expired: the next distribution point"));
                    err_last = RET_UAPKI_CRL_EXPIRED;
                }
                else {
                    ret = RET_OK;
                    break;
                }
                crl_item = nullptr;
                ret = err_last;
            }
            if (ret != RET_OK) {
                SET_ERROR(err_last);
            }
        }
    }   //  end lock_guard

    //  Check CrlNumber and DeltaCrl
    if (!crl_item->getCrlNumber()) {
        SET_ERROR(RET_UAPKI_CRL_NOT_FOUND);
    }
    if (is_full) {
        *baCrlNumber = crl_item->getCrlNumber();
        DEBUG_OUTCON(printf("CertValidator::getCrl(), is full, *baCrlNumber: "); ba_print(stdout, *baCrlNumber));
    }
    else {
        DEBUG_OUTCON(printf("CertValidator::getCrl(), is delta, *baCrlNumber: "); ba_print(stdout, *baCrlNumber));
        DEBUG_OUTCON(printf("CertValidator::getCrl(), is delta, crl_item->getDeltaCrl(): "); ba_print(stdout, crl_item->getDeltaCrl()));
        if (ba_cmp(*baCrlNumber, crl_item->getDeltaCrl()) != RET_OK) {
            SET_ERROR(RET_UAPKI_CRL_NOT_FOUND);
        }
    }

    //  The signer and the signature (also of a cached CRL: it may come from ADD_CRL)
    ret = verifyCrlSigner(*crl_item, cerSubject, cerStore, cerCrlSigner);
    if (joResult) {
        (void)json_object_set_base64(joResult, "crlId", crl_item->getCrlId());
        (void)json_object_set_string(joResult, "statusSignature", Cert::verifyStatusToStr(crl_item->getStatusSign()));
    }

    if (ret == RET_OK) {
        *crlItem = crl_item;
    }

cleanup:
    if ((ret == RET_UAPKI_CERT_NOT_FOUND) && crl_item) {
        (void)addExpectedCertByKeyId(CertEntity::CRL, crl_item->getAuthorityKeyId());
    }

    return ret;
}

int CertValidator::publicKeyFromSpki (
        const ByteArray* baSpki,
        ByteArray** baPublicKey
)
{
    const uint8_t* buf = ba_get_buf_const(baSpki);
    size_t len = ba_get_len(baSpki);
    uint32_t tag = 0;
    size_t hlen = 0, vlen = 0;

    if (!buf || !Util::decodeAsn1Header(buf, len, tag, hlen, vlen) || (tag != 0x30) || (hlen + vlen > len)) return RET_UAPKI_INVALID_STRUCT;
    buf += hlen;
    len = vlen;
    //  algorithm
    if (!Util::decodeAsn1Header(buf, len, tag, hlen, vlen) || (tag != 0x30) || (hlen + vlen > len)) return RET_UAPKI_INVALID_STRUCT;
    buf += hlen + vlen;
    len -= hlen + vlen;
    //  subjectPublicKey
    if (!Util::decodeAsn1Header(buf, len, tag, hlen, vlen) || (tag != 0x03) || (vlen < 1) || (hlen + vlen > len)) return RET_UAPKI_INVALID_STRUCT;

    *baPublicKey = ba_alloc_from_uint8(buf + hlen + 1, vlen - 1);
    return (*baPublicKey) ? RET_OK : RET_UAPKI_GENERAL_ERROR;
}

int CertValidator::verifyCrlIssuer (
        Crl::CrlItem& crlItem,
        Cert::CerStore& cerStore,
        Cert::CerItem** cerCrlSigner
)
{
    //  Signed by its issuer: the certificate with the key id and the name of the CRL issuer, having cRLSign
    const int ret = cerStore.getCertByKeyId(crlItem.getAuthorityKeyId(), cerCrlSigner);
    if (ret != RET_OK) return ret;

    if (ba_cmp(crlItem.getIssuer(), (*cerCrlSigner)->getSubject()) != 0) return RET_UAPKI_CRL_NOT_FOUND;
    if (!checkCertUsage(CertEntity::CRL, *cerCrlSigner)) return RET_UAPKI_INVALID_KEY_USAGE;

    return crlItem.verify(*cerCrlSigner);
}

//  The root a certificate chains to in the store, every link verified; nullptr if there is no such path
static const Cert::CerItem* path_root (
        Cert::CerStore& cerStore,
        const Cert::CerItem* cerItem
)
{
    vector<Cert::CerItem*> chain;
    if (cerStore.getChainCerts(cerItem, chain) != RET_OK) return nullptr;

    //  The path ends at the first trusted certificate, as in buildCertChain(). The certificate itself is the
    //  anchor of its path only when it is a trusted CA (a signer of CRLs of its own certificates); a trusted
    //  end-entity certificate (a TSA or an OCSP responder of a trusted list) has the path of its issuer
    //  Whether a CRL signer has the path of the certificate does not depend on the time: a certificate that may be
    //  a trust anchor (of INIT or of a trusted list, whatever its service is now) ends the path
    if (cerItem->isTrustAnchorCandidate() && cerItem->getCertExtKeyUsage().isCa()) return cerItem;
    const Cert::CerItem* cer_subject = cerItem;
    for (const auto it : chain) {
        if (cer_subject->verifySignatureBy(it->getSpki()) != RET_OK) return nullptr;
        cer_subject = it;
        if (cer_subject->isTrustAnchorCandidate()) return cer_subject;
    }
    if (!cer_subject->isSelfSigned() || (cer_subject->verifySignatureBy(cer_subject->getSpki()) != RET_OK)) return nullptr;
    return cer_subject;
}

int CertValidator::verifyCrlSigner (
        Crl::CrlItem& crlItem,
        const Cert::CerItem* cerSubject,
        Cert::CerStore& cerStore,
        Cert::CerItem** cerCrlSigner
)
{
    //  RFC 5280 without indirect CRLs: the CRL issuer is the issuer of the certificate (its name)
    if (ba_cmp(crlItem.getIssuer(), cerSubject->getIssuer()) != 0) return RET_UAPKI_CRL_NOT_FOUND;

    //  The signer: the certificate with the key id and the name of the CRL issuer, cRLSign, the signature
    const int ret = verifyCrlIssuer(crlItem, cerStore, cerCrlSigner);
    if (ret != RET_OK) return ret;

    //  The very key that signed the certificate - not just a certificate with the same key id
    if (cerSubject->verifySignatureBy((*cerCrlSigner)->getSpki()) == RET_OK) return RET_OK;

    //  A delegated CRL signer (RFC 5280, 6.3.3 f): another key of the same issuer - the same name and
    //  cRLSign (checked above), valid when the CRL was issued, its path leading to the same root
    const Cert::CerItem* cer_signer = *cerCrlSigner;
    if (cer_signer->checkValidity(crlItem.getThisUpdate()) != RET_OK) return RET_UAPKI_CRL_NOT_FOUND;
    const Cert::CerItem* root_subject = path_root(cerStore, cerSubject);
    const Cert::CerItem* root_signer = path_root(cerStore, cer_signer);
    if (!root_subject || (root_subject != root_signer)) return RET_UAPKI_CRL_NOT_FOUND;
    return RET_OK;
}

int CertValidator::addCrlToStore (
        Crl::CrlStore& crlStore,
        Cert::CerStore& cerStore,
        const ByteArray* baEncoded,
        const bool permanent,
        const Cert::CerItem* cerSubject,
        bool& isUnique,
        Crl::CrlItem** crlItem
)
{
    int ret = RET_OK;
    Crl::CrlItem* parsed_crl = nullptr;
    Cert::CerItem* cer_signer = nullptr;
    SmartBA sba_parsed;

    //  Checked before it is stored: a stored CRL with a greater number makes the older ones obsolete
    if (!sba_parsed.set(ba_copy_with_alloc(baEncoded, 0, 0))) return RET_UAPKI_GENERAL_ERROR;
    ret = Crl::parseCrl(sba_parsed.get(), &parsed_crl);
    if (ret != RET_OK) return ret;
    (void)sba_parsed.pop();     //  owned by parsed_crl

    if (cerSubject) {
        //  Downloaded for this certificate: of its segment and signed for its issuer
        ret = parsed_crl->coversCert(cerSubject)
            ? verifyCrlSigner(*parsed_crl, cerSubject, cerStore, &cer_signer)
            : RET_UAPKI_CRL_NOT_FOUND;
    }
    else {
        ret = verifyCrlIssuer(*parsed_crl, cerStore, &cer_signer);
    }
    delete parsed_crl;
    if (ret != RET_OK) return ret;

    return crlStore.addCrl(baEncoded, permanent, isUnique, crlItem);
}

int CertValidator::processResponseData (
        Ocsp::OcspHelper& ocspHelper,
        const ByteArray* baSerialNumber,
        Cert::CerItem* cerIssuer,
        ResultValidationByOcsp& resultValidation,
        std::vector<Cert::CerItem*>* addedCerts,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    size_t idx_certid = 0;
    const ByteArray* ba_certid = nullptr;
    VectorBA vba_encodedcerts;
    vector<Cert::CerStore::AddedCerItem> added_ceritems;
    SmartBA sba_publickey;
    string s_time;

    if (!baSerialNumber) return RET_UAPKI_INVALID_PARAMETER;

    if (joResult) {
        DO_JSON(json_object_set_string(joResult, "status", Crl::certStatusToStr(CertStatus::UNDEFINED)));
    }

    DO(ocspHelper.getCerts(vba_encodedcerts));
    if (!vba_encodedcerts.empty()) {
        DO(m_CerStore->addCerts(
            Cert::NOT_TRUSTED,
            Cert::NOT_PERMANENT,
            vba_encodedcerts,
            added_ceritems
        ));
        for (auto& it : added_ceritems) {
            if (it.cerItem) {
                if (addedCerts) {
                    addedCerts->push_back(it.cerItem);
                }
                if (it.cerItem->equalSerialNumber(baSerialNumber)) {
                    ba_certid = it.cerItem->getCertId();
                }
            }
        }
    }

    if (joResult) {
        DO_JSON(json_object_set_value(joResult, "certIds", json_value_init_array()));
        JSON_Array* ja_certids = json_object_get_array(joResult, "certIds");
        for (auto& it : added_ceritems) {
            DO(json_array_append_base64(ja_certids, it.cerItem->getCertId()));
        }

        if (ba_certid) {
            DO_JSON(json_object_set_base64(joResult, "certId", ba_certid));
        }

        s_time = TimeUtil::mtimeToFtime(ocspHelper.getProducedAt());
        DO_JSON(json_object_set_string(joResult, "producedAt", s_time.c_str()));
    }

    //  The response may hold several certificates: only the one about this certificate of this issuer
    //  counts. Without the issuer certificate (CERT_STATUS_BY_OCSP by hashes) - by the serial number
    if (cerIssuer) {
        (void)publicKeyFromSpki(cerIssuer->getSpki(), &sba_publickey);
        DO(ocspHelper.findSingleResponse(
            cerIssuer->getSubject(),
            cerIssuer->getKeyId(),
            sba_publickey.get(),
            baSerialNumber,
            idx_certid
        ));
    }
    else {
        SmartBA sba_serialnumber;
        DO(ocspHelper.getSerialNumberFromCertId(idx_certid, &sba_serialnumber));
        if (ba_cmp(sba_serialnumber.get(), baSerialNumber) != 0) {
            SET_ERROR(RET_UAPKI_OCSP_RESPONSE_INVALID);
        }
    }
    DO(ocspHelper.scanSingleResponses());
    resultValidation.singleResponseInfo = ocspHelper.getSingleResponseInfo(idx_certid);
    resultValidation.msProducedAt = ocspHelper.getProducedAt();
    (void)ocspHelper.getSignatureAlgorithm(resultValidation.signAlgo);

    if (joResult) {
        auto& res_singlerespinfo = resultValidation.singleResponseInfo;
        DO_JSON(json_object_set_string(joResult, "status", Crl::certStatusToStr(res_singlerespinfo.certStatus)));

        s_time = TimeUtil::mtimeToFtime(res_singlerespinfo.msThisUpdate);
        DO_JSON(json_object_set_string(joResult, "thisUpdate", s_time.c_str()));

        if (res_singlerespinfo.msNextUpdate > 0) {
            s_time = TimeUtil::mtimeToFtime(res_singlerespinfo.msNextUpdate);
            DO_JSON(json_object_set_string(joResult, "nextUpdate", s_time.c_str()));
        }

        if (res_singlerespinfo.certStatus == UapkiNS::CertStatus::REVOKED) {
            DO_JSON(json_object_set_string(joResult, "revocationReason", Crl::crlReasonToStr(res_singlerespinfo.revocationReason)));
            s_time = TimeUtil::mtimeToFtime(res_singlerespinfo.msRevocationTime);
            DO_JSON(json_object_set_string(joResult, "revocationTime", s_time.c_str()));
        }
    }

    DO(ocspHelper.checkNonce());
    DO(verifyResponseData(ocspHelper, cerIssuer, resultValidation, joResult));

cleanup:
    return ret;
}

int CertValidator::verifyResponseData (
        Ocsp::OcspHelper& ocspHelper,
        Cert::CerItem* cerIssuer,
        ResultValidationByOcsp& resultValidation,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    SignatureVerifyStatus status_sign = SignatureVerifyStatus::UNDEFINED;

    resultValidation.statusSignature = SignatureVerifyStatus::UNDEFINED;
    resultValidation.cerResponder = nullptr;
    //  The result may be filled again (the status is looked for once more)
    resultValidation.baResponderId.clear();
    DO(ocspHelper.getResponderId(resultValidation.responderIdType, &resultValidation.baResponderId));
    if (joResult) {
        DO(responderIdToJson(joResult, resultValidation.responderIdType, resultValidation.baResponderId.get()));
    }
    if (resultValidation.responderIdType == Ocsp::ResponderIdType::BY_NAME) {
        //  The name may belong to several certificates: a responder certificate is issued again with the same subject
        //  and a new key. The responder is the one whose key verifies the response - first those valid when it was
        //  produced, the latest of them first; none verifies it - the first of them (the signature is INVALID)
        vector<Cert::CerItem*> cer_responders;
        m_CerStore->getCertsBySubject(resultValidation.baResponderId.get(), cer_responders);
        ret = cer_responders.empty() ? RET_UAPKI_CERT_NOT_FOUND : RET_OK;
        if (ret == RET_OK) {
            const uint64_t ms_produced = resultValidation.msProducedAt;
            const auto valid_when_produced = [ms_produced](const Cert::CerItem* cerItem) {
                return (cerItem->getNotBefore() <= ms_produced) && (ms_produced <= cerItem->getNotAfter());
            };
            std::stable_sort(cer_responders.begin(), cer_responders.end(),
                [&valid_when_produced](const Cert::CerItem* a, const Cert::CerItem* b) {
                    const bool a_valid = valid_when_produced(a), b_valid = valid_when_produced(b);
                    if (a_valid != b_valid) return a_valid;
                    return a->getNotBefore() > b->getNotBefore();
                }
            );
            resultValidation.cerResponder = cer_responders[0];
            if (cer_responders.size() > 1) {
                for (const auto& it : cer_responders) {
                    SignatureVerifyStatus status_candidate = SignatureVerifyStatus::UNDEFINED;
                    if (
                        (ocspHelper.verifyTbsResponseData(it->getSpki(), status_candidate) == RET_OK) &&
                        (status_candidate == SignatureVerifyStatus::VALID)
                    ) {
                        resultValidation.cerResponder = it;
                        break;
                    }
                }
            }
        }
    }
    else {
        //  responder_idtype == OcspHelper::ResponderIdType::BY_KEY
        ret = m_CerStore->getCertByKeyId(resultValidation.baResponderId.get(), &resultValidation.cerResponder);
    }
    if (ret == RET_UAPKI_CERT_NOT_FOUND) {
        resultValidation.statusSignature = SignatureVerifyStatus::INDETERMINATE;
        const int ret2 = addExpectedOcspCert(
            (resultValidation.responderIdType != Ocsp::ResponderIdType::BY_NAME),
            resultValidation.baResponderId.get()
        );
        SET_ERROR((ret2 == RET_OK) ? ret : ret2);
    }
    DO(ret);

    ret = ocspHelper.verifyTbsResponseData(resultValidation.cerResponder->getSpki(), status_sign);
    if ((ret == RET_OK) && cerIssuer) {
        //  A valid signature counts only from a responder authorized for certificates of this issuer
        ret = authorizeOcspResponder(resultValidation.cerResponder, cerIssuer, resultValidation.msProducedAt);
        if (ret != RET_OK) {
            status_sign = SignatureVerifyStatus::INVALID;
        }
    }
    else if (ret == RET_VERIFY_FAILED) {
        ret = RET_UAPKI_OCSP_RESPONSE_VERIFY_FAILED;
    }
    else {
        ret = RET_UAPKI_OCSP_RESPONSE_VERIFY_ERROR;
    }
    resultValidation.statusSignature = status_sign;
    if (joResult) {
        DO_JSON(json_object_set_string(joResult, "statusSignature", verifyStatusToStr(status_sign)));
    }

cleanup:
    return ret;
}

int CertValidator::authorizeOcspResponder (
        Cert::CerItem* cerResponder,
        Cert::CerItem* cerIssuer,
        const uint64_t producedAt
)
{
    if (!cerResponder || !cerIssuer) return RET_UAPKI_INVALID_PARAMETER;

    //  RFC 6960, 4.2.2.2: the issuer of the certificate itself, or its delegate with the extended key
    //  usage id-kp-OCSPSigning, recognized "only if the delegation certificate and the certificate being
    //  checked for revocation were signed by the same key" - not by another key of the same CA
    if (
        cerResponder->equalCertId(cerIssuer->getCertId()) ||
        (ba_cmp(cerResponder->getSpki(), cerIssuer->getSpki()) == 0)
    ) {
        return RET_OK;
    }

    if (!checkCertUsage(CertEntity::OCSP, cerResponder)) return RET_UAPKI_INVALID_KEY_USAGE;
    if (
        !cerIssuer->equalKeyId(cerResponder->getAuthorityKeyId()) ||
        (cerResponder->verifySignatureBy(cerIssuer->getSpki()) != RET_OK)
    ) {
        return RET_UAPKI_CERT_CHAIN_NOT_FOUND;
    }
    if (producedAt > 0) {
        const int ret = cerResponder->checkValidity(producedAt);
        if (ret != RET_OK) return ret;
    }

    return RET_OK;
}

int CertValidator::verifySignatureSignerInfo (
        const CertEntity certEntity,
        Pkcs7::SignedDataParser::SignerInfo& signerInfo,
        Cert::CerItem** cerSigner
)
{
    int ret = RET_OK;
    switch (signerInfo.getSidType()) {
    case Pkcs7::SignerIdentifierType::ISSUER_AND_SN:
    case Pkcs7::SignerIdentifierType::SUBJECT_KEYID:
        ret = getCertBySID(certEntity, signerInfo.getSidEncoded(), cerSigner);
        break;
    default:
        ret = RET_UAPKI_INVALID_STRUCT;
    }

    if (ret == RET_OK) {
        ret = Verify::verifySignature(
            signerInfo.getSignatureAlgorithm().algorithm.c_str(),
            signerInfo.getSignedAttrsEncoded(),
            false,
            (*cerSigner)->getSpki(),
            signerInfo.getSignature(),
            signerInfo.getDigestAlgorithm().algorithm.c_str(),
            signerInfo.getSignatureAlgorithm().baParameters
        );
    }

    return ret;
}


int addUniqueItem (
        vector<Cert::CerItem*>& chainItems,
        Cert::CerItem* cerItem
)
{
    if (!cerItem) return RET_UAPKI_INVALID_PARAMETER;

    if (!findItemByCertId(chainItems, cerItem)) {
        chainItems.push_back(cerItem);
    }

    return RET_OK;
}

int addUniqueItem (
        vector<CertChainItem*>& chainItems,
        const CertEntity certEntity,
        Cert::CerItem* cerItem
)
{
    if (!cerItem) return RET_OK;

    for (const auto it : chainItems) {
        if (cerItem->equalCertId(it->getSubjectCertId())) {
            return RET_OK;
        }
    }

    CertChainItem* entity = new CertChainItem(certEntity, cerItem);
    if (!entity) return RET_UAPKI_GENERAL_ERROR;

    chainItems.push_back(entity);

    return RET_OK;
}

ChainConstraint checkChainConstraints (
        const CertChainItem& chainItem,
        const vector<CertChainItem*>& chain,
        const bool checkCriticalExtensions
)
{
    const Cert::CerItem* cer_subject = chainItem.getSubject();
    if (!cer_subject) return ChainConstraint::NONE;

    //  A trust anchor is not a part of the path (RFC 5280, 6.1)
    if (
        checkCriticalExtensions &&
        cer_subject->hasUnknownCriticalExtension() &&
        !((chainItem.getCertEntity() == CertEntity::ROOT) && chainItem.isTrusted())
    ) {
        return ChainConstraint::UNKNOWN_CRITICAL_EXTENSION;
    }

    switch (chainItem.getCertEntity()) {
    case CertEntity::SIGNER:
        if (cer_subject->hasOcspNoCheckExtension()) {
            return ChainConstraint::FORBIDDEN_EXTENSION;
        }
        //  Without keyUsage the key is not restricted
        if (
            (cer_subject->getKeyUsage() != 0) &&
            !cer_subject->keyUsageByBit(KeyUsage_digitalSignature) &&
            !cer_subject->keyUsageByBit(KeyUsage_nonRepudiation)
        ) {
            return ChainConstraint::SIGNER_KEY_USAGE;
        }
        break;
    case CertEntity::TSP:
        if (cer_subject->hasOcspNoCheckExtension()) {
            return ChainConstraint::FORBIDDEN_EXTENSION;
        }
        if (!cer_subject->getCertExtKeyUsage().isTsp()) {
            return ChainConstraint::TSP_KEY_PURPOSE;
        }
        break;
    default:
        break;
    }

    //  The issuers above an end entity: CA, and not more intermediate certificates below than pathLenConstraint
    switch (chainItem.getCertEntity()) {
    case CertEntity::UNDEFINED:     //  VERIFY_CERT: the certificate itself
    case CertEntity::SIGNER:
    case CertEntity::TSP:
    case CertEntity::OCSP:
    case CertEntity::CRL:
        break;
    default:
        return ChainConstraint::NONE;
    }
    size_t cnt_intermediates = 0;
    const Cert::CerItem* cer_current = cer_subject;
    for (size_t guard = 0; guard < chain.size(); guard++) {
        const CertChainItem* item_current = nullptr;
        for (const auto& it : chain) {
            if (it->getSubject() == cer_current) {
                item_current = it;
                break;
            }
        }
        if (!item_current) break;

        const Cert::CerItem* cer_issuer = item_current->getIssuer();
        if (!cer_issuer || (cer_issuer == cer_current)) break;  //  the issuer is missing or the root

        //  As OpenSSL check_ca(): an intermediate CA has basicConstraints cA, a root without basicConstraints
        //  is accepted with keyCertSign (legacy); keyCertSign itself is checked with the signature (CerItem::verify)
        //  A CA certificate (not a trust anchor) without ocsp-nocheck and noRevAvail
        if (
            (cer_issuer->hasOcspNoCheckExtension() || cer_issuer->hasNoRevAvailExtension()) &&
            !cer_issuer->isTrustAnchorCandidate()
        ) {
            return ChainConstraint::FORBIDDEN_EXTENSION;
        }
        if (!cer_issuer->getCertExtKeyUsage().isCa()) {
            const bool legacy_root = cer_issuer->isSelfSigned() &&
                !cer_issuer->getCertExtKeyUsage().isCaExtnPresent() &&
                cer_issuer->keyUsageByBit(KeyUsage_keyCertSign);
            if (!legacy_root) return ChainConstraint::ISSUER_NOT_CA;
        }
        const int path_len = cer_issuer->getCertExtKeyUsage().pathLen();
        if ((path_len >= 0) && (cnt_intermediates > (size_t)path_len)) return ChainConstraint::PATH_LENGTH;

        //  A self-issued certificate (key rollover) does not count, RFC 5280, 6.1.4 (l)
        if (ba_cmp(cer_issuer->getSubject(), cer_issuer->getIssuer()) != 0) {
            cnt_intermediates++;
        }
        cer_current = cer_issuer;
    }

    return ChainConstraint::NONE;
}

bool revocationCoversCert (
        const Cert::CerItem* cerSubject,
        const uint64_t msThisUpdate,
        const uint64_t msExpiredCertsSince,
        const bool caRemovesExpiredCerts
)
{
    if (!cerSubject) return false;

    uint64_t known_since = msThisUpdate;
    if (msExpiredCertsSince > 0) {
        //  A date not before thisUpdate says nothing more (as EU DSS)
        if (msExpiredCertsSince < known_since) {
            known_since = msExpiredCertsSince;
        }
    }
    else if (!caRemovesExpiredCerts) {
        return true;
    }
    return (cerSubject->getNotAfter() >= known_since);
}

const char* chainConstraintToStr (
        const ChainConstraint chainConstraint
)
{
    switch (chainConstraint) {
    case ChainConstraint::ISSUER_NOT_CA:
        return "THE ISSUER CERTIFICATE IS NOT A CA CERTIFICATE";
    case ChainConstraint::PATH_LENGTH:
        return "THE PATH LENGTH CONSTRAINT OF A CA CERTIFICATE IS EXCEEDED";
    case ChainConstraint::SIGNER_KEY_USAGE:
        return "THE KEY USAGE OF THE SIGNER CERTIFICATE DOES NOT ALLOW SIGNING";
    case ChainConstraint::TSP_KEY_PURPOSE:
        return "THE TSA CERTIFICATE HAS NO TIME-STAMPING KEY PURPOSE";
    case ChainConstraint::UNKNOWN_CRITICAL_EXTENSION:
        return "THE CERTIFICATE HAS AN UNSUPPORTED CRITICAL EXTENSION";
    case ChainConstraint::FORBIDDEN_EXTENSION:
        return "THE CERTIFICATE HAS A FORBIDDEN EXTENSION (OCSP-NOCHECK OR NOREVAVAIL)";
    default:
        return "";
    }
}

bool checkCertUsage (
        const CertEntity certEntity,
        const Cert::CerItem* cerItem
)
{
    if (!cerItem) return false;

    bool ok = false;
    switch (certEntity) {
    case CertEntity::SIGNER:
        ok = cerItem->keyUsageByBit(KeyUsage_digitalSignature);
        break;
    case CertEntity::CRL:
        ok = cerItem->keyUsageByBit(KeyUsage_crlSign);
        break;
    case CertEntity::OCSP:
        ok = cerItem->getCertExtKeyUsage().isOcsp();
        break;
    case CertEntity::TSP:
        ok = cerItem->getCertExtKeyUsage().isTsp();
        break;
    case CertEntity::CA:
    case CertEntity::ROOT:
        ok = cerItem->getCertExtKeyUsage().isCa();
        break;
    default:
        break;
    }

    return ok;
}

const char* certEntityToStr (
        const CertEntity certEntity
)
{
    static const char* CERT_ENTITY_STRINGS[10] = {
        "UNDEFINED",
        "SIGNER",
        "ORIGINATOR",
        "RECIPIENT",
        "INTERMEDIATE",
        "CRL",
        "OCSP",
        "TSP",
        "CA",
        "ROOT"
    };
    return CERT_ENTITY_STRINGS[((uint32_t)certEntity < 10) ? (uint32_t)certEntity : 0];
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

bool findItemByCertId (
        vector<Cert::CerItem*>& chainItems,
        Cert::CerItem* cerItem
)
{
    if (cerItem) {
        for (const auto it : chainItems) {
            if (cerItem->equalCertId(it->getCertId())) {
                return true;
            }
        }
    }

    return false;
}   //  findItemByCertId

bool findItemByCertId (
        vector<CertChainItem*>& chainItems,
        Cert::CerItem* cerItem
)
{
    if (cerItem) {
        for (const auto it : chainItems) {
            if (cerItem->equalCertId(it->getSubjectCertId())) {
                return true;
            }
        }
    }

    return false;
}   //  findItemByCertId

bool findItemByKeyId (
        vector<CertChainItem*>& chainItems,
        const ByteArray* baKeyId
)
{
    for (const auto it : chainItems) {
        if (ba_cmp(baKeyId, it->getSubjectKeyId()) == 0) {
            return true;
        }
    }

    return false;
}   //  findItemByKeyId

int expectedCertItemToJson (
        JSON_Object* joResult,
        const ExpectedCertItem& expectedCertItem
)
{
    int ret = RET_OK;

    DO_JSON(json_object_set_string(joResult, "entity", certEntityToStr(expectedCertItem.getCertEntity())));
    switch (expectedCertItem.getIdType()) {
    case ExpectedCertItem::IdType::CER_IDTYPE:
        if (!expectedCertItem.getKeyId()) {
            DO_JSON(json_object_set_value(joResult, "issuer", json_value_init_object()));
            DO(nameToJson(json_object_get_object(joResult, "issuer"), expectedCertItem.getIssuerName()));
            DO(json_object_set_hex(joResult, "serialNumber", expectedCertItem.getSerialNumber()));
            DO(json_object_set_base64(joResult, "issuerBytes", expectedCertItem.getIssuerName()));
        }
        else {
            DO(json_object_set_hex(joResult, "keyId", expectedCertItem.getKeyId()));
        }
        break;
    case ExpectedCertItem::IdType::ORS_IDTYPE:
        if (!expectedCertItem.getKeyId()) {
            DO_JSON(json_object_set_value(joResult, "responderId", json_value_init_object()));
            DO(nameToJson(json_object_get_object(joResult, "responderId"), expectedCertItem.getIssuerName()));
        }
        else {
            DO(json_object_set_hex(joResult, "responderId", expectedCertItem.getKeyId()));
        }
        break;
    default:
        break;
    }

cleanup:
    return ret;
}   //  expectedCertItemToJson

int expectedCrlItemToJson (
        JSON_Object* joResult,
        const ExpectedCrlItem& expectedCrlItem
)
{
    int ret = RET_OK;

    //  The issuer may have no key identifier (a certificate without authorityKeyIdentifier)
    if (expectedCrlItem.getAuthorityKeyId()) {
        DO(json_object_set_hex(joResult, "authorityKeyId", expectedCrlItem.getAuthorityKeyId()));
    }
    if (expectedCrlItem.getName()) {
        DO_JSON(json_object_set_value(joResult, "issuer", json_value_init_object()));
        DO(nameToJson(json_object_get_object(joResult, "issuer"), expectedCrlItem.getName()));
    }
    if (!expectedCrlItem.getUrl().empty()) {
        DO_JSON(json_object_set_string(joResult, "url", expectedCrlItem.getUrl().c_str()));
    }
    if (expectedCrlItem.isPresentFullCrl()) {
        DO_JSON(json_object_set_value(joResult, "full", json_value_init_object()));
        JSON_Object* jo_crlinfo = json_object_get_object(joResult, "full");
        DO_JSON(json_object_set_string(jo_crlinfo, "thisUpdate", TimeUtil::mtimeToFtime(expectedCrlItem.getThisUpdate()).c_str()));
        DO_JSON(json_object_set_string(jo_crlinfo, "nextUpdate", TimeUtil::mtimeToFtime(expectedCrlItem.getNextUpdate()).c_str()));
        DO(json_object_set_hex(jo_crlinfo, "crlNumber", expectedCrlItem.getCrlNumber()));
    }

cleanup:
    return ret;
}   //  expectedCrlItemToJson

int responderIdToJson (
        JSON_Object* joResult,
        const Ocsp::ResponderIdType responderIdType,
        const ByteArray* baResponderId
)
{
    int ret = RET_OK;
    Name_t* name = nullptr;

    switch (responderIdType) {
    case Ocsp::ResponderIdType::BY_NAME:
        CHECK_NOT_NULL(name = (Name_t*)asn_decode_ba_with_alloc(get_Name_desc(), baResponderId));
        DO_JSON(json_object_set_value(joResult, "responderId", json_value_init_object()));
        DO(nameToJson(json_object_get_object(joResult, "responderId"), *name));
        break;
    case Ocsp::ResponderIdType::BY_KEY:
        DO(json_object_set_hex(joResult, "responderId", baResponderId));
        break;
    default:
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

cleanup:
    asn_free(get_Name_desc(), name);
    return ret;
}   //  responderIdToJson


}   //  end namespace CertValidator

}   //  end namespace UapkiNS
