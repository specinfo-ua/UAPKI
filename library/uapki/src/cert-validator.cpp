/*
 * Copyright (c) 2021, The UAPKI Project Authors.
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

int CertValidator::getStatus (
        Cert::CerItem* cerItem,
        const CertEntity certEntity,
        const uint64_t validateTime
)
{
    if (!cerItem) return RET_UAPKI_INVALID_PARAMETER;

    CertChainItem* entity = new CertChainItem(certEntity, cerItem);
    if (!entity) return RET_UAPKI_GENERAL_ERROR;

    m_CertChain.push_back(entity);
    if (m_ValidationType <= Cert::ValidationType::NONE) return RET_OK;

    int ret = RET_OK;
    vector<Cert::CerItem*> chain_certs, obtained_certs;
    size_t idx_root;
    CertEntity expected_certentity = CertEntity::UNDEFINED;

    //  build a chain of certs
    ret = m_CerStore->getChainCerts(cerItem, chain_certs);
    if (ret != RET_OK) {
        if (((ret == RET_UAPKI_CERT_ISSUER_NOT_FOUND) || (ret == RET_UAPKI_CERT_NOT_FOUND)) && !chain_certs.empty()) {
            (void)addExpectedCertByKeyId(CertEntity::INTERMEDIATE, chain_certs[chain_certs.size() - 1]->getAuthorityKeyId());
        }
        SET_ERROR(ret);
    }
    for (auto it : chain_certs) {
        entity = new CertChainItem(CertEntity::INTERMEDIATE, it);
        if (!entity) return RET_UAPKI_GENERAL_ERROR;
        m_CertChain.push_back(entity);
    }
    chain_certs.clear();

    //  check signature in chain-certs
    idx_root = m_CertChain.size() - 1;
    entity = m_CertChain[idx_root];
    DO(entity->getSubject()->verify(entity->getSubject(), true));
    entity->setRoot();
    for (size_t i = 0; i < idx_root; i++) {
        entity = m_CertChain[i];
        DO(entity->getSubject()->verify(m_CertChain[i + 1]->getSubject(), true));
        entity->setIssuer(m_CertChain[i + 1]->getSubject());
    }

    //  check validity in chain-certs
    for (auto it : m_CertChain) {
        DO(it->getSubject()->checkValidity(validateTime));
    }

    //  check status in chain-certs
    if (m_ValidationType == Cert::ValidationType::OCSP) {
        expected_certentity = CertEntity::OCSP;
        for (size_t i = 0; i < idx_root; i++) {
            entity = m_CertChain[i];
            DO(validateByOcsp(
                entity->getSubject(),
                entity->getIssuer(),
                entity->getResultValidationByOcsp()
            ));
            DO(addUniqueItem(obtained_certs, entity->getResultValidationByOcsp().cerResponder));
        }
    }
    else if (m_ValidationType == Cert::ValidationType::CRL) {
        expected_certentity = CertEntity::CRL;
        for (size_t i = 0; i < idx_root; i++) {
            entity = m_CertChain[i];
            DO(validateByCrl(
                entity->getSubject(),
                validateTime,
                true,
                entity->getResultValidationByCrl()
            ));
            DO(addUniqueItem(obtained_certs, entity->getResultValidationByCrl().cerIssuer));
        }
    }

    //  check restrictions
    if (!checkCertUsage(certEntity, cerItem)) {
        SET_ERROR(RET_UAPKI_INVALID_KEY_USAGE);
    }
    entity = m_CertChain[idx_root];
    if (!entity->getSubject()->getCertExtKeyUsage().isCa()) {
        SET_ERROR(RET_UAPKI_INVALID_KEY_USAGE);
    }
    for (const auto it : obtained_certs) {
        if (!checkCertUsage(expected_certentity, it)) {
            SET_ERROR(RET_UAPKI_INVALID_KEY_USAGE);
        }
    }

    //  check obtained certs
    if (m_ValidationType == Cert::ValidationType::OCSP) {
        for (auto it_obtcert : obtained_certs) {
            if (
                !findItemByKeyId(m_CertChain, it_obtcert->getAuthorityKeyId()) &&
                !findItemByKeyId(m_CertChain, it_obtcert->getKeyId())
            ) {
                (void)addExpectedCert(CertEntity::OCSP, it_obtcert);
                SET_ERROR(RET_UAPKI_CERT_CHAIN_NOT_FOUND);
            }

            if (!it_obtcert->getUris().ocsp.empty()) {
                Cert::CerItem* cer_issuer = nullptr;
                bool is_selfsigned;
                ResultValidationByOcsp result_validation;
                DO(m_CerStore->getIssuerCert(it_obtcert, &cer_issuer, is_selfsigned));
                DO(validateByOcsp(it_obtcert, cer_issuer, result_validation));
            }

            DO(addUniqueItem(m_ObtainedCerts, CertEntity::OCSP, it_obtcert));
        }
    }
    else if (m_ValidationType == Cert::ValidationType::CRL) {
        for (const auto it_obtcert : obtained_certs) {
            if (
                !findItemByKeyId(m_CertChain, it_obtcert->getKeyId()) &&
                !findItemByKeyId(m_CertChain, it_obtcert->getAuthorityKeyId())
            ) {
                (void)addExpectedCert(CertEntity::CRL, it_obtcert);
                SET_ERROR(RET_UAPKI_CERT_CHAIN_NOT_FOUND);
            }
        }
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

    lock_guard<mutex> lock(cerSubject->getMutex());

    int ret = RET_OK;
    Crl::CrlItem* crl_item = nullptr;
    vector<const Crl::RevokedCertItem*> revoked_items;
    JSON_Object* joDelta = nullptr;
    JSON_Object* joFull = nullptr;
    const ByteArray* ba_crlnumber = nullptr;
    bool is_found;

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
    is_found = Crl::findRevokedCert(
        revoked_items,
        validateTime,
        resultValidation.certStatus,
        resultValidation.revokedCertItem
    );
    if (is_found && (resultValidation.crlItem->getVersion() == 1)) {
        resultValidation.certStatus = CertStatus::REVOKED;
        resultValidation.revokedCertItem.crlReason = UapkiNS::CrlReason::UNSPECIFIED;
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
            resultValidation.certStatus,
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

    lock_guard<mutex> lock(cerSubject->getMutex());

    int ret = RET_OK;
    const LibraryConfig::OcspParams& ocsp_params = m_LibConfig->getOcsp();
    Cert::CertStatusInfo& certstatusinfo_by_ocsp = cerSubject->getCertStatusByOcsp();
    Ocsp::OcspHelper ocsp_helper;
    SmartBA sba_ocsprequest, sba_ocspresponse;
    const ByteArray* pba_ocspresponse = nullptr;

    if (joResult) {
        DO_JSON(json_object_set_string(joResult, "status", Crl::certStatusToStr(UapkiNS::CertStatus::UNDEFINED)));
    }

    if (HttpHelper::isOfflineMode()) {
        SET_ERROR(RET_UAPKI_OFFLINE_MODE);
    }

    if (certstatusinfo_by_ocsp.isExpired(TimeUtil::mtimeNow())) {
        vector<string> shuffled_uris;

        if (cerSubject->getUris().ocsp.empty()) {
            SET_ERROR(RET_UAPKI_OCSP_URL_NOT_PRESENT);
        }

        DO(ocsp_helper.init());
        DO(ocsp_helper.addCert(cerIssuer, cerSubject));
        if (ocsp_params.nonceLen > 0) {
            DO(ocsp_helper.genNonce(ocsp_params.nonceLen));
        }
        DO(ocsp_helper.encodeRequest());
        (void)sba_ocsprequest.set(ocsp_helper.getRequestEncoded(true));

        shuffled_uris = HttpHelper::randomURIs(cerSubject->getUris().ocsp);
        for (auto& it : shuffled_uris) {
            ret = HttpHelper::post(
                it,
                HttpHelper::CONTENT_TYPE_OCSP_REQUEST,
                sba_ocsprequest.get(),
                &sba_ocspresponse
            );
            if (ret == RET_OK) {
                DEBUG_OUTCON(printf("validateByOcsp(), url: '%s', size: %zu\n", it.c_str(), sba_ocspresponse.size()));
                break;
            }
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
                resultValidation,
                joResult
            ));

            (void)resultValidation.basicOcspResponse.set(ocsp_helper.getBasicOcspResponseEncoded(true));
            DO(ocsp_helper.getOcspIdentifier(&resultValidation.ocspIdentifier));
            if (!resultValidation.ocspResponse.set(ba_copy_with_alloc(pba_ocspresponse, 0, 0))) {
                SET_ERROR(RET_UAPKI_GENERAL_ERROR);
            }

            if (certstatusinfo_by_ocsp.needUpdate) {
                DO(certstatusinfo_by_ocsp.set(
                    resultValidation.singleResponseInfo.certStatus,
                    resultValidation.singleResponseInfo.msThisUpdate + Ocsp::OFFSET_EXPIRE_DEFAULT,
                    sba_ocspresponse.get()
                ));
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
        uris.deltaCrl
    );

    {   //  begin lock_guard
        lock_guard<mutex> lock(crl_item ? crl_item->getMutex() : crlStore.getMutexFirstDownloading());

        if (crl_item) {
            if (crl_item->getNextUpdate() < validateTime) {
                DEBUG_OUTCON(puts("CertValidator::getCrl(), need get newest CRL"));
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
            if (HttpHelper::isOfflineMode()) {
                SET_ERROR(err_crl);
            }
            if (uris_crl.empty()) {
                SET_ERROR(RET_UAPKI_CRL_URL_NOT_PRESENT);
            }

            const vector<string> shuffled_uris = HttpHelper::randomURIs(uris_crl);
            DEBUG_OUTCON(printf("CertValidator::getCrl(is full=%d), download CRL", is_full));
            for (auto& it : shuffled_uris) {
                DEBUG_OUTCON(printf("CertValidator::getCrl(), HttpHelper::get('%s')\n", it.c_str()));
                ret = HttpHelper::get(it, &sba_crl);
                if (ret == RET_OK) {
                    DEBUG_OUTCON(printf("CertValidator::getCrl(), url: '%s', size: %zu\n", it.c_str(), sba_crl.size()));
                    break;
                }
            }
            if (ret != RET_OK) {
                SET_ERROR(RET_UAPKI_CRL_NOT_DOWNLOADED);
            }

            bool is_unique;
            DO(crlStore.addCrl(
                sba_crl.get(),
                true,
                is_unique,
                &crl_item
            ));
            sba_crl.set(nullptr);
            if (!crl_item) {
                SET_ERROR(RET_UAPKI_CRL_NOT_FOUND);
            }

            if (crl_item->getNextUpdate() < validateTime) {
                DEBUG_OUTCON(puts("CertValidator::getCrl(), need get newest CRL. Again... stop it!"));
                SET_ERROR(RET_UAPKI_CRL_EXPIRED);
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

    //  Find certificate
    DO(cerStore.getCertByKeyId(crl_item->getAuthorityKeyId(), cerCrlSigner));

    //  Verify signature
    ret = crl_item->verify(*cerCrlSigner);
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

int CertValidator::processResponseData (
        Ocsp::OcspHelper& ocspHelper,
        ResultValidationByOcsp& resultValidation,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    const size_t idx_certid = 0;    //  Work with one OCSP request that has one certificate
    const ByteArray* ba_certid = nullptr;
    SmartBA sba_serialnumber;
    VectorBA vba_encodedcerts;
    vector<Cert::CerStore::AddedCerItem> added_ceritems;
    string s_time;

    if (joResult) {
        DO_JSON(json_object_set_string(joResult, "status", Crl::certStatusToStr(CertStatus::UNDEFINED)));
    }

    DO(ocspHelper.getSerialNumberFromCertId(idx_certid, &sba_serialnumber));
    DO(ocspHelper.getCerts(vba_encodedcerts));

    if (!vba_encodedcerts.empty()) {
        DO(m_CerStore->addCerts(
            Cert::NOT_TRUSTED,
            Cert::NOT_PERMANENT,
            vba_encodedcerts,
            added_ceritems
        ));
        for (auto& it : added_ceritems) {
            if (it.cerItem && (ba_cmp(it.cerItem->getSerialNumber(), sba_serialnumber.get()) == 0)) {
                ba_certid = it.cerItem->getCertId();
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

    DO(ocspHelper.scanSingleResponses());
    resultValidation.singleResponseInfo = ocspHelper.getSingleResponseInfo(idx_certid);

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
    DO(verifyResponseData(ocspHelper, resultValidation, joResult));

cleanup:
    return ret;
}

int CertValidator::verifyResponseData (
        Ocsp::OcspHelper& ocspHelper,
        ResultValidationByOcsp& resultValidation,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    SmartBA sba_responderid;
    Ocsp::ResponderIdType responder_idtype = Ocsp::ResponderIdType::UNDEFINED;
    SignatureVerifyStatus status_sign = SignatureVerifyStatus::UNDEFINED;

    DO(ocspHelper.getResponderId(responder_idtype, &sba_responderid));
    if (joResult) {
        DO(responderIdToJson(joResult, responder_idtype, sba_responderid.get()));
    }
    if (responder_idtype == Ocsp::ResponderIdType::BY_NAME) {
        ret = m_CerStore->getCertBySubject(sba_responderid.get(), &resultValidation.cerResponder);
        if (ret == RET_UAPKI_CERT_NOT_FOUND) {
            const int ret2 = addExpectedOcspCert(false, sba_responderid.get());
            SET_ERROR((ret2 == RET_OK) ? ret : ret2);
        }
    }
    else {
        //  responder_idtype == OcspHelper::ResponderIdType::BY_KEY
        ret = m_CerStore->getCertByKeyId(sba_responderid.get(), &resultValidation.cerResponder);
        if (ret == RET_UAPKI_CERT_NOT_FOUND) {
            const int ret2 = addExpectedOcspCert(true, sba_responderid.get());
            SET_ERROR((ret2 == RET_OK) ? ret : ret2);
        }
    }

    ret = ocspHelper.verifyTbsResponseData(resultValidation.cerResponder, status_sign);
    if (joResult) {
        DO_JSON(json_object_set_string(joResult, "statusSignature", verifyStatusToStr(status_sign)));
    }
    if (ret == RET_VERIFY_FAILED) {
        SET_ERROR(RET_UAPKI_OCSP_RESPONSE_VERIFY_FAILED);
    }
    else if (ret != RET_OK) {
        SET_ERROR(RET_UAPKI_OCSP_RESPONSE_VERIFY_ERROR);
    }

cleanup:
    return ret;
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
        ret = getCertByIssuerAndSN(certEntity, signerInfo.getSidEncoded(), cerSigner);
        break;
    case Pkcs7::SignerIdentifierType::SUBJECT_KEYID:
        ret = getCertByKeyId(certEntity, signerInfo.getSidEncoded(), cerSigner);
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
            signerInfo.getSignature()
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

    DO(json_object_set_hex(joResult, "authorityKeyId", expectedCrlItem.getAuthorityKeyId()));
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
