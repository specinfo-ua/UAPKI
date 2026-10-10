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

#define FILE_MARKER "uapki/doc-verify.cpp"

#include "doc-verify.h"
#include "api-json-internal.h"
#include "attribute-helper.h"
#include "cert-validator.h"
#include "global-objects.h"
#include "hash.h"
#include "oid-utils.h"
#include "signature-format.h"
#include "signeddata-helper.h"
#include "store-json.h"
#include "time-util.h"
#include "tsp-helper.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"
#include "uapki-ns-verify.h"
#include <algorithm>


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

    bool set (const VerifyStatus status) {
        values[(uint32_t)status] = true;
        return (status == VerifyStatus::VALID);
    }
};  //  end class CollectVerifyStatus



class ValidationStatusHelper {
    ValidationStatus&
                m_Status;
public:
    ValidationStatusHelper (ValidationStatus& iValidationStatus)
        : m_Status(iValidationStatus)
    {}

    bool isIndeterminate (void) const {
        return (m_Status == ValidationStatus::INDETERMINATE);
    }
    bool isTotalFailed (void) const {
        return (m_Status == ValidationStatus::TOTAL_FAILED);
    }
    bool isTotalValid (void) const {
        return (m_Status == ValidationStatus::TOTAL_VALID);
    }
    bool isUndefined (void) const {
        return (m_Status == ValidationStatus::UNDEFINED);
    }

    void setIndeterminate (void) {
        if (isTotalValid()) {
            m_Status = ValidationStatus::INDETERMINATE;
        }
    }
    void setByCertChainItem (
        const CertChainItem& certChainItem,
        const uint64_t bestSignatureTime
    )
    {
        if (certChainItem.getVerifyStatus() == Cert::VerifyStatus::VALID) {
            switch (certChainItem.getValidationType()) {
            case Cert::ValidationType::UNDEFINED:
                setIndeterminate();
                break;
            case Cert::ValidationType::CRL:
                setByCertStatus(certChainItem.getResultValidationByCrl().certStatus);
                break;
            case Cert::ValidationType::OCSP:
                //  An OCSP response with an invalid signature or from an unauthorized responder says nothing
                if (certChainItem.getResultValidationByOcsp().statusSignature == SignatureVerifyStatus::VALID) {
                    const Ocsp::OcspHelper::SingleResponseInfo& single_resp = certChainItem.getResultValidationByOcsp().singleResponseInfo;
                    //  Revoked after the best signature time: the certificate was valid when signed (as by a CRL at that time)
                    if (
                        (single_resp.certStatus == UapkiNS::CertStatus::REVOKED) && (bestSignatureTime > 0) &&
                        (single_resp.msRevocationTime > bestSignatureTime)
                    ) break;
                    setByCertStatus(single_resp.certStatus);
                }
                else {
                    setIndeterminate();
                }
                break;
            default:
                //  Other cases (ValidationType::NONE and ValidationType::CHAIN) - no action
                break;
            }
        }
    }
    void setByCertStatus (
        const UapkiNS::CertStatus certStatus
    )
    {
        switch (certStatus) {
        case UapkiNS::CertStatus::GOOD:
            //  No action
            break;
        case UapkiNS::CertStatus::REVOKED:
        case UapkiNS::CertStatus::UNKNOWN:
            setTotalFailed();
            break;
        default:
            setIndeterminate();
            break;
        }
    }
    void setTotalFailed (void) {
        m_Status = ValidationStatus::TOTAL_FAILED;
    }

};  //  end class ValidationStatusHelper



AttrTimeStamp::AttrTimeStamp (void)
    : msGenTime(0)
    , cerSigner(nullptr)
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

const ByteArray* AttrTimeStamp::getAtsHashIndex (
        Pkcs7::AtsV3::IndexType& indexType
) const
{
    for (const auto& it : signerInfo.getUnsignedAttrs()) {
        if (it.type == string(OID_ETSI_ATS_HASH_INDEX_V3)) {
            indexType = Pkcs7::AtsV3::IndexType::EN_319_122;
            return it.baValues;
        }
        if (it.type == string(OID_ETSI_ATS_HASH_INDEX)) {
            indexType = Pkcs7::AtsV3::IndexType::TS_101_733;
            return it.baValues;
        }
    }
    return nullptr;
}

int AttrTimeStamp::parse (
        const ByteArray* baEncoded
)
{
    int ret = tsTokenParser.parse(baEncoded);
    if (ret != RET_OK) return ret;

    Pkcs7::SignedDataParser& sdata_parser = tsTokenParser.getSignedDataParser();
    if (
        (!sdata_parser.getEncapContentInfo().baEncapContent) ||
        (sdata_parser.getCountSignerInfos() == 0)
    ) return RET_UAPKI_INVALID_STRUCT;

    ret = sdata_parser.parseSignerInfo(0, signerInfo);
    if (ret != RET_OK) return ret;

    if (!sdata_parser.isContainDigestAlgorithm(signerInfo.getDigestAlgorithm())) return RET_UAPKI_INVALID_STRUCT;

    policy = tsTokenParser.getPolicyId();
    hashAlgo = tsTokenParser.getHashAlgo();
    (void)hashedMessage.set(tsTokenParser.getHashedMessage(true));
    msGenTime = tsTokenParser.getGenTime();
    return RET_OK;
}

int AttrTimeStamp::verifyTstInfo (void)
{
    SmartBA sba_hashtstinfo;
    const HashAlg hash_alg = hash_from_oid(signerInfo.getDigestAlgorithm().algorithm.c_str());

    if (hash_alg == HASH_ALG_UNDEFINED) {
        statusDigest = DigestVerifyStatus::FAILED;
        return RET_UAPKI_UNSUPPORTED_ALG;
    }

    const int ret = ::hash(hash_alg, tsTokenParser.getSignedDataParser().getEncapContentInfo().baEncapContent, &sba_hashtstinfo);
    if (ret != RET_OK) {
        statusDigest = DigestVerifyStatus::FAILED;
        return ret;
    }

    if (ba_cmp(signerInfo.getMessageDigest(), sba_hashtstinfo.get()) != 0) {
        statusDigest = DigestVerifyStatus::INVALID;
        return RET_UAPKI_INVALID_DIGEST;
    }

    return RET_OK;
}

int AttrTimeStamp::verifyDigest (
        ContentHasher& contentHasher,
        const bool isDigest
)
{
    int ret = verifyTstInfo();
    if (ret != RET_OK) return ret;
    HashAlg hash_alg = HASH_ALG_UNDEFINED;

    if (!contentHasher.isPresent()) {
        statusDigest = DigestVerifyStatus::INDETERMINATE;
        return RET_OK;
    }

    if (!isDigest) {
        hash_alg = hash_from_oid(hashAlgo.c_str());
        if (hash_alg == HASH_ALG_UNDEFINED) {
            statusDigest = DigestVerifyStatus::FAILED;
            return RET_UAPKI_UNSUPPORTED_ALG;
        }

        ret = contentHasher.digest(hash_alg);
        if (ret != RET_OK) {
            statusDigest = DigestVerifyStatus::FAILED;
            return ret;
        }

        statusDigest = (ba_cmp(hashedMessage.get(), contentHasher.getHashValue()) == 0)
            ? DigestVerifyStatus::VALID : DigestVerifyStatus::INVALID;
    }
    else {
        statusDigest = (ba_cmp(hashedMessage.get(), contentHasher.getContentBytes()) == 0)
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
        Cert::CerStore* cerStore
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
        Cert::CerItem* cer_item = nullptr;
        if (isPresentCertVals) {
            refba_cert = certValues[idx];
        }
        else {
            SmartBA sba_issuer;
            ret = Cert::issuerFromGeneralNames(it.issuerSerial.baIssuer, &sba_issuer);
            if (ret != RET_OK) {
                statusCertRefs = status = DigestVerifyStatus::FAILED;
                return ret;
            }

            ret = cerStore->getCertByIssuerAndSN(sba_issuer.get(), it.issuerSerial.baSerialNumber, &cer_item);
            if (ret == RET_OK) {
                refba_cert = cer_item->getEncoded();
            }
            else if (ret == RET_UAPKI_CERT_NOT_FOUND) {
                ByteArray* ba_iasn = nullptr;
                ret = Cert::encodeIssuerAndSN(sba_issuer.get(), it.issuerSerial.baSerialNumber, &ba_iasn);
                if (ret != RET_OK) {
                    statusCertRefs = status = DigestVerifyStatus::FAILED;
                    return ret;
                }

                status = DigestVerifyStatus::INDETERMINATE;
                expectedCertsByIssuerAndSN.push_back(ba_iasn);
                idx++;
                continue;
            }
            else {
                statusCertRefs = status = DigestVerifyStatus::FAILED;
                return ret;
            }
        }

        SmartBA sba_hash;
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


VerifiedSignerInfo::VerifiedSignerInfo (void)
    : m_IsDigest(false)
    , m_LastError(RET_OK)
    , m_CerSigner(nullptr)
    , m_ValidationStatus(ValidationStatus::UNDEFINED)
    , m_StatusSignature(SignatureVerifyStatus::UNDEFINED)
    , m_StatusMessageDigest(DigestVerifyStatus::UNDEFINED)
    , m_SigningTime(0)
    , m_StatusEssCert(DataVerifyStatus::UNDEFINED)
    , m_SignatureFormat(SignatureFormat::UNDEFINED)
    , m_IsValidSignatures(false)
    , m_IsValidDigests(false)
    , m_BestSignatureTime(0)
{}

VerifiedSignerInfo::~VerifiedSignerInfo (void)
{
    m_CerSigner = nullptr;
    for (auto& it : m_CertChainItems) {
        delete it;
    }
}

int VerifiedSignerInfo::init (
        LibraryConfig* iLibConfig,
        Cert::CerStore* iCerStore,
        Crl::CrlStore* iCrlStore,
        const bool isDigest
)
{
    m_IsDigest = isDigest;
    return CertValidator::init(iLibConfig, iCerStore, iCrlStore) ? RET_OK : RET_UAPKI_GENERAL_ERROR;
}

int VerifiedSignerInfo::addCertChainItem (
        const CertEntity certEntity,
        Cert::CerItem* cerItem,
        CertChainItem** certChainItem
)
{
    bool is_newitem;
    return addCertChainItem(certEntity, cerItem, certChainItem, is_newitem);
}

int VerifiedSignerInfo::addCertChainItem (
        const CertEntity certEntity,
        Cert::CerItem* cerItem,
        CertChainItem** certChainItem,
        bool& isNewItem
)
{
    for (const auto& it : m_CertChainItems) {
        if (ba_cmp(cerItem->getCertId(), it->getSubjectCertId()) == 0) {
            *certChainItem = it;
            isNewItem = false;
            return RET_OK;
        }
    }

    CertChainItem* certchain_item = new CertChainItem(certEntity, cerItem);
    *certChainItem = certchain_item;
    if (!certchain_item) return RET_UAPKI_GENERAL_ERROR;

    isNewItem = true;
    m_CertChainItems.push_back(certchain_item);
    return certchain_item->decodeName();
}

int VerifiedSignerInfo::addCrlCertsToChain (
        const uint64_t validateTime
)
{
    vector<Cert::CerItem*> crl_certs;
    for (const auto& it : m_CertChainItems) {
        (void)Cert::addCertIfUnique(crl_certs, it->getResultValidationByCrl().cerIssuer);
    }

    for (const auto& it_cer : crl_certs) {
        CertChainItem* added_cci = nullptr;
        bool is_newitem;
        int ret = addCertChainItem(CertEntity::CRL, it_cer, &added_cci, is_newitem);
        if (ret != RET_OK) return ret;

        if (is_newitem) {
            vector<Cert::CerItem*> chain_certs;
            added_cci->checkValidityTime(validateTime);
            added_cci->setValidationType(Cert::ValidationType::NONE);
            ret = getCerStore()->getChainCerts(added_cci->getSubject(), chain_certs);
            if ((ret == RET_OK) && !chain_certs.empty()) {
                //  Add one cert - issuer
                added_cci->setIssuer(chain_certs[0]);
            }
        }
    }
    return RET_OK;
}

int VerifiedSignerInfo::addOcspCertsToChain (
        const uint64_t validateTime
)
{
    vector<Cert::CerItem*> ocsp_certs;
    for (const auto& it : m_ListAddedCerts.ocsp) {
        (void)Cert::addCertIfUnique(ocsp_certs, it);
    }

    for (const auto& it_cer : ocsp_certs) {
        CertChainItem* added_cci = nullptr;
        bool is_newitem;
        int ret = addCertChainItem(CertEntity::OCSP, it_cer, &added_cci, is_newitem);
        if (ret != RET_OK) return ret;

        if (is_newitem) {
            vector<Cert::CerItem*> chain_certs;
            added_cci->checkValidityTime(validateTime);
            added_cci->setValidationType(Cert::ValidationType::NONE);
            ret = getCerStore()->getChainCerts(added_cci->getSubject(), chain_certs);
            if ((ret == RET_OK) && !chain_certs.empty()) {
                //  Add one cert - issuer
                added_cci->setIssuer(chain_certs[0]);
            }
        }
    }
    return RET_OK;
}

int VerifiedSignerInfo::buildCertChain (void)
{
    int ret = RET_OK;
    vector<Cert::CerItem*> tsp_certs;

    //  Build chain for Singer
    if (m_CerSigner) {
        const ByteArray* ba_authkeyid_notfound = nullptr;
        vector<Cert::CerItem*> chain_certs;
        CertChainItem* added_cci = nullptr;

        (void)m_CerSigner->verify(nullptr);
        DO(addCertChainItem(CertEntity::SIGNER, m_CerSigner, &added_cci));
        ret = getCerStore()->getChainCerts(m_CerSigner, chain_certs, &ba_authkeyid_notfound);
        if (ret == RET_OK) {
            for (const auto& it : chain_certs) {
                added_cci->setIssuer(it);
                DO(addCertChainItem(CertEntity::INTERMEDIATE, it, &added_cci));
            }
            added_cci->isSelfSigned() ? added_cci->setRoot() : added_cci->setIssuer(nullptr);
        }
        else {
            m_LastError = ret;
            if (ret == RET_UAPKI_CERT_ISSUER_NOT_FOUND) {
                DO(addExpectedCertByKeyId(CertEntity::INTERMEDIATE, ba_authkeyid_notfound));
                for (const auto& it : chain_certs) {
                    added_cci->setIssuer(it);
                    DO(addCertChainItem(CertEntity::INTERMEDIATE, it, &added_cci));
                }
            }
        }
    }

    //  Build chain for TSP
    for (const auto& it : m_ListAddedCerts.tsp) {
        (void)Cert::addCertIfUnique(tsp_certs, it);
    }
    for (const auto& it_tsp : tsp_certs) {
        const ByteArray* ba_authkeyid_notfound = nullptr;
        vector<Cert::CerItem*> chain_certs;
        CertChainItem* added_cci = nullptr;

        DO(addCertChainItem(CertEntity::TSP, it_tsp, &added_cci));
        ret = getCerStore()->getChainCerts(it_tsp, chain_certs, &ba_authkeyid_notfound);
        if (ret == RET_OK) {
            for (const auto& it : chain_certs) {
                added_cci->setIssuer(it);
                DO(addCertChainItem(CertEntity::INTERMEDIATE, it, &added_cci));
            }
            added_cci->isSelfSigned() ? added_cci->setRoot() : added_cci->setIssuer(nullptr);
        }
        else {
            m_LastError = ret;
            if (ret == RET_UAPKI_CERT_ISSUER_NOT_FOUND) {
                DO(addExpectedCertByKeyId(CertEntity::INTERMEDIATE, ba_authkeyid_notfound));
                for (const auto& it : chain_certs) {
                    added_cci->setIssuer(it);
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
    vector<Cert::CerStore::AddedCerItem> added_ceritems;
    const int ret = getCerStore()->addCerts(
        Cert::NOT_TRUSTED,
        Cert::NOT_PERMANENT,
        m_CadesXlInfo.certValues,
        added_ceritems
    );
    if (ret != RET_OK) return ret;

    for (const auto& it : added_ceritems) {
        if (it.cerItem) {
            m_ListAddedCerts.certValues.push_back(it.cerItem);
            m_ListAddedCerts.fromSignature.push_back(it.cerItem);
        }
    }
    return RET_OK;
}

void VerifiedSignerInfo::determineSignFormat (void)
{
    //  Each level by its own attributes: T - signature time-stamp (content time-stamp is optional),
    //  C - complete references, XL - certificate and revocation values (baseline LT has them without references),
    //  A - archive time-stamp (baseline LTA)
    if (m_SignatureFormat == SignatureFormat::CADES_BES) {
        if (m_SignatureTS.isPresent()) {
            m_SignatureFormat = SignatureFormat::CADES_T;
            if (m_CadesXlInfo.isPresentCadesC()) {
                m_SignatureFormat = SignatureFormat::CADES_C;
            }
            if (m_CadesXlInfo.isPresentCadesXL()) {
                m_SignatureFormat = SignatureFormat::CADES_XL;
            }
            if (m_ArchiveTS.isPresent()) {
                m_SignatureFormat = SignatureFormat::CADES_A;
            }
        }
    }
}

const char* VerifiedSignerInfo::getValidationStatus (void) const {
    return validationStatusToStr(m_ValidationStatus);
}

vector<string> VerifiedSignerInfo::getWarningMessages (void) const
{
    vector<string> rv_warns;

    if (m_SignatureFormat <= SignatureFormat::CADES_BES) {
        if (m_SigningTime == 0) {
            rv_warns.push_back("THE SIGNING TIME IS NOT PRESENT");
        }
    }

    if (m_SignatureFormat >= SignatureFormat::CADES_C) {
        for (const auto& it : m_CertChainItems) {
            if (
                (it->getValidationType() == Cert::ValidationType::OCSP) &&
                (it->getDataSource() != DataSource::SIGNATURE)
            ) {
                rv_warns.push_back("THE STATUS OF CERTIFICATE IS FROM OCSP");
                break;
            }
        }
    }

    return rv_warns;
}

int VerifiedSignerInfo::parseAttributes (void)
{
    int ret = parseSignedAttrs(m_SignerInfo.getSignedAttrs());
    if (ret != RET_OK) return ret;

    ret = parseUnsignedAttrs(m_SignerInfo.getUnsignedAttrs());
    return ret;
}

int VerifiedSignerInfo::setRevocationValuesForChain (
        const uint64_t validateTime
)
{
    int ret = RET_OK;

    for (const auto& it_ocspval : m_CadesXlInfo.revocationValuesParser.getOcspVals()) {
        Ocsp::OcspHelper ocsp_helper;
        if (ocsp_helper.parseBasicOcspResponse(it_ocspval) != RET_OK) continue;

        for (const auto& it_cci : m_CertChainItems) {
            Cert::CerItem* cer_issuer = it_cci->getIssuer();
            if (
                !cer_issuer ||
                (it_cci->getCertEntity() == CertEntity::ROOT) ||
                (it_cci->getValidationType() != Cert::ValidationType::UNDEFINED)
            ) continue;

            //  The response is about this certificate of this issuer (CertID), not just its serial number
            SmartBA sba_publickey;
            size_t idx = 0;
            (void)publicKeyFromSpki(cer_issuer->getSpki(), &sba_publickey);
            if (ocsp_helper.findSingleResponse(
                cer_issuer->getSubject(),
                cer_issuer->getKeyId(),
                sba_publickey.get(),
                it_cci->getSubject()->getSerialNumber(),
                idx
            ) != RET_OK) continue;

            ResultValidationByOcsp& result_valbyocsp = it_cci->getResultValidationByOcsp();
            result_valbyocsp.dataSource = DataSource::SIGNATURE;
            result_valbyocsp.responseStatus = Ocsp::ResponseStatus::SUCCESSFUL;
            //  Verdict in statusSignature: invalid or unauthorized responses do not count (validateStatusCerts)
            ret = processResponseData(
                ocsp_helper,
                it_cci->getSubject()->getSerialNumber(),
                cer_issuer,
                result_valbyocsp,
                &m_ListAddedCerts.fromSignature
            );
            if (ret != RET_OK) {
                m_LastError = ret;
            }
            if (result_valbyocsp.cerResponder) {
                m_ListAddedCerts.ocsp.push_back(result_valbyocsp.cerResponder);
            }
            it_cci->setValidationType(Cert::ValidationType::OCSP);
            break;
        }
    }

    validateValidityTimeCerts(validateTime);
    return RET_OK;
}

int VerifiedSignerInfo::tspCertToStore() {
    int ret = RET_OK;

    if (m_ContentTS.isPresent()) {
        Pkcs7::SignedDataParser& sdata_parser = m_ContentTS.tsTokenParser.getSignedDataParser();
        vector<Cert::CerStore::AddedCerItem> added_ceritems;
        DO(getCerStore()->addCerts(
            Cert::NOT_TRUSTED,
            Cert::NOT_PERMANENT,
            sdata_parser.getCerts(),
            added_ceritems
        ));
    }
    if (m_SignatureTS.isPresent()) {
        Pkcs7::SignedDataParser& sdata_parser = m_SignatureTS.tsTokenParser.getSignedDataParser();
        vector<Cert::CerStore::AddedCerItem> added_ceritems;
        DO(getCerStore()->addCerts(
            Cert::NOT_TRUSTED,
            Cert::NOT_PERMANENT,
            sdata_parser.getCerts(),
            added_ceritems
        ));
    }

cleanup:
    return ret;
}

void VerifiedSignerInfo::validateSignFormat (
        const uint64_t validateTime,
        const bool contentIsPresent
)
{
    CollectVerifyStatus collect_digests, collect_signatures;

    //  Check mandatory elements
    bool sign_is_valid = collect_signatures.set(getStatusSignature());
    bool digest_is_valid = collect_digests.set(getStatusMessageDigest());
    //  The signingTime attribute is a claim of the signer, not a proof of time
    if (sign_is_valid) {
        if ((contentIsPresent && digest_is_valid) || !contentIsPresent) {
            m_BestSignatureTime = validateTime;
        }
    }

    //  Check attribute EssCert
    if (getStatusEssCert() != DataVerifyStatus::NOT_PRESENT) {
        collect_digests.set(getStatusEssCert());
    }

    //  Check Content-Timestamp
    if (m_ContentTS.isPresent()) {
        sign_is_valid = collect_signatures.set(m_ContentTS.statusSignature);
        digest_is_valid = collect_digests.set(m_ContentTS.statusDigest);
        if (sign_is_valid) {
            if ((contentIsPresent && digest_is_valid) || !contentIsPresent) {
                m_BestSignatureTime = m_ContentTS.msGenTime;
            }
        }
    }

    //  Check Signature-Timestamp
    if (m_SignatureTS.isPresent()) {
        sign_is_valid = collect_signatures.set(m_SignatureTS.statusSignature);
        digest_is_valid = collect_digests.set(m_SignatureTS.statusDigest);
        if (sign_is_valid && digest_is_valid) {
            m_BestSignatureTime = m_SignatureTS.msGenTime;
        }
    }

    //  Check complete-certificate-references (if present)
    if (m_CadesXlInfo.isPresentCertRefs) {
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
        m_ValidationStatus = ValidationStatus::TOTAL_VALID;
    }
    else if (collect_signatures.isDeterminate() || collect_digests.isDeterminate()) {
        m_ValidationStatus = ValidationStatus::INDETERMINATE;
    }
    else {
        m_ValidationStatus = ValidationStatus::TOTAL_FAILED;
    }
}

void VerifiedSignerInfo::validateStatusCerts (void)
{
    ValidationStatusHelper validation_status(m_ValidationStatus);

    if (validation_status.isUndefined() || validation_status.isTotalFailed()) return;

    //  Current value is TOTAL_VALID or INDETERMINATE
    for (const auto& it : m_CertChainItems) {
        switch (it->getVerifyStatus()) {
        case Cert::VerifyStatus::VALID:
            validation_status.setByCertChainItem(*it, m_BestSignatureTime);
            break;
        case Cert::VerifyStatus::INDETERMINATE:
        case Cert::VerifyStatus::VALID_WITHOUT_KEYUSAGE:
            validation_status.setIndeterminate();
            DEBUG_OUTCON(printf("VerifiedSignerInfo::validateStatusCerts() set INDETERMINATE for cert (CommonName: '%s')", it->getCommonName().c_str()));
            break;
        default:
            //  Other cases (VerifyStatus::INVALID, VerifyStatus::FAILED and VerifyStatus::UNDEFINED)
            validation_status.setTotalFailed();
            break;
        }

        if (it->isExpired()) {
            validation_status.setTotalFailed();
        }

        if (validation_status.isTotalFailed()) {
            DEBUG_OUTCON(printf("VerifiedSignerInfo::validateStatusCerts() set TOTAL_FAILED for cert (CommonName: '%s')", it->getCommonName().c_str()));
            return;
        }
    }

    if (!getExpectedCerts().empty() || !getExpectedCrls().empty()) {
        validation_status.setIndeterminate();
        DEBUG_OUTCON(printf("VerifiedSignerInfo::validateStatusCerts() set INDETERMINATE because expected certs/CRLs"));
    }
}

void VerifiedSignerInfo::validateValidityTimeCerts (
        const uint64_t validateTime
)
{
    for (auto& it : m_CertChainItems) {
        (void)it->checkValidityTime(validateTime);
    }
}

int VerifiedSignerInfo::verifyArchiveTimeStamp (
        const vector<Cert::CerItem*>& certs,
        const VectorBA& certsEncoded,
        const VectorBA& crls
)
{
    int ret = RET_OK;

    if (m_ArchiveTS.isPresent()) {
        //  genTime and messageImprint of the token count only if TSTInfo is the one the TSA signed
        if (m_ArchiveTS.verifyTstInfo() != RET_OK) {
            m_LastError = RET_UAPKI_INVALID_DIGEST;
            (void)verifyAttrTimestamp(m_ArchiveTS);
            return RET_OK;
        }

        //  archive-time-stamp-v3 with its hash index in the token (UAPKI 3.x, other libraries): first the index -
        //  every hash it has refers to a value of the signature, then the message imprint by this index
        //  (TS 101 733 6.4.2, 6.4.3; EN 319 122-1 5.5.2, 5.5.3). Of several archive time-stamps the last one,
        //  its index covers the earlier ones
        Pkcs7::AtsV3::IndexType index_type = Pkcs7::AtsV3::IndexType::EN_319_122;
        const ByteArray* ba_hashindex = m_ArchiveTS.getAtsHashIndex(index_type);
        if (ba_hashindex) {
            bool is_validindex = false;
            SmartBA sba_hash;
            const HashAlg hash_alg = hash_from_oid(m_ArchiveTS.hashAlgo.c_str());
            m_ArchiveTS.statusDigest = SignatureVerifyStatus::INVALID;
            //  The hash of the signed data by the hash algorithm of the time-stamp: the message-digest attribute
            //  if it is the digest algorithm of the signature
            if (
                (hash_alg != HASH_ALG_UNDEFINED) &&
                (m_ArchiveTS.hashAlgo == m_SignerInfo.getDigestAlgorithm().algorithm) &&
                (Pkcs7::AtsV3::checkHashIndex(index_type, ba_hashindex, certsEncoded, crls, m_SignerInfo.getAsn1Data(), is_validindex) == RET_OK) &&
                is_validindex &&
                (Pkcs7::AtsV3::calcMessageImprint(
                    hash_alg,
                    m_SignerInfo.getContentType(),
                    m_SignerInfo.getMessageDigest(),
                    m_SignerInfo.getAsn1Data(),
                    ba_hashindex,
                    &sba_hash
                ) == RET_OK) &&
                (ba_cmp(m_ArchiveTS.hashedMessage.get(), sba_hash.get()) == 0)
            ) {
                m_ArchiveTS.statusDigest = SignatureVerifyStatus::VALID;
            }
            if (m_ArchiveTS.statusDigest == SignatureVerifyStatus::INVALID) {
                m_LastError = RET_UAPKI_INVALID_DIGEST;
            }
            ret = verifyAttrTimestamp(m_ArchiveTS);
            if (ret != RET_OK) {
                m_LastError = ret;
                ret = (ret == RET_UAPKI_CERT_NOT_FOUND) ? RET_OK : ret;
            }
            return ret;
        }

        DO(m_ArchiveTsHelper.init((const AlgorithmIdentifier*)&m_SignerInfo.getDigestAlgorithm()));

        DO(m_ArchiveTsHelper.setHashContent(m_SignerInfo.getContentType(), m_SignerInfo.getMessageDigest()));

        DO(m_ArchiveTsHelper.setSignerInfo(m_SignerInfo.getAsn1Data()));

        for (const auto& it : certs) {
            DO(m_ArchiveTsHelper.addCertificate(it->getEncoded()));
        }
        for (const auto& it : crls) {
            DO(m_ArchiveTsHelper.addCrl(it));
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
    if (!m_CadesXlInfo.isPresentCertRefs) return RET_OK;

    int ret = m_CadesXlInfo.verifyCertRefs(getCerStore());
    if (ret != RET_OK) {
        m_LastError = ret;
    }
    else {
        if (!m_CadesXlInfo.expectedCertsByIssuerAndSN.empty()) {
            m_LastError = RET_UAPKI_CERT_NOT_FOUND;
        }
    }

    for (const auto& it : m_CadesXlInfo.expectedCertsByIssuerAndSN) {
        ret = addExpectedCertByIssuerAndSN(CertEntity::UNDEFINED, it);
        if (ret != RET_OK) break;
    }

    return ret;
}

int VerifiedSignerInfo::verifyContentTimeStamp (
        ContentHasher& contentHasher
)
{
    int ret = RET_OK;
    if (m_ContentTS.isPresent()) {
        ret = m_ContentTS.verifyDigest(contentHasher, m_IsDigest);
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
        ContentHasher& contentHasher
)
{
    if (!contentHasher.isPresent()) {
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

        const int ret = contentHasher.digest(hash_alg);
        if (ret != RET_OK) {
            m_StatusMessageDigest = DigestVerifyStatus::FAILED;
            return ret;
        }

        m_StatusMessageDigest = (ba_cmp(m_SignerInfo.getMessageDigest(), contentHasher.getHashValue()) == 0)
            ? DigestVerifyStatus::VALID : DigestVerifyStatus::INVALID;
    }
    else {
        m_StatusMessageDigest = (ba_cmp(m_SignerInfo.getMessageDigest(), contentHasher.getContentBytes()) == 0)
            ? DigestVerifyStatus::VALID : DigestVerifyStatus::INVALID;
    }

    return RET_OK;
}

int VerifiedSignerInfo::verifySignatureTimeStamp (void)
{
    int ret = RET_OK;
    if (m_SignatureTS.isPresent()) {
        ContentHasher content_hasher;
        (void)content_hasher.setContent(m_SignerInfo.getSignature(), false);
        ret = m_SignatureTS.verifyDigest(content_hasher);
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

int VerifiedSignerInfo::verifySignedAttribute (
        const vector<Cert::CerItem*>& signatureCerts
)
{
    int ret = RET_OK;

    //  CAdES is the signature with the signing certificate attribute, the SID may be of any type
    switch (m_SignerInfo.getSidType()) {
    case Pkcs7::SignerIdentifierType::ISSUER_AND_SN:
    case Pkcs7::SignerIdentifierType::SUBJECT_KEYID:
        m_SignatureFormat = (m_StatusEssCert == DataVerifyStatus::INDETERMINATE)
            ? SignatureFormat::CADES_BES : SignatureFormat::CMS_SID_KEYID;
        break;
    default:
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

    //  Get signer certificate
    ret = getCerStore()->getCertBySID(m_SignerInfo.getSidEncoded(), &m_CerSigner);
    if ((ret == RET_OK) && (m_SignerInfo.getSidType() == Pkcs7::SignerIdentifierType::SUBJECT_KEYID)) {
        //  One key may have certificates of several CAs (re-issued on the same key)
        selectSignerByKeyId(signatureCerts);
    }

    //  Verify signed attributes
    if (ret == RET_OK) {
        ret = UapkiNS::Verify::verifySignature(
            m_SignerInfo.getSignatureAlgorithm().algorithm.c_str(),
            m_SignerInfo.getSignedAttrsEncoded(),
            false,
            m_CerSigner->getSpki(),
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
        DO(addExpectedCertBySID(CertEntity::SIGNER, m_SignerInfo.getSidEncoded()));
        break;
    default:
        m_StatusSignature = SignatureVerifyStatus::FAILED;
    }

cleanup:
    return ret;
}

void VerifiedSignerInfo::selectSignerByKeyId (
        const vector<Cert::CerItem*>& signatureCerts
)
{
    vector<Cert::CerItem*> cer_candidates;
    getCerStore()->getCertsByKeyId(m_CerSigner->getKeyId(), cer_candidates);
    if (cer_candidates.size() < 2) return;

    //  The certificate of the signing certificate attribute
    if (!m_EssCerts.empty()) {
        const UapkiNS::EssCertId& doc_esscertid = m_EssCerts[0];
        for (const auto& it : cer_candidates) {
            const UapkiNS::EssCertId* cer_esscertid = nullptr;
            if (
                (it->generateEssCertId(doc_esscertid.hashAlgorithm, &cer_esscertid) == RET_OK) &&
                (ba_cmp(doc_esscertid.baHashValue, cer_esscertid->baHashValue) == 0)
            ) {
                m_CerSigner = it;
                return;
            }
        }
        return;
    }

    //  Without it: the newest of the certificates in the signature, else the one getCertBySID found
    Cert::CerItem* cer_signer = nullptr;
    for (const auto& it : cer_candidates) {
        if (
            (std::find(signatureCerts.begin(), signatureCerts.end(), it) != signatureCerts.end()) &&
            (!cer_signer || (it->getNotBefore() > cer_signer->getNotBefore()))
        ) {
            cer_signer = it;
        }
    }
    if (cer_signer) {
        m_CerSigner = cer_signer;
    }
}

int VerifiedSignerInfo::verifySigningCertificateV2 (void)
{
    if (m_StatusEssCert == DataVerifyStatus::NOT_PRESENT) return RET_OK;

    if (m_EssCerts.empty()) {
        //  The attribute is present, but has no ESSCertIDv2
        m_StatusEssCert = DataVerifyStatus::INVALID;
        return RET_OK;
    }

    if (m_CerSigner) {
        //  Process simple case: present only the one ESSCertIDv2
        const UapkiNS::EssCertId& doc_esscertid = m_EssCerts[0];
        const UapkiNS::EssCertId* cer_esscertid = nullptr;
        const int ret = m_CerSigner->generateEssCertId(doc_esscertid.hashAlgorithm, &cer_esscertid);
        if (ret != RET_OK) {
            m_StatusEssCert = DigestVerifyStatus::FAILED;
            return ret;
        }
        m_StatusEssCert = (ba_cmp(doc_esscertid.baHashValue, cer_esscertid->baHashValue) == 0)
            ? DataVerifyStatus::VALID : DataVerifyStatus::INVALID;
        //  issuerSerial (optional) identifies the same certificate
        if (
            (m_StatusEssCert == DataVerifyStatus::VALID) &&
            doc_esscertid.issuerSerial.baIssuer && doc_esscertid.issuerSerial.baSerialNumber && (
                (ba_cmp(doc_esscertid.issuerSerial.baIssuer, cer_esscertid->issuerSerial.baIssuer) != 0) ||
                (ba_cmp(doc_esscertid.issuerSerial.baSerialNumber, cer_esscertid->issuerSerial.baSerialNumber) != 0)
            )
        ) {
            m_StatusEssCert = DataVerifyStatus::INVALID;
        }
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
    const Pkcs7::SignedDataParser::SignerInfo& signer_info = attrTS.signerInfo;
    vector<Cert::CerStore::AddedCerItem> added_ceritems;

    DO(getCerStore()->addCerts(
        Cert::NOT_TRUSTED,
        Cert::NOT_PERMANENT,
        sdata_parser.getCerts(),
        added_ceritems
    ));
    for (const auto& it : added_ceritems) {
        if (it.cerItem) {
            m_ListAddedCerts.fromSignature.push_back(it.cerItem);
        }
    }

    switch (signer_info.getSidType()) {
    case Pkcs7::SignerIdentifierType::ISSUER_AND_SN:
    case Pkcs7::SignerIdentifierType::SUBJECT_KEYID:
        ret = getCerStore()->getCertBySID(signer_info.getSidEncoded(), &attrTS.cerSigner);
        break;
    default:
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

    if (ret == RET_OK) {
        m_ListAddedCerts.tsp.push_back(attrTS.cerSigner);
        ret = UapkiNS::Verify::verifySignature(
            signer_info.getSignatureAlgorithm().algorithm.c_str(),
            signer_info.getSignedAttrsEncoded(),
            false,
            attrTS.cerSigner->getSpki(),
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
        DO(addExpectedCertBySID(CertEntity::TSP, signer_info.getSidEncoded()));
        ret = RET_UAPKI_CERT_NOT_FOUND;
        break;
    default:
        attrTS.statusSignature = SignatureVerifyStatus::FAILED;
    }

cleanup:
    return ret;
}


VerifySignedDoc::VerifySignedDoc (
        LibraryConfig* iLibConfig,
        Cert::CerStore* iCerStore,
        Crl::CrlStore* iCrlStore,
        const Doc::Verify::VerifyOptions& iVerifyOptions
)
    : libConfig(iLibConfig)
    , cerStore(iCerStore)
    , crlStore(iCrlStore)
    , validateTime(TimeUtil::mtimeNow())
    , verifyOptions(iVerifyOptions)
    , refContentHasher(nullptr)
{
}

VerifySignedDoc::~VerifySignedDoc (void)
{
}

int VerifySignedDoc::parse (
        const ByteArray* baSignature
)
{
    const int ret = sdataParser.parse(baSignature);
    if (ret != RET_OK) return ret;
    return (sdataParser.getCountSignerInfos() > 0) ? RET_OK : RET_UAPKI_INVALID_STRUCT;
}

int VerifySignedDoc::getContent (
        ContentHasher& contentHasher
)
{
    int ret = RET_OK;
    refContentHasher = &contentHasher;
    if (sdataParser.getEncapContentInfo().baEncapContent) {
        contentHasher.reset();
        ret = contentHasher.setContent(sdataParser.getEncapContentInfo().baEncapContent, false);
    }
    return ret;
}

int VerifySignedDoc::addCertsToStore (void)
{
    int ret = RET_OK;
    vector<Cert::CerStore::AddedCerItem> added_ceritems;

    DO(cerStore->addCerts(
        Cert::NOT_TRUSTED,
        Cert::NOT_PERMANENT,
        sdataParser.getCerts(),
        added_ceritems
    ));
    for (const auto& it : added_ceritems) {
        if (it.cerItem) {
            addedCerts.push_back(it.cerItem);
        }
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
                Cert::findCertByCertId(addedCerts, cert_id) ||
                Cert::findCertByCertId(it_vsi.getListAddedCerts().fromSignature, cert_id)
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


const char* validationStatusToStr (
        const ValidationStatus validationStatus
)
{
    static const char* VALIDATION_STATUS_STRINGS[4] = {
        "UNDEFINED",
        "INDETERMINATE",
        "TOTAL-FAILED",
        "TOTAL-VALID"
    };
    return VALIDATION_STATUS_STRINGS[((uint32_t)validationStatus < 4) ? (uint32_t)validationStatus : 0];
}   //  validationStatusToStr

VerifyOptions::ValidationType validationTypeFromStr (
    const string& validationType
)
{
    VerifyOptions::ValidationType rv_type = VerifyOptions::ValidationType::UNDEFINED;
    if (validationType.empty() || (validationType == string("STRUCT"))) {
        rv_type = VerifyOptions::ValidationType::STRUCT;
    }
    else if (validationType == string("CHAIN")) {
        rv_type = VerifyOptions::ValidationType::CHAIN;
    }
    else if (validationType == string("FULL")) {
        rv_type = VerifyOptions::ValidationType::FULL;
    }
    return rv_type;
}   //  validationTypeFromStr


}   //  end namespace Verify

}   //  end namespace Doc

}   //  end namespace UapkiNS
