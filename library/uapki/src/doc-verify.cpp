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
#include "der-helper.h"
#include "archive-timestamp-v3.h"
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

static void revocation_info_choices (
    const VectorBA& revocationInfoChoices,
    VectorBA& crls,
    VectorBA& ocspVals
);


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



static const char* WARN_ISSUED_AFTER_EXPIRATION = "THE REVOCATION DATA WAS ISSUED AFTER THE CERTIFICATE EXPIRED";


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
    , parseFailed(false)
    , noHashIndex(false)
    , isV2(false)
    , attrIndex(0)
{}

AttrTimeStamp::~AttrTimeStamp (void)
{}

const ByteArray* AttrTimeStamp::getAtsHashIndexV3 (void) const
{
    for (const auto& it : signerInfo.getUnsignedAttrs()) {
        if (it.type == string(OID_ETSI_ATS_HASH_INDEX_V3)) {
            return it.baValues;
        }
    }
    return nullptr;
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

bool AttrTimeStamp::isPresent (void) const
{
    return (
        !parseFailed &&
        !policy.empty() && 
        !hashAlgo.empty() &&
        (hashedMessage.size() > 0)
    );
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
    , statusRevocationRefs(DigestVerifyStatus::UNDEFINED)
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

    //  The references are matched by IssuerSerial (or the hash), not by index: certificate-values holds
    //  the certificates of the references and the signing certificate if not in SignedData.certificates
    //  (EN 319 122-1, A.1.1.2), signatures of earlier versions also reference the signing certificate

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
        if (!it.issuerSerial.baIssuer || !it.issuerSerial.baSerialNumber) {
            //  Without IssuerSerial: one of the certificate values with the hash
            for (const auto& it_val : certValues) {
                SmartBA sba_valhash;
                if ((::hash(hash_alg, it_val, &sba_valhash) == RET_OK) && (ba_cmp(it.baHashValue, sba_valhash.get()) == 0)) {
                    refba_cert = it_val;
                    break;
                }
            }
            if (!refba_cert) {
                status = DigestVerifyStatus::INDETERMINATE;
                idx++;
                continue;
            }
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
    , m_NotProcessed(false)
    , m_RevocationFreshness(0)
    , m_TsaTrustByPoe(false)
    , m_RevocationFreshnessStrict(false)
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
    return addChainItem(m_CertChainItems, certEntity, cerItem, certChainItem, is_newitem);
}

int VerifiedSignerInfo::addCertChainItem (
        const CertEntity certEntity,
        Cert::CerItem* cerItem,
        CertChainItem** certChainItem,
        bool& isNewItem
)
{
    return addChainItem(m_CertChainItems, certEntity, cerItem, certChainItem, isNewItem);
}

uint64_t VerifiedSignerInfo::getTimeOfStatusData (
        const CertEntity certEntity,
        const Cert::CerItem* cerItem
) const
{
    for (const auto& it : m_CertChainItems) {
        if (certEntity == CertEntity::OCSP) {
            const ResultValidationByOcsp& result = it->getResultValidationByOcsp();
            if ((result.cerResponder == cerItem) && (result.msProducedAt > 0)) return result.msProducedAt;
        }
        else if (certEntity == CertEntity::CRL) {
            const ResultValidationByCrl& result = it->getResultValidationByCrl();
            if ((result.cerIssuer == cerItem) && result.crlItem) return result.crlItem->getThisUpdate();
        }
    }
    return 0;
}

int VerifiedSignerInfo::addSignerOfStatusToChain (
        const CertEntity certEntity,
        Cert::CerItem* cerItem,
        const uint64_t validateTime
)
{
    //  The signer of a CRL or an OCSP response with its own chain: shown, its validity and the trust of
    //  its root count. Its own status: not checked with id-pkix-ocsp-nocheck (RFC 6960, 4.2.2.2.1),
    //  valassured-ST-certs or noRevAvail, else by CRL (validate_certs of VERIFY), as EU DSS
    const size_t first_new = m_CertChainItems.size();
    CertChainItem* added_cci = nullptr;
    bool is_newitem = false;

    int ret = addChainItem(m_CertChainItems, certEntity, cerItem, &added_cci, is_newitem);
    if ((ret != RET_OK) || !is_newitem) return ret;

    //  The trust in the path of the signer of revocation data - at the time the data is validated for
    ret = CertValidator::buildCertChain(certEntity, cerItem, m_CertChainItems, nullptr, validateTime);
    if (ret == RET_UAPKI_CERT_ISSUER_NOT_FOUND) {
        m_LastError = ret;
        ret = RET_OK;
    }
    if (ret != RET_OK) return ret;

    if (cerItem->isNoRevocationCheck()) {
        added_cci->setValidationType(Cert::ValidationType::NONE);
    }
    for (size_t i = first_new; i < m_CertChainItems.size(); i++) {
        (void)m_CertChainItems[i]->checkValidityTime(validateTime);
    }
    {
        //  The signer of revocation data: valid when the data was issued (it may be issued later than the signature)
        const uint64_t status_time = getTimeOfStatusData(certEntity, cerItem);
        if (status_time > 0) {
            (void)added_cci->checkValidityTime(status_time);
        }
    }
    return RET_OK;
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
        const int ret = addSignerOfStatusToChain(CertEntity::CRL, it_cer, validateTime);
        if (ret != RET_OK) return ret;
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
        const int ret = addSignerOfStatusToChain(CertEntity::OCSP, it_cer, validateTime);
        if (ret != RET_OK) return ret;
    }
    return RET_OK;
}

int VerifiedSignerInfo::buildCertChain (void)
{
    int ret = RET_OK;
    vector<Cert::CerItem*> tsp_certs;

    //  The trust is decided at a time (a certificate of a trusted list is trusted in a period): the path of the
    //  signer - at the best signature time (it is set by validateSignFormat() from the time-stamps already verified;
    //  without a valid time-stamp it is the validation time), the path of a TSA - see tsa_time
    //  The time the TSA of a time-stamp must be trusted at. By default - the time of the time-stamp: that its key
    //  was not compromised is told by the revocation status of its certificate (RFC 3161, 4; tsaKeyTrust()).
    //  By proof of existence (the validation policy; ETSI EN 319 102-1): a time-stamp does not prove its own time,
    //  the TSA must be trusted at the time of a later valid time-stamp that covers it (an archive time-stamp over
    //  the signature time-stamp), and without one - at the validation time (0: now). The last time-stamp of a TSA
    //  counts
    const auto tsa_time = [this](const Cert::CerItem* cerTsa) -> uint64_t {
        std::vector<const AttrTimeStamp*> stamps;
        for (const AttrTimeStamp* it : { &m_ContentTS, &m_SignatureTS, &m_ArchiveTS }) {
            if (it->isPresent()) stamps.push_back(it);
        }
        for (const auto& it : m_ArchiveTSsNext) {
            if (it && it->isPresent()) stamps.push_back(it.get());
        }
        uint64_t rv = 0;
        for (size_t i = 0; i < stamps.size(); i++) {
            if (stamps[i]->cerSigner != cerTsa) continue;
            const AttrTimeStamp* later = (i + 1 < stamps.size()) ? stamps[i + 1] : nullptr;
            const bool later_valid = later && (later->msGenTime > 0)
                && (later->statusDigest == DigestVerifyStatus::VALID) && (later->statusSignature == SignatureVerifyStatus::VALID);
            rv = m_TsaTrustByPoe ? (later_valid ? later->msGenTime : 0) : ((stamps[i]->msGenTime > 0) ? stamps[i]->msGenTime : m_BestSignatureTime);
        }
        return rv;
    };

    //  Build chain for Signer
    if (m_CerSigner) {
        ret = CertValidator::buildCertChain(CertEntity::SIGNER, m_CerSigner, m_CertChainItems, nullptr, m_BestSignatureTime);
        if (ret == RET_UAPKI_CERT_ISSUER_NOT_FOUND) {
            m_LastError = ret;
            ret = RET_OK;
        }
        DO(ret);
    }

    //  Build chain for TSP
    for (const auto& it : m_ListAddedCerts.tsp) {
        (void)Cert::addCertIfUnique(tsp_certs, it);
    }
    for (const auto& it_tsp : tsp_certs) {
        ret = CertValidator::buildCertChain(CertEntity::TSP, it_tsp, m_CertChainItems, nullptr, tsa_time(it_tsp));
        if (ret == RET_UAPKI_CERT_ISSUER_NOT_FOUND) {
            m_LastError = ret;
            ret = RET_OK;
        }
        DO(ret);
    }

cleanup:
    return ret;
}

int VerifiedSignerInfo::crlValuesToStore (void)
{
    //  Not to the disk; a CRL whose signer is not known or not valid is not used
    vector<const ByteArray*> crl_vals;
    for (const auto& it : m_CadesXlInfo.revocationValuesParser.getCrlVals()) {
        crl_vals.push_back(it);
    }
    for (const auto& it : m_SdataCrls) {
        crl_vals.push_back(it);
    }
    for (const auto& it : m_TsCrls) {
        crl_vals.push_back(it);
    }
    for (const auto& it : crl_vals) {
        bool is_unique = false;
        Crl::CrlItem* crl_item = nullptr;
        (void)addCrlToStore(*getCrlStore(), *getCerStore(), it, false, nullptr, is_unique, &crl_item);
    }
    return RET_OK;
}

int VerifiedSignerInfo::setSignedDataRevocation (
        const VectorBA& sdataCrls
)
{
    revocation_info_choices(sdataCrls, m_SdataCrls, m_SdataOcspVals);
    return RET_OK;
}

//  OCSPResponse { responseStatus successful, responseBytes { id-pkix-ocsp-basic, BasicOCSPResponse } } in DER
ByteArray* ocspResponseFromBasic (
        const ByteArray* baBasicOcspResponse
)
{
    static const uint8_t OID_BASIC[] = { 0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01 };
    auto tl = [](const uint8_t tag, const size_t len) {
        vector<uint8_t> v = { tag };
        if (len < 0x80) {
            v.push_back((uint8_t)len);
        }
        else {
            vector<uint8_t> n;
            for (size_t l = len; l > 0; l >>= 8) n.insert(n.begin(), (uint8_t)(l & 0xFF));
            v.push_back((uint8_t)(0x80 | n.size()));
            v.insert(v.end(), n.begin(), n.end());
        }
        return v;
    };
    const size_t len_basic = ba_get_len(baBasicOcspResponse);
    vector<uint8_t> octets = tl(0x04, len_basic);
    octets.insert(octets.end(), ba_get_buf_const(baBasicOcspResponse), ba_get_buf_const(baBasicOcspResponse) + len_basic);
    vector<uint8_t> resp_bytes = tl(0x30, sizeof(OID_BASIC) + octets.size());
    resp_bytes.insert(resp_bytes.end(), OID_BASIC, OID_BASIC + sizeof(OID_BASIC));
    resp_bytes.insert(resp_bytes.end(), octets.begin(), octets.end());
    vector<uint8_t> explicit0 = tl(0xA0, resp_bytes.size());
    explicit0.insert(explicit0.end(), resp_bytes.begin(), resp_bytes.end());
    vector<uint8_t> body = { 0x0A, 0x01, 0x00 };
    body.insert(body.end(), explicit0.begin(), explicit0.end());
    vector<uint8_t> ocsp_response = tl(0x30, body.size());
    ocsp_response.insert(ocsp_response.end(), body.begin(), body.end());
    return ba_alloc_from_uint8(ocsp_response.data(), ocsp_response.size());
}

//  The hash of data by OtherHash (encoded): 1 - equal, 0 - not equal, -1 - unable to check
static int other_hash_equal (
        const ByteArray* baOtherHash,
        const ByteArray* baData
)
{
    OtherHash other_hash;
    if (AttributeHelper::decodeOtherHash(baOtherHash, other_hash) != RET_OK) return -1;
    const HashAlg hash_alg = hash_from_oid(other_hash.hashAlgorithm.algorithm.c_str());
    if (hash_alg == HASH_ALG_UNDEFINED) return -1;
    SmartBA sba_hash;
    if (::hash(hash_alg, baData, &sba_hash) != RET_OK) return -1;
    return (ba_cmp(other_hash.baHashValue, sba_hash.get()) == 0) ? 1 : 0;
}

int VerifiedSignerInfo::verifyRevocationRefs (void)
{
    //  The references against the revocation values of the signature itself (its integrity): a reference
    //  to data the signature does not have is not checked, one that points to other data is INVALID
    CadesXlInfo& xl_info = m_CadesXlInfo;
    if (!xl_info.isPresentRevocRefs) return RET_OK;

    xl_info.statusRevocationRefs = DigestVerifyStatus::VALID;
    vector<Crl::CrlItem*> crl_items;
    vector<const ByteArray*> crl_vals;
    for (const auto& it : xl_info.revocationValuesParser.getCrlVals()) {
        crl_vals.push_back(it);
    }
    for (const auto& it : m_SdataCrls) {
        crl_vals.push_back(it);
    }
    for (const auto& it : crl_vals) {
        //  parseCrl() gives the encoded CRL to the item: a copy, the CRLs of the signature stay its own
        Crl::CrlItem* crl_item = nullptr;
        SmartBA sba_copy;
        if (sba_copy.set(ba_copy_with_alloc(it, 0, 0)) && (Crl::parseCrl(sba_copy.get(), &crl_item) == RET_OK)) {
            (void)sba_copy.pop();
            crl_items.push_back(crl_item);
        }
    }
    vector<const ByteArray*> ocsp_vals;
    for (const auto& it : xl_info.revocationValuesParser.getOcspVals()) {
        ocsp_vals.push_back(it);
    }
    for (const auto& it : m_SdataOcspVals) {
        ocsp_vals.push_back(it);
    }

    for (size_t idx = 0; idx < xl_info.revocationRefsParser.getCountCrlOcspRefs(); idx++) {
        AttributeHelper::RevocationRefsParser::CrlOcspRef crlocsp_ref;
        if (xl_info.revocationRefsParser.parseCrlOcspRef(idx, crlocsp_ref) != RET_OK) {
            xl_info.statusRevocationRefs = DigestVerifyStatus::FAILED;
            break;
        }

        //  CRLs by crlIdentifier (issuer, issuedTime, crlNumber); not unique (segments): one of them has to match
        for (const auto& it_ref : crlocsp_ref.getCrlIds()) {
            if (!it_ref.isPresentId() || !it_ref.isPresentHash()) continue;
            bool found = false, matched = false;
            for (const auto& it_crl : crl_items) {
                if (ba_cmp(it_crl->getCrlIdentifier(), it_ref.baId) != 0) continue;
                found = true;
                if (other_hash_equal(it_ref.baHash, it_crl->getEncoded()) != 0) {
                    matched = true;
                    break;
                }
            }
            if (found && !matched) {
                xl_info.statusRevocationRefs = DigestVerifyStatus::INVALID;
            }
        }

        //  OCSP responses by ocspIdentifier (responderID, producedAt), the hash is of OCSPResponse;
        //  not unique (one responder answers for several certificates at once): one of them has to match
        for (const auto& it_ref : crlocsp_ref.getOcspIds()) {
            if (!it_ref.isPresentId() || !it_ref.isPresentHash()) continue;
            bool found = false, matched = false;
            for (const auto& it_ocspval : ocsp_vals) {
                Ocsp::OcspHelper ocsp_helper;
                SmartBA sba_ocspid, sba_ocspresp;
                if (
                    (ocsp_helper.parseBasicOcspResponse(it_ocspval) != RET_OK) ||
                    (ocsp_helper.getOcspIdentifier(&sba_ocspid) != RET_OK) ||
                    (ba_cmp(sba_ocspid.get(), it_ref.baId) != 0)
                ) continue;
                found = true;
                //  The hash of OCSPResponse or of BasicOCSPResponse (EN 319 122-1, A.1.2.1 and 5.4.2.1)
                if (other_hash_equal(it_ref.baHash, it_ocspval) == 1) {
                    matched = true;
                    break;
                }
                if (!sba_ocspresp.set(ocspResponseFromBasic(it_ocspval))) continue;
                if (other_hash_equal(it_ref.baHash, sba_ocspresp.get()) != 0) {
                    matched = true;
                    break;
                }
            }
            if (found && !matched) {
                xl_info.statusRevocationRefs = DigestVerifyStatus::INVALID;
            }
        }
    }

    for (auto& it : crl_items) {
        delete it;
    }
    return RET_OK;
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

//  The revocation data of the signature: revocationValues, SignedData.crls, the validation data of the TSUs
static bool contains_encoded (
        const vector<const ByteArray*>& values,
        const ByteArray* baEncoded
)
{
    if (!baEncoded) return false;
    for (const auto& it : values) {
        if (ba_cmp(it, baEncoded) == 0) return true;
    }
    return false;
}

//  The signature has a CRL for the certificate the CRL crlUsed gave the status of: crlUsed itself or another CRL of
//  the same issuer, type and scope that is not expired at validateTime. The level of a signature is by its own data:
//  the status may have been taken by a newer CRL of the CRL cache
static bool has_crl_as (
        const vector<const ByteArray*>& values,
        const Crl::CrlItem* crlUsed,
        const uint64_t validateTime
)
{
    if (!crlUsed) return false;
    if (contains_encoded(values, crlUsed->getEncoded())) return true;

    bool rv = false;
    for (const auto& it : values) {
        //  parseCrl() gives the encoded CRL to the item: a copy, the CRLs of the signature stay its own
        Crl::CrlItem* crl_item = nullptr;
        SmartBA sba_copy;
        if (!sba_copy.set(ba_copy_with_alloc(it, 0, 0)) || (Crl::parseCrl(sba_copy.get(), &crl_item) != RET_OK)) continue;
        (void)sba_copy.pop();
        rv = (crl_item->getType() == crlUsed->getType()) &&
            (ba_cmp(crl_item->getIssuer(), crlUsed->getIssuer()) == 0) &&
            (ba_cmp(crl_item->getAuthorityKeyId(), crlUsed->getAuthorityKeyId()) == 0) &&
            (crl_item->getIdp().encoded == crlUsed->getIdp().encoded) &&
            (crl_item->getNextUpdate() >= validateTime);
        delete crl_item;
        if (rv) break;
    }
    return rv;
}

bool VerifiedSignerInfo::hasCompleteValidationData (
        const bool onlySignerPath
) const
{
    //  onlySignerPath - CAdES-XL, CAdES-A (TS 101 733, 6.2.2, 6.3.4): the revocation references and values are of
    //  the signing certificate and of each CA certificate of its path; else every certificate of the chains,
    //  with the TSUs, the OCSP responders and the CRL signers (CAdES-B-LT, B-LTA: EN 319 122-1, table 1)
    vector<const Cert::CerItem*> signer_path;
    if (onlySignerPath) {
        const CertChainItem* item = nullptr;
        for (const auto& it : m_CertChainItems) {
            if (it->getCertEntity() == CertEntity::SIGNER) {
                item = it;
                break;
            }
        }
        bool is_ended = false;
        for (size_t guard = 0; item && (guard <= m_CertChainItems.size()); guard++) {
            signer_path.push_back(item->getSubject());
            const Cert::CerItem* cer_issuer = item->getIssuer();
            is_ended = (item->getCertEntity() == CertEntity::ROOT) || (cer_issuer == item->getSubject());
            if (is_ended || !cer_issuer) break;
            const CertChainItem* item_issuer = nullptr;
            for (const auto& it : m_CertChainItems) {
                if (it->getSubject() == cer_issuer) {
                    item_issuer = it;
                    break;
                }
            }
            item = item_issuer;
        }
        //  The path of the signer is not built up to its root
        if (!is_ended) return false;
    }
    else if (!getExpectedCerts().empty() || !getExpectedCrls().empty()) {
        return false;
    }

    vector<const ByteArray*> crl_vals;
    for (const auto& it : m_CadesXlInfo.revocationValuesParser.getCrlVals()) {
        crl_vals.push_back(it);
    }
    for (const auto& it : m_SdataCrls) {
        crl_vals.push_back(it);
    }
    for (const auto& it : m_TsCrls) {
        crl_vals.push_back(it);
    }

    for (const auto& it : m_CertChainItems) {
        //  The trust anchor is not in the validation data (from the trusted list), an expired certificate
        //  makes the result INDETERMINATE or TOTAL-FAILED (validateStatusCerts)
        if ((it->getCertEntity() == CertEntity::ROOT) || it->isExpired()) continue;
        if (
            onlySignerPath &&
            (std::find(signer_path.begin(), signer_path.end(), it->getSubject()) == signer_path.end())
        ) continue;
        if (it->getDataSource() != DataSource::SIGNATURE) return false;
        switch (it->getValidationType()) {
        case Cert::ValidationType::NONE:
            //  id-pkix-ocsp-nocheck: no revocation data needed
            break;
        case Cert::ValidationType::OCSP:
            if (it->getResultValidationByOcsp().dataSource != DataSource::SIGNATURE) return false;
            break;
        case Cert::ValidationType::CRL: {
            const ResultValidationByCrl& result = it->getResultValidationByCrl();
            if (!has_crl_as(crl_vals, result.crlItem, m_BestSignatureTime)) return false;
            if (result.crlFull && !has_crl_as(crl_vals, result.crlFull, m_BestSignatureTime)) return false;
            break;
        }
        default:
            return false;
        }
    }
    return true;
}

void VerifiedSignerInfo::lowerSignFormatByValidationData (void)
{
    switch (m_SignatureFormat) {
    case SignatureFormat::CADES_B_LT:
    case SignatureFormat::CADES_B_LTA:
        if (!hasCompleteValidationData(false)) {
            m_SignatureFormat = SignatureFormat::CADES_T;
        }
        break;
    case SignatureFormat::CADES_XL:
    case SignatureFormat::CADES_A:
        if (!hasCompleteValidationData(true)) {
            m_SignatureFormat = m_CadesXlInfo.isPresentCadesC() ? SignatureFormat::CADES_C : SignatureFormat::CADES_T;
        }
        break;
    default:
        break;
    }
}

void VerifiedSignerInfo::determineSignFormat (void)
{
    //  Each level by its own attributes: T - signature time-stamp (content time-stamp is optional),
    //  C - complete references, XL - revocation values: the attributes certValues and revocationValues (TS 101 733),
    //  B-LT - the revocation data in SignedData.crls only (EN 319 122-1), A - archive time-stamp,
    //  B-LTA - archive-time-stamp-v3 with ats-hash-index-v3 on B-LT (EN 319 122-1)
    if (m_SignatureFormat == SignatureFormat::CADES_BES) {
        if (m_SignatureTS.isPresent()) {
            m_SignatureFormat = SignatureFormat::CADES_T;
            if (m_CadesXlInfo.isPresentCadesC()) {
                m_SignatureFormat = SignatureFormat::CADES_C;
            }
            if (hasRevocationValues()) {
                m_SignatureFormat = hasCadesXlAttributes() ? SignatureFormat::CADES_XL : SignatureFormat::CADES_B_LT;
            }
            if (m_ArchiveTS.isPresent()) {
                m_SignatureFormat = (!hasCadesXlAttributes() && m_ArchiveTS.getAtsHashIndexV3())
                    ? SignatureFormat::CADES_B_LTA : SignatureFormat::CADES_A;
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

    for (const auto& it : m_ChainWarnings) {
        rv_warns.push_back(it);
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
    vector<const ByteArray*> ocsp_vals;
    for (const auto& it : m_CadesXlInfo.revocationValuesParser.getOcspVals()) {
        ocsp_vals.push_back(it);
    }
    for (const auto& it : m_SdataOcspVals) {
        ocsp_vals.push_back(it);
    }
    for (const auto& it : m_TsOcspVals) {
        ocsp_vals.push_back(it);
    }

    for (const auto& it_ocspval : ocsp_vals) {
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
            if (
                result_valbyocsp.cerResponder &&
                (std::find(m_ListAddedCerts.ocsp.begin(), m_ListAddedCerts.ocsp.end(), result_valbyocsp.cerResponder) == m_ListAddedCerts.ocsp.end())
            ) {
                m_ListAddedCerts.ocsp.push_back(result_valbyocsp.cerResponder);
            }
            //  Not fresh for the validation time: not used (the status from other data or online)
            LibraryConfig::OcspParams ocsp_params = getLibConfig()->getOcsp();
            if (m_RevocationFreshness > 0) {
                ocsp_params.maxFreshness = m_RevocationFreshness;
            }
            //  The strict freshness: a response issued before the time the signature is validated for is used up to
            //  its nextUpdate (the validation is to be repeated then: the same response would come before); after
            //  it, or without nextUpdate, a newer one is looked for
            const bool is_stale = m_RevocationFreshnessStrict
                && (result_valbyocsp.singleResponseInfo.msThisUpdate < validateTime)
                && (result_valbyocsp.singleResponseInfo.msNextUpdate <= TimeUtil::mtimeNow());
            if (
                is_stale ||
                !ocsp_params.isFresh(
                    result_valbyocsp.singleResponseInfo.msThisUpdate,
                    result_valbyocsp.singleResponseInfo.msNextUpdate,
                    validateTime
                )
            ) {
                m_UnusedRevocationData.push_back(std::make_pair(it_cci, string("THE REVOCATION DATA OF THE SIGNATURE IS NOT FRESH")));
                continue;
            }
            //  "Good" issued after the certificate expired: not used (the status from other data or online)
            if (
                (result_valbyocsp.singleResponseInfo.certStatus == UapkiNS::CertStatus::GOOD) &&
                !UapkiNS::CertValidator::revocationCoversCert(
                    it_cci->getSubject(),
                    result_valbyocsp.singleResponseInfo.msThisUpdate,
                    result_valbyocsp.singleResponseInfo.msArchiveCutoff,
                    getCaRemovesExpiredCerts()
                )
            ) {
                m_UnusedRevocationData.push_back(std::make_pair(it_cci, string(WARN_ISSUED_AFTER_EXPIRATION)));
                continue;
            }
            it_cci->setValidationType(Cert::ValidationType::OCSP);
            //  A response may hold the statuses of several certificates (RFC 6960, 4.2.1): all of them are used
        }
    }

    validateValidityTimeCerts(validateTime);
    return RET_OK;
}

//  RevocationInfoChoices: CRLs and OCSP responses (RFC 5940: OCSPResponse; EN 319 122-1 4.8.2 also BasicOCSPResponse)
static void revocation_info_choices (
        const VectorBA& revocationInfoChoices,
        VectorBA& crls,
        VectorBA& ocspVals
)
{
    for (const auto& it : revocationInfoChoices) {
        RevocationInfoChoice_t* revinfo_choice = (RevocationInfoChoice_t*)asn_decode_ba_with_alloc(
            get_RevocationInfoChoice_desc(), it);
        if (!revinfo_choice) continue;

        if (revinfo_choice->present == RevocationInfoChoice_PR_crl) {
            //  CertificateList is not tagged in RevocationInfoChoice
            ByteArray* ba_crl = ba_copy_with_alloc(it, 0, 0);
            if (ba_crl) {
                crls.push_back(ba_crl);
            }
        }
        else if (
            (revinfo_choice->present == RevocationInfoChoice_PR_other) &&
            OID_is_equal_oid(&revinfo_choice->choice.other.otherRevInfoFormat, OID_PKIX_RiOcspResponse)
        ) {
            const ANY_t& other_revinfo = revinfo_choice->choice.other.otherRevInfo;
            SmartBA sba_value;
            if (sba_value.set(ba_alloc_from_uint8(other_revinfo.buf, (size_t)other_revinfo.size))) {
                Ocsp::OcspHelper ocsp_helper;
                if (
                    (ocsp_helper.parseResponse(sba_value.get()) == RET_OK) &&
                    (ocsp_helper.getResponseStatus() == Ocsp::ResponseStatus::SUCCESSFUL)
                ) {
                    ByteArray* ba_basic = ocsp_helper.getBasicOcspResponseEncoded(true);
                    if (ba_basic) {
                        ocspVals.push_back(ba_basic);
                    }
                }
                else {
                    Ocsp::OcspHelper ocsp_basic;
                    if (ocsp_basic.parseBasicOcspResponse(sba_value.get()) == RET_OK) {
                        ocspVals.push_back(sba_value.pop());
                    }
                }
            }
        }
        asn_free(get_RevocationInfoChoice_desc(), revinfo_choice);
    }
}   //  revocation_info_choices

int VerifiedSignerInfo::tspValidationData (
        AttrTimeStamp& attrTS
)
{
    //  The validation data of a TSU in its time-stamp token (TS 101 733 6.3.3, 6.3.4): certificate-values and
    //  revocation-values of the unsigned attributes of the token and its SignedData.crls
    Pkcs7::SignedDataParser& sdata_parser = attrTS.tsTokenParser.getSignedDataParser();
    revocation_info_choices(sdata_parser.getCrls(), m_TsCrls, m_TsOcspVals);
    if (sdata_parser.getCountSignerInfos() == 0) return RET_OK;

    Pkcs7::SignedDataParser::SignerInfo signer_info;
    if (sdata_parser.parseSignerInfo(0, signer_info) != RET_OK) return RET_OK;
    for (const auto& it : signer_info.getUnsignedAttrs()) {
        if (it.type == string(OID_PKCS9_CERT_VALUES)) {
            VectorBA vba_certs;
            if (AttributeHelper::decodeCertValues(it.baValues, vba_certs) == RET_OK) {
                vector<Cert::CerStore::AddedCerItem> added_ceritems;
                (void)getCerStore()->addCerts(Cert::NOT_TRUSTED, Cert::NOT_PERMANENT, vba_certs, added_ceritems);
                for (const auto& it_added : added_ceritems) {
                    if (it_added.cerItem) {
                        m_ListAddedCerts.fromSignature.push_back(it_added.cerItem);
                    }
                }
            }
        }
        else if (it.type == string(OID_PKCS9_REVOCATION_VALUES)) {
            AttributeHelper::RevocationValuesParser revvals_parser;
            if (revvals_parser.parse(it.baValues) == RET_OK) {
                for (const auto& it_crl : revvals_parser.getCrlVals()) {
                    m_TsCrls.push_back(ba_copy_with_alloc(it_crl, 0, 0));
                }
                for (const auto& it_ocsp : revvals_parser.getOcspVals()) {
                    m_TsOcspVals.push_back(ba_copy_with_alloc(it_ocsp, 0, 0));
                }
            }
        }
    }
    return RET_OK;
}

int VerifiedSignerInfo::tspCertToStore() {
    int ret = RET_OK;

    //  The certificates of the time-stamp tokens are of the signature
    for (AttrTimeStamp* attr_ts : { &m_ContentTS, &m_SignatureTS }) {
        if (!attr_ts->isPresent()) continue;
        Pkcs7::SignedDataParser& sdata_parser = attr_ts->tsTokenParser.getSignedDataParser();
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
    }
    if (m_ContentTS.isPresent()) {
        DO(tspValidationData(m_ContentTS));
    }
    if (m_SignatureTS.isPresent()) {
        DO(tspValidationData(m_SignatureTS));
    }
    //  An archive time-stamp token holds the validation material added after an earlier form of archive
    //  time-stamp (EN 319 122-1, 5.5.3)
    if (m_ArchiveTS.isPresent()) {
        DO(tspValidationData(m_ArchiveTS));
        for (auto& it : m_ArchiveTSsNext) {
            DO(tspValidationData(*it));
        }
    }

cleanup:
    return ret;
}

void VerifiedSignerInfo::setNotProcessed (
        const int errorCode
)
{
    m_LastError = errorCode;
    if ((errorCode == RET_VERIFY_FAILED) && (m_StatusSignature == SignatureVerifyStatus::INVALID)) {
        m_ValidationStatus = ValidationStatus::TOTAL_FAILED;
    }
    else {
        m_NotProcessed = true;
        m_ValidationStatus = ValidationStatus::INDETERMINATE;
        const string s_warn = "THE SIGNATURE IS NOT PROCESSED COMPLETELY";
        if (std::find(m_ChainWarnings.begin(), m_ChainWarnings.end(), s_warn) == m_ChainWarnings.end()) {
            m_ChainWarnings.push_back(s_warn);
        }
    }
}

static bool timestamp_is_valid (
        const AttrTimeStamp& attrTS
)
{
    return (attrTS.statusSignature == SignatureVerifyStatus::VALID) && (attrTS.statusDigest == DigestVerifyStatus::VALID);
}

}   //  end namespace Verify
}   //  end namespace Doc
}   //  end namespace UapkiNS

std::vector<UapkiNS::Doc::Verify::CryptoRule> UapkiNS::Doc::Verify::defaultCryptoRules (void)
{
    const auto ms = [](const char* date) -> uint64_t {
        uint64_t rv = 0;
        (void)TimeUtil::ftimeToMtime(string(date) + " 00:00:00", rv);
        return rv;
    };
    return {
        { "SHA1",       0,    ms("2012-08-01"), false },
        { "SHA224",     0,    ms("2029-01-01"), false },   //  TS 119 312, table 1: L[2028]
        { "RIPEMD160",  0,    ms("2014-08-01"), false },
        { "WHIRLPOOL",  0,    ms("2020-12-01"), false },
        { "GOST34311",  0,    ms("2026-09-01"), true },
        { "RSA",        1024, ms("2010-08-01"), false },
        { "RSA",        1900, ms("2019-10-01"), false },
        { "RSA",        3000, ms("2029-01-01"), false },   //  TS 119 312, table 6: 2028-12-31
        { "EC",         224,  ms("2012-08-01"), false },
        { "EC",         256,  ms("2021-10-01"), false }
    };
}

namespace UapkiNS {
namespace Doc {
namespace Verify {

vector<string> VerifiedSignerInfo::getTimeStampOrderFailures (void) const
{
    //  A time-stamp is later than the ones over the data it covers: the content time-stamp, the signature
    //  time-stamp, the archive time-stamps one after another. RFC 3161, 2.4.2: the order of two tokens is known
    //  when the difference of their times is greater than the sum of their accuracies (an absent accuracy is
    //  taken as zero); two tokens of one TSA with the ordering field set are ordered by the times alone
    struct Stamp {
        const AttrTimeStamp* ts;
        const char* name;
    };
    vector<Stamp> stamps;
    if (m_ContentTS.isPresent() && timestamp_is_valid(m_ContentTS)) stamps.push_back({ &m_ContentTS, "CONTENT_TIME_STAMP" });
    if (m_SignatureTS.isPresent() && timestamp_is_valid(m_SignatureTS)) stamps.push_back({ &m_SignatureTS, "SIGNATURE_TIME_STAMP" });
    if (m_ArchiveTS.isPresent() && timestamp_is_valid(m_ArchiveTS)) stamps.push_back({ &m_ArchiveTS, "ARCHIVE_TIME_STAMP" });
    for (const auto& it : m_ArchiveTSsNext) {
        if (it && it->isPresent() && timestamp_is_valid(*it)) stamps.push_back({ it.get(), "ARCHIVE_TIME_STAMP" });
    }

    vector<string> rv;
    for (size_t i = 0; i < stamps.size(); i++) {
        for (size_t j = i + 1; j < stamps.size(); j++) {
            const AttrTimeStamp& first = *stamps[i].ts;
            const AttrTimeStamp& second = *stamps[j].ts;
            if ((first.msGenTime == 0) || (second.msGenTime == 0) || (second.msGenTime >= first.msGenTime)) continue;
            const bool ordered_by_tsa = (first.cerSigner != nullptr) && (first.cerSigner == second.cerSigner)
                && first.tsTokenParser.getOrdering() && second.tsTokenParser.getOrdering();
            const uint64_t us_diff = (first.msGenTime - second.msGenTime) * 1000;
            if (ordered_by_tsa || (us_diff > first.tsTokenParser.getAccuracyUs() + second.tsTokenParser.getAccuracyUs())) {
                const string s_failure = string(stamps[j].name) + ((stamps[i].name == stamps[j].name) ? "_BEFORE_PREVIOUS_" : "_BEFORE_") + stamps[i].name;
                if (std::find(rv.begin(), rv.end(), s_failure) == rv.end()) rv.push_back(s_failure);
            }
        }
    }
    return rv;
}

bool VerifiedSignerInfo::archiveTimeStampCoversCert (
        const AttrTimeStamp& archiveTS,
        const Cert::CerItem* cerItem
) const
{
    Pkcs7::AtsV3::IndexType index_type = Pkcs7::AtsV3::IndexType::EN_319_122;
    const ByteArray* ba_hashindex = archiveTS.getAtsHashIndex(index_type);
    if (!ba_hashindex || m_CadesXlInfo.isPresentCertVals) return true;
    bool has_cert = false;
    return (Pkcs7::AtsV3::indexHasCert(index_type, ba_hashindex, cerItem->getEncoded(), has_cert) == RET_OK) && has_cert;
}

bool VerifiedSignerInfo::isTsaOfValidTimeStamp (
        const Cert::CerItem* cerItem
) const
{
    if (m_ContentTS.isPresent() && timestamp_is_valid(m_ContentTS) && (m_ContentTS.cerSigner == cerItem)) return true;
    if (m_SignatureTS.isPresent() && timestamp_is_valid(m_SignatureTS) && (m_SignatureTS.cerSigner == cerItem)) return true;
    if (m_ArchiveTS.isPresent() && timestamp_is_valid(m_ArchiveTS) && (m_ArchiveTS.cerSigner == cerItem)) return true;
    for (const auto& it : m_ArchiveTSsNext) {
        if (timestamp_is_valid(*it) && (it->cerSigner == cerItem)) return true;
    }
    return false;
}

void VerifiedSignerInfo::validateSignFormat (
        const uint64_t validateTime
)
{
    CollectVerifyStatus collect_digests, collect_signatures;

    //  Check mandatory elements
    (void)collect_signatures.set(getStatusSignature());
    (void)collect_digests.set(getStatusMessageDigest());
    //  The best signature time starts at the validation time - the current one or the one given (ETSI EN 319 102-1,
    //  5.5.4 1)) - whatever the result of the cryptographic checks; only time-stamps make it earlier. The signingTime
    //  attribute is a claim of the signer, not a proof of time
    m_BestSignatureTime = validateTime;

    //  Check attribute EssCert
    if (getStatusEssCert() != DataVerifyStatus::NOT_PRESENT) {
        collect_digests.set(getStatusEssCert());
    }

    //  A time-stamp that is not valid (the message imprint or the signature of the token) does not make
    //  the signature invalid: it is not used, as if absent, with a remark (ETSI EN 319 102-1, 5.5.4 4) a), b),
    //  5.6.3 5) d): the token is removed from the set / the attribute is ignored)
    const auto warn_unused = [this](const char* warning) {
        const string s_warn = warning;
        if (std::find(m_ChainWarnings.begin(), m_ChainWarnings.end(), s_warn) == m_ChainWarnings.end()) {
            m_ChainWarnings.push_back(s_warn);
        }
    };

    //  Check Content-Timestamp
    if (m_ContentTS.isPresent()) {
        //  It proves the time of the data, not of the signature
        if (timestamp_is_valid(m_ContentTS)) {
            collect_signatures.set(m_ContentTS.statusSignature);
            collect_digests.set(m_ContentTS.statusDigest);
        }
        else {
            warn_unused("THE CONTENT TIME-STAMP IS NOT VALID AND IS NOT USED");
        }
    }

    //  Check Signature-Timestamp: the earliest proof of the signature time
    bool time_proven = false;
    if (m_SignatureTS.isPresent()) {
        if (timestamp_is_valid(m_SignatureTS)) {
            collect_signatures.set(m_SignatureTS.statusSignature);
            collect_digests.set(m_SignatureTS.statusDigest);
            m_BestSignatureTime = m_SignatureTS.msGenTime;
            time_proven = true;
        }
        else {
            warn_unused("THE SIGNATURE TIME-STAMP IS NOT VALID AND IS NOT USED");
        }
    }

    //  complete-certificate-references: see validateStatusCerts() (unsigned validation material, not a signed hash)

    //  Check Archive-Timestamp: every one; the earliest valid one is a later proof, when the signature
    //  time-stamp gives none
    if (m_ArchiveTS.isPresent()) {
        vector<const AttrTimeStamp*> archive_tss;
        archive_tss.push_back(&m_ArchiveTS);
        for (const auto& it : m_ArchiveTSsNext) {
            archive_tss.push_back(it.get());
        }
        bool any_usable = false;
        for (const auto& it : archive_tss) {
            if (!timestamp_is_valid(*it)) {
                //  Not proven invalid: the message imprint is not computed (an archive-time-stamp of TS 101 733
                //  needs the external content itself, not its hash), or the certificate of the TSA is not found
                const bool is_invalid = (it->statusDigest == DigestVerifyStatus::INVALID) || (it->statusSignature == SignatureVerifyStatus::INVALID);
                warn_unused(it->noHashIndex
                    ? "AN ARCHIVE TIME-STAMP HAS NO HASH INDEX AND IS NOT USED"
                    : (is_invalid
                        ? "AN ARCHIVE TIME-STAMP IS NOT VALID AND IS NOT USED"
                        : "AN ARCHIVE TIME-STAMP IS NOT VERIFIED AND IS NOT USED"));
                any_usable |= !is_invalid;
                continue;
            }
            any_usable = true;
            collect_signatures.set(it->statusSignature);
            collect_digests.set(it->statusDigest);
            if (!time_proven) {
                m_BestSignatureTime = it->msGenTime;
                time_proven = true;
            }
        }

        //  Every archive time-stamp is invalid: the level of the signature is the one it has without them
        if (!any_usable) {
            if (m_SignatureFormat == SignatureFormat::CADES_B_LTA) {
                m_SignatureFormat = SignatureFormat::CADES_B_LT;
            }
            else if (m_SignatureFormat == SignatureFormat::CADES_A) {
                m_SignatureFormat = SignatureFormat::CADES_T;
                if (m_CadesXlInfo.isPresentCadesC()) {
                    m_SignatureFormat = SignatureFormat::CADES_C;
                }
                if (hasRevocationValues()) {
                    m_SignatureFormat = hasCadesXlAttributes() ? SignatureFormat::CADES_XL : SignatureFormat::CADES_B_LT;
                }
            }
        }
    }

    m_IsValidSignatures = collect_signatures.isValid();
    m_IsValidDigests = collect_digests.isValid();
    if (isCryptoFailed()) {
        m_ValidationStatus = ValidationStatus::TOTAL_FAILED;
    }
    else if (m_IsValidSignatures && m_IsValidDigests) {
        m_ValidationStatus = ValidationStatus::TOTAL_VALID;
    }
    else if (collect_signatures.isDeterminate() || collect_digests.isDeterminate()) {
        m_ValidationStatus = ValidationStatus::INDETERMINATE;
    }
    else {
        m_ValidationStatus = ValidationStatus::TOTAL_FAILED;
    }
}

void VerifiedSignerInfo::validateStatusCerts (
        const bool checkCriticalExtensions
)
{
    ValidationStatusHelper validation_status(m_ValidationStatus);

    if (validation_status.isUndefined() || validation_status.isTotalFailed()) return;

    //  The order of the time-stamps is not kept (ETSI EN 319 102-1, 5.5.4, step 4 e: TIMESTAMP_ORDER_FAILURE)
    if (!getTimeStampOrderFailures().empty()) {
        validation_status.setIndeterminate();
        const string s_warn = "THE ORDER OF THE TIME-STAMPS IS NOT KEPT";
        if (std::find(m_ChainWarnings.begin(), m_ChainWarnings.end(), s_warn) == m_ChainWarnings.end()) {
            m_ChainWarnings.push_back(s_warn);
        }
    }

    //  Current value is TOTAL_VALID or INDETERMINATE
    for (const auto& it : m_CertChainItems) {
        //  The TSA of a time-stamp that is not valid: the time-stamp is not used, nor is the status of its certificate
        if ((it->getCertEntity() == CertEntity::TSP) && !isTsaOfValidTimeStamp(it->getSubject())) continue;

        switch (it->getVerifyStatus()) {
        case Cert::VerifyStatus::VALID: {
            //  The status of an OCSP responder (a CRL signer) is required (RFC 6960, 4.2.2.2.1): the certificate
            //  is a service of a trusted list or has id-pkix-ocsp-nocheck (no status is looked for), else its
            //  revocation data is in the signature, in the cache or online. Not determined - INDETERMINATE
            if (
                ((it->getCertEntity() == CertEntity::OCSP) || (it->getCertEntity() == CertEntity::CRL)) &&
                (it->getValidationType() == Cert::ValidationType::UNDEFINED)
            ) {
                validation_status.setIndeterminate();
                const string s_warn = "THE STATUS OF THE OCSP RESPONDER IS NOT DETERMINED";
                if (std::find(m_ChainWarnings.begin(), m_ChainWarnings.end(), s_warn) == m_ChainWarnings.end()) {
                    m_ChainWarnings.push_back(s_warn);
                }
            }
            else {
                validation_status.setByCertChainItem(*it, m_BestSignatureTime);
            }
            //  The time-stamps of a TSA whose key is compromised, or whose certificate is revoked with no reason
            //  given, are not trusted whenever they were made
            if ((it->getCertEntity() == CertEntity::TSP) && (UapkiNS::CertValidator::tsaKeyTrust(*it) != UapkiNS::CertValidator::TsaKeyTrust::OK)) {
                validation_status.setIndeterminate();
                const string s_warn = (UapkiNS::CertValidator::tsaKeyTrust(*it) == UapkiNS::CertValidator::TsaKeyTrust::COMPROMISED)
                    ? "THE KEY OF THE TSA IS COMPROMISED" : "THE TSA CERTIFICATE IS REVOKED WITH NO REASON GIVEN";
                if (std::find(m_ChainWarnings.begin(), m_ChainWarnings.end(), s_warn) == m_ChainWarnings.end()) {
                    m_ChainWarnings.push_back(s_warn);
                }
            }
            if (
                ((it->getValidationType() == Cert::ValidationType::CRL) && it->getResultValidationByCrl().issuedAfterExpiration) ||
                ((it->getValidationType() == Cert::ValidationType::OCSP) && it->getResultValidationByOcsp().issuedAfterExpiration)
            ) {
                const string s_warn = WARN_ISSUED_AFTER_EXPIRATION;
                if (std::find(m_ChainWarnings.begin(), m_ChainWarnings.end(), s_warn) == m_ChainWarnings.end()) {
                    m_ChainWarnings.push_back(s_warn);
                }
            }
            //  A chain proves nothing unless it ends in a trusted root
            if ((it->getCertEntity() == CertEntity::ROOT) && !it->isTrusted()) {
                validation_status.setIndeterminate();
            }
            //  Constraints of the chain (as ETSI EN 319 102-1 CHAIN_CONSTRAINTS_FAILURE / SIG_CONSTRAINTS_FAILURE)
            const UapkiNS::CertValidator::ChainConstraint constraint = UapkiNS::CertValidator::checkChainConstraints(*it, m_CertChainItems, checkCriticalExtensions);
            if (constraint != UapkiNS::CertValidator::ChainConstraint::NONE) {
                validation_status.setIndeterminate();
                const string s_warn = UapkiNS::CertValidator::chainConstraintToStr(constraint);
                if (std::find(m_ChainWarnings.begin(), m_ChainWarnings.end(), s_warn) == m_ChainWarnings.end()) {
                    m_ChainWarnings.push_back(s_warn);
                }
            }
            break;
        }
        case Cert::VerifyStatus::UNDEFINED:
            //  Not verified: the issuer is missing (expected certificate)
        case Cert::VerifyStatus::INDETERMINATE:
        case Cert::VerifyStatus::VALID_WITHOUT_KEYUSAGE:
            validation_status.setIndeterminate();
            DEBUG_OUTCON(printf("VerifiedSignerInfo::validateStatusCerts() set INDETERMINATE for cert (CommonName: '%s')", it->getCommonName().c_str()));
            break;
        default:
            //  Other cases (VerifyStatus::INVALID and VerifyStatus::FAILED)
            validation_status.setTotalFailed();
            break;
        }

        if (it->isExpired()) {
            //  Outside the validity period at the best signature time (ETSI EN 319 102-1, 5.3.4, 5.5.4). The signing
            //  certificate before notBefore - FAILED (NOT_YET_VALID). After notAfter the signature may have been made in time: that it
            //  was not is proven only by a valid content time-stamp later than notAfter of the signing certificate
            //  (FAILED, EXPIRED); otherwise INDETERMINATE (OUT_OF_BOUNDS_NO_POE), as EU DSS
            const Cert::CerItem* cer_subject = it->getSubject();
            const bool is_notyetvalid = (it->getCertEntity() == CertEntity::SIGNER) &&
                (m_BestSignatureTime > 0) && (cer_subject->getNotBefore() > m_BestSignatureTime);
            const bool is_signedafter = (it->getCertEntity() == CertEntity::SIGNER) &&
                m_ContentTS.isPresent() &&
                (m_ContentTS.statusDigest == DigestVerifyStatus::VALID) &&
                (m_ContentTS.statusSignature == SignatureVerifyStatus::VALID) &&
                (m_ContentTS.msGenTime > cer_subject->getNotAfter());
            if (is_notyetvalid || is_signedafter) {
                validation_status.setTotalFailed();
            }
            else {
                validation_status.setIndeterminate();
                const string s_warn = (it->getCertEntity() == CertEntity::SIGNER)
                    ? "THE CERTIFICATE OF THE SIGNER IS EXPIRED, THE SIGNING BEFORE ITS EXPIRATION IS NOT PROVEN"
                    : "A CERTIFICATE OF THE CHAIN IS EXPIRED";
                if (std::find(m_ChainWarnings.begin(), m_ChainWarnings.end(), s_warn) == m_ChainWarnings.end()) {
                    m_ChainWarnings.push_back(s_warn);
                }
            }
        }
        if (validation_status.isTotalFailed()) {
            DEBUG_OUTCON(printf("VerifiedSignerInfo::validateStatusCerts() set TOTAL_FAILED for cert (CommonName: '%s')", it->getCommonName().c_str()));
            return;
        }
    }

    //  The references are unsigned validation material: they do not match - the material is not usable,
    //  the signature is not proven invalid (ETSI EN 319 102-1, 5.1.3: INDETERMINATE, not TOTAL-FAILED)
    if (m_CadesXlInfo.statusRevocationRefs == DigestVerifyStatus::INVALID) {
        validation_status.setIndeterminate();
        const string s_warn = "THE REVOCATION REFERENCES DO NOT MATCH THE REVOCATION DATA";
        if (std::find(m_ChainWarnings.begin(), m_ChainWarnings.end(), s_warn) == m_ChainWarnings.end()) {
            m_ChainWarnings.push_back(s_warn);
        }
    }
    if (m_CadesXlInfo.isPresentCertRefs && (m_CadesXlInfo.statusCertRefs != DigestVerifyStatus::VALID)) {
        validation_status.setIndeterminate();
        if (
            (m_CadesXlInfo.statusCertRefs == DigestVerifyStatus::INVALID) ||
            (m_CadesXlInfo.statusCertRefs == DigestVerifyStatus::FAILED)
        ) {
            const string s_warn = "THE CERTIFICATE REFERENCES DO NOT MATCH THE CERTIFICATES";
            if (std::find(m_ChainWarnings.begin(), m_ChainWarnings.end(), s_warn) == m_ChainWarnings.end()) {
                m_ChainWarnings.push_back(s_warn);
            }
        }
    }

    for (const auto& it : m_UnusedRevocationData) {
        if (it.first->getValidationType() != Cert::ValidationType::UNDEFINED) continue;
        if (std::find(m_ChainWarnings.begin(), m_ChainWarnings.end(), it.second) == m_ChainWarnings.end()) {
            m_ChainWarnings.push_back(it.second);
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
        //  The archive time-stamp is made later than the signature, by a TSA certificate of its own time
        uint64_t archive_time = 0;
        if ((it->getSubject() != m_ContentTS.cerSigner) && (it->getSubject() != m_SignatureTS.cerSigner)) {
            if (m_ArchiveTS.isPresent() && (m_ArchiveTS.msGenTime > 0) && (it->getSubject() == m_ArchiveTS.cerSigner)) {
                archive_time = m_ArchiveTS.msGenTime;
            }
            for (const auto& it_ts : m_ArchiveTSsNext) {
                if ((archive_time == 0) && (it_ts->msGenTime > 0) && (it->getSubject() == it_ts->cerSigner)) {
                    archive_time = it_ts->msGenTime;
                }
            }
        }
        uint64_t status_time = 0;
        if ((it->getCertEntity() == CertEntity::OCSP) || (it->getCertEntity() == CertEntity::CRL)) {
            status_time = getTimeOfStatusData(it->getCertEntity(), it->getSubject());
        }
        (void)it->checkValidityTime((status_time > 0) ? status_time : ((archive_time > 0) ? archive_time : validateTime));
    }
}

int VerifiedSignerInfo::verifyArchiveTimeStamp (
        const vector<Cert::CerItem*>& certs,
        const VectorBA& certsEncoded,
        const VectorBA& crls,
        const ContentHasher& contentHasher
)
{
    int ret = RET_OK;

    if (m_ArchiveTS.isPresent()) {
        DO(verifyOneArchiveTimeStamp(m_ArchiveTS, certs, certsEncoded, crls, contentHasher));
        for (auto& it : m_ArchiveTSsNext) {
            DO(verifyOneArchiveTimeStamp(*it, certs, certsEncoded, crls, contentHasher));
        }
    }

cleanup:
    return ret;
}

//  archive-time-stamp (TS 101 733, 6.4.1): the message imprint is a hash of the concatenation of encapContentInfo,
//  the external content if eContent is omitted, the certificates and crls elements of the SignedData, and all the
//  data elements of the SignerInfo with the unsigned attributes, except this and later archive time-stamps - as
//  they are stored, "including the Type and Length encoding" (NOTE 4). The unsigned attributes are taken both
//  ways the implementations made it: with the tag and length of unsignedAttrs, and without them
void VerifiedSignerInfo::verifyArchiveTimeStampV2Digest (
        AttrTimeStamp& archiveTS,
        const ContentHasher& contentHasher
)
{
    const HashAlg hash_alg = hash_from_oid(archiveTS.hashAlgo.c_str());
    const vector<vector<uint8_t>>& raw_attrs = m_SignerInfo.getRawUnsignedAttrs();
    const vector<uint8_t>& raw_eci = m_SignerInfo.getRawEncapContentInfo();
    const bool is_external = !m_SignerInfo.rawContentIsPresent();

    //  Not computable: the octets of the signature are not obtained, the hash is unknown, or the external
    //  content is given by its hash only
    archiveTS.statusDigest = DigestVerifyStatus::FAILED;
    if (
        (hash_alg == HASH_ALG_UNDEFINED) || raw_eci.empty() || m_SignerInfo.getRawFields().empty() ||
        (archiveTS.attrIndex >= raw_attrs.size()) ||
        (is_external && (m_IsDigest || !contentHasher.isPresent()))
    ) return;

    //  The unsigned attributes without this archive time-stamp and the later ones
    vector<bool> is_excluded(raw_attrs.size(), false);
    is_excluded[archiveTS.attrIndex] = true;
    const auto exclude_later = [&](const AttrTimeStamp& other) {
        if ((&other == &archiveTS) || (other.attrIndex >= raw_attrs.size())) return;
        if (
            (other.msGenTime > archiveTS.msGenTime) ||
            ((other.msGenTime == archiveTS.msGenTime) && (other.attrIndex > archiveTS.attrIndex))
        ) {
            is_excluded[other.attrIndex] = true;
        }
    };
    exclude_later(m_ArchiveTS);
    for (const auto& it : m_ArchiveTSsNext) {
        exclude_later(*it);
    }

    vector<uint8_t> attrs;
    for (size_t i = 0; i < raw_attrs.size(); i++) {
        if (!is_excluded[i]) {
            attrs.insert(attrs.end(), raw_attrs[i].begin(), raw_attrs[i].end());
        }
    }

    vector<uint8_t> head = m_SignerInfo.getRawCertsCrls();
    head.insert(head.end(), m_SignerInfo.getRawFields().begin(), m_SignerInfo.getRawFields().end());

    archiveTS.statusDigest = DigestVerifyStatus::INVALID;
    for (size_t variant = 0; variant < 2; variant++) {
        vector<uint8_t> suffix = head;
        const vector<uint8_t> tail = (variant == 0) ? Der::wrap(0xA1, attrs) : attrs;
        suffix.insert(suffix.end(), tail.begin(), tail.end());

        SmartBA sba_hash;
        int ret = RET_OK;
        if (is_external) {
            ret = contentHasher.digestWithAffixes(hash_alg, raw_eci, suffix, &sba_hash);
        }
        else {
            SmartBA sba_data;
            vector<uint8_t> data = raw_eci;
            data.insert(data.end(), suffix.begin(), suffix.end());
            ret = sba_data.set(ba_alloc_from_uint8(data.data(), data.size())) ? ::hash(hash_alg, sba_data.get(), &sba_hash) : RET_UAPKI_GENERAL_ERROR;
        }
        if (ret != RET_OK) {
            archiveTS.statusDigest = DigestVerifyStatus::FAILED;
            return;
        }
        if (ba_cmp(archiveTS.hashedMessage.get(), sba_hash.get()) == 0) {
            archiveTS.statusDigest = DigestVerifyStatus::VALID;
            return;
        }
    }
}

int VerifiedSignerInfo::verifyOneArchiveTimeStamp (
        AttrTimeStamp& archiveTS,
        const vector<Cert::CerItem*>& certs,
        const VectorBA& certsEncoded,
        const VectorBA& crls,
        const ContentHasher& contentHasher
)
{
    int ret = RET_OK;
    (void)certs;

    {
        //  genTime and messageImprint of the token count only if TSTInfo is the one the TSA signed
        if (archiveTS.verifyTstInfo() != RET_OK) {
            m_LastError = RET_UAPKI_INVALID_DIGEST;
            (void)verifyAttrTimestamp(archiveTS);
            return RET_OK;
        }

        if (archiveTS.isV2) {
            verifyArchiveTimeStampV2Digest(archiveTS, contentHasher);
            if (archiveTS.statusDigest == DigestVerifyStatus::INVALID) {
                m_LastError = RET_UAPKI_INVALID_DIGEST;
            }
            ret = verifyAttrTimestamp(archiveTS);
            if (ret != RET_OK) {
                m_LastError = ret;
                ret = (ret == RET_UAPKI_CERT_NOT_FOUND) ? RET_OK : ret;
            }
            return ret;
        }

        //  archive-time-stamp-v3 with its hash index (EN 319 122-1: ats-hash-index-v3; TS 101 733: ats-hash-index):
        //  first the index - every hash it has refers to a value of the signature, then the message imprint by
        //  this index (EN 319 122-1 5.5.2, 5.5.3; TS 101 733 6.4.2, 6.4.3)
        Pkcs7::AtsV3::IndexType index_type = Pkcs7::AtsV3::IndexType::EN_319_122;
        const ByteArray* ba_hashindex = archiveTS.getAtsHashIndex(index_type);
        if (ba_hashindex) {
            bool is_validindex = false;
            SmartBA sba_hash;
            const HashAlg hash_alg = hash_from_oid(archiveTS.hashAlgo.c_str());
            archiveTS.statusDigest = SignatureVerifyStatus::INVALID;
            //  The hash of the signed data by the hash algorithm of the time-stamp: the message-digest attribute
            //  if it is the digest algorithm of the signature
            if (
                (hash_alg != HASH_ALG_UNDEFINED) &&
                (archiveTS.hashAlgo == m_SignerInfo.getDigestAlgorithm().algorithm) &&
                (Pkcs7::AtsV3::checkHashIndex(index_type, ba_hashindex, certsEncoded, crls, m_SignerInfo.getAsn1Data(), is_validindex) == RET_OK) &&
                is_validindex &&
                (Pkcs7::AtsV3::calcMessageImprint(
                    hash_alg,
                    m_SignerInfo.getContentType(),
                    m_SignerInfo.getMessageDigest(),
                    m_SignerInfo.getAsn1Data(),
                    ba_hashindex,
                    &sba_hash,
                    &m_SignerInfo.getRawContentType(),
                    &m_SignerInfo.getRawFields()
                ) == RET_OK) &&
                (ba_cmp(archiveTS.hashedMessage.get(), sba_hash.get()) == 0)
            ) {
                archiveTS.statusDigest = SignatureVerifyStatus::VALID;
            }
            if (archiveTS.statusDigest == SignatureVerifyStatus::INVALID) {
                m_LastError = RET_UAPKI_INVALID_DIGEST;
            }
            ret = verifyAttrTimestamp(archiveTS);
            if (ret != RET_OK) {
                m_LastError = ret;
                ret = (ret == RET_UAPKI_CERT_NOT_FOUND) ? RET_OK : ret;
            }
            return ret;
        }

        //  No hash index in the token: the archive-time-stamp-v3 "shall include as an unsigned attribute a single
        //  ats-hash-index(-v3)" and is validated by it (EN 319 122-1 5.5.2, 5.5.3; TS 101 733 6.4.3) - without the
        //  index it cannot be validated and is not used
        archiveTS.noHashIndex = true;
        archiveTS.statusDigest = SignatureVerifyStatus::INVALID;

        ret = verifyAttrTimestamp(archiveTS);
        if (ret != RET_OK) {
            m_LastError = ret;
            ret = (ret == RET_UAPKI_CERT_NOT_FOUND) ? RET_OK : ret;
        }
    }

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
            m_SignerInfo.getSignature(),
            m_SignerInfo.getDigestAlgorithm().algorithm.c_str(),
            m_SignerInfo.getSignatureAlgorithm().baParameters
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

    //  Without it: the newest of the certificates in the signature, else the newest one (getCertBySID)
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
            //  A value that is not a time-stamp token: the attribute is not used, the signature is reported
            if (m_ContentTS.parse(it.baValues) != RET_OK) {
                m_ContentTS.parseFailed = true;
                m_ChainWarnings.push_back("THE CONTENT TIME-STAMP IS NOT VALID AND IS NOT USED");
            }
        }
        else if (it.type == string(OID_PKCS9_SIGNING_CERTIFICATE_V2)) {
            //  A value that is not decoded: the reference to the signing certificate is not checked
            if (AttributeHelper::decodeSigningCertificate(it.baValues, m_EssCerts) != RET_OK) {
                m_EssCerts.clear();
                m_StatusEssCert = DataVerifyStatus::FAILED;
                continue;
            }
            m_StatusEssCert = DataVerifyStatus::INDETERMINATE;
        }
        else if (
            (it.type == string(OID_PKCS9_SIGNING_CERTIFICATE)) &&
            (m_StatusEssCert == DataVerifyStatus::NOT_PRESENT)
        ) {
            //  ESSCertID (RFC 2634) is ESSCertIDv2 without hashAlgorithm, the hash is SHA-1
            DO(AttributeHelper::decodeSigningCertificate(it.baValues, m_EssCerts));
            for (auto& it_esscertid : m_EssCerts) {
                it_esscertid.hashAlgorithm.algorithm = string(OID_SHA1);
            }
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
    m_CadesXlInfo.statusRevocationRefs = DataVerifyStatus::NOT_PRESENT;
    size_t attr_index = (size_t)-1;
    for (const auto& it : unsignedAttrs) {
        attr_index++;
        if (it.type == string(OID_PKCS9_TIMESTAMP_TOKEN)) {
            if (m_SignatureTS.parse(it.baValues) != RET_OK) {
                m_SignatureTS.parseFailed = true;
                m_ChainWarnings.push_back("THE SIGNATURE TIME-STAMP IS NOT VALID AND IS NOT USED");
            }
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
        else if ((it.type == string(OID_ETSI_ARCHIVE_TIMESTAMP_V3)) || (it.type == string(OID_PKCS9_ARCHIVE_TIMESTAMP_V2))) {
            const bool is_v2 = (it.type == string(OID_PKCS9_ARCHIVE_TIMESTAMP_V2));
            const string s_warn = "AN ARCHIVE TIME-STAMP IS NOT VALID AND IS NOT USED";
            if (!m_ArchiveTS.isPresent() && !m_ArchiveTS.parseFailed) {
                if (m_ArchiveTS.parse(it.baValues) != RET_OK) {
                    m_ArchiveTS.parseFailed = true;
                    m_ChainWarnings.push_back(s_warn);
                }
                m_ArchiveTS.isV2 = is_v2;
                m_ArchiveTS.attrIndex = attr_index;
            }
            else {
                shared_ptr<AttrTimeStamp> archive_ts = make_shared<AttrTimeStamp>();
                if (archive_ts->parse(it.baValues) != RET_OK) {
                    if (std::find(m_ChainWarnings.begin(), m_ChainWarnings.end(), s_warn) == m_ChainWarnings.end()) {
                        m_ChainWarnings.push_back(s_warn);
                    }
                    continue;
                }
                archive_ts->isV2 = is_v2;
                archive_ts->attrIndex = attr_index;
                m_ArchiveTSsNext.push_back(archive_ts);
            }
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
            signer_info.getSignature(),
            signer_info.getDigestAlgorithm().algorithm.c_str(),
            signer_info.getSignatureAlgorithm().baParameters
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
        attrTS.statusSignature = SignatureVerifyStatus::INDETERMINATE;
        //  The message imprint does not match: the token is not used whatever its signature (ETSI EN 319 102-1,
        //  5.5.4 4) a)), so the certificate of its TSA is not looked for and its absence is no error
        if (attrTS.statusDigest == DigestVerifyStatus::INVALID) {
            ret = RET_OK;
            break;
        }
        m_LastError = RET_UAPKI_CERT_NOT_FOUND;
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


const char* ValidationPolicy::NAME_UKRAINE_DEFAULT = "UkraineDefault";
const char* ValidationPolicy::NAME_ETSI_STRICT = "EtsiStrict";
const char* ValidationPolicy::NAME_CUSTOM = "custom";

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
    else if (validationType == string("FULL-ETSI")) {
        rv_type = VerifyOptions::ValidationType::FULL_ETSI;
    }
    return rv_type;
}   //  validationTypeFromStr


}   //  end namespace Verify

}   //  end namespace Doc

}   //  end namespace UapkiNS
