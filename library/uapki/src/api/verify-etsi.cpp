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

#define FILE_MARKER "uapki/api/verify-etsi.cpp"

#include "api-json-internal.h"
#include "attribute-helper.h"
#include "doc-verify.h"
#include "extension-helper.h"
#include "extension-helper-json.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include "signature-format.h"
#include "signeddata-helper.h"
#include "store-json.h"
#include "time-util.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"
#include <algorithm>
#include <functional>
#include <cstring>
#include <set>


using namespace std;
using namespace UapkiNS;

extern "C" const char* error_code_to_str (int errorCode);


namespace {

//  The report of the validation type FULL-ETSI: the status indications of ETSI EN 319 102-1 (5.1.3, tables 5
//  and 6) in the structure of ETSI TS 119 102-2 (clause 4). The facts are the ones collected by the verification
//  (doc-verify); here they are evaluated into the indications of the standard

enum class Indication : uint32_t {
    PASSED          = 0,
    INDETERMINATE   = 1,
    FAILED          = 2
};

const char* SUB_FORMAT_FAILURE                      = "FORMAT_FAILURE";
const char* SUB_HASH_FAILURE                        = "HASH_FAILURE";
const char* SUB_SIG_CRYPTO_FAILURE                  = "SIG_CRYPTO_FAILURE";
const char* SUB_REVOKED                             = "REVOKED";
const char* SUB_EXPIRED                             = "EXPIRED";
const char* SUB_NOT_YET_VALID                       = "NOT_YET_VALID";
const char* SUB_CHAIN_CONSTRAINTS_FAILURE           = "CHAIN_CONSTRAINTS_FAILURE";
const char* SUB_CERTIFICATE_CHAIN_GENERAL_FAILURE   = "CERTIFICATE_CHAIN_GENERAL_FAILURE";
const char* SUB_NO_SIGNING_CERTIFICATE_FOUND        = "NO_SIGNING_CERTIFICATE_FOUND";
const char* SUB_NO_CERTIFICATE_CHAIN_FOUND          = "NO_CERTIFICATE_CHAIN_FOUND";
const char* SUB_NO_CERTIFICATE_CHAIN_FOUND_NO_POE   = "NO_CERTIFICATE_CHAIN_FOUND_NO_POE";
const char* SUB_REVOKED_NO_POE                      = "REVOKED_NO_POE";
const char* SUB_REVOKED_CA_NO_POE                   = "REVOKED_CA_NO_POE";
const char* SUB_OUT_OF_BOUNDS_NO_POE                = "OUT_OF_BOUNDS_NO_POE";
const char* SUB_TRY_LATER                           = "TRY_LATER";
const char* SUB_REVOCATION_OUT_OF_BOUNDS_NO_POE     = "REVOCATION_OUT_OF_BOUNDS_NO_POE";
const char* SUB_TIMESTAMP_ORDER_FAILURE             = "TIMESTAMP_ORDER_FAILURE";
const char* SUB_CRYPTO_CONSTRAINTS_FAILURE          = "CRYPTO_CONSTRAINTS_FAILURE";
const char* SUB_CRYPTO_CONSTRAINTS_FAILURE_NO_POE   = "CRYPTO_CONSTRAINTS_FAILURE_NO_POE";
const char* SUB_SIG_CONSTRAINTS_FAILURE             = "SIG_CONSTRAINTS_FAILURE";
const char* SUB_SIGNED_DATA_NOT_FOUND               = "SIGNED_DATA_NOT_FOUND";
const char* SUB_CUSTOM                              = "CUSTOM";

const char* CONSTRAINT_FORMAT                   = "formatChecking";
const char* CONSTRAINT_SIGNING_CERTIFICATE      = "identificationOfTheSigningCertificate";
const char* CONSTRAINT_X509                     = "x509CertificateValidation";
const char* CONSTRAINT_X509_VALIDATION_DATA     = "x509ValidationOfTimeStampsAndRevocationData";
const char* CONSTRAINT_CRYPTO                   = "cryptographicVerification";
const char* CONSTRAINT_VALIDATION_MATERIAL      = "validationMaterialReferences";
const char* CONSTRAINT_CRITICAL_EXTENSIONS      = "unknownCriticalExtensions";
const char* CONSTRAINT_REVOCATION_SIGNER_STATUS = "statusOfRevocationDataSigners";
const char* CONSTRAINT_REVOCATION_FRESHNESS     = "revocationFreshnessChecker";
const char* CONSTRAINT_TSA_KEY_PURPOSE          = "tsaExtendedKeyUsage";
const char* CONSTRAINT_SIGNER_KEY_USAGE         = "signerKeyUsage";
const char* CONSTRAINT_TSA_TRUST                = "tsaTrust";
const char* CONSTRAINT_EXPIRED_CERTS_ON_CRL     = "caRemovesExpiredCerts";
const char* CONSTRAINT_CRYPTO_CONSTRAINTS       = "cryptographicConstraints";
const char* CONSTRAINT_WITHDRAWN_ALGORITHMS     = "withdrawnAlgorithms";
const char* CONSTRAINT_PAST_VALIDATION          = "pastValidation";
const char* CONSTRAINT_TIMESTAMP_ORDER          = "timeStampOrderAndDelay";
const char* CONSTRAINT_SIGNATURE_POLICY         = "signaturePolicy";

const char* PROCESS_BASIC   = "Basic";
const char* PROCESS_LTVM    = "LTVM";
const char* PROCESS_LTA     = "LTA";

//  ETSI EN 319 412-5: id-etsi-qcs-QcCompliance, id-etsi-qcs-QcSSCD, id-etsi-qcs-QcType (with id-etsi-qct-eseal)
const char* OID_QCS_COMPLIANCE      = "0.4.0.1862.1.1";
const char* OID_QCS_QSCD            = "0.4.0.1862.1.4";
const char* OID_QCS_TYPE            = "0.4.0.1862.1.6";
const uint8_t DER_OID_QCT_ESEAL[9]  = { 0x06, 0x07, 0x04, 0x00, 0x8E, 0x46, 0x01, 0x06, 0x02 };
//  The certificate policy of the certificates issued in Ukraine as qualified ("посилений") before the statements
//  of ETSI EN 319 412-5 were used (certificatePolicies)
const char* OID_UA_CP_QUALIFIED     = "1.2.804.2.1.1.1.2.2";
//  The key purpose of the certificates of electronic seals issued in Ukraine (extendedKeyUsage)
const char* OID_UA_KP_DIGITAL_STAMP = "1.2.804.2.1.1.1.3.9";


const char* indication_to_str (
        const Indication indication,
        const bool ofSignature
)
{
    switch (indication) {
    case Indication::PASSED:    return ofSignature ? "TOTAL-PASSED" : "PASSED";
    case Indication::FAILED:    return ofSignature ? "TOTAL-FAILED" : "FAILED";
    default:                    return "INDETERMINATE";
    }
}


//  A reason of an indication that is not PASSED, with the data table 6 associates with the sub-indication
struct Finding {
    Indication  indication;
    string      subIndication;
    string      info;               //  what exactly (for CUSTOM - the diagnostic required by 5.1.3)
    const Cert::CerItem*
                cerItem;
    uint64_t    msRevocationTime;
    string      revocationReason;
    //  A cryptographic constraint: the algorithm (with the key size) and the date it was reliable until
    string      algorithm;
    string      reliableUntil;
    //  TRY_LATER: when the validation may give another result
    string      tryAfter;

    Finding (
        const Indication iIndication,
        const char* iSubIndication,
        const string& iInfo = string(),
        const Cert::CerItem* iCerItem = nullptr
    )
        : indication(iIndication)
        , subIndication(iSubIndication)
        , info(iInfo)
        , cerItem(iCerItem)
        , msRevocationTime(0)
    {}
};

struct ConstraintReport {
    string      id;
    bool        applied;
    string      parameter;          //  the value the validation policy gives to the constraint
    bool        warning;            //  the result of the constraint is reported and does not change the one of the signature
    vector<Finding>
                findings;

    explicit ConstraintReport (
        const char* iId,
        const bool iApplied = true,
        const string& iParameter = string()
    )
        : id(iId)
        , applied(iApplied)
        , parameter(iParameter)
        , warning(false)
    {}

    void add (const Finding& finding) {
        findings.push_back(finding);
    }
    Indication indication (void) const {
        Indication rv = Indication::PASSED;
        for (const auto& it : findings) {
            if ((uint32_t)it.indication > (uint32_t)rv) rv = it.indication;
        }
        return rv;
    }
};


string ba_to_base64_string (
        const ByteArray* baData
)
{
    string rv_s;
    char* s_base64 = nullptr;
    if (ba_to_base64_with_alloc(baData, &s_base64) == RET_OK) {
        rv_s = string(s_base64);
    }
    ::free(s_base64);
    return rv_s;
}

//  A service of a trusted list (ADD_TRUST_LIST) the certificate is the identity of, provided at the time:
//  typeMark - a part of the type of the service ("CA/", "TSA/", "OCSP"). nullptr if there is none.
//  For certificates (ETSI TS 119 615, PRO-4.4.4-10): a service without the additional information
//  "for electronic signatures" ("for electronic seals") does not qualify certificates of that kind
enum class ServiceFor { ANY, SIGNATURES, SEALS };

const Cert::TrustService* listed_service (
        const std::shared_ptr<const Cert::TrustServices>& services,
        const char* typeMark,
        const uint64_t msTime,
        const ServiceFor serviceFor = ServiceFor::ANY
)
{
    if (!services) return nullptr;
    for (const auto& it : *services) {
        if (it.type.find(typeMark) == string::npos) continue;
        if ((serviceFor == ServiceFor::SEALS) && !it.forESeals) continue;
        if ((serviceFor == ServiceFor::SIGNATURES) && !it.forESignatures) continue;
        const Cert::TrustService::Period* period = it.periodAt(msTime);
        if (period && Cert::TrustService::isActiveStatus(period->status)) return &it;
    }
    return nullptr;
}

//  The certificate has a service of the type in a trusted list, whatever its status
bool is_listed (
        const std::shared_ptr<const Cert::TrustServices>& services,
        const char* typeMark
)
{
    if (!services) return false;
    for (const auto& it : *services) {
        if (it.type.find(typeMark) != string::npos) return true;
    }
    return false;
}

bool timestamp_is_valid (
        const Doc::Verify::AttrTimeStamp& attrTS
)
{
    return attrTS.isPresent() &&
        (attrTS.statusSignature == SignatureVerifyStatus::VALID) && (attrTS.statusDigest == DigestVerifyStatus::VALID);
}

//  A time-stamp is validated as an object of its own (TS 119 102-2, 4.4.8): one that does not pass is not used
//  (EN 319 102-1, 5.5.4 4) a), 5.6.3 5) d)) and does not change the indication of the signature
void evaluate_timestamp (
        const Doc::Verify::AttrTimeStamp& attrTS,
        Indication& indication,
        string& subIndication,
        string& info
)
{
    indication = Indication::PASSED;
    subIndication.clear();
    info.clear();
    if (timestamp_is_valid(attrTS)) return;

    if (attrTS.parseFailed) {
        indication = Indication::FAILED;
        subIndication = SUB_FORMAT_FAILURE;
    }
    else if (attrTS.statusDigest == DigestVerifyStatus::INVALID) {
        indication = Indication::FAILED;
        subIndication = SUB_HASH_FAILURE;
    }
    else if (attrTS.statusSignature == SignatureVerifyStatus::INVALID) {
        indication = Indication::FAILED;
        subIndication = SUB_SIG_CRYPTO_FAILURE;
    }
    else {
        indication = Indication::INDETERMINATE;
        if (attrTS.noHashIndex) {
            subIndication = SUB_CUSTOM;
            info = "NO_HASH_INDEX";
        }
        else if (!attrTS.cerSigner) {
            subIndication = SUB_NO_SIGNING_CERTIFICATE_FOUND;
        }
        else if (attrTS.statusDigest != DigestVerifyStatus::VALID) {
            subIndication = SUB_SIGNED_DATA_NOT_FOUND;
        }
        else {
            subIndication = SUB_CUSTOM;
            info = "TIME_STAMP_NOT_VERIFIED";
        }
    }
}

//  The certificates from the signing certificate up to its root, in this order
vector<const CertValidator::CertChainItem*> signer_path (
        const Doc::Verify::VerifiedSignerInfo& verifyInfo
)
{
    vector<const CertValidator::CertChainItem*> rv_path;
    const CertValidator::CertChainItem* item = nullptr;
    for (const auto& it : verifyInfo.getCertChainItems()) {
        if (it->getCertEntity() == CertValidator::CertEntity::SIGNER) {
            item = it;
            break;
        }
    }
    while (item && (rv_path.size() < 64)) {
        rv_path.push_back(item);
        const Cert::CerItem* cer_issuer = item->getIssuer();
        if (!cer_issuer || (cer_issuer == item->getSubject())) break;
        const CertValidator::CertChainItem* next = nullptr;
        for (const auto& it : verifyInfo.getCertChainItems()) {
            if (it->getSubject() == cer_issuer) {
                next = it;
                break;
            }
        }
        item = next;
    }
    return rv_path;
}

//  The reason of a revocation as in TS 119 102-2, 4.3.12.6.2 (urn:etsi:019102:revocationReason:...)
const char* revocation_reason_to_str (
        const CrlReason reason
)
{
    switch (reason) {
    case CrlReason::KEY_COMPROMISE:         return "keyCompromise";
    case CrlReason::CA_COMPROMISE:          return "cACompromise";
    case CrlReason::AFFILIATION_CHANGED:    return "affiliationChanged";
    case CrlReason::SUPERSEDED:             return "superseded";
    case CrlReason::CESSATION_OF_OPERATION: return "cessationOfOperation";
    case CrlReason::CERTIFICATE_HOLD:       return "certificateHold";
    case CrlReason::REMOVE_FROM_CRL:        return "removeFromCRL";
    case CrlReason::PRIVILEGE_WITHDRAWN:    return "privilegeWithdrawn";
    case CrlReason::AA_COMPROMISE:          return "aACompromise";
    default:                                return "unspecified";
    }
}

//  The revoked certificate: FAILED/REVOKED only when a content time-stamp proves the signing after the revocation
//  (EN 319 102-1, 5.3.4); otherwise there is no proof that the signature existed before it (5.5.4 4) a))
Finding revoked_finding (
        const Doc::Verify::VerifiedSignerInfo& verifyInfo,
        const CertValidator::CertChainItem& chainItem,
        const uint64_t msRevocationTime,
        const CrlReason reason
)
{
    const bool is_signer = (chainItem.getCertEntity() == CertValidator::CertEntity::SIGNER);
    const Doc::Verify::AttrTimeStamp& content_ts = verifyInfo.getContentTS();
    const bool signed_after = is_signer && timestamp_is_valid(content_ts) &&
        (msRevocationTime > 0) && (content_ts.msGenTime > msRevocationTime);

    Finding rv_finding(
        signed_after ? Indication::FAILED : Indication::INDETERMINATE,
        signed_after ? SUB_REVOKED : (is_signer ? SUB_REVOKED_NO_POE : SUB_REVOKED_CA_NO_POE),
        string(),
        chainItem.getSubject()
    );
    rv_finding.msRevocationTime = msRevocationTime;
    if (reason != CrlReason::UNDEFINED) {
        rv_finding.revocationReason = revocation_reason_to_str(reason);
    }
    return rv_finding;
}

void evaluate_revocation (
        const Doc::Verify::VerifiedSignerInfo& verifyInfo,
        const CertValidator::CertChainItem& chainItem,
        ConstraintReport& report
)
{
    const Cert::CerItem* cer_subject = chainItem.getSubject();
    switch (chainItem.getValidationType()) {
    case Cert::ValidationType::UNDEFINED:
        report.add(Finding(Indication::INDETERMINATE, SUB_TRY_LATER, "REVOCATION_STATUS_NOT_DETERMINED", cer_subject));
        break;
    case Cert::ValidationType::CRL: {
        const CertValidator::ResultValidationByCrl& by_crl = chainItem.getResultValidationByCrl();
        if (by_crl.certStatus == UapkiNS::CertStatus::REVOKED) {
            report.add(revoked_finding(verifyInfo, chainItem, by_crl.revokedCertItem.getDate(), by_crl.revokedCertItem.crlReason));
        }
        else if (by_crl.certStatus != UapkiNS::CertStatus::GOOD) {
            report.add(Finding(Indication::INDETERMINATE, SUB_TRY_LATER, "REVOCATION_STATUS_NOT_DETERMINED", cer_subject));
        }
        break;
    }
    case Cert::ValidationType::OCSP: {
        const CertValidator::ResultValidationByOcsp& by_ocsp = chainItem.getResultValidationByOcsp();
        const Ocsp::OcspHelper::SingleResponseInfo& single_resp = by_ocsp.singleResponseInfo;
        if (by_ocsp.statusSignature != SignatureVerifyStatus::VALID) {
            report.add(Finding(Indication::INDETERMINATE, SUB_TRY_LATER, "OCSP_RESPONSE_NOT_VALID", cer_subject));
        }
        else if (single_resp.certStatus == UapkiNS::CertStatus::REVOKED) {
            //  Revoked after the best signature time: valid when signed
            const uint64_t best_time = verifyInfo.getBestSignatureTime();
            if (!((best_time > 0) && (single_resp.msRevocationTime > best_time))) {
                report.add(revoked_finding(verifyInfo, chainItem, single_resp.msRevocationTime, single_resp.revocationReason));
            }
        }
        else if (single_resp.certStatus != UapkiNS::CertStatus::GOOD) {
            report.add(Finding(Indication::INDETERMINATE, SUB_TRY_LATER, "CERTIFICATE_UNKNOWN_TO_OCSP_RESPONDER", cer_subject));
        }
        break;
    }
    default:
        break;
    }
}

//  X.509 certificate validation (EN 319 102-1, 5.2.6) of one certificate of a chain, by the facts of doc-verify
//  A chain without a trusted anchor that has a certificate of a trusted list whose service was not provided at the
//  time the chain is built for: the trust anchor is not trusted at that time (ETSI EN 319 102-1, 5.2.6.4, the
//  trust anchor sunset date)
void add_untrusted_anchors (
        const Doc::Verify::VerifiedSignerInfo& verifyInfo,
        ConstraintReport& report
)
{
    for (const auto& it : verifyInfo.getCertChainItems()) {
        const Cert::CerItem* cer_subject = it->getSubject();
        if (!it->isTrusted() && cer_subject->wasTrusted() && cer_subject->getCertExtKeyUsage().isCa()) {
            report.add(Finding(Indication::INDETERMINATE, SUB_NO_CERTIFICATE_CHAIN_FOUND_NO_POE, "TRUST_ANCHOR_NOT_TRUSTED_AT_THE_TIME", cer_subject));
        }
    }
}

void evaluate_chain_item (
        const Doc::Verify::VerifiedSignerInfo& verifyInfo,
        const CertValidator::CertChainItem& chainItem,
        const bool checkCriticalExtensions,
        ConstraintReport& report,
        bool& signerStatusNotDetermined
)
{
    const Cert::CerItem* cer_subject = chainItem.getSubject();
    const CertValidator::CertEntity entity = chainItem.getCertEntity();
    const bool is_signer = (entity == CertValidator::CertEntity::SIGNER);

    switch (chainItem.getVerifyStatus()) {
    case Cert::VerifyStatus::VALID: {
        if (
            ((entity == CertValidator::CertEntity::OCSP) || (entity == CertValidator::CertEntity::CRL)) &&
            (chainItem.getValidationType() == Cert::ValidationType::UNDEFINED)
        ) {
            //  A responder (a CRL signer) that is a service of a trusted list provided when it issued the data:
            //  its status is the one the list gives, it is not looked for in revocation data
            const uint64_t status_time = verifyInfo.getTimeOfStatusData(entity, cer_subject);
            const std::shared_ptr<const Cert::TrustServices> services = cer_subject->getTrustServices();
            const char* type_mark = (entity == CertValidator::CertEntity::OCSP) ? "OCSP" : "CRL";
            if (!listed_service(services, type_mark, (status_time > 0) ? status_time : verifyInfo.getBestSignatureTime())) {
                signerStatusNotDetermined = true;
            }
        }
        else if (!chainItem.isExpired()) {
            evaluate_revocation(verifyInfo, chainItem, report);
        }
        //  RFC 3161, 4: the time-stamps of a TSA whose key is compromised, or whose certificate is revoked with no
        //  reason given, are not trusted whenever they were made
        if (entity == CertValidator::CertEntity::TSP) {
            const CertValidator::TsaKeyTrust key_trust = CertValidator::tsaKeyTrust(chainItem);
            if (key_trust != CertValidator::TsaKeyTrust::OK) {
                report.add(Finding(
                    Indication::INDETERMINATE, SUB_REVOKED_NO_POE,
                    (key_trust == CertValidator::TsaKeyTrust::COMPROMISED) ? "TSA_KEY_COMPROMISED" : "TSA_REVOCATION_REASON_NOT_GIVEN",
                    cer_subject
                ));
            }
        }
        if ((entity == CertValidator::CertEntity::ROOT) && !chainItem.isTrusted()) {
            report.add(Finding(Indication::INDETERMINATE, SUB_NO_CERTIFICATE_CHAIN_FOUND, "ROOT_NOT_TRUSTED", cer_subject));
            add_untrusted_anchors(verifyInfo, report);
        }
        const CertValidator::ChainConstraint constraint = CertValidator::checkChainConstraints(
            chainItem, verifyInfo.getCertChainItems(), checkCriticalExtensions
        );
        if (constraint != CertValidator::ChainConstraint::NONE) {
            report.add(Finding(
                Indication::INDETERMINATE, SUB_CHAIN_CONSTRAINTS_FAILURE, CertValidator::chainConstraintToStr(constraint), cer_subject
            ));
        }
        break;
    }
    case Cert::VerifyStatus::UNDEFINED:
        report.add(Finding(Indication::INDETERMINATE, SUB_NO_CERTIFICATE_CHAIN_FOUND, "ISSUER_NOT_FOUND", cer_subject));
        add_untrusted_anchors(verifyInfo, report);
        break;
    case Cert::VerifyStatus::INDETERMINATE:
    case Cert::VerifyStatus::VALID_WITHOUT_KEYUSAGE:
        report.add(Finding(Indication::INDETERMINATE, SUB_CERTIFICATE_CHAIN_GENERAL_FAILURE, "CERTIFICATE_SIGNATURE_NOT_VERIFIED", cer_subject));
        break;
    default:
        report.add(Finding(Indication::INDETERMINATE, SUB_CERTIFICATE_CHAIN_GENERAL_FAILURE, "CERTIFICATE_SIGNATURE_INVALID", cer_subject));
        break;
    }

    if (chainItem.isExpired()) {
        //  Outside the validity period at the best signature time (EN 319 102-1, 5.3.4, 5.5.4 4))
        const uint64_t best_time = verifyInfo.getBestSignatureTime();
        const Doc::Verify::AttrTimeStamp& content_ts = verifyInfo.getContentTS();
        if (is_signer && (best_time > 0) && (cer_subject->getNotBefore() > best_time)) {
            report.add(Finding(Indication::FAILED, SUB_NOT_YET_VALID, string(), cer_subject));
        }
        else if (is_signer && timestamp_is_valid(content_ts) && (content_ts.msGenTime > cer_subject->getNotAfter())) {
            report.add(Finding(Indication::FAILED, SUB_EXPIRED, string(), cer_subject));
        }
        else {
            report.add(Finding(Indication::INDETERMINATE, SUB_OUT_OF_BOUNDS_NO_POE, string(), cer_subject));
        }
    }
}

//  Statements of the signing certificate (ETSI EN 319 412-5): the statements are claims of its issuer
int get_qc_statements (
        const Cert::CerItem* cerItem,
        vector<string>& statementIds,
        bool& isSeal,
        bool& isOldQualified
)
{
    int ret = RET_OK;
    const Certificate_t* cert = cerItem ? cerItem->getCert() : nullptr;
    isSeal = false;
    isOldQualified = false;
    if (!cert || !cert->tbsCertificate.extensions) return RET_OK;

    const Extensions_t* extns = cert->tbsCertificate.extensions;
    {
        vector<string> key_purposeids;
        if (ExtensionHelper::getExtendedKeyUsage(extns, key_purposeids) == RET_OK) {
            for (const auto& it : key_purposeids) {
                isSeal |= oid_is_equal(it.c_str(), OID_UA_KP_DIGITAL_STAMP);
            }
        }
    }
    for (int i = 0; i < extns->list.count; i++) {
        const Extension_t* extn = extns->list.array[i];
        string s_extnid;
        DO(Util::oidFromAsn1(&extn->extnID, s_extnid));
        const bool is_policies = oid_is_equal(s_extnid.c_str(), OID_X509v3_CertificatePolicies);
        if (!is_policies && !oid_is_equal(s_extnid.c_str(), OID_PKIX_QcStatements)) continue;

        SmartBA sba_value;
        ParsonHelper json;
        DO(asn_OCTSTRING2ba(&extn->extnValue, &sba_value));
        if (!json.create()) {
            SET_ERROR(RET_UAPKI_GENERAL_ERROR);
        }
        if (is_policies) {
            if (ExtensionHelper::DecodeToJsonObject::certificatePolicies(sba_value.get(), json.rootObject()) == RET_OK) {
                const JSON_Array* ja_policies = json_object_get_array(json.rootObject(), "certificatePolicies");
                for (size_t j = 0; j < json_array_get_count(ja_policies); j++) {
                    const char* s_id = json_object_get_string(json_array_get_object(ja_policies, j), "policyIdentifier");
                    isOldQualified |= (s_id && oid_is_equal(s_id, OID_UA_CP_QUALIFIED));
                }
            }
            continue;
        }
        //  The statements that are not decoded are not claimed
        if (ExtensionHelper::DecodeToJsonObject::qcStatements(sba_value.get(), json.rootObject()) == RET_OK) {
            const JSON_Array* ja_statements = json_object_get_array(json.rootObject(), "qcStatements");
            for (size_t j = 0; j < json_array_get_count(ja_statements); j++) {
                const JSON_Object* jo_statement = json_array_get_object(ja_statements, j);
                const char* s_id = json_object_get_string(jo_statement, "statementId");
                if (!s_id) continue;
                statementIds.push_back(s_id);

                //  QcType ::= SEQUENCE SIZE (1) OF OBJECT IDENTIFIER: a certificate for electronic seals
                const char* s_info = json_object_get_string(jo_statement, "statementInfo");
                if (oid_is_equal(s_id, OID_QCS_TYPE) && s_info) {
                    SmartBA sba_info;
                    (void)sba_info.set(ba_alloc_from_base64(s_info));
                    const uint8_t* buf = ba_get_buf_const(sba_info.get());
                    const size_t len = ba_get_len(sba_info.get());
                    for (size_t pos = 0; buf && (pos + sizeof(DER_OID_QCT_ESEAL) <= len); pos++) {
                        if (memcmp(buf + pos, DER_OID_QCT_ESEAL, sizeof(DER_OID_QCT_ESEAL)) == 0) {
                            isSeal = true;
                            break;
                        }
                    }
                }
            }
        }
    }

cleanup:
    return ret;
}

//  The names of ETSI TS 119 102-2 (XML Schema TS119102-2-v141.xsd) are used, with the first letter in lower case

int digest_alg_and_value_to_json (
        JSON_Object* joOwner,
        const string& digestAlgo,
        const ByteArray* baDigest
)
{
    int ret = RET_OK;
    DO_JSON(json_object_set_value(joOwner, "digestAlgAndValue", json_value_init_object()));
    {
        JSON_Object* jo_digest = json_object_get_object(joOwner, "digestAlgAndValue");
        DO_JSON(json_object_set_string(jo_digest, "digestMethod", digestAlgo.c_str()));
        if (baDigest) {
            DO(json_object_set_base64(jo_digest, "digestValue", baDigest));
        }
    }

cleanup:
    return ret;
}

//  ValidationStatusType: mainIndication, subIndications, associatedValidationReportData
int validation_status_to_json (
        JSON_Object* joStatus,
        const Indication indication,
        const bool ofSignature,
        const vector<Finding>& findings,
        const vector<const CertValidator::CertChainItem*>* certificateChain = nullptr
)
{
    int ret = RET_OK;
    JSON_Array* ja_data = nullptr;

    DO_JSON(json_object_set_string(joStatus, "mainIndication", indication_to_str(indication, ofSignature)));

    if (!findings.empty()) {
        //  subIndications - every distinct one: of the strongest indication first, then in the order the validation
        //  process meets them (EN 319 102-1, 5.3.4: a chain is built before the validity and the revocation are
        //  checked)
        static const char* const ORDER[] = {
            SUB_FORMAT_FAILURE, SUB_NO_SIGNING_CERTIFICATE_FOUND, SUB_NO_CERTIFICATE_CHAIN_FOUND,
            SUB_NO_CERTIFICATE_CHAIN_FOUND_NO_POE, SUB_CERTIFICATE_CHAIN_GENERAL_FAILURE, SUB_CHAIN_CONSTRAINTS_FAILURE, SUB_REVOKED, SUB_REVOKED_NO_POE,
            SUB_REVOKED_CA_NO_POE, SUB_NOT_YET_VALID, SUB_EXPIRED, SUB_OUT_OF_BOUNDS_NO_POE, SUB_REVOCATION_OUT_OF_BOUNDS_NO_POE, SUB_TRY_LATER,
            SUB_TIMESTAMP_ORDER_FAILURE, SUB_SIG_CONSTRAINTS_FAILURE, SUB_CRYPTO_CONSTRAINTS_FAILURE,
            SUB_CRYPTO_CONSTRAINTS_FAILURE_NO_POE, SUB_HASH_FAILURE, SUB_SIGNED_DATA_NOT_FOUND, SUB_SIG_CRYPTO_FAILURE, SUB_CUSTOM
        };
        vector<string> subs;
        for (int pass = 0; pass < 2; pass++) {
            for (const auto& it_order : ORDER) {
                for (const auto& it : findings) {
                    if ((it.indication == Indication::FAILED) != (pass == 0)) continue;
                    if (it.subIndication != it_order) continue;
                    if (std::find(subs.begin(), subs.end(), it.subIndication) == subs.end()) subs.push_back(it.subIndication);
                }
            }
        }
        DO_JSON(json_object_set_value(joStatus, "subIndications", json_value_init_array()));
        JSON_Array* ja_subs = json_object_get_array(joStatus, "subIndications");
        for (const auto& it : subs) {
            DO_JSON(json_array_append_string(ja_subs, it.c_str()));
        }
    }

    if (findings.empty() && (!certificateChain || certificateChain->empty())) return RET_OK;
    DO_JSON(json_object_set_value(joStatus, "associatedValidationReportData", json_value_init_array()));
    ja_data = json_object_get_array(joStatus, "associatedValidationReportData");

    //  certificateChain (4.3.12.4): the signing certificate first, the trust anchor last
    if (certificateChain && !certificateChain->empty()) {
        DO_JSON(json_array_append_value(ja_data, json_value_init_object()));
        JSON_Object* jo_data = json_array_get_object(ja_data, json_array_get_count(ja_data) - 1);
        const CertValidator::CertChainItem* last = certificateChain->back();
        const bool has_anchor = (last->getCertEntity() == CertValidator::CertEntity::ROOT) && last->isTrusted();
        if (has_anchor) {
            DO(json_object_set_base64(jo_data, "trustAnchor", last->getSubjectCertId()));
        }
        DO_JSON(json_object_set_value(jo_data, "certificateChain", json_value_init_object()));
        JSON_Object* jo_chain = json_object_get_object(jo_data, "certificateChain");
        DO(json_object_set_base64(jo_chain, "signingCertificate", certificateChain->front()->getSubjectCertId()));
        DO_JSON(json_object_set_value(jo_chain, "intermediateCertificates", json_value_init_array()));
        JSON_Array* ja_intermediate = json_object_get_array(jo_chain, "intermediateCertificates");
        for (size_t i = 1; i < certificateChain->size(); i++) {
            if (has_anchor && (i + 1 == certificateChain->size())) break;
            DO(json_array_append_base64(ja_intermediate, (*certificateChain)[i]->getSubjectCertId()));
        }
        if (has_anchor && (certificateChain->size() > 1)) {
            DO(json_object_set_base64(jo_chain, "trustAnchor", last->getSubjectCertId()));
        }
    }

    //  One element per reason: the object it is about, the data of the sub-indication (table 6)
    for (const auto& it : findings) {
        DO_JSON(json_array_append_value(ja_data, json_value_init_object()));
        JSON_Object* jo_data = json_array_get_object(ja_data, json_array_get_count(ja_data) - 1);
        if (it.cerItem) {
            DO(json_object_set_base64(jo_data, "relatedValidationObject", it.cerItem->getCertId()));
        }
        if (it.cerItem && (it.msRevocationTime > 0)) {
            DO_JSON(json_object_set_value(jo_data, "revocationStatusInformation", json_value_init_object()));
            JSON_Object* jo_revocation = json_object_get_object(jo_data, "revocationStatusInformation");
            DO(json_object_set_base64(jo_revocation, "validationObjectId", it.cerItem->getCertId()));
            DO_JSON(json_object_set_string(jo_revocation, "revocationTime", TimeUtil::mtimeToFtime(it.msRevocationTime).c_str()));
            if (!it.revocationReason.empty()) {
                DO_JSON(json_object_set_string(jo_revocation, "revocationReason", it.revocationReason.c_str()));
            }
        }
        DO_JSON(json_object_set_value(jo_data, "additionalValidationReportData", json_value_init_object()));
        JSON_Object* jo_additional = json_object_get_object(jo_data, "additionalValidationReportData");
        DO_JSON(json_object_set_value(jo_additional, "reportData", json_value_init_array()));
        JSON_Array* ja_reportdata = json_object_get_array(jo_additional, "reportData");
        const auto add_typed = [&](const char* type, const string& value) -> int {
            if (json_array_append_value(ja_reportdata, json_value_init_object()) != JSONSuccess) return RET_UAPKI_JSON_FAILURE;
            JSON_Object* jo_typed = json_array_get_object(ja_reportdata, json_array_get_count(ja_reportdata) - 1);
            if (json_object_set_string(jo_typed, "type", type) != JSONSuccess) return RET_UAPKI_JSON_FAILURE;
            return (json_object_set_string(jo_typed, "value", value.c_str()) == JSONSuccess) ? RET_OK : RET_UAPKI_JSON_FAILURE;
        };
        DO(add_typed("mainIndication", indication_to_str(it.indication, false)));
        DO(add_typed("subIndication", it.subIndication));
        if (!it.info.empty()) {
            DO(add_typed("info", it.info));
        }
        if (!it.algorithm.empty()) {
            DO(add_typed("algorithm", it.algorithm));
            DO(add_typed("reliableUntil", it.reliableUntil));
        }
        if (!it.tryAfter.empty()) {
            DO(add_typed("tryAfter", it.tryAfter));
        }
    }

cleanup:
    return ret;
}

//  The hash algorithm by the name of the cryptographic constraints, empty if there is none
string crypto_hash_name (const string& oid)
{
    switch (hash_from_oid(oid.c_str())) {
    case HASH_ALG_SHA1:         return "SHA1";
    case HASH_ALG_SHA224:       return "SHA224";
    case HASH_ALG_SHA256:       return "SHA256";
    case HASH_ALG_SHA384:       return "SHA384";
    case HASH_ALG_SHA512:       return "SHA512";
    case HASH_ALG_SHA3_224:     return "SHA3-224";
    case HASH_ALG_SHA3_256:     return "SHA3-256";
    case HASH_ALG_SHA3_384:     return "SHA3-384";
    case HASH_ALG_SHA3_512:     return "SHA3-512";
    case HASH_ALG_RIPEMD128:    return "RIPEMD128";
    case HASH_ALG_RIPEMD160:    return "RIPEMD160";
    case HASH_ALG_WHIRLPOOL:    return "WHIRLPOOL";
    case HASH_ALG_GOST34311:    return "GOST34311";
    case HASH_ALG_DSTU7564_256: return "DSTU7564-256";
    case HASH_ALG_DSTU7564_384: return "DSTU7564-384";
    case HASH_ALG_DSTU7564_512: return "DSTU7564-512";
    default:                    return string();
    }
}

//  The key of a certificate: the family of the cryptographic constraints ("RSA", "EC"; empty - no constraints of
//  the library, as DSTU 4145) and its size in bits (0 - not known: a curve that is not a named one of the table)
void crypto_key_info (const Cert::CerItem* cerItem, string& family, uint32_t& bits)
{
    family.clear();
    bits = 0;
    const SubjectPublicKeyInfo_t& spki = cerItem->getCert()->tbsCertificate.subjectPublicKeyInfo;
    const string& key_algo = cerItem->getKeyAlgo();
    if (key_algo.compare(0, 19, "1.2.840.113549.1.1.") == 0) {
        //  RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }: the size of the modulus
        family = "RSA";
        const uint8_t* buf = spki.subjectPublicKey.buf;
        const size_t len = (size_t)spki.subjectPublicKey.size;
        size_t pos = 0;
        const auto read_len = [&](size_t& value) -> bool {
            if (pos >= len) return false;
            if (buf[pos] < 0x80) { value = buf[pos++]; return true; }
            const size_t cnt = buf[pos++] & 0x7F;
            if ((cnt == 0) || (cnt > 4) || (pos + cnt > len)) return false;
            value = 0;
            for (size_t i = 0; i < cnt; i++) value = (value << 8) | buf[pos++];
            return true;
        };
        size_t len_seq = 0, len_int = 0;
        if (!buf || (len < 4) || (buf[pos++] != 0x30) || !read_len(len_seq)) return;
        if ((pos >= len) || (buf[pos++] != 0x02) || !read_len(len_int) || (pos + len_int > len)) return;
        while ((len_int > 0) && (buf[pos] == 0)) { pos++; len_int--; }
        if (len_int == 0) return;
        bits = (uint32_t)(len_int * 8);
        for (uint8_t mask = 0x80; mask && !(buf[pos] & mask); mask >>= 1) bits--;
    }
    else if (key_algo == "1.2.840.10045.2.1") {
        //  The named curves
        family = "EC";
        static const struct { const char* oid; uint32_t bits; } CURVES[] = {
            { "1.3.132.0.8", 160 }, { "1.3.132.0.9", 160 }, { "1.3.132.0.30", 160 }, { "1.3.132.0.1", 163 },
            { "1.3.132.0.2", 163 }, { "1.3.132.0.15", 163 }, { "1.2.840.10045.3.1.1", 192 }, { "1.3.132.0.31", 192 },
            { "1.3.132.0.24", 193 }, { "1.3.132.0.25", 193 }, { "1.3.132.0.32", 224 }, { "1.3.132.0.33", 224 },
            { "1.3.132.0.26", 233 }, { "1.3.132.0.27", 233 }, { "1.3.132.0.3", 239 },
            { "1.3.36.3.3.2.8.1.1.1", 160 }, { "1.3.36.3.3.2.8.1.1.3", 192 }, { "1.3.36.3.3.2.8.1.1.5", 224 },
            { "1.2.840.10045.3.1.7", 256 }, { "1.3.132.0.10", 256 }, { "1.3.132.0.34", 384 }, { "1.3.132.0.35", 521 },
            { "1.3.36.3.3.2.8.1.1.7", 256 }, { "1.3.36.3.3.2.8.1.1.11", 384 }, { "1.3.36.3.3.2.8.1.1.13", 512 }
        };
        if (!spki.algorithm.parameters || (spki.algorithm.parameters->size < 3) || (spki.algorithm.parameters->buf[0] != 0x06)) return;
        const uint8_t* buf = spki.algorithm.parameters->buf;
        const size_t len = (size_t)buf[1];
        if ((len >= 0x80) || ((size_t)spki.algorithm.parameters->size < len + 2)) return;
        string s_oid = to_string(buf[2] / 40) + "." + to_string(buf[2] % 40);
        uint64_t arc = 0;
        for (size_t i = 3; i < len + 2; i++) {
            arc = (arc << 7) | (buf[i] & 0x7F);
            if (!(buf[i] & 0x80)) { s_oid += "." + to_string(arc); arc = 0; }
        }
        for (const auto& it : CURVES) {
            if (s_oid == it.oid) bits = it.bits;
        }
    }
}

//  The cryptographic constraints (ETSI EN 319 102-1, 5.2.8.4.1; 5.5.4, steps 8 and 10): an algorithm or a key size
//  must be reliable at the time the object is known to have existed - the best signature time for the signature
//  and the certificates of the path of the signer, the time of a later valid time-stamp for a time-stamp and the
//  certificate of its TSA (of the first archive time-stamp for the signers of revocation data), else the validation
//  time. An algorithm withdrawn by a regulator: only a certificate issued after the date does not meet the
//  constraint; a signature or a time-stamp made after it is reported in reportWithdrawn (a warning)
void evaluate_crypto_constraints (
        Doc::Verify::VerifiedSignerInfo& verifyInfo,
        const Doc::Verify::ValidationPolicy& policy,
        const vector<const CertValidator::CertChainItem*>& path,
        ConstraintReport& report,
        ConstraintReport& reportWithdrawn
)
{
    using Doc::Verify::AttrTimeStamp;
    using Doc::Verify::CryptoRule;
    const uint64_t ms_now = TimeUtil::mtimeNow();
    const uint64_t ms_signature = (verifyInfo.getBestSignatureTime() > 0) ? verifyInfo.getBestSignatureTime() : ms_now;
    const auto stamp_valid = [](const AttrTimeStamp& ts) -> bool {
        return ts.isPresent() && (ts.msGenTime > 0)
            && (ts.statusDigest == DigestVerifyStatus::VALID) && (ts.statusSignature == SignatureVerifyStatus::VALID);
    };
    const auto find_rule = [&policy](const string& algorithm, const uint32_t bits, const bool isKey) -> const CryptoRule* {
        const CryptoRule* rv = nullptr;
        for (const auto& it : policy.cryptoRules) {
            if ((it.algorithm != algorithm) || ((it.keySizeBelow > 0) != isKey)) continue;
            if (isKey && ((bits == 0) || (bits >= it.keySizeBelow))) continue;
            if (!rv || (it.keySizeBelow < rv->keySizeBelow)) rv = &it;
        }
        return (rv && (rv->msEnd > 0)) ? rv : nullptr;
    };
    const auto date_of = [](const uint64_t ms) -> string {
        return TimeUtil::mtimeToFtime(ms).substr(0, 10);
    };
    const auto add_finding = [&](ConstraintReport& to, const Indication indication, const char* sub, const char* info,
            const string& algorithm, const CryptoRule& rule, const Cert::CerItem* cerItem) {
        Finding finding(indication, sub, info, cerItem);
        finding.algorithm = algorithm;
        finding.reliableUntil = date_of(rule.msEnd);
        for (const auto& it : to.findings) {
            if ((it.info == finding.info) && (it.algorithm == finding.algorithm) && (it.cerItem == cerItem)) return;
        }
        to.add(finding);
    };
    //  An object made by its author at a time: a signature, a time-stamp. msMade - when (a withdrawn algorithm),
    //  msKnown - the time it is known to have existed at (the other ones); msAfter - a proof it was made later
    const auto check_made = [&](const string& algorithm, const uint32_t bits, const bool isKey, const uint64_t msMade,
            const uint64_t msKnown, const uint64_t msAfter, const char* info, const Cert::CerItem* cerItem) {
        const CryptoRule* rule = find_rule(algorithm, bits, isKey);
        if (!rule) return;
        const string s_algo = isKey ? (algorithm + "-" + to_string(bits)) : algorithm;
        if (rule->withdrawn) {
            if (msMade >= rule->msEnd) {
                add_finding(reportWithdrawn, Indication::INDETERMINATE, SUB_CRYPTO_CONSTRAINTS_FAILURE_NO_POE, "ALGORITHM_WITHDRAWN", s_algo, *rule, cerItem);
            }
        }
        else if ((msAfter > 0) && (msAfter >= rule->msEnd)) {
            add_finding(report, Indication::FAILED, SUB_CRYPTO_CONSTRAINTS_FAILURE, info, s_algo, *rule, cerItem);
        }
        else if (msKnown >= rule->msEnd) {
            add_finding(report, Indication::INDETERMINATE, SUB_CRYPTO_CONSTRAINTS_FAILURE_NO_POE, info, s_algo, *rule, cerItem);
        }
    };
    const auto check_signer_info = [&](const Pkcs7::SignedDataParser::SignerInfo& signerInfo, const uint64_t msMade,
            const uint64_t msKnown, const uint64_t msAfter, const char* info) {
        const string s_digest = crypto_hash_name(signerInfo.getDigestAlgorithm().algorithm);
        const string s_signhash = crypto_hash_name(signerInfo.getSignatureAlgorithm().algorithm);
        if (!s_digest.empty()) check_made(s_digest, 0, false, msMade, msKnown, msAfter, info, nullptr);
        if (!s_signhash.empty() && (s_signhash != s_digest)) check_made(s_signhash, 0, false, msMade, msKnown, msAfter, info, nullptr);
    };

    //  The time-stamps in the order they cover one another; a time-stamp is known to have existed at the time of
    //  the next valid one
    vector<const AttrTimeStamp*> stamps;
    for (const AttrTimeStamp* it : { &verifyInfo.getContentTS(), &verifyInfo.getSignatureTS(), &verifyInfo.getArchiveTS() }) {
        if (stamp_valid(*it)) stamps.push_back(it);
    }
    for (const auto& it : verifyInfo.getArchiveTSsNext()) {
        if (it && stamp_valid(*it)) stamps.push_back(it.get());
    }
    const auto known_at = [&](const size_t idx) -> uint64_t {
        //  the content time-stamp is covered by the signature
        if ((idx == 0) && (stamps[0] == &verifyInfo.getContentTS())) return ms_signature;
        return (idx + 1 < stamps.size()) ? stamps[idx + 1]->msGenTime : ms_now;
    };
    const uint64_t ms_archived = stamp_valid(verifyInfo.getArchiveTS()) ? verifyInfo.getArchiveTS().msGenTime : ms_now;

    //  The signature: a valid content time-stamp proves it was made later
    {
        const AttrTimeStamp& content_ts = verifyInfo.getContentTS();
        check_signer_info(verifyInfo.getSignerInfo(), ms_signature, ms_signature, stamp_valid(content_ts) ? content_ts.msGenTime : 0, "SIGNATURE_ALGORITHM_NOT_RELIABLE");
    }
    for (size_t i = 0; i < stamps.size(); i++) {
        const AttrTimeStamp& ts = *stamps[i];
        const string s_imprint = crypto_hash_name(ts.hashAlgo);
        if (!s_imprint.empty()) check_made(s_imprint, 0, false, ts.msGenTime, known_at(i), 0, "TIME_STAMP_ALGORITHM_NOT_RELIABLE", ts.cerSigner);
        check_signer_info(ts.signerInfo, ts.msGenTime, known_at(i), 0, "TIME_STAMP_ALGORITHM_NOT_RELIABLE");
    }

    //  The certificates
    for (const auto& it : verifyInfo.getCertChainItems()) {
        const Cert::CerItem* cer_subject = it->getSubject();
        const CertValidator::CertEntity entity = it->getCertEntity();
        if ((entity == CertValidator::CertEntity::TSP) && !verifyInfo.isTsaOfValidTimeStamp(cer_subject)) continue;

        uint64_t ms_known = ms_signature;
        if (entity == CertValidator::CertEntity::TSP) {
            ms_known = ms_now;
            for (size_t i = 0; i < stamps.size(); i++) {
                if (stamps[i]->cerSigner == cer_subject) ms_known = known_at(i);
            }
        }
        else if ((entity == CertValidator::CertEntity::OCSP) || (entity == CertValidator::CertEntity::CRL)) {
            ms_known = ms_archived;
        }
        else if (std::find(path.begin(), path.end(), it) == path.end()) {
            //  a CA certificate of another path (of a TSA, of a signer of revocation data)
            ms_known = ms_archived;
        }

        const auto check_cert = [&](const string& algorithm, const uint32_t bits, const bool isKey) {
            const CryptoRule* rule = find_rule(algorithm, bits, isKey);
            if (!rule) return;
            const string s_algo = isKey ? (algorithm + "-" + to_string(bits)) : algorithm;
            if (rule->withdrawn) {
                if (cer_subject->getNotBefore() >= rule->msEnd) {
                    add_finding(report, Indication::INDETERMINATE, SUB_CRYPTO_CONSTRAINTS_FAILURE_NO_POE, "CERTIFICATE_ISSUED_WITH_WITHDRAWN_ALGORITHM", s_algo, *rule, cer_subject);
                }
            }
            else if (ms_known >= rule->msEnd) {
                add_finding(report, Indication::INDETERMINATE, SUB_CRYPTO_CONSTRAINTS_FAILURE_NO_POE, "CERTIFICATE_ALGORITHM_NOT_RELIABLE", s_algo, *rule, cer_subject);
            }
        };

        //  The revocation data of the certificate: the hash of its signature algorithm
        {
            string s_datahash;
            uint64_t ms_issued = 0, ms_dataknown = ms_now;
            if ((it->getValidationType() == Cert::ValidationType::CRL) && it->getResultValidationByCrl().crlItem) {
                s_datahash = crypto_hash_name(it->getResultValidationByCrl().crlItem->getSignAlgo());
                ms_issued = it->getResultValidationByCrl().crlItem->getThisUpdate();
                if (verifyInfo.hasRevocationValues()) ms_dataknown = ms_archived;
            }
            else if (it->getValidationType() == Cert::ValidationType::OCSP) {
                const CertValidator::ResultValidationByOcsp& by_ocsp = it->getResultValidationByOcsp();
                s_datahash = crypto_hash_name(by_ocsp.signAlgo);
                ms_issued = by_ocsp.msProducedAt;
                if (by_ocsp.dataSource == CertValidator::DataSource::SIGNATURE) ms_dataknown = ms_archived;
            }
            if (!s_datahash.empty() && (ms_issued > 0)) {
                check_made(s_datahash, 0, false, ms_issued, ms_dataknown, 0, "REVOCATION_DATA_ALGORITHM_NOT_RELIABLE", cer_subject);
            }
        }

        string s_family, s_signalgo;
        uint32_t bits = 0;
        crypto_key_info(cer_subject, s_family, bits);
        if (!s_family.empty()) check_cert(s_family, bits, true);
        //  The signature of a trust anchor is not relied on
        if (!it->isTrusted() && !it->isSelfSigned() && (Util::oidFromAsn1(&cer_subject->getCert()->signatureAlgorithm.algorithm, s_signalgo) == RET_OK)) {
            const string s_hash = crypto_hash_name(s_signalgo);
            if (!s_hash.empty()) check_cert(s_hash, 0, false);
        }
    }
}

string timestamp_id (
        const size_t idxSigner,
        const char* kind,
        const size_t number
)
{
    return string("TS-") + to_string(idxSigner) + "-" + kind + ((number > 0) ? ("-" + to_string(number)) : string());
}

//  The past validation (ETSI EN 319 102-1, 5.6.2): the proofs of existence the time-stamps give and the time each
//  certification path can be validated at (the control time, 5.6.2.2). A proof of existence: every object - at the
//  validation time; the signature value - at the time of a time-stamp over it; a time-stamp and the certificates
//  and revocation data embedded in the signature - at the time of a later archive time-stamp (which of the embedded
//  objects an archive time-stamp covers is not told apart: all of them). A time-stamp gives proofs when it is valid
//  and its own past validation passes, the newest first (5.6.3.4, step 5)
struct PastValidation {
    struct Item {
        string      id;             //  of a time-stamp; empty - the signature
        bool        valid;          //  a time-stamp: the token is cryptographically valid
        bool        passed;
        string      reason;         //  why not passed
        string      slide;          //  why the control time is not the validation time
        uint64_t    msControlTime;  //  the path can be validated at
        uint64_t    msPoe;          //  the proof of existence of the object
        string      poeObject;      //  the time-stamp that gives it; empty - the validation time

        Item (void) : valid(true), passed(false), msControlTime(0), msPoe(0) {}
    };
    uint64_t    msNow;
    Item        signature;
    vector<Item>
                timeStamps;         //  in the order of the signature

    PastValidation (void) : msNow(0) {}
};

//  The certificates from a certificate of the chain up to its root, in this order
vector<const CertValidator::CertChainItem*> path_of (
        const Doc::Verify::VerifiedSignerInfo& verifyInfo,
        const Cert::CerItem* cerItem
)
{
    vector<const CertValidator::CertChainItem*> rv_path;
    const Cert::CerItem* cer_next = cerItem;
    while (cer_next && (rv_path.size() < 64)) {
        const CertValidator::CertChainItem* item = nullptr;
        for (const auto& it : verifyInfo.getCertChainItems()) {
            if (it->getSubject() == cer_next) {
                item = it;
                break;
            }
        }
        if (!item) break;
        rv_path.push_back(item);
        const Cert::CerItem* cer_issuer = item->getIssuer();
        if (!cer_issuer || (cer_issuer == item->getSubject())) break;
        cer_next = cer_issuer;
    }
    return rv_path;
}

//  The validation time sliding process (5.6.2.2), the shell or the chain model by the policy. poeOfCert - the proof
//  of existence of a certificate of the path, msPoeData - of the revocation data embedded in the signature.
//  msFreshFrom - the strict freshness of the policy (5.2.5, NOTE 2: the maximum accepted freshness is zero and the
//  validation time is a time the object is known to have existed at): the revocation data of every certificate of
//  the path is issued after it; 0 - not required
bool control_time_of_path (
        const Doc::Verify::ValidationPolicy& policy,
        const vector<const CertValidator::CertChainItem*>& path,
        const uint64_t msNow,
        const std::function<uint64_t(const CertValidator::CertChainItem&)>& poeOfCert,
        const uint64_t msPoeData,
        const uint64_t msFreshFrom,
        uint64_t& msControlTime,
        string& reason,
        string& slide,
        uint64_t& msTrustStart
)
{
    msControlTime = msNow;
    msTrustStart = 0;
    reason.clear();
    slide.clear();
    if (path.empty()) {
        reason = "NO_CERTIFICATE_CHAIN_FOUND";
        return false;
    }

    //  The trust anchor: the first certificate of the path that is, or was, a trust anchor
    size_t idx_anchor = path.size();
    for (size_t i = 0; i < path.size(); i++) {
        const Cert::CerItem* cer_item = path[i]->getSubject();
        if (cer_item->isTrustedInit() || cer_item->wasTrusted()) {
            idx_anchor = i;
            break;
        }
    }
    if (idx_anchor == path.size()) {
        reason = "NO_CERTIFICATE_CHAIN_FOUND";
        return false;
    }
    {
        const Cert::CerItem* cer_anchor = path[idx_anchor]->getSubject();
        uint64_t ms_start = 0, ms_sunset = 0;
        if (!cer_anchor->isTrustedInit() && cer_anchor->trustPeriod(ms_start, ms_sunset)) {
            msTrustStart = ms_start;
            if ((ms_sunset > 0) && (ms_sunset < msNow)) {
                msControlTime = ms_sunset;
                slide = "TRUST_ANCHOR_SUNSET";
            }
        }
    }

    //  From the certificate issued by the trust anchor down to the target one
    for (size_t i = idx_anchor; i-- > 0; ) {
        const CertValidator::CertChainItem& item = *path[i];
        const Cert::CerItem* cer_subject = item.getSubject();
        const uint64_t ms_poecert = poeOfCert(item);
        if (ms_poecert > msControlTime) {
            reason = "NO_POE_OF_CERTIFICATE";
            return false;
        }
        bool is_revoked = false;
        CrlReason reason_revoked = CrlReason::UNDEFINED;
        uint64_t ms_revoked = 0, ms_issued = 0, ms_poedata = msNow;
        switch (item.getValidationType()) {
        case Cert::ValidationType::NONE:
            break;
        case Cert::ValidationType::CRL: {
            const CertValidator::ResultValidationByCrl& by_crl = item.getResultValidationByCrl();
            if (!by_crl.crlItem) {
                reason = "NO_REVOCATION_DATA";
                return false;
            }
            ms_issued = by_crl.crlItem->getThisUpdate();
            if (by_crl.certStatus == UapkiNS::CertStatus::REVOKED) {
                is_revoked = true;
                ms_revoked = by_crl.revokedCertItem.getDate();
                reason_revoked = by_crl.revokedCertItem.crlReason;
            }
            else if (by_crl.hasRevokedLater) {
                is_revoked = true;
                ms_revoked = by_crl.revokedLater.getDate();
                reason_revoked = by_crl.revokedLater.crlReason;
            }
            break;
        }
        case Cert::ValidationType::OCSP: {
            const CertValidator::ResultValidationByOcsp& by_ocsp = item.getResultValidationByOcsp();
            if (by_ocsp.statusSignature != SignatureVerifyStatus::VALID) {
                reason = "NO_REVOCATION_DATA";
                return false;
            }
            ms_issued = (by_ocsp.singleResponseInfo.msThisUpdate > 0) ? by_ocsp.singleResponseInfo.msThisUpdate : by_ocsp.msProducedAt;
            if (by_ocsp.dataSource == CertValidator::DataSource::SIGNATURE) {
                ms_poedata = msPoeData;
            }
            if (by_ocsp.singleResponseInfo.certStatus == UapkiNS::CertStatus::REVOKED) {
                is_revoked = true;
                ms_revoked = by_ocsp.singleResponseInfo.msRevocationTime;
                reason_revoked = by_ocsp.singleResponseInfo.revocationReason;
            }
            break;
        }
        default:
            reason = "NO_REVOCATION_DATA";
            return false;
        }
        if (item.getValidationType() != Cert::ValidationType::NONE) {
            //  Revocation data issued before the control time, with a proof of existence at it
            if ((ms_issued > msControlTime) || (ms_poedata > msControlTime)) {
                reason = "NO_POE_OF_REVOCATION_DATA";
                return false;
            }
            //  5.6.2.4.4, step 1: the revocation data of the target certificate is issued within the validity of
            //  the certificate of its issuer
            if ((i == 0) && (path.size() > 1)) {
                const Cert::CerItem* cer_issuer = path[1]->getSubject();
                if ((ms_issued < cer_issuer->getNotBefore()) || (ms_issued > cer_issuer->getNotAfter())) {
                    reason = "REVOCATION_DATA_OUT_OF_ISSUER_VALIDITY";
                    return false;
                }
            }
            //  The chain model: the revocation of a CA certificate counts if the reason is a compromise or not given
            const bool reason_counts = (reason_revoked == CrlReason::UNDEFINED) || (reason_revoked == CrlReason::UNSPECIFIED)
                || (reason_revoked == CrlReason::KEY_COMPROMISE) || (reason_revoked == CrlReason::CA_COMPROMISE)
                || (reason_revoked == CrlReason::AA_COMPROMISE);
            if (is_revoked && (ms_revoked < msControlTime) && (!policy.chainModel || (i == 0) || reason_counts)) {
                msControlTime = ms_revoked;
                slide = (i == 0) ? "CERTIFICATE_REVOKED" : "CA_CERTIFICATE_REVOKED";
            }
            else if (!is_revoked && (msFreshFrom > 0) && (ms_issued < msFreshFrom)) {
                reason = "REVOCATION_DATA_NOT_FRESH";
                return false;
            }
        }
        //  The cryptographic constraints: up to the time the algorithms were all reliable
        if (policy.cryptoLevel != Doc::Verify::CryptoLevel::OFF) {
            string s_family, s_signalgo;
            uint32_t bits = 0;
            crypto_key_info(cer_subject, s_family, bits);
            const string s_hash = (Util::oidFromAsn1(&cer_subject->getCert()->signatureAlgorithm.algorithm, s_signalgo) == RET_OK)
                ? crypto_hash_name(s_signalgo) : string();
            for (const auto& it : policy.cryptoRules) {
                if ((it.msEnd == 0) || it.withdrawn || (it.msEnd >= msControlTime)) continue;
                const bool concerns = (it.keySizeBelow > 0)
                    ? ((it.algorithm == s_family) && (bits > 0) && (bits < it.keySizeBelow))
                    : (it.algorithm == s_hash);
                if (concerns) {
                    msControlTime = it.msEnd;
                    slide = "ALGORITHM_NOT_RELIABLE";
                }
            }
        }
    }
    return true;
}

void evaluate_past_validation (
        const Doc::Verify::VerifiedSignerInfo& verifyInfo,
        const Doc::Verify::ValidationPolicy& policy,
        const size_t idxSigner,
        const vector<const CertValidator::CertChainItem*>& path,
        const uint64_t msProvidedPoe,
        PastValidation& past
)
{
    using Doc::Verify::AttrTimeStamp;
    enum class Kind { CONTENT, SIGNATURE, ARCHIVE };
    struct Stamp {
        const AttrTimeStamp* ts;
        Kind        kind;
    };
    vector<Stamp> stamps;
    past.msNow = TimeUtil::mtimeNow();
    past.timeStamps.clear();
    const auto add_stamp = [&](const AttrTimeStamp& ts, const Kind kind, const char* name, const size_t number) {
        if (!ts.isPresent()) return;
        stamps.push_back({ &ts, kind });
        PastValidation::Item item;
        item.id = timestamp_id(idxSigner, name, number);
        item.valid = timestamp_is_valid(ts) && (ts.msGenTime > 0);
        past.timeStamps.push_back(item);
    };
    add_stamp(verifyInfo.getContentTS(), Kind::CONTENT, "CONTENT", 0);
    add_stamp(verifyInfo.getSignatureTS(), Kind::SIGNATURE, "SIGNATURE", 0);
    add_stamp(verifyInfo.getArchiveTS(), Kind::ARCHIVE, "ARCHIVE", 0);
    {
        size_t number = 1;
        for (const auto& it : verifyInfo.getArchiveTSsNext()) {
            if (it) add_stamp(*it, Kind::ARCHIVE, "ARCHIVE", number);
            number++;
        }
    }

    //  A proof of existence given by the caller: of the signature with all its objects
    const uint64_t ms_base = ((msProvidedPoe > 0) && (msProvidedPoe < past.msNow)) ? msProvidedPoe : past.msNow;
    //  The newest first: a time-stamp is proven to exist by the later ones that passed
    uint64_t ms_poesignature = ms_base, ms_poearchived = ms_base;
    string s_poesignature, s_poearchived;
    vector<const AttrTimeStamp*> archives;
    //  A certificate embedded in the signature: by the archive time-stamps that passed and cover it
    const auto poe_of_cert = [&](const CertValidator::CertChainItem& item) -> uint64_t {
        if (item.getDataSource() != CertValidator::DataSource::SIGNATURE) return past.msNow;
        uint64_t rv = ms_base;
        for (const auto& it : archives) {
            if ((it->msGenTime < rv) && verifyInfo.archiveTimeStampCoversCert(*it, item.getSubject())) rv = it->msGenTime;
        }
        return rv;
    };
    for (size_t i = stamps.size(); i-- > 0; ) {
        PastValidation::Item& item = past.timeStamps[i];
        const AttrTimeStamp& ts = *stamps[i].ts;
        //  the content time-stamp is a signed attribute: proven with the signature value
        item.msPoe = (stamps[i].kind == Kind::CONTENT) ? ms_poesignature : ms_poearchived;
        item.poeObject = (stamps[i].kind == Kind::CONTENT) ? s_poesignature : s_poearchived;
        if (!item.valid) {
            item.reason = "TIME_STAMP_NOT_VALID";
            continue;
        }
        uint64_t ms_truststart = 0;
        if (!control_time_of_path(policy, path_of(verifyInfo, ts.cerSigner), past.msNow, poe_of_cert, ms_poearchived, policy.revocationFreshnessStrict ? ts.msGenTime : 0, item.msControlTime, item.reason, item.slide, ms_truststart)) continue;
        if (item.msPoe > item.msControlTime) {
            item.reason = "NO_POE_OF_TIME_STAMP";
            continue;
        }
        if (ts.msGenTime < ms_truststart) {
            item.reason = "TRUST_ANCHOR_NOT_YET_TRUSTED";
            continue;
        }
        item.passed = true;
        if ((stamps[i].kind != Kind::CONTENT) && (ts.msGenTime <= ms_poesignature)) {
            ms_poesignature = ts.msGenTime;
            s_poesignature = item.id;
        }
        if (stamps[i].kind == Kind::ARCHIVE) {
            archives.push_back(&ts);
            if (ts.msGenTime < ms_poearchived) {
                ms_poearchived = ts.msGenTime;
                s_poearchived = item.id;
            }
        }
    }

    past.signature = PastValidation::Item();
    past.signature.msPoe = ms_poesignature;
    past.signature.poeObject = s_poesignature;
    uint64_t ms_truststart = 0;
    if (control_time_of_path(policy, path, past.msNow, poe_of_cert, ms_poearchived, policy.revocationFreshnessStrict ? ms_poesignature : 0, past.signature.msControlTime, past.signature.reason, past.signature.slide, ms_truststart)) {
        const Cert::CerItem* cer_signer = path.front()->getSubject();
        if (past.signature.msPoe > past.signature.msControlTime) {
            past.signature.reason = "NO_POE_OF_SIGNATURE";
        }
        //  5.6.2.4.4, step 3: the signature is proven to have existed within the validity of the signing certificate
        else if (past.signature.msPoe < cer_signer->getNotBefore()) {
            past.signature.reason = "NOT_YET_VALID";
        }
        else if (past.signature.msPoe > cer_signer->getNotAfter()) {
            past.signature.reason = "NO_POE_BEFORE_EXPIRATION";
        }
        else if (past.signature.msPoe < ms_truststart) {
            past.signature.reason = "TRUST_ANCHOR_NOT_YET_TRUSTED";
        }
        else {
            past.signature.passed = true;
        }
    }
}

int past_validation_to_json (
        JSON_Object* joReport,
        const PastValidation& past
)
{
    int ret = RET_OK;
    const auto item_to_json = [&past](JSON_Object* joItem, const PastValidation::Item& item) -> int {
        int ret = RET_OK;
        if (!item.id.empty()) {
            DO_JSON(json_object_set_string(joItem, "id", item.id.c_str()));
        }
        DO_JSON(json_object_set_string(joItem, "status", item.passed ? "PASSED" : "NO_POE"));
        if (!item.reason.empty()) {
            DO_JSON(json_object_set_string(joItem, "reason", item.reason.c_str()));
        }
        if (!item.slide.empty()) {
            DO_JSON(json_object_set_string(joItem, "controlTimeReason", item.slide.c_str()));
        }
        if (item.msControlTime > 0) {
            DO_JSON(json_object_set_string(joItem, "controlTime", TimeUtil::mtimeToFtime(item.msControlTime).c_str()));
        }
        if (item.msPoe > 0) {
            DO_JSON(json_object_dotset_string(joItem, "poe.poeTime", TimeUtil::mtimeToFtime(item.msPoe).c_str()));
            //  given by the caller: earlier than the validation time and not by a time-stamp
            DO_JSON(json_object_dotset_string(joItem, "poe.typeOfProof", (item.poeObject.empty() && (item.msPoe < past.msNow)) ? "provided" : "validation"));
            if (!item.poeObject.empty()) {
                DO_JSON(json_object_dotset_string(joItem, "poe.poeObject", item.poeObject.c_str()));
            }
        }
    cleanup:
        return ret;
    };

    DO_JSON(json_object_dotset_value(joReport, "pastValidation.signature", json_value_init_object()));
    DO(item_to_json(json_object_dotget_object(joReport, "pastValidation.signature"), past.signature));
    if (!past.timeStamps.empty()) {
        DO_JSON(json_object_dotset_value(joReport, "pastValidation.timeStamps", json_value_init_array()));
        JSON_Array* ja_stamps = json_object_dotget_array(joReport, "pastValidation.timeStamps");
        for (const auto& it : past.timeStamps) {
            DO_JSON(json_array_append_value(ja_stamps, json_value_init_object()));
            DO(item_to_json(json_array_get_object(ja_stamps, json_array_get_count(ja_stamps) - 1), it));
        }
    }

cleanup:
    return ret;
}

//  IndividualValidationConstraintReportType
int constraint_to_json (
        JSON_Array* jaConstraints,
        const ConstraintReport& report
)
{
    int ret = RET_OK;
    DO_JSON(json_array_append_value(jaConstraints, json_value_init_object()));
    {
        JSON_Object* jo_constraint = json_array_get_object(jaConstraints, json_array_get_count(jaConstraints) - 1);
        DO_JSON(json_object_set_string(jo_constraint, "validationConstraintIdentifier", report.id.c_str()));
        if (!report.parameter.empty()) {
            DO_JSON(json_object_dotset_string(jo_constraint, "validationConstraintParameter.type", "value"));
            DO_JSON(json_object_dotset_string(jo_constraint, "validationConstraintParameter.value", report.parameter.c_str()));
        }
        DO_JSON(json_object_dotset_string(jo_constraint, "constraintStatus.status", report.applied ? "applied" : "disabled"));
        if (report.applied) {
            DO_JSON(json_object_set_string(jo_constraint, "level", report.warning ? "warning" : "fail"));
            DO_JSON(json_object_set_value(jo_constraint, "validationStatus", json_value_init_object()));
            DO(validation_status_to_json(
                json_object_get_object(jo_constraint, "validationStatus"), report.indication(), false, report.findings
            ));
        }
    }

cleanup:
    return ret;
}

//  ValidationObjectType of a time-stamp, with the report of its own validation (4.4.8)
int timestamp_object_to_json (
        JSON_Array* jaObjects,
        const string& id,
        const char* kind,
        const Doc::Verify::AttrTimeStamp& attrTS
)
{
    int ret = RET_OK;
    Indication indication;
    string s_sub, s_info;
    vector<Finding> findings;

    evaluate_timestamp(attrTS, indication, s_sub, s_info);
    if (!s_sub.empty()) {
        findings.push_back(Finding(indication, s_sub.c_str(), s_info));
    }
    DO_JSON(json_array_append_value(jaObjects, json_value_init_object()));
    {
        JSON_Object* jo_object = json_array_get_object(jaObjects, json_array_get_count(jaObjects) - 1);
        DO_JSON(json_object_set_string(jo_object, "id", id.c_str()));
        DO_JSON(json_object_set_string(jo_object, "objectType", "timestamp"));
        DO_JSON(json_object_set_string(jo_object, "timeStampType", kind));
        if (attrTS.cerSigner && (attrTS.msGenTime > 0)) {
            //  The TSA certificate is a time-stamping service of a trusted list: qualified ("QTSA") when the service
            //  was provided at the time of the time-stamp (ETSI TS 119 615, 4.7), else "TSA"
            const std::shared_ptr<const Cert::TrustServices> services = attrTS.cerSigner->getTrustServices();
            if (is_listed(services, "TSA/")) {
                DO_JSON(json_object_set_string(jo_object, "timeStampQualification",
                    listed_service(services, "TSA/QTST", attrTS.msGenTime) ? "QTSA" : "TSA"));
            }
        }
        if (attrTS.msGenTime > 0) {
            //  What the time-stamp proves the existence of at its time, when it passes the validation
            DO_JSON(json_object_dotset_string(jo_object, "poeProvisioning.poeTime", TimeUtil::mtimeToFtime(attrTS.msGenTime).c_str()));
        }
        DO_JSON(json_object_dotset_value(jo_object, "validationReport.signatureValidationStatus", json_value_init_object()));
        DO(validation_status_to_json(
            json_object_dotget_object(jo_object, "validationReport.signatureValidationStatus"), indication, false, findings
        ));
        DO(Doc::Verify::attrTimeStampToJson(jo_object, nullptr, attrTS));
    }

cleanup:
    return ret;
}

int signature_report_to_json (
        JSON_Object* joReport,
        JSON_Array* jaObjects,
        set<string>& objectIds,
        Doc::Verify::VerifySignedDoc& verifySdoc,
        const size_t idxSigner
)
{
    int ret = RET_OK;
    Doc::Verify::VerifiedSignerInfo& verify_info = verifySdoc.verifiedSignerInfos[idxSigner];
    const Doc::Verify::VerifyOptions& verify_options = verifySdoc.verifyOptions;
    const Doc::Verify::ValidationPolicy& policy = verify_options.policy;
    const Pkcs7::SignedDataParser::SignerInfo& signer_info = verify_info.getSignerInfo();
    const vector<const CertValidator::CertChainItem*> path = signer_path(verify_info);
    const bool has_signer_cert = (verify_info.getSignerCertId() != nullptr);
    vector<ConstraintReport> constraints;
    bool signer_status_not_determined = false;
    string s_poeobject;

    //  5.2.2 Format checking. What the library could not process is not proven to be malformed: INDETERMINATE
    {
        ConstraintReport report(CONSTRAINT_FORMAT);
        if (verify_info.isNotProcessed()) {
            report.add(Finding(Indication::INDETERMINATE, SUB_CUSTOM, error_code_to_str(verify_info.getLastError())));
        }
        constraints.push_back(report);
    }

    //  5.2.3 Identification of the signing certificate
    {
        ConstraintReport report(CONSTRAINT_SIGNING_CERTIFICATE);
        if (!has_signer_cert) {
            report.add(Finding(Indication::INDETERMINATE, SUB_NO_SIGNING_CERTIFICATE_FOUND));
        }
        else if (verify_info.getStatusEssCert() == DataVerifyStatus::INVALID) {
            report.add(Finding(Indication::INDETERMINATE, SUB_NO_SIGNING_CERTIFICATE_FOUND, "SIGNING_CERTIFICATE_ATTRIBUTE_MISMATCH"));
        }
        else if (verify_info.getStatusEssCert() == DataVerifyStatus::FAILED) {
            report.add(Finding(Indication::INDETERMINATE, SUB_NO_SIGNING_CERTIFICATE_FOUND, "SIGNING_CERTIFICATE_ATTRIBUTE_NOT_DECODED"));
        }
        constraints.push_back(report);
    }

    //  5.2.6 X.509 certificate validation: the path of the signing certificate, then the certificates of the
    //  time-stamps and of the revocation data used
    {
        ConstraintReport report(CONSTRAINT_X509), report_data(CONSTRAINT_X509_VALIDATION_DATA);
        for (const auto& it : verify_info.getCertChainItems()) {
            //  The TSA of a time-stamp that is not valid: the time-stamp is not used, nor is its certificate
            if ((it->getCertEntity() == CertValidator::CertEntity::TSP) && !verify_info.isTsaOfValidTimeStamp(it->getSubject())) continue;
            const bool in_path = (std::find(path.begin(), path.end(), it) != path.end());
            evaluate_chain_item(verify_info, *it, verify_options.checkCriticalExtensions, in_path ? report : report_data, signer_status_not_determined);
        }
        if (has_signer_cert && path.empty()) {
            report.add(Finding(Indication::INDETERMINATE, SUB_NO_CERTIFICATE_CHAIN_FOUND));
        }
        if (!verify_info.getExpectedCerts().empty()) {
            report.add(Finding(Indication::INDETERMINATE, SUB_NO_CERTIFICATE_CHAIN_FOUND, "CERTIFICATES_NOT_FOUND"));
        }
        if (!verify_info.getExpectedCrls().empty()) {
            report.add(Finding(Indication::INDETERMINATE, SUB_TRY_LATER, "CRLS_NOT_OBTAINED"));
        }
        constraints.push_back(report);
        constraints.push_back(report_data);
    }

    //  5.2.7 Cryptographic verification
    {
        ConstraintReport report(CONSTRAINT_CRYPTO);
        switch (verify_info.getStatusMessageDigest()) {
        case DigestVerifyStatus::VALID:
            break;
        case DigestVerifyStatus::INVALID:
            report.add(Finding(Indication::FAILED, SUB_HASH_FAILURE));
            break;
        default:
            report.add(Finding(Indication::INDETERMINATE, SUB_SIGNED_DATA_NOT_FOUND));
            break;
        }
        switch (verify_info.getStatusSignature()) {
        case SignatureVerifyStatus::VALID:
            break;
        case SignatureVerifyStatus::INVALID:
            report.add(Finding(Indication::FAILED, SUB_SIG_CRYPTO_FAILURE));
            break;
        default:
            if (has_signer_cert) {
                report.add(Finding(Indication::INDETERMINATE, SUB_CUSTOM, "SIGNATURE_VALUE_NOT_VERIFIED"));
            }
            else {
                report.add(Finding(Indication::INDETERMINATE, SUB_NO_SIGNING_CERTIFICATE_FOUND));
            }
            break;
        }
        constraints.push_back(report);
    }

    //  The references to the validation material (TS 101 733: complete-certificate/revocation-references)
    {
        Doc::Verify::CadesXlInfo& xl_info = verify_info.getCadesXlInfo();
        if (xl_info.isPresentCertRefs || xl_info.isPresentRevocRefs) {
            ConstraintReport report(CONSTRAINT_VALIDATION_MATERIAL);
            if (xl_info.statusRevocationRefs == DigestVerifyStatus::INVALID) {
                report.add(Finding(Indication::INDETERMINATE, SUB_CUSTOM, "REVOCATION_REFERENCES_DO_NOT_MATCH"));
            }
            if (xl_info.isPresentCertRefs && (xl_info.statusCertRefs != DigestVerifyStatus::VALID)) {
                report.add(Finding(Indication::INDETERMINATE, SUB_CUSTOM, "CERTIFICATE_REFERENCES_DO_NOT_MATCH"));
            }
            constraints.push_back(report);
        }
    }

    //  The constraints of the validation policy
    {
        //  RFC 5280, 4.2: a certificate with a critical extension that is not recognized
        ConstraintReport report(CONSTRAINT_CRITICAL_EXTENSIONS);
        report.warning = !policy.checkCriticalExtensions;
        for (const auto& it : verify_info.getCertChainItems()) {
            if ((it->getCertEntity() == CertValidator::CertEntity::TSP) && !verify_info.isTsaOfValidTimeStamp(it->getSubject())) continue;
            if (it->getSubject()->hasUnknownCriticalExtension()) {
                report.add(Finding(Indication::INDETERMINATE, SUB_CHAIN_CONSTRAINTS_FAILURE, "UNKNOWN_CRITICAL_EXTENSION", it->getSubject()));
            }
        }
        constraints.push_back(report);
    }
    {
        //  5.2.5: with the strict freshness the revocation data of every certificate is issued after the best
        //  signature time; else the validation is to be repeated when newer data is issued
        ConstraintReport report(CONSTRAINT_REVOCATION_FRESHNESS, true, policy.revocationFreshnessStrict ? "0" : to_string(policy.revocationFreshness));
        if (policy.revocationFreshnessStrict) {
            const uint64_t ms_signature = verify_info.getBestSignatureTime();
            for (const auto& it : verify_info.getCertChainItems()) {
                if (it->isExpired() || (it->getCertEntity() == CertValidator::CertEntity::ROOT)) continue;
                if ((it->getCertEntity() == CertValidator::CertEntity::TSP) && !verify_info.isTsaOfValidTimeStamp(it->getSubject())) continue;
                uint64_t ms_issued = 0, ms_next = 0;
                if ((it->getValidationType() == Cert::ValidationType::CRL) && it->getResultValidationByCrl().crlItem) {
                    if (it->getResultValidationByCrl().certStatus != UapkiNS::CertStatus::GOOD) continue;
                    ms_issued = it->getResultValidationByCrl().crlItem->getThisUpdate();
                    ms_next = it->getResultValidationByCrl().crlItem->getNextUpdate();
                }
                else if (it->getValidationType() == Cert::ValidationType::OCSP) {
                    const CertValidator::ResultValidationByOcsp& by_ocsp = it->getResultValidationByOcsp();
                    if ((by_ocsp.statusSignature != SignatureVerifyStatus::VALID) || (by_ocsp.singleResponseInfo.certStatus != UapkiNS::CertStatus::GOOD)) continue;
                    ms_issued = by_ocsp.singleResponseInfo.msThisUpdate;
                    ms_next = by_ocsp.singleResponseInfo.msNextUpdate;
                }
                if ((ms_issued > 0) && (ms_signature > 0) && (ms_issued < ms_signature)) {
                    Finding finding(Indication::INDETERMINATE, SUB_TRY_LATER, "REVOCATION_DATA_NOT_FRESH", it->getSubject());
                    if (ms_next > 0) {
                        finding.tryAfter = TimeUtil::mtimeToFtime(ms_next);
                    }
                    report.add(finding);
                }
            }
        }
        constraints.push_back(report);
    }
    constraints.push_back(ConstraintReport(CONSTRAINT_EXPIRED_CERTS_ON_CRL, true, policy.caRemovesExpiredCerts ? "true" : "false"));
    constraints.push_back(ConstraintReport(CONSTRAINT_TSA_TRUST, true, policy.tsaTrustByProofOfExistence ? "proofOfExistence" : "timeStampTime"));
    {
        //  The status of an OCSP responder (a CRL signer) is always required: the certificate is a service of
        //  a trusted list, or has id-pkix-ocsp-nocheck, or its status is determined by a CRL (of the signature
        //  or obtained online). Else the signature is not validated yet
        ConstraintReport report(CONSTRAINT_REVOCATION_SIGNER_STATUS);
        if (signer_status_not_determined) {
            report.add(Finding(Indication::INDETERMINATE, SUB_TRY_LATER, "STATUS_OF_REVOCATION_DATA_SIGNER_NOT_DETERMINED"));
        }
        constraints.push_back(report);
    }
    {
        //  RFC 3161, 2.3: the TSA certificate has only the key purpose id-kp-timeStamping
        ConstraintReport report(CONSTRAINT_TSA_KEY_PURPOSE, true, policy.tsaAdditionalKeyPurposes ? "allowAdditional" : "strict");
        if (!policy.tsaAdditionalKeyPurposes) {
            for (const auto& it : verify_info.getCertChainItems()) {
                if ((it->getCertEntity() != CertValidator::CertEntity::TSP) || !verify_info.isTsaOfValidTimeStamp(it->getSubject())) continue;
                const Cert::CertExtKeyUsage& ext_keyusage = it->getSubject()->getCertExtKeyUsage();
                if (ext_keyusage.isUnknown() || ext_keyusage.isOcsp() || ext_keyusage.isCmp()) {
                    report.add(Finding(Indication::INDETERMINATE, SUB_CHAIN_CONSTRAINTS_FAILURE, "TSA_CERTIFICATE_HAS_ADDITIONAL_KEY_PURPOSES", it->getSubject()));
                }
            }
        }
        constraints.push_back(report);
    }
    {
        ConstraintReport report(CONSTRAINT_SIGNER_KEY_USAGE, true, policy.signerNonRepudiation ? "nonRepudiation" : "digitalSignatureOrNonRepudiation");
        if (policy.signerNonRepudiation && !path.empty() && !path.front()->getSubject()->keyUsageByBit(KeyUsage_nonRepudiation)) {
            report.add(Finding(Indication::INDETERMINATE, SUB_CHAIN_CONSTRAINTS_FAILURE, "SIGNING_CERTIFICATE_WITHOUT_NON_REPUDIATION", path.front()->getSubject()));
        }
        constraints.push_back(report);
    }
    {
        const bool applied = (policy.cryptoLevel != Doc::Verify::CryptoLevel::OFF);
        const char* s_level = (policy.cryptoLevel == Doc::Verify::CryptoLevel::FAIL) ? "fail" : (applied ? "warning" : "off");
        ConstraintReport report(CONSTRAINT_CRYPTO_CONSTRAINTS, applied, s_level);
        ConstraintReport report_withdrawn(CONSTRAINT_WITHDRAWN_ALGORITHMS, applied);
        report.warning = (policy.cryptoLevel == Doc::Verify::CryptoLevel::WARNING);
        report_withdrawn.warning = true;
        if (applied) {
            evaluate_crypto_constraints(verify_info, policy, path, report, report_withdrawn);
        }
        constraints.push_back(report);
        constraints.push_back(report_withdrawn);
    }
    {
        //  ETSI EN 319 102-1, 5.5.4: the order of the time-stamps (step 4 e), the time-stamp delay (step 5) when
        //  the policy specifies one
        ConstraintReport report(CONSTRAINT_TIMESTAMP_ORDER, true, to_string(policy.timeStampDelay));
        for (const auto& it : verify_info.getTimeStampOrderFailures()) {
            report.add(Finding(Indication::INDETERMINATE, SUB_TIMESTAMP_ORDER_FAILURE, it));
        }
        const Doc::Verify::AttrTimeStamp& signature_ts = verify_info.getSignatureTS();
        if (
            (policy.timeStampDelay > 0) && signature_ts.isPresent() && (signature_ts.msGenTime > 0) &&
            (signature_ts.statusDigest == DigestVerifyStatus::VALID) && (signature_ts.statusSignature == SignatureVerifyStatus::VALID)
        ) {
            if (verify_info.getSigningTime() == 0) {
                report.add(Finding(Indication::INDETERMINATE, SUB_SIG_CONSTRAINTS_FAILURE, "SIGNING_TIME_NOT_PRESENT"));
            }
            else if (verify_info.getSigningTime() + (uint64_t)policy.timeStampDelay * 60000 <= signature_ts.msGenTime) {
                report.add(Finding(Indication::INDETERMINATE, SUB_SIG_CONSTRAINTS_FAILURE, "TIME_STAMP_DELAY_EXCEEDED"));
            }
        }
        constraints.push_back(report);
    }
    {
        //  The past validation of the signature (ETSI EN 319 102-1, 5.6.2.4): the sub-indication is the one of the
        //  reason the control time is not the validation time
        ConstraintReport report(CONSTRAINT_PAST_VALIDATION, true, policy.pastValidationByPoe ? "proofOfExistence" : "bestSignatureTime");
        if (policy.pastValidationByPoe && !path.empty()) {
            PastValidation past;
            evaluate_past_validation(verify_info, policy, idxSigner, path, verify_options.msProvidedPoe, past);
            const PastValidation::Item& sig = past.signature;
            const Cert::CerItem* cer_signer = path.front()->getSubject();
            if (sig.passed) {
            }
            else if (sig.reason == "NOT_YET_VALID") {
                report.add(Finding(Indication::FAILED, SUB_NOT_YET_VALID, sig.reason, cer_signer));
            }
            else if (sig.reason == "NO_POE_BEFORE_EXPIRATION") {
                report.add(Finding(Indication::INDETERMINATE, SUB_OUT_OF_BOUNDS_NO_POE, sig.reason, cer_signer));
            }
            else if (sig.reason == "REVOCATION_DATA_OUT_OF_ISSUER_VALIDITY") {
                report.add(Finding(Indication::INDETERMINATE, SUB_REVOCATION_OUT_OF_BOUNDS_NO_POE, sig.reason, cer_signer));
            }
            else if (sig.reason == "TRUST_ANCHOR_NOT_YET_TRUSTED") {
                report.add(Finding(Indication::INDETERMINATE, SUB_NO_CERTIFICATE_CHAIN_FOUND, sig.reason, cer_signer));
            }
            else if (sig.reason == "REVOCATION_DATA_NOT_FRESH") {
                report.add(Finding(Indication::INDETERMINATE, SUB_TRY_LATER, sig.reason, cer_signer));
            }
            else if (sig.reason.compare(0, 6, "NO_POE") == 0) {
                const char* sub = (sig.slide == "CERTIFICATE_REVOKED") ? SUB_REVOKED_NO_POE
                    : (sig.slide == "CA_CERTIFICATE_REVOKED") ? SUB_REVOKED_CA_NO_POE
                    : (sig.slide == "ALGORITHM_NOT_RELIABLE") ? SUB_CRYPTO_CONSTRAINTS_FAILURE_NO_POE
                    : SUB_NO_CERTIFICATE_CHAIN_FOUND_NO_POE;
                report.add(Finding(Indication::INDETERMINATE, sub, sig.reason, cer_signer));
            }
        }
        constraints.push_back(report);
    }
    constraints.push_back(ConstraintReport(CONSTRAINT_SIGNATURE_POLICY, false));

    //  The indication of the signature (5.1.3)
    vector<Finding> all_findings;
    for (const auto& it : constraints) {
        if (!it.applied || it.warning) continue;
        for (const auto& it_finding : it.findings) {
            all_findings.push_back(it_finding);
        }
    }
    Indication indication = Indication::PASSED;
    for (const auto& it : all_findings) {
        if ((uint32_t)it.indication > (uint32_t)indication) indication = it.indication;
    }
    //  The sub-indications of the signature are the ones of its indication
    vector<Finding> main_findings;
    for (const auto& it : all_findings) {
        if (it.indication == indication) main_findings.push_back(it);
    }

    //  =signatureIdentifier= (4.3.3): the hash of the data to be signed representation, the signature value
    DO_JSON(json_object_set_number(joReport, "signerInfoIndex", (double)idxSigner));
    {
        DO_JSON(json_object_set_value(joReport, "signatureIdentifier", json_value_init_object()));
        JSON_Object* jo_sigid = json_object_get_object(joReport, "signatureIdentifier");
        const string& s_digestalgo = signer_info.getDigestAlgorithm().algorithm;
        const HashAlg hash_alg = hash_from_oid(s_digestalgo.c_str());
        SmartBA sba_hash;
        if ((hash_alg != HASH_ALG_UNDEFINED) && signer_info.getSignedAttrsEncoded()) {
            (void)::hash(hash_alg, signer_info.getSignedAttrsEncoded(), &sba_hash);
        }
        DO(digest_alg_and_value_to_json(jo_sigid, s_digestalgo, sba_hash.get()));
        if (signer_info.getSignature()) {
            DO(json_object_set_base64(jo_sigid, "signatureValue", signer_info.getSignature()));
        }
        DO_JSON(ParsonHelper::jsonObjectSetBoolean(jo_sigid, "hashOnly", false));
        DO_JSON(ParsonHelper::jsonObjectSetBoolean(jo_sigid, "docHashOnly", verify_info.isContentDigest()));
    }

    //  =signatureValidationStatus= (4.3.4)
    DO_JSON(json_object_set_value(joReport, "signatureValidationStatus", json_value_init_object()));
    DO(validation_status_to_json(
        json_object_get_object(joReport, "signatureValidationStatus"), indication, true, main_findings, &path
    ));

    //  =signatureValidationProcess= (4.3.11)
    {
        bool archive_ts_valid = timestamp_is_valid(verify_info.getArchiveTS());
        for (const auto& it : verify_info.getArchiveTSsNext()) {
            archive_ts_valid |= timestamp_is_valid(*it);
        }
        const char* s_process = archive_ts_valid ? PROCESS_LTA
            : (timestamp_is_valid(verify_info.getSignatureTS()) ? PROCESS_LTVM : PROCESS_BASIC);
        DO_JSON(json_object_dotset_string(joReport, "signatureValidationProcess.signatureValidationProcessId", s_process));
    }

    //  =validationTimeInfo= (4.3.6): the best signature time is proven by the earliest valid time-stamp over
    //  the signature, else it is the validation time
    {
        const uint64_t best_time = verify_info.getBestSignatureTime();
        if (timestamp_is_valid(verify_info.getSignatureTS()) && (verify_info.getSignatureTS().msGenTime == best_time)) {
            s_poeobject = timestamp_id(idxSigner, "SIGNATURE", 0);
        }
        else if (timestamp_is_valid(verify_info.getArchiveTS()) && (verify_info.getArchiveTS().msGenTime == best_time)) {
            s_poeobject = timestamp_id(idxSigner, "ARCHIVE", 0);
        }
        else {
            size_t number = 1;
            for (const auto& it : verify_info.getArchiveTSsNext()) {
                if (s_poeobject.empty() && timestamp_is_valid(*it) && (it->msGenTime == best_time)) {
                    s_poeobject = timestamp_id(idxSigner, "ARCHIVE", number);
                }
                number++;
            }
        }
        DO_JSON(json_object_dotset_string(joReport, "validationTimeInfo.validationTime", TimeUtil::mtimeToFtime(verifySdoc.validateTime).c_str()));
        if (best_time > 0) {
            DO_JSON(json_object_dotset_string(joReport, "validationTimeInfo.bestSignatureTime.poeTime", TimeUtil::mtimeToFtime(best_time).c_str()));
            DO_JSON(json_object_dotset_string(joReport, "validationTimeInfo.bestSignatureTime.typeOfProof", "validation"));
            if (!s_poeobject.empty()) {
                DO_JSON(json_object_dotset_string(joReport, "validationTimeInfo.bestSignatureTime.poeObject", s_poeobject.c_str()));
            }
        }
    }

    //  The past validation (ETSI EN 319 102-1, 5.6.2): the proofs of existence and the control times
    {
        PastValidation past;
        evaluate_past_validation(verify_info, policy, idxSigner, path, verify_options.msProvidedPoe, past);
        DO(past_validation_to_json(joReport, past));
    }

    //  =signersDocument= (4.3.7): the hash of the signed data, as signed
    if (signer_info.getMessageDigest()) {
        DO_JSON(json_object_set_value(joReport, "signersDocument", json_value_init_object()));
        DO(digest_alg_and_value_to_json(
            json_object_get_object(joReport, "signersDocument"), signer_info.getDigestAlgorithm().algorithm, signer_info.getMessageDigest()
        ));
    }

    //  =signerInformation= (4.3.9)
    if (has_signer_cert) {
        DO_JSON(json_object_set_value(joReport, "signerInformation", json_value_init_object()));
        JSON_Object* jo_signer = json_object_get_object(joReport, "signerInformation");
        DO(json_object_set_base64(jo_signer, "signerCertificate", verify_info.getSignerCertId()));
        if (!path.empty()) {
            DO_JSON(json_object_set_string(jo_signer, "signer", path.front()->getCommonName().c_str()));
        }
    }

    //  =signatureQuality= (4.3.10): of a signature that passed, by the statements of the signing certificate.
    //  The values are the ones of EU DSS; a certificate with only the former Ukrainian policy of a qualified
    //  certificate says nothing about the signature creation device
    if ((indication == Indication::PASSED) && !path.empty()) {
        vector<string> statement_ids;
        bool is_seal = false, is_oldqualified = false;
        DO(get_qc_statements(path.front()->getSubject(), statement_ids, is_seal, is_oldqualified));
        const auto has_statement = [&statement_ids](const char* oid) {
            return std::find(statement_ids.begin(), statement_ids.end(), oid) != statement_ids.end();
        };
        //  The issuer of the signing certificate in a trusted list (ETSI TS 119 615, 4.4): the certificate is
        //  qualified when the service that issues qualified certificates (of the kind: for signatures / for seals)
        //  was provided both when the certificate was issued and at the best signature time. A listed issuer
        //  whose service was not provided then - the statements of the certificate are not confirmed
        const Cert::CerItem* cer_signer = path.front()->getSubject();
        const std::shared_ptr<const Cert::TrustServices> issuer_services =
            (path.size() > 1) ? path[1]->getSubject()->getTrustServices() : std::shared_ptr<const Cert::TrustServices>();
        const bool issuer_listed = is_listed(issuer_services, "CA/");
        const ServiceFor service_for = is_seal ? ServiceFor::SEALS : ServiceFor::SIGNATURES;
        const Cert::TrustService* service_issued = listed_service(issuer_services, "CA/QC", cer_signer->getNotBefore(), service_for);
        const Cert::TrustService* service_signed = listed_service(issuer_services, "CA/QC", verify_info.getBestSignatureTime(), service_for);
        const bool confirmed = issuer_listed && service_issued && service_signed;
        const bool claims_qc = has_statement(OID_QCS_COMPLIANCE);

        string s_quality;
        if (claims_qc && (!issuer_listed || confirmed)) {
            s_quality = has_statement(OID_QCS_QSCD) ? (is_seal ? "QESeal" : "QESig") : (is_seal ? "AdESeal-QC" : "AdESig-QC");
        }
        else if (is_oldqualified && !claims_qc && (!issuer_listed || confirmed)) {
            s_quality = is_seal ? "AdESeal-QC-old" : "AdESig-QC-old";
        }
        else {
            s_quality = is_seal ? "AdESeal" : "AdESig";
        }
        DO_JSON(json_object_set_value(joReport, "signatureQuality", json_value_init_object()));
        JSON_Object* jo_quality = json_object_get_object(joReport, "signatureQuality");
        DO_JSON(json_object_set_value(jo_quality, "signatureQualityInformation", json_value_init_array()));
        DO_JSON(json_array_append_string(json_object_get_array(jo_quality, "signatureQualityInformation"), s_quality.c_str()));
        //  "trustedList": the issuer is in a trusted list, the level is what the list confirms;
        //  "certificate": only the statements of the certificate
        DO_JSON(json_object_set_string(jo_quality, "basis", issuer_listed ? "trustedList" : "certificate"));
        if (issuer_listed) {
            DO_JSON(ParsonHelper::jsonObjectSetBoolean(jo_quality, "confirmedByTrustedList", confirmed));
            const Cert::TrustService* service = service_signed ? service_signed : service_issued;
            if (service) {
                DO_JSON(json_object_dotset_string(jo_quality, "trustService.listId", service->listId.c_str()));
                DO_JSON(json_object_dotset_string(jo_quality, "trustService.type", service->type.c_str()));
                DO_JSON(json_object_dotset_string(jo_quality, "trustService.tspName", service->tspName.c_str()));
                DO_JSON(json_object_dotset_string(jo_quality, "trustService.serviceName", service->serviceName.c_str()));
            }
        }
        DO_JSON(json_object_set_value(jo_quality, "qcStatements", json_value_init_array()));
        JSON_Array* ja_statements = json_object_get_array(jo_quality, "qcStatements");
        for (const auto& it : statement_ids) {
            DO_JSON(json_array_append_string(ja_statements, it.c_str()));
        }
    }

    //  =validationConstraintsEvaluationReport= (4.3.5)
    {
        //  signatureValidationPolicy (4.3.5.3): the name of the policy; a custom one - with the named policy it is based on
        DO_JSON(json_object_dotset_string(joReport, "validationConstraintsEvaluationReport.signatureValidationPolicy.policyName", policy.name.c_str()));
        if (policy.isCustom()) {
            DO_JSON(json_object_dotset_string(joReport, "validationConstraintsEvaluationReport.signatureValidationPolicy.basedOn", policy.basedOn.c_str()));
        }
        DO_JSON(json_object_dotset_value(joReport, "validationConstraintsEvaluationReport.validationConstraints", json_value_init_array()));
        JSON_Array* ja_constraints = json_object_dotget_array(joReport, "validationConstraintsEvaluationReport.validationConstraints");
        for (const auto& it : constraints) {
            DO(constraint_to_json(ja_constraints, it));
        }
    }

    //  What TS 119 102-2 does not define: the format, the algorithm, the claimed signing time
    DO_JSON(json_object_set_string(joReport, "signatureFormat", signatureFormatToStr(verify_info.getSignatureFormat())));
    DO_JSON(json_object_set_string(joReport, "signAlgo", signer_info.getSignatureAlgorithm().algorithm.c_str()));
    if (verify_info.getSigningTime() > 0) {
        DO_JSON(json_object_set_string(joReport, "signingTime", TimeUtil::mtimeToFtime(verify_info.getSigningTime()).c_str()));
    }

    //  The time-stamps of the signature: objects with their own validation, referenced from here
    {
        DO_JSON(json_object_set_value(joReport, "timeStamps", json_value_init_array()));
        JSON_Array* ja_timestamps = json_object_get_array(joReport, "timeStamps");
        const auto add_timestamp = [&](const char* kind, const size_t number, const Doc::Verify::AttrTimeStamp& attr_ts) -> int {
            if (!attr_ts.isPresent() && !attr_ts.parseFailed) return RET_OK;
            const string s_id = timestamp_id(idxSigner, kind, number);
            const int r = timestamp_object_to_json(jaObjects, s_id, attr_ts.isV2 ? "ARCHIVE-V2" : kind, attr_ts);
            if (r != RET_OK) return r;
            return (json_array_append_string(ja_timestamps, s_id.c_str()) == JSONSuccess) ? RET_OK : RET_UAPKI_JSON_FAILURE;
        };
        DO(add_timestamp("CONTENT", 0, verify_info.getContentTS()));
        DO(add_timestamp("SIGNATURE", 0, verify_info.getSignatureTS()));
        DO(add_timestamp("ARCHIVE", 0, verify_info.getArchiveTS()));
        size_t number = 1;
        for (const auto& it : verify_info.getArchiveTSsNext()) {
            DO(add_timestamp("ARCHIVE", number++, *it));
        }
    }

    //  The certificates used, with the revocation data of each: the same form as certificateChain of the other types
    {
        DO_JSON(json_object_set_value(joReport, "certificates", json_value_init_array()));
        JSON_Array* ja_certs = json_object_get_array(joReport, "certificates");
        for (const auto& it : verify_info.getCertChainItems()) {
            DO_JSON(json_array_append_value(ja_certs, json_value_init_object()));
            DO(Doc::Verify::certChainItemToJson(
                json_array_get_object(ja_certs, json_array_get_count(ja_certs) - 1), *it, verify_options, verify_info.getBestSignatureTime()
            ));

            //  =signatureValidationObjects=: every certificate once
            const string s_id = ba_to_base64_string(it->getSubjectCertId());
            if (objectIds.insert(s_id).second) {
                DO_JSON(json_array_append_value(jaObjects, json_value_init_object()));
                JSON_Object* jo_object = json_array_get_object(jaObjects, json_array_get_count(jaObjects) - 1);
                DO_JSON(json_object_set_string(jo_object, "id", s_id.c_str()));
                DO_JSON(json_object_set_string(jo_object, "objectType", "certificate"));
                DO_JSON(json_object_set_string(jo_object, "CN", it->getCommonName().c_str()));
                DO(Cert::validityToJson(jo_object, it->getSubject()));
                DO_JSON(ParsonHelper::jsonObjectSetBoolean(jo_object, "selfSigned", it->isSelfSigned()));
                DO_JSON(ParsonHelper::jsonObjectSetBoolean(jo_object, "trusted", it->isTrusted()));
                if (it->getIssuerCertId()) {
                    DO(json_object_set_base64(jo_object, "issuerCertId", it->getIssuerCertId()));
                }
                //  The signer of revocation data whose own status was not looked for: why
                if (
                    ((it->getCertEntity() == CertValidator::CertEntity::OCSP) || (it->getCertEntity() == CertValidator::CertEntity::CRL)) &&
                    !it->isSelfSigned()
                ) {
                    const Cert::CerItem* cer_subject = it->getSubject();
                    const char* type_mark = (it->getCertEntity() == CertValidator::CertEntity::OCSP) ? "OCSP" : "CRL";
                    const uint64_t status_time = verify_info.getTimeOfStatusData(it->getCertEntity(), cer_subject);
                    if (cer_subject->hasOcspNoCheckExtension()) {
                        DO_JSON(json_object_set_string(jo_object, "revocationNotChecked", "ocspNoCheck"));
                    }
                    else if (cer_subject->isNoRevocationCheck()) {
                        DO_JSON(json_object_set_string(jo_object, "revocationNotChecked", "noRevocationAvailable"));
                    }
                    else if (
                        (it->getValidationType() == Cert::ValidationType::NONE) &&
                        listed_service(cer_subject->getTrustServices(), type_mark, (status_time > 0) ? status_time : verify_info.getBestSignatureTime())
                    ) {
                        DO_JSON(json_object_set_string(jo_object, "revocationNotChecked", "trustedList"));
                    }
                }
            }
        }
    }

    if (!verify_info.getExpectedCerts().empty()) {
        DO_JSON(json_object_set_value(joReport, "expectedCerts", json_value_init_array()));
        JSON_Array* ja_items = json_object_get_array(joReport, "expectedCerts");
        size_t idx = 0;
        for (const auto& it : verify_info.getExpectedCerts()) {
            DO_JSON(json_array_append_value(ja_items, json_value_init_object()));
            DO(CertValidator::expectedCertItemToJson(json_array_get_object(ja_items, idx++), *it));
        }
    }
    if (!verify_info.getExpectedCrls().empty()) {
        DO_JSON(json_object_set_value(joReport, "expectedCrls", json_value_init_array()));
        JSON_Array* ja_items = json_object_get_array(joReport, "expectedCrls");
        size_t idx = 0;
        for (const auto& it : verify_info.getExpectedCrls()) {
            DO_JSON(json_array_append_value(ja_items, json_value_init_object()));
            DO(CertValidator::expectedCrlItemToJson(json_array_get_object(ja_items, idx++), *it));
        }
    }

    //  The attributes of the signature (4.3.8), as they are
    DO(Doc::Verify::attributesToJson(joReport, "signedAttributes", signer_info.getSignedAttrs()));
    DO(Doc::Verify::attributesToJson(joReport, "unsignedAttributes", signer_info.getUnsignedAttrs()));

cleanup:
    return ret;
}

}   //  end namespace


int UapkiNS::Doc::Verify::etsiReportToJson (
        JSON_Object* joResult,
        Doc::Verify::VerifySignedDoc& verifySdoc,
        const bool returnContent
)
{
    int ret = RET_OK;
    set<string> object_ids;
    JSON_Array* ja_objects = nullptr;
    JSON_Array* ja_reports = nullptr;

    {   //  =content=
        const Pkcs7::EncapsulatedContentInfo& encap_cinfo = verifySdoc.sdataParser.getEncapContentInfo();
        DO_JSON(json_object_set_value(joResult, "content", json_value_init_object()));
        JSON_Object* jo_content = json_object_get_object(joResult, "content");
        DO_JSON(json_object_set_string(jo_content, "type", encap_cinfo.contentType.c_str()));
        if (returnContent && encap_cinfo.baEncapContent) {
            DO(json_object_set_base64(jo_content, "bytes", encap_cinfo.baEncapContent));
        }
    }

    DO_JSON(json_object_set_value(joResult, "signatureValidationReports", json_value_init_array()));
    ja_reports = json_object_get_array(joResult, "signatureValidationReports");
    DO_JSON(json_object_set_value(joResult, "signatureValidationObjects", json_value_init_array()));
    ja_objects = json_object_get_array(joResult, "signatureValidationObjects");

    for (size_t idx = 0; idx < verifySdoc.verifiedSignerInfos.size(); idx++) {
        //  Only the signatures that were asked to be validated
        if (
            (verifySdoc.verifyOptions.verifySignerInfoIndex >= 0) &&
            (verifySdoc.verifyOptions.verifySignerInfoIndex != (int)idx)
        ) continue;
        DO_JSON(json_array_append_value(ja_reports, json_value_init_object()));
        DO(signature_report_to_json(
            json_array_get_object(ja_reports, json_array_get_count(ja_reports) - 1), ja_objects, object_ids, verifySdoc, idx
        ));
    }

cleanup:
    return ret;
}
