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

#ifndef DOC_VERIFY_H
#define DOC_VERIFY_H

#include "uapki-ns.h"
#include "archive-timestamp-helper.h"
#include "archive-timestamp-v3.h"
#include <memory>
#include "cer-store.h"
#include "cert-validator.h"
#include "content-hasher.h"
#include "crl-store.h"
#include "ocsp-helper.h"
#include "signature-format.h"
#include "signeddata-helper.h"
#include "tsp-helper.h"
#include "verify-status.h"
#include "parson.h"


namespace UapkiNS {

namespace Doc {

namespace Verify {

using CertChainItem = CertValidator::CertChainItem;
using CertEntity = CertValidator::CertEntity;
using DataSource = CertValidator::DataSource;
using ExpectedCertItem = CertValidator::ExpectedCertItem;
using ExpectedCrlItem = CertValidator::ExpectedCrlItem;
using ResultValidationByCrl = CertValidator::ResultValidationByCrl;
using ResultValidationByOcsp = CertValidator::ResultValidationByOcsp;

enum class ValidationStatus : uint32_t {
    UNDEFINED       = 0,
    INDETERMINATE   = 1,
    TOTAL_FAILED    = 2,
    TOTAL_VALID     = 3
};  //  end enum ValidationStatus


struct AttrTimeStamp {
    Tsp::TsTokenParser
                tsTokenParser;
    Pkcs7::SignedDataParser::SignerInfo
                signerInfo;
    std::string policy;
    std::string hashAlgo;
    SmartBA     hashedMessage;
    uint64_t    msGenTime;
    Cert::CerItem*
                cerSigner;
    DigestVerifyStatus
                statusDigest;
    SignatureVerifyStatus
                statusSignature;
    //  The attribute value is not a time-stamp token that can be parsed: the time-stamp is as if absent
    bool        parseFailed;
    //  An archive-time-stamp-v3 without a hash index in its token: it cannot be validated
    bool        noHashIndex;
    //  archive-time-stamp of TS 101 733, 6.4.1 (id-aa-ets-archiveTimestampV2), not archive-time-stamp-v3
    bool        isV2;
    //  The position of the attribute in unsignedAttrs
    size_t      attrIndex;

    AttrTimeStamp (void);
    ~AttrTimeStamp (void);

    bool isPresent (void) const;
    //  ats-hash-index-v3 (ATSHashIndexV3) of an archive-time-stamp-v3 (EN 319 122-1, 5.5.2), nullptr if absent
    const ByteArray* getAtsHashIndexV3 (void) const;
    //  The hash index of an archive-time-stamp-v3 in its token: ats-hash-index-v3 (EN 319 122-1) or
    //  ats-hash-index (TS 101 733), nullptr if absent
    const ByteArray* getAtsHashIndex (
        Pkcs7::AtsV3::IndexType& indexType
    ) const;
    int parse (
        const ByteArray* baEncoded
    );
    //  TSTInfo is the content the TSA signed (its hash is the messageDigest of the token)
    int verifyTstInfo (void);
    int verifyDigest (
        ContentHasher& contentHasher,
        const bool isDigest = false
    );

};  //  end struct AttrTimeStamp


struct CadesXlInfo {
    bool        isPresentCertRefs;
    bool        isPresentRevocRefs;
    bool        isPresentCertVals;
    bool        isPresentRevocVals;
    std::vector<OtherCertId>
                certRefs;
    VectorBA    certValues;
    AttributeHelper::RevocationRefsParser
                revocationRefsParser;
    AttributeHelper::RevocationValuesParser
                revocationValuesParser;
    VectorBA    expectedCertsByIssuerAndSN;
    DigestVerifyStatus
                statusCertRefs;
    DigestVerifyStatus
                statusRevocationRefs;   //  complete-revocation-references against the CRLs and OCSP responses known
    std::vector<DigestVerifyStatus>
                statusesCertRefs;

    CadesXlInfo (void);

    bool isPresentCadesC (void) const {
        return (isPresentCertRefs && isPresentRevocRefs);
    }
    bool isPresentCadesXL (void) const {
        return (isPresentCertVals && isPresentRevocVals);
    }
    int parseCertValues (
        const ByteArray* baValues
    );
    int parseCertificateRefs (
        const ByteArray* baValues
    );
    int parseRevocationRefs (
        const ByteArray* baValues
    );
    int parseRevocationValues (
        const ByteArray* baValues
    );
    int verifyCertRefs (
        Cert::CerStore* cerStore
    );

};  //  end struct CadesXlInfo


//  The validation policy of the validation type FULL-ETSI: the constraints the library can apply. A named policy
//  or the values given in the request (then the policy is "custom", based on a named one)
//  A cryptographic constraint: a hash algorithm ("SHA1"...) or a key of a family ("RSA", "EC") shorter than
//  keySizeBelow bits is reliable until msEnd. withdrawn: the algorithm is taken out of use by a decision of
//  a regulator, it is not weak - only a certificate issued after the date does not meet the constraint, a signature
//  or a time-stamp made after it gives a warning
struct CryptoRule {
    std::string algorithm;
    uint32_t    keySizeBelow;   //  0 - a hash algorithm
    uint64_t    msEnd;          //  0 - no end date
    bool        withdrawn;
};

//  The constraints of the library: ETSI TS 119 312 V1.5.1 (tables 1, 6), the end dates of the algorithms it lists
//  no more - as in its earlier versions and in ETSI TS 102 176-1; GOST 34.311 - withdrawn in Ukraine
std::vector<CryptoRule> defaultCryptoRules (void);

enum class CryptoLevel : uint32_t {
    OFF     = 0,
    WARNING = 1,
    FAIL    = 2
};

struct ValidationPolicy {
    static const char* NAME_UKRAINE_DEFAULT;
    static const char* NAME_ETSI_STRICT;
    static const char* NAME_CUSTOM;
    static const uint32_t REVOCATION_FRESHNESS_DEFAULT = 120;   //  minutes

    std::string name;
    std::string basedOn;                        //  of a custom policy
    uint32_t    revocationFreshness;            //  minutes: revocation data of the signature without nextUpdate is fresh
                                                //  if issued not earlier than this before the best signature time
    bool        tsaAdditionalKeyPurposes;       //  a TSA certificate may have key purposes besides id-kp-timeStamping
    bool        caRemovesExpiredCerts;          //  see VerifyOptions::caRemovesExpiredCerts
    bool        revocationFreshnessStrict;      //  the revocation data of every certificate must be issued
                                                //  after the best signature time (ETSI EN 319 102-1, 5.2.5, the
                                                //  maximum accepted freshness is zero), else TRY_LATER
    bool        chainModel;                     //  the past validation: the revocation of a CA certificate moves the
                                                //  control time only if the reason is a compromise or is not given
                                                //  (5.6.2.2.4, the chain model); false - the shell model
    CryptoLevel cryptoLevel;                    //  the cryptographic constraints (ETSI EN 319 102-1, 5.2.8.4.1): not
                                                //  applied, reported as warnings, or change the result
    std::vector<CryptoRule>
                cryptoRules;
    uint32_t    timeStampDelay;                 //  minutes; the claimed signing time plus the delay must be after the
                                                //  time of the signature time-stamp (ETSI EN 319 102-1, 5.5.4,
                                                //  step 5); 0 - the policy does not specify a delay
    bool        pastValidationByPoe;            //  the past validation of ETSI EN 319 102-1, 5.6: a signature is accepted
                                                //  when it is proven to have existed at the time its path can be
                                                //  validated at (the control time: the trust anchor sunset date, the
                                                //  revocation of a CA, the end of an algorithm), with the proofs of
                                                //  existence of the certificates and revocation data the path needs;
                                                //  false - an allowance of UkraineDefault: the path is validated at
                                                //  the best signature time
    bool        tsaTrustByProofOfExistence;     //  the TSA of a time-stamp must be trusted at a time proven apart from
                                                //  the time-stamp (a later time-stamp over it, else the validation
                                                //  time; ETSI EN 319 102-1, 5.2.6.4 and 5.6.2); false - an allowance
                                                //  of UkraineDefault: at the time of the time-stamp, by RFC 3161,
                                                //  section 4, items 1 and 2 - a time-stamp made before its TSA was
                                                //  taken out of service stays valid unless the key of the TSA is
                                                //  compromised or the certificate is revoked with no reason given
    bool        checkCriticalExtensions;        //  see VerifyOptions::checkCriticalExtensions; false - reported, the
                                                //  result is not changed
    bool        signerNonRepudiation;           //  the signing certificate must have the key usage nonRepudiation

    ValidationPolicy (void)
        : name(NAME_UKRAINE_DEFAULT)
        , revocationFreshness(REVOCATION_FRESHNESS_DEFAULT)
        , tsaAdditionalKeyPurposes(true)
        , caRemovesExpiredCerts(false)
        , revocationFreshnessStrict(false)
        , chainModel(false)
        , cryptoLevel(CryptoLevel::WARNING)
        , cryptoRules(defaultCryptoRules())
        , timeStampDelay(0)
        , pastValidationByPoe(false)
        , tsaTrustByProofOfExistence(false)
        , checkCriticalExtensions(false)
        , signerNonRepudiation(false)
    {}
    bool isCustom (void) const {
        return (name == NAME_CUSTOM);
    }
    //  The values of a named policy; false - there is no such policy
    bool setNamed (const std::string& policyName) {
        if (policyName == NAME_UKRAINE_DEFAULT) {
            *this = ValidationPolicy();
        }
        else if (policyName == NAME_ETSI_STRICT) {
            //  ETSI EN 319 102-1 without the allowances of UkraineDefault (the trust in a TSA at the time of its
            //  time-stamp is the one of RFC 3161, section 4; here it needs a proof of existence): an unknown critical extension makes
            //  a certificate unusable (RFC 5280, 4.2), a TSA certificate has only id-kp-timeStamping (RFC 3161, 2.3), revocation data
            //  issued after a certificate expired does not prove it was not revoked (5.2.6.4, NOTE 4)
            *this = ValidationPolicy();
            checkCriticalExtensions = true;
            tsaAdditionalKeyPurposes = false;
            caRemovesExpiredCerts = true;
            tsaTrustByProofOfExistence = true;
            pastValidationByPoe = true;
            cryptoLevel = CryptoLevel::FAIL;
        }
        else {
            return false;
        }
        name = policyName;
        return true;
    }
};  //  end struct ValidationPolicy


struct VerifyOptions {
    enum class ValidationType : uint32_t {
        UNDEFINED   = 0,
        STRUCT      = 1,
        CHAIN       = 2,
        FULL        = 3,
        FULL_ETSI   = 4     //  as FULL, the report by ETSI EN 319 102-1 and ETSI TS 119 102-2 (api/verify-etsi.cpp)
    };  //  end enum ValidationType

    ValidationType
                validationType;
    bool        onlyCrl;
    int         verifySignerInfoIndex;
    bool        checkCriticalExtensions;    //  unknown critical extensions make a certificate unusable (RFC 5280, 4.2)
    bool        caRemovesExpiredCerts;      //  the CAs remove the expired certificates from the revocation data
                                            //  (RFC 5280, 3.3), see CertValidator::revocationCoversCert()
    uint64_t    msProvidedPoe;              //  FULL-ETSI: the time the caller attests the signature with all its
                                            //  objects existed at (a proof of existence given as an input); 0 - none
    uint64_t    revocationMinThisUpdate;    //  AUGMENT_CMS: the cached/stored revocation data issued before is obtained
                                            //  again, for a signature without revocation data; 0 - no requirement
    ValidationPolicy
                policy;                     //  FULL-ETSI

    VerifyOptions (void)
        : validationType(ValidationType::UNDEFINED)
        , onlyCrl(false)
        , verifySignerInfoIndex(-1)
        , checkCriticalExtensions(false)
        , caRemovesExpiredCerts(false)
        , msProvidedPoe(0)
        , revocationMinThisUpdate(0)
    {}

};  //  end struct VerifyOptions


class VerifiedSignerInfo : public CertValidator::CertValidator {
    struct ListAddedCerts {
        std::vector<Cert::CerItem*> certValues;    //  Certs from attribute certValues
        std::vector<Cert::CerItem*> fromOnline;    //  Certs from OCSP-response
        std::vector<Cert::CerItem*> fromSignature; //  All certs from SignerInfo (including OCSP/TSP-response)
        std::vector<Cert::CerItem*> ocsp;
        std::vector<Cert::CerItem*> tsp;
    };  //  end struct ListAddedCerts

    bool        m_IsDigest;
    int         m_LastError;
    bool        m_NotProcessed;     //  the verification of this signature stopped with m_LastError
    uint32_t    m_RevocationFreshness;  //  minutes; 0 - as the library is configured (INIT: ocsp.maxFreshness)
    bool        m_TsaTrustByPoe;        //  see ValidationPolicy::tsaTrustByProofOfExistence
    bool        m_RevocationFreshnessStrict;    //  see ValidationPolicy::revocationFreshnessStrict
    Pkcs7::SignedDataParser::SignerInfo
                m_SignerInfo;
    Cert::CerItem*
                m_CerSigner;
    ValidationStatus
                m_ValidationStatus;
    SignatureVerifyStatus
                m_StatusSignature;
    DigestVerifyStatus
                m_StatusMessageDigest;
    uint64_t    m_SigningTime;
    std::vector<EssCertId>
                m_EssCerts;
    DataVerifyStatus
                m_StatusEssCert;
    std::string m_SigPolicyId;
    std::vector<std::string>
                m_ChainWarnings;
    //  The revocation data of the signature not used for a certificate (not fresh, issued after it expired):
    //  a warning only if its status is not determined from other data
    std::vector<std::pair<const CertChainItem*, std::string>>
                m_UnusedRevocationData;
    VectorBA    m_SdataCrls;            //  CRLs of SignedData.crls (baseline B-LT, ETSI EN 319 122-1)
    VectorBA    m_SdataOcspVals;        //  BasicOCSPResponse of SignedData.crls.other (RFC 5940)
    VectorBA    m_TsCrls;               //  CRLs of the validation data of the TSUs (in their time-stamp tokens)
    VectorBA    m_TsOcspVals;           //  BasicOCSPResponse of the validation data of the TSUs
    AttrTimeStamp
                m_ContentTS;
    AttrTimeStamp
                m_SignatureTS;
    CadesXlInfo m_CadesXlInfo;
    AttrTimeStamp
                m_ArchiveTS;        //  the first archive time-stamp
    std::vector<std::shared_ptr<AttrTimeStamp>>
                m_ArchiveTSsNext;   //  the next ones (re-archiving), in their order in the unsigned attributes
    Pkcs7::ArchiveTs3Helper
                m_ArchiveTsHelper;
    SignatureFormat
                m_SignatureFormat;
    bool        m_IsValidSignatures;
    bool        m_IsValidDigests;
    uint64_t    m_BestSignatureTime;
    std::vector<CertChainItem*>
                m_CertChainItems;
    ListAddedCerts
                m_ListAddedCerts;

public:
    VerifiedSignerInfo (void);
    ~VerifiedSignerInfo (void);

    int init (
        LibraryConfig* iLibConfig,
        Cert::CerStore* iCerStore,
        Crl::CrlStore* iCrlStore,
        const bool isDigest
    );
    int addCertChainItem (
        const CertEntity certEntity,
        Cert::CerItem* cerItem,
        CertChainItem** certChainItem
    );
    int addCertChainItem (
        const CertEntity certEntity,
        Cert::CerItem* cerItem,
        CertChainItem** certChainItem,
        bool& isNewItem
    );
    //  The issuance time of the revocation data the certificate signed: producedAt of an OCSP response
    //  (certEntity OCSP), thisUpdate of a CRL (certEntity CRL); 0 - not known. The validity period of such
    //  a certificate is checked for this time, not for the validation time (ETSI EN 319 102-1, 5.2.6.4)
    uint64_t getTimeOfStatusData (
        const CertEntity certEntity,
        const Cert::CerItem* cerItem
    ) const;
    int addSignerOfStatusToChain (
        const CertEntity certEntity,
        Cert::CerItem* cerItem,
        const uint64_t validateTime
    );
    int addCrlCertsToChain (
        const uint64_t validateTime
    );
    int addOcspCertsToChain (
        const uint64_t validateTime
    );
    int buildCertChain (void);
    int certValuesToStore (void);
    //  The CRLs of the signature (revocation-values, SignedData.crls) go to the cache the same way as ADD_CRL
    int crlValuesToStore (void);
    //  The revocation data of SignedData.crls (CRLs and OCSP responses, RFC 5940)
    int setSignedDataRevocation (
        const VectorBA& sdataCrls
    );
    //  The revocation values the signature has: attributes (TS 101 733 XL) or SignedData.crls (EN 319 122-1 B-LT)
    bool hasRevocationValues (void) const {
        return m_CadesXlInfo.isPresentCadesXL() || !m_SdataCrls.empty() || !m_SdataOcspVals.empty();
    }
    //  The attributes of the validation data of TS 101 733 (C, X-L): they are not in B-LT/B-LTA (EN 319 122-1, table 1)
    bool hasCadesXlAttributes (void) const {
        return m_CadesXlInfo.isPresentCertRefs || m_CadesXlInfo.isPresentRevocRefs ||
            m_CadesXlInfo.isPresentCertVals || m_CadesXlInfo.isPresentRevocVals;
    }
    int verifyRevocationRefs (void);
    void determineSignFormat (void);
    //  The validation data of the signature (certificates and revocation data) is enough for every certificate
    //  of the chains: signer, CAs, TSUs, OCSP responders and CRL signers without id-pkix-ocsp-nocheck
    //  (EN 319 122-1 5.5.1, table 1 o; as EU DSS). After FULL validation and detectCertSources()
    //  onlySignerPath: of the signing certificate and the CA certificates of its path (TS 101 733, 6.2.2, 6.3.4)
    bool hasCompleteValidationData (const bool onlySignerPath) const;
    //  The level by the validation data, as EU DSS: B-LT and B-LTA without the complete validation data are T,
    //  CAdES-XL and CAdES-A without the data of the path of the signer - C (with the references) or T.
    //  The data was obtained elsewhere: not a warning
    void lowerSignFormatByValidationData (void);
    const char* getValidationStatus (void) const;
    bool isTotalValid (void) const {
        return (m_ValidationStatus == ValidationStatus::TOTAL_VALID);
    }
    std::vector<std::string> getWarningMessages (void) const;
    //  The valid time-stamps that do not keep the order content - signature - archive time-stamps (ETSI
    //  EN 319 102-1, 5.5.4, step 4 e): what is before what, empty if the order is kept, see the definition
    std::vector<std::string> getTimeStampOrderFailures (void) const;
    int parseAttributes (void);
    int setRevocationValuesForChain (
        const uint64_t validateTime
    );
    int tspCertToStore ();
    int tspValidationData (
        AttrTimeStamp& attrTS
    );
    //  The certificate signed a time-stamp of the signature that is valid (digest and signature). A time-stamp
    //  that is not valid is not used (ETSI EN 319 102-1, 5.5.4 4), 5.6.3 5) d)), nor is the status of its TSA
    bool isTsaOfValidTimeStamp (
        const Cert::CerItem* cerItem
    ) const;
    //  The verification of this signature stopped with an error: the report has what was found before it.
    //  A signature value that does not verify - TOTAL-FAILED; anything the library could not process -
    //  INDETERMINATE with a remark (ETSI EN 319 102-1, 5.1.3: a status is returned for every signature)
    void setNotProcessed (
        const int errorCode
    );
    void validateSignFormat (
        const uint64_t validateTime,
        const bool contentIsPresent
    );
    void validateStatusCerts (
        const bool checkCriticalExtensions
    );
    void validateValidityTimeCerts (
        const uint64_t validateTime
    );
    //  certs - the certificates of the store added from the signature, certsEncoded - SignedData.certificates
    int verifyArchiveTimeStamp (
        const std::vector<Cert::CerItem*>& certs,
        const VectorBA& certsEncoded,
        const VectorBA& crls,
        const ContentHasher& contentHasher
    );
private:
    int verifyOneArchiveTimeStamp (
        AttrTimeStamp& archiveTS,
        const std::vector<Cert::CerItem*>& certs,
        const VectorBA& certsEncoded,
        const VectorBA& crls,
        const ContentHasher& contentHasher
    );
    //  The message imprint of an archive-time-stamp (TS 101 733, 6.4.1)
    void verifyArchiveTimeStampV2Digest (
        AttrTimeStamp& archiveTS,
        const ContentHasher& contentHasher
    );
public:
    int verifyCertificateRefs (void);
    int verifyContentTimeStamp (
        ContentHasher& contentHasher
    );
    int verifyMessageDigest (
        ContentHasher& contentHasher
    );
    int verifySignatureTimeStamp (void);
    //  signatureCerts - the certificates of the signature (a signer with the same key in other certificates)
    int verifySignedAttribute (
        const std::vector<Cert::CerItem*>& signatureCerts
    );
    int verifySigningCertificateV2 (void);
private:
    void selectSignerByKeyId (
        const std::vector<Cert::CerItem*>& signatureCerts
    );

public:
    //  The CRLs of the validation data in the time-stamp tokens of the signature
    const VectorBA& getTsCrls (void) const {
        return m_TsCrls;
    }
    const AttrTimeStamp& getArchiveTS (void) const {
        return m_ArchiveTS;
    }
    const std::vector<std::shared_ptr<AttrTimeStamp>>& getArchiveTSsNext (void) const {
        return m_ArchiveTSsNext;
    }
    uint64_t getBestSignatureTime (void) const {
        return m_BestSignatureTime;
    }
    CadesXlInfo& getCadesXlInfo (void) {
        return m_CadesXlInfo;
    }
    const std::vector<CertChainItem*>& getCertChainItems (void) const {
        return m_CertChainItems;
    }
    const AttrTimeStamp& getContentTS (void) const {
        return m_ContentTS;
    }
    const ListAddedCerts& getListAddedCerts (void) const {
        return m_ListAddedCerts;
    }
    ListAddedCerts& getListAddedCerts (void) {
        return m_ListAddedCerts;
    }
    AttributeHelper::RevocationRefsParser& getRevocationRefs (void) {
        return m_CadesXlInfo.revocationRefsParser;
    }
    const std::string& getSigPolicyId (void) const {
        return m_SigPolicyId;
    }
    SignatureFormat getSignatureFormat (void) const {
        return m_SignatureFormat;
    }
    const AttrTimeStamp& getSignatureTS (void) const {
        return m_SignatureTS;
    }
    const ByteArray* getSignerCertId (void) const {
        return (m_CerSigner) ? m_CerSigner->getCertId() : nullptr;
    }
    Pkcs7::SignedDataParser::SignerInfo& getSignerInfo (void) {
        return m_SignerInfo;
    }
    uint64_t getSigningTime (void) const {
        return m_SigningTime;
    }
    DataVerifyStatus getStatusEssCert (void) const {
        return m_StatusEssCert;
    }
    DigestVerifyStatus getStatusMessageDigest (void) const {
        return m_StatusMessageDigest;
    }
    SignatureVerifyStatus getStatusSignature (void) const {
        return m_StatusSignature;
    }
    //  FULL-ETSI: the freshness of the revocation data of the signature by the validation policy, minutes
    void setRevocationFreshnessStrict (const bool strict) {
        m_RevocationFreshnessStrict = strict;
    }
    //  An archive time-stamp covers a certificate embedded in the signature: by its hash index (the certificates of
    //  SignedData), or the signature has the certificate-values attribute; without an index - all of them
    bool archiveTimeStampCoversCert (
        const AttrTimeStamp& archiveTS,
        const Cert::CerItem* cerItem
    ) const;
    void setTsaTrustByProofOfExistence (const bool byProofOfExistence) {
        m_TsaTrustByPoe = byProofOfExistence;
    }
    void setRevocationFreshness (const uint32_t minutes) {
        m_RevocationFreshness = minutes;
    }
    //  The content was given as its hash
    bool isContentDigest (void) const {
        return m_IsDigest;
    }
    //  The verification stopped with the error getLastError(): the report has what was found before it
    bool isNotProcessed (void) const {
        return m_NotProcessed;
    }
    int getLastError (void) const {
        return m_LastError;
    }
    bool isValidDigests (void) const {
        return m_IsValidDigests;
    }
    bool isValidSignatures (void) const {
        return m_IsValidSignatures;
    }

private:
    int parseSignedAttrs (
        const std::vector<Attribute>& signedAattrs
    );
    int parseUnsignedAttrs (
        const std::vector<Attribute>& unsignedAttrs
    );
    int verifyAttrTimestamp (
        AttrTimeStamp& attrTS
    );

};  //  end class VerifiedSignerInfo


struct VerifySignedDoc {
    LibraryConfig*
                libConfig;
    Cert::CerStore*
                cerStore;
    Crl::CrlStore*
                crlStore;
    const uint64_t
                validateTime;
    const Doc::Verify::VerifyOptions&
                verifyOptions;
    Pkcs7::SignedDataParser
                sdataParser;
    ContentHasher*
                refContentHasher;
    std::vector<Cert::CerItem*>
                addedCerts;
    std::vector<Crl::CrlItem*>
                addedCrls;
    std::vector<Doc::Verify::VerifiedSignerInfo>
                verifiedSignerInfos;

    VerifySignedDoc (
        LibraryConfig* iLibConfig,
        Cert::CerStore* iCerStore,
        Crl::CrlStore* iCrlStore,
        const Doc::Verify::VerifyOptions& iVerifyOptions
    );
    ~VerifySignedDoc (void);

    bool isInitialized (void) const {
        return libConfig && cerStore && crlStore;
    }

    int parse (
        const ByteArray* baSignature
    );
    int getContent (
        ContentHasher& contentHasher
    );
    int addCertsToStore (void);
    void detectCertSources (void);
    int getLastError (void);

};  //  end struct VerifyOptions


//  VERIFY of a CMS/CAdES signature without the result in JSON (api/verify.cpp): the signers of
//  verifySdoc.verifyOptions; one code for VERIFY, AUGMENT_CMS and SIGN with CAdES-B-LT/B-LTA
int verifySignedDocument (
    VerifySignedDoc& verifySdoc,
    const ByteArray* baSignature,
    ContentHasher& contentHasher,
    const bool isDigest
);
//  The result of a signer as VERIFY (signatureInfos[]) (api/verify.cpp)
int verifiedSignerInfoToJson (
    JSON_Object* joSignInfo,
    VerifiedSignerInfo& verifyInfo,
    const VerifyOptions& verifyOptions
);
//  Parts of the result of VERIFY that have one form in every report (api/verify.cpp)
int attrTimeStampToJson (
    JSON_Object* joResult,
    const char* attrName,
    const AttrTimeStamp& attrTS
);
int attributesToJson (
    JSON_Object* joResult,
    const char* key,
    const std::vector<UapkiNS::Attribute>& attrs
);
int certChainItemToJson (
    JSON_Object* joResult,
    const CertChainItem& certChainItem,
    const VerifyOptions& verifyOptions,
    const uint64_t bestSignatureTime
);
//  The result of VERIFY with the validation type FULL-ETSI (api/verify-etsi.cpp)
int etsiReportToJson (
    JSON_Object* joResult,
    VerifySignedDoc& verifySdoc,
    const bool returnContent
);

//  OCSPResponse (successful) around a BasicOCSPResponse, DER
ByteArray* ocspResponseFromBasic (
    const ByteArray* baBasicOcspResponse
);

const char* validationStatusToStr (
    const ValidationStatus validationStatus
);

VerifyOptions::ValidationType validationTypeFromStr (
    const std::string& validationType
);


}   //  end namespace Verify

}   //  end namespace Doc

}   //  end namespace UapkiNS


#endif
