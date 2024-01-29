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

#ifndef DOC_VERIFY_H
#define DOC_VERIFY_H

#include "uapki-ns.h"
#include "archive-timestamp-helper.h"
#include "cer-store.h"
#include "cert-validator.h"
#include "content-hasher.h"
#include "crl-store.h"
#include "ocsp-helper.h"
#include "signature-format.h"
#include "signeddata-helper.h"
#include "tsp-helper.h"
#include "verify-status.h"


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

    AttrTimeStamp (void);
    ~AttrTimeStamp (void);

    bool isPresent (void) const;
    int parse (
        const ByteArray* baEncoded
    );
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


struct VerifyOptions {
    enum class ValidationType : uint32_t {
        UNDEFINED   = 0,
        STRUCT      = 1,
        CHAIN       = 2,
        FULL        = 3
    };  //  end enum ValidationType

    ValidationType
                validationType;
    bool        onlyCrl;
    int         verifySignerInfoIndex;

    VerifyOptions (void)
        : validationType(ValidationType::UNDEFINED)
        , onlyCrl(false)
        , verifySignerInfoIndex(-1)
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
    AttrTimeStamp
                m_ContentTS;
    AttrTimeStamp
                m_SignatureTS;
    CadesXlInfo m_CadesXlInfo;
    AttrTimeStamp
                m_ArchiveTS;
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
    int addCrlCertsToChain (
        const uint64_t validateTime
    );
    int addOcspCertsToChain (
        const uint64_t validateTime
    );
    int buildCertChain (void);
    int certValuesToStore (void);
    void determineSignFormat (void);
    const char* getValidationStatus (void) const;
    std::vector<std::string> getWarningMessages (void) const;
    int parseAttributes (void);
    int setRevocationValuesForChain (
        const uint64_t validateTime
    );
    void validateSignFormat (
        const uint64_t validateTime,
        const bool contentIsPresent
    );
    void validateStatusCerts (void);
    void validateValidityTimeCerts (
        const uint64_t validateTime
    );
    int verifyArchiveTimeStamp (
        const std::vector<Cert::CerItem*>& certs,
        const std::vector<Crl::CrlItem*>& crls
    );
    int verifyCertificateRefs (void);
    int verifyContentTimeStamp (
        ContentHasher& contentHasher
    );
    int verifyMessageDigest (
        ContentHasher& contentHasher
    );
    int verifyOcspResponse (
        Ocsp::OcspHelper& ocspClient,
        ResultValidationByOcsp& resultValByOcsp
    );
    int verifySignatureTimeStamp (void);
    int verifySignedAttribute (void);
    int verifySigningCertificateV2 (void);

public:
    const AttrTimeStamp& getArchiveTS (void) const {
        return m_ArchiveTS;
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
