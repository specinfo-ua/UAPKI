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

#ifndef DOC_VERIFY_H
#define DOC_VERIFY_H

#include "uapki-ns.h"
#include "archive-timestamp-helper.h"
#include "cer-store.h"
#include "crl-store.h"
#include "signature-format.h"
#include "signeddata-helper.h"
#include "tsp-helper.h"
#include "verify-status.h"


namespace UapkiNS {

namespace Doc {

namespace Verify {

enum class CertEntity : uint32_t {
    UNDEFINED       = 0,
    SIGNER          = 1,
    INTERMEDIATE    = 2,
    CRL             = 3,
    OCSP            = 4,
    TSP             = 5,
    CA              = 6,
    ROOT            = 7
};  //  end enum CertEntity

enum class CertSource : uint32_t {
    UNDEFINED       = 0,
    SIGNATURE       = 1,
    STORE           = 2
};  //  end enum CertSource

enum class ValidationStatus : uint32_t {
    UNDEFINED       = 0,
    INDETERMINATE   = 1,
    TOTAL_FAILED    = 2,
    TOTAL_VALID     = 3
};  //  end enum ValidationStatus


struct AttrTimeStamp {
    Tsp::TsTokenParser
                tsTokenParser;
    std::string policy;
    std::string hashAlgo;
    SmartBA     hashedMessage;
    uint64_t    msGenTime;
    CerStore::Item*
                csiSigner;
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
        const ByteArray* baData,
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
    std::vector<CerStore::Item*>
                addedCerts;
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
        CerStore* cerStore
    );

};  //  end struct CadesXlInfo


class CertChainItem {
    const CertEntity
                m_CertEntity;
    CerStore::Item*
                m_CsiSubject;
    CertSource  m_CertSource;
    std::string m_CommonName;
    CerStore::Item*
                m_CsiIssuer;
    bool        m_IsExpired;
    bool        m_IsSelfSigned;
    UapkiNS::CertStatus
                m_CertStatus;
    SmartBA     m_OcspResponse;

public:
    CertChainItem (
        const CertEntity iCertEntity,
        CerStore::Item* iCsiSubject
    );
    ~CertChainItem (void);

public:
    int checkValidityTime (
        const uint64_t validateTime
    );
    int decodeName (void);
    int decodeOcspResponse (
        const ByteArray* baOcspResponse
    );
    void setCertSource (
        const CertSource certSource
    );
    void setCertStatus (const UapkiNS::CertStatus certStatus);
    void setIssuerAndVerify (
        CerStore::Item* csiIssuer,
        const bool isSelfSigned
    );

public:
    CertEntity getCertEntity (void) const {
        return m_CertEntity;
    }
    CertSource getCertSource (void) const {
        return m_CertSource;
    }
    UapkiNS::CertStatus getCertStatus (void) const {
        return m_CertStatus;
    }
    const std::string& getCommonName (void) const {
        return m_CommonName;
    }
    CerStore::Item* getIssuer (void) const {
        return m_CsiIssuer;
    }
    const ByteArray* getIssuerCertId (void) const {
        return (m_CsiIssuer) ? m_CsiIssuer->baCertId : nullptr;
    }
    CerStore::Item* getSubject (void) const {
        return m_CsiSubject;
    }
    const ByteArray* getSubjectCertId (void) const {
        return (m_CsiSubject) ? m_CsiSubject->baCertId : nullptr;
    }
    CerStore::VerifyStatus getVerifyStatus (void) const {
        return (m_CsiSubject) ? m_CsiSubject->verifyStatus : CerStore::VerifyStatus::UNDEFINED;
    }
    bool isExpired (void) const {
        return m_IsExpired;
    }
    bool isSelfSigned (void) const {
        return m_IsSelfSigned;
    }
    bool isTrusted (void) const {
        return (m_CsiSubject) ? m_CsiSubject->trusted : false;
    }

};  //  end class CertChainItem


class ExpectedCertItem {
public:
    enum class IdType : uint32_t {
        UNDEFINED = 0,
        CER_IDTYPE,
        ORS_IDTYPE  //  Warning: OCSP_RESPONSE - clash with wincrypt.h
    };  //  end enum IdType

private:
    const CertEntity
                m_CertEntity;
    IdType      m_IdType;
    SmartBA     m_KeyId;
    SmartBA     m_Name;
    SmartBA     m_SerialNumber;

public:
    ExpectedCertItem (
        const CertEntity iCertEntity
    );
    ~ExpectedCertItem (void);

public:
    int setResponderId (
        const bool isKeyId,
        const ByteArray* baNameEncoded
    );
    int setSignerIdentifier (
        const ByteArray* baKeyIdOrSN,
        const ByteArray* baName
    );

public:
    CertEntity getCertEntity (void) const {
        return m_CertEntity;
    }
    IdType getIdType (void) const {
        return m_IdType;
    }
    const ByteArray* getKeyId (void) const {
        return m_KeyId.get();
    }
    const ByteArray* getName (void) const {
        return m_Name.get();
    }
    const ByteArray* getSerialNumber (void) const {
        return m_SerialNumber.get();
    }

};  //  end class ExpectedCertItem


class VerifiedSignerInfo {
    CerStore*   m_CerStore;
    bool        m_IsDigest;
    int         m_LastError;
    Pkcs7::SignedDataParser::SignerInfo
                m_SignerInfo;
    CerStore::Item*
                m_CsiSigner;
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
    std::vector<ExpectedCertItem*>
                m_ExpectedCertItems;
    std::vector<CerStore::Item*>
                m_AddedCerts;

public:
    VerifiedSignerInfo (void);
    ~VerifiedSignerInfo (void);

    int init (
        CerStore* iCerStore,
        const bool isDigest
    );
    int addCertValidationItem (
        const CertEntity certEntity,
        CerStore::Item* cerStoreItem
    );
    int addExpectedCertItem (
        const CertEntity certEntity,
        const ByteArray* baSidEncoded
    );
    int certValuesToStore (void);
    void determineSignatureFormat (void);
    const char* getValidationStatus (void) const;
    int parseAttributes (void);
    int validateStatuses (void);
    int verifyArchiveTS (
        const std::vector<CerStore::Item*>& certs,
        const std::vector<CrlStore::Item*>& crls
    );
    int verifyCertificateRefs (void);
    int verifyContentTS (
        const ByteArray* baContent
    );
    int verifyMessageDigest (
        const ByteArray* baContent
    );
    int verifySignatureTS (void);
    int verifySignedAttribute (void);
    int verifySigningCertificateV2 (void);

public:
    const std::vector<CerStore::Item*>& getAddedCerts (void) const {
        return m_AddedCerts;
    }
    const AttrTimeStamp& getArchiveTS (void) const {
        return m_ArchiveTS;
    }
    uint64_t getBestSignatureTime (void) const {
        return m_BestSignatureTime;
    }
    CadesXlInfo& getCadesXlInfo (void) {
        return m_CadesXlInfo;
    }
    CerStore* getCerStore (void) const {
        return m_CerStore;
    }
    const std::vector<CertChainItem*> getCertChainItems (void) const {
        return m_CertChainItems;
    }
    const std::vector<CerStore::Item*>& getCertValues (void) const {
        return m_CadesXlInfo.addedCerts;
    }
    const AttrTimeStamp& getContentTS (void) const {
        return m_ContentTS;
    }
    const std::vector<ExpectedCertItem*> getExpectedCertItems (void) const {
        return m_ExpectedCertItems;
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
        return (m_CsiSigner) ? m_CsiSigner->baCertId : nullptr;
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

struct VerifyOptions {
    CerStore::ValidationType
                validationType;
    uint64_t    validateTime;
    //  options
    bool        forceOcsp;
    bool        offlineCrl;

    VerifyOptions (void)
        : validationType(CerStore::ValidationType::UNDEFINED)
        , validateTime(0)
        , forceOcsp(false)
        , offlineCrl(false) {
    }

};  //  end struct VerifyOptions

struct VerifySignedDoc {
    CerStore*   cerStore;
    CrlStore*   crlStore;
    const UapkiNS::Doc::Verify::VerifyOptions&
                verifyOptions;
    UapkiNS::Pkcs7::SignedDataParser
                sdataParser;
    const ByteArray*
                refContent;
    std::vector<CerStore::Item*>
                addedCerts;
    std::vector<CrlStore::Item*>
                addedCrls;
    std::vector<UapkiNS::Doc::Verify::VerifiedSignerInfo>
                verifiedSignerInfos;

    VerifySignedDoc (
        CerStore* iCerStore,
        CrlStore* iCrlStore,
        const UapkiNS::Doc::Verify::VerifyOptions& iVerifyOptions
    );
    ~VerifySignedDoc (void);

    int parse (const ByteArray* baSignature);
    void getContent (const ByteArray* baContent);
    int addCertsToStore (void);
    void detectCertSources (void);
    int getLastError (void);

};  //  end struct VerifyOptions


const char* certEntityToStr (
    const CertEntity certEntity
);

const char* certSourceToStr (
    const CertSource certSource
);

const char* validationStatusToStr (
    const ValidationStatus status
);


}   //  end namespace Verify

}   //  end namespace Doc

}   //  end namespace UapkiNS


#endif
