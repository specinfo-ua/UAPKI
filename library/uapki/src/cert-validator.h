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

#ifndef UAPKI_CERT_VALIDATOR_H
#define UAPKI_CERT_VALIDATOR_H


#include "uapki-ns.h"
#include "cer-store.h"
#include "crl-store.h"
#include "http-helper.h"
#include "library-config.h"
#include "ocsp-helper.h"
#include "parson.h"
#include "signeddata-helper.h"


namespace UapkiNS {

namespace CertValidator {


enum class CertEntity : uint32_t {
    UNDEFINED       = 0,
    SIGNER          = 1,
    ORIGINATOR      = 2,
    RECIPIENT       = 3,
    INTERMEDIATE    = 4,
    CRL             = 5,
    OCSP            = 6,
    TSP             = 7,
    CA              = 8,
    ROOT            = 9
};  //  end enum CertEntity

enum class DataSource : uint32_t {
    UNDEFINED   = 0,
    SIGNATURE   = 1,
    STORE       = 2
};  //  end enum DataSource

struct ResultValidationByCrl {
    CertStatus  certStatus;
    Crl::CrlItem*
                crlItem;
    Cert::CerItem*
                cerIssuer;
    Crl::RevokedCertItem
                revokedCertItem;

    ResultValidationByCrl (void)
        : certStatus(CertStatus::UNDEFINED)
        , crlItem(nullptr)
        , cerIssuer(nullptr)
    {}

};  //  end struct ResultValidationByCrl

struct ResultValidationByOcsp : public Ocsp::ResponseInfo {
    Ocsp::OcspHelper::SingleResponseInfo
                singleResponseInfo;
    SmartBA     basicOcspResponse;
    SmartBA     ocspIdentifier;
    //  For sign
    SmartBA     ocspResponse;
    //  For verify
    DataSource  dataSource;

    ResultValidationByOcsp (void)
        : dataSource(DataSource::UNDEFINED)
    {}

};  //  end struct ResultValidationByOcsp

class CertChainItem {
    CertEntity  m_CertEntity;
    Cert::CerItem*
                m_CerSubject;
    DataSource  m_DataSource;
    std::string m_CommonName;
    Cert::CerItem*
                m_CerIssuer;
    bool        m_Expired;
    Cert::ValidationType
                m_ValidationType;
    ResultValidationByCrl
                m_ResultValidationByCrl;
    ResultValidationByOcsp
                m_ResultValidationByOcsp;

public:
    CertChainItem (
        const CertEntity iCertEntity = CertEntity::UNDEFINED,
        Cert::CerItem* iCerSubject = nullptr
    );
    ~CertChainItem (void);

public:
    bool checkValidityTime (
        const uint64_t validateTime
    );
    int decodeName (void);
    void setCerItem (
        const CertEntity certEntity,
        Cert::CerItem* cerItem
    );
    void setDataSource (
        const DataSource dataSource
    );
    void setIssuer (
        Cert::CerItem* cerIssuer
    );
    void setRoot (void);
    void setValidationType (
        const Cert::ValidationType validationType
    );

public:
    CertEntity getCertEntity (void) const {
        return m_CertEntity;
    }
    const std::string& getCommonName (void) const {
        return m_CommonName;
    }
    DataSource getDataSource (void) const {
        return m_DataSource;
    }
    Cert::CerItem* getIssuer (void) const {
        return m_CerIssuer;
    }
    const ByteArray* getIssuerCertId (void) const {
        return (m_CerIssuer) ? m_CerIssuer->getCertId() : nullptr;
    }
    const ResultValidationByCrl& getResultValidationByCrl (void) const {
        return m_ResultValidationByCrl;
    }
    ResultValidationByCrl& getResultValidationByCrl (void) {
        return m_ResultValidationByCrl;
    }
    const ResultValidationByOcsp& getResultValidationByOcsp (void) const {
        return m_ResultValidationByOcsp;
    }
    ResultValidationByOcsp& getResultValidationByOcsp (void) {
        return m_ResultValidationByOcsp;
    }
    Cert::CerItem* getSubject (void) const {
        return m_CerSubject;
    }
    const ByteArray* getSubjectCertId (void) const {
        return (m_CerSubject) ? m_CerSubject->getCertId() : nullptr;
    }
    const ByteArray* getSubjectKeyId (void) const {
        return (m_CerSubject) ? m_CerSubject->getKeyId() : nullptr;
    }
    Cert::ValidationType getValidationType (void) const {
        return m_ValidationType;
    }
    Cert::VerifyStatus getVerifyStatus (void) const {
        return (m_CerSubject) ? m_CerSubject->getVerifyStatus() : Cert::VerifyStatus::UNDEFINED;
    }
    bool isExpired (void) const {
        return m_Expired;
    }
    bool isSelfSigned (void) const {
        return (m_CerSubject) ? m_CerSubject->isSelfSigned() : false;
    }
    bool isTrusted (void) const {
        return (m_CerSubject) ? m_CerSubject->isTrusted() : false;
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
    CertEntity  m_CertEntity;
    IdType      m_IdType;
    SmartBA     m_KeyId;
    SmartBA     m_IssuerName;
    SmartBA     m_SerialNumber;

public:
    ExpectedCertItem (
        const CertEntity iCertEntity
    );

public:
    int copyFrom (
        const ExpectedCertItem* item
    );
    int setResponderId (
        const bool isKeyId,
        const ByteArray* baNameEncoded
    );
    int setSignerIdentifier (
        const ByteArray* baKeyIdOrSN,
        const ByteArray* baIssuerName
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
    const ByteArray* getIssuerName (void) const {
        return m_IssuerName.get();
    }
    const ByteArray* getSerialNumber (void) const {
        return m_SerialNumber.get();
    }

};  //  end class ExpectedCertItem


class ExpectedCrlItem {
    SmartBA     m_AuthorityKeyId;
    SmartBA     m_Name;
    std::string m_Url;
    //  If present Full-CRL
    uint64_t    m_ThisUpdate;
    uint64_t    m_NextUpdate;
    SmartBA     m_CrlNumber;

public:
    ExpectedCrlItem (void);

public:
    int copyFrom (
        const ExpectedCrlItem* item
    );
    int set (
        const Cert::CerItem* cerSubject,
        const Crl::CrlItem* crlFull
    );

public:
    const ByteArray* getAuthorityKeyId (void) const {
        return m_AuthorityKeyId.get();
    }
    const ByteArray* getCrlNumber (void) const {
        return m_CrlNumber.get();
    }
    const ByteArray* getName (void) const {
        return m_Name.get();
    }
    uint64_t getNextUpdate (void) const {
        return m_NextUpdate;
    }
    uint64_t getThisUpdate (void) const {
        return m_ThisUpdate;
    }
    std::string getUrl (void) const {
        return m_Url;
    }
    bool isPresentFullCrl (void) const {
        return !m_CrlNumber.empty();
    }

};  //  end class ExpectedCrlItem


class CertValidator {
    LibraryConfig*
                m_LibConfig;
    Cert::CerStore*
                m_CerStore;
    Crl::CrlStore*
                m_CrlStore;
    Cert::ValidationType
                m_ValidationType;

    std::vector<CertChainItem*>
                m_CertChain;
    std::vector<CertChainItem*>
                m_ObtainedCerts;

    std::vector<ExpectedCertItem*>
                m_ExpectedCerts;
    std::vector<ExpectedCrlItem*>
                m_ExpectedCrls;

public:
    CertValidator (void);
    ~CertValidator (void);

    bool init (
        CertValidator& iCertValidator
    );
    bool init (
        CertValidator* iCertValidator
    );
    bool init (
        LibraryConfig* iLibConfig,
        Cert::CerStore* iCerStore,
        Crl::CrlStore* iCrlStore
    );
    void setValidationType (
        const Cert::ValidationType validationType
    );

    LibraryConfig* getLibConfig (void) const {
        return m_LibConfig;
    }
    Cert::CerStore* getCerStore (void) const {
        return m_CerStore;
    }
    Crl::CrlStore* getCrlStore (void) const {
        return m_CrlStore;
    }

    size_t getCountAllCerts (void) const {
        return m_CertChain.size() + m_ObtainedCerts.size();
    }
    const std::vector<CertChainItem*>& getCertChain (void) const {
        return m_CertChain;
    }
    const std::vector<ExpectedCertItem*>& getExpectedCerts (void) const {
        return m_ExpectedCerts;
    }
    const std::vector<ExpectedCrlItem*>& getExpectedCrls (void) const {
        return m_ExpectedCrls;
    }
    const std::vector<CertChainItem*>& getObtainedCerts (void) const {
        return m_ObtainedCerts;
    }
    Cert::ValidationType getValidationType (void) const {
        return m_ValidationType;
    }

public:
    int getStatus (
        Cert::CerItem* cerItem,
        const CertEntity certEntity,
        const uint64_t validateTime
    );

public:
    int getCertByIssuerAndSN (
        const CertEntity certEntity,
        const ByteArray* baIssuerAndSN,
        Cert::CerItem** cerItem
    );
    int getCertByKeyId (
        const CertEntity certEntity,
        const ByteArray* baKeyId,
        Cert::CerItem** cerItem
    );
    int getCertBySID (
        const CertEntity certEntity,
        const ByteArray* baSID,
        Cert::CerItem** cerItem
    );
    int getIssuerCert (
        Cert::CerItem* cerSubject,
        Cert::CerItem** cerIssuer,
        bool& isSelfSigned
    );

    int validateByCrl (
        Cert::CerItem* cerSubject,
        const uint64_t validateTime,
        const bool needUpdateCert,
        ResultValidationByCrl& resultValidation,
        JSON_Object* joResult = nullptr
    );
    int validateByOcsp (
        Cert::CerItem* cerSubject,
        Cert::CerItem* cerIssuer,
        ResultValidationByOcsp& resultValidation,
        JSON_Object* joResult = nullptr
    );

public:
    int addExpectedCert (
        const CertEntity certEntity,
        Cert::CerItem* cerItem
    );
    int addExpectedCertByIssuerAndSN (
        const CertEntity certEntity,
        const ByteArray* baIssuerAndSN
    );
    int addExpectedCertByKeyId (
        const CertEntity certEntity,
        const ByteArray* baKeyId
    );
    int addExpectedCertBySID (
        const CertEntity certEntity,
        const ByteArray* baSID
    );
    int addExpectedCerts (
        const std::vector<ExpectedCertItem*>& expectedCerts
    );
    int addExpectedCrl (
        Cert::CerItem* cerSubject,
        Crl::CrlItem* crlFull
    );
    int addExpectedCrls (
        const std::vector<ExpectedCrlItem*>& expectedCrls
    );
    int addExpectedOcspCert (
        const bool isKeyId,
        const ByteArray* baResponderId
    );

    int expectedCertsToJson (
        JSON_Object* joResult,
        const char* keyName
    );
    int expectedCrlsToJson (
        JSON_Object* joResult,
        const char* keyName
    );

    int getCrl (
        Crl::CrlStore& crlStore,
        Cert::CerStore& cerStore,
        const Cert::CerItem* cerSubject,
        const uint64_t validateTime,
        const ByteArray** baCrlNumber,
        Crl::CrlItem** crlItem,
        Cert::CerItem** cerCrlSigner,
        JSON_Object* joResult = nullptr
    );
    int processResponseData (
        Ocsp::OcspHelper& ocspHelper,
        ResultValidationByOcsp& resultValidation,
        JSON_Object* joResult = nullptr
    );
    int verifyResponseData (
        Ocsp::OcspHelper& ocspHelper,
        ResultValidationByOcsp& resultValidation,
        JSON_Object* joResult = nullptr
    );
    int verifySignatureSignerInfo (
        const CertEntity certEntity,
        Pkcs7::SignedDataParser::SignerInfo& signerInfo,
        Cert::CerItem** cerSigner
    );

};  //  end class CertValidator


int addUniqueItem (
    std::vector<Cert::CerItem*>& chainItems,
    Cert::CerItem* cerItem
);

int addUniqueItem (
    std::vector<CertChainItem*>& chainItems,
    const CertEntity certEntity,
    Cert::CerItem* cerItem
);

bool checkCertUsage (
    const CertEntity certEntity,
    const Cert::CerItem* cerItem
);

const char* certEntityToStr (
    const CertEntity certEntity
);

const char* dataSourceToStr (
    const DataSource dataSource
);

bool findItemByCertId (
    std::vector<Cert::CerItem*>& chainItems,
    Cert::CerItem* cerItem
);

bool findItemByCertId (
    std::vector<CertChainItem*>& chainItems,
    Cert::CerItem* cerItem
);

bool findItemByKeyId (
    std::vector<CertChainItem*>& chainItems,
    const ByteArray* baKeyId
);

int expectedCertItemToJson (
    JSON_Object* joResult,
    const ExpectedCertItem& expectedCertItem
);

int expectedCrlItemToJson (
    JSON_Object* joResult,
    const ExpectedCrlItem& expectedCrlItem
);

int responderIdToJson (
    JSON_Object* joResult,
    const Ocsp::ResponderIdType responderIdType,
    const ByteArray* baResponderId
);


}   //  end namespace CertValidator

}   //  end namespace UapkiNS


#endif
