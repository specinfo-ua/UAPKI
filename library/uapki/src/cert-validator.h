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
    const bool  needOcspIdentifier;
    SmartBA     ocspIdentifier;
    //  For sign
    SmartBA     ocspResponse;
    //  For verify
    DataSource  dataSource;

    ResultValidationByOcsp (const bool iNeedOcspIdentifier = false)
        : needOcspIdentifier(iNeedOcspIdentifier)
        , dataSource(DataSource::UNDEFINED)
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
    bool        m_SelfSigned;
    Cert::ValidationType
                m_ValidationType;
    ResultValidationByCrl
                m_ResultValidationByCrl;
    ResultValidationByOcsp
                m_ResultValidationByOcsp;

public:
    CertChainItem (
        const CertEntity iCertEntity,
        Cert::CerItem* iCerSubject
    );
    ~CertChainItem (void);

public:
    bool checkValidityTime (
        const uint64_t validateTime
    );
    int decodeName (void);
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
        return m_SelfSigned;
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


class ExpectedCrlItem {
    SmartBA     m_AuthorityKeyId;
    SmartBA     m_Name;
    std::string m_Url;
    //  If present Full-CRL
    uint64_t    m_ThisUpdate;
    uint64_t    m_NextUpdate;
    SmartBA     m_BaCrlNumber;

public:
    ExpectedCrlItem (void);

public:
    int set (
        const Cert::CerItem* cerSubject,
        const Crl::CrlItem* crlFull
    );

public:
    const ByteArray* getAuthorityKeyId (void) const {
        return m_AuthorityKeyId.get();
    }
    const ByteArray* getCrlNumber (void) const {
        return m_BaCrlNumber.get();
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
        return !m_BaCrlNumber.empty();
    }

};  //  end class ExpectedCrlItem


class CertValidator {
    LibraryConfig*
                m_LibConfig;
    Cert::CerStore*
                m_CerStore;
    Crl::CrlStore*
                m_CrlStore;
    std::vector<ExpectedCertItem*>
                m_ExpectedCertItems;
    std::vector<ExpectedCrlItem*>
                m_ExpectedCrlItems;
    SmartBA     m_OcspRequest;
    SmartBA     m_OcspResponse;

public:
    CertValidator (void);
    ~CertValidator (void);

    bool init (
        LibraryConfig* iLibConfig,
        Cert::CerStore* iCerStore,
        Crl::CrlStore* iCrlStore
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
    bool isInitialized (void) const {
        return m_LibConfig && m_CerStore && m_CrlStore;
    }

    const std::vector<ExpectedCertItem*> getExpectedCertItems (void) const {
        return m_ExpectedCertItems;
    }
    const std::vector<ExpectedCrlItem*> getExpectedCrlItems (void) const {
        return m_ExpectedCrlItems;
    }
    const ByteArray* getOcspRequest (void) const {
        return m_OcspRequest.get();
    }
    const ByteArray* getOcspResponse (void) const {
        return m_OcspResponse.get();
    }

public:
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
    int addExpectedCrl (
        Cert::CerItem* cerSubject,
        Crl::CrlItem* crlFull
    );
    int addExpectedOcspCert (
        const bool isKeyId,
        const ByteArray* baResponderId
    );

    int expectedCertItemsToJson (
        JSON_Object* joResult,
        const char* keyName
    );
    int expectedCrlItemsToJson (
        JSON_Object* joResult,
        const char* keyName
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

public:
    int validateByCrl (
        Cert::CerItem* cerSubject,
        Cert::CerItem* cerIssuer,
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
    int processResponseData (
        Ocsp::OcspHelper& ocspHelper,
        Ocsp::OcspHelper::SingleResponseInfo& singleRespInfo,
        JSON_Object* joResult = nullptr
    );
    int verifyResponseData (
        Ocsp::OcspHelper& ocspHelper,
        JSON_Object* joResult = nullptr
    );
    int verifySignatureSignerInfo (
        const CertEntity certEntity,
        Pkcs7::SignedDataParser::SignerInfo& signerInfo,
        Cert::CerItem** cerSigner
    );

};  //  end class CertValidator


const char* certEntityToStr (
    const CertEntity certEntity
);

const char* dataSourceToStr (
    const DataSource dataSource
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

int getCrl (
    Crl::CrlStore& crlStore,
    const Cert::CerItem* ceriSubject,
    const Cert::CerItem* cerIssuer,
    const uint64_t validateTime,
    const ByteArray** baCrlNumber,
    Crl::CrlItem** crlItem,
    JSON_Object* joResult = nullptr
);


}   //  end namespace CertValidator

}   //  end namespace UapkiNS


#endif
