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
                crlItem;        //  the last one used: delta, if used, else full
    Crl::CrlItem*
                crlFull;        //  the full CRL
    Cert::CerItem*
                cerIssuer;
    Crl::RevokedCertItem
                revokedCertItem;
    //  "Not revoked" by a CRL issued after the certificate expired is not proven (see revocationCoversCert)
    bool        issuedAfterExpiration;
    //  Not revoked at the time of the validation, revoked later (the CRL is newer): the entry, see tsaKeyTrust()
    bool        hasRevokedLater;
    Crl::RevokedCertItem
                revokedLater;

    ResultValidationByCrl (void)
        : certStatus(CertStatus::UNDEFINED)
        , crlItem(nullptr)
        , crlFull(nullptr)
        , cerIssuer(nullptr)
        , issuedAfterExpiration(false)
        , hasRevokedLater(false)
    {}

};  //  end struct ResultValidationByCrl

struct OcspResponseInfo {
    Ocsp::ResponseStatus
                responseStatus;
    Ocsp::ResponderIdType
                responderIdType;
    SmartBA     baResponderId;
    uint64_t    msProducedAt;
    Ocsp::OcspHelper::SingleResponseInfo
                singleResponseInfo;
    SignatureVerifyStatus
                statusSignature;
    Cert::CerItem*
                cerResponder;
    std::string signAlgo;       //  the signature algorithm of the response (OID)

    OcspResponseInfo (void)
        : responseStatus(Ocsp::ResponseStatus::UNDEFINED)
        , responderIdType(Ocsp::ResponderIdType::UNDEFINED)
        , msProducedAt(0)
        , statusSignature(SignatureVerifyStatus::UNDEFINED)
        , cerResponder(nullptr)
    {}

};  //  end struct OcspResponseInfo

struct ResultValidationByOcsp : public OcspResponseInfo {
    Ocsp::OcspHelper::SingleResponseInfo
                singleResponseInfo;
    SmartBA     basicOcspResponse;
    SmartBA     ocspIdentifier;
    //  For sign
    SmartBA     ocspResponse;
    //  For verify
    DataSource  dataSource;
    //  "Good" by a response issued after the certificate expired is not proven (see revocationCoversCert)
    bool        issuedAfterExpiration;

    ResultValidationByOcsp (void)
        : dataSource(DataSource::UNDEFINED)
        , issuedAfterExpiration(false)
    {}

};  //  end struct ResultValidationByOcsp

class CertChainItem;

//  The time-stamps of a TSA whose certificate is revoked (RFC 3161, 4): revoked for a reason that is not a compromise
//  (affiliationChanged, superseded, cessationOfOperation...) - the ones made before the revocation stay valid, that
//  is told by the status at their time; revoked for the compromise of a key, or with no reason given - none of
//  them can be trusted, whenever the certificate was revoked
enum class TsaKeyTrust {
    OK,
    COMPROMISED,
    REASON_NOT_GIVEN
};

TsaKeyTrust tsaKeyTrust (
    const CertChainItem& tsaItem
);


class CertChainItem {
    CertEntity  m_CertEntity;
    Cert::CerItem*
                m_CerSubject;
    DataSource  m_DataSource;
    std::string m_CommonName;
    Cert::CerItem*
                m_CerIssuer;
    bool        m_Trusted;
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
    //  The certificate is a trust anchor itself though it is not a CA at the top of a path (a TSA or an OCSP
    //  responder of a trusted list, a certificate given to INIT as trusted): no issuer and no revocation status are
    //  looked for (RFC 5280, 6.1); the entity stays what it is
    void setTrustAnchor (void);
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
    //  Trusted at the time the chain was built for (buildCertChain); an item made apart from a chain - now
    bool isTrusted (void) const {
        return m_Trusted;
    }
    void setTrustAt (const bool trusted) {
        m_Trusted = trusted;
    }
    void addTrust (const bool trusted) {
        m_Trusted = m_Trusted || trusted;
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
    bool        m_CheckTrustedRoot;
    bool        m_CaRemovesExpiredCerts;
    uint64_t    m_RevocationMinThisUpdate;
    uint64_t    m_StrictFreshnessTime;

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
    //  getStatus(): the root of the chain must be trusted (signing: options.checkTrustedRoot)
    void setCheckTrustedRoot (
        const bool checkTrustedRoot
    );
    //  The CAs remove the expired certificates from the revocation data (VERIFY: caRemovesExpiredCerts)
    void setCaRemovesExpiredCerts (
        const bool caRemovesExpiredCerts
    );

    bool getCheckTrustedRoot (void) const {
        return m_CheckTrustedRoot;
    }
    bool getCaRemovesExpiredCerts (void) const {
        return m_CaRemovesExpiredCerts;
    }
    //  The revocation data from the cache (OCSP) or the CRL store issued before this time is obtained again
    //  (AUGMENT_CMS: revocationFreshness); 0 - no requirement
    void setRevocationMinThisUpdate (
        const uint64_t revocationMinThisUpdate
    ) {
        m_RevocationMinThisUpdate = revocationMinThisUpdate;
    }
    //  The strict freshness of a validation policy: the status must be issued after this time. A cached OCSP
    //  response issued before it is asked again (it has no nextUpdate as a rule: nothing to wait for); a CRL
    //  issued before it is used up to its nextUpdate (the same CRL would come) and downloaded again after it.
    //  0 - no requirement
    void setStrictFreshnessTime (
        const uint64_t strictFreshnessTime
    ) {
        m_StrictFreshnessTime = strictFreshnessTime;
    }
    uint64_t getRevocationMinThisUpdate (void) const {
        return m_RevocationMinThisUpdate;
    }
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
    //  The expected CRLs added after the first count removed (an attempt that does not count)
    void truncateExpectedCrls (
        const size_t count
    ) {
        while (m_ExpectedCrls.size() > count) {
            delete m_ExpectedCrls.back();
            m_ExpectedCrls.pop_back();
        }
    }
    const std::vector<CertChainItem*>& getObtainedCerts (void) const {
        return m_ObtainedCerts;
    }
    Cert::ValidationType getValidationType (void) const {
        return m_ValidationType;
    }

public:
    //  Before signing: the chain of cerItem, its validity, status (OCSP or CRL) and usage
    int getStatus (
        Cert::CerItem* cerItem,
        const CertEntity certEntity,
        const uint64_t validateTime
    );

    //  The one chain builder for signing and verifying: the item of cerItem and its issuers up to
    //  a self-signed root are added to chainItems (an item already there is reused), each link is
    //  verified, the root is marked. A missing issuer is expected: RET_UAPKI_CERT_ISSUER_NOT_FOUND.
    //  msTrustTime - the time the trust is decided at (0 - now): the chain ends at the first certificate trusted
    //  then, see Cert::CerItem::isTrustedAt()
    int buildCertChain (
        const CertEntity certEntity,
        Cert::CerItem* cerItem,
        std::vector<CertChainItem*>& chainItems,
        CertChainItem** subjectItem = nullptr,
        const uint64_t msTrustTime = 0
    );
    int addChainItem (
        std::vector<CertChainItem*>& chainItems,
        const CertEntity certEntity,
        Cert::CerItem* cerItem,
        CertChainItem** chainItem,
        bool& isNewItem
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
    //  One check of an OCSP response for all callers (sign, VERIFY_CERT, VERIFY online and embedded):
    //  the SingleResponse about baSerialNumber of cerIssuer, the responder signature and its authority.
    //  The certificates of the response are added to the store (and to addedCerts)
    //  The one way a CRL gets into the cache (ADD_CRL, a download): signed by its issuer
    //  (verifyCrlIssuer), and if it is for cerSubject - by the key that signed cerSubject
    int addCrlToStore (
        Crl::CrlStore& crlStore,
        Cert::CerStore& cerStore,
        const ByteArray* baEncoded,
        const bool permanent,
        const Cert::CerItem* cerSubject,
        bool& isUnique,
        Crl::CrlItem** crlItem
    );
    //  The CRL is signed by the certificate of its issuer (name, key id) having cRLSign
    int verifyCrlIssuer (
        Crl::CrlItem& crlItem,
        Cert::CerStore& cerStore,
        Cert::CerItem** cerCrlSigner
    );
    //  The CRL is signed by the issuer of cerSubject (same name and key) having cRLSign
    int verifyCrlSigner (
        Crl::CrlItem& crlItem,
        const Cert::CerItem* cerSubject,
        Cert::CerStore& cerStore,
        Cert::CerItem** cerCrlSigner
    );
    int processResponseData (
        Ocsp::OcspHelper& ocspHelper,
        const ByteArray* baSerialNumber,
        Cert::CerItem* cerIssuer,
        ResultValidationByOcsp& resultValidation,
        std::vector<Cert::CerItem*>* addedCerts = nullptr,
        JSON_Object* joResult = nullptr
    );
    int verifyResponseData (
        Ocsp::OcspHelper& ocspHelper,
        Cert::CerItem* cerIssuer,
        ResultValidationByOcsp& resultValidation,
        JSON_Object* joResult = nullptr
    );
    //  Public key from SubjectPublicKeyInfo: the content of subjectPublicKey without the unused-bits octet
    static int publicKeyFromSpki (
        const ByteArray* baSpki,
        ByteArray** baPublicKey
    );
    //  RFC 6960, 4.2.2.2: the issuer itself or a certificate issued by it with id-kp-OCSPSigning
    int authorizeOcspResponder (
        Cert::CerItem* cerResponder,
        Cert::CerItem* cerIssuer,
        const uint64_t producedAt
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

//  The constraints a certificate of a built chain breaks (the first one)
enum class ChainConstraint : uint32_t {
    NONE                        = 0,
    ISSUER_NOT_CA               = 1,    //  RFC 5280, 6.1.4 (k): basicConstraints cA of an issuer
    PATH_LENGTH                 = 2,    //  RFC 5280, 6.1.4 (l), (m): pathLenConstraint
    SIGNER_KEY_USAGE            = 3,    //  RFC 5280, 4.2.1.3: digitalSignature or nonRepudiation
    TSP_KEY_PURPOSE             = 4,    //  RFC 3161, 2.3: id-kp-timeStamping
    UNKNOWN_CRITICAL_EXTENSION  = 5,    //  RFC 5280, 4.2 (the check is optional)
    FORBIDDEN_EXTENSION         = 6     //  as EU DSS: ocsp-nocheck in a signing or TSA certificate (RFC 6960, 4.2.2.2.1),
                                        //  ocsp-nocheck or noRevAvail in a CA certificate (RFC 9608, 2)
};  //  end enum ChainConstraint

//  One check for SIGN, VERIFY_CERT and VERIFY: the certificate of chainItem and its issuers in chain
ChainConstraint checkChainConstraints (
    const CertChainItem& chainItem,
    const std::vector<CertChainItem*>& chain,
    const bool checkCriticalExtensions
);

const char* chainConstraintToStr (
    const ChainConstraint chainConstraint
);

//  Revocation data issued after the certificate expired. A CA may remove an expired certificate from its CRLs
//  (RFC 5280, 3.3) and an OCSP responder may forget it: then "not revoked" says nothing (ETSI EN 319 102-1, 5.2.6,
//  NOTE 4; 5.6.2.1, NOTE 3). By default the CAs keep the status (caRemovesExpiredCerts false: the data covers the
//  certificate). If the data says since when the expired certificates are kept - expiredCertsOnCRL (ITU-T X.509)
//  of a CRL, archiveCutoff (RFC 6960, 4.4.4) of an OCSP response - it is processed as for a CA that removes them,
//  as EU DSS: the data covers the certificate if it expired not before min(thisUpdate, that date).
//  certHash (Common PKI, 1.3.36.8.3.13) of an OCSP response is not checked: the Ukrainian QTSPs (KNEDP) do not
//  produce it. If they do, it is to be added (a matching certHash covers the certificate, as EU DSS); until then
//  the status is trusted without it
bool revocationCoversCert (
    const Cert::CerItem* cerSubject,
    const uint64_t msThisUpdate,
    const uint64_t msExpiredCertsSince,
    const bool caRemovesExpiredCerts
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
