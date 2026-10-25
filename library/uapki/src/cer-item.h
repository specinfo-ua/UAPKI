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

#ifndef UAPKI_CER_ITEM_H
#define UAPKI_CER_ITEM_H

#include <atomic>
#include <memory>
#include <mutex>
#include "uapkic.h"
#include "uapkif.h"
#include "attribute-helper.h"
#include "uapki-ns.h"


namespace UapkiNS {

namespace Cert {


const char* const CER_EXT       = ".cer";
constexpr size_t CER_EXT_LEN    = 4;

static const bool NOT_TRUSTED   = false;
static const bool TRUSTED       = true;

static const bool NOT_PERMANENT = false;
static const bool PERMANENT     = true;


enum class ExtKeyUsageMask : uint32_t {
    CA_PATHLEN_MASK     = 0x0003, // value: 0..3
    CA_PATHLEN          = 0x0004, // pathLen is present
    CA                  = 0x0008,
    CA_EXTN_CRITICAL    = 0x0010, // BasicConstrains-extension with critical flag
    CA_EXTN_PRESENT     = 0x0200, // BasicConstrains-extension is present
    OCSP                = 0x0020,
    OCSP_NO_CHECK       = 0x0040,
    TSP                 = 0x0080,
    CMP                 = 0x0100,
    UNKNOWN             = 0x8000
};  //  end enum ExtKeyUsageMask

enum class ValidationType : uint32_t {
    UNDEFINED   = 0,
    NONE        = 1,
    CHAIN       = 2,
    CRL         = 3,
    OCSP        = 4
};  //  end enum ValidationType

enum class VerifyStatus : uint32_t {
    UNDEFINED               = 0,
    INDETERMINATE           = 1,
    FAILED                  = 2,
    INVALID                 = 3,
    VALID_WITHOUT_KEYUSAGE  = 4,
    VALID                   = 5
};  //  end enum VerifyStatus


struct CertStatusInfo {
    const ValidationType
                type;
    std::atomic_bool
                needUpdate;
    ByteArray*  baResult;
    std::atomic<UapkiNS::CertStatus>
                status;
    std::atomic<uint64_t> validTime;
    std::atomic<uint64_t> thisUpdate;  //  of the cached data (OCSP), 0 if unknown

    CertStatusInfo (
        const ValidationType validationType
    );
    ~CertStatusInfo (void);

    bool isExpired (
        const uint64_t time
    );
    void reset (void);
    int set (
        const UapkiNS::CertStatus status,
        const uint64_t validTime,
        const ByteArray* baResult,
        const uint64_t thisUpdate = 0
    );

};  //  end struct CertStatusInfo


//  What a trusted list says about a certificate (a service digital identity of ETSI TS 119 612): the type of
//  the service and the periods of its status, the current one first
struct TrustService {
    struct Period {
        std::string status;         //  the last segment of the status URI: "granted", "withdrawn"...
        uint64_t    msFrom;         //  the starting time of the status
        uint64_t    msTo;           //  the time the next status started; 0 - the current status
        Period (void) : msFrom(0), msTo(0) {}
    };

    std::string listId;             //  the trusted list the service comes from
    std::string type;               //  the service type after ".../Svctype/": "CA/QC", "TSA/QTST", "Certstatus/OCSP"...
    std::string tspName;
    //  The registration identifier of the TSP from its trade name (ETSI TS 119 612, 5.4.2): "NTRUA-36865753",
    //  "VATBE-0123456789"; empty if the list gives none
    std::string tspId;
    std::string serviceName;
    bool        forESignatures;     //  additional service information of a CA/QC service
    bool        forESeals;
    std::vector<Period>
                periods;

    TrustService (void) : forESignatures(false), forESeals(false) {}

    //  The status at the time; nullptr if the service did not exist then
    const Period* periodAt (const uint64_t msTime) const;
    //  The status of a service that is provided ("granted", "recognisedatnationallevel"...), not ended
    static bool isActiveStatus (const std::string& status);
    //  A service that issues certificates: its certificate is a trust anchor
    bool isCa (void) const;
    //  A service of the same TSP in the same list: by the registration identifier, by the name if one of
    //  the services has no identifier
    bool sameProvider (const TrustService& other) const;
};

typedef std::vector<TrustService> TrustServices;


struct CertExtKeyUsage {
    uint32_t value;
    int         pathLenConstraint;  //  basicConstraints.pathLenConstraint, -1 if absent

    CertExtKeyUsage (void)
        : value(0), pathLenConstraint(-1) {}
    bool isCaExtnPresent (void) const {
        return (value & (uint32_t)ExtKeyUsageMask::CA_EXTN_PRESENT) > 0;
    }
    bool isCaExtnCritical (void) const {
        return (value & (uint32_t)ExtKeyUsageMask::CA_EXTN_CRITICAL) > 0;
    }
    bool isCa (void) const {
        return (value & (uint32_t)ExtKeyUsageMask::CA) > 0;
    }
    bool isCmp (void) const {
        return (value & (uint32_t)ExtKeyUsageMask::CMP) > 0;
    }
    bool isOcsp (void) const {
        return (value & (uint32_t)ExtKeyUsageMask::OCSP) > 0;
    }
    bool isOcspNoCheck (void) const {
        return (value & (uint32_t)ExtKeyUsageMask::OCSP_NO_CHECK) > 0;
    }
    bool isTsp (void) const {
        return (value & (uint32_t)ExtKeyUsageMask::TSP) > 0;
    }
    bool isUnknown (void) const {
        return (value & (uint32_t)ExtKeyUsageMask::UNKNOWN) > 0;
    }
    int pathLen (void) const {
        if ((value & (uint32_t)ExtKeyUsageMask::CA_PATHLEN) == 0) {
            return -1;
        }
        return pathLenConstraint;
    }
    void reset (void) {
        value = 0;
        pathLenConstraint = -1;
    }
    void set (const ExtKeyUsageMask ekuMask) {
        value |= (uint32_t)ekuMask;
    }
    void setPathLenConstraint (const int iPathLenConstraint) {
        value |= (uint32_t)ExtKeyUsageMask::CA_PATHLEN;
        pathLenConstraint = iPathLenConstraint;
    }
};  //  end struct CertExtKeyUsage


class CerItem {
public:
    struct Uris {
        std::vector<std::string>
            fullCrl;
        std::vector<std::string>
            deltaCrl;
        std::vector<std::string>
            ocsp;
        std::vector<std::string>
            tsp;
    };  //  end struct Uris

#ifdef DEBUG_CERITEM_INFO
    std::string devsSubject;
    std::string devsIssuerAndSn;
    std::string devsValidity;
#endif

private:
    std::mutex  m_Mutex;
    std::mutex  m_StatusMutex; // OCSP/CRL cache and network coordination only
    std::string m_FileName;
    const ByteArray*
                m_Encoded;
    const Certificate_t*
                m_Cert;
    const ByteArray*
                m_AuthorityKeyId;
    const ByteArray*
                m_CertId;
    std::string m_KeyAlgo;
    const ByteArray*
                m_SerialNumber;
    const ByteArray*
                m_KeyId;
    const ByteArray*
                m_Issuer;
    const ByteArray*
                m_Subject;
    const ByteArray*
                m_Spki;
    HashAlg     m_AlgoKeyId;
    uint64_t    m_NotBefore;
    uint64_t    m_NotAfter;
    uint32_t    m_KeyUsage;
    CertExtKeyUsage
                m_CertExtKeyUsage;
    size_t      m_PublicKeySize;
    std::atomic_bool
                m_SelfSigned;
    bool        m_UnknownCriticalExtension;
    bool        m_AuthorityKeyIdExtn;
    bool        m_NoRevocationCheck;
    bool        m_OcspNoCheckExtn;
    bool        m_NoRevAvailExtn;
    //  Trusted by the configuration of the library (INIT); the trust by a trusted list is in m_TrustServices
    std::atomic_bool
                m_TrustedInit;
    //  A certificate that signs trusted lists (INIT, trustListCache.trustListSignerCerts): a status of its own, it does
    //  not make the certificate trusted in a certification path
    std::atomic_bool
                m_TrustListSigner;
    std::shared_ptr<const TrustServices>
                m_TrustServices;
    Uris        m_Uris;
    std::atomic<VerifyStatus>
                m_VerifyStatus;
    int         m_VerifyError;
    std::string m_VerifyIssuer;
    std::vector<UapkiNS::EssCertId*>
                m_EssCertIds;
    CertStatusInfo
                m_CertStatusByCrl;
    CertStatusInfo
                m_CertStatusByOcsp;
    std::atomic_bool
                m_MarkedToRemove;
    std::atomic_bool
                m_UniqueKeyId;

public:
    CerItem (void);
    ~CerItem (void);

public:
    HashAlg getAlgoKeyId (void) const {
        return m_AlgoKeyId;
    }
    const ByteArray* getAuthorityKeyId (void) const {
        return m_AuthorityKeyId;
    }
    const Certificate_t* getCert (void) const {
        return m_Cert;
    }
    const CertExtKeyUsage& getCertExtKeyUsage (void) const {
        return m_CertExtKeyUsage;
    }
    const ByteArray* getCertId (void) const {
        return m_CertId;
    }
    const CertStatusInfo& getCertStatusByCrl (void) const {
        return m_CertStatusByCrl;
    }
    CertStatusInfo& getCertStatusByCrl (void) {
        return m_CertStatusByCrl;
    }
    const CertStatusInfo& getCertStatusByOcsp (void) const {
        return m_CertStatusByOcsp;
    }
    CertStatusInfo& getCertStatusByOcsp (void) {
        return m_CertStatusByOcsp;
    }
    const ByteArray* getEncoded (void) const {
        return m_Encoded;
    }
    const std::string& getFileName (void) const {
        return m_FileName;
    }
    std::mutex& getMutex (void) {
        return m_Mutex;
    }
    std::mutex& getStatusMutex (void) {
        return m_StatusMutex;
    }
    const ByteArray* getIssuer (void) const {
        return m_Issuer;
    }
    const std::string& getKeyAlgo (void) const {
        return m_KeyAlgo;
    }
    const ByteArray* getKeyId (void) const {
        return m_KeyId;
    }
    uint32_t getKeyUsage (void) const {
        return m_KeyUsage;
    }
    uint64_t getNotAfter (void) const {
        return m_NotAfter;
    }
    uint64_t getNotBefore (void) const {
        return m_NotBefore;
    }
    size_t getPublicKeySize (void) const {
        return m_PublicKeySize;
    }
    const ByteArray* getSerialNumber (void) const {
        return m_SerialNumber;
    }
    const ByteArray* getSpki (void) const {
        return m_Spki;
    }
    const ByteArray* getSubject (void) const {
        return m_Subject;
    }
    const Uris& getUris (void) const {
        return m_Uris;
    }
    VerifyStatus getVerifyStatus (void) const {
        return m_VerifyStatus.load();
    }

public:
    //  The certificate is a service of a trusted list provided at the time; typeMark - a part of the type of the
    //  service ("OCSP", "CRL", "TSA/", "CA/")
    bool hasActiveTrustService (
        const char* typeMark,
        const uint64_t msTime
    ) const;
    bool isTrustListSigner (void) const {
        return m_TrustListSigner;
    }
    void setTrustListSigner (void) {
        m_TrustListSigner = true;
        m_MarkedToRemove = false;
    }
    bool isMarkedToRemove (void) const {
        return m_MarkedToRemove;
    }
    bool isSelfSigned (void) const {
        return m_SelfSigned;
    }
    //  A critical extension the library does not process (RFC 5280, 4.2: such a certificate must be rejected)
    bool hasUnknownCriticalExtension (void) const {
        return m_UnknownCriticalExtension;
    }
    //  The revocation status is not checked (as EU DSS): id-pkix-ocsp-nocheck (RFC 6960, 4.2.2.2.1),
    //  id-etsi-ext-valassured-ST-certs (ETSI EN 319 412-1, 5.2), noRevAvail (RFC 9608)
    bool isNoRevocationCheck (void) const {
        return m_NoRevocationCheck;
    }
    //  The certificate has the authorityKeyIdentifier extension with a key identifier. Without it getAuthorityKeyId()
    //  is the key identifier of the certificate itself, and the issuer is found by its name (CerStore::getIssuerCert)
    bool hasAuthorityKeyIdExtension (void) const {
        return m_AuthorityKeyIdExtn;
    }
    bool hasOcspNoCheckExtension (void) const {
        return m_OcspNoCheckExtn;
    }
    bool hasNoRevAvailExtension (void) const {
        return m_NoRevAvailExtn;
    }
    //  Trust. A certificate given to INIT as trusted is trusted always. A certificate of a trusted list is
    //  trusted conditionally: at a time from the first provision of a service of the certificate to its sunset
    //  date - the end of the last period a service was provided in (ETSI EN 319 102-1: the trust anchor sunset
    //  date); what the list says is kept whatever the status is now, so a signature made in that period is
    //  validated with it.
    //  isTrusted() - trusted now
    bool isTrusted (void) const;
    //  Trusted at the time (milliseconds; 0 - now)
    bool isTrustedAt (
        const uint64_t msTime
    ) const;
    //  May be a trust anchor at some time: trusted by INIT or a certificate of a service of a trusted list
    bool isTrustAnchorCandidate (void) const;
    //  Was a trust anchor at some time: trusted by INIT or a certificate of a service that was provided
    bool wasTrusted (void) const;
    //  The period a certificate of a trusted list is a trust anchor in: from the first time a service of it was
    //  provided to the sunset date (0 - none, a service is provided now); false - no service was ever provided
    bool trustPeriod (
        uint64_t& msStart,
        uint64_t& msSunset
    ) const;
    //  Trusted by the configuration of the library (the trusted certificates of INIT), not by a trusted list
    bool isTrustedInit (void) const {
        return m_TrustedInit;
    }
    //  The services of trusted lists the certificate is the identity of; nullptr if none
    std::shared_ptr<const TrustServices> getTrustServices (void) const {
        return std::atomic_load(&m_TrustServices);
    }
    bool isUniqueKeyId (void) const {
        return m_UniqueKeyId;
    }

public:
    bool equalCertId (
        const ByteArray* baCertId
    ) const {
        return (ba_cmp(m_CertId, baCertId) == 0);
    }
    bool equalKeyId (
        const ByteArray* baKeyId
    ) const {
        return (ba_cmp(m_KeyId, baKeyId) == 0);
    }
    bool equalSerialNumber (
        const ByteArray* baSerialNumber
    ) const {
        return (ba_cmp(m_SerialNumber, baSerialNumber) == 0);
    }

public:
    //  The group of functions that have lock_guard
    int generateEssCertId (
        const UapkiNS::AlgorithmIdentifier& aidDigest,
        const UapkiNS::EssCertId** essCertId
    );
    void markToRemove (
        const bool marked
    );
    bool setFileName (
        const std::string& fileName
    );
    void setTrusted (
        const bool trusted
    );
    //  The services of the trusted lists (nullptr - none); trusted by a list while any of them is provided
    void setTrustServices (
        const std::shared_ptr<const TrustServices>& trustServices
    );
    void setUniqueKeyId (
        const bool uniqueKeyId
    );
    int verify (
        const CerItem* cerIssuer,
        const bool force = false
    );
    //  The signature of this certificate made by the key baIssuerSpki (no cached verdict):
    //  RET_OK, RET_VERIFY_FAILED or an error
    int verifySignatureBy (
        const ByteArray* baIssuerSpki
    ) const;

public:
    int checkValidity (
        const uint64_t validateTime
    ) const;
    std::string generateFileName (void) const;
    int getIssuerAndSN (
        ByteArray** baIssuerAndSN
    ) const;
    bool keyUsageByBit (
        const uint32_t bitNum
    ) const;

public:
    friend int parseCert (
        const ByteArray* baEncoded,
        CerItem** cerItem
    );

};  //  end class CerItem


bool addCertIfUnique (
    std::vector<CerItem*>& cerItems,
    CerItem* cerItem
);
int calcKeyId (
    const HashAlg algoKeyId,
    const ByteArray* baPubkey,
    ByteArray** baKeyId
);
int encodeIssuerAndSN (
    const ByteArray* baIssuer,
    const ByteArray* baSerialNumber,
    ByteArray** baIssuerAndSN
);
CerItem* findCertByCertId (
    const std::vector<CerItem*>& cerItems,
    const ByteArray* baCertId
);
int issuerFromGeneralNames (
    const ByteArray* baEncoded,
    ByteArray** baIssuer
);
int issuerToGeneralNames (
    const ByteArray* baIssuer,
    ByteArray** baEncoded
);
int keyIdFromSID (
    const ByteArray* baEncoded,
    ByteArray** baKeyId
);
int keyIdToSID (
    const ByteArray* baKeyId,
    ByteArray** baEncoded
);
int parseCert (
    const ByteArray* baEncoded,
    CerItem** cerItem
);
int parseIssuerAndSN (
    const ByteArray* baEncoded,
    ByteArray** baIssuer,
    ByteArray** baSerialNumber
);
int parseSID (
    const ByteArray* baEncoded,
    ByteArray** baIssuer,
    ByteArray** baSerialNumber,
    ByteArray** baKeyId
);
ValidationType validationTypeFromStr (
    const std::string& validationType
);
const char* verifyStatusToStr (
    const VerifyStatus status
);


}   //  end namespace Cert

}   //  end namespace UapkiNS


#endif
