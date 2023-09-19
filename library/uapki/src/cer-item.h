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

#ifndef UAPKI_CER_ITEM_H
#define UAPKI_CER_ITEM_H

#include <atomic>
#include <mutex>
#include "uapkic.h"
#include "uapkif.h"
#include "attribute-helper.h"
#include "uapki-ns.h"


namespace UapkiNS {

namespace Cert {


static const char* CER_EXT      = ".cer";
static const size_t CER_EXT_LEN = 4;
static const bool NOT_TRUSTED   = false;
static const bool TRUSTED       = true;
static const bool NOT_PERMANENT = false;
static const bool PERMANENT     = true;


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
    UapkiNS::CertStatus
                status;
    uint64_t    validTime;

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
        const ByteArray* baResult
    );

};  //  end struct CertStatusInfo


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
    std::atomic_bool
                m_Trusted;
    Uris        m_Uris;
    VerifyStatus
                m_VerifyStatus;
    std::vector<UapkiNS::EssCertId*>
                m_EssCertIds;
    CertStatusInfo
                m_CertStatusByCrl;
    CertStatusInfo
                m_CertStatusByOcsp;
    std::atomic_bool
                m_MarkedToRemove;

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
    const Certificate_t* const getCert (void) const {
        return m_Cert;
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
        return m_VerifyStatus;
    }
    bool isMarkedToRemove (void) const {
        return m_MarkedToRemove;
    }
    bool isTrusted (void) const {
        return m_Trusted;
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
    int verify (
        const CerItem* cerIssuer,
        const bool force = false
    );

public:
    int checkValidity (
        const uint64_t validateTime
    ) const;
    std::string generateFileName (void) const;
    int getIssuerAndSN (
        ByteArray** baIssuerAndSN
    ) const;
    int keyUsageByBit (
        const uint32_t bitNum,
        bool& bitValue
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
