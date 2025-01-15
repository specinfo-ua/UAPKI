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

#ifndef UAPKI_CRL_ITEM_H
#define UAPKI_CRL_ITEM_H

#include <mutex>
#include "cer-item.h"
#include "byte-array.h"
#include "uapkif.h"
#include "uapki-ns.h"
#include "verify-status.h"


namespace UapkiNS {

namespace Crl {


static const char* CRL_EXT      = ".crl";
static const size_t CRL_EXT_LEN = 4;


enum class Type : uint32_t {
    UNDEFINED   = 0,
    //  Support only v2: FULL and DELTA
    FULL        = 1,
    DELTA       = 2
};  //  end enum Type


struct RevokedCertItem {
    uint64_t    revocationDate;
    UapkiNS::CrlReason
                crlReason;
    uint64_t    invalidityDate;

    RevokedCertItem (
        const uint64_t iRevocationDate = 0,
        const UapkiNS::CrlReason iCrlReason = UapkiNS::CrlReason::UNDEFINED,
        const uint64_t iInvalidityDate = 0
    )
        : revocationDate(iRevocationDate)
        , crlReason(iCrlReason)
        , invalidityDate(iInvalidityDate)
    {}
    uint64_t getDate (void) const {
        return (invalidityDate > 0) ? invalidityDate : revocationDate;
    }
};  //  end struct RevokedCertItem

struct RevokedCertOffset {
    size_t  offset;
    size_t  offsetSn;

    RevokedCertOffset (
        const size_t iOffset = 0,
        const size_t iOffsetSn = 0
    )
    : offset(iOffset)
    , offsetSn(iOffsetSn)
    {}
};  //  end struct RevokedCertOffset


class CrlItem {
public:
    enum class Actuality : uint32_t {
        UNDEFINED       = 0,
        LAST_AVAILABLE  = 1,
        OBSOLETE        = 2
    };  //  end enum Actuality

    struct Uris {
        std::vector<std::string>
                    fullCrl;
        std::vector<std::string>
                    deltaCrl;
    };  //  end struct Uris

private:
    std::mutex  m_Mutex;
    std::string m_FileName;
    uint32_t    m_Version;
    const Type  m_Type;
    const ByteArray*
                m_Encoded;
    const TBSCertListAlt_t*
                m_TbsCrl;
    const ByteArray*
                m_CrlId;
    const ByteArray*
                m_Issuer;
    uint64_t    m_ThisUpdate;
    uint64_t    m_NextUpdate;
    std::vector<RevokedCertOffset>
                m_RevokedCertOffsets;
    const ByteArray*
                m_AuthorityKeyId;
    const ByteArray*
                m_CrlNumber;
    const ByteArray*
                m_DeltaCrl;
    Uris        m_Uris;
    Cert::VerifyStatus
                m_StatusSign;
    std::vector<UapkiNS::OtherHash*>
                m_CrlHashes;
    const ByteArray*
                m_CrlIdentifier;
    Actuality   m_Actuality;

public:
    CrlItem (
        const Type iType
    );
    ~CrlItem (void);

public:
    Actuality getActuality (void) const {
        return m_Actuality;
    }
    const ByteArray* getAuthorityKeyId (void) const {
        return m_AuthorityKeyId;
    }
    size_t getCountRevokedCerts (void) const {
        return m_RevokedCertOffsets.size();
    }
    const ByteArray* getCrlId (void) const {
        return m_CrlId;
    }
    const ByteArray* getCrlIdentifier (void) const {
        return m_CrlIdentifier;
    }
    const ByteArray* getCrlNumber (void) const {
        return m_CrlNumber;
    }
    const ByteArray* getDeltaCrl (void) const {
        return m_DeltaCrl;
    }
    const ByteArray* getEncoded (void) const {
        return m_Encoded;
    }
    const std::string& getFileName (void) const {
        return m_FileName;
    }
    const ByteArray* getIssuer (void) const {
        return m_Issuer;
    }
    std::mutex& getMutex (void) {
        return m_Mutex;
    }
    uint64_t getNextUpdate (void) const {
        return m_NextUpdate;
    }
    Cert::VerifyStatus getStatusSign (void) const {
        return m_StatusSign;
    }
    const TBSCertListAlt_t* const getTbsCrl (void) const {
        return m_TbsCrl;
    }
    uint64_t getThisUpdate (void) const {
        return m_ThisUpdate;
    }
    Type getType (void) const {
        return m_Type;
    }
    const Uris& getUris (void) const {
        return m_Uris;
    }
    uint32_t getVersion (void) const {
        return m_Version;
    }

public:
    //  The group of functions that have lock_guard
    int generateHash (
        const UapkiNS::AlgorithmIdentifier& aidDigest,
        const UapkiNS::OtherHash** crlHash
    );
    int saveToFile (
        const std::string& dirName
    );
    void setActuality (
        const Actuality actuality
    );
    bool setFileName (
        const std::string& fileName
    );
    int verify (
        const Cert::CerItem* cerIssuer,
        const bool force = false
    );

public:
    std::string generateFileName (void) const;
    int parsedRevokedCert (
        const size_t index,
        ByteArray** baSerialNumber,
        uint64_t& revocationDate,
        UapkiNS::CrlReason& crlReason,
        uint64_t& invalidityDate
    ) const;
    int revokedCerts (
        const Cert::CerItem* cerSubject,
        std::vector<const RevokedCertItem*>& revokedItems
    );

public:
    friend int parseCrl (
        const ByteArray* baEncoded,
        CrlItem** crlItem
    );

};  //  end class CrlItem


const char* certStatusToStr (
    const UapkiNS::CertStatus status
);
const char* crlReasonToStr (
    const UapkiNS::CrlReason reason
);
int decodeCrlIdentifier (
    const ByteArray* baEncoded,
    ByteArray** baIssuer,
    uint64_t& issuedTime,
    ByteArray** baCrlNumber
);
const RevokedCertItem* findNearBefore (
    const std::vector<const RevokedCertItem*>& revokedItems,
    const uint64_t validateTime
);
bool findRevokedCert (
    const std::vector<const RevokedCertItem*>& revokedItems,
    const uint64_t validateTime,
    UapkiNS::CertStatus& status,
    RevokedCertItem& revokedCertItem
);
int parseRevokedCerts (
    std::vector<RevokedCertOffset>& Offsets,
    const uint8_t* bufEncoded,
    const int lenEncoded
);
int parseCrl (
    const ByteArray* baEncoded,
    CrlItem** crlItem
);


}   //  end namespace Crl

}   //  end namespace UapkiNS

#endif
