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

#ifndef UAPKI_CER_STORE_H
#define UAPKI_CER_STORE_H


#include "cer-item.h"
#include <map>


namespace UapkiNS {

namespace Cert {


//  A chain of issuers (CerStore::getChainCerts) ends at the first certificate trusted at the time (milliseconds;
//  0 - now): the trust anchor (RFC 5280, 6.1), whether it is self-signed or not; what is above it is cut off.
//  false - no certificate of the chain is trusted then
bool cutChainAtTrusted (
    std::vector<CerItem*>& chainCerts,
    const uint64_t msTime
);


//  A trusted list accepted by the library (ADD_TRUST_LIST, the lists read by INIT)
struct AcceptedTrustList {
    std::string listId;
    std::string type;
    std::string territory;
    std::string schemeName;             //  the name of the scheme and of its operator: in English if the list
    std::string schemeOperatorName;     //  has it, else the first one
    uint64_t    sequenceNumber;
    uint64_t    msIssued;
    uint64_t    msNextUpdate;       //  0 - the list has no next update (a closed list)
    std::vector<uint8_t>
                signerCertId;
    uint32_t    countCerts;
    uint32_t    countTrustedCerts;
    bool        stored;

    AcceptedTrustList (void)
        : sequenceNumber(0), msIssued(0), msNextUpdate(0), countCerts(0), countTrustedCerts(0), stored(false)
    {}
};


class CerStore {
    std::mutex  m_Mutex;
    std::string m_Path;
    std::string m_TrustListPath;
    std::vector<std::vector<uint8_t>>
                m_TrustListSigners;
    //  The sequence number of every trusted list accepted (by the identifier of the list)
    std::map<std::string, uint64_t>
                m_TrustListSequences;
    //  The trusted lists accepted, the last version of every list (by the identifier of the list)
    std::map<std::string, AcceptedTrustList>
                m_AcceptedTrustLists;
    std::vector<CerItem*>
                m_Items;

public:
    CerStore (void);
    ~CerStore (void);

    void setParams (
        const std::string& path
    );

public:
    struct AddedCerItem {
        int         errorCode;
        CerItem*    cerItem;
        bool        isUnique;
        AddedCerItem (
            CerItem* iCerItem = nullptr,
            const bool iIsUnique = false
        )
            : errorCode(RET_OK)
            , cerItem(iCerItem)
            , isUnique(iIsUnique)
        {}
    };  //  end struct AddedCerItem

    struct FilterListCerts {
        SmartBA     publicKeyBytes;
        VectorBA    subjectKeyIds;
        bool check (
            const CerItem* cerItem
        ) const;
    };  //  end struct FilterListCerts

    //  The group of functions that have lock_guard
    int addCerts (
        const bool trusted,
        const bool permanent,
        const VectorBA& vbaEncodedCerts,
        std::vector<AddedCerItem>& addedCerItems
    );
    std::vector<CerItem*> getCerItems (
        const FilterListCerts& filter
    );
    int getCertByCertId (
        const ByteArray* baCertId,
        CerItem** cerItem
    );
    int getCertByEncoded (
        const ByteArray* baEncoded,
        CerItem** cerItem
    );
    int getCertByIndex (
        const size_t index,
        CerItem** cerItem
    );
    int getCertByIssuerAndSN (
        const ByteArray* baIssuerAndSN,
        CerItem** cerItem
    );
    int getCertByIssuerAndSN (
        const ByteArray* baIssuer,
        const ByteArray* baSerialNumber,
        CerItem** cerItem
    );
    int getCertByKeyId (
        const ByteArray* baKeyId,
        CerItem** cerItem
    );
    int getCertBySID (
        const ByteArray* baSID,
        CerItem** cerItem
    );
    int getCertBySPKI (
        const ByteArray* baSPKI,
        CerItem** cerItem
    );
    int getCertBySubject (
        const ByteArray* baSubject,
        CerItem** cerItem
    );
    //  All certificates with the subject name
    void getCertsBySubject (
        const ByteArray* baSubject,
        std::vector<CerItem*>& cerItems
    );
    int getChainCerts (
        const CerItem* cerSubject,
        std::vector<CerItem*>& chainCerts
    );
    int getChainCerts (
        const CerItem* cerSubject,
        std::vector<CerItem*>& chainCerts,
        const ByteArray** baIssuerKeyId
    );
    int getCount (
        size_t& count
    );
    int getCount (
        size_t& count,
        size_t& countTrusted
    );
    //  All certificates with the key identifier (overlay and base)
    void getCertsByKeyId (
        const ByteArray* baKeyId,
        std::vector<CerItem*>& cerItems
    );
    int getIssuerCert (
        CerItem* cerSubject,
        CerItem** cerIssuer,
        bool& isSelfSigned
    );
    int load (void);
    //  A trusted list is accepted (ADD_TRUST_LIST): its sequence number must not be less than the one accepted
    //  before (a protection against a replay of an old list) - else RET_UAPKI_TRUST_LIST_OBSOLETE. The numbers are
    //  kept in the directory of the trusted lists (else of the store), when there is one. Then the services of the
    //  list replace the ones this list gave before: services - the certificates (not added if absent, see addCerts)
    //  with their services. baList with storeName: the accepted list is kept in the directory of the trusted lists
    //  under this file name (the last version of every list; INIT reads them again)
    int applyTrustList (
        const std::string& listId,
        const uint64_t sequenceNumber,
        const std::vector<std::pair<CerItem*, TrustService>>& services,
        size_t& countTrusted,
        const ByteArray* baList = nullptr,
        const std::string& storeName = std::string(),
        bool* stored = nullptr
    );
    //  The directory of the trusted lists (INIT, trustListCache.path), with the separator at the end; empty - none
    void setTrustListPath (
        const std::string& path
    );
    std::string getTrustListPath (void);
    //  The certificates that sign trusted lists (INIT, trustListCache.trustListSignerCerts), encoded. A trust of its own
    //  kind: such a certificate is not a trusted certificate of a certification path, and a trusted certificate
    //  of the store is not a signer of trusted lists
    void setTrustListSigners (
        const std::vector<std::vector<uint8_t>>& encodedCerts
    );
    bool isTrustListSigner (
        const ByteArray* baEncodedCert
    );
    //  The trusted lists accepted: the last version of every list
    void setAcceptedTrustList (
        const AcceptedTrustList& trustList
    );
    std::vector<AcceptedTrustList> getAcceptedTrustLists (void);
    //  The files of the lists kept in the directory (full names)
    int getStoredTrustLists (
        std::vector<std::string>& fileNames
    );
    int removeCert (
        CerItem* cerSubject,
        const bool permanent
    );
    int removeMarkedCerts (void);

private:
    //  addItem - added unique item, return new-item or exists-item
    CerItem* addItem (
        CerItem* cerItem
    );
    int loadDir (void);
    void reset (void);

public:
    void saveStatToLog (
        const std::string& message
    );

};  //  end class CerStore


}   //  end namespace Cert

}   //  end namespace UapkiNS


#endif
