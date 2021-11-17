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

#ifndef UAPKI_CRL_STORE_H
#define UAPKI_CRL_STORE_H

#include "cer-store.h"
#include "uapkic.h"
#include "uapkif.h"
#include "uapki-export.h"
#include "verify-status.h"
#include <string>
#include <vector>


using namespace std;


class CrlStore {
public:
    enum class Actuality : int32_t {
        UNDEFINED       = 0,
        LAST_AVAILABLE  = 1,
        OBSOLETE        = 2
    };

    enum class CrlReason : int32_t {
        UNDEFINED               = -1,
        UNSPECIFIED             = 0,
        KEY_COMPROMISE          = 1,
        CA_COMPROMISE           = 2,
        AFFILIATION_CHANGED     = 3,
        SUPERSEDED              = 4,
        CESSATION_OF_OPERATION  = 5,
        CERTIFICATE_HOLD        = 6,
        // not used              (7)
        REMOVE_FROM_CRL         = 8,
        PRIVILEGE_WITHDRAWN     = 9,
        AA_COMPROMISE           = 10
    };

    enum class CertStatus : int32_t {
        UNDEFINED   = -1,
        GOOD        = 0,
        REVOKED     = 1,
        UNKNOWN     = 2
    };

    enum class CrlType : int32_t {
        UNDEFINED   = -1,
        FULL        = 0,    //  CRL_V2
        DELTA       = 1,    //  CRL_V2
        V1          = 2
    };

    struct RevokedCertItem {
        size_t      index;
        uint64_t    revocationDate;
        CrlReason   crlReason;
        uint64_t    invalidityDate;

        RevokedCertItem (const size_t iIndex, const uint64_t iRevocationDate = 0,
                const CrlReason iCrlReason = CrlReason::UNDEFINED, const uint64_t iInvalidityDate = 0)
            : index(iIndex), revocationDate(iRevocationDate), crlReason(iCrlReason), invalidityDate(iInvalidityDate)
        {}
        uint64_t getDate (void) const { return (invalidityDate > 0) ? invalidityDate : revocationDate; }
    };

    struct Item {
        Actuality   actuality;
        CrlType     type;
        const ByteArray*
                    baEncoded;
        const CertificateList_t*
                    crl;
        const ByteArray*
                    baCrlId;
        ByteArray*  baIssuer;
        uint64_t    thisUpdate;
        uint64_t    nextUpdate;
        ByteArray*  baAuthorityKeyId;
        ByteArray*  baCrlNumber;
        ByteArray*  baDeltaCrl;
        SIGNATURE_VERIFY::STATUS
                    statusSign;

        Item (const CrlType iType);
        ~Item (void);

        size_t countRevokedCerts (void) const;
        int revokedCerts (const CerStore::Item* cerSubject, vector<const RevokedCertItem*>& revokedItems);
        int verify (const CerStore::Item* cerIssuer);
    };

private:
    string          m_Path;
    vector<Item*>   m_Items;

public:
    CrlStore (void);
    ~CrlStore (void);

    int addCrl (const ByteArray* baEncoded, const bool permanent, bool& isUnique, const Item** crlStoreItem);
    int getCount (size_t& count);
    Item* getCrl (const ByteArray* baAuthorityKeyId, const CrlType type);
    int getCrlByCrlId (const ByteArray* baCrlId, const Item** crlStoreItem);
    int load (const char* path);
    int reload (void);
    void reset (void);

public:
    static const char* certStatusToStr (const CertStatus status);
    static const char* crlReasonToStr (const CrlReason reason);
    static const RevokedCertItem* foundNearAfter (const vector<const RevokedCertItem*>& revokedItems, const uint64_t validityTime);
    static const RevokedCertItem* foundNearBefore (const vector<const RevokedCertItem*>& revokedItems, const uint64_t validityTime);
    static int parseCrl (const ByteArray* baEncoded, Item** crlStoreItem);

private:
    Item* addItem (Item* crlStoreItem);
    int loadDir (void);
    int saveToFile (const Item* crlStoreItem);

};  //  end class CrlStore


#endif
