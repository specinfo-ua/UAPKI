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

#ifndef UAPKI_CER_STORE_H
#define UAPKI_CER_STORE_H


#include "cer-item.h"


namespace UapkiNS {

namespace Cert {


class CerStore {
    std::mutex  m_Mutex;
    std::string m_Path;
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

    //  The group of functions that have lock_guard
    int addCerts (
        const bool trusted,
        const bool permanent,
        const VectorBA& vbaEncodedCerts,
        std::vector<AddedCerItem>& addedCerItems
    );
    std::vector<CerItem*> getCerItems (void);
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
    int getIssuerCert (
        CerItem* cerSubject,
        CerItem** cerIssuer,
        bool& isSelfSigned
    );
    int load (void);
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
