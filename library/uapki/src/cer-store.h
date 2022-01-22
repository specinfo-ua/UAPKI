/*
 * Copyright (c) 2022, The UAPKI Project Authors.
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

#include "uapkic.h"
#include "uapkif.h"
#include "uapki-export.h"
#include "verify-status.h"
#include <string>
#include <vector>


using namespace std;


class CerStore {

public:
    struct Item {
        const ByteArray*
                    baEncoded;
        const Certificate_t*
                    cert;
        const ByteArray*
                    baCertId;
        const char* keyAlgo;
        const ByteArray*
                    baSerialNumber;
        const ByteArray*
                    baKeyId;
        const ByteArray*
                    baIssuer;
        const ByteArray*
                    baSubject;
        const ByteArray*
                    baSPKI;
        HashAlg     algoKeyId;
        uint64_t    notBefore;
        uint64_t    notAfter;
        uint32_t    keyUsage;
        bool        trusted;

        Item (void);
        ~Item (void);

        int checkValidity (const uint64_t validateTime) const;
        int getCrlUris (const bool isFull, vector<string>& uris) const;
        int getIssuerAndSN (ByteArray** baIssuerAndSN) const;
        int getOcspUris (vector<string>& uris) const;
        int getTspUris (vector<string>& uris) const;
        int keyUsageByBit (const uint32_t bitNum, bool& bitValue) const;

    };

private:
    string          m_Path;
    vector<Item*>   m_Items;

public:
    CerStore (void);
    ~CerStore (void);

    int addCert (const ByteArray* baEncoded, const bool copyWithAlloc, const bool permanent, const bool trusted, bool& isUnique, const Item** cerStoreItem);
    int getCount (size_t& count);
    int getCountTrusted (size_t& count);
    int getCertByCertId (const ByteArray* baCertId, const Item** cerStoreItem);
    int getCertByEncoded (const ByteArray* baEncoded, const Item** cerStoreItem);
    int getCertByIndex (const size_t index, const Item** cerStoreItem);
    int getCertByKeyId (const ByteArray* baKeyId, const Item** cerStoreItem);
    int getCertBySID (const ByteArray* baSID, const Item** cerStoreItem);
    int getCertBySPKI (const ByteArray* baSPKI, const Item** cerStoreItem);
    int getCertBySubject (const ByteArray* baSubject, const Item** cerStoreItem);
    int getIssuerCert (const Item* cerSubject, const Item** cerIssuer, bool& isSelfSigned);
    int load (const char* path);
    int reload (void);
    int removeCert (const ByteArray* baCertId, const bool permanent);
    void reset (void);

public:
    static int calcKeyId (const HashAlg algoKeyId, const ByteArray* baPubkey, ByteArray** baKeyId);
    static int parseCert (const ByteArray* baEncoded, Item** cerStoreItem);
    static int parseSID (const ByteArray* baSID, ByteArray** baIssuer, ByteArray** baSerialNumber, ByteArray** baKeyId);

private:
    //  addItem - added unique item, return new-item or exists-item
    Item* addItem (Item* cerStoreItem);
    int loadDir (void);
    int saveToFile (const Item* cerStoreItem);

};  //  end class CerStore


#endif
