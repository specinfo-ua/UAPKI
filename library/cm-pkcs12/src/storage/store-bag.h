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

#ifndef STORE_BAG_H
#define STORE_BAG_H


#include "cm-api.h"
#include "byte-array.h"
#include "hash.h"
#include "uapki-ns.h"


struct StoreAttr {
    std::string oid;
    ByteArray*  data;
    StoreAttr (void)
        : data(nullptr) {}
    StoreAttr (const char* iOid)
        : oid(std::string(iOid)), data(nullptr) {}
    ~StoreAttr (void) {
        ba_free(data);
        data = nullptr;
    }
};  //  end struct StoreAttr

struct StoreKeyInfo {
    std::string id;
    std::string mechanismId;
    std::string parameterId;
    std::string label;
    std::vector<std::string>
                signAlgo;
    std::string publicKey;
    std::string application;
};  //  end struct StoreKeyInfo

class StoreBag {
    public:
        enum class BAG_TYPE : uint32_t {
            UNDEFINED = 0,
            KEY,
            CERT,
            DATA,
        };  //  end enum class BAG_TYPE

    private:
        BAG_TYPE    m_BagType;
        std::string m_BagId;
        UapkiNS::SmartBA
                    m_BagValue;
        std::vector<StoreAttr*>
                    m_BagAttributes;
        UapkiNS::SmartBA
                    m_EncodedBag;
        std::string m_MechanismId;
        std::string m_ParameterId;
        UapkiNS::SmartBA
                    m_KeyId;
        UapkiNS::SmartBA
                    m_KeyId2; // only for DSTU-key
        ByteArray*  m_PtrFriendlyName;
        ByteArray*  m_PtrLocalKeyId;
        struct {
            const char* kdf;
            const char* cipher;
        }           m_Pbes2param;

    public:
        StoreBag (void);
        ~StoreBag (void);

        std::vector<StoreAttr*>& bagAttributes (void) {
            return m_BagAttributes;
        }
        const char* bagId (void) const {
            return m_BagId.c_str();
        }
        BAG_TYPE bagType (void) const {
            return m_BagType;
        }
        const ByteArray* bagValue (void) const {
            return m_BagValue.get();
        }
        const ByteArray* encodedBag (void) const {
            return m_EncodedBag.get();
        }
        const ByteArray* keyId (void) const {
            return m_KeyId.get();
        }
        const ByteArray* keyId2 (void) const {
            return m_KeyId2.get();
        }
        const std::string& mechanismId (void) const {
            return m_MechanismId;
        }
        const std::string& parameterId (void) const {
            return m_ParameterId;
        }
        const ByteArray* friendlyName (void) const {
            return m_PtrFriendlyName;
        }
        const ByteArray* localKeyId (void) const {
            return m_PtrLocalKeyId;
        }

        int encodeBag (
            const char* password = nullptr,
            const size_t iterations = 0
        );
        bool equalKeyId (
            const ByteArray* baKeyId
        ) const;
        StoreAttr* findBagAttr (
            const char* oid
        );
        bool getKeyInfo (
            StoreKeyInfo& keyInfo
        );
        void scanStdAttrs (void);
        StoreAttr* setBagAttr (
            const char* oid
        );
        bool setBagId (
            const std::string& bagId
        );
        void setData (
            const BAG_TYPE bagType,
            ByteArray* bagValue
        );
        void setEncodedBag (
            const ByteArray* baEncoded
        );
        bool setFriendlyName (
            const char* utf8label
        );
        bool setKeyId (
            const ByteArray* baKeyId
        );
        void setPbes2Param (
            const char* oidKdf,
            const char* oidCipher
        );

    public:
        static bool certContainKeyId (
            const ByteArray* baEncoded,
            const ByteArray* baKeyId
        );
        static bool keyIdFromPrivKeyInfo (
            const HashAlg hashAlg,
            const ByteArray* baPrivKeyInfo,
            ByteArray** baKeyId
        );
};  //  end class StoreBag


#endif
