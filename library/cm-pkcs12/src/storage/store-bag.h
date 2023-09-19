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
#include <string>
#include <vector>


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
    std::string application;
    std::vector<std::string>
                signAlgo;
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
        ByteArray*  m_BagValue;
        std::vector<StoreAttr*>
                    m_BagAttributes;
        ByteArray*  m_EncodedBag;
        ByteArray*  m_KeyId;
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
            return m_BagValue;
        }
        const ByteArray* encodedBag (void) const {
            return m_EncodedBag;
        }
        const ByteArray* keyId (void) const {
            return m_KeyId;
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
        StoreAttr* findAttrByOid (
            const char* oid
        );
        bool getKeyInfo (
            StoreKeyInfo& keyInfo
        );
        void scanStdAttrs (void);
        void setBagId (
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
        bool setLocalKeyID (
            const char* hex
        );
        void setPbes2Param (
            const char* oidKdf,
            const char* oidCipher
        );

};  //  end class StoreBag


#endif
