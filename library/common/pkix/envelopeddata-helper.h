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

//  Last update: 2022-04-06

#ifndef UAPKI_NS_ENVELOPEDDATA_HELPER_H
#define UAPKI_NS_ENVELOPEDDATA_HELPER_H


#include "uapki-ns.h"
#include "oids.h"
#include "uapkif.h"


namespace UapkiNS {

namespace Pkcs7 {

    struct EncryptedContentInfo {
        std::string contentType;
        AlgorithmIdentifier
                    contentEncryptionAlgo;
        ByteArray*  baEncryptedContent;

        EncryptedContentInfo (void)
            : baEncryptedContent(nullptr) {
        }
        ~EncryptedContentInfo (void) {
            clear();
        }
        void clear (void) {
            contentType.clear();
            ba_free(baEncryptedContent);
        }
    };  //  end struct EncryptedContentInfo

    //class EnvelopedDataBuilder {
    //    EnvelopedData_t*
    //                m_EnvData;
    //    ByteArray*  m_BaEncoded;

    //public:
    //    EnvelopedDataBuilder (void);
    //    ~EnvelopedDataBuilder (void);

    //    int init (void);
    //    int encode (void);
    //    ByteArray* getEncoded (const bool move = false);

    //};  //  end class EnvelopedDataBuilder

    class EnvelopedDataParser {
        EnvelopedData_t*
                    m_EnvData;
        uint32_t    m_Version;
        struct OriginatorInfo {
            VectorBA    certs;
            VectorBA    crls;
        }           m_OriginatorInfo;
        std::vector<RecipientInfo_PR>
                    m_RecipientInfoTypes;
        EncryptedContentInfo
                    m_EncryptedContentInfo;
        //TODO: unprotectedAttrs (OPTIONAL)

    public:
        struct RecipientEncryptedKey {
            ByteArray*  baRid;
            ByteArray*  baEncryptedKey;

            RecipientEncryptedKey (void)
                : baRid(nullptr), baEncryptedKey(nullptr) {}
            ~RecipientEncryptedKey (void) {
                ba_free(baRid);
                ba_free(baEncryptedKey);
            }
        };  //  end class RecipientEncryptedKey

        class KeyAgreeRecipientInfo {
            uint32_t    m_Version;
            OriginatorIdentifierOrKey_PR
                        m_OriginatorType;
            ByteArray*  m_BaOriginator;
            ByteArray*  m_BaUkm;
            AlgorithmIdentifier
                        m_KeyEncryptionAlgorithm;
            std::vector<RecipientEncryptedKey>
                        m_RecipientEncryptedKeys;

        public:
            KeyAgreeRecipientInfo (void);
            ~KeyAgreeRecipientInfo (void);

            int parse (const KeyAgreeRecipientInfo_t& kari);

            uint32_t getVersion (void) const { return m_Version; }
            OriginatorIdentifierOrKey_PR getOriginatorType (void) const { return m_OriginatorType; }
            const ByteArray* getOriginator (void) const { return m_BaOriginator; }
            const ByteArray* getUkm (void) const { return m_BaUkm; }
            const AlgorithmIdentifier& getKeyEncryptionAlgorithm (void) const { return m_KeyEncryptionAlgorithm; }
            const std::vector<RecipientEncryptedKey>& getRecipientEncryptedKeys (void) const { return m_RecipientEncryptedKeys; }

        public:
            static int encodeOriginator (const OriginatorIdentifierOrKey_t& originatorIdOrKey, ByteArray** baEncodedOriginator);

        };  //  end class KeyAgreeRecipientInfo

    public:
        EnvelopedDataParser (void);
        ~EnvelopedDataParser (void);

        int parse (const ByteArray* baEncoded);
        int parseKeyAgreeRecipientInfo (const size_t index, KeyAgreeRecipientInfo& kari);

        uint32_t getVersion (void) const { return m_Version; }
        const VectorBA& getOriginatorCerts (void) const { return m_OriginatorInfo.certs; }
        const VectorBA& getOriginatorCrls (void) const { return m_OriginatorInfo.crls; }
        const std::vector<RecipientInfo_PR>& getRecipientInfoTypes (void) const { return m_RecipientInfoTypes; }
        const EncryptedContentInfo& getEncryptedContentInfo (void) const { return m_EncryptedContentInfo; }
        //TODO: getUnprotectedAttrs (void) const { return TODO; }

    public:
        static int parseEncryptedContentInfo (const EncryptedContentInfo_t& encryptedContentInfo, EncryptedContentInfo& parsedECI);
        static int parseOriginatorInfo (const OriginatorInfo_t& originatorInfo, OriginatorInfo& parsedOriginatorInfo);

    };  //  end class EnvelopedDataParser

}   //  end namespace Pkcs7

}   //  end namespace UapkiNS

#endif
