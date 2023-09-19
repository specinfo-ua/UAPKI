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

    struct RecipientEncryptedKey {
        ByteArray* baRid;
        ByteArray* baEncryptedKey;

        RecipientEncryptedKey (void)
            : baRid(nullptr), baEncryptedKey(nullptr) {}
        ~RecipientEncryptedKey (void) {
            ba_free(baRid);
            ba_free(baEncryptedKey);
        }
    };  //  end struct RecipientEncryptedKey

    class EnvelopedDataBuilder {
        class RecipientInfoBase {
            const RecipientInfo_PR
                        m_RecipInfoType;

        public:
            RecipientInfoBase (
                const RecipientInfo_PR iRecipInfoType
            );
            ~RecipientInfoBase (void);

            RecipientInfo_PR getRecipientInfoType (void) const {
                return m_RecipInfoType;
            }

        };  //  end class RecipientInfoBase

        EncryptedContentInfo
                    m_EncryptedContentInfo;
        EnvelopedData_t*
                    m_EnvData;
        std::vector<RecipientInfoBase*>
                    m_RecipientInfos;
        ByteArray*  m_BaEncoded;

    public:
        class KeyAgreeRecipientInfo : public RecipientInfoBase {
            KeyAgreeRecipientInfo_t*
                        m_RefKari;

        public:
            KeyAgreeRecipientInfo (
                KeyAgreeRecipientInfo_t* iRefKari
            );
            ~KeyAgreeRecipientInfo (void);

            int setVersion (
                const uint32_t version = 3u
            );
            int setOriginatorByIssuerAndSN (
                const ByteArray* baIssuerAndSN
            );
            int setOriginatorBySubjectKeyId (
                const ByteArray* baSubjectKeyId
            );
            int setOriginatorByPublicKey (
                const UapkiNS::AlgorithmIdentifier& aidOriginator,
                const ByteArray* baPublicKey
            );
            int setOriginatorByPublicKey (
                const ByteArray* baSPKI
            );
            int setUkm (
                const ByteArray* baUkm
            );
            int setKeyEncryptionAlgorithm (
                const UapkiNS::AlgorithmIdentifier& aidKeyEncryptionAlgoId
            );
            int addRecipientEncryptedKey (
                const RecipientEncryptedKey& recipEncryptedKey
            );
            int addRecipientEncryptedKeyByIssuerAndSN (
                const ByteArray* baIssuerAndSN,
                const ByteArray* baEncryptedKey
            );
            int addRecipientEncryptedKeyByRecipientKeyId (
                const ByteArray* baSubjectKeyId,
                const ByteArray* baEncryptedKey,
                const uint64_t date = 0,
                const ByteArray* baOtherKeyAttribute = nullptr
            );

        };  //  end class KeyAgreeRecipientInfo

    public:
        EnvelopedDataBuilder (void);
        ~EnvelopedDataBuilder (void);

        int init (
            const uint32_t version
        );
        int addOriginatorCert (
            const ByteArray* baCertEncoded
        );
        int addOriginatorCrl (
            const ByteArray* baCrlEncoded
        );
        int addRecipientInfo (
            const RecipientInfo_PR recipInfoType
        );
        KeyAgreeRecipientInfo* getKeyAgreeRecipientInfo (
            const size_t index = 0
        ) const;
        int setEncryptedContentInfo (
            const char* contentType,
            const UapkiNS::AlgorithmIdentifier& aidContentEncryptionAlgoId,
            const ByteArray* baEncryptedContent
        );
        int setEncryptedContentInfo (
            const std::string& contentType,
            const UapkiNS::AlgorithmIdentifier& aidContentEncryptionAlgoId,
            const ByteArray* baEncryptedContent
        );
        int addUnprotectedAttr (const UapkiNS::Attribute& unprotectedAttrs);

        int encode (
            const char* contentType = OID_PKCS7_ENVELOPED_DATA
        );
        int encode (
            const std::string& contentType
        );
        ByteArray* getEncoded (
            const bool move = false
        );

        EncryptedContentInfo& getEncryptedContentInfo (void) {
            return m_EncryptedContentInfo;
        }

    };  //  end class EnvelopedDataBuilder

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
        std::vector<UapkiNS::Attribute>
                    m_UnprotectedAttrs;

    public:
        class KeyAgreeRecipientIdentifier {
            KeyAgreeRecipientIdentifier_t*
                        m_KarId;
        public:
            KeyAgreeRecipientIdentifier (void);
            ~KeyAgreeRecipientIdentifier (void);

            KeyAgreeRecipientIdentifier_PR getType (void) const;
            int parse (
                const ByteArray* baEncoded
            );
            int toIssuerAndSN (
                ByteArray** baIssuerAndSN
            ) const;
            int toIssuerAndSN (
                ByteArray** baIssuer,
                ByteArray** baSerialNumber
            ) const;
            int toRecipientKeyId (
                ByteArray** baSubjectKeyId
            ) const;
            int toRecipientKeyId (
                ByteArray** baSubjectKeyId,
                uint64_t& date,
                ByteArray** baOtherKeyAttribute
            ) const;

        };  //  end class KeyAgreeRecipientIdentifier

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

            uint32_t getVersion (void) const {
                return m_Version;
            }
            OriginatorIdentifierOrKey_PR getOriginatorType (void) const {
                return m_OriginatorType;
            }
            const ByteArray* getOriginator (void) const {
                return m_BaOriginator;
            }
            const ByteArray* getUkm (void) const {
                return m_BaUkm;
            }
            const AlgorithmIdentifier& getKeyEncryptionAlgorithm (void) const {
                return m_KeyEncryptionAlgorithm;
            }
            const std::vector<RecipientEncryptedKey>& getRecipientEncryptedKeys (void) const {
                return m_RecipientEncryptedKeys;
            }

        public:
            static int parseOriginator (
                const OriginatorIdentifierOrKey_t& originatorIdOrKey,
                ByteArray** baEncodedOriginator
            );

        };  //  end class KeyAgreeRecipientInfo

    public:
        EnvelopedDataParser (void);
        ~EnvelopedDataParser (void);

        int parse (
            const ByteArray* baEncoded
        );
        int parseKeyAgreeRecipientInfo (
            const size_t index,
            KeyAgreeRecipientInfo& kari
        );

        uint32_t getVersion (void) const {
            return m_Version;
        }
        const VectorBA& getOriginatorCerts (void) const {
            return m_OriginatorInfo.certs;
        }
        VectorBA& getOriginatorCerts (void) {
            return m_OriginatorInfo.certs;
        }
        const VectorBA& getOriginatorCrls (void) const {
            return m_OriginatorInfo.crls;
        }
        VectorBA& getOriginatorCrls (void) {
            return m_OriginatorInfo.crls;
        }
        const std::vector<RecipientInfo_PR>& getRecipientInfoTypes (void) const {
            return m_RecipientInfoTypes;
        }
        const EncryptedContentInfo& getEncryptedContentInfo (void) const {
            return m_EncryptedContentInfo;
        }
        const std::vector<UapkiNS::Attribute>& getUnprotectedAttrs (void) const {
            return m_UnprotectedAttrs;
        }

    public:
        static int parseEncryptedContentInfo (
            const EncryptedContentInfo_t& encryptedContentInfo,
            EncryptedContentInfo& parsedECI
        );
        static int parseOriginatorInfo (
            const OriginatorInfo_t& originatorInfo,
            OriginatorInfo& parsedOriginatorInfo
        );
        static int parseUnprotectedAttrs (
            const Attributes_t* attrs,
            std::vector<UapkiNS::Attribute>& parsedAttrs
        );

    };  //  end class EnvelopedDataParser

}   //  end namespace Pkcs7

}   //  end namespace UapkiNS

#endif
