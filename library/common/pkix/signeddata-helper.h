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

#ifndef UAPKI_NS_SIGNEDDATA_HELPER_H
#define UAPKI_NS_SIGNEDDATA_HELPER_H


#include "uapki-ns.h"
#include "oids.h"
#include "uapkif.h"


namespace UapkiNS {

namespace Pkcs7 {

    enum class SignerIdentifierType : size_t {
        UNDEFINED       = 0,
        ISSUER_AND_SN   = 1,
        SUBJECT_KEYID   = 2
    };  //  end enum class SignerIdentifierType

    struct EncapsulatedContentInfo {
        std::string contentType;
        ByteArray*  baEncapContent;

        EncapsulatedContentInfo (void)
            : baEncapContent(nullptr) {
        }
        ~EncapsulatedContentInfo (void) {
            clear();
        }
        void clear (void) {
            contentType.clear();
            ba_free(baEncapContent);
        }
    };  //  end struct EncapsulatedContentInfo

    class SignedDataBuilder {
    public:
        class SignerInfo {
            SignerInfo_t*
                        m_SignerInfo;
            Attributes_t*
                        m_SignedAttrs;
            Attributes_t*
                        m_UnsignedAttrs;
            SignerIdentifierType
                        m_SidType;
            ByteArray*  m_BaDigestAlgoEncoded;
            ByteArray*  m_BaSignedAttrsEncoded;
            std::string m_SignAlgo;

        public:
            SignerInfo (
                SignerInfo_t* iSignerInfo
            );
            ~SignerInfo (void);

            int setVersion (
                const uint32_t version
            );
            int setSid (
                const ByteArray* baSidEncoded
            );
            int setSid (
                const SignerIdentifierType sidType,
                const ByteArray* baData
            );
            int setDigestAlgorithm (
                const UapkiNS::AlgorithmIdentifier& aidDigest
            );
            int addSignedAttr (
                const char* type,
                const ByteArray* baValues
            );
            int addSignedAttr (
                const UapkiNS::Attribute& signedAttr
            );
            int setSignedAttrs (
                const std::vector<UapkiNS::Attribute>& signedAttrs
            );
            int encodeSignedAttrs (void);
            int setSignature (
                const UapkiNS::AlgorithmIdentifier& aidSignature,
                const ByteArray* baSignValue
            );
            int addUnsignedAttr (
                const UapkiNS::Attribute& unsignedAttr
            );
            int setUnsignedAttrs (
                const std::vector<UapkiNS::Attribute>& unsignedAttrs
            );
            int encodeUnsignedAttrs (void);

        public:
            const SignerInfo_t* getAsn1Data (void) const {
                return m_SignerInfo;
            }
            const ByteArray* getDigestAlgoEncoded (void) const {
                return m_BaDigestAlgoEncoded;
            }
            SignerIdentifierType getSidType (void) const {
                return m_SidType;
            }
            const std::string& getSignAlgo (void) const {
                return m_SignAlgo;
            }
            const Attributes_t* getSignedAttrs (void) const {
                return m_SignedAttrs;
            }
            const ByteArray* getSignedAttrsEncoded (void) const {
                return m_BaSignedAttrsEncoded;
            }
            const Attributes_t* getUnsignedAttrs (void) const {
                return m_UnsignedAttrs;
            }

        public:
            int addSignedAttrContentType (
                const char* contentType = OID_PKCS7_DATA
            );
            int addSignedAttrContentType (
                const std::string& contentType
            );
            int addSignedAttrMessageDigest (
                const ByteArray* baMessageDigest
            );
            int addSignedAttrSigningTime (
                const uint64_t signingTime
            );

        };  //  end class SignerInfo

    private:
        SignedData_t*
                    m_SignedData;
        std::vector<SignerInfo*>
                    m_SignerInfos;
        ByteArray*  m_BaEncoded;

    public:
        SignedDataBuilder (void);
        ~SignedDataBuilder (void);

        int init (void);
        int setVersion (
            const uint32_t version
        );
        int setEncapContentInfo (
            const char* eContentType,
            const ByteArray* baEncapContent
        );
        int setEncapContentInfo (
            const std::string& eContentType,
            const ByteArray* baEncapContent
        );
        int setEncapContentInfo (
            const EncapsulatedContentInfo& encapContentInfo
        );
        int addCertificate (
            const ByteArray* baCertEncoded
        );
        int addCrl (
            const ByteArray* baCrlEncoded
        );
        int addSignerInfo (void);
        SignerInfo* getSignerInfo (
            const size_t index = 0
        ) const;

        int encode (
            const char* contentType = OID_PKCS7_SIGNED_DATA
        );
        int encode (
            const std::string& contentType
        );
        ByteArray* getEncoded (
            const bool move = false
        );

    private:
        int collectDigestAlgorithms (void);

    };  //  end class SignedDataBuilder

    class SignedDataParser {
        SignedData_t*
                    m_SignedData;
        uint32_t    m_Version;
        std::vector<std::string>
                    m_DigestAlgorithms;
        EncapsulatedContentInfo
                    m_EncapContentInfo;
        VectorBA    m_Certs;
        VectorBA    m_Crls;
        size_t      m_CountSignerInfos;

    public:
        class SignerInfo {
            const SignerInfo_t*
                        m_SignerInfo;
            uint32_t    m_Version;
            SignerIdentifierType
                        m_SidType;
            SmartBA     m_SidEncoded;
            AlgorithmIdentifier
                        m_DigestAlgorithm;
            std::vector<Attribute>
                        m_SignedAttrs;
            AlgorithmIdentifier
                        m_SignatureAlgorithm;
            SmartBA     m_Signature;
            std::vector<Attribute>
                        m_UnsignedAttrs;

            SmartBA     m_SignedAttrsEncoded;
            struct MandatoryAttrs {
                std::string contentType;
                SmartBA     messageDigest;
            }           m_MandatoryAttrs;

        public:
            SignerInfo (void);
            ~SignerInfo (void);

            int parse (const SignerInfo_t* signerInfo);

        public:
            const SignerInfo_t* getAsn1Data (void) const {
                return m_SignerInfo;
            }
            uint32_t getVersion (void) const {
                return m_Version;
            }
            SignerIdentifierType getSidType (void) const {
                return m_SidType;
            }
            const ByteArray* getSidEncoded (void) const {
                return m_SidEncoded.get();
            }
            const AlgorithmIdentifier& getDigestAlgorithm (void) const {
                return m_DigestAlgorithm;
            }
            const std::vector<Attribute>& getSignedAttrs (void) const {
                return m_SignedAttrs;
            }
            const AlgorithmIdentifier& getSignatureAlgorithm (void) const {
                return m_SignatureAlgorithm;
            }
            const ByteArray* getSignature (void) const {
                return m_Signature.get();
            }
            const std::vector<Attribute>& getUnsignedAttrs (void) const {
                return m_UnsignedAttrs;
            }
            const ByteArray* getSignedAttrsEncoded (void) const {
                return m_SignedAttrsEncoded.get();
            }
            const std::string& getContentType (void) const {
                return m_MandatoryAttrs.contentType;
            }
            const ByteArray* getMessageDigest (void) const {
                return m_MandatoryAttrs.messageDigest.get();
            }

        private:
            int decodeMandatoryAttrs (void);

        public:
            static int decodeAttributes (
                const Attributes_t& attrs,
                std::vector<Attribute>& decodedAttrs
            );

        };  //  end class SignerInfo

    public:
        SignedDataParser (void);
        ~SignedDataParser (void);

        int parse (
            const ByteArray* baEncoded
        );
        int parseSignerInfo (
            const size_t index,
            SignerInfo& signerInfo
        );
        bool isContainDigestAlgorithm (
            const AlgorithmIdentifier& digestAlgorithm
        );

    public:
        uint32_t getVersion (void) const {
            return m_Version;
        }
        const std::vector<std::string>& getDigestAlgorithms (void) const {
            return m_DigestAlgorithms;
        }
        const EncapsulatedContentInfo& getEncapContentInfo (void) const {
            return m_EncapContentInfo;
        }
        const VectorBA& getCerts (void) const {
            return m_Certs;
        }
        VectorBA& getCerts (void) {
            return m_Certs;
        }
        const VectorBA& getCrls (void) const {
            return m_Crls;
        }
        VectorBA& getCrls (void) {
            return m_Crls;
        }
        const size_t getCountSignerInfos (void) const {
            return m_CountSignerInfos;
        }

    public:
        static int decodeDigestAlgorithms (
                const DigestAlgorithmIdentifiers_t& digestAlgorithms,
                std::vector<std::string>& decodedDigestAlgos
        );
        static int decodeEncapContentInfo (
                const EncapsulatedContentInfo_t& encapContentInfo,
                EncapsulatedContentInfo& decodedEncapContentInfo
        );

    };  //  end class SignedDataParser

    int keyIdToSid (
        const ByteArray* baKeyId,
        ByteArray** baSidEncoded
    );

}   //  end namespace Pkcs7

}   //  end namespace UapkiNS

#endif
