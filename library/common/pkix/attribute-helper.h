/*
 * Copyright (c) 2023, The UAPKI Project Authors.
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

//  Last update: 2023-01-30

#ifndef UAPKI_NS_ATTRIBUTE_HELPER_H
#define UAPKI_NS_ATTRIBUTE_HELPER_H


#include "uapki-ns.h"
#include "byte-array.h"
#include "ATSHashIndex.h"
#include "CompleteRevocationRefs.h"
#include "CrlOcspRef.h"
#include "RevocationValues.h"


namespace UapkiNS {

    struct OtherHash {
        UapkiNS::AlgorithmIdentifier
                    hashAlgorithm;
        ByteArray*  baHashValue;

        OtherHash (void)
            : baHashValue(nullptr) {
        }
        ~OtherHash (void) {
            ba_free(baHashValue);
        }
        bool isPresent (void) const {
            return (hashAlgorithm.isPresent() && baHashValue);
        }
    };  //  end struct OtherHash

    struct AttrCertId : public OtherHash {
        struct IssuerSerial {
            ByteArray*  baIssuer;
            ByteArray*  baSerialNumber;
            IssuerSerial (void)
                : baIssuer(nullptr), baSerialNumber(nullptr) {
            }
            ~IssuerSerial (void) {
                ba_free(baIssuer);
                ba_free(baSerialNumber);
            }
            bool isPresent (void) const {
                return (baIssuer && baSerialNumber);
            }
        }           issuerSerial;
    };  //  end struct AttrCertId

    using EssCertId = AttrCertId;
    using OtherCertId = AttrCertId;

namespace AttributeHelper {

    int decodeCertValues (const ByteArray* baEncoded, std::vector<ByteArray*>& certValues);
    int decodeCertificateRefs (const ByteArray* baEncoded, std::vector<OtherCertId>& otherCertIds);
    int decodeContentType (const ByteArray* baEncoded, std::string& contentType);
    int decodeMessageDigest (const ByteArray* baEncoded, ByteArray** baMessageDigest);
    int decodeSignaturePolicy (const ByteArray* baEncoded, std::string& sigPolicyId);
    int decodeSigningCertificate (const ByteArray* baEncoded, std::vector<EssCertId>& essCertIds);
    int decodeSigningTime (const ByteArray* baEncoded, uint64_t& signingTime);

    int encodeAttribute (
        const UapkiNS::Attribute& attr,
        ByteArray** baEncoded
    );
    int encodeCertValues (
        const std::vector<const ByteArray*>& certValues,
        ByteArray** baEncoded
    );
    int encodeCertificateRefs (
        const std::vector<OtherCertId>& otherCertIds,
        ByteArray** baEncoded
    );
    int encodeSignaturePolicy (
        const std::string& sigPolicyId,
        ByteArray** baEncoded
    );
    int encodeSigningCertificate (
        const EssCertId& essCertId,
        ByteArray** baEncoded
    );
    int encodeSigningCertificate (
        const std::vector<EssCertId>& essCertIds,
        ByteArray** baEncoded
    );

    class AtsHashIndexBuilder {
        ATSHashIndexDefault_t*
                    m_AtsHashIndexDefault;
        ATSHashIndexFull_t*
                    m_AtsHashIndexFull;
        ByteArray*  m_BaEncoded;

    public:
        AtsHashIndexBuilder (void);
        ~AtsHashIndexBuilder (void);

        int init (
            const char* hashIndAlgorithm,
            const ByteArray* baParameters = nullptr
        );
        int init (
            const AlgorithmIdentifier& hashIndAlgorithm
        );
        int addHashCert (
            const ByteArray* baHash
        );
        int addHashCrl (
            const ByteArray* baHash
        );
        int addHashUnsignedAttr (
            const ByteArray* baHash
        );

        int encode (void);
        ByteArray* getEncoded (
            const bool move = false
        );

    };  //  AtsHashIndexBuilder

    class AtsHashIndexParser {
        AlgorithmIdentifier
                    m_HashIndAlgorithm;
        VectorBA    m_CertsHashIndex;
        VectorBA    m_CrlsHashIndex;
        VectorBA    m_UnsignedAttrsHashIndex;

    public:
        AtsHashIndexParser (void);
        ~AtsHashIndexParser (void);

        int parse (const ByteArray* baEncoded);

        const VectorBA& getCertsHashIndex (void) const {
            return m_CertsHashIndex;
        }
        const VectorBA& getCrlsHashIndex (void) const {
            return m_CrlsHashIndex;
        }
        const AlgorithmIdentifier& getHashIndAlgorithm (void) const {
            return m_HashIndAlgorithm;
        }
        const VectorBA& getUnsignedAttrsHashIndex (void) const {
            return m_UnsignedAttrsHashIndex;
        }

    };  //  AtsHashIndexParser

    class RevocationRefsBuilder {
    public:
        class CrlOcspRef {
            CrlOcspRef_t*
                        m_RefCrlOcspRef;

        public:
            CrlOcspRef (CrlOcspRef_t* iRefCrlOcspRef);
            ~CrlOcspRef (void);

            int addCrlValidatedId (
                const UapkiNS::OtherHash& crlHash,
                const ByteArray* baCrlIdentifier = nullptr
            );
            int addOcspResponseId (
                const ByteArray* baOcspIdentifier,
                const ByteArray* baOcspRespHash = nullptr
            );
            int setOtherRevRefs (
                const char* otherRevRefType,
                const ByteArray* baOtherRevRefs
            );
            int setOtherRevRefs (
                const std::string& otherRevRefType,
                const ByteArray* baOtherRevRefs
            );

        };  //  end class CrlOcspRef

    private:
        CompleteRevocationRefs_t*
                    m_RevRefs;
        std::vector<CrlOcspRef*>
                    m_CrlOcspRefs;
        ByteArray*  m_BaEncoded;

    public:
        RevocationRefsBuilder (void);
        ~RevocationRefsBuilder (void);

        int init (void);
        int addCrlOcspRef (void);
        CrlOcspRef* getCrlOcspRef (
            const size_t index = 0
        ) const;

        int encode (void);
        ByteArray* getEncoded (
            const bool move = false
        );

    };  //  end class RevocationRefsBuilder

    class RevocationRefsParser {
    public:
        struct CrlOcspId {
            ByteArray*  baHash;
            ByteArray*  baId;
            CrlOcspId (void)
            : baHash(nullptr), baId(nullptr) {}
            ~CrlOcspId(void) {
                ba_free(baHash);
                ba_free(baId);
            }
            bool isPresentHash (void) const {
                return (baHash);
            }
            bool isPresentId (void) const {
                return (baId);
            }
        };  //  end struct CrlOcspId

        class CrlOcspRef {
            std::vector<CrlOcspId>
                        m_CrlIds;
            std::vector<CrlOcspId>
                        m_OcspIds;
            Attribute   m_OtherRevRefs;

        public:
            CrlOcspRef (void);
            ~CrlOcspRef (void);

            int parse (
                const CrlOcspRef_t& crlOcspRef
            );

            const std::vector<CrlOcspId>& getCrlIds (void) const { return m_CrlIds; }
            const std::vector<CrlOcspId>& getOcspIds (void) const { return m_OcspIds; }
            const Attribute& getOtherRevRefs (void) const { return m_OtherRevRefs; }

        };  //  end class CrlOcspRef

    private:
        CompleteRevocationRefs_t*
                    m_RevRefs;
        size_t      m_CountCrlOcspRefs;

    public:
        RevocationRefsParser (void);
        ~RevocationRefsParser (void);

        int parse (
            const ByteArray* baEncoded
        );
        int parseCrlOcspRef (
            const size_t index,
            CrlOcspRef& crlOcspRef
        );

        const size_t getCountCrlOcspRefs (void) const { return m_CountCrlOcspRefs; }

    };  //  end class RevocationRefsParser

    class RevocationValuesBuilder {
    private:
        RevocationValues_t*
                    m_RevValues;
        ByteArray*  m_BaEncoded;

    public:
        RevocationValuesBuilder (void);
        ~RevocationValuesBuilder (void);

        int init (void);
        int addCrlValue (
            const ByteArray* baCrlEncoded
        );
        int addOcspValue (
            const ByteArray* baBasicOcspResponseEncoded
        );
        int setCrlValues (
            const std::vector<const ByteArray*>& abaCrlValues
        );
        int setOcspValues (
            const std::vector<const ByteArray*>& abaOcspValues
        );
        int setOtherRevVals (
            const char* otherRevValType,
            const ByteArray* baOtherRevVals
        );
        int setOtherRevVals (
            const std::string& otherRevValType,
            const ByteArray* baOtherRevVals
        );

        int encode (void);
        ByteArray* getEncoded (
            const bool move = false
        );

    };  //  end class RevocationValuesBuilder

    class RevocationValuesParser {
        VectorBA    m_CrlVals;
        VectorBA    m_OcspVals;
        Attribute   m_OtherRevVals;

    public:
        RevocationValuesParser (void);
        ~RevocationValuesParser (void);

        int parse (
            const ByteArray* baEncoded
        );

        const VectorBA& getCrlVals (void) const { return m_CrlVals; }
        const VectorBA& getOcspVals (void) const { return m_OcspVals; }
        const Attribute& getOtherRevVals (void) const { return m_OtherRevVals; }

    };  //  end class RevocationValuesParser

}   //  end namespace AttributeHelper

}   //  end namespace UapkiNS


#endif
