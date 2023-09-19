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


#ifndef UAPKI_NS_H
#define UAPKI_NS_H


#include <string>
#include <vector>
#include "byte-array.h"


namespace UapkiNS {

    enum class CertStatus : int32_t {
        UNDEFINED   = -1,
        GOOD        = 0,
        REVOKED     = 1,
        UNKNOWN     = 2
    };  //  end enum CertStatus

    enum class CrlReason : int32_t {
        //  CRLReason ::= ENUMERATED    -- rfc5280 $5.3.1, z1400-12 $3.8.1 --
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
    };  //  end enum CrlReason

    struct AlgorithmIdentifier {
        std::string algorithm;
        ByteArray*  baParameters;

        AlgorithmIdentifier (
            const std::string& iAlgorithm = std::string(),
            const ByteArray* iParameters = nullptr
        )
        : algorithm(iAlgorithm)
        , baParameters((ByteArray*)iParameters)
        {}
        ~AlgorithmIdentifier (void) {
            clear();
        }
        void clear (void) {
            algorithm.clear();
            ba_free(baParameters);
        }
        bool copy (const AlgorithmIdentifier& src) {
            algorithm = src.algorithm;
            if (src.baParameters) {
                baParameters = ba_copy_with_alloc(src.baParameters, 0, 0);
                return (baParameters);
            }
            return true;
        }
        bool isPresent (void) const {
            return (!algorithm.empty());
        }
    };  //  end struct AlgorithmIdentifier

    struct Attribute {
        std::string type;
        ByteArray*  baValues;

        Attribute (
            const std::string& iType = std::string(),
            const ByteArray* iBaValues = nullptr
        )
        : type(iType)
        , baValues((ByteArray*)iBaValues)
        {}
        ~Attribute (void) {
            clear();
        }
        void clear (void) {
            type.clear();
            ba_free(baValues);
        }
        bool isPresent (void) const {
            return (!type.empty());
        }
    };  //  end struct Attribute

    struct Extension {
        std::string extnId;
        bool        critical;
        ByteArray*  baExtnValue;

        Extension (
            const std::string& iExtnId = std::string(),
            const bool iCritical = false,
            const ByteArray* iBaValues = nullptr
        )
        : extnId(iExtnId)
        , critical(iCritical)
        , baExtnValue((ByteArray*)iBaValues)
        {}
        ~Extension (void) {
            clear();
        }
        void clear (void) {
            extnId.clear();
            ba_free(baExtnValue);
        }
        bool isPresent (void) const {
            return (!extnId.empty());
        }
    };  //  end struct Extension

    struct RdName {
        enum class StringType : uint32_t {
            UNDEFINED   = 0,
            PRINTABLE   = 1,
            UTF8        = 2,
            BMP         = 3,    // for backward compatibility
            IA5         = 4,    // for backward compatibility
            TELETEX     = 5,    // for backward compatibility
            UNIVERSAL   = 6     // for backward compatibility
        };  //  end enum class StringType

        std::string type;
        StringType  stringType;
        std::string value;

        RdName (void)
            : stringType(StringType::UNDEFINED) {
        }
        void clear (void) {
            type.clear();
            value.clear();
        }
        bool isPresent (void) const {
            return (!type.empty());
        }
    };  //  end struct RdName

    class SmartBA {
        ByteArray* m_Ba;
    public:
        SmartBA (void)
            : m_Ba(nullptr) {}
        ~SmartBA (void) {
            clear();
        }
        ByteArray*& operator* (void) {
            return m_Ba;
        }
        ByteArray** operator& (void) {
            return &m_Ba;
        }
        uint8_t* buf (void) const {
            return ba_get_buf(m_Ba);
        }
        void clear (void) {
            ba_free(m_Ba);
            m_Ba = nullptr;
        }
        bool empty (void) const {
            return (size() == 0);
        }
        ByteArray* get (void) const {
            return m_Ba;
        }
        ByteArray* pop (void) {
            ByteArray* rv_ba = m_Ba;
            m_Ba = nullptr;
            return rv_ba;
        }
        bool reset (ByteArray* ba) {
            clear();
            m_Ba = ba;
            return (m_Ba);
        }
        bool set (ByteArray* ba) {
            m_Ba = ba;
            return (m_Ba);
        }
        size_t size (void) const {
            return ba_get_len(m_Ba);
        }
    };  //  end class SmartBA

    class VectorBA : public std::vector<ByteArray*> {
    public:
        VectorBA (const size_t newSize = 0) {
            resize(newSize);
        }
        ~VectorBA (void) {
            for (size_t i = 0; i < size(); i++) {
                ba_free(at(i));
            }
        }
    };  //  end class VectorBA

}   //  end namespace UapkiNS


#endif
