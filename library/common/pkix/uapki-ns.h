//  Last update: 2022-01-06

#ifndef UAPKI_NS_H
#define UAPKI_NS_H


#include <string>
#include <vector>
#include "byte-array.h"


using namespace std;


namespace UapkiNS {

    enum class CertStatus : uint32_t {
        GOOD        = 0,
        REVOKED     = 1,
        UNKNOWN     = 2,
        UNDEFINED   = 3
    };  //  end enum class CertStatus

    enum class CrlReason : uint32_t {
        //  CRLReason ::= ENUMERATED    -- rfc5280 $5.3.1, z1400-12 $3.8.1 --
        UNSPECIFIED             = 0,
        KEY_COMPROMISE          = 1,
        CA_COMPROMISE           = 2,
        AFFILIATION_CHANGED     = 3,
        SUPERSEDED              = 4,
        CESSATION_OF_OPERATION  = 5,
        CERTIFICATE_HOLD        = 6,
        //  -- value 7 is not used
        REMOVE_FROM_CRL         = 8,
        PRIVILEGE_WITHDRAWN     = 9,
        AA_COMPROMISE           = 10,
        UNDEFINED               = 11
    };  //  end enum class CrlReason

    struct AlgorithmIdentifier {
        string      algorithm;
        ByteArray*  baParameters;

        AlgorithmIdentifier (void)
            : baParameters(nullptr) {
        }
        explicit AlgorithmIdentifier (const string& iAlgorithm, const ByteArray* iParameters = nullptr)
            : algorithm(iAlgorithm), baParameters((ByteArray*)iParameters) {
        }
        ~AlgorithmIdentifier (void) {
            clear();
        }
        void clear (void) {
            algorithm.clear();
            ba_free(baParameters);
        }
        bool isPresent (void) const {
            return (!algorithm.empty());
        }
    };  //  end struct AlgorithmIdentifier

    struct Attribute {
        string      type;
        ByteArray*  baValues;

        Attribute (void)
            : baValues(nullptr) {
        }
        ~Attribute (void) {
            clear();
        }
        void clear (void) {
            type.clear();
            ba_free(baValues);
        }
        bool isPresent(void) const {
            return (!type.empty());
        }
    };  //  end struct Attribute

    struct Extension {
        string      extnId;
        bool        critical;
        ByteArray*  baExtnValue;

        Extension (void)
            : critical(false), baExtnValue(nullptr) {
        }
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

        string  type;
        StringType
                stringType;
        string  value;

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
        ByteArray*& operator* (void) { return m_Ba; }
        ByteArray** operator& (void) { return &m_Ba; }
        uint8_t* buf (void) const { return ba_get_buf(m_Ba); }
        ByteArray* get (void) const { return m_Ba; }
        void clear (void) {
            ba_free(m_Ba);
            m_Ba = nullptr;
        }
        bool reset (ByteArray* ba) {
            clear();
            m_Ba = ba;
            return (m_Ba != nullptr);
        }
        bool set (ByteArray* ba) {
            m_Ba = ba;
            return (m_Ba != nullptr);
        }
        size_t size (void) const { return ba_get_len(m_Ba); }
    };  //  end class SmartBA

    class VectorBA : public vector<ByteArray*> {
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
