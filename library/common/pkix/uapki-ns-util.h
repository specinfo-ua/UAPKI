//  Last update: 2022-07-27

#ifndef UAPKI_NS_UTIL_H
#define UAPKI_NS_UTIL_H


#include "uapki-ns.h"
#include "uapkif.h"


namespace UapkiNS {

namespace Util {

    int algorithmIdentifierFromAsn1 (const AlgorithmIdentifier_t& asn1, UapkiNS::AlgorithmIdentifier& algoId);
    int algorithmIdentifierToAsn1 (AlgorithmIdentifier_t& asn1, const char* algo, const ByteArray* baParams);
    int algorithmIdentifierToAsn1 (AlgorithmIdentifier_t& asn1, const UapkiNS::AlgorithmIdentifier& algoId);
    int attributeFromAsn1 (const Attribute_t& asn1, UapkiNS::Attribute& attr);
    int attributeToAsn1 (Attribute_t& asn1, const char* type, const ByteArray* baValues);
    int attributeToAsn1 (Attribute_t& asn1, const UapkiNS::Attribute& attr);
    int addToAttributes (Attributes_t* attrs, const char* type, const ByteArray* baValues);
    int addToAttributes (Attributes_t* attrs, const UapkiNS::Attribute& attr);

}   //  end namespace Util

}   //  end namespace UapkiNS


#endif
