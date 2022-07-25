//  Last update: 2022-07-23

#ifndef UAPKI_NS_UTIL_H
#define UAPKI_NS_UTIL_H


#include "uapki-ns.h"
#include "uapkif.h"


namespace UapkiNS {

namespace Util {

    int algorithmIdentifierFromAsn1 (const AlgorithmIdentifier_t& asn1, AlgorithmIdentifier& algoId);
    int algorithmIdentifierToAsn1 (const AlgorithmIdentifier& algoId, AlgorithmIdentifier_t& asn1);
    int attributeFromAsn1 (const Attribute_t& asn1, Attribute& attr);
    int attributeToAsn1 (const Attribute& attr, Attribute_t& asn1);

}   //  end namespace Util

}   //  end namespace UapkiNS


#endif
