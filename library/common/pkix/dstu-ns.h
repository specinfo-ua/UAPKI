//  Last update: 2022-04-21

#ifndef UAPKI_DSTU_NS_H
#define UAPKI_DSTU_NS_H


#include "byte-array.h"
#include "uapkif.h"
#include <string>


namespace DstuNS {

    int ba2BitStringEncapOctet (const ByteArray* baData, BIT_STRING_t* bsEncapOctet);
    int calcKeyId (const ByteArray* baPubkey, ByteArray** baKeyId);
    bool isDstu4145family (const char* algo);
    bool isDstu4145family (const std::string& algo);

    namespace Dstu4145 {
        int decodeParams (const ByteArray* baEncoded, std::string& oidNamedCurve);
        int encodeParams (const std::string& oidNamedCurve, const ByteArray* baDKE, ByteArray** baEncoded);

    }   //  end namespace Dstu4145

}   //  end namespace DstuNS

#endif
