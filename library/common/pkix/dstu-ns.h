//  Last update: 2021-11-29

#ifndef UAPKI_DSTU_NS_H
#define UAPKI_DSTU_NS_H


#include "byte-array.h"
#include "uapkif.h"


namespace DstuNS {

    int ba2BitStringEncapOctet (const ByteArray* baData, BIT_STRING_t* bsEncapOctet);
    int calcKeyId (const ByteArray* baPubkey, ByteArray** baKeyId);
    bool isDstu4145family (const char* algo);

}   //  end namespace DstuNS

#endif
