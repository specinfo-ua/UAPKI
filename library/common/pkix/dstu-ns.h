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

//  Last update: 2023-02-28

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
