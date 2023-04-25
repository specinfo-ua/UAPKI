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

 //  Last update: 2023-04-25

#ifndef UAPKI_UTILS_H
#define UAPKI_UTILS_H


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

    int decodePkixTime (
        const ByteArray* baEncoded,
        uint64_t& msTime
    );
    int encodeGenTime (
        const uint64_t msTime,
        ByteArray** baEncoded
    );
    int encodePkixTime (
        const PKIXTime_PR frmTime,
        const uint64_t msTime,
        ByteArray** baEncoded
    );
    int encodeUtcTime (
        const uint64_t msTime,
        ByteArray** baEncoded
    );

    int pkixTimeFromAsn1 (
        const PKIXTime_t* pkixTime,
        uint64_t& msTime
    );

}   //  end namespace Util

}   //  end namespace UapkiNS


#endif
