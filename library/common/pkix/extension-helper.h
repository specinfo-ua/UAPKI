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

#ifndef UAPKI_EXTENSION_HELPER_H
#define UAPKI_EXTENSION_HELPER_H


#include "byte-array.h"
#include "Extension.h"
#include "Extensions.h"
#include "parson.h"
#include <string>
#include <vector>


namespace UapkiNS {

namespace ExtensionHelper {


int addOcspNonce (
    Extensions_t* extns,
    const ByteArray* baNonce
);
int addSubjectKeyId (
    Extensions_t* extns,
    const ByteArray* baSubjectKeyId
);

int decodeAccessDescriptions (
    const ByteArray* baEncoded,
    const char* oidAccessMethod,
    std::vector<std::string>& uris
);
int decodeDistributionPoints (
    const ByteArray* baEncoded,
    std::vector<std::string>& uris
);

int getAuthorityKeyId (
    const Extensions_t* extns,
    ByteArray** baKeyId
);
int getBasicConstrains (
    const Extensions_t* extns,
    bool& cA,
    int& pathLenConstraint
);
int getCrlInvalidityDate (
    const Extensions_t* extns,
    uint64_t& invalidityDate
);
int getCrlNumber (
    const Extensions_t* extns,
    ByteArray** baCrlNumber
);
int getCrlReason (
    const Extensions_t* extns,
    uint32_t& crlReason
);
int getCrlUris (
    const Extensions_t* extns,
    const char* oidExtnId,
    std::vector<std::string>& uris
);
int getDeltaCrlIndicator (
    const Extensions_t* extns,
    ByteArray** baDeltaCrlIndicator
);
int getKeyUsage (
    const Extensions_t* extns,
    uint32_t& keyUsage
);
int getOcspNonce (
    const Extensions_t* extns,
    ByteArray** baNonce
);
int getOcspUris (
    const Extensions_t* extns,
    std::vector<std::string>& uris
);
int getSubjectDirectoryAttributes (
    const Extensions_t* extns,
    const char* oidType,
    ByteArray** baEncoded
);
int getSubjectKeyId (
    const Extensions_t* extns,
    ByteArray** baKeyId
);
int getTspUris (
    const Extensions_t* extns,
    std::vector<std::string>& uris
);


}   //  end namespace ExtensionHelper

}   //  end namespace UapkiNS

#endif
