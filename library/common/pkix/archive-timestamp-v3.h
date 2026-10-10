/*
 * Copyright (c) 2026, The UAPKI Project Authors.
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

#ifndef UAPKI_NS_ARCHIVE_TIMESTAMP_V3_H
#define UAPKI_NS_ARCHIVE_TIMESTAMP_V3_H


#include "SignerInfo.h"
#include "byte-array.h"
#include "hash.h"
#include "uapki-ns.h"
#include <string>


namespace UapkiNS {

namespace Pkcs7 {

//  archive-time-stamp-v3 with its hash index in the time-stamp token: ats-hash-index (ETSI TS 101 733 V2.2.1,
//  6.4.2 and 6.4.3; CAdES-A) or ats-hash-index-v3 (ETSI EN 319 122-1, 5.5.2 and 5.5.3; CAdES-B-LTA)
namespace AtsV3 {

    enum class IndexType : uint32_t {
        TS_101_733  = 1,    //  ats-hash-index: the hash of each unsigned Attribute; hashIndAlgorithm DEFAULT sha256
        EN_319_122  = 2     //  ats-hash-index-v3: the hash of attrType || AttributeValue for each value
    };

    //  The OID of the attribute of the index in the time-stamp token
    const char* indexAttrType (
        const IndexType indexType
    );

    //  ATSHashIndex / ATSHashIndexV3 (DER): the hashes of the CertificateChoices of SignedData.certificates, of the
    //  RevocationInfoChoice of SignedData.crls and, for each AttributeValue of the unsigned attributes of the
    //  SignerInfo, of attrType || AttributeValue (5.5.2)
    int buildHashIndex (
        const IndexType indexType,
        const std::string& hashIndAlgorithm,
        const VectorBA& certs,
        const VectorBA& crls,
        const SignerInfo_t* signerInfo,
        ByteArray** baHashIndex
    );
    //  Every hash of the index has its value in the signature (5.5.2: otherwise the index is invalid)
    int checkHashIndex (
        const IndexType indexType,
        const ByteArray* baHashIndex,
        const VectorBA& certs,
        const VectorBA& crls,
        const SignerInfo_t* signerInfo,
        bool& isValid
    );
    //  The message imprint (5.5.3): eContentType || the hash of the signed data || the fields version, sid,
    //  digestAlgorithm, signedAttrs, signatureAlgorithm, signature of the SignerInfo || ATSHashIndex(V3)
    int calcMessageImprint (
        const HashAlg hashAlg,
        const std::string& contentType,
        const ByteArray* baHashContent,
        const SignerInfo_t* signerInfo,
        const ByteArray* baHashIndex,
        ByteArray** baHash
    );

}   //  end namespace AtsV3

}   //  end namespace Pkcs7

}   //  end namespace UapkiNS


#endif
