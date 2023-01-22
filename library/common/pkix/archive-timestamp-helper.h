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

#ifndef UAPKI_NS_ARCHIVE_TIMESTAMP_HELPER_H
#define UAPKI_NS_ARCHIVE_TIMESTAMP_HELPER_H


#include "SignerInfo.h"
#include "byte-array.h"
#include "attribute-helper.h"
#include "hash.h"
#include "uapki-ns.h"


namespace UapkiNS {

namespace Pkcs7 {

    class ArchiveTs3Helper {
        const AlgorithmIdentifier*
                    m_HashIndAlgorithm;
        HashAlg     m_HashAlgo;
        struct ATSHashIndex {
            VectorBA    certHashes;
            VectorBA    crlHashes;
            VectorBA    unsignedAttrHashes;
        }           m_ATSHashIndex;
        struct {
            SmartBA     contentType;
            SmartBA     hashContent;
            SmartBA     signerInfo;
            SmartBA     atsHashIndex;
        }           m_Parts;
        SmartBA     m_HashValue;

    public:
        ArchiveTs3Helper (void);
        ~ArchiveTs3Helper (void);

        int init (
            const AlgorithmIdentifier* hashIndAlgorithm
        );

        //  Step 1: SignedData
        int setHashContent (
            const std::string& contentType,
            const ByteArray* baHashContent
        );
        //  Step 2: SignerInfo
        int setSignerInfo (
            const SignerInfo_t* signerInfo
        );
        //  Step 3: ATSHashIndex (data of SignedData and SignerInfo)
        int setUnsignedAttrs (
            const SignerInfo_t* signerInfo
        );
        int addCertificate (
            const ByteArray* baCertEncoded
        );
        int addCrl (
            const ByteArray* baCrlEncoded
        );
        int addUnsignedAttr (
            const ByteArray* baAttrEncoded
        );

        int calcHash (void);

        const ByteArray* getHashValue (void) const { return m_HashValue.get(); }
        bool isEnabled (void) const { return (m_HashAlgo != HASH_ALG_UNDEFINED); }

    private:
        int hashAndAdd (
            VectorBA& hashes,
            const ByteArray* baData
        );

    };  //  ArchiveTs3Helper

}   //  end namespace Pkcs7

}   //  end namespace UapkiNS


#endif
