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

#ifndef UAPKI_CERTREQ_BUILDER_H
#define UAPKI_CERTREQ_BUILDER_H


#include "uapki-ns.h"
#include "uapkif.h"


namespace UapkiNS {


class CertReqBuilder {
    CertificationRequestInfo_t*
                m_TbsCsrInfo;
    std::string m_KeyAlgo;
    SmartBA     m_TbsEncoded;
    SmartBA     m_CsrEncoded;

public:
    CertReqBuilder (void);
    ~CertReqBuilder (void);

    int init (
        const uint32_t version = 1
    );
    int init (
        const ByteArray* tbsEncoded
    );
    int setSubject (
        const ByteArray* nameEncoded
    );
    int setSubject (
        const std::vector<UapkiNS::RdName>& rdNames
    );
    int setSubjectPublicKeyInfo (
        const ByteArray* spkiEncoded
    );
    int setSubjectPublicKeyInfo (
        const ByteArray* algoIdEncoded,
        const ByteArray* publicKey
    );
    int setSubjectPublicKeyInfo (
        const UapkiNS::AlgorithmIdentifier& algorithm,
        const ByteArray* publicKey
    );
    int addExtensions (
        const ByteArray* extensionsEncoded
    );
    int addExtensions (
        const std::vector<UapkiNS::Extension>& extensions
    );
    int addExtensions (
        const std::vector<ByteArray*>& vbaEncodedExtensions
    );
    const std::string& getKeyAlgo (void) const {
        return m_KeyAlgo;
    }

    int encodeTbs (void);
    const ByteArray* getTbsEncoded (void) const {
        return m_TbsEncoded.get();
    }

    int encodeCertRequest (
        const char* signAlgo,
        const ByteArray* signAlgoParam,
        const ByteArray* signature
    );
    int encodeCertRequest (
        const UapkiNS::AlgorithmIdentifier& aidSignature,
        const ByteArray* signature
    );
    ByteArray* getCsrEncoded (
        const bool move = false
    );

public:
    static int encodeExtensions (
        const std::vector<UapkiNS::Extension>& extensions,
        ByteArray** encoded
    );
    static int encodeExtensions (
        const std::vector<ByteArray*>& vbaEncodedExtensions,
        ByteArray** encoded
    );
    static int nameAddRdName (
        Name_t* name,
        const UapkiNS::RdName& rdName
    );

};  //  end class CertReqBuilder


}   //  end namespace UapkiNS

#endif
