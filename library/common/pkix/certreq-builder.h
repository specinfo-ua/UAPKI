/*
 * Copyright (c) 2022, The UAPKI Project Authors.
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

#ifndef UAPKI_NS_CERTREQ_BUILDER_H
#define UAPKI_NS_CERTREQ_BUILDER_H


#include "uapki-ns.h"
#include "uapkif.h"


using namespace std;


namespace UapkiNS {


class CertReqBuilder {
    CertificationRequestInfo_t*
                m_TbsCsrInfo;
    string      m_KeyAlgo;
    ByteArray*  m_BaTbsEncoded;
    ByteArray*  m_BaCsrEncoded;

public:
    CertReqBuilder (void);
    ~CertReqBuilder (void);

    int init (const uint32_t version = 1);
    int setSubject (const ByteArray* baNameEncoded);
    int setSubject (const vector<UapkiNS::RdName>& rdNames);
    int setSubjectPublicKeyInfo (const ByteArray* baSpkiEncoded);
    int setSubjectPublicKeyInfo (const ByteArray* baAlgoId, const ByteArray* baSubjectPublicKey);
    int setSubjectPublicKeyInfo (const UapkiNS::AlgorithmIdentifier& algorithm, const ByteArray* baSubjectPublicKey);
    int addExtensions (const vector<UapkiNS::Extension>& extensions);
    const string& getKeyAlgo (void) const { return m_KeyAlgo; }

    int encodeTbs (void);
    const ByteArray* getTbsEncoded (void) const { return m_BaTbsEncoded; }

    int encodeCertRequest (const char* signAlgo, const ByteArray* baSignAlgoParam, const ByteArray* baSignature);
    int encodeCertRequest (const UapkiNS::AlgorithmIdentifier& aidSignature, const ByteArray* baSignature);
    ByteArray* getCsrEncoded (const bool move = false);

public:
    static int encodeExtensions (const vector<UapkiNS::Extension>& extensions, ByteArray** baEncoded);
    static int nameAddRdName (Name_t* name, const UapkiNS::RdName& rdName);

};  //  end class CertReqBuilder


}   //  end namespace UapkiNS

#endif
