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

#ifndef DOC_SIGNFLOW_H
#define DOC_SIGNFLOW_H

#include "uapkic.h"
#include "uapkif.h"
#include "cer-store.h"
#include <string>
#include <vector>


using namespace  std;


enum class SIGNATURE_FORMAT {
    CADES_UNDEFINED     = 0,
    CADES_BES           = 1,
    CADES_T             = 2,
    CADES_C             = 3,
    CADES_Av3           = 4,
    //  specified
    CMS_SID_KEYID       = 10,
    RAW                 = 11
};


struct SignParams {
    SIGNATURE_FORMAT signatureFormat;
    HashAlg digestHashAlgo;
    HashAlg signHashAlgo;
    string digestAlgo;  //  for digest-message, tsp, ess-cert; by default use digestAlgo from signAlgo
    string signAlgo;
    const CerStore::Item* cerStoreItem;
    ByteArray* baKeyId;
    bool detachedData;
    bool includeCert;
    bool includeTime;
    bool includeContentTS;
    bool includeSignatureTS;
    bool sidUseKeyId;
    ByteArray* baEssCertId;
    ByteArray* baSignPolicy;

    SignParams (void)
    : signatureFormat(SIGNATURE_FORMAT::CADES_UNDEFINED)
    , digestHashAlgo(HashAlg::HASH_ALG_UNDEFINED), signHashAlgo(HashAlg::HASH_ALG_UNDEFINED)
    , cerStoreItem(nullptr), baKeyId(nullptr)
    , detachedData(true), includeCert(false), includeTime(false)
    , includeContentTS(false), includeSignatureTS(false)
    , sidUseKeyId(false), baEssCertId(nullptr), baSignPolicy(nullptr)
    {}
    ~SignParams (void) {
        signatureFormat = SIGNATURE_FORMAT::CADES_UNDEFINED;
        ba_free(baKeyId);
        ba_free(baEssCertId);
        ba_free(baSignPolicy);
    }
};  //  end struct SignParams

struct DocAttr {
    const char* type;   //  reference
    ByteArray*  baValue;

    DocAttr (void)
        : type(nullptr), baValue(nullptr) {}
    explicit DocAttr (const char* iType, ByteArray* iValue)
        : type(iType), baValue(iValue) {}
    ~DocAttr (void) {
        ba_free(baValue);
    }
};  //  end struct DocAttr

struct SigningDoc {
    const SignParams*   signParams; //  ref
    const char*         id;         //  ref
    bool                isDigest;
    ByteArray*          baData;
    ByteArray*          baMessageDigest;
    ByteArray*          baSignedAttrs;
    ByteArray*          baHashSignedAttrs;
    ByteArray*          baSignature;
    ByteArray*          baUnsignedAttrs;
    ByteArray*          baEncoded;  //  in case RAW-format store value signature
    vector<DocAttr*>    signedAttrs;
    vector<DocAttr*>    unsignedAttrs;

    SigningDoc (void)
    : signParams(nullptr), id(nullptr)
    , isDigest(false), baData(nullptr), baMessageDigest(nullptr)
    , baSignedAttrs(nullptr), baHashSignedAttrs(nullptr), baSignature(nullptr), baUnsignedAttrs(nullptr)
    , baEncoded(nullptr)
    {}

    ~SigningDoc (void)
    {
        ba_free(baData);
        ba_free(baMessageDigest);
        ba_free(baSignedAttrs);
        ba_free(baHashSignedAttrs);
        ba_free(baSignature);
        ba_free(baUnsignedAttrs);
        ba_free(baEncoded);
        for (auto& it : signedAttrs) {
            delete it;
        }
        for (auto& it : unsignedAttrs) {
            delete it;
        }
    }

    int init (const SignParams* iSignParams, const char* iId, ByteArray* iData);
    int buildSignedAttributes (void);
    int buildSignedData (void);
    int buildUnsignedAttributes (void);
    int digestMessage (void);
    int digestSignature (ByteArray** baHash);
    int digestSignedAttributes (void);

};  //  end struct SigningDoc


#endif
