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

#ifndef UAPKI_VERIFY_SIGNER_INFO_H
#define UAPKI_VERIFY_SIGNER_INFO_H


#include "uapkic.h"
#include "uapkif.h"
#include "cer-store.h"
#include "tsp-utils.h"
#include "verify-status.h"
#include <vector>


using namespace std;


typedef struct AttrItem_ST
{
    const char* attrType;
    ByteArray*  baAttrValue;
    AttrItem_ST (void)
        : attrType(NULL), baAttrValue(NULL)
    {}
    ~AttrItem_ST (void)
    {
        ::free((char*)attrType);
        attrType = NULL;
        ba_free(baAttrValue);
        baAttrValue = NULL;
    }
} AttrItem;

typedef struct AttrTimeStamp_ST
{
    const char* policy;
    const char* hashAlgo;
    ByteArray*  baHashedMessage;
    uint64_t    msGenTime;
    SIGNATURE_VERIFY::STATUS
                statusDigest;
    SIGNATURE_VERIFY::STATUS
                statusSign;

    AttrTimeStamp_ST (void);
    ~AttrTimeStamp_ST (void);
    int checkEqual (const ByteArray* baData);
} AttrTimeStamp;

typedef struct VerifyInfo_ST {
    const CerStore::Item*
                    cerStoreItem;
    vector<AttrItem>
                    signedAttrs;
    vector<AttrItem>
                    unsignedAttrs;
    SIGNATURE_VERIFY::STATUS
                    statusSignature;
    SIGNATURE_VERIFY::STATUS
                    statusMessageDigest;
    SIGNATURE_VERIFY::STATUS
                    statusEssCert;
    uint64_t        signingTime;
    AttrTimeStamp*  contentTS;
    AttrTimeStamp*  signatureTS;

    VerifyInfo_ST (void);
    ~VerifyInfo_ST (void);
} VerifyInfo;


int verify_signer_info (const SignerInfo_t* signerInfo, const vector<char*>& dgstAlgos,
                const ByteArray* baContent, const bool isDigest, VerifyInfo* verifyInfo);


#endif
