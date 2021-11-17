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

//  Last update: 2021-11-02

#ifndef CMS_UTILS_H
#define CMS_UTILS_H


#include "uapkic.h"
#include "uapkif.h"
#include "common.h"


#ifdef __cplusplus
extern "C" {
#endif


int create_signer_info (uint32_t version, const ByteArray* baSID, const char* digestAlgo, const ByteArray* baSignedAttrs,
        const SignatureParams* signatureParams, const ByteArray* baUnsignedAttrs, SignerInfo_t** signerInfo);
int create_signed_data (uint32_t version, const ByteArray* baContent, const ByteArray* baCert, const SignerInfo_t* signerInfo,
        SignedData_t** signedData);
int create_std_signed_attrs (const char* contentType, const ByteArray* baMessageDigest, const uint64_t signingTime,
        Attributes_t** signedAttrs);
int encode_signed_data (const SignedData_t* sdata, ByteArray** baEncoded);
int gen_attrvalue_ess_certid_v2(const HashAlg hashAlgo, const ByteArray* baCert, ByteArray** baEncoded);
int keyid_to_sid_subjectkeyid (const ByteArray* baKeyId, ByteArray** baSubjectKeyId);


#ifdef __cplusplus
}
#endif


#endif
