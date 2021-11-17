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

#ifndef UAPKI_VERIFY_UTILS_H
#define UAPKI_VERIFY_UTILS_H


#include "uapkic.h"
#include "uapkif.h"
#include "oid-utils.h"


#ifdef __cplusplus
extern "C" {
#endif


int parse_spki (const ByteArray* baSignerSPKI, SignAlg* keyAlgo, EcParamsId* ecParamsId, ByteArray** baPubkey, ByteArray** baPubkeyRsaE);
int verify_ec_sign (const SignAlg signAlgo, const EcParamsId ecParamId,
        const ByteArray* baPubkey, const ByteArray* baHash, const ByteArray* baSignValue);
int verify_rsa_v15_sign (const HashAlg hashAlgo, const ByteArray* baPubkeyN, const ByteArray* baPubkeyE,
        const ByteArray* baHash, const ByteArray* baSignValue);
int verify_signature (const char* signAlgo, const ByteArray* baData, const bool isHash,
        const ByteArray* baSignerSPKI, const ByteArray* baSignValue);


#ifdef __cplusplus
}
#endif


#endif
