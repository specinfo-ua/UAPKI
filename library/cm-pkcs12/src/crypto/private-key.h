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

//  Last update: 2021-03-01

#ifndef CM_PRIVATE_KEY_H
#define CM_PRIVATE_KEY_H

#include "uapkic.h"
#include "cm-export.h"

#ifdef __cplusplus
extern "C" {
#endif

int private_key_generate(const char* alg, const char* param, ByteArray** key);
int private_key_get_info(const ByteArray* key, char** alg, char** param);
int private_key_get_spki(const ByteArray* key, ByteArray** spki);

int spki_get_key_id(const ByteArray* spki, ByteArray** key_id);
int spki_get_algo_param(const ByteArray* baSpki, char** algo, char** algoParam);
int spki_get_pubkey(const ByteArray* baSpki, ByteArray** baPubkey);
int spki_get_dstu_dke(const ByteArray* baSpki, ByteArray** baDKE);

int private_key_sign_check(const ByteArray* key, const char* signAlgo, const ByteArray* signAlgoParams, HashAlg* hashAlgo);
int private_key_sign_single(const ByteArray* key, const char* signAlgo, const ByteArray* signAlgoParams,
        const ByteArray* hash, ByteArray** signature);
int private_key_sign(const ByteArray* key, const ByteArray** hashes, size_t hashes_count,
        const char* signAlgo, const ByteArray* signAlgoParams, ByteArray*** signatures);
int private_key_ecdh(const bool withCofactor, const ByteArray* baSenderKey,
        const ByteArray* baRecipientSpki, ByteArray** baCommonSecret);

int keyid_by_cert (const ByteArray * baCert, ByteArray ** baKeyId);
int keyid_by_privkeyinfo (const ByteArray * baPrivateKeyInfo, ByteArray ** baKeyId);
int spki_by_privkeyinfo (const ByteArray * baPrivateKeyInfo, ByteArray ** baAlgoId, ByteArray ** baPubkey);


#ifdef __cplusplus
}
#endif

#endif
