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


#ifndef UAPKI_KEY_TRANS_H
#define UAPKI_KEY_TRANS_H

#include "uapkic.h"
#include "cm-export.h"

#ifdef __cplusplus
extern "C" {
#endif

//  Key transport with RSA (RFC 8017): rsaEncryption - RSAES-PKCS1-v1_5 (RFC 3370, 4.2.1),
//  id-RSAES-OAEP - RSAES-OAEP with RSAES-OAEP-params (RFC 3560, RFC 4055 section 4)

//  The algorithm of an encoded AlgorithmIdentifier: isOaep, the hash and the label of OAEP.
//  MGF1 must have the same hash as the label hash - otherwise RET_CM_UNSUPPORTED_ALG
int key_trans_parse_algo (const char* oid, const ByteArray* baParams,
        bool* isOaep, HashAlg* hashAlgo, ByteArray** baLabel);

int key_trans_decode_algid (const ByteArray* baAlgorithmIdentifier,
        char** oid, ByteArray** baParams);

//  RSAES-OAEP-params: the hash, MGF1 with the same hash, the empty label
int key_trans_encode_oaep_params (const HashAlg hashAlgo, ByteArray** baParams);

//  Encryption of a key for the public key of baSpki (rsaEncryption)
int key_trans_encrypt (const ByteArray* baSpki, const char* oid, const ByteArray* baParams,
        const ByteArray* baKey, ByteArray** baEncryptedKey);

//  Decryption by the modulus and the private exponent
int key_trans_decrypt (const ByteArray* baModulus, const ByteArray* baPrivateExponent,
        const char* oid, const ByteArray* baParams,
        const ByteArray* baEncryptedKey, ByteArray** baKey);

#ifdef __cplusplus
}
#endif

#endif
