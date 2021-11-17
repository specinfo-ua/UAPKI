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

//  Last update: 2021-03-20

#ifndef CM_PKCS5_H
#define CM_PKCS5_H


#include "byte-array.h"
#include "cm-export.h"
#include "uapkic.h"
#include "uapkif.h"


#ifdef __cplusplus
extern "C" {
#endif


typedef enum {
    DIRECTION_ENCRYPT = 0,
    DIRECTION_DECRYPT = 1
} CryptDirection;

int pbes1_crypt(CryptDirection direction, const PBKDF2_params_t * params, const char * pass,
    const ByteArray* data, ByteArray** crypted);

int pbes2_crypt(CryptDirection direction, const PBES2_params_t * params, const char * pass,
    const ByteArray *data, ByteArray **crypted);

int pkcs8_decrypt(const ByteArray * container, const char * pass, ByteArray ** key, char ** oidKdf, char ** oidCipher);

int pkcs8_pbes2_encrypt(const ByteArray * key, const char * pass, size_t iterations, 
    const char * kdf_oid, const char * cipher_oid, ByteArray ** container);


#ifdef __cplusplus
}
#endif

#endif
