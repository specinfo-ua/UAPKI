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

#ifndef UAPKI_KEY_WRAP_H
#define UAPKI_KEY_WRAP_H

#include "uapkic.h"
#include "cm-export.h"

#ifdef __cplusplus
extern "C" {
#endif

int key_wrap (const ByteArray* baPrivateKeyInfo, bool isStaticKey,
        const char* oidDhKdf, const char* oidWrapAlgo,
        const size_t count, const ByteArray** baSpkis, const ByteArray** baSessionKeys,
        ByteArray*** baSalts, ByteArray*** baWrappedKeys);

int key_unwrap (const ByteArray* baPrivateKeyInfo,
        const char* oidDhKdf, const char* oidWrapAlgo,
        const size_t count, const ByteArray** baSpkis, const ByteArray** baSalts,
        const ByteArray** baWrappedKeys, ByteArray*** baSessionKeys);

#ifdef __cplusplus
}
#endif

#endif
