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

#include <string.h>
#include "cm-pkcs12-ctx.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
    #define DEBUG_OUTCON(expression) expression
#endif


SessionPkcs12Context::SessionPkcs12Context (void)
    : activeBag(nullptr)
    , ctxHash(nullptr)
    , hashAlgo(HASH_ALG_UNDEFINED)
    , signAlgoParam(nullptr)
{
    DEBUG_OUTCON( printf("SessionPkcs12Context::SessionPkcs12Context()\n"); )
    memset(&keyApi, 0, sizeof(CM_KEY_API));
}

SessionPkcs12Context::~SessionPkcs12Context (void)
{
    DEBUG_OUTCON( printf("SessionPkcs12Context::~SessionPkcs12Context()\n"); )
    resetSignLong();
}

void SessionPkcs12Context::resetSignLong (void)
{
    activeBag = nullptr;
    if (ctxHash) {
        hash_free(ctxHash);
        ctxHash = nullptr;
    }
    hashAlgo = HASH_ALG_UNDEFINED;
    signAlgo.clear();
    ba_free(signAlgoParam);
    signAlgoParam = nullptr;
}
