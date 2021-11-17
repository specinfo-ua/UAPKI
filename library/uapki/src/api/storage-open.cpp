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

#include "api-json-internal.h"

#undef FILE_MARKER
#define FILE_MARKER "api/storage-open.cpp"

// "method": "OPEN"
// "parameters": {"provider":"PKCS12", "storage":"test.p12", "password":"testpassword", "mode":"RO/RW/CREATE"}
// out: {"mechanisms":[{"id":"ECDSA", "description":"ECDSA", "parameters":[{"id":"P256", "description":"NIST P256 curve"},{...}],{...}]}, "user_presense":false}

int uapki_storage_open(JSON_Object* joParams, JSON_Object* joResult)
{
    const char* provider_id = json_object_get_string(joParams, "provider");
    const char* storage_id = json_object_get_string(joParams, "storage");
    if (!provider_id || !storage_id) return RET_UAPKI_INVALID_PARAMETER;

    int ret = CmProviders::storageOpen(provider_id, storage_id, joParams);
    if (ret != RET_OK) return ret;

    ret = CmProviders::sessionInfo(joResult);
    if (ret != RET_OK) {
        CmProviders::storageClose();
        return ret;
    }

    //TODO: add certs from storage to cache

    return ret;
}
