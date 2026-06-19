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

#include <stdio.h>
#include "byte-array.h"
#include "cm-api.h"
#include "cm-cryptoki.h"
#include "cm-cryptoki-debug.h"
#include "parson-helper.h"
#define CM_LIBRARY
#include "cm-export.h"


#define DEBUG_OUTPUT(msg)
#ifndef DEBUG_OUTPUT
DEBUG_OUTPUT_FUNC
#define DEBUG_OUTPUT(msg) debug_output(DEBUG_OUTSTREAM_DEFAULT, msg);
#endif


static CmCryptoki* cm_cryptoki = nullptr;


#ifdef __cplusplus
extern "C" {
#endif


CM_EXPORT CM_ERROR provider_info (
        CM_JSON_PCHAR* providerInfo
)
{
    DEBUG_OUTPUT("provider_info()");
    return CmCryptoki::providerInfoToJson(providerInfo);
}

CM_EXPORT CM_ERROR provider_init (
        CM_JSON_PCHAR providerParams
)
{
    DEBUG_OUTPUT("provider_init()");
    CM_ERROR cm_err = RET_CM_GENERAL_ERROR;
    if (!cm_cryptoki) {
        ParsonHelper json;
        JSON_Object* jo_params = nullptr;
        if (providerParams) {
            jo_params = json.parse((const char*)providerParams);
            if (!jo_params) return RET_CM_INVALID_JSON;
        }

        cm_cryptoki = new CmCryptoki();
        if (cm_cryptoki) {
            cm_err = cm_cryptoki->init(jo_params);
            if (cm_err != RET_OK) {
                delete cm_cryptoki;
                cm_cryptoki = nullptr;
            }
        }
    }
    else {
        cm_err = RET_CM_ALREADY_INITIALIZED;
    }
    return cm_err;
}

CM_EXPORT CM_ERROR provider_deinit (void)
{
    DEBUG_OUTPUT("provider_deinit()");
    CM_ERROR cm_err = RET_OK;
    if (cm_cryptoki) {
        delete cm_cryptoki;
        cm_cryptoki = nullptr;
    }
    else {
        cm_err = RET_CM_NOT_INITIALIZED;
    }
    return cm_err;
}

CM_EXPORT CM_ERROR provider_list_storages (
        CM_JSON_PCHAR* jsonList
)
{
    DEBUG_OUTPUT("provider_list_storages()");
    return (cm_cryptoki) ? cm_cryptoki->listStorages(jsonList) : RET_CM_NOT_INITIALIZED;
}

CM_EXPORT CM_ERROR provider_storage_info (
    const char* storageId,
    CM_JSON_PCHAR* jsonInfo
)
{
    DEBUG_OUTPUT("provider_storage_info()");
    return (cm_cryptoki) ? cm_cryptoki->storageInfo(storageId, jsonInfo) : RET_CM_NOT_INITIALIZED;
}

CM_EXPORT CM_ERROR provider_open (
        const char* storageId,
        uint32_t openMode,
        const CM_JSON_PCHAR openParams,
        CM_SESSION_API** session
)
{
    DEBUG_OUTPUT("provider_open()");
    return (cm_cryptoki)
        ? cm_cryptoki->open(
            storageId,
            openMode,
            openParams,
            session
        )
        : RET_CM_NOT_INITIALIZED;
}

CM_EXPORT CM_ERROR provider_close (
        CM_SESSION_API* session
)
{
    DEBUG_OUTPUT("provider_close()");
    return (cm_cryptoki) ? cm_cryptoki->close(session) : RET_CM_NOT_INITIALIZED;
}

CM_EXPORT void block_free (
        void* ptr
)
{
    ::free(ptr);
}

CM_EXPORT void bytearray_free (
        CM_BYTEARRAY* ba
)
{
    if (ba) {
        ba_free((ByteArray*)ba);
    }
}


#ifdef __cplusplus
}
#endif
