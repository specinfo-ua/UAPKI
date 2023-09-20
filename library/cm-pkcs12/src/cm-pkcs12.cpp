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

#include <stdlib.h>
#include <string.h>
#include "cm-api.h"
#include "cm-errors.h"
#include "cm-pkcs12.h"
#include "cm-pkcs12-ctx.h"
#include "file-storage.h"
#include "parson-ba-utils.h"
#include "parson-helper.h"
#include "uapki-errors.h"
#include "uapki-ns.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
    #define DEBUG_OUTCON(expression) expression
#endif


static CM_ERROR err_to_cmerror (int err)
{
    switch (err) {
    case RET_OK:                        return RET_OK;
    case RET_UAPKI_FILE_OPEN_ERROR:     return RET_CM_FILE_OPEN_ERROR;
    case RET_UAPKI_FILE_READ_ERROR:     return RET_CM_FILE_READ_ERROR;
    case RET_UAPKI_FILE_WRITE_ERROR:    return RET_CM_FILE_WRITE_ERROR;
    case RET_UAPKI_FILE_DELETE_ERROR:   return RET_CM_FILE_DELETE_ERROR;
    }
    return (CM_ERROR)err;
}   //  err_to_cmerror


CmPkcs12::CmPkcs12 (void)
{
    DEBUG_OUTCON(puts("CmPkcs12::CmPkcs12()"));
}

CmPkcs12::~CmPkcs12 (void)
{
    DEBUG_OUTCON(puts("CmPkcs12::~CmPkcs12()"));
}

CM_ERROR CmPkcs12::open (
        const char* fileName,
        uint32_t openMode,
        const CM_JSON_PCHAR openParams,
        CM_SESSION_API** session
)
{
    DEBUG_OUTCON(printf("CmPkcs12::open(fileName = '%s', openMode = %u)\n", fileName, openMode));
    if (!fileName || (strlen(fileName) == 0) || !session) return RET_CM_INVALID_PARAMETER;

    SessionPkcs12Context* ss_ctx = new SessionPkcs12Context();
    if (!ss_ctx) return RET_CM_GENERAL_ERROR;

    ss_ctx->fileStorage.storageParam().setDefault(&this->getDefaultParam());

    CM_ERROR cm_err = RET_CM_INVALID_PARAMETER;
    UapkiNS::SmartBA sba_pfx;

    switch (openMode) {
    case OPEN_MODE_RW:
    case OPEN_MODE_RO:
        if (strcmp(fileName, FILENAME_ON_MEMORY) == 0) {
            cm_err = CmPkcs12::parseBytes(openParams, &sba_pfx);
            if ((cm_err == RET_OK) && (sba_pfx.size() > 0)) {
                ss_ctx->fileStorage.loadFromBuffer(sba_pfx.get(), openMode == OPEN_MODE_RO);
                sba_pfx.set(nullptr);
            }
        }
        else {
            cm_err = err_to_cmerror(ss_ctx->fileStorage.loadFromFile(fileName, openMode == OPEN_MODE_RO));
        }
        break;
    case OPEN_MODE_CREATE:
        cm_err = CmPkcs12::parseConfig(openParams, ss_ctx->fileStorage.storageParam());
        if (cm_err == RET_OK) {
            ss_ctx->fileStorage.create(fileName);
        }
        break;
    default:
        break;
    }

    if (cm_err != RET_OK) {
        delete ss_ctx;
        return cm_err;
    }

    CM_SESSION_API* new_ss = (CM_SESSION_API*)calloc(1, sizeof(CM_SESSION_API));
    if (!new_ss) {
        delete ss_ctx;
        return RET_CM_GENERAL_ERROR;
    }

    CmPkcs12::assignSessionFunc(*new_ss);
    *((void**)&new_ss->ctx) = ss_ctx;
    CmPkcs12::assignKeyFunc(ss_ctx->keyApi);

    *session = new_ss;
    return RET_OK;
}

CM_ERROR CmPkcs12::close (
        CM_SESSION_API* session
)
{
    DEBUG_OUTCON(puts("CmPkcs12::close()"));
    if (session && session->ctx) {
        delete (SessionPkcs12Context*)session->ctx;
        ::free(session);
    }
    return RET_OK;
}

CM_ERROR CmPkcs12::parseBytes (
        const CM_JSON_PCHAR jsonParams,
        ByteArray** baEncoded
)
{
    if (!jsonParams) return RET_OK;

    ParsonHelper json;
    if (!json.parse((const char*)jsonParams)) return RET_CM_INVALID_JSON;

    if (!json.hasValue("bytes", JSONString)) return RET_CM_INVALID_PARAMETER;

    *baEncoded = json_object_get_base64(json.rootObject(), "bytes");

    return (*baEncoded) ? RET_OK : RET_CM_INVALID_JSON;
}

CM_ERROR CmPkcs12::parseConfig (
        const CM_JSON_PCHAR jsonParams,
        FileStorageParam& storageParam
)
{
    if (!jsonParams) return RET_OK;

    ParsonHelper json;
    if (!json.parse((const char*)jsonParams)) return RET_CM_INVALID_JSON;

    JSON_Object* jo_default = json.getObject("createPfx");
    if (jo_default) {
        storageParam.bagCipher = FileStorage::checkCipherOid(json_object_get_string(jo_default, "bagCipher"), nullptr);
        if (!storageParam.bagCipher) return RET_CM_UNSUPPORTED_CIPHER_ALG;
        storageParam.bagKdf = FileStorage::checkHashOid(json_object_get_string(jo_default, "bagKdf"), nullptr);
        if (!storageParam.bagKdf) return RET_CM_UNSUPPORTED_KEY_DERIVATION_FUNC_ALG;
        storageParam.macAlgo = FileStorage::checkHashOid(json_object_get_string(jo_default, "macAlgo"), nullptr);
        if (!storageParam.macAlgo) return RET_CM_UNSUPPORTED_MAC;
        storageParam.iterations = ParsonHelper::jsonObjectGetUint32(jo_default, "iterations", 0);
        if (storageParam.iterations == 0) return RET_CM_INVALID_PARAMETER;
    }

    return RET_OK;
}
