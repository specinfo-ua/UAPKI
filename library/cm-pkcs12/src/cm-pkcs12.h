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

#ifndef CM_PKCS12_H
#define CM_PKCS12_H


#include "cm-api.h"
#include "file-storage.h"
#include "parson.h"
#include "store-bag.h"


class CmPkcs12
{
    FileStorageParam m_DefaultParam;

public:
    static const uint32_t CM_SESSION_API_V1 = 1;
    static const char* CM_SESSION_DESCRIPTION;
    static const char* CM_SESSION_MANUFACTURER;
    static const char* CM_SESSION_MODEL;

    CmPkcs12 (void);
    ~CmPkcs12 (void);

    FileStorageParam& getDefaultParam (void) {
        return m_DefaultParam;
    }
    CM_ERROR open (
            const char* fileName,
            uint32_t openMode,
            const CM_JSON_PCHAR openParams,
            CM_SESSION_API** session
    );
    CM_ERROR close (
            CM_SESSION_API* session
    );

    static void assignKeyFunc (
        CM_KEY_API& key
    );
    static void assignSessionFunc (
        CM_SESSION_API& session
    );

    static CM_ERROR keyInfoToJson (
        const StoreKeyInfo& keyInfo,
        JSON_Object* joResult
    );
    static CM_ERROR listMechanisms (
        JSON_Array* jaMechanisms
    );
    static CM_ERROR mechanismParamsToJson (
        const char* mechanismId,
        CM_JSON_PCHAR* jsonParameters
    );
    static CM_ERROR parseBytes (
        const CM_JSON_PCHAR jsonParams,
        ByteArray** baEncoded
    );
    static CM_ERROR parseConfig (
        const CM_JSON_PCHAR jsonParams,
        FileStorageParam& storageParam
    );
    static CM_ERROR sessionInfoToJson (
        const std::string& filename,
        CM_JSON_PCHAR* jsonResult
    );
    static CM_ERROR signAlgoByMechanismId (
        const char* mechanismId,
        JSON_Array* jaSignAlgos
    );

};  //  end class CmPkcs12

#endif
