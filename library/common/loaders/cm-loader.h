/*
 * Copyright (c) 2022, The UAPKI Project Authors.
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

#ifndef CM_LOADER_H
#define CM_LOADER_H


#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string>
#include "cm-api.h"
#include "cm-errors.h"
#include "dl-macros.h"


using namespace std;


class CmLoader
{
    CM_PROVIDER_API m_Api;

public:
    CmLoader (void);
    ~CmLoader (void);

    static string getLibName (const string& libName);

    HANDLE_DLIB getHandle (void) const { return (HANDLE_DLIB)m_Api.hlib; }
    bool isLoaded (void) const { return (m_Api.hlib != nullptr); }
    bool load (const string& libName, const string& dir = string());
    void unload (void);

    const CM_PROVIDER_API* getApi (void) const { return &m_Api; }
    int info (CM_JSON_PCHAR* providerInfo);
    int init (const CM_JSON_PCHAR providerParams);
    int deinit (void);
    int listStorages (CM_JSON_PCHAR* listUris);
    int storageInfo (const char* uri, CM_JSON_PCHAR* storageInfo);
    int open (const char* uri, uint32_t mode, const CM_JSON_PCHAR createParams, CM_SESSION_API** session);
    int close (CM_SESSION_API* session);
    int format (const char* uri, const char* soPassword, const char* userPassword);

    void blockFree (void* ptr);
    void baFree (CM_BYTEARRAY* ba);

};  //  end class CmLoader


#endif
