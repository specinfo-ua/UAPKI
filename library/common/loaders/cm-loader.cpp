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

#include "cm-loader.h"
#include "uapki-errors.h"
#include <stdio.h>
#include <string.h>


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


CmLoader::CmLoader (void)
{
    DEBUG_OUTCON(puts("CmLoader::CmLoader"));
    memset(&m_Api, 0, sizeof(CM_PROVIDER_API));
}

CmLoader::~CmLoader (void)
{
    DEBUG_OUTCON(puts("CmLoader::~CmLoader"));
    unload();
}

string CmLoader::getLibName (
        const string& libName
)
{
    return string(LIBNAME_PREFIX) + libName + "." + string(LIBNAME_EXT);
}

bool CmLoader::load (
        const string& libName,
        const string& dir
)
{
    unload();

    bool ok = false;
    const string lib_name = dir + getLibName(libName);
    DEBUG_OUTCON(printf("CmLoader.load('%s'), lib_name: '%s'\n", libName.c_str(), lib_name.c_str()));

    m_Api.hlib = DL_LOAD_LIBRARY(lib_name.c_str());
    DEBUG_OUTCON(printf("CmLoader.load(), m_Api.hlib: %p\n", m_Api.hlib));

    if (isLoaded()) {
        m_Api.info              = (cm_provider_info_f)          DL_GET_PROC_ADDRESS((HANDLE_DLIB)m_Api.hlib, "provider_info");          //  required API
        m_Api.init              = (cm_provider_init_f)          DL_GET_PROC_ADDRESS((HANDLE_DLIB)m_Api.hlib, "provider_init");          //  required API
        m_Api.deinit            = (cm_provider_deinit_f)        DL_GET_PROC_ADDRESS((HANDLE_DLIB)m_Api.hlib, "provider_deinit");        //  required API
        m_Api.list_storages     = (cm_provider_list_storages_f) DL_GET_PROC_ADDRESS((HANDLE_DLIB)m_Api.hlib, "provider_list_storages"); //  optional API
        m_Api.storage_info      = (cm_provider_storage_info_f)  DL_GET_PROC_ADDRESS((HANDLE_DLIB)m_Api.hlib, "provider_storage_info");  //  optional API
        m_Api.open              = (cm_provider_open_f)          DL_GET_PROC_ADDRESS((HANDLE_DLIB)m_Api.hlib, "provider_open");          //  required API
        m_Api.close             = (cm_provider_close_f)         DL_GET_PROC_ADDRESS((HANDLE_DLIB)m_Api.hlib, "provider_close");         //  required API
        m_Api.format            = (cm_provider_format_f)        DL_GET_PROC_ADDRESS((HANDLE_DLIB)m_Api.hlib, "provider_format");        //  optional API
        m_Api.block_free        = (cm_block_free_f)             DL_GET_PROC_ADDRESS((HANDLE_DLIB)m_Api.hlib, "block_free");             //  required API
        m_Api.bytearray_free    = (cm_bytearray_free_f)         DL_GET_PROC_ADDRESS((HANDLE_DLIB)m_Api.hlib, "bytearray_free");         //  required API
        DEBUG_OUTCON(printf("CmLoader.load(), m_Api.info: %p\n", m_Api.info));

        ok = (m_Api.info && m_Api.init && m_Api.deinit && m_Api.open && m_Api.close
            && m_Api.block_free && m_Api.bytearray_free);
        if (!ok) {
            unload();
        }
    }

    DEBUG_OUTCON(printf("CmLoader.load(), ok: %d\n", ok));
    return ok;
}

void CmLoader::unload (void)
{
    if (isLoaded()) {
        DL_FREE_LIBRARY(m_Api.hlib);
        memset(&m_Api, 0, sizeof(CM_PROVIDER_API));
    }
}

int CmLoader::info (
        CM_JSON_PCHAR* providerInfo
)
{
    return (m_Api.info) ? (int)m_Api.info(providerInfo) : RET_UAPKI_PROVIDER_NOT_LOADED;
}

int CmLoader::init (
        const CM_JSON_PCHAR providerParams
)
{
    return (m_Api.init) ? (int)m_Api.init(providerParams) : RET_UAPKI_PROVIDER_NOT_LOADED;
}

int CmLoader::deinit (void)
{
    return (m_Api.deinit) ? (int)m_Api.deinit() : RET_UAPKI_PROVIDER_NOT_LOADED;
}

int CmLoader::listStorages (
        CM_JSON_PCHAR* listUris
)
{
    return (m_Api.list_storages) ? (int)m_Api.list_storages(listUris) : (isLoaded() ? RET_UAPKI_UNSUPPORTED_CMAPI : RET_UAPKI_PROVIDER_NOT_LOADED);
}

int CmLoader::storageInfo (
        const char* uri,
        CM_JSON_PCHAR* storageInfo
)
{
    return (m_Api.storage_info) ? (int)m_Api.storage_info(uri, storageInfo) : (isLoaded() ? RET_UAPKI_UNSUPPORTED_CMAPI : RET_UAPKI_PROVIDER_NOT_LOADED);
}

int CmLoader::open (
        const char* uri,
        uint32_t mode,
        const CM_JSON_PCHAR openParams,
        CM_SESSION_API** session
)
{
    return (m_Api.open) ? (int)m_Api.open(uri, mode, openParams, session) : RET_UAPKI_PROVIDER_NOT_LOADED;
}

int CmLoader::close (
        CM_SESSION_API* session
)
{
    return (m_Api.close) ? (int)m_Api.close(session) : RET_UAPKI_PROVIDER_NOT_LOADED;
}

int CmLoader::format (
        const char* uri,
        const char* soPassword,
        const char* userPassword
)
{
    return (m_Api.format) ? (int)m_Api.format(uri, soPassword, userPassword) : (isLoaded() ? RET_UAPKI_UNSUPPORTED_CMAPI : RET_UAPKI_PROVIDER_NOT_LOADED);
}

void CmLoader::blockFree (
        void* ptr
)
{
    if (m_Api.block_free) {
        m_Api.block_free(ptr);
    }
}

void CmLoader::baFree (
        CM_BYTEARRAY* ba
)
{
    if (m_Api.bytearray_free) {
        m_Api.bytearray_free(ba);
    }
}
