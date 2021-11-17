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
#include "cm-loader.h"
#include "dl-macros.h"


CmLoader::CmLoader (void)
{
    memset(&m_Api, 0, sizeof(CM_PROVIDER_API));
}

CmLoader::~CmLoader (void)
{
    unload();
}

bool CmLoader::load (const char* path)
{
    bool ok = false;
    unload();

    m_Api.hlib = DL_LOAD_LIBRARY(path);
    if (m_Api.hlib) {
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
        ok = (m_Api.info && m_Api.init && m_Api.deinit && m_Api.open && m_Api.close
            && m_Api.block_free && m_Api.bytearray_free);
        if (!ok) {
            unload();
        }
    }

    return ok;
}

void CmLoader::unload (void)
{
    if (m_Api.hlib) {
        DL_FREE_LIBRARY(m_Api.hlib);
        memset(&m_Api, 0, sizeof(CM_PROVIDER_API));
    }
}

CM_ERROR CmLoader::info (CM_JSON_PCHAR* providerInfo)
{
    return (m_Api.info) ? m_Api.info(providerInfo) : RET_CM_LIBRARY_NOT_LOADED;
}

CM_ERROR CmLoader::init (const CM_JSON_PCHAR providerParams)
{
    return (m_Api.init) ? m_Api.init(providerParams) : RET_CM_LIBRARY_NOT_LOADED;
}

CM_ERROR CmLoader::deinit (void)
{
    return (m_Api.deinit) ? m_Api.deinit() : RET_CM_LIBRARY_NOT_LOADED;
}

CM_ERROR CmLoader::listStorages (CM_JSON_PCHAR* listUrls)
{
    return (m_Api.list_storages) ? m_Api.list_storages(listUrls) : ((m_Api.hlib) ? RET_CM_UNSUPPORTED_API : RET_CM_LIBRARY_NOT_LOADED);
}

CM_ERROR CmLoader::storageInfo (const char* url, CM_JSON_PCHAR* storageInfo)
{
    return (m_Api.storage_info) ? m_Api.storage_info(url, storageInfo) : ((m_Api.hlib) ? RET_CM_UNSUPPORTED_API : RET_CM_LIBRARY_NOT_LOADED);
}

CM_ERROR CmLoader::open (const char* url, uint32_t mode,
        const CM_JSON_PCHAR createParams, CM_SESSION_API** session)
{
    return (m_Api.open) ? m_Api.open(url, mode, createParams, session) : RET_CM_LIBRARY_NOT_LOADED;
}

CM_ERROR CmLoader::close (CM_SESSION_API* session)
{
    return (m_Api.close) ? m_Api.close(session) : RET_CM_LIBRARY_NOT_LOADED;
}

CM_ERROR CmLoader::format (const char* url, const char* soPassword, const char* userPassword)
{
    return (m_Api.format) ? m_Api.format(url, soPassword, userPassword) : ((m_Api.hlib) ? RET_CM_UNSUPPORTED_API : RET_CM_LIBRARY_NOT_LOADED);
}

void CmLoader::blockFree (void* ptr)
{
    if (m_Api.block_free) m_Api.block_free(ptr);
}

void CmLoader::baFree (CM_BYTEARRAY* ba)
{
    if (m_Api.bytearray_free) m_Api.bytearray_free(ba);
}

