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

#include "uapki-session-loader.h"


UapkiSessionLoader::UapkiSessionLoader (void)
    : m_SessionCreate(nullptr), m_SessionFree(nullptr), m_SessionProcess(nullptr)
    , m_SharedMemoryCreate(nullptr), m_SharedMemoryFree(nullptr), m_SharedMemoryProcess(nullptr)
{
}

UapkiSessionLoader::~UapkiSessionLoader (void)
{
    unload();
}

bool UapkiSessionLoader::load (
        const std::string& libName,
        const bool isAbsolutePath
)
{
    unload();
    if (!UapkiLoader::load(libName, isAbsolutePath)) return false;

    m_SessionCreate = (f_session_create)DL_GET_PROC_ADDRESS(getHandle(), "uapki_session_create");
    m_SessionFree = (f_session_free)DL_GET_PROC_ADDRESS(getHandle(), "uapki_session_free");
    m_SessionProcess = (f_session_process)DL_GET_PROC_ADDRESS(getHandle(), "uapki_session_process");
    m_SharedMemoryCreate = (f_shared_memory_create)DL_GET_PROC_ADDRESS(getHandle(), "uapki_session_shared_memory_create");
    m_SharedMemoryFree = (f_shared_memory_free)DL_GET_PROC_ADDRESS(getHandle(), "uapki_session_shared_memory_free");
    m_SharedMemoryProcess = (f_shared_memory_process)DL_GET_PROC_ADDRESS(getHandle(), "uapki_session_shared_memory_process");
    if (!isSessionsSupported()) {
        resetSessionFunctions();
    }
    return true;
}

void UapkiSessionLoader::unload (void)
{
    resetSessionFunctions();
    UapkiLoader::unload();
}

void UapkiSessionLoader::resetSessionFunctions (void)
{
    m_SessionCreate = nullptr;
    m_SessionFree = nullptr;
    m_SessionProcess = nullptr;
    m_SharedMemoryCreate = nullptr;
    m_SharedMemoryFree = nullptr;
    m_SharedMemoryProcess = nullptr;
}

UAPKI_SESSION* UapkiSessionLoader::sessionCreate (void)
{
    return (m_SessionCreate) ? m_SessionCreate() : nullptr;
}

void UapkiSessionLoader::sessionFree (
        UAPKI_SESSION* session
)
{
    if (m_SessionFree && session) {
        m_SessionFree(session);
    }
}

char* UapkiSessionLoader::sessionProcess (
        UAPKI_SESSION* session,
        UAPKI_SESSION_SHARED_MEMORY* memory,
        const char* jsonRequest
)
{
    return (m_SessionProcess) ? m_SessionProcess(session, memory, jsonRequest) : nullptr;
}

UAPKI_SESSION_SHARED_MEMORY* UapkiSessionLoader::sharedMemoryCreate (void)
{
    return (m_SharedMemoryCreate) ? m_SharedMemoryCreate() : nullptr;
}

void UapkiSessionLoader::sharedMemoryFree (
        UAPKI_SESSION_SHARED_MEMORY* memory
)
{
    if (m_SharedMemoryFree && memory) {
        m_SharedMemoryFree(memory);
    }
}

char* UapkiSessionLoader::sharedMemoryProcess (
        UAPKI_SESSION_SHARED_MEMORY* memory,
        const char* jsonRequest
)
{
    return (m_SharedMemoryProcess) ? m_SharedMemoryProcess(memory, jsonRequest) : nullptr;
}


UapkiSession::UapkiSession (
        UapkiSessionLoader& loader
)
    : m_Loader(loader), m_Session(loader.sessionCreate())
{
}

UapkiSession::~UapkiSession (void)
{
    m_Loader.sessionFree(m_Session);
}

char* UapkiSession::process (
        const char* jsonRequest,
        UAPKI_SESSION_SHARED_MEMORY* memory
)
{
    return m_Loader.sessionProcess(m_Session, memory, jsonRequest);
}

void UapkiSession::jsonFree (
        char* jsonResponse
)
{
    m_Loader.jsonFree(jsonResponse);
}


UapkiSharedMemory::UapkiSharedMemory (
        UapkiSessionLoader& loader
)
    : m_Loader(loader), m_Memory(loader.sharedMemoryCreate())
{
}

UapkiSharedMemory::~UapkiSharedMemory (void)
{
    m_Loader.sharedMemoryFree(m_Memory);
}

char* UapkiSharedMemory::process (
        const char* jsonRequest
)
{
    return m_Loader.sharedMemoryProcess(m_Memory, jsonRequest);
}

void UapkiSharedMemory::jsonFree (
        char* jsonResponse
)
{
    m_Loader.jsonFree(jsonResponse);
}
