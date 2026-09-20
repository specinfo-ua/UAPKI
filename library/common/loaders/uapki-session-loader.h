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

#ifndef UAPKI_SESSION_LOADER_H
#define UAPKI_SESSION_LOADER_H


#include <string>
#include "uapki-loader.h"


typedef struct UAPKI_SESSION_ST UAPKI_SESSION;
typedef struct UAPKI_SESSION_SHARED_MEMORY_ST UAPKI_SESSION_SHARED_MEMORY;


class UapkiSessionLoader : public UapkiLoader
{
    typedef UAPKI_SESSION* (*f_session_create)(void);
    typedef void (*f_session_free)(UAPKI_SESSION* session);
    typedef char* (*f_session_process)(UAPKI_SESSION* session, UAPKI_SESSION_SHARED_MEMORY* memory, const char* request);
    typedef UAPKI_SESSION_SHARED_MEMORY* (*f_shared_memory_create)(void);
    typedef void (*f_shared_memory_free)(UAPKI_SESSION_SHARED_MEMORY* memory);
    typedef char* (*f_shared_memory_process)(UAPKI_SESSION_SHARED_MEMORY* memory, const char* request);

    f_session_create
                m_SessionCreate;
    f_session_free
                m_SessionFree;
    f_session_process
                m_SessionProcess;
    f_shared_memory_create
                m_SharedMemoryCreate;
    f_shared_memory_free
                m_SharedMemoryFree;
    f_shared_memory_process
                m_SharedMemoryProcess;

    void resetSessionFunctions (void);

public:
    UapkiSessionLoader (void);
    ~UapkiSessionLoader (void);

    bool isSessionsSupported (void) const {
        return (m_SessionCreate && m_SessionFree && m_SessionProcess
            && m_SharedMemoryCreate && m_SharedMemoryFree && m_SharedMemoryProcess);
    }
    bool load (
        const std::string& libName = std::string("uapki"),
        const bool isAbsolutePath = false
    );
    void unload (void);

    UAPKI_SESSION* sessionCreate (void);
    void sessionFree (UAPKI_SESSION* session);
    char* sessionProcess (UAPKI_SESSION* session, UAPKI_SESSION_SHARED_MEMORY* memory, const char* jsonRequest);

    UAPKI_SESSION_SHARED_MEMORY* sharedMemoryCreate (void);
    void sharedMemoryFree (UAPKI_SESSION_SHARED_MEMORY* memory);
    char* sharedMemoryProcess (UAPKI_SESSION_SHARED_MEMORY* memory, const char* jsonRequest);

};  //  end class UapkiSessionLoader


class UapkiSession
{
    UapkiSessionLoader&
                m_Loader;
    UAPKI_SESSION*
                m_Session;

public:
    explicit UapkiSession (UapkiSessionLoader& loader);
    ~UapkiSession (void);

    UapkiSession (const UapkiSession&) = delete;
    UapkiSession& operator= (const UapkiSession&) = delete;

    UAPKI_SESSION* getHandle (void) const {
        return m_Session;
    }
    bool isCreated (void) const {
        return (m_Session != nullptr);
    }
    char* process (const char* jsonRequest, UAPKI_SESSION_SHARED_MEMORY* memory = nullptr);
    void jsonFree (char* jsonResponse);

};  //  end class UapkiSession


class UapkiSharedMemory
{
    UapkiSessionLoader&
                m_Loader;
    UAPKI_SESSION_SHARED_MEMORY*
                m_Memory;

public:
    explicit UapkiSharedMemory (UapkiSessionLoader& loader);
    ~UapkiSharedMemory (void);

    UapkiSharedMemory (const UapkiSharedMemory&) = delete;
    UapkiSharedMemory& operator= (const UapkiSharedMemory&) = delete;

    UAPKI_SESSION_SHARED_MEMORY* getHandle (void) const {
        return m_Memory;
    }
    bool isCreated (void) const {
        return (m_Memory != nullptr);
    }
    char* process (const char* jsonRequest);
    void jsonFree (char* jsonResponse);

};  //  end class UapkiSharedMemory


#endif
