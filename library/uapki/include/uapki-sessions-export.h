/*
 * Copyright (c) 2026, The UAPKI Project Authors.
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

#ifndef UAPKI_SESSIONS_EXPORT_H
#define UAPKI_SESSIONS_EXPORT_H

#include "uapki-export.h"


#ifdef  __cplusplus
extern "C" {
#endif


typedef struct UAPKI_SESSION_ST UAPKI_SESSION;
typedef struct UAPKI_SESSION_SHARED_MEMORY_ST UAPKI_SESSION_SHARED_MEMORY;

UAPKI_EXPORT UAPKI_SESSION* uapki_session_create (void);
UAPKI_EXPORT void uapki_session_free (UAPKI_SESSION* session);
UAPKI_EXPORT char* uapki_session_process (UAPKI_SESSION* session, UAPKI_SESSION_SHARED_MEMORY* memory, const char* request);

UAPKI_EXPORT UAPKI_SESSION_SHARED_MEMORY* uapki_session_shared_memory_create (void);
UAPKI_EXPORT void uapki_session_shared_memory_free (UAPKI_SESSION_SHARED_MEMORY* memory);
UAPKI_EXPORT char* uapki_session_shared_memory_process (UAPKI_SESSION_SHARED_MEMORY* memory, const char* request);


#ifdef  __cplusplus
}
#endif

#endif
