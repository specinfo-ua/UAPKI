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

#include "uapki-loader.h"
#include <stdio.h>


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


UapkiLoader::UapkiLoader (void)
    : m_HandleDLib(nullptr), m_Process(nullptr), m_JsonFree(nullptr)
{
    DEBUG_OUTCON(puts("UapkiLoader::UapkiLoader"));
}

UapkiLoader::~UapkiLoader (void)
{
    DEBUG_OUTCON(puts("UapkiLoader::~UapkiLoader"));
    unload();
}

string UapkiLoader::getLibName (
        const string& libName
)
{
    return string(LIBNAME_PREFIX) + libName + "." + string(LIBNAME_EXT);
}

bool UapkiLoader::load (
        const string& libName,
        const bool isAbsolutePath
)
{
    unload();

    bool ok = false;
    const string lib_name = !isAbsolutePath ? getLibName(libName) : libName;
    DEBUG_OUTCON(printf("UapkiLoader.load('%s'), lib_name: '%s'\n", libName.c_str(), lib_name.c_str()));

    m_HandleDLib = DL_LOAD_LIBRARY(lib_name.c_str());
    DEBUG_OUTCON(printf("UapkiLoader.load(), m_HandleDLib: %p\n", m_HandleDLib));

    if (m_HandleDLib) {
        m_Process = (f_process)DL_GET_PROC_ADDRESS(m_HandleDLib, "process");
        m_JsonFree = (f_json_free)DL_GET_PROC_ADDRESS(m_HandleDLib, "json_free");
        DEBUG_OUTCON(printf("UapkiLoader.load(), m_Process: %p\n", m_Process));

        ok = (m_Process && m_JsonFree);
        if (!ok) {
            unload();
        }
    }

    DEBUG_OUTCON(printf("UapkiLoader.load(), ok: %d\n", ok));
    return ok;
}

void UapkiLoader::unload (void)
{
    if (m_HandleDLib) {
        DL_FREE_LIBRARY(m_HandleDLib);
        m_HandleDLib = nullptr;
        m_Process = nullptr;
        m_JsonFree = nullptr;
    }
}

char* UapkiLoader::process (
        const char* jsonRequest
)
{
    return (m_Process) ? m_Process(jsonRequest) : nullptr;
}

void UapkiLoader::jsonFree (
        char* jsonResponse
)
{
    if (m_JsonFree) {
        m_JsonFree(jsonResponse);
    }
}
