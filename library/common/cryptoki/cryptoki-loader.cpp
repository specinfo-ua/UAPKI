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

#include "cryptoki-loader.h"
#include <stdio.h>
#include <string>


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


namespace Cryptoki {


Version::Version (void)
{
    //  Note: initialize members (major and minor) here - this is restriction of compiler GCC version 4.8.5
    major = minor = 0;
}

string Version::toString (void) const
{
    return to_string(major) + string(".") + to_string(minor);
}


Loader::Loader (void)
    : m_HandleDLib(nullptr)
    , m_FunctionList(nullptr)
{
    DEBUG_OUTCON(puts("Cryptoki::Loader::Loader"));
}

Loader::~Loader (void)
{
    DEBUG_OUTCON(puts("Cryptoki::Loader::~Loader"));
    unload();
}

bool Loader::load (
        const string& libName
)
{
    unload();

    bool ok = false;
    const string lib_name = getLibName(libName);
    DEBUG_OUTCON(printf("Loader.load('%s'), lib_name: '%s'\n", libName.c_str(), lib_name.c_str()));

    m_HandleDLib = dl_load_library_utf8(lib_name.c_str());
    DEBUG_OUTCON(printf("Loader.load(), m_HandleDLib: %p\n", m_HandleDLib));

    if (m_HandleDLib) {
        CK_C_GetFunctionList get_function_list = (CK_C_GetFunctionList)DL_GET_PROC_ADDRESS(m_HandleDLib, "C_GetFunctionList");
        if (get_function_list) {
            const CK_RV rv = get_function_list(&m_FunctionList);
            ok = (rv == CKR_OK);
        }

        if (!ok) {
            unload();
        }
    }

    DEBUG_OUTCON(printf("Loader.load(), ok: %d\n", ok));
    return ok;
}

void Loader::unload (void)
{
    if (m_HandleDLib) {
        DL_FREE_LIBRARY(m_HandleDLib);
        m_HandleDLib = nullptr;
        m_FunctionList = nullptr;
    }
}

Version Loader::getApiVersion (void) const
{
    Version rv_ver;
    if (m_FunctionList) {
        rv_ver.major = m_FunctionList->version.major;
        rv_ver.minor = m_FunctionList->version.minor;
    }
    return rv_ver;
}

string Loader::getLibName (
        const string& libName
)
{
    return string(LIBNAME_PREFIX) + libName + string(".") + string(LIBNAME_EXT);
}


}   //  end namespace Cryptoki
