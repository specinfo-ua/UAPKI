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

#ifndef UAPKI_LOADER_H
#define UAPKI_LOADER_H


#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string>
#include "dl-macros.h"


class UapkiLoader
{
    typedef char* (*f_process)(const char* request);
    typedef void (*f_json_free)(char* buf);

    HANDLE_DLIB m_HandleDLib;
    f_process   m_Process;
    f_json_free m_JsonFree;

public:
    UapkiLoader (void);
    ~UapkiLoader (void);

    static std::string getLibName (
        const std::string& libName
    );

    HANDLE_DLIB getHandle (void) const {
        return m_HandleDLib;
    }
    bool isLoaded (void) const {
        return (m_HandleDLib != nullptr);
    }
    bool load (
        const std::string& libName = std::string("uapki"),
        const bool isAbsolutePath = false
    );
    void unload (void);

    char* process (const char* jsonRequest);
    void jsonFree (char* jsonResponse);

};  //  end class UapkiLoader


#endif
