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

#ifndef CRYPTOKI_LOADER_H
#define CRYPTOKI_LOADER_H


#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string>
#include "../loaders/dl-macros.h"
#include "pkcs11.h"


namespace Cryptoki {


struct Version {
    uint32_t    major;
    uint32_t    minor;
    Version (void);
    std::string toString (void) const;
};  //  end struct Version


class Loader
{
    HANDLE_DLIB m_HandleDLib;
    CK_FUNCTION_LIST_PTR
                m_FunctionList;

public:
    Loader (void);
    ~Loader (void);

    HANDLE_DLIB getHandle (void) const {
        return m_HandleDLib;
    }
    bool isLoaded (void) const {
        return (m_HandleDLib);
    }

    bool load (
        const std::string& libName
    );
    void unload (void);

    Version getApiVersion (void) const;
    CK_FUNCTION_LIST_PTR getApi (void) const {
        return m_FunctionList;
    }

public:
    static std::string getLibName (
        const std::string& libName
    );

};  //  end class Loader


}   //  end namespace Cryptoki


#endif
