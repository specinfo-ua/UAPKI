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

#ifndef UAPKI_VERIFY_STATUS_H
#define UAPKI_VERIFY_STATUS_H


#include "uapkic.h"


struct SIGNATURE_VALIDATION {
    enum class STATUS : uint32_t {
        UNDEFINED       = 0,
        INDETERMINATE   = 1,
        TOTAL_FAILED    = 2,
        TOTAL_VALID     = 3
    };

    static const char* toStr (const STATUS status);
};

struct SIGNATURE_VERIFY {
    enum class STATUS : uint32_t {
        UNDEFINED   = 0,
        NOT_PRESENT = 1,
        FAILED      = 2,
        INVALID     = 3,
        VALID       = 4
    };

    static const char* toStr (const STATUS status);
};

struct CERTIFICATE_VERIFY {
    enum class STATUS : uint32_t {
        UNDEFINED               = 0,
        FAILED                  = 1,
        INVALID                 = 2,
        VALID                   = 3,
        VALID_WITHOUT_KEYUSAGE  = 4
    };

    static const char* toStr (const STATUS status);
};


#endif
