/*
 * Copyright 2021 The UAPKI Project Authors.
 * Copyright 2016 PrivatBank IT <acsk@privatbank.ua>
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

#ifndef UAPKIC_STACKTRACE_H
#define UAPKIC_STACKTRACE_H

#include <stddef.h>
#include <stdbool.h>

#include "byte-array.h"

#ifdef EDEBUG
#undef ASSERT
#include <assert.h>

#define ASSERT(condition) assert(condition)
#else
#undef ASSERT
#define ASSERT(...)
#endif

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef FILE_MARKER
#define FILE_MARKER "undefined"
#endif

typedef struct ErrorCtx_st {
    char *file;
    size_t line;
    int error_code;
    struct ErrorCtx_st *next;
} ErrorCtx;

#define ERROR_CREATE(error_code) stacktrace_create(FILE_MARKER, __LINE__, error_code, NULL)
#define ERROR_ADD(error_code) stacktrace_add(FILE_MARKER, __LINE__, error_code)

UAPKIC_EXPORT const ErrorCtx *stacktrace_get_last(void);
UAPKIC_EXPORT void stacktrace_create(const char *file, const size_t line, const int error_code, const char *msg);
UAPKIC_EXPORT void stacktrace_add(const char *file, const size_t line, const int error_code);
UAPKIC_EXPORT ErrorCtx *stacktrace_get_last_with_alloc(void);
UAPKIC_EXPORT void error_ctx_free(ErrorCtx *err);
UAPKIC_EXPORT void stacktrace_free_current(void);
UAPKIC_EXPORT void stacktrace_finalize(void);

#ifdef  __cplusplus
}
#endif

#endif
