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

#ifndef UAPKIC_MACROS_INTERNAL_H_
#define UAPKIC_MACROS_INTERNAL_H_

#include <stdlib.h>

#include "uapkic-errors.h"
#include "stacktrace.h"

/**
 * У тілі функції обов'язково повинна бути
 * int ret = RET_OK;
 * ...
 * cleanup:
 * ...
 * return ret;
 */
#define DO(func)                                         \
    {                                                    \
        ret = (func);                                    \
        if (ret != RET_OK) {                             \
            ERROR_ADD(ret);                              \
            goto cleanup;                                \
        }                                                \
    }

/**
 * У тілі функції обов'язково повинна бути
 * int ret = RET_OK;
 * ...
 * cleanup:
 * ...
 * return ret;
 */
#define MALLOC_CHECKED(_buffer, _len)                    \
    {                                                    \
        if (NULL == (_buffer = malloc(_len))) {          \
            ret = RET_MEMORY_ALLOC_ERROR;                \
            ERROR_CREATE(ret);                           \
            goto cleanup;                                \
        }                                                \
    }

/**
 * У тілі функції обов'язково повинна бути
 * int ret = RET_OK;
 * ...
 * cleanup:
 * ...
 * return ret;
 */
#define CALLOC_CHECKED(_buffer, _len)                    \
    {                                                    \
        if (NULL == (_buffer = calloc(1, _len))) {       \
            ret = RET_MEMORY_ALLOC_ERROR;                \
            ERROR_CREATE(ret);                           \
            goto cleanup;                                \
        }                                                \
    }

/**
 * У тілі функції обов'язково повинна бути
 * int ret = RET_OK;
 * ...
 * cleanup:
 * ...
 * return ret;
 */
#define REALLOC_CHECKED(_buffer, _len, _out)             \
    {                                                    \
        void *tmp = NULL;                                \
        if (NULL == (tmp = realloc(_buffer, _len))) {    \
            ret = RET_MEMORY_ALLOC_ERROR;                \
            ERROR_CREATE(ret);                           \
            goto cleanup;                                \
        }                                                \
        _out = tmp;                                      \
    }

/**
 * У тілі функції обов'язково повинна бути
 * int ret = RET_OK;
 * ...
 * cleanup:
 * ...
 * return ret;
 */
#define CHECK_PARAM(_statement)                          \
    {                                                    \
        if (!(_statement)) {                             \
            ret = RET_INVALID_PARAM;                     \
            ERROR_CREATE(ret);                           \
            goto cleanup;                                \
        }                                                \
    }

/**
 * У тілі функції обов'язково повинна бути
 * int ret = RET_OK;
 * ...
 * cleanup:
 * ...
 * return ret;
 */
#define CHECK_NOT_NULL(_buffer)                          \
    {                                                    \
        if (NULL == (_buffer)) {                         \
            ret = RET_INVALID_PARAM;                     \
            ERROR_ADD(ret);                              \
            goto cleanup;                                \
        }                                                \
    }

/**
 * У тілі функції обов'язково повинна бути
 * int ret = RET_OK;
 * ...
 * cleanup:
 * ...
 * return ret;
 */
#define SET_ERROR(_error_code)                           \
        ret = _error_code;                               \
        ERROR_CREATE(ret);                               \
        goto cleanup;

#endif
