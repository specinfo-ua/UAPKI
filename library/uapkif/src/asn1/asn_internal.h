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

/*
 * Declarations internally useful for the ASN.1 support code.
 */
#ifndef    ASN_INTERNAL_H
#define    ASN_INTERNAL_H

#include "asn_application.h"      /* Application-visible API */
#include "macros-internal.h"

#include <stdio.h>

#ifdef    __cplusplus
extern "C" {
#endif

/* Environment version might be used to avoid running with the old library */
#define ASN1C_ENVIRONMENT_VERSION    923       /* Compile-time version */
UAPKIF_EXPORT int get_asn1c_environment_version(void);       /* Run-time version */

#define CALLOC(nmemb, size)    calloc(nmemb, size)
#define MALLOC(size)           malloc(size)
#define REALLOC(oldptr, size)  realloc(oldptr, size)
#define FREEMEM(ptr)           free(ptr); ptr = NULL;

#define asn_debug_indent    0
#define ASN_DEBUG_INDENT_ADD(i) do{}while(0)

#if defined(DEBUG)   /* If debugging code is not defined elsewhere... */
#define ASN_DEBUG(...) {                        \
        FILE* out = fopen("./debug.log", "a+"); \
        fprintf(out, __VA_ARGS__);              \
        fprintf(out, " (%s:%d)\n",              \
                __FILE__, __LINE__);            \
        fflush(out);                            \
        fclose(out);                            \
    }
#else   /* _DEBUG */
#define ASN_DEBUG(...)
#endif  /* _DEBUG */

/*
 * Invoke the application-supplied callback and fail, if something is wrong.
 */
#define    ASN__E_cbc(buf, size)    (cb((buf), (size), app_key) < 0)
#define    ASN__E_CALLBACK(foo)    do {                    \
        if(foo)    goto cb_failed;                         \
    } while(0)
#define    ASN__CALLBACK(buf, size)                    \
    ASN__E_CALLBACK(ASN__E_cbc(buf, size))
#define    ASN__CALLBACK2(buf1, size1, buf2, size2)            \
    ASN__E_CALLBACK(ASN__E_cbc(buf1, size1) || ASN__E_cbc(buf2, size2))
#define    ASN__CALLBACK3(buf1, size1, buf2, size2, buf3, size3)        \
    ASN__E_CALLBACK(ASN__E_cbc(buf1, size1)                             \
        || ASN__E_cbc(buf2, size2)                                      \
        || ASN__E_cbc(buf3, size3))

#define ASN__TEXT_INDENT(nl, level) do {            \
        int tmp_level = (level);                    \
        int tmp_nl = ((nl) != 0);                   \
        int tmp_i;                                  \
        if(tmp_nl) ASN__CALLBACK("\n", 1);          \
        if(tmp_level < 0) tmp_level = 0;            \
        for(tmp_i = 0; tmp_i < tmp_level; tmp_i++)  \
            ASN__CALLBACK("    ", 4);               \
        er.encoded += tmp_nl + 4 * tmp_level;       \
    } while(0)

#define _i_INDENT(nl)    do {                       \
        int tmp_i;                                  \
        if((nl) && cb("\n", 1, app_key) < 0)        \
            return -1;                              \
        for(tmp_i = 0; tmp_i < ilevel; tmp_i++)     \
            if(cb("    ", 4, app_key) < 0)          \
                return -1;                          \
    } while(0)

/*
 * Check stack against overflow, if limit is set.
 */
#define ASN__DEFAULT_STACK_MAX    (30000)

#ifdef _MSC_VER
_Check_return_
static int
#else
static int __attribute__((unused))
#endif
ASN__STACK_OVERFLOW_CHECK(asn_codec_ctx_t *ctx)
{
    if (ctx && ctx->max_stack_size) {

        /* ctx MUST be allocated on the stack */
        ptrdiff_t usedstack = ((char *)ctx - (char *)&ctx);
        if (usedstack > 0) {
            usedstack = -usedstack;    /* grows up! */
        }

        /* double negative required to avoid int wrap-around */
        if (usedstack < -(ptrdiff_t)ctx->max_stack_size) {
            ASN_DEBUG("Stack limit %ld reached",
                    (long)ctx->max_stack_size);
            return -1;
        }
    }
    return 0;
}

#if (defined(__clang__)) || (defined(__GNUC__) && __GNUC__ >= 7)
#define FALL_THROUGH __attribute__ ((fallthrough));
#else
#define FALL_THROUGH /* Fall through */
#endif

#ifdef    __cplusplus
}
#endif

#endif
