/*
 * Copyright 2021 The UAPKI Project Authors.
 * Copyright 2004 Lev Walkin <vlm@lionet.info>. All rights reserved.
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
 * Miscellaneous system-dependent types.
 */
#ifndef    ASN_SYSTEM_H
#define    ASN_SYSTEM_H

#include <stdio.h>     /* For snprintf(3) */
#include <stdlib.h>    /* For *alloc(3) */
#include <string.h>    /* For memcpy(3) */
#include <sys/types.h> /* For size_t */
#include <limits.h>    /* For LONG_MAX */
#include <stdarg.h>    /* For va_start */
#include <stddef.h>    /* for offsetof and ptrdiff_t */

#ifdef  __GNUC__
#ifndef alloca
#define alloca(size)   __builtin_alloca (size)
#endif
#endif

#if defined(WIN32) || defined(_WIN32) || \
    defined(WIN64) || defined(_WIN64)

#include <malloc.h>
#define snprintf     _snprintf
#define vsnprintf    _vsnprintf

/* To avoid linking with ws2_32.lib, here's the definition of ntohl() */
#define sys_ntohl(l)    ((((l) << 24)  & 0xff000000)    \
                      | (((l) << 8) & 0xff0000)         \
                      | (((l) >> 8)  & 0xff00)          \
                      | ((l >> 24) & 0xff))

#ifdef _MSC_VER            /* MSVS.Net */
#ifndef __cplusplus
#define inline __inline
#endif
#include <stdint.h>
#ifndef ssize_t
#define ssize_t SSIZE_T
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <float.h>
#define finite   _finite
#define copysign _copysign
#else    /* !_MSC_VER */
#include <stdint.h>
#endif    /* _MSC_VER */

#else    /* !_WIN32 */

#if defined(__vxworks)
#include <types/vxTypes.h>
#else    /* !defined(__vxworks) */

#include <inttypes.h>    /* C99 specifies this file */
/*
 * 1. Earlier FreeBSD version didn't have <stdint.h>,
 * but <inttypes.h> was present.
 * 2. Sun Solaris requires <alloca.h> for alloca(3),
 * but does not have <stdint.h>.
 */
#if    (!defined(__FreeBSD__) || !defined(_SYS_INTTYPES_H_))
#if    defined(sun)
#include <alloca.h>    /* For alloca(3) */
#include <ieeefp.h>    /* for finite(3) */
#elif    defined(__hpux)
#ifdef    __GNUC__
#include <alloca.h>    /* For alloca(3) */
#else    /* !__GNUC__ */
#define inline
#endif    /* __GNUC__ */
#else
#include <stdint.h>    /* SUSv2+ and C99 specify this file, for uintXX_t */
#endif    /* defined(sun) */
#endif

#include <netinet/in.h> /* for ntohl() */
#define    sys_ntohl(foo)    ntohl(foo)

#endif    /* defined(__vxworks) */

#endif    /* _WIN32 */

#if    __GNUC__ >= 3
#ifndef    GCC_PRINTFLIKE
#define    GCC_PRINTFLIKE(fmt,var)    __attribute__((format(printf,fmt,var)))
#endif
#ifndef    GCC_NOTUSED
#define    GCC_NOTUSED        __attribute__((unused))
#endif
#else
#ifndef    GCC_PRINTFLIKE
#define    GCC_PRINTFLIKE(fmt,var)    /* nothing */
#endif
#ifndef    GCC_NOTUSED
#define    GCC_NOTUSED
#endif
#endif

/* Figure out if thread safety is requested */
#if !defined(ASN_THREAD_SAFE) && (defined(THREAD_SAFE) || defined(_REENTRANT))
#define    ASN_THREAD_SAFE
#endif    /* Thread safety */

#ifndef    offsetof    /* If not defined by <stddef.h> */
#define    offsetof(s, m)    ((ptrdiff_t)&(((s *)0)->m) - (ptrdiff_t)((s *)0))
#endif    /* offsetof */

#ifndef    MIN        /* Suitable for comparing primitive types (integers) */
#if defined(__GNUC__)
#define    MIN(a,b)    ({ __typeof a _a = a; __typeof b _b = b;    \
    ((_a)<(_b)?(_a):(_b)); })
#else    /* !__GNUC__ */
#define    MIN(a,b)    ((a)<(b)?(a):(b))    /* Unsafe variant */
#endif /* __GNUC__ */
#endif    /* MIN */

#endif
