/*
 * Copyright 2021 The UAPKI Project Authors.
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

#define FILE_MARKER "uapkic/entropy.c"

#include <time.h>
#include <string.h>
#include <limits.h>

#ifdef _WIN32
#   include <windows.h>
#   include <bcrypt.h>
#else
#   include <errno.h>
#   include <unistd.h>
#   if defined(__linux__)
#       include <sys/syscall.h>
#   endif
#   if defined(__APPLE__) || defined(__FreeBSD__) || defined(__EMSCRIPTEN__)
#       include <sys/random.h>
#   endif
#endif

#include "entropy.h"
#include "jitterentropy-internal.h"
#include "pthread-internal.h"
#include "word-internal.h"
#include "math-int-internal.h"
#include "macros-internal.h"
#include "byte-utils-internal.h"

#if defined(_WIN32)

/* Системний ГПВП Windows (BCryptGenRandom), без відкриття провайдера алгоритму */
static int os_prng(void *rnd, size_t size)
{
    uint8_t *p = (uint8_t *)rnd;

    while (size > 0) {
        const ULONG chunk = (size > ULONG_MAX) ? ULONG_MAX : (ULONG)size;
        if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, p, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
            return RET_OS_PRNG_ERROR;
        }
        p += chunk;
        size -= chunk;
    }

    return RET_OK;
}

#else

static int os_prng(void *rnd, size_t size)
{
    uint8_t *p = (uint8_t *)rnd;

#if defined(__linux__)
#   if !defined(SYS_getrandom)
#       error "SYS_getrandom is not defined: Linux kernel headers 3.17 or later are required"
#   endif
    /* Linux, Android: системний виклик getrandom (не залежить від версії glibc;
       блокується, доки пул ентропії ядра не ініціалізовано) */
    while (size > 0) {
        const long n = syscall(SYS_getrandom, p, size, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return RET_OS_PRNG_ERROR;
        }
        p += n;
        size -= (size_t)n;
    }
    return RET_OK;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__EMSCRIPTEN__)
    /* macOS, iOS, FreeBSD, OpenBSD, Emscripten: getentropy, не більше 256 байтів за виклик */
    while (size > 0) {
        const size_t chunk = (size > 256) ? 256 : size;
        if (getentropy(p, chunk) != 0) {
            return RET_OS_PRNG_ERROR;
        }
        p += chunk;
        size -= chunk;
    }
    return RET_OK;
#else
#   error "Unsupported platform: no OS entropy source"
#endif
}

#endif

#ifndef __EMSCRIPTEN__
static pthread_mutex_t jent_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static int jent_initialized = 0;

/* Стартова перевірка jitterentropy: один раз на процес, повторно - лише на вимогу самотестування */
static int jent_init(int force)
{
    int ret = RET_OK;

    pthread_mutex_lock(&jent_init_mutex);
    if (force || !jent_initialized) {
        jent_initialized = (jent_entropy_init() == 0);
        if (!jent_initialized) {
            ret = RET_JITTER_RNG_ERROR;
        }
    }
    pthread_mutex_unlock(&jent_init_mutex);

    return ret;
}
#endif


int entropy_get(ByteArray** entropy)
{
    int ret = RET_OK;
#ifndef __EMSCRIPTEN__
    JitentCtx* jec = NULL;
#endif
    ByteArray* out = NULL;

    CHECK_NOT_NULL(out = ba_alloc_by_len(512));
    
#ifndef __EMSCRIPTEN__
    DO(os_prng(out->buf, 256));

    DO(jent_init(0));
    CHECK_NOT_NULL(jec = jent_entropy_collector_alloc(1, 0));
    if (jent_read_entropy(jec, out->buf + 256, 256) != 0) {
        SET_ERROR(RET_JITTER_RNG_ERROR);
    }
#else
    DO(os_prng(out->buf, 512));
#endif

    *entropy = out;
    out = NULL;

cleanup:
#ifndef __EMSCRIPTEN__
    jent_entropy_collector_free(jec);
#endif
    ba_free_private(out);
    return ret;
}

int entropy_std(ByteArray* random)
{
    return os_prng(random->buf, random->len);
}

int entropy_jitter(ByteArray* random)
{
#ifndef __EMSCRIPTEN__
    int ret = RET_OK;
    JitentCtx* jec = NULL;

    DO(jent_init(0));
    CHECK_NOT_NULL(jec = jent_entropy_collector_alloc(1, 0));
    if (jent_read_entropy(jec, random->buf, random->len) != 0) {
        SET_ERROR(RET_JITTER_RNG_ERROR);
    }

cleanup:
    jent_entropy_collector_free(jec);
    return ret;
#else
    (void)random;
    return RET_UNSUPPORTED;
#endif
}

int entropy_self_test(void)
{
    int ret = RET_OK;
#ifndef __EMSCRIPTEN__
    JitentCtx* jec = NULL;
#endif
    uint8_t buf[256];

    DO(os_prng(buf, sizeof(buf)));

#ifndef __EMSCRIPTEN__
    DO(jent_init(1));
    CHECK_NOT_NULL(jec = jent_entropy_collector_alloc(1, 0));
    if (jent_read_entropy(jec, buf, sizeof(buf)) != 0) {
        SET_ERROR(RET_JITTER_RNG_ERROR);
    }
#endif
cleanup:
#ifndef __EMSCRIPTEN__
    jent_entropy_collector_free(jec);
#endif
    return ret;
}
