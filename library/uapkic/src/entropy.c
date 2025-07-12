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

#ifdef _WIN32
#   include <windows.h>
#   include <winternl.h>
#   include <winioctl.h>
#   pragma comment(lib, "NTDLL.lib")
#   pragma comment(lib, "BCrypt.lib")
#   define RTL_CONSTANT_STRING(s) { sizeof(s) - sizeof((s)[0]), sizeof(s), s }
#   ifndef IOCTL_KSEC_RNG   // ntddksec.h, 0x390004
#       define IOCTL_KSEC_RNG   CTL_CODE(FILE_DEVICE_KSEC, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#   endif
#   ifndef IOCTL_KSEC_RNG_REKEY // ntddksec.h, 0x390008
#       define IOCTL_KSEC_RNG_REKEY CTL_CODE(FILE_DEVICE_KSEC, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#   endif
#else
#   ifdef __linux
#       include <sys/random.h>
#   endif
#   include <fcntl.h>
#   include <unistd.h>
#   include <sys/time.h>
#endif

#include "entropy.h"
#include "jitterentropy-internal.h"
#include "word-internal.h"
#include "math-int-internal.h"
#include "macros-internal.h"
#include "byte-utils-internal.h"

#ifndef __EMSCRIPTEN__
static int os_prng(void *rnd, size_t size)
{
    int ret = RET_OK;

#if defined(_WIN32) && !defined(_WIN32_WCE)
    // Try calling SystemPrng in the CNG kernel-mode driver via an IOCTL.
    HANDLE dev;
    IO_STATUS_BLOCK iosb;
    UNICODE_STRING path = RTL_CONSTANT_STRING(L"\\Device\\CNG");
    OBJECT_ATTRIBUTES oa;
    NTSTATUS status;
    ULONG ioctl = size < 16384 ? IOCTL_KSEC_RNG : IOCTL_KSEC_RNG_REKEY;

    InitializeObjectAttributes(&oa, &path, 0, NULL, NULL);
    NtOpenFile(&dev, FILE_READ_DATA, &oa, &iosb, FILE_SHARE_READ, 0);
    status = NtDeviceIoControlFile(dev, NULL, NULL, NULL, &iosb, ioctl, NULL, (ULONG)size, rnd, (ULONG)size);
    NtClose(dev);

    if (NT_SUCCESS(status)) {
        return RET_OK;
    }

    // Try using BCryptGenRandom.
    BCRYPT_ALG_HANDLE alg;
    status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        SET_ERROR(RET_OS_PRNG_ERROR);
    }
    status = BCryptGenRandom(alg, rnd, (ULONG)size, 0);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!NT_SUCCESS(status)) {
        SET_ERROR(RET_OS_PRNG_ERROR);
    }

#else
    uint8_t* _b = rnd;
#ifdef __linux
    // Use a system call.
    do {
        ssize_t r = getrandom(_b, size, 0);
        if (r == -1) {
            break;
        }
        _b += r;
        size -= r;
    } while (size);
    if (!size) {
        return RET_OK;
    }
#endif
    int f = open("/dev/urandom", O_RDONLY);
    if (f == -1) {
        SET_ERROR(RET_OS_PRNG_ERROR);
    }
    do {
        ssize_t r = read(f, _b, size);
        if (r == -1) {
            break;
        }
        _b += r;
        size -= r;
    } while (size);
    close(f);
    if (size) {
        SET_ERROR(RET_OS_PRNG_ERROR);
    }
#endif

cleanup:
    return ret;
}
#else
#include <emscripten.h>

int os_prng_init(void)
{
    return EM_ASM_INT({
        if (Module.getRandomValue === undefined) {
            try {
                var window_ = 'object' === typeof window ? window : self;
                var crypto_ = typeof window_.crypto !== 'undefined' ? window_.crypto : window_.msCrypto;
                var randomValuesStandard = function() {
                    var buf = new Uint8Array(1);
                    crypto_.getRandomValues(buf);
                    return buf[0] >>> 0;
                };
                randomValuesStandard();
                Module.getRandomValue = randomValuesStandard;
                return 0;
            } catch (e) {
                try {
                    var crypto = require('crypto');
                    var randomValueNodeJS = function() {
                        var buf = crypto['randomBytes'](1);
                        return buf[0] >>> 0;
                    };
                    randomValueNodeJS();
                    Module.getRandomValue = randomValueNodeJS;
                    return 0;
                } catch (e) {
                    return RET_OS_PRNG_ERROR;
                }
            }
        }
    });
}

int os_prng(void* buf, size_t n)
{
    uint8_t* p = (uint8_t*)buf;
    size_t i;

    if (os_prng_init() != 0) {
        return RET_OS_PRNG_ERROR;
    }

    for (i = 0; i < n; i++)
    {
        p[i] = (uint8_t)EM_ASM_INT({
           return Module.getRandomValue();
            });
    }

    return 0;
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

    if (jent_entropy_init() != 0) {
        SET_ERROR(RET_JITTER_RNG_ERROR);
    }
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

    if (jent_entropy_init() != 0) {
        SET_ERROR(RET_JITTER_RNG_ERROR);
    }
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
    if (jent_entropy_init() != 0) {
        SET_ERROR(RET_JITTER_RNG_ERROR);
    }
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
