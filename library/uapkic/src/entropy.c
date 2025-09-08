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

#if defined(_WIN32) && !defined(_WIN32_WCE)
#   include <Windows.h>
#   include <winternl.h>
#   include <winioctl.h>
#   pragma comment(lib, "ntdll.lib")
#   pragma comment(lib, "bcrypt.lib")
#   define RTL_CONSTANT_STRING(s) { sizeof(s) - sizeof((s)[0]), sizeof(s), s }
#   ifndef IOCTL_KSEC_RNG   // ntddksec.h, 0x390004
#       define IOCTL_KSEC_RNG   CTL_CODE(FILE_DEVICE_KSEC, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#   endif
#   ifndef IOCTL_KSEC_RNG_REKEY // ntddksec.h, 0x390008
#       define IOCTL_KSEC_RNG_REKEY CTL_CODE(FILE_DEVICE_KSEC, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#   endif
#else
#   include <sys/random.h>
#   include <fcntl.h>
#   include <unistd.h>
#endif

#include "entropy.h"
#include "jitterentropy-internal.h"
#include "word-internal.h"
#include "math-int-internal.h"
#include "macros-internal.h"
#include "byte-utils-internal.h"
#include "cpu-features-internal.h"

#ifndef __EMSCRIPTEN__
#if defined(_WIN32) && !defined(_WIN32_WCE)
static HANDLE rng = NULL;
static BCRYPT_ALG_HANDLE rng2 = NULL;
#else
//static int rng = 0;
#endif
#endif

int entropy_init(void)
{
    int ret = RET_OK;

#ifndef __EMSCRIPTEN__
#if defined(_WIN32) && !defined(_WIN32_WCE)
    NTSTATUS status;

    if (rng == NULL) {
        IO_STATUS_BLOCK iosb;
        UNICODE_STRING path = RTL_CONSTANT_STRING(L"\\Device\\CNG");
        OBJECT_ATTRIBUTES oa;

        InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = NtOpenFile(
            &rng,
            FILE_READ_DATA,
            &oa,
            &iosb,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0
        );
        if (!NT_SUCCESS(status)) {
            UNICODE_STRING path2 = RTL_CONSTANT_STRING(L"\\Device\\KSecDD");

            InitializeObjectAttributes(&oa, &path2, OBJ_CASE_INSENSITIVE, NULL, NULL);
            status = NtOpenFile(
                &rng,
                FILE_READ_DATA,
                &oa,
                &iosb,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                0
            );
            if (!NT_SUCCESS(status)) {
                rng = NULL;
            }
        }
    }

    if (rng == NULL && rng2 == NULL) {
        status = BCryptOpenAlgorithmProvider(&rng2, BCRYPT_RNG_ALGORITHM, NULL, 0);
        if (!NT_SUCCESS(status)) {
            rng2 = NULL;
            SET_ERROR(RET_OS_PRNG_ERROR);
        }
    }
#else
    //rng = open("/dev/urandom", O_RDONLY);
    //if (rng == -1) {
    //    rng = 0;
    //    SET_ERROR(RET_OS_PRNG_ERROR);
    //}
#endif  // _WIN32
    if (jent_entropy_init()) {
        SET_ERROR(RET_JITTER_RNG_ERROR);
    }
#endif  // __EMSCRIPTEN__

cleanup:
    return ret;
}

#ifndef __EMSCRIPTEN__
static int os_prng(void *rnd, size_t size)
{
    int ret = RET_OK;

#if defined(_WIN32) && !defined(_WIN32_WCE)
    uint8_t* b = rnd;
    NTSTATUS status;
    BCRYPT_ALG_HANDLE alg;

    // Try calling SystemPrng in the CNG kernel-mode driver via an IOCTL.
    do {
        IO_STATUS_BLOCK iosb;
        ULONG block_size = (ULONG)min(size, ULONG_MAX);
        ULONG ioctl = block_size < 16384 ? IOCTL_KSEC_RNG : IOCTL_KSEC_RNG_REKEY;
        status = NtDeviceIoControlFile(rng, NULL, NULL, NULL, &iosb, ioctl, NULL, block_size, b, block_size);
        b += iosb.Information;  // Advance by the number of random bytes we have just got.
        size -= iosb.Information;
        if (!NT_SUCCESS(status)) {
            break;
        }
    } while (size);
    if (!size) {
        return RET_OK;
    }

    // If accessing the kernel-mode RNG fails, try using BCryptGenRandom.
    alg = InterlockedCompareExchangePointer(&rng2, NULL, NULL);
    if (alg == NULL) {
        BCRYPT_ALG_HANDLE alg2;
        status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_RNG_ALGORITHM, NULL, 0);
        if (!NT_SUCCESS(status)) {
            SET_ERROR(RET_OS_PRNG_ERROR);
        }
        alg2 = InterlockedCompareExchangePointer(&rng2, alg, NULL);
        if (alg2 != NULL) {
            BCryptCloseAlgorithmProvider(alg, 0);
            alg = alg2;
        }
    }
    do {
        ULONG block_size = (ULONG)min(size, ULONG_MAX);
        status = BCryptGenRandom(alg, b, block_size, 0);
        if (!NT_SUCCESS(status)) {
            break;
        }
        b += block_size;
        size -= block_size;
    } while (size);
    if (size) {
        SET_ERROR(RET_OS_PRNG_ERROR);
    }
#else
    uint8_t* b = rnd;

    // Use a system call.
    do {
        ssize_t r = getrandom(b, size, 0);
        if (r == -1) {
            // We’ve got an error!
            break;
        }
        b += r; // Advance by the number of random bytes we have just got.
        size -= r;
    } while (size);
    if (!size) {
        return RET_OK;
    }

    // If the system call fails, fall back to reading /dev/urandom.
    int f = open("/dev/urandom", O_RDONLY);
    if (f == -1) {
        SET_ERROR(RET_OS_PRNG_ERROR);
    }
    do {
        ssize_t r = read(f, b, size);
        if (r == -1) {
            // We’ve got an error!
            break;
        }
        b += r; // Advance by the number of random bytes we have just got.
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
    size_t hwrng_out;

    CHECK_NOT_NULL(out = ba_alloc_by_len(512));

    hwrng_out = hw_rng(out->buf, 448);
#ifndef __EMSCRIPTEN__
    DO(os_prng(out->buf + hwrng_out, 480 - hwrng_out));
    CHECK_NOT_NULL(jec = jent_entropy_collector_alloc(1, 0));
    if (jent_read_entropy(jec, out->buf + 480, 32)) {
        SET_ERROR(RET_JITTER_RNG_ERROR);
    }
#else
    DO(os_prng(out->buf + hwrng_out, 512 - hwrng_out));
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

    CHECK_NOT_NULL(jec = jent_entropy_collector_alloc(1, 0));
    if (jent_read_entropy(jec, random->buf, random->len)) {
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

    DO(entropy_init());
    DO(os_prng(buf, sizeof(buf)));

#ifndef __EMSCRIPTEN__
    CHECK_NOT_NULL(jec = jent_entropy_collector_alloc(1, 0));
    if (jent_read_entropy(jec, buf, sizeof(buf))) {
        SET_ERROR(RET_JITTER_RNG_ERROR);
    }
#endif
cleanup:
#ifndef __EMSCRIPTEN__
    jent_entropy_collector_free(jec);
#endif
    return ret;
}

void entropy_free(void)
{
#ifndef __EMSCRIPTEN__
#if defined(_WIN32) && !defined(_WIN32_WCE)
    if (rng != NULL) {
        CloseHandle(rng);
        rng = NULL;
    }
    if (rng2 != NULL) {
        BCryptCloseAlgorithmProvider(rng2, 0);
        rng2 = NULL;
    }
#else
    //close(rng);
    //rng = 0;
#endif
#endif
}
