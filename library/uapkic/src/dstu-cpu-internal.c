/*
 * Copyright 2026 The UAPKI Project Authors.
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

#include "dstu-cpu-internal.h"

#if DSTU_AVX512
#include <cpuid.h>
#include <stdlib.h>

static int detect_avx512(void)
{
    unsigned int a, b, c, d, xcr0, xcr0_hi;
    const char *disabled = getenv("UAPKIC_DISABLE_AVX512");
    if (disabled && disabled[0] && disabled[0] != '0') return 0;
    if (!__get_cpuid(1, &a, &b, &c, &d) || !(c & (1u << 27))) return 0;
    /* The OS must save XMM, YMM, opmask and both ZMM state components. */
    __asm__ volatile ("xgetbv" : "=a"(xcr0), "=d"(xcr0_hi) : "c"(0));
    if ((xcr0 & 0xe6) != 0xe6) return 0;
    return __builtin_cpu_supports("avx512f") &&
        __builtin_cpu_supports("avx512bw") &&
        __builtin_cpu_supports("avx512vl") &&
        __builtin_cpu_supports("avx512vbmi") &&
        __builtin_cpu_supports("gfni");
}
#endif

int dstu_avx512_available(void)
{
#if DSTU_AVX512
    /* Detection is idempotent; no locks, mutable tables or initialization race. */
    static int cached = -1;
    int result = __atomic_load_n(&cached, __ATOMIC_RELAXED);
    if (result < 0) {
        result = detect_avx512();
        __atomic_store_n(&cached, result, __ATOMIC_RELAXED);
    }
    return result;
#else
    return 0;
#endif
}
