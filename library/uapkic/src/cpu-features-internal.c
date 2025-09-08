/*
 * Copyright 2025 The UAPKI Project Authors.
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

#define FILE_MARKER "uapkic/cpu-features-internal.c"

#include <string.h>

#include "cpu-features-internal.h"
#include "word-internal.h"

/**
 * References:
 * https://www.intel.com/content/www/us/en/developer/articles/tool/intel-advanced-encryption-standard-aes-instructions-set.html
 * https://www.intel.com/content/www/us/en/developer/articles/guide/intel-digital-random-number-generator-drng-software-implementation-guide.html
 */

static bool aes_supported = false;
static bool rdrand_supported = false;
static bool rdseed_supported = false;

#ifdef _M_AMD64
#define RDRAND_SIZE (int)sizeof(word_t)
#define RDRAND_FUNC _rdrand64_step
#define RDSEED_FUNC _rdseed64_step
#elif defined(_M_IX86)
#define RDRAND_SIZE (int)sizeof(word_t)
#define RDRAND_FUNC _rdrand32_step
#define RDSEED_FUNC _rdseed32_step
#endif

void cpu_features_init(void)
{
#if defined(_M_IX86) || defined(_M_AMD64)
	int cpuInfo[4];	// EAX, EBX, ECX, EDX
	__cpuid(cpuInfo, 0);
	int max_func_param = cpuInfo[0];

	if (max_func_param < 1) {
		return;
	}
	__cpuid(cpuInfo, 1);
	aes_supported = (cpuInfo[2] >> 25) & 1;
	rdrand_supported = (cpuInfo[2] >> 30) & 1;

	if (max_func_param < 7) {
		return;
	}
	__cpuid(cpuInfo, 7);
	rdseed_supported = (cpuInfo[1] >> 18) & 1;
#endif
}

bool cpu_aes_available(void)
{
#if defined(_M_IX86) || defined(_M_AMD64)
	return aes_supported;
#else
	return false;
#endif
}

#if defined(_M_IX86) || defined(_M_AMD64)
#ifdef __GNUC__
#pragma GCC target("rdrnd", "rdseed")
#elif defined(__clang__)
__attribute__((target("rdrnd,rdseed")))
#endif
static bool rdrand(word_t *n)
{
	word_t a;

	if (rdseed_supported) {
		for (int i = 10; i; i--) {
			if (RDSEED_FUNC(&a)) {
				*n = a;
				return true;
			}
		}
		rdseed_supported = false;
	}

	if (rdrand_supported) {
		for (int i = 10; i; i--) {
			if (RDRAND_FUNC(&a)) {
				*n = a;
				return true;
			}
		}
		rdrand_supported = false;
	}

	return false;
}
#endif	// x86

size_t hw_rng(void *buffer, size_t size)
{
#if defined(_M_IX86) || defined(_M_AMD64)
	union {
		word_t n;
		uint8_t a[RDRAND_SIZE];
	} rdrand_out;
	intptr_t buffer_address = (intptr_t)buffer;
	size_t bytes_written = 0;
	int head_align = buffer_address & (RDRAND_SIZE - 1);

	if (head_align) {
		if (!rdrand(&rdrand_out.n)) {
			return 0;
		}
		if (size <= RDRAND_SIZE) {
			memcpy(buffer, rdrand_out.a, size);
			bytes_written = size;
			goto cleanup;
		}
		int head_len = RDRAND_SIZE - head_align;
		memcpy((void*)buffer_address, rdrand_out.a + head_align, head_len);
		buffer_address += head_len;
		bytes_written += head_len;
		size -= head_len;
	}

	// Now we can perform aligned writes.
	while (size >= RDRAND_SIZE) {
		if (!rdrand((void*)buffer_address)) {
			goto cleanup;
		}
		buffer_address += RDRAND_SIZE;
		bytes_written += RDRAND_SIZE;
		size -= RDRAND_SIZE;
	}

	if (size) {
		if (head_align < size && !rdrand(&rdrand_out.n)) {
			goto cleanup;
		}
		memcpy((void*)buffer_address, rdrand_out.a, size);
		bytes_written += size;
	}

cleanup:
	*(volatile word_t*)&(rdrand_out.n) = 0;
	return bytes_written;
#else	// x86
	// Not implemented.

	buffer;
	size;

	return 0;
#endif
}

// TODO: Реалізувати підтримку деяких інших розширень x86, як-от AES-NI.
