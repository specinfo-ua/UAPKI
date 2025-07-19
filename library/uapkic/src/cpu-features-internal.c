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

#include <inttypes.h>

#if !defined(_M_IX86) && defined(__i386__)
#define _M_IX86
#endif

#if !defined(_M_AMD64) && defined(__x86_64__)
#define _M_AMD64
#endif

#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_AMD64))
#include <intrin.h>
#endif

#include <string.h>
#include <stdbool.h>

//static bool aes_supported = false;
static bool rdrand_supported = false;
static bool rdseed_supported = false;

#ifdef _MSC_VER
#ifdef _M_AMD64
typedef uint64_t rdrand_out_t;
#define RDRAND_SIZE (int)sizeof(uint64_t)
#define RDRAND_FUNC _rdrand64_step
#define RDSEED_FUNC _rdseed64_step
#elif defined(_M_IX86)
typedef uint32_t rdrand_out_t;
#define RDRAND_SIZE (int)sizeof(uint32_t)
#define RDRAND_FUNC _rdrand32_step
#define RDSEED_FUNC _rdseed32_step
#endif
#endif

void cpu_features_init(void) {
#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_AMD64))
	int cpuInfo[4];	// EAX, EBX, ECX, EDX
	__cpuid(cpuInfo, 0);
	int max_func_param = cpuInfo[0];

	if (max_func_param < 1) {
		return;
	}
	__cpuid(cpuInfo, 1);
	//aes_supported = _bittest((const long*)cpuInfo + 2, 25);
	rdrand_supported = _bittest((const long*)cpuInfo + 2, 30);

	if (max_func_param < 7) {
		return;
	}
	__cpuid(cpuInfo, 7);
	rdseed_supported = _bittest((const long*)cpuInfo + 1, 18);
#endif
}

#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_AMD64))
static bool rdrand(rdrand_out_t* n) {
	if (rdseed_supported) {
		for (int i = 10; i; i--) {
			if (RDSEED_FUNC(n)) {
				return true;
			}
		}
		rdseed_supported = false;
	}

	if (rdrand_supported) {
		for (int i = 10; i; i--) {
			if (RDRAND_FUNC(n)) {
				return true;
			}
		}
		rdrand_supported = false;
	}

	return false;
}
#endif

size_t hw_rng(void* buffer, size_t size) {
#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_AMD64))
	union {
		rdrand_out_t n;
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
	*(volatile rdrand_out_t*)&(rdrand_out.n) = 0;
	return bytes_written;
#else
	// Not implemented.

	buffer;
	size;

	return 0;
#endif
}

// TODO: Реалізувати підтримку деяких інших розширень x86.
