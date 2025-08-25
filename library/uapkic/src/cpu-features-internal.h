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

#ifndef UAPKIC_CPU_FEATURES_H
#define UAPKIC_CPU_FEATURES_H

#include <inttypes.h>
#include <stdbool.h>

#if !defined(_M_IX86) && defined(__i386__)
#define _M_IX86
#endif

#if !defined(_M_AMD64) && defined(__x86_64__)
#define _M_AMD64
#endif

#if defined(_M_IX86) || defined(_M_AMD64)
#ifdef _MSC_VER
#include <intrin.h>
#else
#include <immintrin.h>
#endif	// _MSC_VER
#endif	// x86


#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Перевіряє наявність розширення AES-NI на процесорі архітектури x86 або AMD64.
 *
 * @return true, якщо розширення доступне, інакше false.
 * @return на архітектурах, відмінних від x86 або AMD64, — завжди false.
 */
bool cpu_aes_available(void);

/**
 * Заповнює буфер випадковими байтами з ГВЧ, якщо такий є.
 *
 * @param buffer указівник на буфер
 * @param size розмір буферу
 * @return кількість записаних у буфер випадкових байтів; може бути меншою за size у разі помилки.
 */
size_t hw_rng(void* buffer, size_t size);

#ifdef  __cplusplus
}
#endif


#endif	// UAPKIC_CPU_FEATURES_H
