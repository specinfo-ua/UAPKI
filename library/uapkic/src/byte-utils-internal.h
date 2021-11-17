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

#ifndef UAPKIC_BYTE_UTILS_H
#define UAPKIC_BYTE_UTILS_H

#include <inttypes.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define UINT32_LEN             4
#define UINT64_LEN             8

int uint8_to_uint32(const uint8_t *in, size_t in_len, uint32_t *out, size_t out_len);
int uint32_to_uint8(const uint32_t *in, size_t in_len, uint8_t *out, size_t out_len);
int uint64_to_uint8(const uint64_t *in, size_t in_len, uint8_t *out, size_t out_len);
int uint8_to_uint64(const uint8_t *in, size_t in_len, uint64_t *out, size_t out_len);
int uint32_to_uint64(const uint32_t *in, size_t in_len, uint64_t *out, size_t out_len);
int uint64_to_uint32(const uint64_t *in, size_t in_len, uint32_t *out, size_t out_len);
uint8_t *uint8_swap_with_alloc(const uint8_t *in, size_t in_len);
int uint8_swap(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len);
void secure_zero(void *s, size_t n);

#ifdef  __cplusplus
}
#endif

#endif
