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

#ifndef UAPKIC_WORD_INTERNAL_H
#define UAPKIC_WORD_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "byte-array-internal.h"

#ifdef  __cplusplus
extern "C" {
#endif

#if defined(__LP64__) || defined(_WIN64)
# define ARCH64
#else
# define ARCH32
#endif

#ifdef ARCH64
# define WORD_BIT_LENGTH  64
# define DWORD_BIT_LENGTH 128
# define WORD_BIT_LEN_MASK 0x3f
# define WORD_BIT_LEN_SHIFT 6
# define WORD_BYTE_LEN_SHIFT 3
# define HALF_WORD_BIT_LENGTH 32

typedef uint64_t word_t;

# define HALF_WORD_MASK ((word_t)0xffffffff)

#else
# undef ARCH32
# define ARCH32
# define WORD_BIT_LENGTH      32
# define DWORD_BIT_LENGTH     64
# define WORD_BIT_LEN_MASK  0x1f
# define WORD_BIT_LEN_SHIFT    5
# define WORD_BYTE_LEN_SHIFT   2
# define HALF_WORD_BIT_LENGTH 16

typedef uint32_t word_t;

# define HALF_WORD_MASK ((word_t)0xffff)

#endif

#define WORD_LO(_a) ((_a) & HALF_WORD_MASK)
#define WORD_HI(_a) ((_a) >> HALF_WORD_BIT_LENGTH)
#define WA_LEN(_bytes) ((int)(((_bytes) + sizeof(word_t) - 1) >> WORD_BYTE_LEN_SHIFT))
#define WA_LEN_FROM_BITS(_bits) (((_bits) + WORD_BIT_LENGTH - 1) >> WORD_BIT_LEN_SHIFT)

#define WORD_BYTE_LENGTH (sizeof(word_t))

/* Необхідно використовувати, якщо не гарантовано, що величина зсуву менша за довжину слова в бітах. */
#define WORD_LSHIFT(_word, _bit) (((_bit) >= WORD_BIT_LENGTH) ? 0 : ((_word) << (_bit)))
#define WORD_RSHIFT(_word, _bit) (((_bit) >= WORD_BIT_LENGTH) ? 0 : ((_word) >> (_bit)))

typedef struct WordArray_st {
    word_t *buf;
    size_t len;
} WordArray;

WordArray *wa_alloc(size_t len);
WordArray *wa_alloc_with_zero(size_t len);
WordArray *wa_alloc_with_one(size_t len);
void wa_zero(WordArray *wa);
void wa_one(WordArray *wa);
WordArray *wa_alloc_from_ba(const ByteArray *in);
WordArray *wa_alloc_from_le(const uint8_t *in, size_t in_len);
WordArray *wa_alloc_from_be(const uint8_t *in, size_t in_len);
int wa_from_ba(const ByteArray *ba, WordArray *wa);
WordArray *wa_copy_with_alloc(const WordArray *in);
int wa_copy(const WordArray *in, WordArray *out);
int wa_copy_part(const WordArray *in, size_t off, size_t len, WordArray *out);
ByteArray *wa_to_ba(const WordArray *wa);
void wa_change_len(WordArray *wa, size_t len);
void wa_free(WordArray *in);
void wa_free_private(WordArray *in);
int word_bit_len(word_t a);
word_t generate_bits(size_t bits);
WordArray *wa_alloc_from_uint8(const uint8_t *in, size_t in_len);
int wa_to_uint8(WordArray *wa, uint8_t *in, size_t in_len);

int wa_cmp(const WordArray *a, const WordArray *b);

#ifdef  __cplusplus
}
#endif

#endif
