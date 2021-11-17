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

#include <string.h>

#include "word-internal.h"
#include "byte-utils-internal.h"
#include "macros-internal.h"

#undef FILE_MARKER
#define FILE_MARKER "uapkic/word-internal.c"

WordArray *wa_alloc(size_t len)
{
    WordArray *wa = NULL;
    int ret = RET_OK;

    CHECK_PARAM(len != 0);

    CALLOC_CHECKED(wa, sizeof(WordArray));
    MALLOC_CHECKED(wa->buf, len * WORD_BYTE_LENGTH);
    wa->len = len;

cleanup:
    if (ret != RET_OK) {
        wa_free(wa);
        wa = NULL;
    }

    return wa;
}

void wa_zero(WordArray *wa)
{
    if (wa) {
        memset(wa->buf, 0, wa->len * WORD_BYTE_LENGTH);
    }
}

WordArray *wa_alloc_with_zero(size_t len)
{
    WordArray *wa = NULL;
    int ret = RET_OK;

    CHECK_PARAM(len != 0);
    CHECK_NOT_NULL(wa = wa_alloc(len));
    memset(wa->buf, 0, len * WORD_BYTE_LENGTH);

cleanup:
    if (ret != RET_OK) {
        wa_free(wa);
        wa = NULL;
    }

    return wa;
}

void wa_one(WordArray *wa)
{
    if (wa) {
        memset(wa->buf, 0, wa->len * WORD_BYTE_LENGTH);
        wa->buf[0] = 1;
    }
}

WordArray *wa_alloc_with_one(size_t len)
{
    WordArray *wa = NULL;
    int ret = RET_OK;

    CHECK_PARAM(len != 0);

    CHECK_NOT_NULL(wa = wa_alloc(len));
    memset(wa->buf, 0, len * WORD_BYTE_LENGTH);
    wa->buf[0] = 1;


cleanup:
    if (ret != RET_OK) {
        wa_free(wa);
        wa = NULL;
    }
    return wa;
}

WordArray *wa_alloc_from_ba(const ByteArray *ba)
{
    WordArray *ans = NULL;
    int ret;

    CHECK_PARAM(ba != NULL);

    CHECK_NOT_NULL(ans = wa_alloc_from_le(ba->buf, ba->len));

cleanup:

    return ans;
}

WordArray *wa_alloc_from_le(const uint8_t *in, size_t in_len)
{
    WordArray *wa = NULL;
    int ret = RET_OK;

    CHECK_PARAM(in != NULL);
    CHECK_PARAM(in_len != 0);

    MALLOC_CHECKED(wa, sizeof(WordArray));
    wa->len = (in_len + WORD_BYTE_LENGTH - 1) / WORD_BYTE_LENGTH;
    MALLOC_CHECKED(wa->buf, wa->len * WORD_BYTE_LENGTH);

#ifdef ARCH64
    DO(uint8_to_uint64(in, in_len, wa->buf, wa->len));
#else
    DO(uint8_to_uint32(in, in_len, wa->buf, wa->len));
#endif

cleanup:
    if (ret != RET_OK) {
        wa_free(wa);
        wa = NULL;
    }
    return wa;
}

WordArray *wa_alloc_from_be(const uint8_t *in, size_t in_len)
{
    WordArray *wa = NULL;
    uint8_t *in_le = NULL;
    int ret = RET_OK;

    CHECK_PARAM(in != NULL);
    CHECK_PARAM(in_len != 0);

    MALLOC_CHECKED(wa, sizeof(WordArray));
    wa->len = (in_len + WORD_BYTE_LENGTH - 1) / WORD_BYTE_LENGTH;
    MALLOC_CHECKED(wa->buf, wa->len * WORD_BYTE_LENGTH);
    CHECK_NOT_NULL(in_le = uint8_swap_with_alloc(in, in_len));

#ifdef ARCH64
    DO(uint8_to_uint64(in_le, in_len, wa->buf, wa->len));
#else
    DO(uint8_to_uint32(in_le, in_len, wa->buf, wa->len));
#endif


cleanup:
    if (ret != RET_OK) {
        wa_free(wa);
        wa = NULL;
    }
    free(in_le);

    return wa;
}

int wa_from_ba(const ByteArray *ba, WordArray *wa)
{
    int ret = RET_OK;

    CHECK_PARAM(ba != NULL);

    wa->len = (ba->len + WORD_BYTE_LENGTH - 1) / WORD_BYTE_LENGTH;
    REALLOC_CHECKED(wa->buf, wa->len * WORD_BYTE_LENGTH, wa->buf);

#ifdef ARCH64
    DO(uint8_to_uint64(ba->buf, ba->len, wa->buf, wa->len));
#else
    DO(uint8_to_uint32(ba->buf, ba->len, wa->buf, wa->len));
#endif

cleanup:

    return ret;
}

WordArray *wa_copy_with_alloc(const WordArray *in)
{
    WordArray *wa = NULL;
    int ret = RET_OK;

    CHECK_PARAM(in != NULL);

    CHECK_NOT_NULL(wa = wa_alloc(in->len));
    DO(wa_copy(in, wa));

cleanup:
    if (ret != RET_OK) {
        wa_free(wa);
        wa = NULL;
    }
    return wa;
}

int wa_to_uint8(WordArray *wa, uint8_t *in, size_t in_len)
{
    int ret = RET_OK;

    CHECK_PARAM(wa != NULL);
    CHECK_PARAM(in != NULL);

#ifdef ARCH64
    DO(uint64_to_uint8(wa->buf, wa->len, in, in_len));
#else
    DO(uint32_to_uint8(wa->buf, wa->len, in, in_len));
#endif

cleanup:
    return ret;
}

WordArray *wa_alloc_from_uint8(const uint8_t *in, size_t in_len)
{
    WordArray *wa = NULL;
    int ret = RET_OK;

    CHECK_PARAM(in != NULL);
    CHECK_PARAM(in_len != 0);

    MALLOC_CHECKED(wa, sizeof (WordArray));
    wa->len = (in_len + WORD_BYTE_LENGTH - 1) / WORD_BYTE_LENGTH;
    MALLOC_CHECKED(wa->buf, wa->len * WORD_BYTE_LENGTH);

#ifdef ARCH64
    DO(uint8_to_uint64(in, in_len, wa->buf, wa->len));
#else
    DO(uint8_to_uint32(in, in_len, wa->buf, wa->len));
#endif

    return wa;
cleanup:
    free(wa);
    return NULL;
}

int wa_copy(const WordArray *in, WordArray *out)
{
    if (in == NULL || out == NULL || in->len > out->len) {
        ERROR_CREATE(RET_INVALID_PARAM);
        return RET_INVALID_PARAM;
    }

    if (in != out) {
        memcpy(out->buf, in->buf, in->len * WORD_BYTE_LENGTH);
        if (in->len < out->len) {
            memset(&out->buf[in->len], 0, (out->len - in->len) * WORD_BYTE_LENGTH);
        }
    }

    return RET_OK;
}

int wa_copy_part(const WordArray *in, size_t off, size_t len, WordArray *out)
{
    if (in == NULL || out == NULL || in->len < off + len || out->len != len || in == out) {
        ERROR_CREATE(RET_INVALID_PARAM);
        return RET_INVALID_PARAM;
    }

    memcpy(out->buf, in->buf + off, len * WORD_BYTE_LENGTH);

    return RET_OK;
}

ByteArray *wa_to_ba(const WordArray *wa)
{
    ByteArray *ans = NULL;
    int ret;

    if (wa != NULL) {
#ifdef ARCH64
        CHECK_NOT_NULL(ans = ba_alloc_from_uint64(wa->buf, wa->len));
#else
        CHECK_NOT_NULL(ans = ba_alloc_from_uint32(wa->buf, wa->len));
#endif
    }

cleanup:

    return ans;
}

void wa_change_len(WordArray *wa, size_t len)
{
    int ret = RET_OK;

    REALLOC_CHECKED(wa->buf, len * sizeof (word_t), wa->buf);
    if (wa->len < len) {
        memset(&wa->buf[wa->len], 0, (len - wa->len) * sizeof (word_t));
    }
    wa->len = len;

cleanup:
    return;
}

void wa_free(WordArray *in)
{
    if (in) {
        free(in->buf);
        free(in);
    }
}

void wa_free_private(WordArray *in)
{
    if (in) {
        if (in->buf && in->len > 0) {
            secure_zero(in->buf, in->len * WORD_BYTE_LENGTH);
        }
        free(in->buf);
        free(in);
    }
}

#define U64(a) ((uint64_t)(a))

int word_bit_len(word_t a)
{
#ifdef ARCH64
    return
            (a < U64(0x100000000) ?
                    (a < 0x10000 ? (a < 0x100 ? (a < 0x10 ?
                            (a < 0x4 ? (a < 0x2 ? (a < 0x1 ? 0 : 1) : 2) : (a < 0x8 ? 3 : 4))
                            : (a < 0x40 ? (a < 0x20 ? 5 : 6) : (a < 0x80 ? 7 : 8)))
                            : (a < 0x1000 ?
                                    (a < 0x400 ? (a < 0x200 ? 9 : 10) : (a < 0x800 ? 11 : 12))
                                    : (a < 0x4000 ? (a < 0x2000 ? 13 : 14) : (a < 0x8000 ? 15 : 16))))
                            : (a < 0x1000000 ? (a < 0x100000 ?
                                    (a < 0x40000 ? (a < 0x20000 ? 17 : 18) : (a < 0x80000 ? 19 : 20))
                                    : (a < 0x400000 ? (a < 0x200000 ? 21 : 22) : (a < 0x800000 ? 23 : 24)))
                                    : (a < 0x10000000 ?
                                            (a < 0x4000000 ? (a < 0x2000000 ? 25 : 26) : (a < 0x8000000 ? 27 : 28))
                                            : (a < 0x40000000 ? (a < 0x20000000 ? 29 : 30) : (a < 0x80000000 ? 31 : 32)))))

                    : (a < U64(0x1000000000000) ? (a < U64(0x10000000000) ? (a < U64(0x1000000000) ?
                            (a < U64(0x400000000) ? (a < U64(0x200000000) ? 33 : 34) : (a < U64(0x800000000) ? 35 : 36))
                            : (a < U64(0x4000000000) ? (a < U64(0x2000000000) ? 37 : 38) : (a < U64(0x8000000000) ? 39 : 40)))
                            : (a < U64(0x100000000000) ?
                                    (a < U64(0x40000000000) ? (a < U64(0x20000000000) ? 41 : 42) : (a < U64(0x80000000000) ? 43 : 44))
                                    : (a < U64(0x400000000000) ? (a < U64(0x200000000000) ? 45 : 46) : (a < U64(0x800000000000) ? 47 : 48))))
                            : (a < U64(0x100000000000000) ? (a < U64(0x10000000000000) ?
                                    (a < U64(0x4000000000000) ? (a < U64(0x2000000000000) ? 49 : 50) : (a < U64(0x8000000000000) ? 51 : 52))
                                    : (a < U64(0x40000000000000) ? (a < U64(0x20000000000000) ? 53 : 54) : (a < U64(0x80000000000000) ? 55 : 56)))
                                    : (a < U64(0x1000000000000000) ?
                                            (a < U64(0x400000000000000) ? (a < U64(0x200000000000000) ? 57 : 58) : (a < U64(0x800000000000000) ? 59 : 60))
                                            : (a < U64(0x4000000000000000) ? (a < U64(0x2000000000000000) ? 61 : 62) : (a < U64(0x8000000000000000) ? 63 : 64))))));
#else
    return
            (a < 0x10000 ? (a < 0x100 ? (a < 0x10 ?
                    (a < 0x4 ? (a < 0x2 ? (a < 0x1 ? 0 : 1) : 2) : (a < 0x8 ? 3 : 4))
                    : (a < 0x40 ? (a < 0x20 ? 5 : 6) : (a < 0x80 ? 7 : 8)))
                    : (a < 0x1000 ?
                            (a < 0x400 ? (a < 0x200 ? 9 : 10) : (a < 0x800 ? 11 : 12))
                            : (a < 0x4000 ? (a < 0x2000 ? 13 : 14) : (a < 0x8000 ? 15 : 16))))
                    : (a < 0x1000000 ? (a < 0x100000 ?
                            (a < 0x40000 ? (a < 0x20000 ? 17 : 18) : (a < 0x80000 ? 19 : 20))
                            : (a < 0x400000 ? (a < 0x200000 ? 21 : 22) : (a < 0x800000 ? 23 : 24)))
                            : (a < 0x10000000 ?
                                    (a < 0x4000000 ? (a < 0x2000000 ? 25 : 26) : (a < 0x8000000 ? 27 : 28))
                                    : (a < 0x40000000 ? (a < 0x20000000 ? 29 : 30) : (a < 0x80000000 ? 31 : 32)))));
#endif
}

int wa_cmp(const WordArray *a, const WordArray *b)
{
    if (a->len != b->len) {
        return (int)(a->len - b->len);
    }

    return memcmp(a->buf, b->buf, a->len * sizeof(word_t));
}
