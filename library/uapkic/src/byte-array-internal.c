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

#define FILE_MARKER "uapkic/byte-array-internal.c"

#include <string.h>

#include "byte-array-internal.h"
#include "byte-utils-internal.h"
#include "macros-internal.h"

ByteArray *ba_alloc_from_uint8_be(const uint8_t *buf, size_t buf_len)
{
    ByteArray *ba = NULL;
    int ret = RET_OK;

    if (buf != NULL && buf_len != 0) {
        MALLOC_CHECKED(ba, sizeof (ByteArray));
        CHECK_NOT_NULL(ba->buf = uint8_swap_with_alloc(buf, buf_len));
        ba->len = buf_len;
    }

cleanup:

    if (ret != RET_OK) {
        ba_free(ba);
        ba = NULL;
    }

    return ba;
}

ByteArray *ba_alloc_from_uint64(const uint64_t *buf, size_t buf_len)
{
    ByteArray *ba = NULL;
    int ret = RET_OK;

    if (buf != NULL && buf_len != 0) {
        MALLOC_CHECKED(ba, sizeof (ByteArray));
        ba->len = buf_len * UINT64_LEN;
        MALLOC_CHECKED(ba->buf, ba->len);
        DO(uint64_to_uint8(buf, buf_len, ba->buf, ba->len));
    }

cleanup:

    if (ret != RET_OK) {
        ba_free(ba);
        ba = NULL;
    }

    return ba;
}

int ba_to_uint64_with_alloc(const ByteArray *ba, uint64_t **buf, size_t *buf_len)
{
    size_t buf_len_;
    int ret = RET_OK;

    CHECK_PARAM(ba != NULL);
    CHECK_PARAM(buf != NULL);
    CHECK_PARAM(*buf == NULL);

    buf_len_ = (ba->len + UINT64_LEN - 1) / UINT64_LEN;

    MALLOC_CHECKED(*buf, buf_len_ * UINT64_LEN);

    memset(*buf, 0, buf_len_ * UINT64_LEN);
    DO(uint8_to_uint64(ba->buf, ba->len, *buf, buf_len_));
    *buf_len = buf_len_;

cleanup:

    return ret;
}

int ba_to_uint32(const ByteArray *ba, uint32_t *buf, size_t buf_len)
{
    int ret = RET_OK;
    CHECK_PARAM(ba != NULL);
    CHECK_PARAM(buf != NULL);

    DO(uint8_to_uint32(ba->buf, ba->len, buf, buf_len));

cleanup:

    return ret;
}

ByteArray *ba_alloc_from_uint32(const uint32_t *buf, size_t buf_len)
{
    ByteArray *ba = NULL;
    int ret = RET_OK;

    if (buf != NULL && buf_len != 0) {
        MALLOC_CHECKED(ba, sizeof(ByteArray));
        ba->len = buf_len * UINT32_LEN;
        MALLOC_CHECKED(ba->buf, ba->len);
        DO(uint32_to_uint8(buf, buf_len, ba->buf, ba->len));
    }

cleanup:

    if (ret != RET_OK) {
        ba_free(ba);
        ba = NULL;
    }

    return ba;
}

int ba_to_uint64(const ByteArray *ba, uint64_t *buf, size_t buf_len)
{
    int ret = RET_OK;

    CHECK_PARAM(ba != NULL);
    CHECK_PARAM(buf != NULL);
    CHECK_PARAM(buf_len == (ba->len + UINT64_LEN - 1) / UINT64_LEN);

    DO(uint8_to_uint64(ba->buf, ba->len, buf, buf_len));

cleanup:

    return ret;
}

int ba_from_uint64(const uint64_t *buf, size_t buf_len, ByteArray *ba)
{
    int ret = RET_OK;

    CHECK_PARAM(buf != NULL);
    CHECK_PARAM(buf_len != 0);
    CHECK_PARAM(ba != NULL);

    ba->len = buf_len * UINT64_LEN;
    REALLOC_CHECKED(ba->buf, ba->len, ba->buf);
    DO(uint64_to_uint8(buf, buf_len, ba->buf, ba->len));

cleanup:

    return ret;
}

int ba_from_uint32(const uint32_t *buf, size_t buf_len, ByteArray *ba)
{
    int ret = RET_OK;

    CHECK_PARAM(buf != NULL);
    CHECK_PARAM(buf_len != 0);
    CHECK_PARAM(ba != NULL);

    ba->len = buf_len * UINT32_LEN;
    REALLOC_CHECKED(ba->buf, ba->len, ba->buf);
    DO(uint32_to_uint8(buf, buf_len, ba->buf, ba->len));

cleanup:

    return ret;
}

int ba_trim_leading_zeros(ByteArray *ba)
{
    size_t i;
    int ret = RET_OK;

    CHECK_PARAM(ba);
    CHECK_PARAM(ba->buf);

    i = ba->len - 1;
    while (ba->buf[i] == 0 && i != 0) {
        i--;
    }
    i++;

    REALLOC_CHECKED(ba->buf, i, ba->buf);
    ba->len = i;

cleanup:

    return ret;
}

int ba_truncate(ByteArray *a, size_t bit_len)
{
    int ret = RET_OK;
    size_t byte_off = bit_len >> 3;

    CHECK_PARAM(a != NULL);

    a->buf[byte_off] &= (((uint8_t) 1 << (bit_len & 0x07)) - 1);
    if (a->len > byte_off) {
        memset(&a->buf[byte_off + 1], 0, a->len - byte_off - 1);
    }

cleanup:

    return ret;
}

bool ba_is_zero(const ByteArray *a)
{
    size_t i;
    if (a == NULL) {
        return true;
    }

    for (i = 0; i < a->len; i++) {
        if (a->buf[i] != 0) {
            return false;
        }
    }

    return true;
}
