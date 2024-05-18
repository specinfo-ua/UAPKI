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

#define FILE_MARKER "uapkic/byte-array.c"

#include <stddef.h>
#include <string.h>

#include "byte-array.h"
#include "byte-array-internal.h"
#include "byte-utils-internal.h"
#include "macros-internal.h"

ByteArray *ba_alloc(void)
{
    ByteArray *ba = NULL;
    int ret = RET_OK;

    MALLOC_CHECKED(ba, sizeof (ByteArray));

    ba->buf = NULL;
    ba->len = 0;

cleanup:

    return ba;
}

ByteArray *ba_alloc_by_len(size_t len)
{
    ByteArray *ba = NULL;
    int ret = RET_OK;

    MALLOC_CHECKED(ba, sizeof (ByteArray));
    MALLOC_CHECKED(ba->buf, len);

    ba->len = len;

    return ba;
cleanup:
    return NULL;
}

ByteArray *ba_alloc_from_uint8(const uint8_t *buf, size_t buf_len)
{
    ByteArray *ba = NULL;
    int ret = RET_OK;

    if (buf != NULL) {
        MALLOC_CHECKED(ba, sizeof (ByteArray));
        if (buf_len != 0) {
            MALLOC_CHECKED(ba->buf, buf_len);
            memcpy(ba->buf, buf, buf_len);
        } else {
            ba->buf = NULL;
        }

        ba->len = buf_len;
    }

    return ba;

cleanup:

    free(ba);

    return NULL;
}

ByteArray *ba_alloc_from_str(const char *buf)
{
    ByteArray *ans = NULL;
    int ret = RET_OK;

    if (buf != NULL) {
        CHECK_NOT_NULL(ans = ba_alloc_from_uint8((const uint8_t *)buf, strlen(buf)));
    }

cleanup:

    return ans;
}

ByteArray *ba_copy_with_alloc(const ByteArray *in, size_t off, size_t len)
{
    ByteArray *ba = NULL;
    int ret = RET_OK;

    if ((in != NULL) && (in->len >= (off + len))) {
        if (len == 0) {
            len = in->len - off;
        }

        MALLOC_CHECKED(ba, sizeof (ByteArray));
        MALLOC_CHECKED(ba->buf, len);

        memcpy(ba->buf, &in->buf[off], len);
        ba->len = len;
    }

    return ba;
cleanup:

    free(ba);
    return NULL;
}

int ba_swap(const ByteArray *a)
{
    int ret = RET_OK;

    CHECK_PARAM(a != NULL);
    DO(uint8_swap(a->buf, a->len, a->buf, a->len));

cleanup:

    return ret;
}

int ba_xor(const ByteArray *a, const ByteArray *b)
{
    int ret = RET_OK;
    size_t i;

    CHECK_PARAM(a != NULL);
    CHECK_PARAM(b != NULL);
    CHECK_PARAM(b->len >= a->len);

    for (i = 0; i < a->len; i++) {
        a->buf[i] ^= b->buf[i];
    }

cleanup:

    return ret;
}

int ba_set(ByteArray *a, uint8_t value)
{
    int ret = RET_OK;

    CHECK_PARAM(a != NULL);

    memset(a->buf, value, a->len);

cleanup:

    return ret;
}

ByteArray *ba_join(const ByteArray *a, const ByteArray *b)
{
    ByteArray *out = NULL;
    int ret = RET_OK;

    CHECK_PARAM(a != NULL);
    CHECK_PARAM(b != NULL);

    CHECK_NOT_NULL(out = ba_alloc_by_len(a->len + b->len));
    memcpy(out->buf, a->buf, a->len);
    memcpy(out->buf + a->len, b->buf, b->len);

cleanup:

    return out;
}

int ba_cmp(const ByteArray *a, const ByteArray *b)
{
    if (a && b) {
        if (a->len != b->len) {
            return (int)(a->len - b->len);
        }

        return memcmp(a->buf, b->buf, a->len);
    }

    ERROR_CREATE(RET_INVALID_PARAM);

    return -1;
}

size_t ba_get_len(const ByteArray *ba)
{
    return (ba != NULL) ? ba->len : 0;
}

const uint8_t* ba_get_buf_const(const ByteArray* ba)
{
    if (ba) {
        return ba->buf;
    }
    ERROR_CREATE(RET_INVALID_PARAM);

    return NULL;
}

uint8_t* ba_get_buf(ByteArray* ba)
{
    if (ba) {
        return ba->buf;
    }
    ERROR_CREATE(RET_INVALID_PARAM);

    return NULL;
}

int ba_get_byte(const ByteArray* ba, size_t index, uint8_t* value)
{
    int ret = RET_OK;

    CHECK_PARAM(ba != NULL);
    CHECK_PARAM(value != NULL);

    if (index < ba->len) {
        *value = ba->buf[index];
    }
    else {
        ret = RET_INDEX_OUT_OF_RANGE;
    }

cleanup:
    return ret;
}

int ba_set_byte(ByteArray* ba, size_t index, uint8_t value)
{
    int ret = RET_OK;

    CHECK_PARAM(ba != NULL);

    if (index < ba->len) {
        ba->buf[index] = value;
    }
    else {
        ret = RET_INDEX_OUT_OF_RANGE;
    }

cleanup:
    return ret;
}

int ba_to_uint8_with_alloc(const ByteArray *ba, uint8_t **buf, size_t *buf_len)
{
    int ret = RET_OK;

    CHECK_PARAM(ba != NULL);
    CHECK_PARAM(buf != NULL);
    CHECK_PARAM(buf_len != NULL);

    MALLOC_CHECKED(*buf, ba->len);
    memcpy(*buf, ba->buf, ba->len);
    *buf_len = ba->len;

cleanup:
    return ret;
}

int ba_to_uint8(const ByteArray *ba, uint8_t *buf, size_t buf_len)
{
    int ret = RET_OK;

    CHECK_PARAM(ba != NULL);
    CHECK_PARAM(buf != NULL);
    CHECK_PARAM(ba->len <= buf_len);

    memcpy(buf, ba->buf, ba->len);
cleanup:
    return ret;
}

int ba_copy(const ByteArray *in, size_t in_off, size_t len, ByteArray *out, size_t out_off)
{
    int ret = RET_OK;

    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    if (len == 0) {
        len = in->len - in_off;
    }
    CHECK_PARAM(in_off + len <= in->len);
    CHECK_PARAM(out_off + len <= out->len);

    memcpy(&out->buf[out_off], &in->buf[in_off], len);
cleanup:
    return ret;
}

int ba_append(const ByteArray *in, size_t in_off, size_t len, ByteArray *out)
{
    int ret = RET_OK;

    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    if (len == 0) {
        len = in->len - in_off;
    }
    CHECK_PARAM(in_off + len <= in->len);
    REALLOC_CHECKED(out->buf, out->len + len, out->buf);
    memcpy(&out->buf[out->len], &in->buf[in_off], len);
    out->len += len;

cleanup:

    return ret;
}

void ba_free(ByteArray *ba)
{
    if (ba) {
        free(ba->buf);
    }
    free(ba);
}


int ba_change_len(ByteArray *ba, size_t len)
{
    int ret = RET_OK;
    if (ba == NULL) {
        SET_ERROR(RET_INVALID_PARAM);
    }

    REALLOC_CHECKED(ba->buf, len, ba->buf);

    if (ba->len < len) {
        memset(&ba->buf[ba->len], 0, len - ba->len);
    }
    ba->len = len;

cleanup:

    return ret;
}

void ba_free_private(ByteArray *ba)
{
    if (ba) {
        secure_zero(ba->buf, ba->len);
        free(ba->buf);
    }
    free(ba);
}

int ba_trim_leading_zeros_le(ByteArray* ba)
{
    int ret = RET_OK;
    const uint8_t* buf;
    size_t i;

    CHECK_PARAM(ba);

    buf = ba_get_buf(ba);

    for (i = ba_get_len(ba) - 1; i > 1; --i) {
        if (buf[i] != 0) {
            break;
        }
    }

    DO(ba_change_len(ba, i + 1));

cleanup:

    return ret;
}

static int base64_encode(const uint8_t* in, size_t inlen, uint8_t* out, size_t* outlen)
{
    static const uint8_t* codes = (uint8_t*)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i, len2, leven;
    uint8_t* p;

    len2 = 4 * ((inlen + 2) / 3);
    if (*outlen < len2 + 1) {
        *outlen = len2 + 1;
        return RET_DATA_TOO_LONG;
    }

    p = out;
    leven = 3 * (inlen / 3);
    for (i = 0; i < leven; i += 3) {
        *p++ = codes[(in[0] >> 2) & 0x3F];
        *p++ = codes[(((in[0] & 3) << 4) + (in[1] >> 4)) & 0x3F];
        *p++ = codes[(((in[1] & 0xf) << 2) + (in[2] >> 6)) & 0x3F];
        *p++ = codes[in[2] & 0x3F];
        in += 3;
    }

    if (i < inlen) {
        unsigned a = in[0];
        unsigned b = (i + 1 < inlen) ? in[1] : 0;

        *p++ = codes[(a >> 2) & 0x3F];
        *p++ = codes[(((a & 3) << 4) + (b >> 4)) & 0x3F];
        *p++ = (i + 1 < inlen) ? codes[(((b & 0xf) << 2)) & 0x3F] : '=';
        *p++ = '=';
    }

    *p = '\0';

    *outlen = len2 + 1;
    return RET_OK;
}

int ba_to_base64(const ByteArray* ba, char* buf, size_t *buflen)
{
    int ret = RET_OK;

    CHECK_PARAM(ba);
    CHECK_PARAM(buf);
    CHECK_PARAM(buflen);

    DO(base64_encode(ba->buf, ba->len, (uint8_t*)buf, buflen));

cleanup:
    return ret;
}

int ba_to_base64_with_alloc(const ByteArray* ba, char** buf)
{
    int ret = RET_OK;
    size_t buf_len;

    CHECK_PARAM(ba);
    CHECK_PARAM(buf);

    buf_len = 4 * ((ba->len + 2) / 3) + 1;

    if ((*buf = malloc(buf_len)) == NULL) {
        return RET_MEMORY_ALLOC_ERROR;
    }
    DO(base64_encode(ba->buf, ba->len, (uint8_t*)*buf, &buf_len));

cleanup:
    if (ret != RET_OK) {
        free(*buf);
    }

    return ret;
}

static int base64_decode(const uint8_t* in, size_t inlen, uint8_t* out, size_t* outlen)
{
    static const uint8_t base64map[256] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255,  62, 255, 255, 255,  63,
    52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255,
    255, 254, 255, 255, 255,   0,   1,   2,   3,   4,   5,   6,
    7,   8,   9,  10,  11,  12,  13,  14,  15,  16,  17,  18,
    19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255, 255,
    255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,
    37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
    49,  50,  51, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255 };

    size_t t, x, y, z;
    uint8_t c;
    int g;

    g = 3;
    for (x = y = z = t = 0; x < inlen; x++) {
        c = base64map[in[x] & 0xFF];
        if (c == 255) continue;

        if (c == 254) {
            c = 0;

            if (--g < 0) {
                return RET_INVALID_BASE64_STRING;
            }
        }
        else if (g != 3) {
            return RET_INVALID_BASE64_STRING;
        }

        t = (t << 6) | c;

        if (++y == 4) {
            if (z + g > *outlen) {
                return RET_DATA_TOO_LONG;
            }
            out[z++] = (uint8_t)((t >> 16) & 255);
            if (g > 1) out[z++] = (uint8_t)((t >> 8) & 255);
            if (g > 2) out[z++] = (uint8_t)(t & 255);
            y = t = 0;
        }
    }
    if (y != 0) {
        return RET_INVALID_BASE64_STRING;
    }
    *outlen = z;
    return RET_OK;
}

ByteArray* ba_alloc_from_base64(const char* str)
{
    int ret = RET_OK;
    ByteArray* ba = NULL;
    size_t len = (strlen(str) * 3) / 4;

    CHECK_NOT_NULL(ba = ba_alloc_by_len(len));
    DO(base64_decode((const uint8_t*)str, strlen(str), ba->buf, &len));
    if (len > 0) {
        DO(ba_change_len(ba, len));
    }

cleanup:
    if (ret != RET_OK) {
        ba_free(ba);
        ba = NULL;
    }
    return ba;
}

int ba_from_base64(const char* str, ByteArray* ba)
{
    int ret = RET_OK;
    size_t len;

    CHECK_PARAM(str != NULL);
    CHECK_PARAM(ba != NULL);

    len = (strlen(str) * 3) / 4;

    REALLOC_CHECKED(ba->buf, len, ba->buf);
    ba->len = len;
    DO(base64_decode((const uint8_t*)str, strlen(str), ba->buf, &len));
    DO(ba_change_len(ba, len));

cleanup:

    return ret;
}

int ba_from_uint8(const uint8_t* buf, size_t buf_len, ByteArray* ba)
{
    int ret = RET_OK;

    CHECK_PARAM(buf != NULL);
    CHECK_PARAM(buf_len != 0);
    CHECK_PARAM(ba != NULL);

    REALLOC_CHECKED(ba->buf, buf_len, ba->buf);

    memcpy(ba->buf, buf, buf_len);
    ba->len = buf_len;

cleanup:

    return ret;
}

static const uint16_t hexmap[] = {
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100,
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100,
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // ........
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // ........
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, //  !"#$%&'
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // ()*+,-./
    0x000, 0x001, 0x002, 0x003, 0x004, 0x005, 0x006, 0x007, // 01234567
    0x008, 0x009, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // 89:;<=>?
    0x100, 0x00a, 0x00b, 0x00c, 0x00d, 0x00e, 0x00f, 0x100, // @ABCDEFG
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // HIJKLMNO
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // PQRSTUVW
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // XYZ[\]^_
    0x100, 0x00a, 0x00b, 0x00c, 0x00d, 0x00e, 0x00f, 0x100, // `abcdefg
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // hijklmno
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // pqrstuvw
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // xyz{|}~.
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // ........
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // ........
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // ........
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // ........
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // ........
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // ........
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // ........
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // ........
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // ........
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // ........
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // ........
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // ........
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // ........
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // ........
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, // ........
    0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100, 0x100  // ........
};

static int uint8_from_hex(const char* hex, size_t hexlen, uint8_t* buf)
{
    int ret = RET_OK;
    size_t i, len;
    uint16_t val;

    len = hexlen / 2;

    for (i = 0; i < len; i++) {
        val = (hexmap[(uint8_t)hex[i * 2]] << 4) | hexmap[(uint8_t)hex[i * 2 + 1]];
        if (val > 0xFF) {
            SET_ERROR(RET_INVALID_HEX_STRING);
        }
        buf[i] = (uint8_t)val;
    };

cleanup:
    return ret;
}

ByteArray* ba_alloc_from_hex(const char* hex)
{
    int ret = RET_OK;
    ByteArray* ret_ba = NULL;
    size_t len;

    len = strlen(hex);
    if ((len & 1) != 0) {
        SET_ERROR(RET_INVALID_HEX_STRING);
    }

    CHECK_NOT_NULL(ret_ba = ba_alloc_by_len(len / 2));
    DO(uint8_from_hex(hex, len, ret_ba->buf));

cleanup:
    if (ret != RET_OK) {
        ba_free(ret_ba);
        ret_ba = NULL;
    }
    return ret_ba;
}

int ba_from_hex(const char* hex, ByteArray* ba)
{
    int ret = RET_OK;
    size_t len;

    CHECK_PARAM(hex != NULL);
    CHECK_PARAM(ba != NULL);

    len = strlen(hex);
    if ((len & 1) != 0) {
        SET_ERROR(RET_INVALID_HEX_STRING);
    }

    REALLOC_CHECKED(ba->buf, len / 2, ba->buf);
    ba->len = len / 2;
    DO(uint8_from_hex(hex, len, ba->buf));

cleanup:

    return ret;
}

static const char* hex_symbols = "0123456789ABCDEF";

int ba_to_hex_with_alloc(const ByteArray* ba, char** buf)
{
    int ret = RET_OK;
    const uint8_t* bin;
    size_t i, len;

    CHECK_PARAM(ba != NULL);
    CHECK_PARAM(buf != NULL);

    bin = ba->buf;
    len = ba->len;

    if ((*buf = malloc(len * 2 + 1)) == NULL) {
        SET_ERROR(RET_MEMORY_ALLOC_ERROR);
    }

    for (i = 0; i < len; i++) {
        (*buf)[i * 2] = hex_symbols[bin[i] >> 4];
        (*buf)[i * 2 + 1] = hex_symbols[bin[i] & 0x0F];
    }

    (*buf)[len * 2] = '\0';

cleanup:
    return ret;
}

int ba_to_hex(const ByteArray* ba, char* buf, size_t *buf_len)
{
    int ret = RET_OK;
    const uint8_t* bin;
    size_t i, len;

    CHECK_PARAM(ba != NULL);
    CHECK_PARAM(buf != NULL);
    CHECK_PARAM(buf_len != NULL);

    bin = ba->buf;
    len = ba->len;
    if (*buf_len < len * 2 + 1) {
        *buf_len = len * 2 + 1;
        SET_ERROR(RET_DATA_TOO_LONG);
    }

    for (i = 0; i < len; i++) {
        buf[i * 2] = hex_symbols[bin[i] >> 4];
        buf[i * 2 + 1] = hex_symbols[bin[i] & 0x0F];
    }

    buf[len * 2] = '\0';
    *buf_len = len * 2 + 1;

cleanup:
    return ret;
}

int ba_to_str_with_alloc (const ByteArray* ba, size_t off, size_t len, char** str)
{
    int ret = RET_OK;

    CHECK_PARAM(str != NULL);

    if ((ba != NULL) && (ba->len >= (off + len))) {
        if (len == 0) {
            len = ba->len - off;
        }

        *str = calloc(1, len + 1);
        if (*str == NULL) {
            SET_ERROR(RET_MEMORY_ALLOC_ERROR);
        }

        memcpy(*str, &ba->buf[off], len);
    }
    else {
        *str = NULL;
    }

cleanup:
    return ret;
}
