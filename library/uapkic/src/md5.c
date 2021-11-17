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

#include <inttypes.h>
#include <memory.h>

#include "md5.h"
#include "byte-array-internal.h"
#include "macros-internal.h"
#include "byte-utils-internal.h"

#undef FILE_MARKER
#define FILE_MARKER "uapkic/md5.c"

struct MD5Ctx_st {
    uint32_t state[4]; /* state (ABCD) */
    uint32_t count[2]; /* number of bits, modulo 2^64 (lsb first) */
    uint8_t buffer[64]; /* input buffer */
};


/* Constants for MD5Transform routine.
 */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

static unsigned char PADDING[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* F, G, H and I are basic MD5 functions.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
Rotation is separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, x, s, ac) {                          \
    (a) += F ((b), (c), (d)) + (x) + (uint32_t)(ac);        \
    (a) = ROTATE_LEFT ((a), (s));                           \
    (a) += (b);                                             \
    }

#define GG(a, b, c, d, x, s, ac) {                          \
    (a) += G ((b), (c), (d)) + (x) + (uint32_t)(ac);        \
    (a) = ROTATE_LEFT ((a), (s));                           \
    (a) += (b);                                             \
    }

#define HH(a, b, c, d, x, s, ac) {                          \
    (a) += H ((b), (c), (d)) + (x) + (uint32_t)(ac);        \
    (a) = ROTATE_LEFT ((a), (s));                           \
    (a) += (b);                                             \
    }

#define II(a, b, c, d, x, s, ac) {                          \
        (a) += I ((b), (c), (d)) + (x) + (uint32_t)(ac);    \
        (a) = ROTATE_LEFT ((a), (s));                       \
        (a) += (b);                                         \
        }

#define PACK32(i, j)\
    x[i] = ((uint32_t) block[j]) | (((uint32_t) block[j + 1]) << 8) | \
    (((uint32_t) block[j + 2]) << 16) | (((uint32_t) block[j + 3]) << 24);

__inline static void md5_basic_transform(uint32_t state[4], const uint8_t block[64])
{
    uint32_t x[16];
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];

    PACK32(0, 0)
    PACK32(1, 4)
    PACK32(2, 8)
    PACK32(3, 12)
    PACK32(4, 16)
    PACK32(5, 20)
    PACK32(6, 24)
    PACK32(7, 28)
    PACK32(8, 32)
    PACK32(9, 36)
    PACK32(10, 40)
    PACK32(11, 44)
    PACK32(12, 48)
    PACK32(13, 52)
    PACK32(14, 56)
    PACK32(15, 60)

    /* Round 1 */
    FF(a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
    FF(d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
    FF(c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
    FF(b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
    FF(a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
    FF(d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
    FF(c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
    FF(b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
    FF(a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
    FF(d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
    FF(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
    FF(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
    FF(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
    FF(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
    FF(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
    FF(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

    /* Round 2 */
    GG(a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
    GG(d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
    GG(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
    GG(b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
    GG(a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
    GG(d, a, b, c, x[10], S22, 0x2441453); /* 22 */
    GG(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
    GG(b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
    GG(a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
    GG(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
    GG(c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
    GG(b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
    GG(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
    GG(d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
    GG(c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
    GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

    /* Round 3 */
    HH(a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
    HH(d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
    HH(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
    HH(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
    HH(a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
    HH(d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
    HH(c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
    HH(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
    HH(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
    HH(d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
    HH(c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
    HH(b, c, d, a, x[ 6], S34, 0x4881d05); /* 44 */
    HH(a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
    HH(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
    HH(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
    HH(b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

    /* Round 4 */
    II(a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
    II(d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
    II(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
    II(b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
    II(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
    II(d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
    II(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
    II(b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
    II(a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
    II(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
    II(c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
    II(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
    II(a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
    II(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
    II(c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
    II(b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

/* Encodes input (uint32_t) into output (unsigned char). Assumes len is
  a multiple of 4.
 */
#define UNPACK32(input, output, i, j)                           \
    output[j] = (unsigned char) (input[i] & 0xff);              \
    output[j + 1] = (unsigned char) ((input[i] >> 8) & 0xff);   \
    output[j + 2] = (unsigned char) ((input[i] >> 16) & 0xff);  \
    output[j + 3] = (unsigned char) ((input[i] >> 24) & 0xff);

/* Decodes input (unsigned char) into output (uint32_t). Assumes len is
  a multiple of 4.
 */
static int md5_init(Md5Ctx *ctx)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);

    memset(ctx, 0, sizeof(Md5Ctx));
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;

cleanup:

    return ret;
}

Md5Ctx *md5_alloc(void)
{
    Md5Ctx *ctx = NULL;
    int ret = RET_OK;

    CALLOC_CHECKED(ctx, sizeof(Md5Ctx));
    md5_init(ctx);

cleanup:

    return ctx;
}

Md5Ctx* md5_copy_with_alloc(const Md5Ctx* ctx)
{
    Md5Ctx* out = NULL;
    int ret = RET_OK;

    CALLOC_CHECKED(out, sizeof(Md5Ctx));
    memcpy(out, ctx, sizeof(Md5Ctx));

cleanup:

    return out;
}

int md5_update(Md5Ctx *ctx, const ByteArray *data)
{
    uint8_t *data_buf = NULL;
    size_t data_len;
    size_t i, index, part_len;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(data != NULL);

    data_buf = data->buf;
    data_len = data->len;

    CHECK_PARAM(data_len <= 0x1FFFFFFF);

    /* Compute number of bytes mod 64 */
    index = (unsigned int) ((ctx->count[0] >> 3) & 0x3F);

    /* Update number of bits */
    if ((ctx->count[0] += ((uint32_t) data_len << 3)) < ((uint32_t) data_len << 3)) {
        ctx->count[1]++;
    }
    ctx->count[1] += ((uint32_t) data_len >> 29);

    part_len = 64 - index;

    /* Transform as many times as possible.*/
    if (data_len >= part_len) {
        memcpy(&ctx->buffer[index], data_buf, part_len);
        md5_basic_transform(ctx->state, ctx->buffer);

        for (i = part_len; i + 63 < data_len; i += 64) {
            md5_basic_transform(ctx->state, &data_buf[i]);
        }

        index = 0;
    } else {
        i = 0;
    }

    /* Buffer remaining input */
    memcpy(&ctx->buffer[index], &data_buf[i], data_len - i);

cleanup:

    return ret;
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
  the message digest and zeroizing the context.
 */
int md5_final(Md5Ctx *ctx, ByteArray **hash_code)
{
    ByteArray *ba_padding = NULL;
    ByteArray *ba_bits = NULL;
    uint8_t digest[16];
    unsigned char bits[8];
    unsigned int index, pad_len;
    uint32_t count_tmp[2];
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(hash_code != NULL);

    memcpy(count_tmp, ctx->count, sizeof(uint32_t) * 2);

    /* Save number of bits */
    UNPACK32(ctx->count, bits, 0, 0)
    UNPACK32(ctx->count, bits, 1, 4)

    /* Pad out to 56 mod 64. */
    index = (unsigned int) ((ctx->count[0] >> 3) & 0x3f);
    pad_len = (index < 56) ? (56 - index) : (120 - index);

    CHECK_NOT_NULL(ba_padding = ba_alloc_from_uint8(PADDING, pad_len));

    DO(md5_update(ctx, ba_padding));

    CHECK_NOT_NULL(ba_bits = ba_alloc_from_uint8(bits, 8));
    /* Append length (before padding) */
    DO(md5_update(ctx, ba_bits));
    memcpy(ctx->count, count_tmp, sizeof(uint32_t) * 2);
    /* Store state in digest */
    UNPACK32(ctx->state, digest, 0, 0)
    UNPACK32(ctx->state, digest, 1, 4)
    UNPACK32(ctx->state, digest, 2, 8)
    UNPACK32(ctx->state, digest, 3, 12)

    /* Zeroize sensitive information. */
    CHECK_NOT_NULL(*hash_code = ba_alloc_from_uint8(digest, 16));
    DO(md5_init(ctx));

cleanup:

    ba_free(ba_padding);
    ba_free(ba_bits);

    return ret;
}

size_t md5_get_block_size(const Md5Ctx* ctx)
{
    (void)ctx;
    return 64;
}

void md5_free(Md5Ctx *ctx)
{
    if (ctx) {
        secure_zero(ctx, sizeof(Md5Ctx));
        free(ctx);
    }
}

int md5_self_test(void)
{
    // RFC 1321. A.5 Test suite
    static const uint8_t M1[] = "abc";
    static const uint8_t H1[] = {
        0x90, 0x01, 0x50, 0x98, 0x3C, 0xD2, 0x4F, 0xB0, 0xD6, 0x96, 0x3F, 0x7D, 0x28, 0xE1, 0x7F, 0x72 };
    static const uint8_t M2[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    static const uint8_t H2[] = {
        0xD1, 0x74, 0xAB, 0x98, 0xD2, 0x77, 0xD9, 0xF5, 0xA5, 0x61, 0x1C, 0x2C, 0x9F, 0x41, 0x9D, 0x9F };

    static const ByteArray ba_M1 = { (uint8_t*)M1, sizeof(M1) - 1 };
    static const ByteArray ba_M2 = { (uint8_t*)M2, sizeof(M2) - 1 };

    int ret = RET_OK;
    Md5Ctx* ctx = NULL;
    ByteArray* H = NULL;

    CHECK_NOT_NULL(ctx = md5_alloc());
    DO(md5_update(ctx, &ba_M1));
    DO(md5_final(ctx, &H));
    if (H->len != sizeof(H1) ||
        memcmp(H->buf, H1, sizeof(H1)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }
    ba_free(H);
    H = NULL;

    DO(md5_update(ctx, &ba_M2));
    DO(md5_final(ctx, &H));
    if (H->len != sizeof(H2) ||
        memcmp(H->buf, H2, sizeof(H2)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

cleanup:
    md5_free(ctx);
    ba_free(H);
    return ret;
}