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

#define FILE_MARKER "uapkic/ripemd.c"

#include <stdio.h>
#include <string.h>

#include "ripemd.h"
#include "byte-utils-internal.h"
#include "byte-array-internal.h"
#include "macros-internal.h"

#define BYTES_TO_DWORD(strptr)                          \
            (( *((strptr) + 3) << 24) |                 \
             ( *((strptr) + 2) << 16) |                 \
             ( *((strptr) + 1) <<  8) |                 \
             ( *(strptr)))

#define ROL(x, n)        (((x) << (n)) | ((x) >> (32-(n))))

#define F(x, y, z)        ((x) ^ (y) ^ (z))
#define G(x, y, z)        (((x) & (y)) | (~(x) & (z)))
#define H(x, y, z)        (((x) | ~(y)) ^ (z))
#define I(x, y, z)        (((x) & (z)) | ((y) & ~(z)))
#define J(x, y, z)        ((x) ^ ((y) | ~(z)))

#define FF(a, b, c, d, e, x, s) {                       \
        (a) += F((b), (c), (d)) + (x);                  \
        (a) = ROL((a), (s)) + (e);                      \
        (c) = ROL((c), 10);                             \
        }

#define GG(a, b, c, d, e, x, s) {                       \
       (a) += G((b), (c), (d)) + (x) + 0x5a827999UL;    \
       (a) = ROL((a), (s)) + (e);                       \
       (c) = ROL((c), 10);                              \
       }

#define HH(a, b, c, d, e, x, s) {                       \
        (a) += H((b), (c), (d)) + (x) + 0x6ed9eba1UL;   \
        (a) = ROL((a), (s)) + (e);                      \
        (c) = ROL((c), 10);                             \
        }

#define II(a, b, c, d, e, x, s) {                       \
        (a) += I((b), (c), (d)) + (x) + 0x8f1bbcdcUL;   \
        (a) = ROL((a), (s)) + (e);                      \
        (c) = ROL((c), 10);                             \
        }

#define JJ(a, b, c, d, e, x, s) {                       \
        (a) += J((b), (c), (d)) + (x) + 0xa953fd4eUL;   \
        (a) = ROL((a), (s)) + (e);                      \
        (c) = ROL((c), 10);                             \
        }

#define FFF(a, b, c, d, e, x, s) {                      \
        (a) += F((b), (c), (d)) + (x);                  \
        (a) = ROL((a), (s)) + (e);                      \
        (c) = ROL((c), 10);                             \
        }

#define GGG(a, b, c, d, e, x, s) {                      \
        (a) += G((b), (c), (d)) + (x) + 0x7a6d76e9UL;   \
        (a) = ROL((a), (s)) + (e);                      \
        (c) = ROL((c), 10);                             \
        }

#define HHH(a, b, c, d, e, x, s) {                      \
        (a) += H((b), (c), (d)) + (x) + 0x6d703ef3UL;   \
        (a) = ROL((a), (s)) + (e);                      \
        (c) = ROL((c), 10);                             \
        }

#define III(a, b, c, d, e, x, s) {                      \
        (a) += I((b), (c), (d)) + (x) + 0x5c4dd124UL;   \
        (a) = ROL((a), (s)) + (e);                      \
        (c) = ROL((c), 10);                             \
        }

#define JJJ(a, b, c, d, e, x, s) {                      \
        (a) += J((b), (c), (d)) + (x) + 0x50a28be6UL;   \
        (a) = ROL((a), (s)) + (e);                      \
        (c) = ROL((c), 10);                             \
        }

struct RipemdCtx_st {
    uint32_t state[16];
    uint8_t last_block[64];
    size_t last_block_len;
    size_t mode_eng;
    uint64_t tot_len;
    void (*compress)(uint32_t *, uint32_t *);
};

static __inline void ripemd_init160(RipemdCtx *ctx)
{
    memset(ctx->state, 0,  64);
    memset(ctx->last_block, 0,  64);
    ctx->tot_len = 0;
    ctx->last_block_len = 0;

    ctx->state[0] = 0x67452301UL;
    ctx->state[1] = 0xefcdab89UL;
    ctx->state[2] = 0x98badcfeUL;
    ctx->state[3] = 0x10325476UL;
    ctx->state[4] = 0xc3d2e1f0UL;
}

static __inline void ripemd_init128(RipemdCtx *ctx)
{
    memset(ctx->state, 0,  64);
    memset(ctx->last_block, 0,  64);
    ctx->tot_len = 0;
    ctx->last_block_len = 0;

    ctx->state[0] = 0x67452301UL;
    ctx->state[1] = 0xefcdab89UL;
    ctx->state[2] = 0x98badcfeUL;
    ctx->state[3] = 0x10325476UL;
}

static __inline void compress_160(uint32_t *MDbuf, uint32_t *X)
{
    uint32_t aa = MDbuf[0], bb = MDbuf[1], cc = MDbuf[2],
             dd = MDbuf[3], ee = MDbuf[4];
    uint32_t aaa = MDbuf[0], bbb = MDbuf[1], ccc = MDbuf[2],
             ddd = MDbuf[3], eee = MDbuf[4];

    /* round 1 */
    FF(aa, bb, cc, dd, ee, X[ 0], 11);
    FF(ee, aa, bb, cc, dd, X[ 1], 14);
    FF(dd, ee, aa, bb, cc, X[ 2], 15);
    FF(cc, dd, ee, aa, bb, X[ 3], 12);
    FF(bb, cc, dd, ee, aa, X[ 4], 5);
    FF(aa, bb, cc, dd, ee, X[ 5], 8);
    FF(ee, aa, bb, cc, dd, X[ 6], 7);
    FF(dd, ee, aa, bb, cc, X[ 7], 9);
    FF(cc, dd, ee, aa, bb, X[ 8], 11);
    FF(bb, cc, dd, ee, aa, X[ 9], 13);
    FF(aa, bb, cc, dd, ee, X[10], 14);
    FF(ee, aa, bb, cc, dd, X[11], 15);
    FF(dd, ee, aa, bb, cc, X[12], 6);
    FF(cc, dd, ee, aa, bb, X[13], 7);
    FF(bb, cc, dd, ee, aa, X[14], 9);
    FF(aa, bb, cc, dd, ee, X[15], 8);

    /* round 2 */
    GG(ee, aa, bb, cc, dd, X[ 7], 7);
    GG(dd, ee, aa, bb, cc, X[ 4], 6);
    GG(cc, dd, ee, aa, bb, X[13], 8);
    GG(bb, cc, dd, ee, aa, X[ 1], 13);
    GG(aa, bb, cc, dd, ee, X[10], 11);
    GG(ee, aa, bb, cc, dd, X[ 6], 9);
    GG(dd, ee, aa, bb, cc, X[15], 7);
    GG(cc, dd, ee, aa, bb, X[ 3], 15);
    GG(bb, cc, dd, ee, aa, X[12], 7);
    GG(aa, bb, cc, dd, ee, X[ 0], 12);
    GG(ee, aa, bb, cc, dd, X[ 9], 15);
    GG(dd, ee, aa, bb, cc, X[ 5], 9);
    GG(cc, dd, ee, aa, bb, X[ 2], 11);
    GG(bb, cc, dd, ee, aa, X[14], 7);
    GG(aa, bb, cc, dd, ee, X[11], 13);
    GG(ee, aa, bb, cc, dd, X[ 8], 12);

    /* round 3 */
    HH(dd, ee, aa, bb, cc, X[ 3], 11);
    HH(cc, dd, ee, aa, bb, X[10], 13);
    HH(bb, cc, dd, ee, aa, X[14], 6);
    HH(aa, bb, cc, dd, ee, X[ 4], 7);
    HH(ee, aa, bb, cc, dd, X[ 9], 14);
    HH(dd, ee, aa, bb, cc, X[15], 9);
    HH(cc, dd, ee, aa, bb, X[ 8], 13);
    HH(bb, cc, dd, ee, aa, X[ 1], 15);
    HH(aa, bb, cc, dd, ee, X[ 2], 14);
    HH(ee, aa, bb, cc, dd, X[ 7], 8);
    HH(dd, ee, aa, bb, cc, X[ 0], 13);
    HH(cc, dd, ee, aa, bb, X[ 6], 6);
    HH(bb, cc, dd, ee, aa, X[13], 5);
    HH(aa, bb, cc, dd, ee, X[11], 12);
    HH(ee, aa, bb, cc, dd, X[ 5], 7);
    HH(dd, ee, aa, bb, cc, X[12], 5);

    /* round 4 */
    II(cc, dd, ee, aa, bb, X[ 1], 11);
    II(bb, cc, dd, ee, aa, X[ 9], 12);
    II(aa, bb, cc, dd, ee, X[11], 14);
    II(ee, aa, bb, cc, dd, X[10], 15);
    II(dd, ee, aa, bb, cc, X[ 0], 14);
    II(cc, dd, ee, aa, bb, X[ 8], 15);
    II(bb, cc, dd, ee, aa, X[12], 9);
    II(aa, bb, cc, dd, ee, X[ 4], 8);
    II(ee, aa, bb, cc, dd, X[13], 9);
    II(dd, ee, aa, bb, cc, X[ 3], 14);
    II(cc, dd, ee, aa, bb, X[ 7], 5);
    II(bb, cc, dd, ee, aa, X[15], 6);
    II(aa, bb, cc, dd, ee, X[14], 8);
    II(ee, aa, bb, cc, dd, X[ 5], 6);
    II(dd, ee, aa, bb, cc, X[ 6], 5);
    II(cc, dd, ee, aa, bb, X[ 2], 12);

    /* round 5 */
    JJ(bb, cc, dd, ee, aa, X[ 4], 9);
    JJ(aa, bb, cc, dd, ee, X[ 0], 15);
    JJ(ee, aa, bb, cc, dd, X[ 5], 5);
    JJ(dd, ee, aa, bb, cc, X[ 9], 11);
    JJ(cc, dd, ee, aa, bb, X[ 7], 6);
    JJ(bb, cc, dd, ee, aa, X[12], 8);
    JJ(aa, bb, cc, dd, ee, X[ 2], 13);
    JJ(ee, aa, bb, cc, dd, X[10], 12);
    JJ(dd, ee, aa, bb, cc, X[14], 5);
    JJ(cc, dd, ee, aa, bb, X[ 1], 12);
    JJ(bb, cc, dd, ee, aa, X[ 3], 13);
    JJ(aa, bb, cc, dd, ee, X[ 8], 14);
    JJ(ee, aa, bb, cc, dd, X[11], 11);
    JJ(dd, ee, aa, bb, cc, X[ 6], 8);
    JJ(cc, dd, ee, aa, bb, X[15], 5);
    JJ(bb, cc, dd, ee, aa, X[13], 6);

    /* parallel round 1 */
    JJJ(aaa, bbb, ccc, ddd, eee, X[ 5], 8);
    JJJ(eee, aaa, bbb, ccc, ddd, X[14], 9);
    JJJ(ddd, eee, aaa, bbb, ccc, X[ 7], 9);
    JJJ(ccc, ddd, eee, aaa, bbb, X[ 0], 11);
    JJJ(bbb, ccc, ddd, eee, aaa, X[ 9], 13);
    JJJ(aaa, bbb, ccc, ddd, eee, X[ 2], 15);
    JJJ(eee, aaa, bbb, ccc, ddd, X[11], 15);
    JJJ(ddd, eee, aaa, bbb, ccc, X[ 4], 5);
    JJJ(ccc, ddd, eee, aaa, bbb, X[13], 7);
    JJJ(bbb, ccc, ddd, eee, aaa, X[ 6], 7);
    JJJ(aaa, bbb, ccc, ddd, eee, X[15], 8);
    JJJ(eee, aaa, bbb, ccc, ddd, X[ 8], 11);
    JJJ(ddd, eee, aaa, bbb, ccc, X[ 1], 14);
    JJJ(ccc, ddd, eee, aaa, bbb, X[10], 14);
    JJJ(bbb, ccc, ddd, eee, aaa, X[ 3], 12);
    JJJ(aaa, bbb, ccc, ddd, eee, X[12], 6);

    /* parallel round 2 */
    III(eee, aaa, bbb, ccc, ddd, X[ 6], 9);
    III(ddd, eee, aaa, bbb, ccc, X[11], 13);
    III(ccc, ddd, eee, aaa, bbb, X[ 3], 15);
    III(bbb, ccc, ddd, eee, aaa, X[ 7], 7);
    III(aaa, bbb, ccc, ddd, eee, X[ 0], 12);
    III(eee, aaa, bbb, ccc, ddd, X[13], 8);
    III(ddd, eee, aaa, bbb, ccc, X[ 5], 9);
    III(ccc, ddd, eee, aaa, bbb, X[10], 11);
    III(bbb, ccc, ddd, eee, aaa, X[14], 7);
    III(aaa, bbb, ccc, ddd, eee, X[15], 7);
    III(eee, aaa, bbb, ccc, ddd, X[ 8], 12);
    III(ddd, eee, aaa, bbb, ccc, X[12], 7);
    III(ccc, ddd, eee, aaa, bbb, X[ 4], 6);
    III(bbb, ccc, ddd, eee, aaa, X[ 9], 15);
    III(aaa, bbb, ccc, ddd, eee, X[ 1], 13);
    III(eee, aaa, bbb, ccc, ddd, X[ 2], 11);

    /* parallel round 3 */
    HHH(ddd, eee, aaa, bbb, ccc, X[15], 9);
    HHH(ccc, ddd, eee, aaa, bbb, X[ 5], 7);
    HHH(bbb, ccc, ddd, eee, aaa, X[ 1], 15);
    HHH(aaa, bbb, ccc, ddd, eee, X[ 3], 11);
    HHH(eee, aaa, bbb, ccc, ddd, X[ 7], 8);
    HHH(ddd, eee, aaa, bbb, ccc, X[14], 6);
    HHH(ccc, ddd, eee, aaa, bbb, X[ 6], 6);
    HHH(bbb, ccc, ddd, eee, aaa, X[ 9], 14);
    HHH(aaa, bbb, ccc, ddd, eee, X[11], 12);
    HHH(eee, aaa, bbb, ccc, ddd, X[ 8], 13);
    HHH(ddd, eee, aaa, bbb, ccc, X[12], 5);
    HHH(ccc, ddd, eee, aaa, bbb, X[ 2], 14);
    HHH(bbb, ccc, ddd, eee, aaa, X[10], 13);
    HHH(aaa, bbb, ccc, ddd, eee, X[ 0], 13);
    HHH(eee, aaa, bbb, ccc, ddd, X[ 4], 7);
    HHH(ddd, eee, aaa, bbb, ccc, X[13], 5);

    /* parallel round 4 */
    GGG(ccc, ddd, eee, aaa, bbb, X[ 8], 15);
    GGG(bbb, ccc, ddd, eee, aaa, X[ 6], 5);
    GGG(aaa, bbb, ccc, ddd, eee, X[ 4], 8);
    GGG(eee, aaa, bbb, ccc, ddd, X[ 1], 11);
    GGG(ddd, eee, aaa, bbb, ccc, X[ 3], 14);
    GGG(ccc, ddd, eee, aaa, bbb, X[11], 14);
    GGG(bbb, ccc, ddd, eee, aaa, X[15], 6);
    GGG(aaa, bbb, ccc, ddd, eee, X[ 0], 14);
    GGG(eee, aaa, bbb, ccc, ddd, X[ 5], 6);
    GGG(ddd, eee, aaa, bbb, ccc, X[12], 9);
    GGG(ccc, ddd, eee, aaa, bbb, X[ 2], 12);
    GGG(bbb, ccc, ddd, eee, aaa, X[13], 9);
    GGG(aaa, bbb, ccc, ddd, eee, X[ 9], 12);
    GGG(eee, aaa, bbb, ccc, ddd, X[ 7], 5);
    GGG(ddd, eee, aaa, bbb, ccc, X[10], 15);
    GGG(ccc, ddd, eee, aaa, bbb, X[14], 8);

    /* parallel round 5 */
    FFF(bbb, ccc, ddd, eee, aaa, X[12], 8);
    FFF(aaa, bbb, ccc, ddd, eee, X[15], 5);
    FFF(eee, aaa, bbb, ccc, ddd, X[10], 12);
    FFF(ddd, eee, aaa, bbb, ccc, X[ 4], 9);
    FFF(ccc, ddd, eee, aaa, bbb, X[ 1], 12);
    FFF(bbb, ccc, ddd, eee, aaa, X[ 5], 5);
    FFF(aaa, bbb, ccc, ddd, eee, X[ 8], 14);
    FFF(eee, aaa, bbb, ccc, ddd, X[ 7], 6);
    FFF(ddd, eee, aaa, bbb, ccc, X[ 6], 8);
    FFF(ccc, ddd, eee, aaa, bbb, X[ 2], 13);
    FFF(bbb, ccc, ddd, eee, aaa, X[13], 6);
    FFF(aaa, bbb, ccc, ddd, eee, X[14], 5);
    FFF(eee, aaa, bbb, ccc, ddd, X[ 0], 15);
    FFF(ddd, eee, aaa, bbb, ccc, X[ 3], 13);
    FFF(ccc, ddd, eee, aaa, bbb, X[ 9], 11);
    FFF(bbb, ccc, ddd, eee, aaa, X[11], 11);

    /* combine results */
    ddd += cc + MDbuf[1]; /* final result for MDbuf[0] */
    MDbuf[1] = MDbuf[2] + dd + eee;
    MDbuf[2] = MDbuf[3] + ee + aaa;
    MDbuf[3] = MDbuf[4] + aa + bbb;
    MDbuf[4] = MDbuf[0] + bb + ccc;
    MDbuf[0] = ddd;

    return;
}

void ripemd_free(RipemdCtx *ctx)
{
    if (ctx) {
        secure_zero(ctx, sizeof(RipemdCtx));
        free(ctx);
    }
}

int ripemd_update(RipemdCtx *ctx, const ByteArray *data)
{
    uint8_t *data_buf = NULL;
    uint8_t *shifted_arr = NULL;
    uint32_t X[16];
    size_t data_len;
    size_t i = 0;
    size_t j = 0;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(data != NULL);

    data_buf = data->buf;
    data_len = data->len;

    ctx->tot_len += data_len;
    if (ctx->last_block_len + data_len < 64) {
        memcpy(&ctx->last_block[ctx->last_block_len], data_buf, data_len);
        ctx->last_block_len += data_len;
        goto cleanup;
    }

    memcpy(&ctx->last_block[ctx->last_block_len], data_buf, 64 - ctx->last_block_len);
    DO(uint8_to_uint32(ctx->last_block, 64, X, 16));
    ctx->compress(ctx->state, X);
    shifted_arr = data_buf + (64 - ctx->last_block_len);
    data_len -= (64 - ctx->last_block_len);
    for (j = 0; j + 64 <= data_len; j += 64) {
        for (i = 0; i < 16; i++) {
            X[i] = BYTES_TO_DWORD(&shifted_arr[j + (i << 2)]);
        }
        ctx->compress(ctx->state, X);
    }

    ctx->last_block_len = data_len - j;
    if (ctx->last_block_len != 0) {
        memcpy(ctx->last_block, shifted_arr + j, ctx->last_block_len);
    }

cleanup:

    return ret;
}

int ripemd_final(RipemdCtx *ctx, ByteArray **hash_code)
{
    uint32_t X[16]; /* message words */
    const uint8_t *strptr = NULL;
    int8_t *H = NULL;
    size_t i;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(hash_code != NULL);

    strptr = (uint8_t *) ctx->last_block;

    memset(X, 0, 16 * sizeof (uint32_t));

    /* put bytes from strptr into X */
    for (i = 0; i < ctx->last_block_len; i++) {
        /* byte i goes into word X[i div 4] at pos.  8*(i mod 4)  */
        X[i >> 2] ^= (uint32_t) * strptr++ << (8 * (i & 3));
    }

    /* append the bit m_n == 1 */
    X[(ctx->tot_len >> 2) & 15] ^= (uint32_t) 1 << (8 * (ctx->tot_len & 3) + 7);

    if (ctx->last_block_len > 55) {
        /* length goes to next block */
        ctx->compress(ctx->state, X);
        memset(X, 0, 16 * sizeof (uint32_t));
    }

    /* append length in bits*/
    X[14] = (uint32_t) (ctx->tot_len << 3);
    X[15] = (uint32_t) (ctx->tot_len >> 29);
    ctx->compress(ctx->state, X);

    MALLOC_CHECKED(H, ctx->mode_eng >> 3);

    for (i = 0; i < ctx->mode_eng / 8; i += 4) {
        H[i] = (uint8_t) ctx->state[i >> 2]; /* implicit cast to byte  */
        H[i + 1] = (uint8_t) (ctx->state[i >> 2] >> 8); /*  extracts the 8 least  */
        H[i + 2] = (uint8_t) (ctx->state[i >> 2] >> 16); /*  significant bits.     */
        H[i + 3] = (uint8_t) (ctx->state[i >> 2] >> 24);
    }
    CHECK_NOT_NULL(*hash_code = ba_alloc_from_uint8((const uint8_t *) H, ctx->mode_eng / 8));
    ctx->mode_eng == 160 ? ripemd_init160(ctx) : ripemd_init128(ctx);

cleanup:

    free(H);
    return ret;
}

#define FF128(a, b, c, d, x, s)        {\
      (a) += F((b), (c), (d)) + (x);\
      (a) = ROL((a), (s));\
   }

#define GG128(a, b, c, d, x, s)        {\
      (a) += G((b), (c), (d)) + (x) + 0x5a827999UL;\
      (a) = ROL((a), (s));\
   }

#define HH128(a, b, c, d, x, s)        {\
      (a) += H((b), (c), (d)) + (x) + 0x6ed9eba1UL;\
      (a) = ROL((a), (s));\
   }

#define II128(a, b, c, d, x, s)        {\
      (a) += I((b), (c), (d)) + (x) + 0x8f1bbcdcUL;\
      (a) = ROL((a), (s));\
   }

#define FFF128(a, b, c, d, x, s)        {\
      (a) += F((b), (c), (d)) + (x);\
      (a) = ROL((a), (s));\
   }

#define GGG128(a, b, c, d, x, s)        {\
      (a) += G((b), (c), (d)) + (x) + 0x6d703ef3UL;\
      (a) = ROL((a), (s));\
   }

#define HHH128(a, b, c, d, x, s)        {\
      (a) += H((b), (c), (d)) + (x) + 0x5c4dd124UL;\
      (a) = ROL((a), (s));\
   }

#define III128(a, b, c, d, x, s)        {\
      (a) += I((b), (c), (d)) + (x) + 0x50a28be6UL;\
      (a) = ROL((a), (s));\
   }

static __inline void compress_128(uint32_t *MDbuf, uint32_t *X)
{
    uint32_t aa = MDbuf[0], bb = MDbuf[1], cc = MDbuf[2], dd = MDbuf[3];
    uint32_t aaa = MDbuf[0], bbb = MDbuf[1], ccc = MDbuf[2], ddd = MDbuf[3];

    /* round 1 */
    FF128(aa, bb, cc, dd, X[ 0], 11);
    FF128(dd, aa, bb, cc, X[ 1], 14);
    FF128(cc, dd, aa, bb, X[ 2], 15);
    FF128(bb, cc, dd, aa, X[ 3], 12);
    FF128(aa, bb, cc, dd, X[ 4], 5);
    FF128(dd, aa, bb, cc, X[ 5], 8);
    FF128(cc, dd, aa, bb, X[ 6], 7);
    FF128(bb, cc, dd, aa, X[ 7], 9);
    FF128(aa, bb, cc, dd, X[ 8], 11);
    FF128(dd, aa, bb, cc, X[ 9], 13);
    FF128(cc, dd, aa, bb, X[10], 14);
    FF128(bb, cc, dd, aa, X[11], 15);
    FF128(aa, bb, cc, dd, X[12], 6);
    FF128(dd, aa, bb, cc, X[13], 7);
    FF128(cc, dd, aa, bb, X[14], 9);
    FF128(bb, cc, dd, aa, X[15], 8);

    /* parallel round 1 */
    III128(aaa, bbb, ccc, ddd, X[ 5], 8);
    III128(ddd, aaa, bbb, ccc, X[14], 9);
    III128(ccc, ddd, aaa, bbb, X[ 7], 9);
    III128(bbb, ccc, ddd, aaa, X[ 0], 11);
    III128(aaa, bbb, ccc, ddd, X[ 9], 13);
    III128(ddd, aaa, bbb, ccc, X[ 2], 15);
    III128(ccc, ddd, aaa, bbb, X[11], 15);
    III128(bbb, ccc, ddd, aaa, X[ 4], 5);
    III128(aaa, bbb, ccc, ddd, X[13], 7);
    III128(ddd, aaa, bbb, ccc, X[ 6], 7);
    III128(ccc, ddd, aaa, bbb, X[15], 8);
    III128(bbb, ccc, ddd, aaa, X[ 8], 11);
    III128(aaa, bbb, ccc, ddd, X[ 1], 14);
    III128(ddd, aaa, bbb, ccc, X[10], 14);
    III128(ccc, ddd, aaa, bbb, X[ 3], 12);
    III128(bbb, ccc, ddd, aaa, X[12], 6);

    /* round 2 */
    GG128(aa, bb, cc, dd, X[ 7], 7);
    GG128(dd, aa, bb, cc, X[ 4], 6);
    GG128(cc, dd, aa, bb, X[13], 8);
    GG128(bb, cc, dd, aa, X[ 1], 13);
    GG128(aa, bb, cc, dd, X[10], 11);
    GG128(dd, aa, bb, cc, X[ 6], 9);
    GG128(cc, dd, aa, bb, X[15], 7);
    GG128(bb, cc, dd, aa, X[ 3], 15);
    GG128(aa, bb, cc, dd, X[12], 7);
    GG128(dd, aa, bb, cc, X[ 0], 12);
    GG128(cc, dd, aa, bb, X[ 9], 15);
    GG128(bb, cc, dd, aa, X[ 5], 9);
    GG128(aa, bb, cc, dd, X[ 2], 11);
    GG128(dd, aa, bb, cc, X[14], 7);
    GG128(cc, dd, aa, bb, X[11], 13);
    GG128(bb, cc, dd, aa, X[ 8], 12);

    /* parallel round 2 */
    HHH128(aaa, bbb, ccc, ddd, X[ 6], 9);
    HHH128(ddd, aaa, bbb, ccc, X[11], 13);
    HHH128(ccc, ddd, aaa, bbb, X[ 3], 15);
    HHH128(bbb, ccc, ddd, aaa, X[ 7], 7);
    HHH128(aaa, bbb, ccc, ddd, X[ 0], 12);
    HHH128(ddd, aaa, bbb, ccc, X[13], 8);
    HHH128(ccc, ddd, aaa, bbb, X[ 5], 9);
    HHH128(bbb, ccc, ddd, aaa, X[10], 11);
    HHH128(aaa, bbb, ccc, ddd, X[14], 7);
    HHH128(ddd, aaa, bbb, ccc, X[15], 7);
    HHH128(ccc, ddd, aaa, bbb, X[ 8], 12);
    HHH128(bbb, ccc, ddd, aaa, X[12], 7);
    HHH128(aaa, bbb, ccc, ddd, X[ 4], 6);
    HHH128(ddd, aaa, bbb, ccc, X[ 9], 15);
    HHH128(ccc, ddd, aaa, bbb, X[ 1], 13);
    HHH128(bbb, ccc, ddd, aaa, X[ 2], 11);

    /* round 3 */
    HH128(aa, bb, cc, dd, X[ 3], 11);
    HH128(dd, aa, bb, cc, X[10], 13);
    HH128(cc, dd, aa, bb, X[14], 6);
    HH128(bb, cc, dd, aa, X[ 4], 7);
    HH128(aa, bb, cc, dd, X[ 9], 14);
    HH128(dd, aa, bb, cc, X[15], 9);
    HH128(cc, dd, aa, bb, X[ 8], 13);
    HH128(bb, cc, dd, aa, X[ 1], 15);
    HH128(aa, bb, cc, dd, X[ 2], 14);
    HH128(dd, aa, bb, cc, X[ 7], 8);
    HH128(cc, dd, aa, bb, X[ 0], 13);
    HH128(bb, cc, dd, aa, X[ 6], 6);
    HH128(aa, bb, cc, dd, X[13], 5);
    HH128(dd, aa, bb, cc, X[11], 12);
    HH128(cc, dd, aa, bb, X[ 5], 7);
    HH128(bb, cc, dd, aa, X[12], 5);


    /* parallel round 3 */
    GGG128(aaa, bbb, ccc, ddd, X[15], 9);
    GGG128(ddd, aaa, bbb, ccc, X[ 5], 7);
    GGG128(ccc, ddd, aaa, bbb, X[ 1], 15);
    GGG128(bbb, ccc, ddd, aaa, X[ 3], 11);
    GGG128(aaa, bbb, ccc, ddd, X[ 7], 8);
    GGG128(ddd, aaa, bbb, ccc, X[14], 6);
    GGG128(ccc, ddd, aaa, bbb, X[ 6], 6);
    GGG128(bbb, ccc, ddd, aaa, X[ 9], 14);
    GGG128(aaa, bbb, ccc, ddd, X[11], 12);
    GGG128(ddd, aaa, bbb, ccc, X[ 8], 13);
    GGG128(ccc, ddd, aaa, bbb, X[12], 5);
    GGG128(bbb, ccc, ddd, aaa, X[ 2], 14);
    GGG128(aaa, bbb, ccc, ddd, X[10], 13);
    GGG128(ddd, aaa, bbb, ccc, X[ 0], 13);
    GGG128(ccc, ddd, aaa, bbb, X[ 4], 7);
    GGG128(bbb, ccc, ddd, aaa, X[13], 5);

    /* round 4 */
    II128(aa, bb, cc, dd, X[ 1], 11);
    II128(dd, aa, bb, cc, X[ 9], 12);
    II128(cc, dd, aa, bb, X[11], 14);
    II128(bb, cc, dd, aa, X[10], 15);
    II128(aa, bb, cc, dd, X[ 0], 14);
    II128(dd, aa, bb, cc, X[ 8], 15);
    II128(cc, dd, aa, bb, X[12], 9);
    II128(bb, cc, dd, aa, X[ 4], 8);
    II128(aa, bb, cc, dd, X[13], 9);
    II128(dd, aa, bb, cc, X[ 3], 14);
    II128(cc, dd, aa, bb, X[ 7], 5);
    II128(bb, cc, dd, aa, X[15], 6);
    II128(aa, bb, cc, dd, X[14], 8);
    II128(dd, aa, bb, cc, X[ 5], 6);
    II128(cc, dd, aa, bb, X[ 6], 5);
    II128(bb, cc, dd, aa, X[ 2], 12);

    /* parallel round 4 */
    FFF128(aaa, bbb, ccc, ddd, X[ 8], 15);
    FFF128(ddd, aaa, bbb, ccc, X[ 6], 5);
    FFF128(ccc, ddd, aaa, bbb, X[ 4], 8);
    FFF128(bbb, ccc, ddd, aaa, X[ 1], 11);
    FFF128(aaa, bbb, ccc, ddd, X[ 3], 14);
    FFF128(ddd, aaa, bbb, ccc, X[11], 14);
    FFF128(ccc, ddd, aaa, bbb, X[15], 6);
    FFF128(bbb, ccc, ddd, aaa, X[ 0], 14);
    FFF128(aaa, bbb, ccc, ddd, X[ 5], 6);
    FFF128(ddd, aaa, bbb, ccc, X[12], 9);
    FFF128(ccc, ddd, aaa, bbb, X[ 2], 12);
    FFF128(bbb, ccc, ddd, aaa, X[13], 9);
    FFF128(aaa, bbb, ccc, ddd, X[ 9], 12);
    FFF128(ddd, aaa, bbb, ccc, X[ 7], 5);
    FFF128(ccc, ddd, aaa, bbb, X[10], 15);
    FFF128(bbb, ccc, ddd, aaa, X[14], 8);

    /* combine results */
    ddd += cc + MDbuf[1]; /* final result for MDbuf[0] */
    MDbuf[1] = MDbuf[2] + dd + aaa;
    MDbuf[2] = MDbuf[3] + aa + bbb;
    MDbuf[3] = MDbuf[0] + bb + ccc;
    MDbuf[0] = ddd;
}

RipemdCtx *ripemd_alloc(RipemdVariant mode)
{
    RipemdCtx *ctx = NULL;
    int ret = RET_OK;

    CALLOC_CHECKED(ctx, sizeof(RipemdCtx));
    switch (mode) {
    case RIPEMD_VARIANT_128:
        ripemd_init128(ctx);
        ctx->mode_eng = 128;
        ctx->compress = compress_128;
        break;
    case RIPEMD_VARIANT_160:
        ripemd_init160(ctx);
        ctx->mode_eng = 160;
        ctx->compress = compress_160;
        break;
    default:
        SET_ERROR(RET_INVALID_PARAM);
    }

    ctx->tot_len = 0;
    ctx->last_block_len = 0;

cleanup:

    if (ret != RET_OK) {
        free(ctx);
        ctx = NULL;
    }

    return ctx;
}

RipemdCtx* ripemd_copy_with_alloc(const RipemdCtx* ctx)
{
    RipemdCtx* out = NULL;
    int ret = RET_OK;

    CALLOC_CHECKED(out, sizeof(RipemdCtx));
    memcpy(out, ctx, sizeof(RipemdCtx));

cleanup:

    return out;
}

size_t ripemd_get_block_size(const RipemdCtx* ctx)
{
    (void)ctx;
    return 64;
}

static int ripemd128_self_test(void)
{
    // ДСТУ ISO/IEC 10118-3:2005. A.2.3, A.2.6
    static const uint8_t M1[] = "abc";
    static const uint8_t H1[] = {
        0xC1, 0x4A, 0x12, 0x19, 0x9C, 0x66, 0xE4, 0xBA, 0x84, 0x63, 0x6B, 0x0F, 0x69, 0x14, 0x4C, 0x77 };
    static const uint8_t M2[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    static const uint8_t H2[] = {
        0xD1, 0xE9, 0x59, 0xEB, 0x17, 0x9C, 0x91, 0x1F, 0xAE, 0xA4, 0x62, 0x4C, 0x60, 0xC5, 0xC7, 0x02 };

    static const ByteArray ba_M1 = { (uint8_t*)M1, sizeof(M1) - 1 };
    static const ByteArray ba_M2 = { (uint8_t*)M2, sizeof(M2) - 1 };

    int ret = RET_OK;
    RipemdCtx* ctx = NULL;
    ByteArray* H = NULL;

    CHECK_NOT_NULL(ctx = ripemd_alloc(RIPEMD_VARIANT_128));
    DO(ripemd_update(ctx, &ba_M1));
    DO(ripemd_final(ctx, &H));
    if (H->len != sizeof(H1) ||
        memcmp(H->buf, H1, sizeof(H1)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }
    ba_free(H);
    H = NULL;

    DO(ripemd_update(ctx, &ba_M2));
    DO(ripemd_final(ctx, &H));
    if (H->len != sizeof(H2) ||
        memcmp(H->buf, H2, sizeof(H2)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

cleanup:
    ripemd_free(ctx);
    ba_free(H);
    return ret;
}

static int ripemd160_self_test(void)
{
    // ДСТУ ISO/IEC 10118-3:2005. A.1.3, A.1.6
    static const uint8_t M1[] = "abc";
    static const uint8_t H1[] = {
        0x8E, 0xB2, 0x08, 0xF7, 0xE0, 0x5D, 0x98, 0x7A, 0x9B, 0x04, 0x4A, 0x8E, 0x98, 0xC6, 0xB0, 0x87, 
        0xF1, 0x5A, 0x0B, 0xFC };
    static const uint8_t M2[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    static const uint8_t H2[] = {
        0xB0, 0xE2, 0x0B, 0x6E, 0x31, 0x16, 0x64, 0x02, 0x86, 0xED, 0x3A, 0x87, 0xA5, 0x71, 0x30, 0x79, 
        0xB2, 0x1F, 0x51, 0x89 };

    static const ByteArray ba_M1 = { (uint8_t*)M1, sizeof(M1) - 1 };
    static const ByteArray ba_M2 = { (uint8_t*)M2, sizeof(M2) - 1 };

    int ret = RET_OK;
    RipemdCtx* ctx = NULL;
    ByteArray* H = NULL;

    CHECK_NOT_NULL(ctx = ripemd_alloc(RIPEMD_VARIANT_160));
    DO(ripemd_update(ctx, &ba_M1));
    DO(ripemd_final(ctx, &H));
    if (H->len != sizeof(H1) ||
        memcmp(H->buf, H1, sizeof(H1)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }
    ba_free(H);
    H = NULL;

    DO(ripemd_update(ctx, &ba_M2));
    DO(ripemd_final(ctx, &H));
    if (H->len != sizeof(H2) ||
        memcmp(H->buf, H2, sizeof(H2)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

cleanup:
    ripemd_free(ctx);
    ba_free(H);
    return ret;
}

int ripemd_self_test(void)
{
    int ret = RET_OK;

    DO(ripemd128_self_test());
    DO(ripemd160_self_test());

cleanup:
    return ret;
}
