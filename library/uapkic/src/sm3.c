/*
 * Copyright 2021 The UAPKI Project Authors.
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
#include <stddef.h>

#include "sm3.h"
#include "byte-utils-internal.h"
#include "byte-array-internal.h"
#include "macros-internal.h"

#undef FILE_MARKER
#define FILE_MARKER "uapkic/sm3.c"

struct Sm3Ctx_st {
    uint32_t total[2];
    uint32_t state[8];
    uint8_t buffer[64];
};

#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                       \
{                                                  \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )        \
        | ( (uint32_t) (b)[(i) + 1] << 16 )        \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )        \
        | ( (uint32_t) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                      \
{                                                 \
    (b)[(i)    ] = (uint8_t) ( (n) >> 24 );       \
    (b)[(i) + 1] = (uint8_t) ( (n) >> 16 );       \
    (b)[(i) + 2] = (uint8_t) ( (n) >>  8 );       \
    (b)[(i) + 3] = (uint8_t) ( (n)       );       \
}
#endif

#define FF0(x,y,z) ( (x) ^ (y) ^ (z)) 
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x,y,z) ( (x) ^ (y) ^ (z)) 
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )

#define  SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))

#define P0(x) ((x) ^  ROTL((x),9) ^ ROTL((x),17)) 
#define P1(x) ((x) ^  ROTL((x),15) ^ ROTL((x),23)) 

static void sm3_init(Sm3Ctx* ctx)
{
    memset(ctx, 0, sizeof(Sm3Ctx));

    ctx->state[0] = 0x7380166F;
    ctx->state[1] = 0x4914B2B9;
    ctx->state[2] = 0x172442D7;
    ctx->state[3] = 0xDA8A0600;
    ctx->state[4] = 0xA96F30BC;
    ctx->state[5] = 0x163138AA;
    ctx->state[6] = 0xE38DEE4D;
    ctx->state[7] = 0xB0FB0E4E;
}

static void sm3_process(Sm3Ctx* ctx, const uint8_t data[64])
{
    uint32_t SS1, SS2, TT1, TT2, W[68], W1[64];
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t T[64];
    uint32_t Temp1, Temp2, Temp3, Temp4, Temp5;
    size_t j;

    for (j = 0; j < 16; j++) {
        T[j] = 0x79CC4519;
    }
    for (j = 16; j < 64; j++) {
        T[j] = 0x7A879D8A;
    }

    GET_UINT32_BE(W[0], data, 0);
    GET_UINT32_BE(W[1], data, 4);
    GET_UINT32_BE(W[2], data, 8);
    GET_UINT32_BE(W[3], data, 12);
    GET_UINT32_BE(W[4], data, 16);
    GET_UINT32_BE(W[5], data, 20);
    GET_UINT32_BE(W[6], data, 24);
    GET_UINT32_BE(W[7], data, 28);
    GET_UINT32_BE(W[8], data, 32);
    GET_UINT32_BE(W[9], data, 36);
    GET_UINT32_BE(W[10], data, 40);
    GET_UINT32_BE(W[11], data, 44);
    GET_UINT32_BE(W[12], data, 48);
    GET_UINT32_BE(W[13], data, 52);
    GET_UINT32_BE(W[14], data, 56);
    GET_UINT32_BE(W[15], data, 60);

    for (j = 16; j < 68; j++)
    {
        Temp1 = W[j - 16] ^ W[j - 9];
        Temp2 = ROTL(W[j - 3], 15);
        Temp3 = Temp1 ^ Temp2;
        Temp4 = P1(Temp3);
        Temp5 = ROTL(W[j - 13], 7) ^ W[j - 6];
        W[j] = Temp4 ^ Temp5;
    }

    for (j = 0; j < 64; j++)
    {
        W1[j] = W[j] ^ W[j + 4];
    }

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];

    for (j = 0; j < 16; j++)
    {
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = FF0(A, B, C) + D + SS2 + W1[j];
        TT2 = GG0(E, F, G) + H + SS1 + W[j];
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }

    for (j = 16; j < 64; j++)
    {
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = FF1(A, B, C) + D + SS2 + W1[j];
        TT2 = GG1(E, F, G) + H + SS1 + W[j];
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }

    ctx->state[0] ^= A;
    ctx->state[1] ^= B;
    ctx->state[2] ^= C;
    ctx->state[3] ^= D;
    ctx->state[4] ^= E;
    ctx->state[5] ^= F;
    ctx->state[6] ^= G;
    ctx->state[7] ^= H;
}

Sm3Ctx* sm3_alloc(void)
{
    Sm3Ctx *ctx = calloc(1, sizeof(Sm3Ctx));
    if (ctx) {
        sm3_init(ctx);
    }
    return ctx;
}

Sm3Ctx* sm3_copy_with_alloc(const Sm3Ctx* ctx)
{
    Sm3Ctx* out = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CALLOC_CHECKED(out, sizeof(Sm3Ctx));
    memcpy(out, ctx, sizeof(Sm3Ctx));

cleanup:

    return out;
}

int sm3_update(Sm3Ctx* ctx, const ByteArray* msg)
{
    int ret = RET_OK;
    size_t fill, left, ilen;
    const uint8_t* input;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(msg != NULL);

    input = msg->buf;
    ilen = msg->len;
    if (ilen == 0) {
        goto cleanup;
    }

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += (uint32_t)ilen;
    if (ctx->total[0] < (uint32_t)ilen) {
        ctx->total[1]++;
    }

    if (left && (ilen >= fill)) {
        memcpy(ctx->buffer + left, input, fill);
        sm3_process(ctx, ctx->buffer);
        input += fill;
        ilen -= fill;
        left = 0;
    }

    while (ilen >= 64) {
        sm3_process(ctx, input);
        input += 64;
        ilen -= 64;
    }

    if (ilen > 0) {
        memcpy(ctx->buffer + left, input, ilen);
    }

cleanup:
    return ret;
}

int sm3_final(Sm3Ctx* ctx, ByteArray** H)
{
    int ret = RET_OK;
    uint32_t last, high, low;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(H != NULL);
    CHECK_NOT_NULL(*H = ba_alloc_by_len(32));

    last = ctx->total[0] & 0x3F;

    high = (ctx->total[0] >> 29)
        | (ctx->total[1] << 3);
    low = (ctx->total[0] << 3);

    ctx->buffer[last++] = 0x80;
    memset(ctx->buffer + last, 0, (size_t)64 - last);

    if (last > 56) {
        sm3_process(ctx, ctx->buffer);
        memset(ctx->buffer, 0, 56);
    }

    PUT_UINT32_BE(high, ctx->buffer, 56);
    PUT_UINT32_BE(low, ctx->buffer, 60);
    sm3_process(ctx, ctx->buffer);

    PUT_UINT32_BE(ctx->state[0], (*H)->buf, 0);
    PUT_UINT32_BE(ctx->state[1], (*H)->buf, 4);
    PUT_UINT32_BE(ctx->state[2], (*H)->buf, 8);
    PUT_UINT32_BE(ctx->state[3], (*H)->buf, 12);
    PUT_UINT32_BE(ctx->state[4], (*H)->buf, 16);
    PUT_UINT32_BE(ctx->state[5], (*H)->buf, 20);
    PUT_UINT32_BE(ctx->state[6], (*H)->buf, 24);
    PUT_UINT32_BE(ctx->state[7], (*H)->buf, 28);
    sm3_init(ctx);

cleanup:
    return ret;
}

size_t sm3_get_block_size(const Sm3Ctx* ctx)
{
    (void)ctx;
    return 64;
}

void sm3_free(Sm3Ctx* ctx)
{
    if (ctx) {
        secure_zero(ctx, sizeof(Sm3Ctx));
        free(ctx);
    }
}

int sm3_self_test(void)
{
// GB/T 32905-2016 A.1, A.2 
    static const uint8_t M1[] = "abc";
    static const uint8_t H1[] = {
        0x66, 0xC7, 0xF0, 0xF4, 0x62, 0xEE, 0xED, 0xD9, 0xD1, 0xF2, 0xD4, 0x6B, 0xDC, 0x10, 0xE4, 0xE2,
        0x41, 0x67, 0xC4, 0x87, 0x5C, 0xF2, 0xF7, 0xA2, 0x29, 0x7D, 0xA0, 0x2B, 0x8F, 0x4B, 0xA8, 0xE0 };
    static const uint8_t M2[] = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    static const uint8_t H2[] = {
        0xDE, 0xBE, 0x9F, 0xF9, 0x22, 0x75, 0xB8, 0xA1, 0x38, 0x60, 0x48, 0x89, 0xC1, 0x8E, 0x5A, 0x4D, 
        0x6F, 0xDB, 0x70, 0xE5, 0x38, 0x7E, 0x57, 0x65, 0x29, 0x3D, 0xCB, 0xA3, 0x9C, 0x0C, 0x57, 0x32 };

    static const ByteArray ba_M1 = { (uint8_t*)M1, sizeof(M1) - 1 };
    static const ByteArray ba_M2 = { (uint8_t*)M2, sizeof(M2) - 1 };

    int ret = RET_OK;
    Sm3Ctx* ctx = NULL;
    ByteArray* ba_hash = NULL;

    CHECK_NOT_NULL(ctx = sm3_alloc());
    DO(sm3_update(ctx, &ba_M1));
    DO(sm3_final(ctx, &ba_hash));
    if ((ba_hash->len != sizeof(H1)) ||
        (memcmp(ba_hash->buf, H1, sizeof(H1)) != 0)) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }
    ba_free(ba_hash);
    ba_hash = NULL;

    DO(sm3_update(ctx, &ba_M2));
    DO(sm3_final(ctx, &ba_hash));
    if ((ba_hash->len != sizeof(H2)) ||
        (memcmp(ba_hash->buf, H2, sizeof(H2)) != 0)) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

cleanup:
    ba_free(ba_hash);
    sm3_free(ctx);
    return ret;
}
