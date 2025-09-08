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

#define FILE_MARKER "uapkic/gost34311.c"

#include <string.h>

#include "gost28147.h"
#include "gost34311.h"
#include "byte-array-internal.h"
#include "byte-utils-internal.h"
#include "macros-internal.h"

void base_cycle32(Gost28147Ctx *ctx, uint32_t src[8], const uint32_t k[32]);

/** Контекст выработки хэш-вектора. */
struct Gost34311Ctx_st {
    Gost28147Ctx *gost;
    uint8_t m32[32];          /* Часть сообщения, не прошедшая процедуру хэширования на предыдущих итерациях. */
    size_t m32_ind;           /* Смещенее первого свободного байта в буфере m32. */
    uint32_t m_bit_len[8];    /* Размер обработаных данных в битах. */
    uint8_t sync[32];         /* Cинхропосылка. */
    uint32_t sigma[8];        /* Текущее значение контрольной суммы. */
    uint8_t H[32];         /* Текущее значение хэш-функции. */
};

static __inline void reset(Gost34311Ctx *ctx)
{
    memset(ctx->sigma, 0, sizeof(ctx->sigma));
    memset(ctx->m_bit_len, 0, sizeof(ctx->m_bit_len));
    memset(ctx->m32, 0, sizeof(ctx->m32));
    memcpy(ctx->H, ctx->sync, sizeof(ctx->H));
    ctx->m32_ind = 0;
}

#define copy_keys(x1, x2, x3, x4, y1, y2, y3, y4)                                                                               \
        (y1) = ((x1) & 0xff)             ^ ((x2) & 0xff)       << 8  ^ ((x3) & 0xff)       << 16 ^ ((x4) & 0xff)       << 24;   \
        (y2) = ((x1) & 0xff00)     >>  8 ^ ((x2) & 0xff00)           ^ ((x3) & 0xff00)     << 8  ^ ((x4) & 0xff00)     << 16;   \
        (y3) = ((x1) & 0xff0000)   >> 16 ^ ((x2) & 0xff0000)   >> 8  ^ ((x3) & 0xff0000)         ^ ((x4) & 0xff0000)   << 8 ;   \
        (y4) = ((x1) & 0xff000000) >> 24 ^ ((x2) & 0xff000000) >> 16 ^ ((x3) & 0xff000000) >> 8  ^ ((x4) & 0xff000000);

/**
 * Перемешивающее преобразование.
 */
static __inline void mix_transform(const uint8_t *a8_buf, const uint8_t *b8_buf, const uint8_t *c8_buf, uint8_t *out8)
{
    /* Можно привести тип, поскольку на результат функции не влияет переворачивание порядка байт. */
    uint16_t *a = (uint16_t*)a8_buf;
    uint16_t *b = (uint16_t*)b8_buf;
    uint16_t *c = (uint16_t*)c8_buf;
    uint16_t *out = (uint16_t*)out8;
    uint16_t p1, p2, p3, p4, p5, p6, p7, p8;
    uint16_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4], a5 = a[5], a6 = a[6], a7 = a[7];
    uint16_t a8 = a[8], a9 = a[9], a10 = a[10], a11 = a[11], a12 = a[12], a13 = a[13], a14 = a[14], a15 = a[15];
    uint16_t b0 = b[0], b1 = b[1], b2 = b[2], b3 = b[3], b4 = b[4], b5 = b[5], b6 = b[6], b7 = b[7];
    uint16_t b8 = b[8], b9 = b[9], b10 = b[10], b11 = b[11], b12 = b[12], b13 = b[13], b14 = b[14], b15 = b[15];
    uint16_t c0 = c[0], c1 = c[1], c2 = c[2], c3 = c[3], c4 = c[4], c5 = c[5], c6 = c[6], c7 = c[7];
    uint16_t c8 = c[8], c9 = c[9], c10 = c[10], c11 = c[11], c12 = c[12], c13 = c[13], c14 = c[14], c15 = c[15];

    p1 = a1 ^ a4 ^ b1 ^ b5;
    p2 = a3 ^ a5 ^ a6 ^ a12 ^ b4 ^ b6 ^ b7 ^ b13;
    p3 = a6 ^ a13 ^ b3 ^ b7 ^ b14;
    p4 = a0 ^ a4 ^ a8 ^ a13 ^ a14 ^ b1 ^ b5 ^ b9 ^ b14 ^ b15 ^ c2 ^ c3 ^ c7 ^ c10 ^ c12 ^ c15;
    p5 = a1 ^ a7 ^ a10 ^ a13 ^ a14 ^ b8 ^ b11 ^ b14 ^ c5 ^ c13;
    p6 = p1 ^ a8 ^ a11 ^ a14 ^ b9 ^ c6 ^ c7 ^ c10 ^ c13 ^ c14;
    p7 = p5 ^ a3 ^ a11 ^ b1 ^ b4 ^ c1 ^ c6 ^ c9 ^ c12 ^ c14;
    p8 = p3 ^ a1 ^ a5 ^ a10 ^ b6 ^ b11 ^ b12 ^ c0 ^ c10;
    p1 ^= a5 ^ a9 ^ a15 ^ b0 ^ b6 ^ b10 ^ b12 ^ c1 ^ c2 ^ c4 ^ c8 ^ c11 ^ c15;
    p3 ^= a3 ^ a7 ^ a12 ^ a15 ^ b0 ^ b2 ^ b4 ^ b8 ^ b13 ^ c2 ^ c14;
    p5 ^= a5 ^ a9 ^ a12 ^ a15 ^ b0 ^ b6 ^ b10 ^ b13;
    out[0] = p7 ^ a15 ^ b0 ^ b3 ^ c7 ^ c10 ^ c11 ^ c15;
    out[1] = p6 ^ a0 ^ a3 ^ b2 ^ b4 ^ b12 ^ b15 ^ c0 ^ c1 ^ c3 ^ c8 ^ c11;
    out[2] = p1 ^ a2 ^ a12 ^ b13 ^ b15 ^ c7 ^ c9 ^ c12 ^ c14;
    out[3] = p8 ^ a0 ^ a12 ^ a15 ^ b0 ^ b13 ^ b15 ^ c1 ^ c5 ^ c8 ^ c9 ^ c13;
    out[4] = p3 ^ a0 ^ a11 ^ a14 ^ c1 ^ c6 ^ c9 ^ c10 ^ c11;
    out[5] = p4 ^ a2 ^ a3 ^ a7 ^ b3 ^ b4 ^ b8 ^ c11;
    out[6] = p1 ^ a3 ^ a8 ^ a14 ^ b3 ^ b4 ^ b9 ^ c0 ^ c13;
    out[7] = p2 ^ a0 ^ a1 ^ a4 ^ a9 ^ a10 ^ b1 ^ b2 ^ b5 ^ b10 ^ b11 ^ c0 ^ c5 ^ c9 ^ c14 ^ c15;
    out[8] = p8 ^ a2 ^ a4 ^ a7 ^ a11 ^ b2 ^ b5 ^ b8 ^ c2 ^ c3 ^ c6 ^ c12;
    out[9] = p2 ^ a2 ^ a7 ^ a8 ^ a11 ^ a14 ^ b3 ^ b8 ^ b9 ^ b12 ^ b15 ^ c1 ^ c3 ^ c4 ^ c7 ^ c11 ^ c13;
    out[10] = p3 ^ a4 ^ a8 ^ a9 ^ b1 ^ b5 ^ b9 ^ b10 ^ b12 ^ b15 ^ c4 ^ c5 ^ c8 ^ c12;
    out[11] = p5 ^ a0 ^ a2 ^ a3 ^ a4 ^ a8 ^ b4 ^ b5 ^ b9 ^ b12 ^ c3 ^ c6 ^ c9 ^ c15;
    out[12] = p4 ^ a5 ^ a6 ^ a9 ^ a10 ^ a11 ^ a12 ^ b6 ^ b7 ^ b10 ^ b11 ^ b12 ^ b13 ^ c0 ^ c1 ^ c4 ^ c6 ^ c14;
    out[13] = p5 ^ a6 ^ a11 ^ b1 ^ b3 ^ b7 ^ c0 ^ c4 ^ c7 ^ c8 ^ c11 ^ c12;
    out[14] = p7 ^ a0 ^ a6 ^ a8 ^ b2 ^ b7 ^ b9 ^ b12 ^ b15 ^ c8;
    out[15] = p6 ^ a2 ^ a7 ^ a9 ^ a12 ^ a15 ^ b0 ^ b8 ^ b10 ^ b13 ^ c2 ^ c9 ^ c15;
}

/**
 * Генерирует ключи шифрования.
 *
 * @param h текущее значение хэш-вектора
 * @param m блок сообщения
 * @param k сгенерированные ключи
 */
static __inline void generate_keys(const uint32_t *h32, const uint32_t *m32, uint32_t *k)
{
    uint32_t h32_0 = h32[0], h32_1 = h32[1], h32_2 = h32[2], h32_3 = h32[3];
    uint32_t h32_4 = h32[4], h32_5 = h32[5], h32_6 = h32[6], h32_7 = h32[7];
    uint32_t m32_0 = m32[0], m32_1 = m32[1], m32_2 = m32[2], m32_3 = m32[3];
    uint32_t m32_4 = m32[4], m32_5 = m32[5], m32_6 = m32[6], m32_7 = m32[7];
    uint32_t k0 = h32_0 ^ m32_0;
    uint32_t k1 = h32_2 ^ m32_2;
    uint32_t k2 = h32_4 ^ m32_4;
    uint32_t k3 = h32_6 ^ m32_6;
    copy_keys(k0, k1, k2, k3, k[0], k[1], k[2], k[3]);

    k0 = h32_1 ^ m32_1;
    k1 = h32_3 ^ m32_3;
    k2 = h32_5 ^ m32_5;
    k3 = h32_7 ^ m32_7;
    copy_keys(k0, k1, k2, k3, k[4], k[5], k[6], k[7]);

    k0 = h32_2 ^ m32_4;
    k1 = h32_4 ^ m32_6;
    k2 = h32_6 ^ m32_0 ^ m32_2;
    k3 = h32_0 ^ m32_2 ^ k0;
    copy_keys(k0, k1, k2, k3, k[8], k[9], k[10], k[11]);

    k0 = h32_3 ^ m32_5;
    k1 = h32_5 ^ m32_7;
    k2 = h32_7 ^ m32_1 ^ m32_3;
    k3 = h32_1 ^ m32_3 ^ k0;
    copy_keys(k0, k1, k2, k3, k[12], k[13], k[14], k[15]);

    k0 = h32_4 ^ m32_0 ^ m32_2;
    k1 = h32_2 ^ m32_6;
    k2 = k1 ^ h32_0 ^ m32_4 ^ 0x00ffff00;
    k3 = k0 ^ k1 ^ 0x000000ff;
    k0 ^= 0xff00ff00;
    k1 = h32_6 ^ m32_2 ^ m32_4 ^ 0x00ff00ff;
    copy_keys(k0, k1, k2, k3, k[16], k[17], k[18], k[19]);

    k0 = h32_5 ^ m32_1 ^ m32_3;
    k1 = h32_3 ^ m32_7;
    k2 = k1 ^ h32_1 ^ m32_5 ^ 0xff0000ff;
    k3 = k0 ^ k1 ^ 0xff00ffff;
    k0 ^= 0xff00ff00;
    k1 = h32_7 ^ m32_3 ^ m32_5 ^ 0x00ff00ff;
    copy_keys(k0, k1, k2, k3, k[20], k[21], k[22], k[23]);

    k0 = h32_6 ^ m32_6;
    k3 = k0 ^ h32_4 ^ m32_2 ^ 0xffffffff;
    k0 ^= m32_4 ^ 0x00ff00ff;
    k1 = h32_2 ^ m32_0;
    k2 = k1 ^ h32_4 ^ m32_4 ^ 0x000000ff;
    k1 ^= h32_0 ^ m32_2 ^ m32_6 ^ 0x00ffff00;
    copy_keys(k0, k1, k2, k3, k[24], k[25], k[26], k[27]);

    k0 = h32_7 ^ m32_7;
    k3 = k0 ^ h32_5 ^ m32_3 ^ 0xffffffff;
    k0 ^= m32_5 ^ 0x00ff00ff;
    k1 = h32_3 ^ m32_1;
    k2 = k1 ^ h32_5 ^ m32_5 ^ 0xff00ffff;
    k1 ^= h32_1 ^ m32_3 ^ m32_7 ^ 0xff0000ff;
    copy_keys(k0, k1, k2, k3, k[28], k[29], k[30], k[31]);
}

/**
 * Выполняет итерацию хэширования.
 *
 * @param ctx контекст выработки хэш-вектора
 * @param m 32 байтный блок сообщения
 */
static int hash_step(Gost34311Ctx *ctx, const uint8_t *m)
{
    uint8_t s[32];
    uint32_t keys[32];
    uint32_t hash32[8];
    uint32_t m32[8];
    uint8_t new_hash[32];
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(m != NULL);

    DO(uint8_to_uint32(ctx->H, 32, hash32, 8));
    DO(uint8_to_uint32(m, 32, m32, 8));

    /* Генерация ключей для шифрующего преобразования. */
    generate_keys(hash32, m32, keys);

    /* Шифрующее преобразование. */
    base_cycle32(ctx->gost, hash32, keys);

    DO(uint32_to_uint8(hash32, 8, s, 32));

    mix_transform(ctx->H, m, s, new_hash);

    memcpy(ctx->H, new_hash, 32);

cleanup:

    return ret;
}

/**
 * Выполняет сложение двух 32 байтных чисел.
 *
 * @param a первое слагаемое, замещаемое суммой
 * @param b второе слагаемое
 */
static void add(uint32_t *a, const uint32_t *b)
{
    uint64_t sum = 0;
    int i;

    for (i = 0; i < 8; i++) {
        sum = (uint64_t)a[i] + b[i] + (sum >> 32);
        a[i] = (uint32_t)sum;
    }
}

/**
 * Обновляет текущее значение хэш-функции очередными 32 байтами сообщения.
 *
 * @param ctx контекст выработки хэш-вектора
 */
static int update(Gost34311Ctx *ctx)
{
    int i;
    uint32_t m32[8];
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);

    /* Базовый шаг. */
    DO(hash_step(ctx, ctx->m32));

    /* Вычисление длины сообщения. */
    ctx->m_bit_len[0] += 256;
    if (ctx->m_bit_len[0] < 256) {
        for (i = 1; (i < 8) && (++ctx->m_bit_len[i] == 0); i++);
    }

    /* Вычисление контрольной суммы. */
    DO(uint8_to_uint32(ctx->m32, 32, m32, 8));
    add(ctx->sigma, m32);

cleanup:

    return ret;
}

Gost34311Ctx *gost34311_alloc(Gost28147SboxId sbox_id, const ByteArray *sync)
{
    Gost34311Ctx *ctx = NULL;
    int ret = RET_OK;
    
    CALLOC_CHECKED(ctx, sizeof(Gost34311Ctx));
    CHECK_NOT_NULL(ctx->gost = gost28147_alloc(sbox_id));
    if (sync) {
        CHECK_PARAM(sync->len == 32);
        DO(ba_to_uint8(sync, ctx->sync, sizeof(ctx->sync)));
    } else {
        memset(ctx->sync, 0, sizeof(ctx->sync));
    }

    reset(ctx);

cleanup:

    if (ret != RET_OK) {
        gost34311_free(ctx);
        ctx = NULL;
    }

    return ctx;
}

Gost34311Ctx *gost34311_alloc_user_sbox(const ByteArray *sbox, const ByteArray *sync)
{
    Gost28147Ctx *gost28147_ctx = NULL;
    Gost34311Ctx *ctx = NULL;
    int ret = RET_OK;

    CHECK_PARAM(sync != NULL);
    CHECK_PARAM(sync->len == 32);

    CALLOC_CHECKED(ctx, sizeof(Gost34311Ctx));
    CHECK_NOT_NULL(gost28147_ctx = gost28147_alloc_user_sbox(sbox));

    ctx->gost = gost28147_ctx;
    DO(ba_to_uint8(sync, ctx->sync, sizeof(ctx->sync)));

    reset(ctx);

cleanup:

    if (ret != RET_OK) {
        gost34311_free(ctx);
        ctx = NULL;
    }

    return ctx;
}

Gost34311Ctx *gost34311_copy_with_alloc(const Gost34311Ctx *ctx)
{
    Gost34311Ctx *out = NULL;
    int ret = RET_OK;

    CALLOC_CHECKED(out, sizeof(Gost34311Ctx));
    memcpy(out, ctx, sizeof(Gost34311Ctx));
    CHECK_NOT_NULL(out->gost = gost28147_copy_with_alloc(ctx->gost));

cleanup:

    if (ret != RET_OK) {
        gost34311_free(out);
        out = NULL;
    }

    return out;
}

int gost34311_update(Gost34311Ctx *ctx, const ByteArray *data)
{
    const uint8_t *buf;
    size_t len = ba_get_len(data);
    size_t size = 0;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(data != NULL);

    buf = data->buf;

    for (;;) {
        size = min(32 - ctx->m32_ind, len);
        memcpy(ctx->m32 + ctx->m32_ind, buf, size);
        ctx->m32_ind += size;
        buf += size;
        len -= size;

        if (!len) {
            break;
        }

        DO(update(ctx));
        ctx->m32_ind = 0;
    }

cleanup:

    return ret;
}

int gost34311_final(Gost34311Ctx *ctx, ByteArray **out)
{
    uint32_t m32[8];
    uint32_t bit;
    uint8_t m_bit_len[32];
    uint8_t sigma8[32];
    int i;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(out != NULL);

    /* Вычисление длины сообщения. */
    bit = (uint32_t)(ctx->m32_ind << 3);
    ctx->m_bit_len[0] += bit;
    if (ctx->m_bit_len[0] < bit) {
        for (i = 1; (i < 8) && (++ctx->m_bit_len[i] == 0); i++);
    }

    memset(ctx->m32 + ctx->m32_ind, 0, 32 - ctx->m32_ind);

    /* Итерация вычисления контрольной суммы для оставшихся у m32 даних. */
    DO(uint8_to_uint32(ctx->m32, 32, m32, 8));
    add(ctx->sigma, m32);
    memset(m32, 0, sizeof(m32));

    DO(hash_step(ctx, ctx->m32));

    DO(uint32_to_uint8(ctx->m_bit_len, 8, m_bit_len, 32));
    DO(hash_step(ctx, m_bit_len));

    /* Обрабатываем буфер sigma. */
    DO(uint32_to_uint8(ctx->sigma, 8, sigma8, 32));
    DO(hash_step(ctx, sigma8));

    CHECK_NOT_NULL(*out = ba_alloc_from_uint8(ctx->H, 32));

    /* Переинициализируем контекст хэш-вектора. */
    reset(ctx);

cleanup:

    return ret;
}

void gost34311_free(Gost34311Ctx *ctx)
{
    if (ctx) {
        gost28147_free(ctx->gost);
        free(ctx);
    }
}

size_t gost34311_get_block_size(const Gost34311Ctx* ctx)
{
    (void)ctx;
    return 32;
}

int gost34311_self_test(void)
{
    // ГОСТ 34.311-95. А.3.1, А.3.2
    static const uint8_t M1[] = {
        0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2c,
        0x20, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3d, 0x33, 0x32, 0x20, 0x62, 0x79, 0x74, 0x65, 0x73 };
    static const uint8_t H1[] = {
        0xb1, 0xc4, 0x66, 0xd3, 0x75, 0x19, 0xb8, 0x2e, 0x83, 0x19, 0x81, 0x9f, 0xf3, 0x25, 0x95, 0xe0,
        0x47, 0xa2, 0x8c, 0xb6, 0xf8, 0x3e, 0xff, 0x1c, 0x69, 0x16, 0xa8, 0x15, 0xa6, 0x37, 0xff, 0xfa };
    static const uint8_t M2[] = {
        0x53, 0x75, 0x70, 0x70, 0x6f, 0x73, 0x65, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6f, 0x72, 0x69, 0x67,
        0x69, 0x6e, 0x61, 0x6c, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x68, 0x61, 0x73,
        0x20, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x20, 0x3d, 0x20, 0x35, 0x30, 0x20, 0x62, 0x79, 0x74,
        0x65, 0x73 };
    static const uint8_t H2[] = {
        0x47, 0x1a, 0xba, 0x57, 0xa6, 0x0a, 0x77, 0x0d, 0x3a, 0x76, 0x13, 0x06, 0x35, 0xc1, 0xfb, 0xea,
        0x4e, 0xf1, 0x4d, 0xe5, 0x1f, 0x78, 0xb4, 0xae, 0x57, 0xdd, 0x89, 0x3b, 0x62, 0xf5, 0x52, 0x08 };

    static const ByteArray ba_M1 = { (uint8_t*)M1, sizeof(M1) };
    static const ByteArray ba_M2 = { (uint8_t*)M2, sizeof(M2) };

    int ret = RET_OK;
    Gost34311Ctx* ctx = NULL;
    ByteArray* H = NULL;

    CHECK_NOT_NULL(ctx = gost34311_alloc(GOST28147_SBOX_ID_11, NULL));
    DO(gost34311_update(ctx, &ba_M1));
    DO(gost34311_final(ctx, &H));
    if (H->len != sizeof(H1) ||
        memcmp(H->buf, H1, sizeof(H1)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }
    ba_free(H);
    H = NULL;

    DO(gost34311_update(ctx, &ba_M2));
    DO(gost34311_final(ctx, &H));
    if (H->len != sizeof(H2) ||
        memcmp(H->buf, H2, sizeof(H2)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

cleanup:
    gost34311_free(ctx);
    ba_free(H);
    return ret;
}
