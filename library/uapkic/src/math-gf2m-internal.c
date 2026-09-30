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

#define FILE_MARKER "uapkic/math-gf2m-internal.c"

#include <stdint.h>
#include <string.h>

#include "math-gf2m-internal.h"
#include "math-int-internal.h"
#include "macros-internal.h"

#if defined(ARCH64) && (defined(__x86_64__) || defined(_M_X64)) && !defined(UAPKI_NO_CLMUL)
# define GF2M_CLMUL 1
# if defined(_MSC_VER) && !defined(__clang__)
#  include <intrin.h>
#  define GF2M_CLMUL_TARGET
# else
#  include <immintrin.h>
#  define GF2M_CLMUL_TARGET __attribute__((target("pclmul,sse2")))
# endif
#endif

#if defined(GF2M_CLMUL)

/* Максимальна довжина елемента поля в словах для апаратного множення (1024 біти). */
#define GF2M_CLMUL_MAX_LEN 16

static int gf2m_clmul_state = 0;

/* UAPKIC_DISABLE_CLMUL=1 у змінних середовища примусово вмикає програмний шлях (для тестування резервної реалізації). */
static int gf2m_clmul_detect(void)
{
    const char *disabled = getenv("UAPKIC_DISABLE_CLMUL");
    if (disabled != NULL && disabled[0] != '\0' && disabled[0] != '0') {
        return 0;
    }
#if defined(_MSC_VER) && !defined(__clang__)
    {
        int info[4] = {0, 0, 0, 0};
        __cpuid(info, 1);
        return (info[2] & (1 << 1)) != 0;
    }
#else
    __builtin_cpu_init();
    return __builtin_cpu_supports("pclmul") && __builtin_cpu_supports("sse2");
#endif
}

/* Ознака наявності PCLMULQDQ; визначається один раз (повторний запис того самого значення безпечний). */
static inline int gf2m_use_clmul(void)
{
#if defined(_MSC_VER) && !defined(__clang__)
    int s = gf2m_clmul_state;
#else
    int s = __atomic_load_n(&gf2m_clmul_state, __ATOMIC_RELAXED);
#endif
    if (s == 0) {
        s = gf2m_clmul_detect() ? 1 : -1;
#if defined(_MSC_VER) && !defined(__clang__)
        gf2m_clmul_state = s;
#else
        __atomic_store_n(&gf2m_clmul_state, s, __ATOMIC_RELAXED);
#endif
    }
    return s > 0;
}

GF2M_CLMUL_TARGET
static void gf2m_mul_64_clmul(const word_t x, const word_t y, Dword *res)
{
    __m128i r = _mm_clmulepi64_si128(_mm_cvtsi64_si128((long long)x), _mm_cvtsi64_si128((long long)y), 0x00);

    res->lo = (word_t)_mm_cvtsi128_si64(r);
    res->hi = (word_t)_mm_cvtsi128_si64(_mm_srli_si128(r, 8));
}

/**
 * Множення многочленів довжиною n слів (схема "стовпчиком" на PCLMULQDQ), r = x * y довжиною 2n слів.
 * Стовпець k накопичує всі добутки x[i]*y[j], i + j = k; слово k результату = lo(c[k]) ^ hi(c[k-1]).
 */
GF2M_CLMUL_TARGET
static inline void gf2m_mul_clmul_n(const word_t *x, const word_t *y, int n, word_t *r)
{
    __m128i c[2 * GF2M_CLMUL_MAX_LEN];
    __m128i yv[GF2M_CLMUL_MAX_LEN];
    __m128i prev;
    int i, j;

    for (j = 0; j < n; j++) {
        yv[j] = _mm_cvtsi64_si128((long long)y[j]);
    }

    for (i = 0; i < n; i++) {
        __m128i xi = _mm_cvtsi64_si128((long long)x[i]);
        if (i == 0) {
            for (j = 0; j < n; j++) {
                c[j] = _mm_clmulepi64_si128(xi, yv[j], 0x00);
            }
        } else {
            for (j = 0; j < n - 1; j++) {
                c[i + j] = _mm_xor_si128(c[i + j], _mm_clmulepi64_si128(xi, yv[j], 0x00));
            }
            c[i + n - 1] = _mm_clmulepi64_si128(xi, yv[n - 1], 0x00);
        }
    }

    prev = _mm_setzero_si128();
    for (i = 0; i < 2 * n - 2; i += 2) {
        __m128i lo = _mm_unpacklo_epi64(c[i], c[i + 1]);
        __m128i hi = _mm_unpackhi_epi64(prev, c[i]);
        _mm_storeu_si128((__m128i *)(r + i), _mm_xor_si128(lo, hi));
        prev = c[i + 1];
    }
    _mm_storeu_si128((__m128i *)(r + 2 * n - 2),
            _mm_xor_si128(_mm_unpacklo_epi64(c[2 * n - 2], _mm_setzero_si128()), _mm_unpackhi_epi64(prev, c[2 * n - 2])));
}

GF2M_CLMUL_TARGET
static void gf2m_mul_clmul(const word_t *x, const word_t *y, int n, word_t *r)
{
    switch (n) {
    case 3:
        gf2m_mul_clmul_n(x, y, 3, r);
        break;
    case 4:
        gf2m_mul_clmul_n(x, y, 4, r);
        break;
    case 5:
        gf2m_mul_clmul_n(x, y, 5, r);
        break;
    case 6:
        gf2m_mul_clmul_n(x, y, 6, r);
        break;
    case 7:
        gf2m_mul_clmul_n(x, y, 7, r);
        break;
    case 9:
        gf2m_mul_clmul_n(x, y, 9, r);
        break;
    default:
        gf2m_mul_clmul_n(x, y, n, r);
        break;
    }
}

GF2M_CLMUL_TARGET
static void gf2m_sqr_clmul(const word_t *x, int n, word_t *r)
{
    int i;

    for (i = 0; i < n; i++) {
        __m128i xi = _mm_cvtsi64_si128((long long)x[i]);
        _mm_storeu_si128((__m128i *)(r + 2 * i), _mm_clmulepi64_si128(xi, xi, 0x00));
    }
}

/*
 * Один крок зведення: a = L + H * x^m -> L + H * (f - x^m), де f - x^m = x^f[1] (+ x^f[2] + x^f[3]) + 1
 * розміщується в fr_lo | fr_hi << 64, H - старші hw слів, починаючи з біта m (слово w = n - 1, біт b).
 * Буфер a має 2n + 2 слова (два старші - нульові).
 */
GF2M_CLMUL_TARGET
static inline void gf2m_mod_clmul_step(word_t *a, int n, int b, int hw, __m128i flo, __m128i fhi, int has_hi)
{
    word_t h[GF2M_CLMUL_MAX_LEN + 2];
    word_t nmask = (b == 0) ? 0 : ~(word_t)0;
    int ls = (WORD_BIT_LENGTH - b) & WORD_BIT_LEN_MASK;
    int w = n - 1;
    int i;

    for (i = 0; i < hw; i++) {
        h[i] = (a[w + i] >> b) | ((a[w + i + 1] << ls) & nmask);
    }

    a[w] &= ((word_t)1 << b) - 1;
    for (i = w + 1; i < 2 * n; i++) {
        a[i] = 0;
    }

    for (i = 0; i < hw; i++) {
        __m128i hi = _mm_cvtsi64_si128((long long)h[i]);
        __m128i p = _mm_clmulepi64_si128(hi, flo, 0x00);
        a[i] ^= (word_t)_mm_cvtsi128_si64(p);
        a[i + 1] ^= (word_t)_mm_cvtsi128_si64(_mm_srli_si128(p, 8));
        if (has_hi) {
            p = _mm_clmulepi64_si128(hi, fhi, 0x00);
            a[i + 1] ^= (word_t)_mm_cvtsi128_si64(p);
            a[i + 2] ^= (word_t)_mm_cvtsi128_si64(_mm_srli_si128(p, 8));
        }
    }
}

/*
 * Повертає 1, якщо в a залишилися біти зі степенем >= m.
 */
static inline int gf2m_mod_clmul_rest(const word_t *a, int n, int b)
{
    int w = n - 1;
    word_t rest = a[w] >> b;
    int i;

    for (i = w + 1; i < 2 * n; i++) {
        rest |= a[i];
    }

    return rest != 0;
}

/**
 * Зведення за модулем f многочлена a довжиною 2n + 2 слова (a руйнується): out = a mod f.
 * Для deg(a) <= 2m - 2 старша частина H займає не більше n слів і достатньо двох кроків: після першого
 * deg <= m - 2 + k, другий обробляє hw2 старших слів. Цикл ніколи не виконується для коректних
 * аргументів і залишений для повноти.
 */
GF2M_CLMUL_TARGET
static inline void gf2m_mod_clmul_n(const Gf2mCtx *ctx, word_t *a, int n, word_t *out)
{
    __m128i flo = _mm_cvtsi64_si128((long long)ctx->fr_lo);
    __m128i fhi = _mm_cvtsi64_si128((long long)ctx->fr_hi);
    int has_hi = ctx->fr_hi != 0;
    int b = ctx->f[0] & WORD_BIT_LEN_MASK;

    a[2 * n] = 0;
    a[2 * n + 1] = 0;

    gf2m_mod_clmul_step(a, n, b, n, flo, fhi, has_hi);
    gf2m_mod_clmul_step(a, n, b, ctx->hw2, flo, fhi, has_hi);
    while (gf2m_mod_clmul_rest(a, n, b)) {
        gf2m_mod_clmul_step(a, n, b, n + 1, flo, fhi, has_hi);
    }

    memcpy(out, a, n * sizeof(word_t));
}

GF2M_CLMUL_TARGET
static void gf2m_mod_clmul(const Gf2mCtx *ctx, word_t *a, word_t *out)
{
    switch (ctx->len) {
    case 3:
        gf2m_mod_clmul_n(ctx, a, 3, out);
        break;
    case 4:
        gf2m_mod_clmul_n(ctx, a, 4, out);
        break;
    case 5:
        gf2m_mod_clmul_n(ctx, a, 5, out);
        break;
    case 6:
        gf2m_mod_clmul_n(ctx, a, 6, out);
        break;
    case 7:
        gf2m_mod_clmul_n(ctx, a, 7, out);
        break;
    case 9:
        gf2m_mod_clmul_n(ctx, a, 9, out);
        break;
    default:
        gf2m_mod_clmul_n(ctx, a, (int)ctx->len, out);
        break;
    }
}

/*
 * Апаратний шлях застосовний, якщо довжина елемента від 3 до GF2M_CLMUL_MAX_LEN слів, f[1] < 128
 * (f - x^m вміщується в 128 біт) і 2 * f[1] - 2 < m (двох кроків зведення достатньо).
 * Константи зведення обчислюються один раз під час створення контексту.
 */
static void gf2m_clmul_init(Gf2mCtx *ctx)
{
    int m = ctx->f[0];
    int i;

    ctx->clmul = 0;
    if (ctx->len < 3 || ctx->len > GF2M_CLMUL_MAX_LEN || ctx->len != (size_t)(m >> WORD_BIT_LEN_SHIFT) + 1
            || ctx->f[1] >= DWORD_BIT_LENGTH || 2 * ctx->f[1] - 2 >= m || !gf2m_use_clmul()) {
        return;
    }

    ctx->fr_lo = 1;
    ctx->fr_hi = 0;
    for (i = 1; ctx->f[i] != 0; i++) {
        if (ctx->f[i] < WORD_BIT_LENGTH) {
            ctx->fr_lo |= (word_t)1 << ctx->f[i];
        } else {
            ctx->fr_hi |= (word_t)1 << (ctx->f[i] - WORD_BIT_LENGTH);
        }
    }
    ctx->hw2 = ((m - 2 + ctx->f[1]) >> WORD_BIT_LEN_SHIFT) - (int)ctx->len + 2;
    ctx->clmul = 1;
}

#endif

/* Таблиця попередніх обчислень для піднесення до квадрата. */
static const uint16_t GF2M_SQR_PRECOMP[256] = {
    0x0000, 0x0001, 0x0004, 0x0005, 0x0010, 0x0011, 0x0014, 0x0015,
    0x0040, 0x0041, 0x0044, 0x0045, 0x0050, 0x0051, 0x0054, 0x0055,
    0x0100, 0x0101, 0x0104, 0x0105, 0x0110, 0x0111, 0x0114, 0x0115,
    0x0140, 0x0141, 0x0144, 0x0145, 0x0150, 0x0151, 0x0154, 0x0155,
    0x0400, 0x0401, 0x0404, 0x0405, 0x0410, 0x0411, 0x0414, 0x0415,
    0x0440, 0x0441, 0x0444, 0x0445, 0x0450, 0x0451, 0x0454, 0x0455,
    0x0500, 0x0501, 0x0504, 0x0505, 0x0510, 0x0511, 0x0514, 0x0515,
    0x0540, 0x0541, 0x0544, 0x0545, 0x0550, 0x0551, 0x0554, 0x0555,
    0x1000, 0x1001, 0x1004, 0x1005, 0x1010, 0x1011, 0x1014, 0x1015,
    0x1040, 0x1041, 0x1044, 0x1045, 0x1050, 0x1051, 0x1054, 0x1055,
    0x1100, 0x1101, 0x1104, 0x1105, 0x1110, 0x1111, 0x1114, 0x1115,
    0x1140, 0x1141, 0x1144, 0x1145, 0x1150, 0x1151, 0x1154, 0x1155,
    0x1400, 0x1401, 0x1404, 0x1405, 0x1410, 0x1411, 0x1414, 0x1415,
    0x1440, 0x1441, 0x1444, 0x1445, 0x1450, 0x1451, 0x1454, 0x1455,
    0x1500, 0x1501, 0x1504, 0x1505, 0x1510, 0x1511, 0x1514, 0x1515,
    0x1540, 0x1541, 0x1544, 0x1545, 0x1550, 0x1551, 0x1554, 0x1555,
    0x4000, 0x4001, 0x4004, 0x4005, 0x4010, 0x4011, 0x4014, 0x4015,
    0x4040, 0x4041, 0x4044, 0x4045, 0x4050, 0x4051, 0x4054, 0x4055,
    0x4100, 0x4101, 0x4104, 0x4105, 0x4110, 0x4111, 0x4114, 0x4115,
    0x4140, 0x4141, 0x4144, 0x4145, 0x4150, 0x4151, 0x4154, 0x4155,
    0x4400, 0x4401, 0x4404, 0x4405, 0x4410, 0x4411, 0x4414, 0x4415,
    0x4440, 0x4441, 0x4444, 0x4445, 0x4450, 0x4451, 0x4454, 0x4455,
    0x4500, 0x4501, 0x4504, 0x4505, 0x4510, 0x4511, 0x4514, 0x4515,
    0x4540, 0x4541, 0x4544, 0x4545, 0x4550, 0x4551, 0x4554, 0x4555,
    0x5000, 0x5001, 0x5004, 0x5005, 0x5010, 0x5011, 0x5014, 0x5015,
    0x5040, 0x5041, 0x5044, 0x5045, 0x5050, 0x5051, 0x5054, 0x5055,
    0x5100, 0x5101, 0x5104, 0x5105, 0x5110, 0x5111, 0x5114, 0x5115,
    0x5140, 0x5141, 0x5144, 0x5145, 0x5150, 0x5151, 0x5154, 0x5155,
    0x5400, 0x5401, 0x5404, 0x5405, 0x5410, 0x5411, 0x5414, 0x5415,
    0x5440, 0x5441, 0x5444, 0x5445, 0x5450, 0x5451, 0x5454, 0x5455,
    0x5500, 0x5501, 0x5504, 0x5505, 0x5510, 0x5511, 0x5514, 0x5515,
    0x5540, 0x5541, 0x5544, 0x5545, 0x5550, 0x5551, 0x5554, 0x5555
};

/**
 * @param ctx
 * @param f
 * @param f_len
 */
static void gf2m_init(Gf2mCtx *ctx, const int *f, size_t f_len)
{
    int i;
    int ret = RET_OK;

    ASSERT(ctx != NULL);
    ASSERT(f != NULL);
    ASSERT(f[f_len - 1] == 0);

    MALLOC_CHECKED(ctx->f, f_len * sizeof(int));
    memcpy(ctx->f, f, f_len * sizeof(int));

    ctx->len = (f[0] >> WORD_BIT_LEN_SHIFT) + 1;

    CHECK_NOT_NULL(ctx->f_ext = wa_alloc_with_zero(ctx->len));
    for (i = (f[2] == 0 ? 2 : 4); i >= 0; i--) {
        ctx->f_ext->buf[(f[i] >> WORD_BIT_LEN_SHIFT)] |= (word_t)1 << (f[i] & WORD_BIT_LEN_MASK);
    }

#if defined(GF2M_CLMUL)
    gf2m_clmul_init(ctx);
#endif

cleanup:

    return;
}

Gf2mCtx *gf2m_alloc(const int *f, size_t f_len)
{
    Gf2mCtx *ctx = NULL;
    int ret = RET_OK;

    if (f == NULL) {
        return NULL;
    }

    CHECK_PARAM(f[0] > 0 && f[0] <= GF2M_MAX_BIT_LENGTH);

    CALLOC_CHECKED(ctx, sizeof(Gf2mCtx));
    gf2m_init(ctx, f, f_len);

cleanup:

    return ctx;
}

/**
 * Довжина великого цілого в бітах (еквівалент int_bit_len для необробленого масиву слів).
 *
 * @param a масив слів
 * @param len довжина масиву в словах
 */
static size_t gf2m_bit_len(const word_t *a, size_t len)
{
    size_t i = len - 1;

    while (i > 0 && a[i] == 0) {
        i--;
    }

    return i * WORD_BIT_LENGTH + word_bit_len(a[i]);
}

void gf2m_mod_add(const WordArray *a, const WordArray *b, WordArray *out)
{
    /*comparsion signed/unsigned types*/
    size_t i;

    ASSERT(a != NULL);
    ASSERT(b != NULL);
    ASSERT(out != NULL);
    ASSERT(a->len == b->len);
    ASSERT(a->len == out->len);

    for (i = 0; i < a->len; out->buf[i] = a->buf[i] ^ b->buf[i], i++);
}

/**
 * Зводить многочлен за модулем твірного многочлена поля.
 *
 * @param ctx Параметри GF(2^m)
 * @param a многочлен довжиною 2 * ctx->len слів (руйнується)
 * @param out буфер для результату довжиною ctx->len слів
 */
static void gf2m_mod_raw(const Gf2mCtx *ctx, word_t *a, word_t *out)
{
    ASSERT(ctx != NULL);
    ASSERT(a != NULL);
    ASSERT(out != NULL);

    int alen = (int)(2 * ctx->len);
    int degA = (int)gf2m_bit_len(a, alen) - 1;
    int degF = ctx->f[0];
    int i;

    /* Слова, що містять x^f[0], x^f[1], x^f[2] тощо. */
    int a_woff0, a_woff1, a_woff2, a_woff3 = 0;

    /* Зсув у бітах від межі слова для x^f[0], x^f[1] тощо. */
    word_t a_boff0, a_boff1, a_boff2, a_boff3 = 0;

    ASSERT(degA <= (degF << 1) - 2);

    if (degA < degF) {
        memcpy(out, a, ctx->len * WORD_BYTE_LENGTH);
        return;
    }

    a_woff0 = alen - 1 - (ctx->f[0] >> WORD_BIT_LEN_SHIFT);
    a_woff1 = alen - 1 - (ctx->f[1] >> WORD_BIT_LEN_SHIFT);
    a_woff2 = alen - 1 - (ctx->f[2] >> WORD_BIT_LEN_SHIFT);
    a_boff0 = ctx->f[0] & WORD_BIT_LEN_MASK;
    a_boff1 = ctx->f[1] & WORD_BIT_LEN_MASK;
    a_boff2 = ctx->f[2] & WORD_BIT_LEN_MASK;
    if (ctx->f[2] != 0) {
        a_woff3 = alen - 1 - (ctx->f[3] >> WORD_BIT_LEN_SHIFT);
        a_boff3 = ctx->f[3] & WORD_BIT_LEN_MASK;
    }

    i = (degA - (degF - (int)a_boff0)) >> WORD_BIT_LEN_SHIFT;

    /* XOR-додавання неповного старшого слова "a" з послідовностями, що починаються з t-го біта, з k-го біта тощо. */
    if (a_woff0 == i) {
        word_t T = WORD_RSHIFT(a[alen - 1], a_boff0);
        int j;
        a[alen - 1] ^= WORD_LSHIFT(T, a_boff0);

        j = a_woff1 - i;
        a[alen - 1 - j] ^= WORD_LSHIFT(T, a_boff1);
        if (j != 0 && a_boff1 != 0) {
            a[alen - j] ^= WORD_RSHIFT(T, WORD_BIT_LENGTH - a_boff1);
        }

        j = a_woff2 - i;
        a[alen - 1 - j] ^= WORD_LSHIFT(T, a_boff2);
        if (j != 0 && a_boff2 != 0) {
            a[alen - j] ^= WORD_RSHIFT(T, WORD_BIT_LENGTH - a_boff2);
        }

        if (ctx->f[2] != 0) {
            j = a_woff3 - i;
            a[alen - 1 - j] ^= WORD_LSHIFT(T, a_boff3);
            if (j != 0 && a_boff3 != 0) {
                a[alen - j] ^= WORD_RSHIFT(T, WORD_BIT_LENGTH - a_boff3);
            }

            a[i] ^= T;
        }
        i--;
    }

    /* XOR-додавання повних слів, починаючи з m-го біта, з послідовностями, що починаються з t-го біта, з k-го біта тощо. */
    while (degA >= degF) {
        for (; i >= 0; i--) {
            word_t a_woff0i = a_woff0 - i;
            word_t a_woff1i = a_woff1 - i;
            word_t a_woff2i = a_woff2 - i;

            word_t T = WORD_RSHIFT(a[alen - 1 - a_woff0i], a_boff0) | (WORD_LSHIFT(a[alen - a_woff0i],
                    WORD_BIT_LENGTH - a_boff0));

            a[alen - 1 - a_woff0i] ^= WORD_LSHIFT(T, a_boff0);
            a[alen - a_woff0i] ^= WORD_RSHIFT(T, WORD_BIT_LENGTH - a_boff0);
            a[alen - 1 - a_woff1i] ^= WORD_LSHIFT(T, a_boff1);
            if (a_boff1 != 0) {
                a[alen - a_woff1i] ^= WORD_RSHIFT(T, WORD_BIT_LENGTH - a_boff1);
            }
            a[alen - 1 - a_woff2i] ^= WORD_LSHIFT(T, a_boff2);

            if (ctx->f[2] != 0) {
                int a_woff3i = a_woff3 - i;
                int a_woff4i = alen - 1 - i;
                if (a_boff2 != 0) {
                    a[alen - a_woff2i] ^= WORD_RSHIFT(T, WORD_BIT_LENGTH - a_boff2);
                }
                a[alen - 1 - a_woff3i] ^= WORD_LSHIFT(T, a_boff3);
                if (a_boff3 != 0) {
                    a[alen - a_woff3i] ^= WORD_RSHIFT(T, WORD_BIT_LENGTH - a_boff3);
                }
                a[alen - 1 - a_woff4i] ^= T;
            }
        }

        degA = (int)gf2m_bit_len(a, alen) - 1;
        i = (degA - (degF - (int)a_boff0)) >> WORD_BIT_LEN_SHIFT;
    }

    memcpy(out, a, ctx->len * WORD_BYTE_LENGTH);
}

void gf2m_mod(const Gf2mCtx *ctx, WordArray *a, WordArray *out)
{
    ASSERT(ctx != NULL);
    ASSERT(a != NULL);
    ASSERT(out != NULL);
    ASSERT(a->len == 2 * ctx->len);
    ASSERT(out->len == ctx->len);

    gf2m_mod_raw(ctx, a->buf, out->buf);
}

void gf2m_mod_sqr(const Gf2mCtx *ctx, const WordArray *a, WordArray *out)
{
    ASSERT(ctx != NULL);
    ASSERT(a != NULL);
    ASSERT(out != NULL);
    ASSERT(a->len == (unsigned int)ctx->len);
    ASSERT(out->len == (unsigned int)ctx->len);
    ASSERT(ctx->len <= GF2M_MAX_LEN);

    word_t sqr[2 * GF2M_MAX_LEN];
    const word_t *ab = a->buf;
    size_t i;

#if defined(GF2M_CLMUL)
    if (ctx->clmul) {
        word_t t[2 * GF2M_CLMUL_MAX_LEN + 2];

        gf2m_sqr_clmul(a->buf, (int)ctx->len, t);
        gf2m_mod_clmul(ctx, t, out->buf);
        return;
    }
#endif

    for (i = 0; i < ctx->len; i++) {
#if defined(ARCH64)
        sqr[2 * i + 1] = ((word_t)GF2M_SQR_PRECOMP[(ab[i] >> 56) & 0xff] << 48)
                | ((word_t)GF2M_SQR_PRECOMP[(ab[i] >> 48) & 0xff] << 32)
                | ((word_t)GF2M_SQR_PRECOMP[(ab[i] >> 40) & 0xff] << 16)
                |  (word_t)GF2M_SQR_PRECOMP[(ab[i] >> 32) & 0xff];
        sqr[2 * i] = ((word_t)GF2M_SQR_PRECOMP[(ab[i] >> 24) & 0xff] << 48)
                | ((word_t)GF2M_SQR_PRECOMP[(ab[i] >> 16) & 0xff] << 32)
                | ((word_t)GF2M_SQR_PRECOMP[(ab[i] >> 8) & 0xff] << 16)
                |  (word_t)GF2M_SQR_PRECOMP[ab[i] & 0xff];
# else
        sqr[2 * i + 1] = (GF2M_SQR_PRECOMP[ab[i] >> 24] << 16)
                | GF2M_SQR_PRECOMP[(ab[i] >> 16) & 0xff];
        sqr[2 * i] = (GF2M_SQR_PRECOMP[(ab[i] >> 8) & 0xff] << 16)
                | GF2M_SQR_PRECOMP[ab[i] & 0xff];
#endif
    }

    gf2m_mod_raw(ctx, sqr, out->buf);
}

#if defined(ARCH64)

#define WORD_LSHIFT_AND_XOR(_x, _y, _res, _i)    if ((_y) & ((word_t)1 << (_i))) { (_res)->hi ^= ((_x) >> (64 - (_i))); (_res)->lo ^= (_x) << (_i); }

void gf2m_mul_64_fast(const word_t x, const word_t y, Dword *res)
{
#if defined(GF2M_CLMUL)
    if (gf2m_use_clmul()) {
        gf2m_mul_64_clmul(x, y, res);
        return;
    }
#endif

    res->hi = 0;
    res->lo = 0;

    WORD_LSHIFT_AND_XOR(x, y, res, 63);
    WORD_LSHIFT_AND_XOR(x, y, res, 62);
    WORD_LSHIFT_AND_XOR(x, y, res, 61);
    WORD_LSHIFT_AND_XOR(x, y, res, 60);
    WORD_LSHIFT_AND_XOR(x, y, res, 59);
    WORD_LSHIFT_AND_XOR(x, y, res, 58);
    WORD_LSHIFT_AND_XOR(x, y, res, 57);
    WORD_LSHIFT_AND_XOR(x, y, res, 56);
    WORD_LSHIFT_AND_XOR(x, y, res, 55);
    WORD_LSHIFT_AND_XOR(x, y, res, 54);
    WORD_LSHIFT_AND_XOR(x, y, res, 53);
    WORD_LSHIFT_AND_XOR(x, y, res, 52);
    WORD_LSHIFT_AND_XOR(x, y, res, 51);
    WORD_LSHIFT_AND_XOR(x, y, res, 50);
    WORD_LSHIFT_AND_XOR(x, y, res, 49);
    WORD_LSHIFT_AND_XOR(x, y, res, 48);
    WORD_LSHIFT_AND_XOR(x, y, res, 47);
    WORD_LSHIFT_AND_XOR(x, y, res, 46);
    WORD_LSHIFT_AND_XOR(x, y, res, 45);
    WORD_LSHIFT_AND_XOR(x, y, res, 44);
    WORD_LSHIFT_AND_XOR(x, y, res, 43);
    WORD_LSHIFT_AND_XOR(x, y, res, 42);
    WORD_LSHIFT_AND_XOR(x, y, res, 41);
    WORD_LSHIFT_AND_XOR(x, y, res, 40);
    WORD_LSHIFT_AND_XOR(x, y, res, 39);
    WORD_LSHIFT_AND_XOR(x, y, res, 38);
    WORD_LSHIFT_AND_XOR(x, y, res, 37);
    WORD_LSHIFT_AND_XOR(x, y, res, 36);
    WORD_LSHIFT_AND_XOR(x, y, res, 35);
    WORD_LSHIFT_AND_XOR(x, y, res, 34);
    WORD_LSHIFT_AND_XOR(x, y, res, 33);
    WORD_LSHIFT_AND_XOR(x, y, res, 32);
    WORD_LSHIFT_AND_XOR(x, y, res, 31);
    WORD_LSHIFT_AND_XOR(x, y, res, 30);
    WORD_LSHIFT_AND_XOR(x, y, res, 29);
    WORD_LSHIFT_AND_XOR(x, y, res, 28);
    WORD_LSHIFT_AND_XOR(x, y, res, 27);
    WORD_LSHIFT_AND_XOR(x, y, res, 26);
    WORD_LSHIFT_AND_XOR(x, y, res, 25);
    WORD_LSHIFT_AND_XOR(x, y, res, 24);
    WORD_LSHIFT_AND_XOR(x, y, res, 23);
    WORD_LSHIFT_AND_XOR(x, y, res, 22);
    WORD_LSHIFT_AND_XOR(x, y, res, 21);
    WORD_LSHIFT_AND_XOR(x, y, res, 20);
    WORD_LSHIFT_AND_XOR(x, y, res, 19);
    WORD_LSHIFT_AND_XOR(x, y, res, 18);
    WORD_LSHIFT_AND_XOR(x, y, res, 17);
    WORD_LSHIFT_AND_XOR(x, y, res, 16);
    WORD_LSHIFT_AND_XOR(x, y, res, 15);
    WORD_LSHIFT_AND_XOR(x, y, res, 14);
    WORD_LSHIFT_AND_XOR(x, y, res, 13);
    WORD_LSHIFT_AND_XOR(x, y, res, 12);
    WORD_LSHIFT_AND_XOR(x, y, res, 11);
    WORD_LSHIFT_AND_XOR(x, y, res, 10);
    WORD_LSHIFT_AND_XOR(x, y, res, 9);
    WORD_LSHIFT_AND_XOR(x, y, res, 8);
    WORD_LSHIFT_AND_XOR(x, y, res, 7);
    WORD_LSHIFT_AND_XOR(x, y, res, 6);
    WORD_LSHIFT_AND_XOR(x, y, res, 5);
    WORD_LSHIFT_AND_XOR(x, y, res, 4);
    WORD_LSHIFT_AND_XOR(x, y, res, 3);
    WORD_LSHIFT_AND_XOR(x, y, res, 2);
    WORD_LSHIFT_AND_XOR(x, y, res, 1);
    if (y & 1) {
        res->lo ^= x;
    }
}

#else

static uint64_t gf2m_mul_32(word_t x, word_t y)
{
    uint64_t res;
    int32_t s = (int32_t)y;

    res  = ((((uint64_t)(s      ) >> 32) & 0xffffffff) & x) << 31;
    res ^= ((((uint64_t)(s << 1 ) >> 32) & 0xffffffff) & x) << 30;
    res ^= ((((uint64_t)(s << 2 ) >> 32) & 0xffffffff) & x) << 29;
    res ^= ((((uint64_t)(s << 3 ) >> 32) & 0xffffffff) & x) << 28;
    res ^= ((((uint64_t)(s << 4 ) >> 32) & 0xffffffff) & x) << 27;
    res ^= ((((uint64_t)(s << 5 ) >> 32) & 0xffffffff) & x) << 26;
    res ^= ((((uint64_t)(s << 6 ) >> 32) & 0xffffffff) & x) << 25;
    res ^= ((((uint64_t)(s << 7 ) >> 32) & 0xffffffff) & x) << 24;
    res ^= ((((uint64_t)(s << 8 ) >> 32) & 0xffffffff) & x) << 23;
    res ^= ((((uint64_t)(s << 9 ) >> 32) & 0xffffffff) & x) << 22;
    res ^= ((((uint64_t)(s << 10) >> 32) & 0xffffffff) & x) << 21;
    res ^= ((((uint64_t)(s << 11) >> 32) & 0xffffffff) & x) << 20;
    res ^= ((((uint64_t)(s << 12) >> 32) & 0xffffffff) & x) << 19;
    res ^= ((((uint64_t)(s << 13) >> 32) & 0xffffffff) & x) << 18;
    res ^= ((((uint64_t)(s << 14) >> 32) & 0xffffffff) & x) << 17;
    res ^= ((((uint64_t)(s << 15) >> 32) & 0xffffffff) & x) << 16;
    res ^= ((((uint64_t)(s << 16) >> 32) & 0xffffffff) & x) << 15;
    res ^= ((((uint64_t)(s << 17) >> 32) & 0xffffffff) & x) << 14;
    res ^= ((((uint64_t)(s << 18) >> 32) & 0xffffffff) & x) << 13;
    res ^= ((((uint64_t)(s << 19) >> 32) & 0xffffffff) & x) << 12;
    res ^= ((((uint64_t)(s << 20) >> 32) & 0xffffffff) & x) << 11;
    res ^= ((((uint64_t)(s << 21) >> 32) & 0xffffffff) & x) << 10;
    res ^= ((((uint64_t)(s << 22) >> 32) & 0xffffffff) & x) <<  9;
    res ^= ((((uint64_t)(s << 23) >> 32) & 0xffffffff) & x) <<  8;
    res ^= ((((uint64_t)(s << 24) >> 32) & 0xffffffff) & x) <<  7;
    res ^= ((((uint64_t)(s << 25) >> 32) & 0xffffffff) & x) <<  6;
    res ^= ((((uint64_t)(s << 26) >> 32) & 0xffffffff) & x) <<  5;
    res ^= ((((uint64_t)(s << 27) >> 32) & 0xffffffff) & x) <<  4;
    res ^= ((((uint64_t)(s << 28) >> 32) & 0xffffffff) & x) <<  3;
    res ^= ((((uint64_t)(s << 29) >> 32) & 0xffffffff) & x) <<  2;
    res ^= ((((uint64_t)(s << 30) >> 32) & 0xffffffff) & x) <<  1;
    res ^= ((((uint64_t)(s << 31) >> 32) & 0xffffffff) & x);

    return (uint64_t)res;
}
#endif

/**
 * Виконує множення многочленів, степінь яких менший за 256. Використовується метод Карацуби.
 *
 * @param x многочлен 1
 * @param y многочлен 2
 * @param len довжина многочленів у словах
 * @param mode вказує на зміни в многочлені r
 * @param r буфер для добутку многочленів
 */
static void gf2m_mul_256(const word_t *x, const word_t *y, int len, bool mode, word_t *r)
{
#if defined(ARCH64)
    word_t x0, x1, x2, x3;
    word_t y0, y1, y2, y3;
    word_t x00, x01, x10, x11, x20, x21, x30, x31;
    word_t y00, y01, y10, y11;
    word_t a00, a01, a10, a11;
    word_t d0, d1;
    word_t e00, e10, e20, e30, e31, e32, c;

    int indx = mode ? len : len - 4;
    word_t mul256[8];
    Dword res = {0, 0};

    if (mode && indx >= 4) {
        x0 = x[indx - 4];
        x1 = x[indx - 3];
        x2 = x[indx - 2];
        x3 = x[indx - 1];
        y0 = y[indx - 4];
        y1 = y[indx - 3];
        y2 = y[indx - 2];
        y3 = y[indx - 1];
    } else {
        memset(mul256, 0, 4 * sizeof(word_t));
        memcpy(mul256 + 4 - indx, x, indx * sizeof(word_t));
        x0 = mul256[0];
        x1 = mul256[1];
        x2 = mul256[2];
        x3 = mul256[3];

        memset(mul256, 0, 4 * sizeof(word_t));
        memcpy(mul256 + 4 - indx, y, indx * sizeof(word_t));
        y0 = mul256[0];
        y1 = mul256[1];
        y2 = mul256[2];
        y3 = mul256[3];
    }

    gf2m_mul_64_fast(x0, y0, &res);
    x00 = res.hi, x01 = res.lo;
    gf2m_mul_64_fast(x1, y1, &res);
    x10 = res.hi, x11 = res.lo;
    gf2m_mul_64_fast(x2, y2, &res);
    x20 = res.hi, x21 = res.lo;
    gf2m_mul_64_fast(x3, y3, &res);
    x30 = res.hi, x31 = res.lo;
    gf2m_mul_64_fast(x0 ^ x1, y0 ^ y1, &res);
    y00 = res.hi, y01 = res.lo;
    gf2m_mul_64_fast(x2 ^ x3, y2 ^ y3, &res);
    y10 = res.hi, y11 = res.lo;
    gf2m_mul_64_fast(x0 ^ x2, y0 ^ y2, &res);
    a00 = res.hi, a01 = res.lo;
    gf2m_mul_64_fast(x1 ^ x3, y1 ^ y3, &res);
    a10 = res.hi, a11 = res.lo;

    gf2m_mul_64_fast(x0 ^ x1 ^ x2 ^ x3, y0 ^ y1 ^ y2 ^ y3, &res);
    d0 = res.hi, d1 = res.lo;

    e32 = x31  ^ x21 ^ x30;
    e31 = e32 ^ x11 ^ x20;
    e30 = e31 ^ x01 ^ x10;
    e20 = e30 ^ x31 ^ x00;
    e10 = e20 ^ x21 ^ x30;
    e00 = e10 ^ x11 ^ x20;
    c = a01 ^ a10;

    mul256[7] = x31;
    mul256[6] = y11 ^ e32;
    mul256[5] = a11 ^ e31 ^ y10;
    mul256[4] = d1  ^ a11  ^ y01 ^ y11 ^ e30 ^ c;
    mul256[3] = d0  ^ a00  ^ y00 ^ y10 ^ e20 ^ c;
    mul256[2] = y01 ^ e10 ^ a00;
    mul256[1] = y00 ^ e00;
    mul256[0] = x00;

    if (!mode) {
        int i, j;

        memcpy(r, mul256 + 2 * (4 - indx), (2 * indx - 4) * sizeof(word_t));

        for (i = (2 * indx) - 4, j = 4;   j < 8; r[i++] ^= mul256[j++]);
        for (i = 4, j = 2 * (4 - indx); j < 8; r[i++] ^= mul256[j++]);

        return;
    }

    if (indx >= 4) {
        memcpy(r + 2 * (indx - 4), mul256, 8 * sizeof(word_t));
    } else {
        memcpy(r, mul256 + 2 * (4 - indx), 2 * indx * sizeof(word_t));
    }

#else

    word_t x0, x1, x2, x3, x4, x5, x6, x7;
    word_t y0, y1, y2, y3, y4, y5, y6, y7;

    word_t x00, x01, x10, x11, x20, x21, x30, x31, x40, x41, x50, x51, x60, x61, x70, x71;
    word_t y00, y01, y10, y11, y20, y21, y30, y31;
    word_t a00, a01, a10, a11, a20, a21, a30, a31;
    word_t b00, b01, d10, d11, d20, d21, d30, d31;
    word_t c0, c1, c2, c3, c4, c5, c6, c7;
    word_t d0, d1, d2, d3, d4, d5;
    word_t e0, e1, e2, e3, e4, e5, e6, e7;
    word_t f0, f1, f2, f3;
    word_t g0, g1, g2, g3, g4, g5, g6, g7;
    word_t h0, h1, h2, h3, h4, h5, h6, h8, h9, h10, h11, h12, h13, h14;
    word_t k0, k1, k2, k3, k4, k5, k6, k7;
    word_t m0, m1, m2, m3, m4, m5, m6, m7;
    word_t n0, n1, n2, n3;

    int indx = mode ? len : len - 8;
    word_t mul256[16];
    uint64_t res;

    if (mode && indx >= 8) {
        x0 = x[indx - 8];
        x1 = x[indx - 7];
        x2 = x[indx - 6];
        x3 = x[indx - 5];
        x4 = x[indx - 4];
        x5 = x[indx - 3];
        x6 = x[indx - 2];
        x7 = x[indx - 1];
        y0 = y[indx - 8];
        y1 = y[indx - 7];
        y2 = y[indx - 6];
        y3 = y[indx - 5];
        y4 = y[indx - 4];
        y5 = y[indx - 3];
        y6 = y[indx - 2];
        y7 = y[indx - 1];
    } else {
        memset(mul256, 0, 8 * sizeof(word_t));
        memcpy(mul256 + 8 - indx, x, indx * sizeof(word_t));
        x0 = mul256[0];
        x1 = mul256[1];
        x2 = mul256[2];
        x3 = mul256[3];
        x4 = mul256[4];
        x5 = mul256[5];
        x6 = mul256[6];
        x7 = mul256[7];

        memset(mul256, 0, 8 * sizeof(word_t));
        memcpy(mul256 + 8 - indx, y, indx * sizeof(word_t));
        y0 = mul256[0];
        y1 = mul256[1];
        y2 = mul256[2];
        y3 = mul256[3];
        y4 = mul256[4];
        y5 = mul256[5];
        y6 = mul256[6];
        y7 = mul256[7];
    }

    res = gf2m_mul_32(x0, y0);
    x00 = (word_t)(res >> 32), x01 = (word_t)res;
    res = gf2m_mul_32(x1, y1);
    x10 = (word_t)(res >> 32), x11 = (word_t)res;
    res = gf2m_mul_32(x2, y2);
    x20 = (word_t)(res >> 32), x21 = (word_t)res;
    res = gf2m_mul_32(x3, y3);
    x30 = (word_t)(res >> 32), x31 = (word_t)res;
    res = gf2m_mul_32(x4, y4);
    x40 = (word_t)(res >> 32), x41 = (word_t)res;
    res = gf2m_mul_32(x5, y5);
    x50 = (word_t)(res >> 32), x51 = (word_t)res;
    res = gf2m_mul_32(x6, y6);
    x60 = (word_t)(res >> 32), x61 = (word_t)res;
    res = gf2m_mul_32(x7, y7);
    x70 = (word_t)(res >> 32), x71 = (word_t)res;

    e0 = x0 ^ x1, e1 = x2 ^ x3, e2 = x4 ^ x5, e3 = x6 ^ x7;
    e4 = x0 ^ x2, e5 = x1 ^ x3, e6 = x4 ^ x6, e7 = x5 ^ x7;
    g0 = y0 ^ y1, g1 = y2 ^ y3, g2 = y4 ^ y5, g3 = y6 ^ y7;
    g4 = y0 ^ y2, g5 = y1 ^ y3, g6 = y4 ^ y6, g7 = y5 ^ y7;
    f0 = e0 ^ e1, f1 = e2 ^ e3;
    f2 = g0 ^ g1, f3 = g2 ^ g3;

    res = gf2m_mul_32(e0, g0);
    y00 = (word_t)(res >> 32), y01 = (word_t)res;
    res = gf2m_mul_32(e1, g1);
    y10 = (word_t)(res >> 32), y11 = (word_t)res;
    res = gf2m_mul_32(e2, g2);
    y20 = (word_t)(res >> 32), y21 = (word_t)res;
    res = gf2m_mul_32(e3, g3);
    y30 = (word_t)(res >> 32), y31 = (word_t)res;

    res = gf2m_mul_32(e4, g4);
    a00 = (word_t)(res >> 32), a01 = (word_t)res;
    res = gf2m_mul_32(e5, g5);
    a10 = (word_t)(res >> 32), a11 = (word_t)res;
    res = gf2m_mul_32(e6, g6);
    a20 = (word_t)(res >> 32), a21 = (word_t)res;
    res = gf2m_mul_32(e7, g7);
    a30 = (word_t)(res >> 32), a31 = (word_t)res;

    res = gf2m_mul_32(x0 ^ x4, y0 ^ y4);
    b00 = (word_t)(res >> 32), b01 = (word_t)res;
    res = gf2m_mul_32(x1 ^ x5, y1 ^ y5);
    d10 = (word_t)(res >> 32), d11 = (word_t)res;
    res = gf2m_mul_32(x2 ^ x6, y2 ^ y6);
    d20 = (word_t)(res >> 32), d21 = (word_t)res;
    res = gf2m_mul_32(x3 ^ x7, y3 ^ y7);
    d30 = (word_t)(res >> 32), d31 = (word_t)res;

    res = gf2m_mul_32(f0, f2);
    c0 = (word_t)(res >> 32), c1 = (word_t)res;
    res = gf2m_mul_32(f1, f3);
    c2 = (word_t)(res >> 32), c3 = (word_t)res;
    res = gf2m_mul_32(e0 ^ e2, g0 ^ g2);
    c4 = (word_t)(res >> 32), c5 = (word_t)res;
    res = gf2m_mul_32(e1 ^ e3, g1 ^ g3);
    c6 = (word_t)(res >> 32), c7 = (word_t)res;
    res = gf2m_mul_32(e4 ^ e6, g4 ^ g6);
    d0 = (word_t)(res >> 32), d1 = (word_t)res;
    res = gf2m_mul_32(e5 ^ e7, g5 ^ g7);
    d2 = (word_t)(res >> 32), d3 = (word_t)res;

    res = gf2m_mul_32(f0 ^ f1, f2 ^ f3);
    d4 = (word_t)(res >> 32), d5 = (word_t)res;

    h8 = x71 ^ x61 ^ x70;
    h9 = h8 ^ x51 ^ x60, h10 = h9 ^ x41 ^ x50, h11 = h10 ^ x31 ^ x40;
    h12 = h11 ^ x21 ^ x30, h13 = h12 ^ x11 ^ x20, h14 = h13 ^ x01 ^ x10;

    h0 = x01 ^ x00 ^ x10;
    h1 = h0 ^ x11 ^ x20, h2 = h1 ^ x21 ^ x30, h3 = h2 ^ x31 ^ x40;
    h4 = h3 ^ x41 ^ x50, h5 = h4 ^ x51 ^ x60, h6 = h5 ^ x61 ^ x70;

    k0 = a01 ^ a11, k1 = a00 ^ a10, k2 = a31 ^ a21, k3 = a20 ^ a30;
    k4 = y01 ^ y11, k5 = y00 ^ y10, k6 = y31 ^ y21, k7 = y30 ^ y20;
    m0 = b01 ^ d11, m1 = b00 ^ d10, m2 = d31 ^ d21, m3 = d30 ^ d20;

    m4 = c7 ^ k6, m5 = c6 ^ k7;
    m6 = c5 ^ k4, m7 = c4 ^ k5;

    n0 = d1 ^ m0 ^ a21 ^ a01, n1 = d0 ^ m1 ^ a20 ^ a00;
    n2 = d3 ^ m2 ^ a31 ^ a11, n3 = d2 ^ m3 ^ a30 ^ a10;

    mul256[15] = x71;
    mul256[14] = y31 ^ h8;
    mul256[13] = a31 ^ h9 ^ y30;
    mul256[12] = c3 ^ k2 ^ k6 ^ h10 ^ a30;
    mul256[11] = d31 ^ a21 ^ h11 ^ c2 ^ k3 ^ k7;
    mul256[10] = m4 ^ m2 ^ y11 ^ h12 ^ d30 ^ a20;
    mul256[9]  = n2 ^ d11 ^ h13 ^ m5 ^ m3 ^ y10;
    mul256[8]  = d5 ^ n0 ^ n2 ^ m6 ^ m4 ^ c1 ^ c3 ^ h14 ^ n3 ^ d10;
    mul256[7]  = n0 ^ d21 ^ h6 ^ d4 ^ n1 ^ n3 ^ m7 ^ m5 ^ c0 ^ c2;
    mul256[6]  = m6 ^ m0 ^ y21 ^ h5 ^ n1 ^ d20;
    mul256[5]  = b01 ^ a11 ^ h4 ^ m7 ^ m1 ^ y20;
    mul256[4]  = c1 ^ k0 ^ k4 ^ h3 ^ b00 ^ a10;
    mul256[3]  = a01 ^ h2 ^ c0 ^ k5 ^ k1;
    mul256[2]  = y01 ^ h1 ^ a00;
    mul256[1]  = h0 ^ y00;
    mul256[0]  = x00;

    if (!mode) {
        int i, j;

        memcpy(r, mul256 + 2 * (8 - indx), (2 * indx - 8) * sizeof(word_t));

        for (i = (2 * indx) - 8, j = 8; j < 16; r[i++] ^= mul256[j++]);
        for (i = 8, j = 2 * (8 - indx); j < 16; r[i++] ^= mul256[j++]);

        return;
    }

    if (indx >= 8) {
        memcpy(r + 2 * (indx - 8), mul256, 16 * sizeof(word_t));
    } else {
        memcpy(r, mul256 + 2 * (8 - indx), 2 * indx * sizeof(word_t));
    }

#endif
}

/**
 * Змінює порядок слів на зворотний.
 *
 * @param x масив слів
 * @param len довжина в словах
 * @param y буфер для результату
 */
static void words_swap(const word_t *x, size_t len, word_t *y)
{
    size_t i;

    for (i = 0; i < len; i++) {
        y[i] = x[len - 1 - i];
    }
}

/**
* Виконує множення многочленів, степінь яких більший за 32 і менший за 64.
*
* @param x многочлен 1
* @param y многочлен 2
* @param r буфер для добутку многочленів
*/
static void gf2m_mul_64(const word_t *x, const word_t *y, word_t *r)
{
#if defined(ARCH32)
    uint64_t res = gf2m_mul_32(x[0], y[0]);
    word_t a00, a11, b00, b11;
    word_t c;

    a00 = (word_t)(res >> 32), c = (word_t)res;

    res = gf2m_mul_32(x[1], y[1]);
    a11 = (word_t)res;
    c ^= (word_t)(res >> 32);

    res = gf2m_mul_32(x[0] ^ x[1], y[0] ^ y[1]);
    b00 = (word_t)(res >> 32), b11 = (word_t)res;

    r[3] = a11;
    r[2] = b11 ^ a11 ^ c;
    r[1] = b00 ^ a00 ^ c;
    r[0] = a00;

#elif defined(ARCH64)
    Dword res;
    gf2m_mul_64_fast(x[0], y[0], &res);
    r[0] = res.hi;
    r[1] = res.lo;
#endif
}

/**
* Виконує множення многочленів, степінь яких більший за 64 і менший за 128.
*
* @param x многочлен 1
* @param y многочлен 2
* @param len довжина многочленів у словах
* @param z буфер для добутку многочленів
*/
static void gf2m_mul_128(const word_t *x, const word_t *y, int len, word_t *z)
{
#if defined(ARCH32)

    word_t a0, a1, a2, a3;
    word_t b0, b1, b2, b3;
    word_t d0, d1;
    word_t a00, a01, a10, a11, a20, a21, a30, a31;
    word_t b00, b01, b10, b11;
    word_t c00, c01, c10, c11;
    word_t t0, t1, t2, t3, t4, t5, c;
    uint64_t res;

    if (len < 12) {
        a0 = 0;
        a1 = x[0];
        a2 = x[1];
        a3 = x[2];
        b0 = 0;
        b1 = y[0];
        b2 = y[1];
        b3 = y[2];
    } else {
        a0 = x[0];
        a1 = x[1];
        a2 = x[2];
        a3 = x[3];
        b0 = y[0];
        b1 = y[1];
        b2 = y[2];
        b3 = y[3];
    }

    res = gf2m_mul_32(a0, b0);
    a00 = (word_t)(res >> 32), a01 = (word_t)res;
    res = gf2m_mul_32(a1, b1);
    a10 = (word_t)(res >> 32), a11 = (word_t)res;
    res = gf2m_mul_32(a2, b2);
    a20 = (word_t)(res >> 32), a21 = (word_t)res;
    res = gf2m_mul_32(a3, b3);
    a30 = (word_t)(res >> 32), a31 = (word_t)res;

    res = gf2m_mul_32(a0 ^ a1, b0 ^ b1);
    b00 = (word_t)(res >> 32), b01 = (word_t)res;
    res = gf2m_mul_32(a2 ^ a3, b2 ^ b3);
    b10 = (word_t)(res >> 32), b11 = (word_t)res;

    res = gf2m_mul_32(a0 ^ a2, b0 ^ b2);
    c00 = (word_t)(res >> 32), c01 = (word_t)res;
    res = gf2m_mul_32(a1 ^ a3, b1 ^ b3);
    c10 = (word_t)(res >> 32), c11 = (word_t)res;

    res = gf2m_mul_32(a0 ^ a1 ^ a2 ^ a3, b0 ^ b1 ^ b2 ^ b3);
    d0 = (word_t)(res >> 32), d1 = (word_t)res;

    t0 = a31  ^ a21 ^ a30;
    t1 = t0 ^ a11 ^ a20;
    t2 = t1 ^ a01 ^ a10;
    t3 = t2 ^ a31 ^ a00;
    t4 = t3 ^ a21 ^ a30;
    t5 = t4 ^ a11 ^ a20;
    c = c01 ^ c10;

    z[7] = a31;
    z[6] = b11 ^ t0;
    z[5] = c11 ^ t1 ^ b10;
    z[4] = d1  ^ c11  ^ b01 ^ b11 ^ t2 ^ c;
    z[3] = d0  ^ c00  ^ b00 ^ b10 ^ t3 ^ c;
    z[2] = b01 ^ t4 ^ c00;
    z[1] = b00 ^ t5;
    z[0] = a00;

#elif defined(ARCH64)
    Dword res;
    word_t a00, a11, b00, b11, c;
    (void)len;

    gf2m_mul_64_fast(x[0], y[0], &res);
    a00 = res.hi;
    c = res.lo;

    gf2m_mul_64_fast(x[1], y[1], &res);
    a11 = res.lo;
    c ^= res.hi;

    gf2m_mul_64_fast(x[0] ^ x[1], y[0] ^ y[1], &res);
    b00 = res.hi;
    b11 = res.lo;

    z[3] = a11;
    z[2] = b11 ^ a11 ^ c;
    z[1] = b00 ^ a00 ^ c;
    z[0] = a00;
#endif
}

/**
 * Виконує множення многочленів (без зведення за модулем).
 *
 * @param ctx Параметри GF(2^m)
 * @param x1 многочлен 1 довжиною ctx->len слів
 * @param y1 многочлен 2 довжиною ctx->len слів
 * @param r1 буфер для добутку довжиною 2 * ctx->len слів
 */
static void gf2m_mul_raw(const Gf2mCtx *ctx, const word_t *x1, const word_t *y1, word_t *r1)
{
    word_t x[GF2M_MAX_LEN];
    word_t y[GF2M_MAX_LEN];
    word_t r[2 * GF2M_MAX_LEN];
    word_t xPoly[32];
    word_t yPoly[32];
    word_t dtPoly[16 * 4];
    int n;
    int s;
    int i, j;

    ASSERT(ctx != NULL);
    ASSERT(x1 != NULL);
    ASSERT(y1 != NULL);
    ASSERT(r1 != NULL);
    ASSERT(ctx->len <= GF2M_MAX_LEN);

    n = (int)ctx->len;

    if (n > WA_LEN(64)) {
        int y_len = (int)gf2m_bit_len(y1, n);

        memset(r1, 0, 2 * n * sizeof(word_t));
        memcpy(r, x1, n * sizeof(word_t));
        memset(r + n, 0, n * sizeof(word_t));

        for (i = 0; i < y_len; i++) {
            if (i != 0) {
                for (j = 2 * n - 1; j > 0; j--) {
                    r[j] = (r[j] << 1) | (r[j - 1] >> (WORD_BIT_LENGTH - 1));
                }
                r[0] <<= 1;
            }
            if ((y1[i >> WORD_BIT_LEN_SHIFT] >> (i & WORD_BIT_LEN_MASK)) & 1) {
                for (j = 0; j < 2 * n; j++) {
                    r1[j] ^= r[j];
                }
            }
        }

        return;
    }

    memset(r, 0, 2 * n * sizeof(word_t));

    /* XXX */
    words_swap(x1, n, x);
    words_swap(y1, n, y);

    /* Степінь многочлена, що породжує поліноміальний базис, менший за 257. */
    if (n <= WA_LEN(32)) {
        gf2m_mul_256(x, y, n, true, r);
        words_swap(r, 2 * n, r1);

        return;
    }

    /* Степінь многочлена, що породжує поліноміальний базис, дорівнює 257. */
    if (ctx->f[0] == 257) {

        r[0] = 0;
        r[1] = (x[0] == 1 && y[0] == 1 ? 1 : 0);

        gf2m_mul_256(x, y, n, true, r);

        if (x[0] == 1) {
            for (i = 1; i < WA_LEN(36); i++) {
                r[i + 1] ^= y[i];
            }
        }

        if (y[0] == 1)
            for (i = 1; i < WA_LEN(36); i++) {
                r[i + 1] ^= x[i];
            }

        /* XXX */
        words_swap(r, 2 * n, r1);

        return;
    }

    /*
     * Степінь многочлена більший за 257. Многочлени x і y подаються у вигляді:
     * x(t) = x0(t) * t^256 + x1(t),
     * y(t) = y0(t) * t^256 + y1(t)
     */
    s = (2 * n > WA_LEN(96)) ? (2 * n - WA_LEN(96)) : 0;

    gf2m_mul_256(x, y, n, true, r);
    memcpy(&r[s], r + WA_LEN(32) + s, (2 * n - WA_LEN(64) - s) * sizeof(word_t));
    for (i = 2 * n - WA_LEN(64), j = 2 * n - WA_LEN(32); j < 2 * n; r[i++] ^= r[j++]);

    memcpy(&xPoly[0], x + n - WA_LEN(32), WA_LEN(32) * sizeof(word_t));
    for (i = WA_LEN(64) - n, j = 0; i < WA_LEN(32); xPoly[i++] ^= x[j++]);

    memcpy(&yPoly[0], y + n - WA_LEN(32), WA_LEN(32) * sizeof(word_t));
    for (i = WA_LEN(64) - n, j = 0; i < WA_LEN(32); yPoly[i++] ^= y[j++]);

    gf2m_mul_256(xPoly, yPoly, WA_LEN(32), true, dtPoly);
    for (i = s, j = WA_LEN(96) - 2 * n + s; j < WA_LEN(64); r[i++] ^= dtPoly[j++]);

#if defined(ARCH32)
    if (n == WA_LEN(36)) {
        uint64_t res = gf2m_mul_32(x[0], y[0]);

        word_t t = (word_t)(res >> WORD_BIT_LENGTH);
        r[0] ^= t;
        r[WA_LEN(32)] ^= t;

        t = (word_t)res;
        r[1] ^= t;
        r[WA_LEN(36)] ^= t;
    } else if (n <= WA_LEN(40)) {
        gf2m_mul_64(x, y, dtPoly);
        for (i = 0; i < WA_LEN(16); i++) {
            r[i] ^= dtPoly[i];
            r[i + WA_LEN(32)] ^= dtPoly[i];
        }
    } else if (n <= WA_LEN(48)) {
        gf2m_mul_128(x, y, n, dtPoly);
        for (j = (WA_LEN(48) - n) * 2, i = WA_LEN(32) - 1 - j; i >= 0 ; i--) {
            r[i] ^= dtPoly[i + j];
            r[i + WA_LEN(32)] ^= dtPoly[i + j];
        }
    } else {
        gf2m_mul_256(x, y, n, false, r);
    }

#elif defined(ARCH64)
    if (n <= WA_LEN(40)) {
        gf2m_mul_64(x, y, dtPoly);
        for (i = 0; i < WA_LEN(16); i++) {
            r[i] ^= dtPoly[i];
            r[i + WA_LEN(32)] ^= dtPoly[i];
        }
    } else if (n <= WA_LEN(48)) {
        gf2m_mul_128(x, y, n, dtPoly);
        for (j = (WA_LEN(48) - n) * 2, i = WA_LEN(32) - 1 - j; i >= 0 ; i--) {
            r[i] ^= dtPoly[i + j];
            r[i + WA_LEN(32)] ^= dtPoly[i + j];
        }
    } else {
        gf2m_mul_256(x, y, n, false, r);
    }

#else

    gf2m_mul_256(x, y, n, false, r);

#endif
    words_swap(r, 2 * n, r1);
}

void gf2m_mod_mul(const Gf2mCtx *ctx, const WordArray *a, const WordArray *b, WordArray *out)
{
    ASSERT(ctx != NULL);
    ASSERT(a != NULL);
    ASSERT(b != NULL);
    ASSERT(out != NULL);
    ASSERT(a->len == ctx->len);
    ASSERT(b->len == ctx->len);
    ASSERT(out->len == ctx->len);
    ASSERT(ctx->len <= GF2M_MAX_LEN);

    word_t out2[2 * GF2M_MAX_LEN];

#if defined(GF2M_CLMUL)
    if (ctx->clmul) {
        word_t t[2 * GF2M_CLMUL_MAX_LEN + 2];

        gf2m_mul_clmul(a->buf, b->buf, (int)ctx->len, t);
        gf2m_mod_clmul(ctx, t, out->buf);
        return;
    }
#endif

    gf2m_mul_raw(ctx, a->buf, b->buf, out2);
    gf2m_mod_raw(ctx, out2, out->buf);
}

void gf2m_mod_inv(const Gf2mCtx *ctx, const WordArray *a, WordArray *out)
{
    ASSERT(!int_is_zero(a));

    if (int_is_one(a)) {
        wa_copy(a, out);
        return;
    }

    gf2m_mod_gcd(a, ctx->f_ext, NULL, out, NULL);
}

void gf2m_mod_gcd(const WordArray *a, const WordArray *b, WordArray *gcd, WordArray *ka, WordArray *kb)
{
    ASSERT(a != NULL && b != NULL && a->len == b->len);

    size_t n = a->len;
    word_t t1_buf[GF2M_MAX_LEN];
    word_t t2_buf[GF2M_MAX_LEN];
    word_t t3_buf[GF2M_MAX_LEN];
    word_t t4_buf[GF2M_MAX_LEN];
    word_t dt_buf[GF2M_MAX_LEN];
    WordArray t1_wa = { t1_buf, n };
    WordArray t2_wa = { t2_buf, n };
    WordArray t3_wa = { t3_buf, n };
    WordArray t4_wa = { t4_buf, n };
    WordArray dt_wa = { dt_buf, n };
    WordArray *t1 = &t1_wa;
    WordArray *t2 = &t2_wa;
    WordArray *t3 = &t3_wa;
    WordArray *t4 = &t4_wa;
    WordArray *dt = &dt_wa;
    WordArray *buf;
    int t1_blen;

    ASSERT(n <= GF2M_MAX_LEN);

    memcpy(t1_buf, a->buf, n * WORD_BYTE_LENGTH);
    memcpy(t2_buf, b->buf, n * WORD_BYTE_LENGTH);
    wa_one(t3);
    wa_zero(t4);

    while ((t1_blen = (int)int_bit_len(t1)) > 1) {
        int i = t1_blen - (int)int_bit_len(t2);
        if (i < 0) {
            buf = t1;
            t1 = t2;
            t2 = buf;
            buf = t3;
            t3 = t4;
            t4 = buf;
            i = -i;
        }

        int_lshift(t2, i, dt);
        gf2m_mod_add(t1, dt, t1);
        int_lshift(t4, i, dt);
        gf2m_mod_add(t3, dt, t3);
    }

    if (gcd != NULL) {
        wa_copy(t1, gcd);
    }

    if (ka != NULL) {
        wa_copy(t3, ka);
    }

    if (kb != NULL) {
        wa_copy(t4, kb);
    }
}

int gf2m_mod_trace(const Gf2mCtx *ctx, const WordArray *a)
{
    WordArray *tr = NULL;
    int ret = RET_OK;
    int i;

    CHECK_NOT_NULL(tr = wa_copy_with_alloc(a));

    for (i = 0; i < ctx->f[0] - 1; i++) {
        gf2m_mod_sqr(ctx, tr, tr);
        gf2m_mod_add(a, tr, tr);
    }

    ret = tr->buf[0] ? 1 : 0;

    wa_free(tr);
cleanup:
    return ret;
}

/**
 * Обчислює напівслід елемента поля GF(2^m).
 *
 * @param ctx параметри GF(2^m)
 * @param a елемент поля
 * @param htrace напівслід розміром n
 */
static void gf2m_mod_htrace(const Gf2mCtx *ctx, const WordArray *a, WordArray *htrace)
{
    int i;
    WordArray *ht = NULL;
    int ret = RET_OK;

    CHECK_NOT_NULL(ht = wa_copy_with_alloc(a));
    for (i = (ctx->f[0] - 1) / 2 - 1; i >= 0 ; i--) {
        gf2m_mod_sqr(ctx, ht, ht);
        gf2m_mod_sqr(ctx, ht, ht);
        gf2m_mod_add(a, ht, ht);
    }

    wa_copy(ht, htrace);

cleanup:

    wa_free(ht);
}

bool gf2m_mod_solve_quad(const Gf2mCtx *ctx, const WordArray *a, WordArray *out)
{
    if (gf2m_mod_trace(ctx, a) != 0) {
        return false;
    }

    gf2m_mod_htrace(ctx, a, out);

    return true;
}

void gf2m_mod_sqrt(const Gf2mCtx *ctx, const WordArray *a, WordArray *out)
{
    int i;
    int stop;

    wa_copy(a, out);

    for (i = 0, stop = ctx->f[0] - 1; i < stop; i++) {
        gf2m_mod_sqr(ctx, out, out);
    }
}

Gf2mCtx *gf2m_copy_with_alloc(const Gf2mCtx *ctx)
{
    Gf2mCtx *ctx_copy = NULL;
    int len, ret = RET_OK;

    ASSERT(ctx != NULL);

    CALLOC_CHECKED(ctx_copy, sizeof(Gf2mCtx));

    len = (ctx->f[2] == 0 ? 3 : 5);
    MALLOC_CHECKED(ctx_copy->f, len * sizeof(int));
    memcpy(ctx_copy->f, ctx->f, len * sizeof(int));

    ctx_copy->len = ctx->len;
    ctx_copy->fr_lo = ctx->fr_lo;
    ctx_copy->fr_hi = ctx->fr_hi;
    ctx_copy->hw2 = ctx->hw2;
    ctx_copy->clmul = ctx->clmul;

    CHECK_NOT_NULL(ctx_copy->f_ext = wa_copy_with_alloc(ctx->f_ext));

    return ctx_copy;

cleanup:

    gf2m_free(ctx_copy);

    return NULL;
}

void gf2m_free(Gf2mCtx *ctx)
{
    if (ctx) {
        free(ctx->f);
        wa_free(ctx->f_ext);
        free(ctx);
    }
}
