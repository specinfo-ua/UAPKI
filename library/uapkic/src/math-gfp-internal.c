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

#define FILE_MARKER "uapkic/math-gfp-internal.c"

#include "math-gfp-internal.h"
#include "math-int-internal.h"
#include "macros-internal.h"

static WordArray *gfp_mod_inv_ext_euclid(const WordArray *in, const WordArray *p)
{
    WordArray *out = NULL;
    WordArray *a = NULL;
    WordArray *b = NULL;
    WordArray *q = NULL;
    WordArray *r = NULL;
    WordArray *x1 = NULL;
    WordArray *x2 = NULL;
    WordArray *x = NULL;
    WordArray *tmp = NULL;
    WordArray *tmp2;
    size_t len;
    int ret = RET_OK;

    CHECK_PARAM(in != NULL);
    CHECK_PARAM(p != NULL);

    len = in->len;
    CHECK_NOT_NULL(q = wa_alloc(2 * len));
    CHECK_NOT_NULL(r = wa_alloc(len));
    CHECK_NOT_NULL(x1 = wa_alloc_with_zero(len));
    CHECK_NOT_NULL(x2 = wa_alloc_with_one(len));
    CHECK_NOT_NULL(x = wa_alloc(len));
    CHECK_NOT_NULL(tmp = wa_alloc(len));

    /* x2 = 1, x1 = 0 */
    CHECK_NOT_NULL(a = wa_copy_with_alloc(in));
    wa_change_len(a, 2 * len);
    CHECK_NOT_NULL(b = wa_copy_with_alloc(p));

    if (int_is_zero(b)) {
        goto cleanup;
    }

    while (!int_is_zero(b)) {
        /* q = a / b, r = a - q * b */
        int_div(a, b, q, r);

        /* x = x2 - q * x1 */
        wa_copy_part(q, 0, len, tmp);
        int_mul(tmp, x1, a);
        int_div(a, p, NULL, tmp);
        if (int_sub(x2, tmp, x) < 0) {
            int_add(x, p, x);
        }

        /* a = b */
        wa_copy(b, a);

        /* b = r */
        tmp2 = r;
        r = b;
        b = tmp2;

        /* x2 = x1 */
        /* x1 = x */
        tmp2 = x2;
        x2 = x1;
        x1 = x;
        x = tmp2;
    }

    if (int_is_one(a)) {
        out = x2;
        x2 = NULL;
    }

cleanup:

    wa_free(a);
    wa_free(b);
    wa_free(q);
    wa_free(r);
    wa_free(x1);
    wa_free(x);
    wa_free(x2);
    wa_free(tmp);

    return out;
}

/**
 * Вычисляет обратный элемент в поле GF(p) используется бинарный алгоритм.
 */
static WordArray *gfp_mod_inv_binary(const WordArray *x, const WordArray *p)
{
    WordArray *out = NULL;
    WordArray *a = NULL;
    WordArray *b = NULL;
    WordArray *c = NULL;
    WordArray *d = NULL;
    int ret = RET_OK;

    if (int_is_one(x)) {
        CHECK_NOT_NULL(out = wa_copy_with_alloc(x));
        return out;
    }

    /* a = x; b = p; c = 1; d = 0. */
    CHECK_NOT_NULL(a = wa_copy_with_alloc(x));
    CHECK_NOT_NULL(b = wa_copy_with_alloc(p));
    CHECK_NOT_NULL(c = wa_alloc_with_one(x->len));
    CHECK_NOT_NULL(d = wa_alloc_with_zero(x->len));

    /* Пока a != 1 і b != 1. */
    while (!int_is_one(a) && !int_is_one(b)) {

        /* Пока a = 0 (mod 2), a = a/2, якщо c = 1 (mod 2), c = (c + p)/2, иначе c = c/2. */
        while (int_get_bit(a, 0) == 0) {
            word_t c_hi = 0;

            int_rshift(0, a, 1, a);
            if (int_get_bit(c, 0) == 1) {
                c_hi = int_add(c, p, c);
            }

            int_rshift(c_hi, c, 1, c);
        }

        /* Пока b = 0 (mod 2), b = b/2 і якщо d = 1 (mod 2), то d = (d + p) / 2, иначе d = d/2 */
        while (int_get_bit(b, 0) == 0) {
            word_t carry = 0;

            int_rshift(0, b, 1, b);

            if (int_get_bit(d, 0) == 1) {
                carry = int_add(d, p, d);
            }

            int_rshift(carry, d, 1, d);
        }

        if (int_cmp(a, b) >= 0) {

            /* якщо a >= b, то a = a - b і c = (c - d) (mod p) */
            int_sub(a, b, a);
            if (int_sub(c, d, c) < 0) {
                int_add(c, p, c);
            }
        } else {

            /* якщо a <= b, то b = b - a і d = (d - c) (mod p) */
            int_sub(b, a, b);
            if (int_sub(d, c, d) < 0) {
                int_add(d, p, d);
            }
        }
    }

    out = (int_is_one(a)) ? wa_copy_with_alloc(c) : wa_copy_with_alloc(d);

    CHECK_NOT_NULL(out);

cleanup:

    wa_free(a);
    wa_free(b);
    wa_free(c);
    wa_free(d);
    if (ret != RET_OK) {
        wa_free(out);
        out = NULL;
    }
    return out;
}

/**
 * Вычисляет обратный элемент в поле GF(p).
 */
WordArray *gfp_mod_inv_core(const WordArray *x, const WordArray *p)
{
    ASSERT(!int_is_zero(x));
    ASSERT(!int_is_zero(p));

    /* Если p четное - необходимо использовать базовый алгоритм поиска обратного элемента на основе расширенного алгоритма Евклида. */
    return ((p->buf[0] & 1) == 0)
            ? gfp_mod_inv_ext_euclid(x, p)
            : gfp_mod_inv_binary(x, p);
}

GfpCtx *gfp_alloc(const WordArray *p)
{
    GfpCtx *ctx;

    if (p == NULL) {
        return NULL;
    }

    ctx = calloc(1, sizeof(GfpCtx));
    if (ctx != NULL) {
        gfp_init(ctx, p);
    } else {
        ERROR_CREATE(RET_MEMORY_ALLOC_ERROR);
    }

    return ctx;
}

GfpCtx *gfp_copy_with_alloc(const GfpCtx *ctx)
{
    GfpCtx *ctx_copy = NULL;
    int ret = RET_OK;

    ASSERT(ctx != NULL);

    CALLOC_CHECKED(ctx_copy, sizeof(GfpCtx));

    CHECK_NOT_NULL(ctx_copy->invert_const = wa_copy_with_alloc(ctx->invert_const));
    CHECK_NOT_NULL(ctx_copy->one = wa_copy_with_alloc(ctx->one));
    CHECK_NOT_NULL(ctx_copy->p = wa_copy_with_alloc(ctx->p));
    CHECK_NOT_NULL(ctx_copy->two = wa_copy_with_alloc(ctx->two));

    return ctx_copy;

cleanup:

    gfp_free(ctx_copy);

    return NULL;
}

void gfp_init(GfpCtx *ctx, const WordArray *p)
{
    WordArray *two_power_plen = NULL;
    WordArray *two_power_plen_mod_p = NULL;
    int ret = RET_OK;

    ASSERT(ctx != NULL);
    ASSERT(p != NULL);

    CHECK_NOT_NULL(ctx->p = wa_copy_with_alloc(p));
    CHECK_NOT_NULL(ctx->one = wa_alloc_with_one(p->len));
    CHECK_NOT_NULL(ctx->two = wa_alloc_with_zero(p->len));
    ctx->two->buf[0] = 2;

    CHECK_NOT_NULL(two_power_plen = wa_alloc_with_zero(2 * p->len));
    CHECK_NOT_NULL(two_power_plen_mod_p = wa_alloc_with_zero(p->len));
    two_power_plen->buf[int_word_len(p)] = 1;

    int_div(two_power_plen, p, NULL, two_power_plen_mod_p);
    CHECK_NOT_NULL(ctx->invert_const = gfp_mod_inv_core(two_power_plen_mod_p, p));
cleanup:

    wa_free(two_power_plen);
    wa_free(two_power_plen_mod_p);
}

void gfp_mod_add(const GfpCtx *ctx, const WordArray *a, const WordArray *b, WordArray *out)
{
    ASSERT(ctx != NULL);
    ASSERT(a != NULL);
    ASSERT(b != NULL);
    ASSERT(out != NULL);
    ASSERT(a->len == b->len);
    ASSERT(a->len == out->len);

    if (int_add(a, b, out) > 0 || int_cmp(out, ctx->p) >= 0) {
        int_sub(out, ctx->p, out);
    }
}

void gfp_mod_sub(const GfpCtx *ctx, const WordArray *a, const WordArray *b, WordArray *out)
{
    ASSERT(ctx != NULL);
    ASSERT(a != NULL);
    ASSERT(b != NULL);
    ASSERT(out != NULL);
    ASSERT(a->len == b->len);
    ASSERT(a->len == out->len);

    if (int_sub(a, b, out) < 0) {
        int_add(out, ctx->p, out);
    }
}

void gfp_mod(const GfpCtx *ctx, const WordArray *a, WordArray *out)
{
    ASSERT(ctx != NULL);
    ASSERT(a != NULL);
    ASSERT(out != NULL);
    ASSERT(a->len == 2 * ctx->p->len);

    int_div(a, ctx->p, NULL, out);
}

void gfp_mod_mul(const GfpCtx *ctx, const WordArray *a, const WordArray *b, WordArray *out)
{
    WordArray *ab;

    ASSERT(ctx != NULL);
    ASSERT(a != NULL);
    ASSERT(b != NULL);
    ASSERT(out != NULL);
    ASSERT(a->len == b->len);
    ASSERT(a->len == out->len);

    ab = wa_alloc(2 * a->len);
    if (!ab) {
        ERROR_CREATE(RET_MEMORY_ALLOC_ERROR);
        return;
    }
    ASSERT(ab != NULL);

    int_mul(a, b, ab);
    gfp_mod(ctx, ab, out);

    wa_free(ab);
}

void gfp_mod_sqr(const GfpCtx *ctx, const WordArray *a, WordArray *out)
{
    WordArray *aa;

    ASSERT(ctx != NULL && a != NULL && out != NULL && a->len == out->len);

    aa = wa_alloc(2 * a->len);
    if (!aa) {
        ERROR_CREATE(RET_MEMORY_ALLOC_ERROR);
        return;
    }
    ASSERT(aa != NULL);

    int_sqr(a, aa);
    gfp_mod(ctx, aa, out);

    wa_free(aa);
}

WordArray *gfp_mod_inv(const GfpCtx *ctx, const WordArray *in)
{
    WordArray *out = NULL;
    WordArray *a = NULL;
    WordArray *b = NULL;
    WordArray *c = NULL;
    WordArray *d = NULL;
    int ret = RET_OK;

    ASSERT(ctx != NULL);
    ASSERT(in != NULL);

    word_t carry = 0;
    size_t k = 0;
    size_t len;

    /* Если p четное - необходимо использовать базовый алгоритм поиска обратного элемента на основе расширенного алгоритма Евклида. */
    if ((ctx->p->buf[0] & 1) == 0) {
        return gfp_mod_inv_ext_euclid(in, ctx->p);
    }

    if (int_equals(in, ctx->one)) {
        CHECK_NOT_NULL(out = wa_copy_with_alloc(in));
        return out;
    }

    /* a = in; b = p; c = 1; d = 0. */
    CHECK_NOT_NULL(a = wa_copy_with_alloc(in));
    CHECK_NOT_NULL(b = wa_copy_with_alloc(ctx->p));
    CHECK_NOT_NULL(c = wa_alloc_with_one(in->len));
    CHECK_NOT_NULL(d = wa_alloc_with_zero(in->len));

    while (!int_is_zero(b)) {
        if (int_get_bit(b, 0) == 0) {
            /* якщо b = 0 (mod 2), b = b/2, c = 2*c. */
            int_rshift(0, b, 1, b);
            carry = c->buf[c->len - 1] >> (WORD_BIT_LENGTH - 1);
            int_lshift(c, 1, c);
        } else if (int_get_bit(a, 0) == 0) {
            /* якщо a = 0 (mod 2), a = a/2, d = 2*d. */
            int_rshift(0, a, 1, a);
            int_lshift(d, 1, d);
        } else if (int_cmp(b, a) >= 0) {
            /* якщо b >= a, b = (b - a)/2, d = d + c, x1 = 2*c. */
            int_sub(b, a, b);
            int_rshift(0, b, 1, b);
            int_add(d, c, d);
            carry = c->buf[c->len - 1] >> (WORD_BIT_LENGTH - 1);
            int_lshift(c, 1, c);
        } else {
            /* Иначе a = (a - b)/2, c = d + c, d = 2*d. */
            int_sub(a, b, a);
            int_rshift(0, a, 1, a);
            int_add(d, c, c);
            int_lshift(d, 1, d);
        }
        k++;
    }

    if (carry > 0 || int_cmp(c, ctx->p) >= 0) {
        int_sub(c, ctx->p, c);
    }

    len = int_word_len(ctx->p) * WORD_BIT_LENGTH;

    while (k > len) {
        carry = 0;

        /* якщо c = 1 (mod 2), c = (c + p) / 2, иначе c = c/2. */
        if (int_get_bit(c, 0) == 1) {
            carry = int_add(c, ctx->p, c);
        }

        int_rshift(carry, c, 1, c);
        k--;
    }

    CHECK_NOT_NULL(out = wa_alloc(in->len));
    gfp_mod_mul(ctx, c, ctx->invert_const, out);

cleanup:

    wa_free(a);
    wa_free(b);
    wa_free(c);
    wa_free(d);

    return out;
}

/**
 * @param ctx
 * @param a - Число для вознесения в степень.
 * @param x - Степень.
 * @param out
 */
void gfp_mod_pow(const GfpCtx *ctx, const WordArray *a, const WordArray *x, WordArray *out)
{
    WordArray *tmp = NULL;
    int len;
    int i;

    ASSERT(ctx != NULL);
    ASSERT(a != NULL);
    ASSERT(x != NULL);
    ASSERT(a->len == out->len);

    /* Метод удвоения сложения. */
    tmp = wa_alloc(ctx->p->len);
    wa_copy(ctx->one, out);
    wa_copy(ctx->one, tmp);

    len = (int)int_bit_len(x);
    for (i = len - 1; i >= 0; i--) {
        gfp_mod_sqr(ctx, out, out);
        if (int_get_bit(x, i)) {
            gfp_mod_mul(ctx, a, out, out);
        } else {
            gfp_mod_mul(ctx, a, out, tmp);
        }
    }

    wa_free(tmp);
}

void gfp_mod_dual_pow(const GfpCtx *ctx, const WordArray *a, const WordArray *x,
        const WordArray *b, const WordArray *y, WordArray *out)
{
    WordArray *tmp = NULL;
    int xlen, ylen, len;
    int i;

    ASSERT(ctx != NULL);
    ASSERT(a != NULL);
    ASSERT(x != NULL);
    ASSERT(b != NULL);
    ASSERT(y != NULL);
    ASSERT(a->len == out->len);
    ASSERT(b->len == out->len);

    /* Метод удвоения сложения. */
    wa_copy(ctx->one, out);
    wa_copy(ctx->one, tmp);

    xlen = (int)int_bit_len(x);
    ylen = (int)int_bit_len(y);
    len = (xlen > ylen) ? xlen : ylen;
    for (i = len - 1; i >= 0; i--) {
        gfp_mod_sqr(ctx, out, out);
        if (int_get_bit(x, i)) {
            gfp_mod_mul(ctx, a, out, out);
        } else {
            gfp_mod_mul(ctx, a, out, tmp);
        }

        if (int_get_bit(y, i)) {
            gfp_mod_mul(ctx, b, out, out);
        } else {
            gfp_mod_mul(ctx, b, out, tmp);
        }
    }
    wa_free(tmp);
}

/**
 * Генерирует последовательности Лукаса.
 * c[0] = 2, c[1] = a, c[k] = a * c[k - 1] - b * c[k - 2] (mod p).
 *
 * @param ctx контекст простого конечного поля
 * @param a начальное значение для генерации последовательности
 * @param b начальное значение для генерации последовательности
 * @param k номер элемента последовательности Лукаса
 * @param ck = c[k] (mod p)
 * @param bk = b^[k/2] (mod p)
 */
static void gfp_mod_lucas_seq(const GfpCtx *ctx, const WordArray *a, const WordArray *b,
        const WordArray *k, WordArray *ck, WordArray *bk)
{
    WordArray *b0 = NULL;
    WordArray *b1 = NULL;
    WordArray *c0 = NULL;
    WordArray *c1 = NULL;
    WordArray *t = NULL;
    int i;
    int ret = RET_OK;

    CHECK_NOT_NULL(b0 = wa_copy_with_alloc(ctx->one));
    CHECK_NOT_NULL(b1 = wa_copy_with_alloc(ctx->one));
    CHECK_NOT_NULL(c0 = wa_copy_with_alloc(ctx->two));
    CHECK_NOT_NULL(c1 = wa_copy_with_alloc(a));
    CHECK_NOT_NULL(t = wa_alloc(ctx->p->len));

    for (i = (int)int_bit_len(k) - 1; i >= 0; i--) {
        gfp_mod_mul(ctx, b0, b1, b0);
        if (int_get_bit(k, i) == 1) {
            gfp_mod_mul(ctx, b0, b, b1);
            gfp_mod_mul(ctx, c0, c1, c0);
            gfp_mod_mul(ctx, b0, a, t);
            gfp_mod_sub(ctx, c0, t, c0);
            gfp_mod_sqr(ctx, c1, c1);
            gfp_mod_add(ctx, b1, b1, t);
            gfp_mod_sub(ctx, c1, t, c1);
        } else {
            wa_copy(b0, b1);
            gfp_mod_mul(ctx, c0, c1, c1);
            gfp_mod_mul(ctx, b0, a, t);
            gfp_mod_sub(ctx, c1, t, c1);
            gfp_mod_sqr(ctx, c0, c0);
            gfp_mod_add(ctx, b0, b0, t);
            gfp_mod_sub(ctx, c0, t, c0);
        }
    }

    wa_copy(c0, ck);
    wa_copy(b0, bk);
cleanup:
    wa_free(b0);
    wa_free(b1);
    wa_free(c0);
    wa_free(c1);
    wa_free(t);
}

bool gfp_mod_sqrt(const GfpCtx *ctx, const WordArray *a, WordArray *out)
{
    ASSERT(ctx != NULL);
    ASSERT(a != NULL);
    ASSERT(out != NULL);
    ASSERT(a->len == ctx->p->len);
    ASSERT(out->len == ctx->p->len);
    int ret = RET_OK;

    size_t len = ctx->p->len;
    word_t carry;
    WordArray *b = wa_alloc(len);
    WordArray *c = wa_alloc(len);
    WordArray *d = wa_alloc(len);
    WordArray *e = wa_alloc(len);
    WordArray *k = wa_alloc(len);
    WordArray *ck = wa_alloc(len);
    bool answ = false;

    CHECK_NOT_NULL(b);
    CHECK_NOT_NULL(c);
    CHECK_NOT_NULL(d);
    CHECK_NOT_NULL(e);
    CHECK_NOT_NULL(k);
    CHECK_NOT_NULL(ck);

    if (int_is_zero(a) || int_equals(a, ctx->one)) {
        wa_copy(a, out);
        answ = true;
        goto cleanup;
    }

    if ((ctx->p->buf[0] & 3) == 3) {
        /* p = 3 (mod 4). */
        int_rshift(0, ctx->p, 2, b);
        int_add(b, ctx->one, b);
        gfp_mod_pow(ctx, a, b, c);
        gfp_mod_sqr(ctx, c, d);

        if (int_equals(d, a)) {
            wa_copy(c, out);
            answ = true;
        }
    } else if ((ctx->p->buf[0] & 7) == 5) {
        /* p = 5 (mod 8). */
        gfp_mod_add(ctx, a, a, b);
        int_rshift(0, ctx->p, 3, d);
        gfp_mod_pow(ctx, b, d, c);

        gfp_mod_sqr(ctx, c, e);
        gfp_mod_mul(ctx, e, b, e);
        gfp_mod_sub(ctx, e, ctx->one, e);
        gfp_mod_mul(ctx, e, c, e);
        gfp_mod_mul(ctx, a, e, k);
        gfp_mod_sqr(ctx, k, ck);

        if (int_equals(ck, a)) {
            wa_copy(k, out);
            answ = true;
        }
    } else {
        /* p = 1 (mod 8). */
        int_sub(ctx->p, ctx->one, e);

        carry = int_add(ctx->p, ctx->one, k);
        int_rshift(carry, k, 1, k);
        wa_copy(a, c);

        do {
            /* Генерация случайного числа 1 < b < p. */
            int_prand(ctx->p, b);

            /* d = d[k] (mod p) и ck = c^[k/2] (mod p). */
            gfp_mod_lucas_seq(ctx, b, c, k, d, ck);

            /* Если 1 < ck < p - 1, то g квадратичный невычет. */
            if ((int_cmp(ck, ctx->one) > 0) && (int_cmp(ck, e) < 0)) {
                answ = false;
                goto cleanup;
            }

            /* d = d/2 (mod p). */
            carry = 0;
            if (int_get_bit(d, 0)) {
                carry = int_add(d, ctx->p, d);
            }
            int_rshift(carry, d, 1, d);

            /* Если d^2 = x (mod p), то вернуть результат. */
            gfp_mod_sqr(ctx, d, b);

            if (int_equals(b, a)) {
                wa_copy(d, out);
                answ = true;
                goto cleanup;
            }
        } while (true);
    }

cleanup:

    wa_free(b);
    wa_free(c);
    wa_free(d);
    wa_free(e);
    wa_free(k);
    wa_free(ck);

    return answ;
}

void gfp_free(GfpCtx *ctx)
{
    if (ctx) {
        wa_free_private(ctx->p);
        wa_free_private(ctx->invert_const);
        wa_free(ctx->one);
        wa_free(ctx->two);
        free(ctx);
    }
}
