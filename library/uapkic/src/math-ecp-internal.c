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

#include "math-ecp-internal.h"
#include "math-int-internal.h"
#include "macros-internal.h"

#undef FILE_MARKER
#define FILE_MARKER "uapkic/math-ecp-internal.c"

EcGfpCtx *ecp_alloc(const WordArray *p, const WordArray *a, const WordArray *b)
{
    EcGfpCtx *ctx = NULL;
    int ret = RET_OK;

    CHECK_PARAM(p != NULL);
    CHECK_PARAM(a != NULL);
    CHECK_PARAM(b != NULL);

    CALLOC_CHECKED(ctx, sizeof(EcGfpCtx));

    ecp_init(ctx, p, a, b);

cleanup:
    return ctx;
}

EcGfpCtx *ecp_copy_with_alloc(EcGfpCtx *ctx)
{
    int ret = RET_OK;
    EcGfpCtx *ctx_copy = NULL;

    CHECK_PARAM(ctx != NULL);

    CALLOC_CHECKED(ctx_copy, sizeof(EcGfpCtx));

    CHECK_NOT_NULL(ctx_copy->a = wa_copy_with_alloc(ctx->a));
    ctx_copy->a_equal_minus_3 = ctx->a_equal_minus_3;
    CHECK_NOT_NULL(ctx_copy->b = wa_copy_with_alloc(ctx->b));
    CHECK_NOT_NULL(ctx_copy->gfp = gfp_copy_with_alloc(ctx->gfp));
    ctx_copy->len = ctx->len;

    return ctx_copy;

cleanup:

    ecp_free(ctx_copy);

    return NULL;
}

void ecp_init(EcGfpCtx *ctx, const WordArray *p, const WordArray *a, const WordArray *b)
{
    int ret = RET_OK;
    size_t len = p->len;

    ASSERT(ctx != NULL);
    ASSERT(p != NULL);
    ASSERT(a != NULL);
    ASSERT(b != NULL);
    ASSERT(p->len == a->len);
    ASSERT(p->len == b->len);

    CHECK_NOT_NULL(ctx->gfp = gfp_alloc(p));
    CHECK_NOT_NULL(ctx->a = wa_alloc(len));
    CHECK_NOT_NULL(ctx->b = wa_alloc(len));

    int_sub(p, a, ctx->a);
    ctx->a_equal_minus_3 = (int_bit_len(ctx->a) == 2) && (ctx->a->buf[0] == 3);
    ctx->len = p->len;
    wa_copy(a, ctx->a);
    wa_copy(b, ctx->b);

cleanup:
    return;
}

bool ecp_is_on_curve(const EcGfpCtx *ctx, const WordArray *px, const WordArray *py)
{
    WordArray *x = NULL;
    WordArray *y = NULL;
    bool answ = false;
    int ret = RET_OK;

    ASSERT(ctx != NULL);
    ASSERT(px != NULL);
    ASSERT(py != NULL);
    ASSERT(ctx->len == px->len);
    ASSERT(px->len == py->len);

    CHECK_NOT_NULL(x = wa_alloc(ctx->len));
    CHECK_NOT_NULL(y = wa_alloc(ctx->len));
    wa_copy(px, x);
    gfp_mod_sqr(ctx->gfp, x, y);

    gfp_mod_add(ctx->gfp, y, ctx->a, y);

    gfp_mod_mul(ctx->gfp, y, x, y);
    gfp_mod_add(ctx->gfp, y, ctx->b, x);

    wa_copy(py, y);
    gfp_mod_sqr(ctx->gfp, y, y);

    answ = int_equals(x, y);

    wa_free(x);
    wa_free(y);

cleanup:

    return answ;
}

/**
 * Удваивает точку эллиптической кривой.
 *
 * @param P точка эллиптической кривой
 * @param R  = 2*P
 */
static void ecp_double_point(const EcGfpCtx *ctx, const ECPoint *p, ECPoint *r)
{
    WordArray *t1 = NULL;
    WordArray *t2 = NULL;
    WordArray *t3 = NULL;
    WordArray *t4 = NULL;
    int ret = RET_OK;

    ASSERT(ctx != NULL);
    ASSERT(p != NULL);
    ASSERT(r != NULL);
    ASSERT(ctx->len == p->x->len);
    ASSERT(ctx->len == r->x->len);

    if (int_is_zero(p->y)) {
        wa_zero(r->x);
        wa_zero(r->y);
        wa_copy(ctx->gfp->one, r->z);
        return;
    }

    CHECK_NOT_NULL(t1 = wa_alloc(ctx->len));
    CHECK_NOT_NULL(t2 = wa_alloc(ctx->len));
    CHECK_NOT_NULL(t3 = wa_alloc(ctx->len));
    CHECK_NOT_NULL(t4 = wa_alloc(ctx->len));

    /* t1 = p(y)^2, t2 = 4 * p(x) * p(y)^2. */
    gfp_mod_sqr(ctx->gfp, p->y, t1);
    gfp_mod_mul(ctx->gfp, p->x, t1, t2);
    gfp_mod_add(ctx->gfp, t2, t2, t2);
    gfp_mod_add(ctx->gfp, t2, t2, t2);

    /* t3 = 3 * p(x)^2 + a * p(z)^4. */
    if (ctx->a_equal_minus_3) {
        /* a = -3 => t3 = 3 * (p(x) - p(z)^2) * (p(x) + p(z)^2). */
        gfp_mod_sqr(ctx->gfp, p->z, t4);
        gfp_mod_add(ctx->gfp, p->x, t4, t3);
        gfp_mod_sub(ctx->gfp, p->x, t4, t4);
        gfp_mod_mul(ctx->gfp, t3, t4, t3);
        gfp_mod_add(ctx->gfp, t3, t3, t4);
        gfp_mod_add(ctx->gfp, t3, t4, t3);
    } else {
        gfp_mod_sqr(ctx->gfp, p->x, t3);
        gfp_mod_add(ctx->gfp, t3, t3, t4);
        gfp_mod_add(ctx->gfp, t3, t4, t3);
        gfp_mod_sqr(ctx->gfp, p->z, t4);
        gfp_mod_sqr(ctx->gfp, t4, t4);
        gfp_mod_mul(ctx->gfp, t4, ctx->a, t4);
        gfp_mod_add(ctx->gfp, t3, t4, t3);
    }

    /* r(x) = t3^2 - 2 * t2. */
    gfp_mod_sqr(ctx->gfp, t3, r->x);
    gfp_mod_sub(ctx->gfp, r->x, t2, r->x);
    gfp_mod_sub(ctx->gfp, r->x, t2, r->x);

    /* r(z) = 2 * p(y) * p(z). */
    gfp_mod_mul(ctx->gfp, p->y, p->z, r->z);
    gfp_mod_add(ctx->gfp, r->z, r->z, r->z);

    /* r(y) = t3 * (t2 - r(x)) - 8 * p(y)^4. */
    gfp_mod_add(ctx->gfp, t1, t1, t1);
    gfp_mod_sqr(ctx->gfp, t1, t1);
    gfp_mod_add(ctx->gfp, t1, t1, r->y);

    gfp_mod_sub(ctx->gfp, t2, r->x, t1);
    gfp_mod_mul(ctx->gfp, t3, t1, t1);
    gfp_mod_sub(ctx->gfp, t1, r->y, r->y);

cleanup:

    wa_free(t1);
    wa_free(t2);
    wa_free(t3);
    wa_free(t4);
}

/**
 * Складывает точку эллиптической кривой с другой точкой.
 *
 * @param ctx
 * @param p точка эллиптической кривой
 * @param qx X-координата точки Q представленной в аффинных координатах
 * @param qy Y-координата точки Q представленной в аффинных координатах
 * @param sign = -1 або 1
 * @param r  = P + sign * Q
 */
void ecp_add_point(const EcGfpCtx *ctx, const ECPoint *p, const WordArray *qx, const WordArray *qy, int sign,
        ECPoint *r)
{
    WordArray *t1 = NULL;
    WordArray *t2 = NULL;
    WordArray *t3 = NULL;
    WordArray *t4 = NULL;
    int ret = RET_OK;

    ASSERT(ctx != NULL);
    ASSERT(p != NULL);
    ASSERT(qx != NULL);
    ASSERT(qy != NULL);
    ASSERT(r != NULL);
    ASSERT(ctx->len == p->x->len);
    ASSERT(ctx->len == qx->len);
    ASSERT(ctx->len == qy->len);
    ASSERT(ctx->len == r->x->len);

    /* P = 0 ? */
    if (int_is_zero(p->x) && int_is_zero(p->y)) {
        wa_copy(qx, r->x);
        wa_copy(qy, r->y);
        wa_copy(ctx->gfp->one, r->z);

        if (sign == -1) {
            int_sub(ctx->gfp->p, r->y, r->y);
        }
        return;
    }

    /* Q = 0 ? */
    if (int_is_zero(qx) && int_is_zero(qy)) {
        ec_point_copy(p, r);
        return;
    }

    CHECK_NOT_NULL(t1 = wa_alloc(ctx->len));
    CHECK_NOT_NULL(t2 = wa_alloc(ctx->len));
    CHECK_NOT_NULL(t3 = wa_alloc(ctx->len));
    CHECK_NOT_NULL(t4 = wa_alloc(ctx->len));

    /*
     * t1 = q(x) * p(z)^2 - p(x)
     * t2 = p(z)^2
     */
    gfp_mod_sqr(ctx->gfp, p->z, t2);
    gfp_mod_mul(ctx->gfp, qx, t2, t1);
    gfp_mod_sub(ctx->gfp, t1, p->x, t1);

    /* t2 = q(y) * p(z)^3 */
    gfp_mod_mul(ctx->gfp, t2, p->z, t2);
    gfp_mod_mul(ctx->gfp, qy, t2, t2);
    if (sign == -1) {
        int_sub(ctx->gfp->p, t2, t2);
    }

    /* Q == -P ? */
    gfp_mod_add(ctx->gfp, t2, p->y, t3);
    if (int_is_zero(t1) && int_is_zero(t3)) {
        wa_zero(r->x);
        wa_zero(r->y);
        wa_copy(ctx->gfp->one, r->z);

        goto cleanup;
    }

    /* t2 = t2 - p(y) */
    gfp_mod_sub(ctx->gfp, t2, p->y, t2);

    /* P == Q ? */
    if (int_is_zero(t1) && int_is_zero(t2)) {
        ecp_double_point(ctx, p, r);
        goto cleanup;
    }

    /* r(x) = -t1^3 + t2^2;
     * t3 = p(x) * t1^2;
     * t4 = t1^3;
     */
    gfp_mod_sqr(ctx->gfp, t1, t3);
    gfp_mod_mul(ctx->gfp, t1, t3, t4);
    gfp_mod_mul(ctx->gfp, p->x, t3, t3);
    gfp_mod_sqr(ctx->gfp, t2, r->x);
    gfp_mod_sub(ctx->gfp, r->x, t4, r->x);

    /* r(x) = r(x) - 2 * t3;
     * r(y) = p(y) * t1^3;
     */
    gfp_mod_mul(ctx->gfp, t4, p->y, r->y);
    gfp_mod_add(ctx->gfp, t3, t3, t4);
    gfp_mod_sub(ctx->gfp, r->x, t4, r->x);

    /* r(y) = t2 * (t3 - r(x)) - r(y) */
    gfp_mod_sub(ctx->gfp, t3, r->x, t4);
    gfp_mod_mul(ctx->gfp, t2, t4, t4);
    gfp_mod_sub(ctx->gfp, t4, r->y, r->y);

    /* r(z) = p(z) * t1 */
    gfp_mod_mul(ctx->gfp, p->z, t1, r->z);

cleanup:

    wa_free(t1);
    wa_free(t2);
    wa_free(t3);
    wa_free(t4);
}

void ecp_point_to_affine(const EcGfpCtx *ctx, ECPoint *p)
{
    WordArray *t;

    ASSERT(ctx != NULL);
    ASSERT(p != NULL);
    ASSERT(ctx->len == p->x->len);

    if (int_is_zero(p->x) && int_is_zero(p->y)) {
        wa_copy(ctx->gfp->one, p->z);
        return;
    }

    t = gfp_mod_inv(ctx->gfp, p->z);
    ASSERT(t != NULL);

    gfp_mod_mul(ctx->gfp, p->y, t, p->y);
    gfp_mod_sqr(ctx->gfp, t, t);
    gfp_mod_mul(ctx->gfp, p->x, t, p->x);
    gfp_mod_mul(ctx->gfp, p->y, t, p->y);
    wa_copy(ctx->gfp->one, p->z);

    wa_free(t);
}

static int ecp_points_to_affine(EcGfpCtx *ctx, ECPoint **array, int off, int len)
{
    WordArray **k = NULL;
    WordArray *t = NULL;
    int i;
    int ret = RET_OK;

    CALLOC_CHECKED(k, len * sizeof(WordArray *));
    CHECK_NOT_NULL(k[0] = wa_alloc(ctx->len));

    DO(wa_copy(array[off]->z, k[0]));

    for (i = 1; i < len; i++) {
        CHECK_NOT_NULL(k[i] = wa_alloc(ctx->len));
        gfp_mod_mul(ctx->gfp, array[i + off]->z, k[i - 1], k[i]);
    }

    t = gfp_mod_inv(ctx->gfp, k[len - 1]);

    for (i = len - 1; i > 0; i--) {
        gfp_mod_mul(ctx->gfp, t, k[i - 1], k[i]);
        gfp_mod_mul(ctx->gfp, t, array[i + off]->z, t);
    }
    wa_copy(t, k[0]);

    for (i = 0; i < len; i++) {
        gfp_mod_mul(ctx->gfp, array[i + off]->y, k[i], array[i + off]->y);
        gfp_mod_sqr(ctx->gfp, k[i], k[i]);
        gfp_mod_mul(ctx->gfp, array[i + off]->x, k[i], array[i + off]->x);
        gfp_mod_mul(ctx->gfp, array[i + off]->y, k[i], array[i + off]->y);
        DO(wa_copy(ctx->gfp->one, array[i + off]->z));
    }

cleanup:

    for (i = 0; i < len; i++) {
        wa_free(k[i]);
    }
    free(k);
    wa_free(t);

    return ret;
}

static void ecp_point_zero(EcGfpCtx *ctx, ECPoint *p)
{
    wa_zero(p->x);
    wa_zero(p->y);
    wa_copy(ctx->gfp->one, p->z);
}

int ecp_calc_win_precomp(EcGfpCtx *ctx, const ECPoint *p, int width, EcPrecomp **precomp1)
{
    EcPrecomp *precomp = NULL;
    EcPrecompWin *precomp_win = NULL;
    ECPoint *r = NULL;
    int i;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);

    CALLOC_CHECKED(precomp_win, sizeof(EcPrecompWin));
    CALLOC_CHECKED(precomp, sizeof(EcPrecomp));
    precomp->type = EC_PRECOMP_TYPE_WIN;
    precomp->ctx.win = precomp_win;

    precomp_win->win_width = width;

    if (p == NULL) {
        precomp_win->precomp_len = 0;
        precomp_win->precomp = NULL;
    } else {
        CHECK_PARAM(ctx->len == p->x->len);
        int precomp_len = 1 << (width - 2);

        precomp_win->precomp_len = precomp_len;

        CALLOC_CHECKED(precomp_win->precomp, precomp_len * sizeof(ECPoint *));
        for (i = 0; i < precomp_len; i++) {
            CHECK_NOT_NULL(precomp_win->precomp[i] = ec_point_alloc(ctx->len));
            ecp_point_zero(ctx, precomp_win->precomp[i]);
        }

        CHECK_NOT_NULL(r = ec_point_copy_with_alloc(p));
        ec_point_copy(r, precomp_win->precomp[0]);

        ecp_double_point(ctx, r, r);
        ecp_point_to_affine(ctx, r);

        for (i = 1; i < precomp_len; i++) {
            ecp_add_point(ctx, precomp_win->precomp[i - 1], r->x, r->y, 1, precomp_win->precomp[i]);
        }

        DO(ecp_points_to_affine(ctx, precomp_win->precomp, 1, precomp_len - 1));
    }

    *precomp1 = precomp;

cleanup:

    ec_point_free(r);

    return ret;
}

int ecp_calc_comb_precomp(EcGfpCtx *ctx, const ECPoint *p, int width, EcPrecomp **precomp1)
{
    int i, j;
    ECPoint *r = NULL;
    EcPrecompComb *comb = NULL;
    int comb_step;
    int comb_len;
    EcPrecomp *precomp = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);

    CALLOC_CHECKED(comb, sizeof(EcPrecompComb));
    CALLOC_CHECKED(precomp, sizeof(EcPrecomp));
    precomp->type = EC_PRECOMP_TYPE_COMB;
    precomp->ctx.comb = comb;

    comb->comb_width = width;

    if (p == NULL) {
        comb->precomp = NULL;
    } else {
        CHECK_PARAM(ctx->len == p->x->len);

        comb_step = (8 * (int) ctx->len * sizeof(word_t) + width - 1) / width;
        comb_len = (1 << width) - 1;

        CALLOC_CHECKED(comb->precomp, comb_len * sizeof(ECPoint *));
        for (i = 0; i < comb_len; i++) {
            CHECK_NOT_NULL(comb->precomp[i] = ec_point_alloc(ctx->len));
            ecp_point_zero(ctx, comb->precomp[i]);
        }

        CHECK_NOT_NULL(r = ec_point_copy_with_alloc(p));
        ec_point_copy(r, comb->precomp[0]);

        for (i = 1; i < width; i++) {
            for (j = 0; j < comb_step; j++) {
                ecp_double_point(ctx, r, r);
            }
            ec_point_copy(r, comb->precomp[(1 << i) - 1]);
            ecp_point_to_affine(ctx, comb->precomp[(1 << i) - 1]);
        }

        for (i = 2; i < comb_len; i++) {
            for (j = 0; j < width; j++) {
                int power_precomp_ind = (1 << j) - 1;
                if ((((i + 1) >> j) & 1) && (i != power_precomp_ind)) {
                    ecp_add_point(ctx, comb->precomp[i], comb->precomp[power_precomp_ind]->x, comb->precomp[power_precomp_ind]->y, 1,
                            comb->precomp[i]);
                }
            }
            ecp_point_to_affine(ctx, comb->precomp[i]);
        }
    }

    *precomp1 = precomp;

cleanup:

    ec_point_free(r);

    return ret;
}

void ecp_mul(EcGfpCtx *ctx, const ECPoint *p, const WordArray *k, ECPoint *r)
{
    int len;
    int i;

    ASSERT(ctx != NULL);
    ASSERT(p != NULL);
    ASSERT(p->x != NULL);
    ASSERT(p->y != NULL);
    ASSERT(k != NULL);
    ASSERT(r != NULL);
    ASSERT(r->x != NULL);
    ASSERT(r->y != NULL);
    ASSERT(ctx->len == p->x->len);
    ASSERT(ctx->len == r->x->len);

    wa_zero(r->x);
    wa_zero(r->y);
    wa_copy(ctx->gfp->one, r->z);

    len = (int)int_bit_len(k);
    for (i = len - 1; i >= 0; i--) {
        ecp_double_point(ctx, r, r);
        if (int_get_bit(k, i)) {
            ecp_add_point(ctx, r, p->x, p->y, 1, r);
        }
    }

    ecp_point_to_affine(ctx, r);
}

void ecp_dual_mul(EcGfpCtx *ctx, const ECPoint *p, const WordArray *k,
        const ECPoint *q, const WordArray *n, ECPoint *r)
{
    int len;
    int mlen, nlen;
    int i;

    ASSERT(ctx != NULL);
    ASSERT(p != NULL);
    ASSERT(k != NULL);
    ASSERT(ctx->len == p->x->len);
    ASSERT(q != NULL);
    ASSERT(n != NULL);
    ASSERT(ctx->len == q->x->len);
    ASSERT(ctx->len == r->x->len);

    wa_zero(r->x);
    wa_zero(r->y);
    wa_copy(ctx->gfp->one, r->z);

    mlen = (int)int_bit_len(k);
    nlen = (int)int_bit_len(n);
    len = (mlen > nlen) ? mlen : nlen;
    for (i = len - 1; i >= 0; i--) {
        ecp_double_point(ctx, r, r);
        ecp_point_to_affine(ctx, r);
        if (int_get_bit(k, i)) {
            ecp_add_point(ctx, r, p->x, p->y, 1, r);
        }
        if (int_get_bit(n, i)) {
            ecp_add_point(ctx, r, q->x, q->y, 1, r);
        }
    }

    ecp_point_to_affine(ctx, r);
}

static void ecp_dual_mul_opt_step(const EcGfpCtx *ctx, const EcPrecomp *p_precomp, const WordArray *m, int *m_naf,
        ECPoint *r, int iter, int max_iter)
{
    int comb_ind;
    int comb_bit;
    int j;

    if (p_precomp->type == EC_PRECOMP_TYPE_WIN) {
        int nafi = m_naf[iter];
        if (nafi > 0) {
            ecp_add_point(ctx, r, p_precomp->ctx.win->precomp[(nafi - 1) >> 1]->x, p_precomp->ctx.win->precomp[(nafi - 1) >> 1]->y,
                    1, r);
        } else if (nafi < 0) {
            ecp_add_point(ctx, r, p_precomp->ctx.win->precomp[(-nafi - 1) >> 1]->x,
                    p_precomp->ctx.win->precomp[(-nafi - 1) >> 1]->y, -1, r);
        }
    } else if (p_precomp->type == EC_PRECOMP_TYPE_COMB) {
        if (iter <= max_iter && m != NULL) {
            comb_ind = 0;
            comb_bit = iter;
            int bit_len = 8 * (int) ctx->len * sizeof(word_t);
            int comb_step = (bit_len + p_precomp->ctx.comb->comb_width - 1) / p_precomp->ctx.comb->comb_width;

            for (j = 0; comb_bit < bit_len; j++) {
                comb_ind |= int_get_bit(m, comb_bit) << j;
                comb_bit += comb_step;
            }

            if (comb_ind > 0) {
                ecp_add_point(ctx, r, p_precomp->ctx.comb->precomp[comb_ind - 1]->x, p_precomp->ctx.comb->precomp[comb_ind - 1]->y, 1,
                        r);
            }
        }
    }
}

static void ecp_dual_mul_opt_extra_addition(const EcGfpCtx *ctx, const EcPrecomp *precomp, const WordArray *in, int *naf, ECPoint *buf)
{
    int iter_p = 0;
    int iter_b = 0;
    int iter_max = 0;
    int i = 0;

    if (ctx != NULL && buf != NULL && in != NULL && precomp != NULL && precomp->type == EC_PRECOMP_TYPE_WIN) {
        iter_max = (int)int_bit_len(in);
        iter_b = (int)(in->len * WORD_BIT_LENGTH * 0.9) - iter_max;

        int_get_naf_extra_add(in, naf, precomp->ctx.win->win_width, &iter_p);

        do {
            for (i = 0; i < iter_max && iter_p >= 0; ++i) {
                if (naf[i] != 0) {
                    ecp_dual_mul_opt_step(ctx, precomp, in, naf, buf, i, iter_max);
                    --iter_p;
                }
            }
        } while (iter_p >= 0);

        for (; iter_b >= 0; --iter_b) {
            ecp_double_point(ctx, buf, buf);
        }
    }
}


int ecp_dual_mul_opt(EcGfpCtx *ctx, const EcPrecomp *p_precomp, const WordArray *m,
        const EcPrecomp *q_precomp, const WordArray *n, ECPoint *r)
{
    int *n_naf = NULL;
    int *m_naf = NULL;
    int iter_max;
    int iter_q = 0;
    int i;
    int ret = RET_OK;
    ECPoint *tmp = NULL;

    ASSERT(ctx != NULL);
    ASSERT(p_precomp != NULL);
    ASSERT(m != NULL);
    ASSERT(r != NULL);
    ASSERT(ctx->len == r->x->len);

    CHECK_NOT_NULL(tmp = ec_point_copy_with_alloc(r));

    int iter_p = 0;
    int m_bit_len = 8 * (int) ctx->len * sizeof(word_t);

    if (p_precomp != NULL) {
        if (p_precomp->type == EC_PRECOMP_TYPE_COMB) {
            iter_p = (m_bit_len + p_precomp->ctx.comb->comb_width - 1) / p_precomp->ctx.comb->comb_width - 1;
        } else if (p_precomp->type == EC_PRECOMP_TYPE_WIN) {
            ASSERT(m != NULL);
            ASSERT(ctx->len == p_precomp->ctx.win->precomp[0]->x->len);

            iter_p = (int)int_bit_len(m);
            DO(int_get_naf(m, p_precomp->ctx.win->win_width, &m_naf));
            for (; (m_naf[iter_p] == 0) && (iter_p > 0); iter_p--);
        }
    }

    if (q_precomp != NULL) {
        if (q_precomp->type == EC_PRECOMP_TYPE_COMB) {
            iter_q = (m_bit_len + q_precomp->ctx.comb->comb_width - 1) / q_precomp->ctx.comb->comb_width - 1;
        } else if (q_precomp->type == EC_PRECOMP_TYPE_WIN) {
            ASSERT(n != NULL);
            ASSERT(ctx->len == q_precomp->ctx.win->precomp[0]->x->len);

            iter_q = (int)int_bit_len(n);
            DO(int_get_naf(n, q_precomp->ctx.win->win_width, &n_naf));
            for (; (n_naf[iter_q] == 0) && (iter_q > 0); iter_q--);
        }
    }

    iter_max = (iter_p > iter_q) ? iter_p : iter_q;

    ecp_point_zero(ctx, r);

    for (i = iter_max; i >= 0; i--) {
        ecp_double_point(ctx, r, r);

        if (p_precomp != NULL) {
            ecp_dual_mul_opt_step(ctx, p_precomp, m, m_naf, r, i, iter_p);
        }

        if (n != NULL) {
            if (q_precomp != NULL) {
                ecp_dual_mul_opt_step(ctx, q_precomp, n, n_naf, r, i, iter_q);
            }
        }
    }

    ecp_dual_mul_opt_extra_addition(ctx, p_precomp, m, m_naf, tmp);
    ecp_dual_mul_opt_extra_addition(ctx, q_precomp, n, n_naf, tmp);

    ecp_point_to_affine(ctx, r);

cleanup:

    ec_point_free(tmp);
    free(n_naf);
    free(m_naf);

    return ret;
}

void ecp_free(EcGfpCtx *ctx)
{
    if (ctx) {
        gfp_free(ctx->gfp);
        wa_free(ctx->a);
        wa_free(ctx->b);
        free(ctx);
    }
}
