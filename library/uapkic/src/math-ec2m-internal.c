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

#define FILE_MARKER "uapkic/math-ec2m-internal.c"

#include "math-ec2m-internal.h"
#include "math-int-internal.h"
#include "macros-internal.h"

static int ec2m_points_to_affine(EcGf2mCtx *ctx, ECPoint **array, int off, int len)
{
    /* Получить a0, a0*a1, ..., a0*...*aN. */
    WordArray **k = NULL;
    WordArray *t = NULL;
    int i;
    int ret = RET_OK;

    CALLOC_CHECKED(k, len * sizeof(WordArray *));
    CHECK_NOT_NULL(k[0] = wa_alloc(ctx->len));
    CHECK_NOT_NULL(t = wa_alloc(ctx->len));

    DO(wa_copy(array[off]->z, k[0]));

    for (i = 1; i < len; i++) {
        CHECK_NOT_NULL(k[i] = wa_alloc(ctx->len));
        gf2m_mod_mul(ctx->gf2m, array[i + off]->z, k[i - 1], k[i]);
    }

    /* inv = (a0*...*aN)^(-1). */
    gf2m_mod_inv(ctx->gf2m, k[len - 1], t);

    /* k[i] = ai^(-1) i = 0, 1, ... */
    for (i = len - 1; i > 0; i--) {
        gf2m_mod_mul(ctx->gf2m, t, k[i - 1], k[i]);
        gf2m_mod_mul(ctx->gf2m, t, array[i + off]->z, t);
    }
    wa_copy(t, k[0]);

    for (i = 0; i < len; i++) {
        gf2m_mod_mul(ctx->gf2m, array[i + off]->x, k[i], array[i + off]->x);
        gf2m_mod_sqr(ctx->gf2m, k[i], k[i]);
        gf2m_mod_mul(ctx->gf2m, array[i + off]->y, k[i], array[i + off]->y);
        wa_one(array[i + off]->z);
    }

cleanup:

    for (i = 0; i < len; i++) {
        wa_free(k[i]);
    }
    free(k);
    wa_free(t);

    return ret;
}

EcGf2mCtx *ec2m_alloc(const int *f, size_t f_len, size_t a, const WordArray *b)
{
    int ret = RET_OK;
    EcGf2mCtx *ctx = NULL;

    CHECK_PARAM(f != NULL);
    CHECK_PARAM(b != NULL);
    CHECK_PARAM((f_len == 3 || f_len == 5));

    CALLOC_CHECKED(ctx, sizeof(EcGf2mCtx));

    ec2m_init(ctx, f, f_len, a, b);
cleanup:
    return ctx;
}

void ec2m_init(EcGf2mCtx *ctx, const int *f, size_t f_len, size_t a, const WordArray *b)
{
    int ret = RET_OK;

    ASSERT(ctx != NULL);
    ASSERT(f != NULL);
    ASSERT(b != NULL);

    CHECK_NOT_NULL(ctx->gf2m = gf2m_alloc(f, f_len));
    ctx->len = ctx->gf2m->len;
    ctx->a = a;
    CHECK_NOT_NULL(ctx->b = wa_copy_with_alloc(b));
    wa_change_len(ctx->b, ctx->len);

cleanup:

    return;
}

bool ec2m_is_on_curve(const EcGf2mCtx *ctx, const WordArray *px, const WordArray *py)
{
    WordArray *t1 = NULL;
    WordArray *t2 = NULL;
    bool answ = false;
    int ret = RET_OK;

    ASSERT(ctx != NULL);
    ASSERT(px != NULL);
    ASSERT(py != NULL);
    ASSERT(ctx->len == px->len);
    ASSERT(ctx->len == py->len);

    CHECK_NOT_NULL(t1 = wa_alloc(ctx->len));
    CHECK_NOT_NULL(t2 = wa_alloc(ctx->len));

    gf2m_mod_add(px, py, t1);
    gf2m_mod_mul(ctx->gf2m, t1, py, t1);

    gf2m_mod_sqr(ctx->gf2m, px, t2);
    if (ctx->a == 1) {
        gf2m_mod_add(t1, t2, t1);
    }

    gf2m_mod_mul(ctx->gf2m, px, t2, t2);
    gf2m_mod_add(t1, t2, t1);
    gf2m_mod_add(t1, ctx->b, t1);

    answ = int_is_zero(t1);

    wa_free(t1);
    wa_free(t2);
cleanup:
    return answ;
}

/**
 * Удваивает точку эллиптической кривой.
 *
 * @param ctx контекст группы точек эллиптической кривой
 * @param p точка эллиптической кривой
 * @param r = 2*p
 */
void ec2m_double(const EcGf2mCtx *ctx, const ECPoint *p, ECPoint *r)
{
    WordArray *t1 = NULL;
    WordArray *t2 = NULL;
    int ret = RET_OK;

    ASSERT(ctx != NULL);
    ASSERT(p != NULL);
    ASSERT(r != NULL);
    ASSERT(ctx->len == p->x->len);
    ASSERT(ctx->len == r->x->len);

    if (int_is_zero(p->x)) {
        /* точка на бесконечности */
        ec_point_zero(r);
        return;
    }

    CHECK_NOT_NULL(t1 = wa_alloc(ctx->len));
    CHECK_NOT_NULL(t2 = wa_alloc(ctx->len));

    gf2m_mod_sqr(ctx->gf2m, p->x, t1);
    gf2m_mod_sqr(ctx->gf2m, p->z, r->z);
    gf2m_mod_sqr(ctx->gf2m, r->z, t2);
    gf2m_mod_mul(ctx->gf2m, t2, ctx->b, t2);
    gf2m_mod_mul(ctx->gf2m, t1, r->z, r->z);

    gf2m_mod_sqr(ctx->gf2m, t1, t1);
    gf2m_mod_add(t1, t2, r->x);

    gf2m_mod_sqr(ctx->gf2m, p->y, t1);
    gf2m_mod_add(t1, t2, t1);
    if (ctx->a == 1) {
        gf2m_mod_add(t1, r->z, t1);
    }

    gf2m_mod_mul(ctx->gf2m, r->x, t1, t1);
    gf2m_mod_mul(ctx->gf2m, r->z, t2, r->y);
    gf2m_mod_add(r->y, t1, r->y);
cleanup:
    wa_free(t1);
    wa_free(t2);
}

/**
 * Складывает две точки эллиптической кривой.
 *
 * @param ctx контекст группы точек эллиптической кривой
 * @param p точка эллиптической кривой
 * @param qx X-координата точки Q представленной в аффинных координатах
 * @param qy Y-координата точки Q представленной в аффинных координатах
 * @param sign = -1 або 1
 * @param r  = P + sign * Q
 */
void ec2m_add(const EcGf2mCtx *ctx, const ECPoint *p, const WordArray *qx, const WordArray *qy, int sign, ECPoint *r)
{
    WordArray *t1 = NULL;
    WordArray *t2 = NULL;
    WordArray *t3 = NULL;
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

    /* Q == O ? */
    if (int_is_zero(qx) && int_is_zero(qy)) {
        ec_point_copy(p, r);
        return;
    }

    /* P == O ? */
    if (int_is_zero(p->x) && int_is_zero(p->y)) {
        wa_copy(qx, r->x);

        if (sign == 1) {
            wa_copy(qy, r->y);
        } else {
            gf2m_mod_add(qx, qy, r->y);
        }

        wa_one(r->z);

        return;
    }

    CHECK_NOT_NULL(t1 = wa_alloc(ctx->len));
    CHECK_NOT_NULL(t2 = wa_alloc(ctx->len));
    CHECK_NOT_NULL(t3 = wa_alloc(ctx->len));

    gf2m_mod_sqr(ctx->gf2m, p->z, t1);
    if (sign == -1) {
        gf2m_mod_add(qx, qy, t2);
        gf2m_mod_mul(ctx->gf2m, t2, t1, t1);
    } else {
        gf2m_mod_mul(ctx->gf2m, qy, t1, t1);
    }

    gf2m_mod_add(t1, p->y, t1);
    gf2m_mod_mul(ctx->gf2m, qx, p->z, t2);
    gf2m_mod_add(t2, p->x, t2);

    /* P == Q ? */
    if (int_is_zero(t1) && int_is_zero(t2)) {
        ec2m_double(ctx, p, r);
        goto cleanup;
    }

    /* P і Q взаимно обратны. */
    if (int_is_zero(t2)) {
        ec_point_zero(r);
        goto cleanup;
    }

    gf2m_mod_mul(ctx->gf2m, t2, p->z, t3);
    gf2m_mod_sqr(ctx->gf2m, t3, r->z);

    gf2m_mod_sqr(ctx->gf2m, t2, t2);
    gf2m_mod_add(t1, t2, t2);
    if (ctx->a == 1) {
        gf2m_mod_add(t2, t3, t2);
    }

    gf2m_mod_mul(ctx->gf2m, t3, t2, t2);
    gf2m_mod_sqr(ctx->gf2m, t1, r->x);
    gf2m_mod_add(r->x, t2, r->x);

    if (sign == 1) {
        gf2m_mod_add(qx, qy, t2);
    } else {
        wa_copy(qy, t2);
    }
    gf2m_mod_sqr(ctx->gf2m, r->z, r->y);
    gf2m_mod_mul(ctx->gf2m, t2, r->y, r->y);

    gf2m_mod_mul(ctx->gf2m, qx, r->z, t2);
    gf2m_mod_add(t2, r->x, t2);

    gf2m_mod_mul(ctx->gf2m, t3, t1, t1);
    gf2m_mod_add(t1, r->z, t1);

    gf2m_mod_mul(ctx->gf2m, t1, t2, t1);
    gf2m_mod_add(t1, r->y, r->y);

cleanup:

    wa_free(t1);
    wa_free(t2);
    wa_free(t3);
}

void ec2m_point_to_affine(const EcGf2mCtx *ctx, ECPoint *p)
{
    WordArray *t = NULL;
    int ret = RET_OK;

    ASSERT(ctx != NULL);
    ASSERT(p != NULL);
    ASSERT(ctx->len == p->x->len);

    if (int_is_zero(p->x) && int_is_zero(p->y)) {
        wa_one(p->z);
        return;
    }

    CHECK_NOT_NULL(t = wa_alloc(ctx->len));

    gf2m_mod_inv(ctx->gf2m, p->z, t);
    gf2m_mod_mul(ctx->gf2m, p->x, t, p->x);
    gf2m_mod_sqr(ctx->gf2m, t, t);
    gf2m_mod_mul(ctx->gf2m, p->y, t, p->y);
    wa_one(p->z);

cleanup:

    wa_free(t);
}

void ec2m_mul(EcGf2mCtx *ctx, const ECPoint *p, const WordArray *k, ECPoint *r)
{
    ECPoint *p_ptr = NULL;
    int len;
    int i;
    int ret = RET_OK;

    ASSERT(ctx != NULL);
    ASSERT(p != NULL);
    ASSERT(k != NULL);
    ASSERT(r != NULL);
    ASSERT(ctx->len == p->x->len);
    ASSERT(ctx->len == r->x->len);

    if (p == r) {
        CHECK_NOT_NULL(p_ptr = ec_point_copy_with_alloc(p));
    } else {
        p_ptr = (ECPoint *) p;
    }

    ec_point_zero(r);

    len = (int)int_bit_len(k);
    for (i = len - 1; i >= 0; i--) {
        ec2m_double(ctx, r, r);
        if (int_get_bit(k, i)) {
            ec2m_add(ctx, r, p_ptr->x, p_ptr->y, 1, r);
        }
    }

    ec2m_point_to_affine(ctx, r);

cleanup:

    if (p == r) {
        ec_point_free(p_ptr);
    }
}

int ec2m_calc_win_precomp(EcGf2mCtx *ctx, const ECPoint *p, int width, EcPrecomp **precomp1)
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
            ec_point_zero(precomp_win->precomp[i]);
        }

        CHECK_NOT_NULL(r = ec_point_copy_with_alloc(p));
        ec_point_copy(r, precomp_win->precomp[0]);

        ec2m_double(ctx, r, r);
        ec2m_point_to_affine(ctx, r);

        for (i = 1; i < precomp_len; i++) {
            ec2m_add(ctx, precomp_win->precomp[i - 1], r->x, r->y, 1, precomp_win->precomp[i]);
        }

        DO(ec2m_points_to_affine(ctx, precomp_win->precomp, 1, precomp_len - 1));
    }

    *precomp1 = precomp;

cleanup:

    ec_point_free(r);

    return ret;
}

int ec2m_calc_comb_precomp(EcGf2mCtx *ctx, const ECPoint *p, int width, EcPrecomp **precomp1)
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

        comb_step = (ctx->gf2m->f[0] + width - 1) / width;
        comb_len = (1 << width) - 1;

        CALLOC_CHECKED(comb->precomp, comb_len * sizeof(ECPoint *));
        for (i = 0; i < comb_len; i++) {
            comb->precomp[i] = ec_point_alloc(ctx->len);
            ec_point_zero(comb->precomp[i]);
        }

        CHECK_NOT_NULL(r = ec_point_copy_with_alloc(p));
        ec_point_copy(r, comb->precomp[0]);

        for (i = 1; i < width; i++) {
            for (j = 0; j < comb_step; j++) {
                ec2m_double(ctx, r, r);
            }
            ec_point_copy(r, comb->precomp[(1 << i) - 1]);
            ec2m_point_to_affine(ctx, comb->precomp[(1 << i) - 1]);
        }

        for (i = 2; i < comb_len; i++) {
            for (j = 0; j < width; j++) {
                int power_precomp_ind = (1 << j) - 1;
                if ((((i + 1) >> j) & 1) && (i != power_precomp_ind)) {
                    ec2m_add(ctx, comb->precomp[i], comb->precomp[power_precomp_ind]->x, comb->precomp[power_precomp_ind]->y, 1,
                            comb->precomp[i]);
                }
            }
            ec2m_point_to_affine(ctx, comb->precomp[i]);
        }
    }

    *precomp1 = precomp;

cleanup:

    ec_point_free(r);

    return ret;
}

void ec2m_dual_mul(const EcGf2mCtx *ctx, const ECPoint *p, const WordArray *m,
        const ECPoint *q, const WordArray *n, ECPoint *r)
{
    int len;
    int mlen;
    int nlen = 0;
    int i;

    ASSERT(ctx != NULL);
    ASSERT(p != NULL);
    ASSERT(m != NULL);
    ASSERT(ctx->len == p->x->len);
    ASSERT(ctx->len == r->x->len);

    if (q != NULL) {
        ASSERT(n != NULL);
        ASSERT(ctx->len == q->x->len);

        nlen = (int)int_bit_len(n);
    }

    ec_point_zero(r);

    mlen = (int)int_bit_len(m);
    len = (mlen > nlen) ? mlen : nlen;
    for (i = len - 1; i >= 0; i--) {
        ec2m_double(ctx, r, r);
        if (int_get_bit(m, i)) {
            ec2m_add(ctx, r, p->x, p->y, 1, r);
        }

        if (n != NULL && q != NULL && int_get_bit(n, i)) {
            ec2m_add(ctx, r, q->x, q->y, 1, r);
        }
    }

    ec2m_point_to_affine(ctx, r);
}

static void ec2m_dual_mul_opt_step(const EcGf2mCtx *ctx, const EcPrecomp *p_precomp, const WordArray *m, int *m_naf,
        ECPoint *r, int iter, int max_iter)
{
    int comb_ind;
    int comb_bit;
    int j;

    if (p_precomp->type == EC_PRECOMP_TYPE_WIN) {
        int nafi = m_naf[iter];
        if (nafi > 0) {
            ec2m_add(ctx, r, p_precomp->ctx.win->precomp[(nafi - 1) >> 1]->x, p_precomp->ctx.win->precomp[(nafi - 1) >> 1]->y, 1,
                    r);
        } else if (nafi < 0) {
            ec2m_add(ctx, r, p_precomp->ctx.win->precomp[(-nafi - 1) >> 1]->x, p_precomp->ctx.win->precomp[(-nafi - 1) >> 1]->y, -1,
                    r);
        }
    } else if (p_precomp->type == EC_PRECOMP_TYPE_COMB) {
        if (iter <= max_iter && m != NULL) {
            comb_ind = 0;
            comb_bit = iter;
            int comb_step = (ctx->gf2m->f[0] + p_precomp->ctx.comb->comb_width - 1) / p_precomp->ctx.comb->comb_width;

            for (j = 0; comb_bit < ctx->gf2m->f[0]; j++) {
                comb_ind |= int_get_bit(m, comb_bit) << j;
                comb_bit += comb_step;
            }

            if (comb_ind > 0) {
                ec2m_add(ctx, r, p_precomp->ctx.comb->precomp[comb_ind - 1]->x, p_precomp->ctx.comb->precomp[comb_ind - 1]->y, 1, r);
            }
        }
    }
}

static void ec2m_dual_mul_opt_extra_addition(const EcGf2mCtx *ctx, const EcPrecomp *precomp, const WordArray *in, int *naf, ECPoint *buf)
{
    int iter_p = 0;
    int iter_b = 0;
    int iter_max = 0;
    int i = 0;

    if (ctx != NULL && buf != NULL && in != NULL && precomp != NULL && precomp->type == EC_PRECOMP_TYPE_WIN) {
        iter_max = (int)int_bit_len(in);
        iter_b = (int)(ctx->gf2m->f[0] * 0.9) - iter_max;

        int_get_naf_extra_add(in, naf, precomp->ctx.win->win_width, &iter_p);

        do {
            for (i = 0; i < iter_max && iter_p >= 0; ++i) {
                if (naf[i] != 0) {
                    ec2m_dual_mul_opt_step(ctx, precomp, in, naf, buf, i, iter_max);
                    --iter_p;
                }
            }
        } while (iter_p >= 0);

        for (; iter_b >= 0; --iter_b) {
            ec2m_double(ctx, buf, buf);
        }
    }
}

int ec2m_dual_mul_opt(const EcGf2mCtx *ctx, const EcPrecomp *p_precomp, const WordArray *m,
        const EcPrecomp *q_precomp, const WordArray *n, ECPoint *r)
{
    int *n_naf = NULL;
    int *m_naf = NULL;
    int iter_max = 0;
    int iter_q = 0;
    int i = 0;
    int ret = RET_OK;
    ECPoint *tmp = NULL;

    ASSERT(ctx != NULL);
    ASSERT(p_precomp != NULL);
    ASSERT(m != NULL);
    ASSERT(ctx->len == r->x->len);

    CHECK_NOT_NULL(tmp = ec_point_copy_with_alloc(r));

    int iter_p = 0;
    int m_bit_len = ctx->gf2m->f[0];

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

    ec_point_zero(r);

    for (i = iter_max; i >= 0; i--) {
        ec2m_double(ctx, r, r);

        if (p_precomp != NULL) {
            ec2m_dual_mul_opt_step(ctx, p_precomp, m, m_naf, r, i, iter_p);
        }

        if (n != NULL) {
            if (q_precomp != NULL) {
                ec2m_dual_mul_opt_step(ctx, q_precomp, n, n_naf, r, i, iter_q);
            }
        }
    }

    //Дополнительные операции для размазывания времени у "слабых" naf ключей
    ec2m_dual_mul_opt_extra_addition(ctx, p_precomp, m, m_naf, tmp);
    ec2m_dual_mul_opt_extra_addition(ctx, q_precomp, n, n_naf, tmp);

    ec2m_point_to_affine(ctx, r);

cleanup:

    ec_point_free(tmp);
    free(n_naf);
    free(m_naf);

    return ret;
}

EcGf2mCtx *ec2m_copy_with_alloc(EcGf2mCtx *ctx)
{
    int ret = RET_OK;
    EcGf2mCtx *ctx_copy = NULL;

    CHECK_PARAM(ctx != NULL);

    CALLOC_CHECKED(ctx_copy, sizeof(EcGf2mCtx));

    ctx_copy->a = ctx->a;
    ctx_copy->len = ctx->len;

    CHECK_NOT_NULL(ctx_copy->b = wa_copy_with_alloc(ctx->b));
    CHECK_NOT_NULL(ctx_copy->gf2m = gf2m_copy_with_alloc(ctx->gf2m));

    return ctx_copy;

cleanup:

    ec2m_free(ctx_copy);

    return NULL;
}

void ec2m_free(EcGf2mCtx *ctx)
{
    if (ctx) {
        gf2m_free(ctx->gf2m);
        wa_free(ctx->b);
        free(ctx);
    }
}
