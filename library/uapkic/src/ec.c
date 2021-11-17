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
#include "ec-internal.h"
#include "ec-cache-internal.h"
#include "math-ecp-internal.h"
#include "math-ec2m-internal.h"
#include "math-int-internal.h"
#include "macros-internal.h"

#undef FILE_MARKER
#define FILE_MARKER "uapkic/ec_params.c"

static void ec_params_free(EcParamsCtx* params)
{
    size_t i;

    if (params != NULL) {
        wa_free(params->n);
        ec_point_free(params->p);
        if (params->ec_field == EC_FIELD_BINARY) {
            ec2m_free(params->ec2m);
            if (params->to_pb) {
                for (i = 0; i < params->m; i++) {
                    wa_free(params->to_pb[i]);
                }
                free(params->to_pb);
            }
            if (params->to_onb) {
                for (i = 0; i < params->m; i++) {
                    wa_free(params->to_onb[i]);
                }
                free(params->to_onb);
            }
        }
        else {
            ecp_free(params->ecp);
        }

        ec_precomp_free(params->precomp_p);

        free(params);
    }
}

static EcParamsCtx* ec_params_alloc_prime(const ByteArray* p, const ByteArray* a, const ByteArray* b,
    const ByteArray* q, const ByteArray* px, const ByteArray* py)
{
    WordArray* wa = NULL;
    WordArray* wb = NULL;
    WordArray* wp = NULL;
    WordArray* wpx = NULL;
    WordArray* wpy = NULL;
    size_t len;
    int ret = RET_OK;
    EcParamsCtx* params = NULL;

    CALLOC_CHECKED(params, sizeof(EcParamsCtx));

    params->ec_field = EC_FIELD_PRIME;
    params->is_onb = false;

    CHECK_NOT_NULL(wp = wa_alloc_from_ba(p));
    len = WA_LEN_FROM_BITS(int_bit_len(wp));
    wa_change_len(wp, len);

    CHECK_NOT_NULL(wa = wa_alloc_from_ba(a));
    wa_change_len(wa, len);

    CHECK_NOT_NULL(wb = wa_alloc_from_ba(b));
    wa_change_len(wb, len);

    CHECK_NOT_NULL(params->ecp = ecp_alloc(wp, wa, wb));

    CHECK_NOT_NULL(params->n = wa_alloc_from_ba(q));
    wa_change_len(params->n, WA_LEN_FROM_BITS(int_bit_len(params->n)));

    CHECK_NOT_NULL(wpx = wa_alloc_from_ba(px));
    wa_change_len(wpx, len);

    CHECK_NOT_NULL(wpy = wa_alloc_from_ba(py));
    wa_change_len(wpy, len);

    CHECK_NOT_NULL(params->p = ec_point_aff_alloc(wpx, wpy));

cleanup:

    if (ret != RET_OK) {
        ec_params_free(params);
        params = NULL;
    }

    wa_free(wa);
    wa_free(wb);
    wa_free(wp);
    wa_free(wpx);
    wa_free(wpy);

    return params;
}

EcCtx* ec_alloc_prime(const ByteArray* p, const ByteArray* a, const ByteArray* b, const ByteArray* q,
    const ByteArray* px, const ByteArray* py)
{
    EcCtx* ctx;

    ctx = ec_cache_get_ecp(p, a, b, q, px, py);
    if (ctx != NULL) {
        return ctx;
    }

    return ec_alloc_prime_new(p, a, b, q, px, py);

}

EcCtx* ec_alloc_prime_new(const ByteArray* p, const ByteArray* a, const ByteArray* b, const ByteArray* q,
    const ByteArray* px, const ByteArray* py)
{
    EcCtx* ctx = NULL;
    int ret = RET_OK;

    CHECK_PARAM(p != NULL);
    CHECK_PARAM(a != NULL);
    CHECK_PARAM(b != NULL);
    CHECK_PARAM(q != NULL);
    CHECK_PARAM(px != NULL);
    CHECK_PARAM(py != NULL);

    CALLOC_CHECKED(ctx, sizeof(EcCtx));
    CHECK_NOT_NULL(ctx->params = ec_params_alloc_prime(p, a, b, q, px, py));

    ctx->priv_key = NULL;
    ctx->pub_key = NULL;
    ctx->sign_status = false;
    ctx->verify_status = false;

cleanup:

    if (ret != RET_OK) {
        ec_free(ctx);
        ctx = NULL;
    }

    return ctx;
}

static EcParamsCtx* ec_params_alloc_binary(const int* f, size_t f_len, size_t a, const ByteArray* b,
    const ByteArray* n, const ByteArray* px, const ByteArray* py, bool is_onb)
{
    EcParamsCtx* params = NULL;
    WordArray* px_wa = NULL;
    WordArray* py_wa = NULL;
    WordArray* b_wa = NULL;
    ByteArray* qx = NULL;
    ByteArray* qy = NULL;
    int ret = RET_OK;

    CHECK_PARAM(f != NULL);
    CHECK_PARAM(f_len == 3 || f_len == 5);
    CHECK_PARAM(b != NULL);
    CHECK_PARAM(n != NULL);
    CHECK_PARAM(px != NULL);

    CALLOC_CHECKED(params, sizeof(EcParamsCtx));

    params->ec_field = EC_FIELD_BINARY;
    params->is_onb = is_onb;

    CHECK_NOT_NULL(b_wa = wa_alloc_from_ba(b));
    CHECK_NOT_NULL(params->ec2m = ec2m_alloc(f, f_len, a, b_wa));

    CHECK_NOT_NULL(params->n = wa_alloc_from_ba(n));
    wa_change_len(params->n, WA_LEN_FROM_BITS(int_bit_len(params->n)));
    params->m = f[0];

    if (is_onb) {
        init_onb_params(params, f[0]);

        /* b принадлежит GF(2^m). */
        if (int_bit_len(params->ec2m->b) > params->m) {
            SET_ERROR(RET_INVALID_EC_PARAMS);
        }
        DO(onb_to_pb(params, params->ec2m->b));
    }

    /* Инициализация базовой точки. */
    if (py == NULL) {
        DO(ec2m_decompress_point_core(params, px, 0, &qx, &qy));
        CHECK_NOT_NULL(px_wa = wa_alloc_from_ba(qx));
        CHECK_NOT_NULL(py_wa = wa_alloc_from_ba(qy));
    }
    else {
        CHECK_NOT_NULL(px_wa = wa_alloc_from_ba(px));
        CHECK_NOT_NULL(py_wa = wa_alloc_from_ba(py));
    }

    wa_change_len(px_wa, params->ec2m->len);
    wa_change_len(py_wa, params->ec2m->len);

    if (is_onb) {
        DO(onb_to_pb(params, px_wa));
        DO(onb_to_pb(params, py_wa));
    }
    CHECK_NOT_NULL(params->p = ec_point_aff_alloc(px_wa, py_wa));

    params->precomp_p = NULL;

cleanup:

    if (ret != RET_OK) {
        free(params);
        params = NULL;
    }

    wa_free(b_wa);
    wa_free(px_wa);
    wa_free(py_wa);

    ba_free(qx);
    ba_free(qy);

    return params;
}

EcCtx* ec_alloc_binary_pb_new(const int* f, size_t f_len, size_t a, const ByteArray* b, const ByteArray* n,
    const ByteArray* px, const ByteArray* py)
{
    int ret = RET_OK;
    EcCtx* ctx = NULL;

    CHECK_PARAM(f != NULL);
    CHECK_PARAM(b != NULL);
    CHECK_PARAM(n != NULL);
    CHECK_PARAM(px != NULL);

    CALLOC_CHECKED(ctx, sizeof(EcCtx));
    CHECK_NOT_NULL(ctx->params = ec_params_alloc_binary(f, f_len, a, b, n, px, py, false));

cleanup:

    if (ret != RET_OK) {
        ec_free(ctx);
        ctx = NULL;
    }

    return ctx;
}

EcCtx* ec_alloc_binary_pb(const int* f, size_t f_len, size_t a, const ByteArray* b, const ByteArray* n,
    const ByteArray* px, const ByteArray* py)
{
    EcCtx* ctx;

    ctx = ec_cache_get_ec2m_pb(f, f_len, a, b, n, px, py);
    if (ctx != NULL) {
        return ctx;
    }

    return ec_alloc_binary_pb_new(f, f_len, a, b, n, px, py);
}

EcCtx* ec_alloc_binary_onb_new(size_t m, size_t a, const ByteArray* b, const ByteArray* n,
    const ByteArray* px, const ByteArray* py)
{
    int ret = RET_OK;
    EcCtx* ctx = NULL;

    CHECK_PARAM(b != NULL);
    CHECK_PARAM(n != NULL);
    CHECK_PARAM(px != NULL);
    CHECK_PARAM(py != NULL);

    CALLOC_CHECKED(ctx, sizeof(EcCtx));

    const int* f = get_defaut_f_onb(m);
    CHECK_PARAM(f != NULL);

    CHECK_NOT_NULL(ctx->params = ec_params_alloc_binary(f, 5, a, b, n, px, py, true));

cleanup:

    if (ret != RET_OK) {
        ec_free(ctx);
        ctx = NULL;
    }

    return ctx;
}

EcCtx* ec_alloc_binary_onb(size_t m, size_t a, const ByteArray* b, const ByteArray* n, const ByteArray* px, const ByteArray* py)
{
    EcCtx* ctx;

    ctx = ec_cache_get_ec2m_onb(m, a, b, n, px, py);
    if (ctx != NULL) {
        return ctx;
    }

    return ec_alloc_binary_onb_new(m, a, b, n, px, py);
}

EcCtx* ec_alloc_new(EcParamsId params_id)
{
    const void* def_params;
    EcFieldType field_type;
    ByteArray* a = NULL;
    ByteArray* b = NULL;
    ByteArray* p = NULL;
    ByteArray* n = NULL;
    ByteArray* px = NULL;
    ByteArray* py = NULL;
    EcCtx* ctx = NULL;
    int ret = RET_OK;

    CHECK_NOT_NULL(def_params = ec_get_defaut_params(params_id, &field_type));

    if (field_type == EC_FIELD_PRIME) {
        const EcpDefaultParamsCtx* def_paramsp = def_params;
        CHECK_NOT_NULL(a = ba_alloc_from_uint8(def_paramsp->a, def_paramsp->len));
        CHECK_NOT_NULL(b = ba_alloc_from_uint8(def_paramsp->b, def_paramsp->len));
        CHECK_NOT_NULL(p = ba_alloc_from_uint8(def_paramsp->p, def_paramsp->len));
        CHECK_NOT_NULL(n = ba_alloc_from_uint8(def_paramsp->n, def_paramsp->len));
        CHECK_NOT_NULL(px = ba_alloc_from_uint8(def_paramsp->px, def_paramsp->len));
        CHECK_NOT_NULL(py = ba_alloc_from_uint8(def_paramsp->py, def_paramsp->len));
        CHECK_NOT_NULL(ctx = ec_alloc_prime(p, a, b, n, px, py));
    }
    else {
        int len;

        const Ec2mDefaultParamsCtx* def_params2m = def_params;

        len = (def_params2m->f[0] + 7) / 8;
        CHECK_NOT_NULL(b = ba_alloc_from_uint8(def_params2m->b, len));
        CHECK_NOT_NULL(n = ba_alloc_from_uint8(def_params2m->n, len)); // довжина n може бути меншою, як у випадку 257, тому необхідно доповнювати 0 до довжини полінома
        CHECK_NOT_NULL(px = ba_alloc_from_uint8(def_params2m->px, len));
        CHECK_NOT_NULL(py = ba_alloc_from_uint8(def_params2m->py, len));

        ctx = (def_params2m->is_onb)
            ? ec_alloc_binary_onb(def_params2m->f[0], def_params2m->a, b, n, px, py)
            : ec_alloc_binary_pb(def_params2m->f, 5, def_params2m->a, b, n, px, py);
        CHECK_NOT_NULL(ctx);
    }

    ctx->params->params_id = params_id;

cleanup:

    ba_free(a);
    ba_free(b);
    ba_free(p);
    ba_free(n);
    ba_free(px);
    ba_free(py);
    if (ret != RET_OK) {
        ec_free(ctx);
        ctx = NULL;
    }

    return ctx;
}

EcCtx* ec_alloc_default(EcParamsId params_id)
{
    EcCtx* ctx;

    ctx = ec_cache_get_default(params_id);
    if (ctx != NULL) {
        return ctx;
    }

    return ec_alloc_new(params_id);
}

void ec_free(EcCtx* ctx)
{
    if (ctx) {
        wa_free_private(ctx->priv_key);
        ec_params_free(ctx->params);
        ec_point_free(ctx->pub_key);
        ec_precomp_free(ctx->precomp_q);
        free(ctx);
    }
}

int ec_set_sign_precomp(const EcCtx* ctx, int sign_comb_opt_level, int sign_win_opt_level)
{
    EcParamsCtx* params = NULL;
    int ret = RET_OK;

    params = ctx->params;

    if (sign_comb_opt_level == 0 && sign_win_opt_level == 0) {
        if (default_opt_level != 0) {
            sign_comb_opt_level = (default_opt_level >> 12) & 0x0f;
            sign_win_opt_level = (default_opt_level >> 8) & 0x0f;
        }
        else {
            sign_win_opt_level = EC_DEFAULT_WIN_WIDTH;
        }
    }

    if (sign_comb_opt_level > 0) {
        if (params->precomp_p == NULL || params->precomp_p->type != EC_PRECOMP_TYPE_COMB
            || params->precomp_p->ctx.comb->comb_width != sign_comb_opt_level) {
            ec_precomp_free(params->precomp_p);
            params->precomp_p = NULL;
            if (params->ec_field == EC_FIELD_BINARY) {
                DO(ec2m_calc_comb_precomp(params->ec2m, params->p, sign_comb_opt_level, &params->precomp_p));
            }
            else {
                DO(ecp_calc_comb_precomp(params->ecp, params->p, sign_comb_opt_level, &params->precomp_p));
            }
        }
    }
    else if (sign_win_opt_level > 0) {
        if (params->precomp_p == NULL || params->precomp_p->type != EC_PRECOMP_TYPE_WIN
            || params->precomp_p->ctx.win->win_width != sign_win_opt_level) {
            ec_precomp_free(params->precomp_p);
            params->precomp_p = NULL;
            if (params->ec_field == EC_FIELD_BINARY) {
                DO(ec2m_calc_win_precomp(params->ec2m, params->p, sign_win_opt_level, &params->precomp_p));
            }
            else {
                DO(ecp_calc_win_precomp(params->ecp, params->p, sign_win_opt_level, &params->precomp_p));
            }
        }
    }

cleanup:

    return ret;
}

int ec_set_verify_precomp(EcCtx* ctx, int verify_comb_opt_level, int verify_win_opt_level)
{
    EcParamsCtx* params = NULL;
    int ret = RET_OK;

    params = ctx->params;

    if (verify_comb_opt_level == 0 && verify_win_opt_level == 0) {
        if (default_opt_level != 0) {
            verify_comb_opt_level = (default_opt_level >> 4) & 0x0f;
            verify_win_opt_level = default_opt_level & 0x0f;
        }
        else {
            verify_win_opt_level = EC_DEFAULT_WIN_WIDTH;
        }
    }

    if (verify_comb_opt_level > 0) {
        if (ctx->precomp_q == NULL || ctx->precomp_q->type != EC_PRECOMP_TYPE_COMB
            || ctx->precomp_q->ctx.comb->comb_width != verify_comb_opt_level) {
            ec_precomp_free(ctx->precomp_q);
            ctx->precomp_q = NULL;
            if (params->ec_field == EC_FIELD_BINARY) {
                DO(ec2m_calc_comb_precomp(params->ec2m, ctx->pub_key, verify_comb_opt_level, &ctx->precomp_q));
            }
            else {
                DO(ecp_calc_comb_precomp(params->ecp, ctx->pub_key, verify_comb_opt_level, &ctx->precomp_q));
            }
        }
    }
    else if (verify_win_opt_level > 0) {
        if (ctx->precomp_q == NULL || ctx->precomp_q->type != EC_PRECOMP_TYPE_WIN
            || ctx->precomp_q->ctx.win->win_width != verify_win_opt_level) {
            ec_precomp_free(ctx->precomp_q);
            ctx->precomp_q = NULL;
            if (params->ec_field == EC_FIELD_BINARY) {
                DO(ec2m_calc_win_precomp(params->ec2m, ctx->pub_key, verify_win_opt_level, &ctx->precomp_q));
            }
            else {
                DO(ecp_calc_win_precomp(params->ecp, ctx->pub_key, verify_win_opt_level, &ctx->precomp_q));
            }
        }
    }

cleanup:

    return ret;
}

int ec_set_opt_level(EcCtx* ctx, OptLevelId opt_level)
{
    int ret = RET_OK;
    int sign_comb_opt_level;
    int sign_win_opt_level;
    int verify_comb_opt_level;
    int verify_win_opt_level;

    CHECK_PARAM(ctx != NULL);

    if (ctx->params == NULL) {
        SET_ERROR(RET_CONTEXT_NOT_READY);
    }

    sign_comb_opt_level = (opt_level >> 12) & 0x0f;
    sign_win_opt_level = (opt_level >> 8) & 0x0f;
    verify_comb_opt_level = (opt_level >> 4) & 0x0f;
    verify_win_opt_level = opt_level & 0x0f;

    CHECK_PARAM(sign_comb_opt_level == 0 || sign_win_opt_level == 0);
    CHECK_PARAM(sign_win_opt_level == 0 || (sign_win_opt_level & 1) == 1);
    CHECK_PARAM(verify_comb_opt_level == 0 || verify_win_opt_level == 0);
    CHECK_PARAM(verify_win_opt_level == 0 || (verify_win_opt_level & 1) == 1);

    DO(ec_set_sign_precomp(ctx, sign_comb_opt_level, sign_win_opt_level));
    DO(ec_set_verify_precomp(ctx, verify_comb_opt_level, verify_win_opt_level));

cleanup:

    return ret;
}

EcCtx* ec_copy_params_with_alloc(const EcCtx* param)
{
    int ret = RET_OK;
    size_t i;
    EcCtx* param_copy = NULL;

    CHECK_PARAM(param != NULL);

    CALLOC_CHECKED(param_copy, sizeof(EcCtx));
    CALLOC_CHECKED(param_copy->params, sizeof(EcParamsCtx));

    param_copy->params->ec_field = param->params->ec_field;
    param_copy->params->params_id = param->params->params_id;
    param_copy->params->is_onb = param->params->is_onb;
    param_copy->params->m = param->params->m;

    if (param->params->ec_field == EC_FIELD_BINARY) {
        CHECK_NOT_NULL(param_copy->params->ec2m = ec2m_copy_with_alloc(param->params->ec2m));

        if (param->params->to_onb) {
            MALLOC_CHECKED(param_copy->params->to_onb, param->params->m * sizeof(WordArray*));
            for (i = 0; i < param->params->m; i++) {
                param_copy->params->to_onb[i] = wa_copy_with_alloc(param->params->to_onb[i]);
            }
        }

        if (param->params->to_pb) {
            MALLOC_CHECKED(param_copy->params->to_pb, param->params->m * sizeof(WordArray*));
            for (i = 0; i < param->params->m; i++) {
                param_copy->params->to_pb[i] = wa_copy_with_alloc(param->params->to_pb[i]);
            }
        }
    }
    else {
        CHECK_NOT_NULL(param_copy->params->ecp = ecp_copy_with_alloc(param->params->ecp));
    }
    CHECK_NOT_NULL(param_copy->params->p = ec_point_copy_with_alloc(param->params->p));
    CHECK_NOT_NULL(param_copy->params->n = wa_copy_with_alloc(param->params->n));
    if (param->params->precomp_p) {
        CHECK_NOT_NULL(param_copy->params->precomp_p = ec_copy_precomp_with_alloc(param->params->precomp_p));
    }

    if (param->precomp_q != NULL) {
        int verify_comb_opt_level = (param->precomp_q->type == EC_PRECOMP_TYPE_COMB) ? param->precomp_q->ctx.comb->comb_width : 0;
        int verify_win_opt_level = (param->precomp_q->type == EC_PRECOMP_TYPE_WIN) ? param->precomp_q->ctx.win->win_width : 0;
        ec_set_verify_precomp(param_copy, verify_comb_opt_level, verify_win_opt_level);
    }

    return param_copy;

cleanup:

    ec_free(param_copy);

    return NULL;
}

EcCtx* ec_copy_with_alloc(const EcCtx* param)
{
    int ret = RET_OK;
    ByteArray* seed = NULL;
    EcCtx* param_copy = NULL;

    CHECK_PARAM(param != NULL);

    CHECK_NOT_NULL(param_copy = ec_copy_params_with_alloc(param));

    if (param->priv_key) {
        CHECK_NOT_NULL(param_copy->priv_key = wa_copy_with_alloc(param->priv_key));
    }
    if (param->pub_key) {
        CHECK_NOT_NULL(param_copy->pub_key = ec_point_copy_with_alloc(param->pub_key));
    }
    if (param->precomp_q) {
        if (param_copy->precomp_q) {
            ec_precomp_free(param_copy->precomp_q);
        }
        CHECK_NOT_NULL(param_copy->precomp_q = ec_copy_precomp_with_alloc(param->precomp_q));
    }

    param_copy->sign_status = param->sign_status;
    param_copy->verify_status = param->verify_status;

    ba_free_private(seed);

    return param_copy;

cleanup:

    ec_free(param_copy);
    ba_free_private(seed);

    return NULL;
}

int ec_equals_params(const EcCtx* param_a, const EcCtx* param_b, bool* equals)
{
    int f_len_a, f_len_b;
    int ret = RET_OK;

    CHECK_PARAM(param_a != NULL);
    CHECK_PARAM(param_b != NULL);
    CHECK_PARAM(equals != NULL);

    *equals = false;

    if (param_a->params->ec_field != param_b->params->ec_field) {
        return RET_OK;
    }

    if (param_a->params->ec_field == EC_FIELD_BINARY) {
        if (param_a->params->is_onb != param_b->params->is_onb) {
            *equals = false;
            return RET_OK;
        }

        f_len_a = (param_a->params->ec2m->gf2m->f[2] == 0) ? 3 : 5;
        f_len_b = (param_b->params->ec2m->gf2m->f[2] == 0) ? 3 : 5;

        if ((f_len_a != f_len_b)) {
            return RET_OK;
        }

        if (memcmp(param_a->params->ec2m->gf2m->f, param_b->params->ec2m->gf2m->f, f_len_a * sizeof(int))) {
            return RET_OK;
        }

        if (param_a->params->ec2m->a != param_b->params->ec2m->a) {
            return RET_OK;
        }

        if (wa_cmp(param_a->params->ec2m->b, param_b->params->ec2m->b)) {
            return RET_OK;
        }
    }
    else {
        if (wa_cmp(param_a->params->ecp->gfp->p, param_b->params->ecp->gfp->p)) {
            return RET_OK;
        }

        if (wa_cmp(param_a->params->ecp->a, param_b->params->ecp->a)) {
            return RET_OK;
        }

        if (wa_cmp(param_a->params->ecp->b, param_b->params->ecp->b)) {
            return RET_OK;
        }
    }
    if (wa_cmp(param_a->params->n, param_b->params->n)) {
        return RET_OK;
    }

    if (wa_cmp(param_a->params->p->x, param_b->params->p->x)) {
        return RET_OK;
    }

    if (wa_cmp(param_a->params->p->y, param_b->params->p->y)) {
        return RET_OK;
    }

    *equals = true;
cleanup:
    return ret;
}


int ec_is_onb_params(const EcCtx* ctx, bool* is_onb_params)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(is_onb_params != NULL);

    *is_onb_params = ctx->params->is_onb;

cleanup:

    return ret;
}

int ec_get_params(const EcCtx* ctx, EcFieldType* field_type, ByteArray** p, int** f, ByteArray** a, ByteArray** b, 
    ByteArray** n, ByteArray** px, ByteArray** py)
{
    int ret = RET_OK;
    WordArray* tmp = NULL;
    size_t params_len;

    CHECK_PARAM(ctx != NULL);
    *field_type = ctx->params->ec_field;

    if (EC_FIELD_PRIME == *field_type) {
        params_len = (int_bit_len(ctx->params->ecp->gfp->p) + 7) / 8;

        if (p) {
            CHECK_NOT_NULL(*p = wa_to_ba(ctx->params->ecp->gfp->p));
            DO(ba_change_len(*p, params_len));
        }

        if (a) {
            CHECK_NOT_NULL(*a = wa_to_ba(ctx->params->ecp->a));
            DO(ba_change_len(*a, params_len));
        }

        if (b) {
            CHECK_NOT_NULL(*b = wa_to_ba(ctx->params->ecp->b));
            DO(ba_change_len(*b, params_len));
        }
    }
    else {
        size_t len = (ctx->params->ec2m->gf2m->f[2] == 0 ? 3 : 5);
        params_len = ((size_t)ctx->params->ec2m->gf2m->f[0] + 7) >> 3;

        if (f) {
            MALLOC_CHECKED(*f, len * sizeof(int));
            memcpy(*f, ctx->params->ec2m->gf2m->f, len * sizeof(int));
        }

        if (a) {
            uint8_t tmp_a = (uint8_t) ctx->params->ec2m->a;
            CHECK_NOT_NULL(*a = ba_alloc_from_uint8(&tmp_a, 1));
        }

        if (b) {
            if (ctx->params->is_onb) {
                CHECK_NOT_NULL(tmp = wa_copy_with_alloc(ctx->params->ec2m->b));
                DO(pb_to_onb(ctx->params, tmp));
                CHECK_NOT_NULL(*b = wa_to_ba(tmp));
                wa_free(tmp);
                tmp = NULL;
            }
            else {
                CHECK_NOT_NULL(*b = wa_to_ba(ctx->params->ec2m->b));
            }
            DO(ba_change_len(*b, params_len));
        }
    }

    if (n) {
        CHECK_NOT_NULL(*n = wa_to_ba(ctx->params->n));
        DO(ba_change_len(*n, params_len));
    }

    if (px) {
        if (ctx->params->is_onb) {
            CHECK_NOT_NULL(tmp = wa_copy_with_alloc(ctx->params->p->x));
            DO(pb_to_onb(ctx->params, tmp));
            CHECK_NOT_NULL(*px = wa_to_ba(tmp));
            wa_free(tmp);
            tmp = NULL;
        }
        else {
            CHECK_NOT_NULL(*px = wa_to_ba(ctx->params->p->x));
        }
        DO(ba_change_len(*px, params_len));
    }

    if (py) {
        if (ctx->params->is_onb) {
            CHECK_NOT_NULL(tmp = wa_copy_with_alloc(ctx->params->p->y));
            DO(pb_to_onb(ctx->params, tmp));
            CHECK_NOT_NULL(*py = wa_to_ba(tmp));
        }
        else {
            CHECK_NOT_NULL(*py = wa_to_ba(ctx->params->p->y));
        }
        DO(ba_change_len(*py, params_len));
    }

cleanup:
    wa_free(tmp);

    return ret;
}

int public_key_to_ec_point(const EcParamsCtx* params, const ByteArray* qx, const ByteArray* qy, ECPoint** q)
{
    WordArray* wqx = NULL;
    WordArray* wqy = NULL;
    int ret = RET_OK;

    CHECK_PARAM(params != NULL);
    CHECK_PARAM(qx != NULL);
    CHECK_PARAM(qy != NULL);
    CHECK_PARAM(q != NULL);

    CHECK_NOT_NULL(wqx = wa_alloc_from_be(qx->buf, qx->len));
    CHECK_NOT_NULL(wqy = wa_alloc_from_be(qy->buf, qy->len));

    if (params->ec_field == EC_FIELD_PRIME) {
        if (int_cmp(wqx, params->ecp->gfp->p) >= 0 ||
            int_cmp(wqy, params->ecp->gfp->p) >= 0) {
            SET_ERROR(RET_INVALID_PUBLIC_KEY);
        }

        wa_change_len(wqx, params->ecp->len);
        wa_change_len(wqy, params->ecp->len);

        if (!ecp_is_on_curve(params->ecp, wqx, wqy)) {
            SET_ERROR(RET_INVALID_PUBLIC_KEY);
        }
    }
    else {
        if (int_bit_len(wqx) > params->m ||
            int_bit_len(wqy) > params->m) {
            SET_ERROR(RET_INVALID_PUBLIC_KEY);
        }

        wa_change_len(wqx, params->ec2m->len);
        wa_change_len(wqy, params->ec2m->len);

        if (params->is_onb) {
            DO(onb_to_pb(params, wqx));
            DO(onb_to_pb(params, wqy));
        }

        if (!ec2m_is_on_curve(params->ec2m, wqx, wqy)) {
            SET_ERROR(RET_INVALID_PUBLIC_KEY);
        }
    }

    CHECK_NOT_NULL(*q = ec_point_aff_alloc(wqx, wqy));

cleanup:

    wa_free(wqx);
    wa_free(wqy);

    return ret;
}

int ec_point_compress(const EcCtx* ctx, const ByteArray* qx, const ByteArray* qy, int* compressed_y)
{
    ECPoint* ec_point = NULL;
    WordArray* tmp = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(qx != NULL);
    CHECK_PARAM(qy != NULL);
    CHECK_PARAM(compressed_y != NULL);

    DO(public_key_to_ec_point(ctx->params, qx, qy, &ec_point));

    if (ctx->params->ec_field == EC_FIELD_PRIME) {
        *compressed_y = int_get_bit(ec_point->y, 0);
    }
    else {
        if (int_is_zero(ec_point->x)) {
            *compressed_y = 0;
        }
        else {
            CHECK_NOT_NULL(tmp = wa_alloc(ctx->params->ec2m->len));
            gf2m_mod_inv(ctx->params->ec2m->gf2m, ec_point->x, tmp);
            gf2m_mod_mul(ctx->params->ec2m->gf2m, tmp, ec_point->y, tmp);
            *compressed_y = int_get_bit(tmp, 0);
        }
    }

cleanup:

    wa_free(tmp);
    ec_point_free(ec_point);

    return ret;
}

int ec_point_decompress(const EcCtx* ctx, const ByteArray* q, int compressed_y, ByteArray** qy)
{
    WordArray* x = NULL;
    WordArray* y = NULL;
    size_t blen;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(qy != NULL);
    CHECK_PARAM(q != NULL);

    if (compressed_y != 0 && compressed_y != 1) {
        SET_ERROR(RET_INVALID_PARAM);
    }

    CHECK_NOT_NULL(x = wa_alloc_from_be(q->buf, q->len));

    if (ctx->params->ec_field == EC_FIELD_PRIME) {
        GfpCtx* gfp = ctx->params->ecp->gfp;
        wa_change_len(x, ctx->params->ecp->len);

        if (int_cmp(x, gfp->p) >= 0 || int_is_zero(x)) {
            SET_ERROR(RET_INVALID_PARAM);
        }

        CHECK_NOT_NULL(y = wa_alloc(ctx->params->ecp->len));
        gfp_mod_sqr(gfp, x, y);
        gfp_mod_add(gfp, y, ctx->params->ecp->a, y);
        gfp_mod_mul(gfp, x, y, y);
        gfp_mod_add(gfp, y, ctx->params->ecp->b, y);
        if (!gfp_mod_sqrt(gfp, y, y)) {
            SET_ERROR(RET_POINT_NOT_ON_CURVE);
        }

        if (int_get_bit(y, 0) != compressed_y) {
            gfp_mod_sub(gfp, gfp->p, y, y);
        }

        blen = (int_bit_len(gfp->p) + 7) / 8;

        *qy = wa_to_ba(y);
        DO(ba_change_len(*qy, blen));
        DO(ba_swap(*qy));
    }
    else {
        //!!!to be
        DO(ec2m_decompress_point_core(ctx->params, q, compressed_y, NULL, qy));
    }

cleanup:

    wa_free(x);
    wa_free(y);

    return ret;
}

int ec_init_sign(EcCtx* ctx, const ByteArray* d)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(d != NULL);

    if (ctx->params == NULL) {
        SET_ERROR(RET_CONTEXT_NOT_READY);
    }

    if (ctx->pub_key) {
        ctx->verify_status = false;
        ec_point_free(ctx->pub_key);
        ctx->pub_key = NULL;
    }

    if (ctx->precomp_q != NULL) {
        ec_precomp_free(ctx->precomp_q);
        ctx->precomp_q = NULL;
    }

    if (ctx->priv_key) {
        wa_free_private(ctx->priv_key);
        ctx->priv_key = NULL;
    }

    CHECK_NOT_NULL(ctx->priv_key = wa_alloc_from_be(d->buf, d->len));
    wa_change_len(ctx->priv_key, ctx->params->n->len);

    if (int_is_zero(ctx->priv_key)) {
        SET_ERROR(RET_INVALID_PRIVATE_KEY);
    }

    if (int_cmp(ctx->priv_key, ctx->params->n) >= 0) {
        SET_ERROR(RET_INVALID_PRIVATE_KEY);
    }

    if (ctx->params->precomp_p == NULL) {
        int sign_win_opt_level = (default_opt_level >> 8) & 0x0f;
        if (sign_win_opt_level == 0) {
            sign_win_opt_level = EC_DEFAULT_WIN_WIDTH;
        }

        ec_set_sign_precomp(ctx, 0, sign_win_opt_level);
    }

    ctx->sign_status = true;

cleanup:

    if (ret != RET_OK && ctx != NULL) {
        ctx->sign_status = false;
    }

    return ret;
}

int ec_init_verify(EcCtx* ctx, const ByteArray* qx, const ByteArray* qy)
{
    int ret = RET_OK;
    int verify_comb_opt_level = 0;
    int verify_win_opt_level = 0;
    ECPoint* pub_key = NULL;
    bool need_update_precomp_q = false;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(qx != NULL);
    CHECK_PARAM(qy != NULL);

    if (ctx->priv_key) {
        ctx->sign_status = false;
        wa_free_private(ctx->priv_key);
        ctx->priv_key = NULL;
    }

    /* Установка открытого ключа. */
    DO(public_key_to_ec_point(ctx->params, qx, qy, &pub_key));
    if (ctx->pub_key != NULL) {
        if ((wa_cmp(pub_key->x, ctx->pub_key->x) != 0) || 
            (wa_cmp(pub_key->y, ctx->pub_key->y) != 0) || 
            (wa_cmp(pub_key->z, ctx->pub_key->z) != 0)) {
            ec_point_free(ctx->pub_key);
            ctx->pub_key = pub_key;
            pub_key = NULL;
            need_update_precomp_q = true;
        }
    }
    else {
        ctx->pub_key = pub_key;
        pub_key = NULL;
        need_update_precomp_q = true;
    }

    if (ctx->params->precomp_p == NULL) {
        int win_opt_level = (default_opt_level >> 8) & 0x0f;
        if (win_opt_level == 0) {
            win_opt_level = EC_DEFAULT_WIN_WIDTH;
        }

        ec_set_sign_precomp(ctx, 0, win_opt_level);
    }
    
    if (ctx->precomp_q != NULL) {
        if (need_update_precomp_q) {
            verify_comb_opt_level = (ctx->precomp_q->type == EC_PRECOMP_TYPE_COMB) ? ctx->precomp_q->ctx.comb->comb_width : 0;
            verify_win_opt_level = (ctx->precomp_q->type == EC_PRECOMP_TYPE_WIN) ? ctx->precomp_q->ctx.win->win_width : 0;

            ec_precomp_free(ctx->precomp_q);
            ctx->precomp_q = NULL;
        }
    }
    else {
        verify_comb_opt_level = 0;
        verify_win_opt_level = default_opt_level & 0x0f;
        if (verify_win_opt_level == 0) {
            verify_win_opt_level = EC_DEFAULT_WIN_WIDTH;
        }
        need_update_precomp_q = true;
    }

    if (need_update_precomp_q) {
        DO(ec_set_verify_precomp(ctx, verify_comb_opt_level, verify_win_opt_level));
    }

    ctx->verify_status = true;

cleanup:

    ec_point_free(pub_key);
    if (ret != RET_OK && ctx != NULL) {
        ctx->verify_status = false;
    }

    return ret;
}

/**
 * Возвращает кофактор.
 *
 * @param ctx параметры кривой
 * @param cofactor кофактор
 */
static void ec2m_get_cofactor(const EcParamsCtx* params, WordArray* cofactor)
{
    size_t len = params->ec2m->len;
    word_t carry;
    WordArray* s = NULL;
    WordArray* one = NULL;
    WordArray* power_two = NULL;
    int ret = RET_OK;

    CHECK_PARAM(params != NULL);
    CHECK_PARAM(cofactor != NULL);

    CHECK_NOT_NULL(one = wa_alloc_with_one(len));
    CHECK_NOT_NULL(power_two = wa_alloc(len));

    int_lshift(one, params->m, power_two);
    int_sqrt(power_two, cofactor);
    carry = int_add(cofactor, cofactor, cofactor);
    carry += int_add(cofactor, one, cofactor);
    carry += int_add(cofactor, power_two, cofactor);

    CHECK_NOT_NULL(s = wa_copy_with_alloc(cofactor));
    wa_change_len(s, 2 * len);
    s->buf[len] = carry;
    int_div(s, params->n, s, NULL);

    DO(wa_copy_part(s, 0, len, cofactor));

cleanup:

    wa_free(s);
    wa_free(one);
    wa_free(power_two);
}

int ec_dh(const EcCtx* ctx, bool with_cofactor, const ByteArray* d, const ByteArray* qx,
    const ByteArray* qy, ByteArray** zx, ByteArray** zy)
{
    int ret = RET_OK;
    WordArray* x = NULL;
    WordArray* cofactor = NULL;
    ECPoint* rq = NULL;
    ECPoint* r = NULL;
    size_t len;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(d != NULL);
    CHECK_PARAM(qx != NULL);
    CHECK_PARAM(qy != NULL);
    CHECK_PARAM(zx != NULL);
    CHECK_PARAM(zy != NULL);

    /* Инициализация открытого ключа удаленной стороны. */
    DO(public_key_to_ec_point(ctx->params, qx, qy, &rq));

    /* Проверка корректности закрытого ключа (0 < d < n). */
    CHECK_NOT_NULL(x = wa_alloc_from_be(d->buf, d->len));
    if (int_cmp(x, ctx->params->n) >= 0) {
        SET_ERROR(RET_INVALID_PRIVATE_KEY);
    }

    wa_change_len(x, ctx->params->n->len);
    
    if (ctx->params->ec_field == EC_FIELD_BINARY) {
        len = ((size_t)ctx->params->ec2m->gf2m->f[0] + 7) / 8;
        CHECK_NOT_NULL(r = ec_point_alloc(ctx->params->ec2m->len));//a

        /* Проверка того что открытый ключ лежит в подгруппе порядка n. */
        /* Получение кофактора. */
        CHECK_NOT_NULL(cofactor = wa_alloc(ctx->params->ec2m->len));//a
        ec2m_get_cofactor(ctx->params, cofactor);

        ec2m_mul(ctx->params->ec2m, rq, cofactor, r);

        if (int_is_zero(r->x) && int_is_zero(r->y)) {
            SET_ERROR(RET_INVALID_PUBLIC_KEY);
        }

        /* Получение общего секрета. */
        ec2m_mul(ctx->params->ec2m, rq, x, r);

        if (with_cofactor) {
            ec2m_mul(ctx->params->ec2m, r, cofactor, r);
        }

        if (ctx->params->is_onb) {
            DO(pb_to_onb(ctx->params, r->x));
            DO(pb_to_onb(ctx->params, r->y));
        }
    }
    else {
        len = (int_bit_len(ctx->params->ecp->gfp->p) + 7) / 8;
        CHECK_NOT_NULL(r = ec_point_alloc(ctx->params->ecp->len));//a

        /* Получение общего секрета. */
        ecp_mul(ctx->params->ecp, rq, x, r);
    }

    CHECK_NOT_NULL(*zx = wa_to_ba(r->x));
    CHECK_NOT_NULL(*zy = wa_to_ba(r->y));
    DO(ba_change_len(*zx, len));
    DO(ba_change_len(*zy, len));
    DO(ba_swap(*zx));
    DO(ba_swap(*zy));

    ret = RET_OK;

cleanup:

    wa_free_private(x);
    wa_free(cofactor);
    ec_point_free(r);
    ec_point_free(rq);

    return ret;
}

int ec_dh_self_test(void)
{
    //test vectors from https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Component-Testing
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/ecccdhtestvectors.zip
    int ret = RET_OK;
    ByteArray* d = NULL;
    ByteArray* qx = NULL;
    ByteArray* qy = NULL;
    ByteArray* zx = NULL;
    ByteArray* zy = NULL;
    ByteArray* expected = NULL;
    EcCtx* ctx = NULL;

    CHECK_NOT_NULL(ctx = ec_alloc_default(EC_PARAMS_ID_NIST_B163));

    CHECK_NOT_NULL(d = ba_alloc_from_hex("03edae173de8fa0cf0412d6a7bdc81fdbd0617adf8"));
    CHECK_NOT_NULL(qx = ba_alloc_from_hex("03a647ba32dac71ec6780b0638a70cd24fc3bd4c8e"));
    CHECK_NOT_NULL(qy = ba_alloc_from_hex("02e69e961541844a4aa33769a7bce710f6640a560c"));
    CHECK_NOT_NULL(expected = ba_alloc_from_hex("0100fb42d177ffe6c31378e2e04e0da7376ffe8765"));
    
    DO(ec_dh(ctx, true, d, qx, qy, &zx, &zy));

    if (ba_cmp(zx, expected) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

    ec_free(ctx); ctx = NULL;
    ba_free(d); d = NULL;
    ba_free(qx); qx = NULL;
    ba_free(qy); qy = NULL;
    ba_free(expected); expected = NULL;
    ba_free(zx); zx = NULL;
    ba_free(zy); zy = NULL;

    CHECK_NOT_NULL(ctx = ec_alloc_default(EC_PARAMS_ID_NIST_P192));

    CHECK_NOT_NULL(d = ba_alloc_from_hex("f17d3fea367b74d340851ca4270dcb24c271f445bed9d527"));
    CHECK_NOT_NULL(qx = ba_alloc_from_hex("42ea6dd9969dd2a61fea1aac7f8e98edcc896c6e55857cc0"));
    CHECK_NOT_NULL(qy = ba_alloc_from_hex("dfbe5d7c61fac88b11811bde328e8a0d12bf01a9d204b523"));
    CHECK_NOT_NULL(expected = ba_alloc_from_hex("803d8ab2e5b6e6fca715737c3a82f7ce3c783124f6d51cd0"));
    
    DO(ec_dh(ctx, true, d, qx, qy, &zx, &zy));

    if (ba_cmp(zx, expected) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

cleanup:
    ec_free(ctx);
    ba_free(d);
    ba_free(qx);
    ba_free(qy);
    ba_free(expected);
    ba_free(zx);
    ba_free(zy);
    return ret;
}