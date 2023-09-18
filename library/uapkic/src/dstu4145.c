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

#define FILE_MARKER "uapkic/dstu4145.c"

#include <string.h>

#include "dstu4145.h"
#include "drbg.h"
#include "ec-internal.h"
#include "ec-cache-internal.h"
#include "math-int-internal.h"
#include "macros-internal.h"

int dstu4145_generate_privkey(const EcCtx *ctx, ByteArray **d)
{
    int ret = RET_OK;
    size_t n_bit_len;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(d != NULL);

    n_bit_len = int_bit_len(ctx->params->n);

    CHECK_NOT_NULL(*d = ba_alloc_by_len((n_bit_len + 7) / 8));

    /* Генерация закрытого ключа. */
    do {
        DO(drbg_random(*d));
        DO(ba_truncate(*d, n_bit_len - 1));
    } while (ba_is_zero(*d));

cleanup:

    return ret;

}

int dstu4145_get_pubkey(const EcCtx *ctx, const ByteArray *d, ByteArray **qx, ByteArray **qy)
{
    WordArray *d_wa = NULL;
    const EcParamsCtx *params;
    ECPoint *Q = NULL;
    size_t q_len;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(d != NULL);
    CHECK_PARAM(qx != NULL);
    CHECK_PARAM(qy != NULL);
    CHECK_PARAM(ctx->params->ec_field == EC_FIELD_BINARY);

    params = ctx->params;

    CHECK_NOT_NULL(d_wa = wa_alloc_from_ba(d));

    /* 0 < d < n */
    if (int_is_zero(d_wa) || int_cmp(d_wa, params->n) >= 0) {
        SET_ERROR(RET_INVALID_PRIVATE_KEY);
    }

    wa_change_len(d_wa, ctx->params->ec2m->len);

    /* Получение открытого ключа. */
    CHECK_NOT_NULL(Q = ec_point_alloc(params->ec2m->len));
    if (ctx->params->precomp_p == NULL) {
        int sign_win_opt_level = (default_opt_level >> 8) & 0x0f;
        if (sign_win_opt_level == 0) {
            sign_win_opt_level = EC_DEFAULT_WIN_WIDTH;
        }

        DO(ec_set_sign_precomp(ctx, 0, sign_win_opt_level));
    }
    DO(ec2m_dual_mul_opt(params->ec2m, params->precomp_p, d_wa, NULL, NULL, Q));

    /* Инвертируем точку эллиптической кривой. */
    gf2m_mod_add(Q->x, Q->y, Q->y);

    if (params->is_onb) {
        DO(pb_to_onb(ctx->params, Q->x));
        DO(pb_to_onb(ctx->params, Q->y));
    }

    q_len = (ctx->params->m + 7) / 8;

    CHECK_NOT_NULL(*qx = wa_to_ba(Q->x));
    CHECK_NOT_NULL(*qy = wa_to_ba(Q->y));

    DO(ba_change_len(*qx, q_len));
    DO(ba_change_len(*qy, q_len));

cleanup:

    ec_point_free(Q);
    wa_free_private(d_wa);

    return ret;
}

int dstu4145_compress_pubkey(const EcCtx *ctx, const ByteArray *qx, const ByteArray *qy, ByteArray **q)
{
    int ret = RET_OK;
    int trace;
    size_t q_len;
    ECPoint *ec_point = NULL;
    ByteArray* tmp_qx = NULL;
    ByteArray* tmp_qy = NULL;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(qx != NULL);
    CHECK_PARAM(qy != NULL);
    CHECK_PARAM(q != NULL);
    CHECK_PARAM(ctx->params->ec_field == EC_FIELD_BINARY);

    CHECK_NOT_NULL(tmp_qx = ba_alloc_from_uint8_be(qx->buf, qx->len));
    CHECK_NOT_NULL(tmp_qy = ba_alloc_from_uint8_be(qy->buf, qy->len));
    DO(public_key_to_ec_point(ctx->params, tmp_qx, tmp_qy, &ec_point));

    q_len = (ctx->params->m + 7) / 8;
    if (int_is_zero(ec_point->x)) {
        CHECK_NOT_NULL(*q = ba_alloc_by_len(qx->len));
        memset((*q)->buf, 0, q_len);
        ret = RET_OK;
        goto cleanup;
    }

    CHECK_NOT_NULL(*q = ba_alloc_from_uint8(qx->buf, qx->len));

    gf2m_mod_inv(ctx->params->ec2m->gf2m, ec_point->x, ec_point->x);
    gf2m_mod_mul(ctx->params->ec2m->gf2m, ec_point->x, ec_point->y, ec_point->y);
    trace = gf2m_mod_trace(ctx->params->ec2m->gf2m, ec_point->y);

    if (((*q)->buf[0] ^ trace) & 1) {
        (*q)->buf[0] ^= 1;
    }

    DO(ba_change_len(*q, q_len));

cleanup:

    ba_free(tmp_qx);
    ba_free(tmp_qy);
    ec_point_free(ec_point);

    return ret;
}

int dstu4145_decompress_pubkey(const EcCtx *ctx, const ByteArray *q, ByteArray **qx, ByteArray **qy)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(ctx->params->ec_field == EC_FIELD_BINARY);

    DO(ec2m_decompress_point_core(ctx->params, q, 0, qx, qy));

cleanup:

    return ret;
}

static int dstu4145_sign_internal(const EcCtx* ctx, const ByteArray* H, const WordArray* e, ByteArray** r, ByteArray** s)
{
    const EcParamsCtx* params;
    WordArray* res = NULL;
    WordArray* h = NULL;
    WordArray* wr = NULL;
    WordArray* ws = NULL;
    ByteArray* r_ba = NULL;
    ByteArray* s_ba = NULL;
    ECPoint* rec = NULL;
    int ret = RET_OK;
    size_t words, n_bit_len;

    params = ctx->params;
    words = params->ec2m->len;

    CHECK_NOT_NULL(h = wa_alloc_from_ba(H));
    int_truncate(h, params->m);

    wa_change_len(h, words);

    if (params->is_onb) {
        DO(onb_to_pb(params, h));
    }

    if (int_is_zero(h)) {
        h->buf[0] = 1;
    }

    CHECK_NOT_NULL(rec = ec_point_alloc(words));
    CHECK_NOT_NULL(wr = wa_alloc(words));
    CHECK_NOT_NULL(ws = wa_alloc(params->n->len));

    DO(ec2m_dual_mul_opt(params->ec2m, params->precomp_p, e, NULL, NULL, rec));

    gf2m_mod_mul(params->ec2m->gf2m, rec->x, h, wr);

    if (params->is_onb) {
        DO(pb_to_onb(params, wr));
    }

    n_bit_len = int_bit_len(params->n);
    int_truncate(wr, n_bit_len - 1);

    if (int_is_zero(wr)) {
        ret = -1;
        goto cleanup;
    }

    CHECK_NOT_NULL(res = wa_alloc(2 * words));

    /* ws = (e + rd)(mod n). */
    wa_change_len(ctx->priv_key, wr->len);
    int_mul(ctx->priv_key, wr, res);
    int_div(res, params->n, NULL, ws);
    if (int_add(e, ws, ws) > 0 || int_cmp(ws, params->n) >= 0) {
        int_sub(ws, params->n, ws);
    }

    if (int_is_zero(ws)) {
        ret = -1;
    }
    else {
        CHECK_NOT_NULL(r_ba = wa_to_ba(wr));
        DO(ba_change_len(r_ba, (n_bit_len + 7) / 8));
        CHECK_NOT_NULL(s_ba = wa_to_ba(ws));
        DO(ba_change_len(s_ba, (n_bit_len + 7) / 8));

        *r = r_ba;
        *s = s_ba;

        r_ba = NULL;
        s_ba = NULL;
    }

cleanup:

    wa_free_private(res);
    wa_free(h);
    wa_free(wr);
    wa_free(ws);
    ba_free(r_ba);
    ba_free(s_ba);
    ec_point_free(rec);

    return ret;
}

int dstu4145_sign(const EcCtx *ctx, const ByteArray *H, ByteArray **r, ByteArray **s)
{
    WordArray *e = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(H != NULL);
    CHECK_PARAM((H->len == 32) || (H->len == 48) || (H->len == 64));
    CHECK_PARAM(r != NULL);
    CHECK_PARAM(s != NULL);
    CHECK_PARAM(ctx->params->ec_field == EC_FIELD_BINARY);

    if (!ctx->sign_status) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    CHECK_NOT_NULL(e = wa_alloc(ctx->params->n->len));

    do {
        DO(int_rand(ctx->params->n, e));
        ret = dstu4145_sign_internal(ctx, H, e, r, s);
    } while (ret == -1);

cleanup:

    wa_free_private(e);
    return ret;
}

int dstu4145_verify(const EcCtx *ctx, const ByteArray *H, const ByteArray *r, const ByteArray *s)
{
    const EcParamsCtx *params;
    WordArray *ws = NULL;
    WordArray *wr = NULL;
    WordArray *r1 = NULL;
    WordArray *h = NULL;
    ECPoint *r_point = NULL;
    const EcGf2mCtx *ec2m;
    size_t n_bit_len;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(H != NULL);
    CHECK_PARAM((H->len == 32) || (H->len == 48) || (H->len == 64));
    CHECK_PARAM(r != NULL);
    CHECK_PARAM(s != NULL);
    CHECK_PARAM(ctx->params->ec_field == EC_FIELD_BINARY);

    params = ctx->params;

    if (ctx->verify_status == 0) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    ec2m = params->ec2m;

    /* Проверка ЭЦП. */
    n_bit_len = int_bit_len(ctx->params->n);

    if (((ba_get_len(s) + ba_get_len(r)) & 1) == 1) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

    CHECK_NOT_NULL(wr = wa_alloc_from_ba(r));
    CHECK_NOT_NULL(ws = wa_alloc_from_ba(s));

    /* 0 < wr < n і 0 < ws < n, иначе подпись неверная. */
    if ((int_cmp(wr, ctx->params->n) >= 0) || (int_cmp(ws, ctx->params->n) >= 0)
            || int_is_zero(wr) || int_is_zero(ws)) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

    CHECK_NOT_NULL(h = wa_alloc_from_ba(H));
    int_truncate(h, params->m);
    wa_change_len(h, ec2m->len);

    if (params->is_onb) {
        DO(onb_to_pb(params, h));
    }

    if (int_is_zero(h)) {
        h->buf[0] = 1;
    }

    CHECK_NOT_NULL(r_point = ec_point_alloc(ec2m->len));

    DO(ec2m_dual_mul_opt(ec2m, ctx->params->precomp_p, ws, ctx->precomp_q, wr, r_point));

    CHECK_NOT_NULL(r1 = wa_alloc(ec2m->len));
    gf2m_mod_mul(ec2m->gf2m, r_point->x, h, r1);

    if (params->is_onb) {
        DO(pb_to_onb(ctx->params, r1));
    }

    int_truncate(r1, n_bit_len - 1);

    if (!int_equals(r1, wr)) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

cleanup:

    wa_free(wr);
    wa_free(ws);
    wa_free(r1);
    wa_free(h);
    ec_point_free(r_point);

    return ret;
}

int dstu4145_init_sign(EcCtx* ctx, const ByteArray* d)
{
    int ret = RET_OK;
    ByteArray* d_be = NULL;

    CHECK_NOT_NULL(d_be = ba_alloc_from_uint8_be(d->buf, d->len));
    DO(ec_init_sign(ctx, d_be));

cleanup:
    ba_free_private(d_be);
    return ret;
}

int dstu4145_init_verify(EcCtx* ctx, const ByteArray* Qx, const ByteArray* Qy)
{
    int ret = RET_OK;
    ByteArray* Qx_be = NULL;
    ByteArray* Qy_be = NULL;

    CHECK_NOT_NULL(Qx_be = ba_alloc_from_uint8_be(Qx->buf, Qx->len));
    CHECK_NOT_NULL(Qy_be = ba_alloc_from_uint8_be(Qy->buf, Qy->len));
    DO(ec_init_verify(ctx, Qx_be, Qy_be));

cleanup:
    ba_free(Qx_be);
    ba_free(Qy_be);
    return ret;
}

int dstu4145_self_test(void)
{   
    // ДСТУ 4145-2002. Додаток Б 
    static const uint8_t test_H[] = {
        0xFF, 0x47, 0x22, 0xF5, 0xAE, 0xED, 0x76, 0xEB, 0x2E, 0x53, 0x73, 0xDF, 0x6D, 0x16, 0x80, 0x71, 
        0x5B, 0xB9, 0x2E, 0x3A, 0x88, 0x86, 0xE4, 0xAE, 0x9A, 0x0C, 0x91, 0x77, 0x42, 0xC4, 0xC9, 0x09 };
    static const uint8_t test_d[] = {
        0x3E, 0x5A, 0x9B, 0x1C, 0x0C, 0x79, 0x73, 0xD0, 0xF8, 0x93, 0x71, 0xD6, 0x47, 0xFF, 0x51, 0x79,
        0xDF, 0x0F, 0xF6, 0x83, 0x01 };
    static const uint8_t test_Qx[] = {
        0xDA, 0xC2, 0xBD, 0x4A, 0xF6, 0x9C, 0xB7, 0xE4, 0x5C, 0x78, 0xAC, 0xB6, 0x9C, 0x92, 0xFF, 0x23, 
        0xE0, 0xFD, 0xE7, 0x7D, 0x05 };
    static const uint8_t test_Qy[] = {
        0xAA, 0xB9, 0x32, 0x05, 0x77, 0x34, 0x5F, 0x7B, 0xAD, 0xF6, 0xAB, 0x85, 0xAD, 0x06, 0xCF, 0x4B, 
        0x32, 0x44, 0x54, 0xE8, 0x03 };
    static const uint8_t test_k[] = {
        0xC6, 0x61, 0x7F, 0x24, 0x2D, 0x93, 0x12, 0x8E, 0xDE, 0x79, 0x1D, 0x7A, 0x2B, 0x01, 0xDB, 0x97, 
        0xBD, 0x40, 0x5E, 0x02, 0x01 };
    static const uint8_t test_R[] = {
        0xA7, 0x08, 0x8D, 0x06, 0x93, 0x7A, 0xDE, 0x9A, 0xF5, 0x24, 0xA4, 0x80, 0x0D, 0x4A, 0x01, 0xAA, 
        0x0C, 0x2C, 0xEA, 0x74, 0x02 };
    static const uint8_t test_S[] = {
        0xCA, 0x5A, 0x61, 0xB3, 0x32, 0xA3, 0xD6, 0x5B, 0x0F, 0x23, 0x8C, 0x8E, 0x2B, 0x83, 0x31, 0x73, 
        0x95, 0x86, 0x0D, 0x10, 0x02 };

    static const ByteArray ba_d = { (uint8_t*)test_d, sizeof(test_d) };
    static const ByteArray ba_H = { (uint8_t*)test_H, sizeof(test_H) };

    int ret = RET_OK;
    EcCtx* ec_ctx = NULL;
    WordArray* wa_k = NULL;
    ByteArray* ba_Qx = NULL;
    ByteArray* ba_Qy = NULL;
    ByteArray* ba_R = NULL;
    ByteArray* ba_S = NULL;

    CHECK_NOT_NULL(ec_ctx = ec_alloc_default(EC_PARAMS_ID_DSTU4145_M163_PB_TEST));
    DO(dstu4145_get_pubkey(ec_ctx, &ba_d, &ba_Qx, &ba_Qy));
    if (ba_Qx->len != sizeof(test_Qx) ||
        ba_Qy->len != sizeof(test_Qy) ||
        memcmp(ba_Qx->buf, test_Qx, sizeof(test_Qx)) != 0 ||
        memcmp(ba_Qy->buf, test_Qy, sizeof(test_Qy)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

    CHECK_NOT_NULL(wa_k = wa_alloc_from_le(test_k, sizeof(test_k)));

    DO(dstu4145_init_sign(ec_ctx, &ba_d));
    DO(dstu4145_sign_internal(ec_ctx, &ba_H, wa_k, &ba_R, &ba_S));

    if (ba_R->len != sizeof(test_R) ||
        ba_S->len != sizeof(test_S) ||
        memcmp(ba_R->buf, test_R, sizeof(test_R)) != 0 ||
        memcmp(ba_S->buf, test_S, sizeof(test_S)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

    DO(dstu4145_init_verify(ec_ctx, ba_Qx, ba_Qy));
    DO(dstu4145_verify(ec_ctx, &ba_H, ba_R, ba_S));
    
cleanup:
    wa_free(wa_k);
    ba_free(ba_Qx);
    ba_free(ba_Qy);
    ba_free(ba_R);
    ba_free(ba_S);
    ec_free(ec_ctx);
    return ret;
}
