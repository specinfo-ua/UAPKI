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

#define FILE_MARKER "uapkic/ecrdsa.c"

#include <string.h>
#include "ecrdsa.h"
#include "ec-internal.h"
#include "ec-cache-internal.h"
#include "math-int-internal.h"
#include "macros-internal.h"
#include "hash.h"

int ecrdsa_generate_privkey(const EcCtx *ctx, ByteArray **d)
{
    return ec_generate_privkey(ctx, d);
}

int ecrdsa_get_pubkey(const EcCtx* ctx, const ByteArray* d, ByteArray** qx, ByteArray** qy)
{
    size_t blen;
    WordArray* wd = NULL;
    ECPoint* r = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(ctx->params->ec_field == EC_FIELD_PRIME);
    CHECK_PARAM(d != NULL);
    CHECK_PARAM(qx != NULL);
    CHECK_PARAM(qy != NULL);

    CHECK_NOT_NULL(wd = wa_alloc_from_be(d->buf, d->len));
    if (int_is_zero(wd) || int_cmp(wd, ctx->params->n) >= 0) {
        SET_ERROR(RET_INVALID_PRIVATE_KEY);
    }

    wa_change_len(wd, ctx->params->n->len);

    if (ctx->params->precomp_p == NULL) {
        int sign_win_opt_level = (default_opt_level >> 8) & 0x0f;
        if (sign_win_opt_level == 0) {
            sign_win_opt_level = EC_DEFAULT_WIN_WIDTH;
        }
        DO(ec_set_sign_precomp(ctx, 0, sign_win_opt_level));
    }

    CHECK_NOT_NULL(r = ec_point_alloc(ctx->params->ecp->len));
    blen = (int_bit_len(ctx->params->ecp->gfp->p) + 7) / 8;
    DO(ecp_dual_mul_opt(ctx->params->ecp, ctx->params->precomp_p, wd, NULL, NULL, r));

    CHECK_NOT_NULL(*qx = wa_to_ba(r->x));
    CHECK_NOT_NULL(*qy = wa_to_ba(r->y));
    DO(ba_change_len(*qx, blen));
    DO(ba_change_len(*qy, blen));
    DO(ba_swap(*qx));
    DO(ba_swap(*qy));

cleanup:

    ec_point_free(r);
    wa_free_private(wd);

    return ret;
}

static int ecrdsa_sign_internal(const EcCtx* ctx, const ByteArray* H, const WordArray* k, ByteArray** r, ByteArray** s)
{
    WordArray* tmp = NULL;
    WordArray* t = NULL;
    WordArray* e = NULL;
    WordArray* wr = NULL;
    WordArray* ws = NULL;
    ByteArray* br = NULL;
    ByteArray* bs = NULL;
    ECPoint* C = NULL;
    const WordArray* q;
    int ret = RET_OK;

    q = ctx->params->n;
    CHECK_NOT_NULL(e = wa_alloc_from_be(H->buf, H->len));
    if (e->len >= q->len) {
        CHECK_NOT_NULL(tmp = wa_alloc(q->len));
        int_div(e, q, NULL, tmp);
        wa_copy(tmp, e);
        wa_free(tmp);
        tmp = NULL;
    }
    if (int_is_zero(e)) {
        wa_one(e);
    }
    wa_change_len(e, q->len);

    /* Шаг 3. Обчислити точку ЕК C = kP,
     * c = (cx, cy) та визначити r = cx (mod q). */
    CHECK_NOT_NULL(C = ec_point_alloc(ctx->params->ecp->len));
    DO(ecp_dual_mul_opt(ctx->params->ecp, ctx->params->precomp_p, k, NULL, NULL, C));

    CHECK_NOT_NULL(tmp = wa_alloc(q->len * 2));
    CHECK_NOT_NULL(wr = wa_alloc(q->len));
    CHECK_NOT_NULL(ws = wa_alloc(q->len));

    wa_copy(C->x, tmp);
    int_div(tmp, q, NULL, wr);

    /* Якщо r = 0, то повернутися до Шагу 2. */
    if (int_is_zero(wr)) {
        ret = -1;
        goto cleanup;
    }

    CHECK_NOT_NULL(t = wa_alloc(q->len));
    /* s = (rx + ke) mod q */
    int_mul(wr, ctx->priv_key, tmp);
    int_div(tmp, q, NULL, ws);
    int_mul(k, e, tmp);
    int_div(tmp, q, NULL, t);

    if ((int_add(ws, t, ws) > 0) || (int_cmp(ws, q) >= 0)) {
        int_sub(ws, q, ws);
    }

    /* Якщо r = 0, то повернутися до Шагу 2. */
    if (int_is_zero(ws)) {
        ret = -1;
    }
    else {
        size_t ln = (int_bit_len(q) + 7) >> 3;

        CHECK_NOT_NULL(br = wa_to_ba(wr));
        CHECK_NOT_NULL(bs = wa_to_ba(ws));

        DO(ba_change_len(br, ln));
        DO(ba_change_len(bs, ln));
        DO(ba_swap(br));
        DO(ba_swap(bs));

        *r = br;
        *s = bs;

        br = NULL;
        bs = NULL;
    }

cleanup:

    wa_free_private(tmp);
    wa_free_private(t);
    wa_free(e);
    wa_free(wr);
    wa_free(ws);
    ba_free(br);
    ba_free(bs);
    ec_point_free(C);

    return ret;
}

int ecrdsa_sign(const EcCtx* ctx, const ByteArray* H, ByteArray** r, ByteArray** s)
{
    WordArray* k = NULL;
    const WordArray* q;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(ctx->params->ec_field == EC_FIELD_PRIME);
    CHECK_PARAM(H != NULL);
    CHECK_PARAM(r != NULL);
    CHECK_PARAM(s != NULL);

    if (!ctx->sign_status) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    q = ctx->params->n;

    CHECK_NOT_NULL(k = wa_alloc(q->len));

    do {
        /* Шаг 2. Згенерувати випадкове число k (0 < k < q). */
        DO(int_rand(q, k));
        ret = ecrdsa_sign_internal(ctx, H, k, r, s);
    } while (ret == -1);

cleanup:

    wa_free_private(k);

    return ret;
}

int ecrdsa_verify(const EcCtx* ctx, const ByteArray* H, const ByteArray* r, const ByteArray* s)
{
    WordArray* e = NULL;
    WordArray* u = NULL;
    WordArray* v = NULL;
    WordArray* wr = NULL;
    WordArray* ws = NULL;
    WordArray* e_inv = NULL;
    WordArray* r_act = NULL;
    WordArray* t = NULL;
    WordArray* tmp = NULL;
    ECPoint* C = NULL;
    const WordArray* q;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(ctx->params->ec_field == EC_FIELD_PRIME);
    CHECK_PARAM(H != NULL);
    CHECK_PARAM(r != NULL);
    CHECK_PARAM(s != NULL);

    if (ctx->verify_status == 0) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    q = ctx->params->n;

    CHECK_NOT_NULL(wr = wa_alloc_from_be(r->buf, r->len));
    CHECK_NOT_NULL(ws = wa_alloc_from_be(s->buf, s->len));

    wa_change_len(wr, q->len);
    wa_change_len(ws, q->len);

    /* 0 < r < n та 0 < s < n, інакше підпис неправильний. */
    if ((int_cmp(wr, ctx->params->n) >= 0) || (int_cmp(ws, ctx->params->n) >= 0)
        || int_is_zero(wr) || int_is_zero(ws)) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

    CHECK_NOT_NULL(e = wa_alloc_from_be(H->buf, H->len));
    if (e->len >= q->len) {
        CHECK_NOT_NULL(tmp = wa_alloc(q->len));
        int_div(e, q, NULL, tmp);
        wa_copy(tmp, e);
        wa_free(tmp);
        tmp = NULL;
    }
    if (int_is_zero(e)) {
        wa_one(e);
    }
    wa_change_len(e, q->len);

    /* Шаг 3. Обчислити e = OS2I(h)^-1 (mod q). */
    CHECK_NOT_NULL(e_inv = gfp_mod_inv_core(e, q));

    /* Шаг 4. Обчислити u = es (mod q), v = -er (mod q). */
    CHECK_NOT_NULL(u = wa_alloc(q->len));
    CHECK_NOT_NULL(v = wa_alloc(q->len));
    CHECK_NOT_NULL(tmp = wa_alloc(q->len * 2));

    int_mul(e_inv, ws, tmp);
    int_div(tmp, q, NULL, u);
    int_mul(e_inv, wr, tmp);
    int_div(tmp, q, NULL, v);
    int_sub(q, v, v);

    /* Шаг 5. Обчислити точку ЕК C = uG + vY */
    CHECK_NOT_NULL(C = ec_point_alloc(ctx->params->ecp->len));
    DO(ecp_dual_mul_opt(ctx->params->ecp, ctx->params->precomp_p, u, ctx->precomp_q, v, C));

    CHECK_NOT_NULL(t = wa_copy_with_alloc(C->x));
    wa_change_len(t, q->len * 2);

    CHECK_NOT_NULL(r_act = wa_alloc(q->len));
    int_div(t, q, NULL, r_act);

    if (!int_equals(r_act, wr)) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

cleanup:

    wa_free(e);
    wa_free(tmp);
    wa_free(u);
    wa_free(v);
    wa_free(wr);
    wa_free(ws);
    wa_free(e_inv);
    wa_free(r_act);
    wa_free(t);
    ec_point_free(C);

    return ret;
}

int ecrdsa_self_test(void)
{
    // ДСТУ ISO/IEC 14888-3:2019. F.9.1
    static const uint8_t test_Msg[] = "abc";
    static const uint8_t test_d[] = {
        0x7A, 0x92, 0x9A, 0xDE, 0x78, 0x9B, 0xB9, 0xBE, 0x10, 0xED, 0x35, 0x9D, 0xD3, 0x9A, 0x72, 0xC1,
        0x1B, 0x60, 0x96, 0x1F, 0x49, 0x39, 0x7E, 0xEE, 0x1D, 0x19, 0xCE, 0x98, 0x91, 0xEC, 0x3B, 0x28 };
    static const uint8_t test_Qx[] = {
        0x7F, 0x2B, 0x49, 0xE2, 0x70, 0xDB, 0x6D, 0x90, 0xD8, 0x59, 0x5B, 0xEC, 0x45, 0x8B, 0x50, 0xC5, 
        0x85, 0x85, 0xBA, 0x1D, 0x4E, 0x9B, 0x78, 0x8F, 0x66, 0x89, 0xDB, 0xD8, 0xE5, 0x6F, 0xD8, 0x0B };
    static const uint8_t test_Qy[] = {
        0x26, 0xF1, 0xB4, 0x89, 0xD6, 0x70, 0x1D, 0xD1, 0x85, 0xC8, 0x41, 0x3A, 0x97, 0x7B, 0x3C, 0xBB, 
        0xAF, 0x64, 0xD1, 0xC5, 0x93, 0xD2, 0x66, 0x27, 0xDF, 0xFB, 0x10, 0x1A, 0x87, 0xFF, 0x77, 0xDA };
    static const uint8_t test_k[] = {
        0x77, 0x10, 0x5C, 0x9B, 0x20, 0xBC, 0xD3, 0x12, 0x28, 0x23, 0xC8, 0xCF, 0x6F, 0xCC, 0x7B, 0x95,
        0x6D, 0xE3, 0x38, 0x14, 0xE9, 0x5B, 0x7F, 0xE6, 0x4F, 0xED, 0x92, 0x45, 0x94, 0xDC, 0xEA, 0xB3 };
    static const uint8_t test_R[] = {
        0x41, 0xAA, 0x28, 0xD2, 0xF1, 0xAB, 0x14, 0x82, 0x80, 0xCD, 0x9E, 0xD5, 0x6F, 0xED, 0xA4, 0x19,
        0x74, 0x05, 0x35, 0x54, 0xA4, 0x27, 0x67, 0xB8, 0x3A, 0xD0, 0x43, 0xFD, 0x39, 0xDC, 0x04, 0x93 };
    static const uint8_t test_S[] = {
        0x0A, 0x7B, 0xA4, 0x72, 0x2D, 0xA5, 0x69, 0x3F, 0x22, 0x9D, 0x17, 0x5F, 0xAB, 0x6A, 0xFB, 0x85,
        0x7E, 0xC2, 0x27, 0x3B, 0x9F, 0x88, 0xDA, 0x58, 0x92, 0xCE, 0xD3, 0x11, 0x7F, 0xCF, 0x1E, 0x36 }; 

    static const ByteArray ba_d = { (uint8_t*)test_d, sizeof(test_d) };
    static const ByteArray ba_Msg = { (uint8_t*)test_Msg, sizeof(test_Msg) - 1 };

    int ret = RET_OK;
    EcCtx* ec_ctx = NULL;
    HashCtx* hash_ctx = NULL;
    ByteArray* ba_hash = NULL;
    WordArray* wa_k = NULL;
    ByteArray* ba_Qx = NULL;
    ByteArray* ba_Qy = NULL;
    ByteArray* ba_R = NULL;
    ByteArray* ba_S = NULL;

    CHECK_NOT_NULL(ec_ctx = ec_alloc_default(EC_PARAMS_ID_GOST_P256_TEST));
    DO(ecrdsa_get_pubkey(ec_ctx, &ba_d, &ba_Qx, &ba_Qy));
    if (ba_Qx->len != sizeof(test_Qx) ||
        ba_Qy->len != sizeof(test_Qy) ||
        memcmp(ba_Qx->buf, test_Qx, sizeof(test_Qx)) != 0 ||
        memcmp(ba_Qy->buf, test_Qy, sizeof(test_Qy)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

    CHECK_NOT_NULL(hash_ctx = hash_alloc(HASH_ALG_SHA256));
    DO(hash_update(hash_ctx, &ba_Msg));
    DO(hash_final(hash_ctx, &ba_hash));

    CHECK_NOT_NULL(wa_k = wa_alloc_from_be(test_k, sizeof(test_k)));

    DO(ec_init_sign(ec_ctx, &ba_d));
    DO(ecrdsa_sign_internal(ec_ctx, ba_hash, wa_k, &ba_R, &ba_S));

    if (ba_R->len != sizeof(test_R) ||
        ba_S->len != sizeof(test_S) ||
        memcmp(ba_R->buf, test_R, sizeof(test_R)) != 0 ||
        memcmp(ba_S->buf, test_S, sizeof(test_S)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

    DO(ec_init_verify(ec_ctx, ba_Qx, ba_Qy));
    DO(ecrdsa_verify(ec_ctx, ba_hash, ba_R, ba_S));

cleanup:
    ba_free(ba_hash);
    wa_free(wa_k);
    ba_free(ba_Qx);
    ba_free(ba_Qy);
    ba_free(ba_R);
    ba_free(ba_S);
    hash_free(hash_ctx);
    ec_free(ec_ctx);
    return ret;
}
