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

#define FILE_MARKER "uapkic/ecdsa.c"

#include <string.h>
#include "ecdsa.h"
#include "ec-internal.h"
#include "ec-cache-internal.h"
#include "math-int-internal.h"
#include "macros-internal.h"
#include "hash.h"

int ecdsa_generate_privkey(const EcCtx *ctx, ByteArray **d)
{
    return ec_generate_privkey(ctx, d);
}

int ecdsa_get_pubkey(const EcCtx* ctx, const ByteArray* d, ByteArray** qx, ByteArray** qy)
{
    size_t blen;
    WordArray* wd = NULL;
    ECPoint* r = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
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

    if (ctx->params->ec_field == EC_FIELD_PRIME) {
        CHECK_NOT_NULL(r = ec_point_alloc(ctx->params->ecp->len));
        blen = (int_bit_len(ctx->params->ecp->gfp->p) + 7) / 8;
        DO(ecp_dual_mul_opt(ctx->params->ecp, ctx->params->precomp_p, wd, NULL, NULL, r));
    }
    else {
        CHECK_NOT_NULL(r = ec_point_alloc(ctx->params->ec2m->len));
        blen = ((size_t)ctx->params->ec2m->gf2m->f[0] + 7) / 8;
        DO(ec2m_dual_mul_opt(ctx->params->ec2m, ctx->params->precomp_p, wd, NULL, NULL, r));
    }

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

static int ecdsa_sign_internal(const EcCtx* ctx, const ByteArray* H, const WordArray* k, ByteArray** r, ByteArray** s)
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
    size_t q_bit_len, q_byte_len, used_hash_len;

    q = ctx->params->n;
    q_bit_len = int_bit_len(q);
    q_byte_len = (q_bit_len + 7) / 8;
    used_hash_len = H->len;
    if (used_hash_len > q_byte_len) {
        used_hash_len = q_byte_len;
    }

    CHECK_NOT_NULL(e = wa_alloc_from_be(H->buf, used_hash_len));
    wa_change_len(e, q->len);

    if (used_hash_len * 8 > q_bit_len) {
        size_t rshift = used_hash_len * 8 - q_bit_len;
        int_rshift(0, e, rshift, e);
    }

    if (int_cmp(q, e) != 1) {
        int_sub(e, q, e);
    }

    /* Шаг 3. Обчислити точку ЕК C = kP,
     * c = (cx, cy) та визначити r = cx (mod q). */
    if (ctx->params->ec_field == EC_FIELD_PRIME) {
        CHECK_NOT_NULL(C = ec_point_alloc(ctx->params->ecp->len));
        DO(ecp_dual_mul_opt(ctx->params->ecp, ctx->params->precomp_p, k, NULL, NULL, C));
    }
    else {
        CHECK_NOT_NULL(C = ec_point_alloc(ctx->params->ec2m->len));
        DO(ec2m_dual_mul_opt(ctx->params->ec2m, ctx->params->precomp_p, k, NULL, NULL, C));
    }

    CHECK_NOT_NULL(tmp = wa_alloc(q->len * 2));
    CHECK_NOT_NULL(wr = wa_alloc(q->len));
    wa_copy(C->x, tmp);
    int_div(tmp, q, NULL, wr);

    /* Якщо r = 0, то повернутися до Шагу 2. */
    if (int_is_zero(wr)) {
        ret = -1;
        goto cleanup;
    }

    /* t = k^(-1)(mod q);
     * s = t * (rd + e)(mod q). */
    CHECK_NOT_NULL(t = gfp_mod_inv_core(k, q));
    int_mul(wr, ctx->priv_key, tmp);
    CHECK_NOT_NULL(ws = wa_alloc(q->len));
    int_div(tmp, q, NULL, ws);
    if ((int_add(ws, e, ws) > 0) || (int_cmp(ws, q) >= 0)) {
        int_sub(ws, q, ws);
    }
    int_mul(ws, t, tmp);
    int_div(tmp, q, NULL, ws);

    /* Якщо r = 0, то повернутися до Шагу 2. */
    if (int_is_zero(ws)) {
        ret = -1;
    }
    else {
        CHECK_NOT_NULL(br = wa_to_ba(wr));
        CHECK_NOT_NULL(bs = wa_to_ba(ws));

        DO(ba_change_len(br, q_byte_len));
        DO(ba_change_len(bs, q_byte_len));
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
    wa_free(wr);
    wa_free(ws);
    wa_free(e);
    ba_free(br);
    ba_free(bs);
    ec_point_free(C);

    return ret;
}

int ecdsa_sign(const EcCtx* ctx, const ByteArray* H, ByteArray** r, ByteArray** s)
{
    WordArray* k = NULL;
    const WordArray* q;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
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
        ret = ecdsa_sign_internal(ctx, H, k, r, s);
    } while (ret == -1);

cleanup:

    wa_free_private(k);

    return ret;
}

int ecdsa_verify(const EcCtx *ctx, const ByteArray *H, const ByteArray *r, const ByteArray *s)
{
    WordArray *e = NULL;
    WordArray *z1 = NULL;
    WordArray *z2 = NULL;
    WordArray *wr = NULL;
    WordArray *ws = NULL;
    WordArray *s_inv = NULL;
    WordArray *r_act = NULL;
    WordArray* t = NULL;
    WordArray* tmp = NULL;
    ECPoint *C = NULL;
    const WordArray *q;
    int ret = RET_OK;
    size_t q_bit_len, q_byte_len, used_hash_len;

    CHECK_PARAM(ctx != NULL);
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

    q_bit_len = int_bit_len(q);
    q_byte_len = (q_bit_len + 7) / 8;
    used_hash_len = H->len;
    if (used_hash_len > q_byte_len) {
        used_hash_len = q_byte_len;
    }

    CHECK_NOT_NULL(e = wa_alloc_from_be(H->buf, used_hash_len));
    wa_change_len(e, q->len);

    if (used_hash_len * 8 > q_bit_len) {
        size_t rshift = used_hash_len * 8 - q_bit_len;
        int_rshift(0, e, rshift, e);
    }

    if (int_cmp(q, e) != 1) {
        int_sub(e, q, e);
    }

    /* Шаг 3. s = s^(-1)(mod q). */
    CHECK_NOT_NULL(s_inv = gfp_mod_inv_core(ws, q));

    /* Шаг 4. z1 = s*e(mod q), z2 = s*r(mod q). */
    CHECK_NOT_NULL(z1 = wa_alloc(q->len));
    CHECK_NOT_NULL(z2 = wa_alloc(q->len));
    CHECK_NOT_NULL(tmp = wa_alloc(q->len * 2));

    int_mul(s_inv, e, tmp);
    int_div(tmp, q, NULL, z1);
    int_mul(s_inv, wr, tmp);
    int_div(tmp, q, NULL, z2);

    /* Шаг 5. Обчислити точку ЕК C = z1*P+z2*Q */
    if (ctx->params->ec_field == EC_FIELD_PRIME) {
        CHECK_NOT_NULL(C = ec_point_alloc(ctx->params->ecp->len));
        DO(ecp_dual_mul_opt(ctx->params->ecp, ctx->params->precomp_p, z1, ctx->precomp_q, z2, C));
    }
    else {
        CHECK_NOT_NULL(C = ec_point_alloc(ctx->params->ec2m->len));
        DO(ec2m_dual_mul_opt(ctx->params->ec2m, ctx->params->precomp_p, z1, ctx->precomp_q, z2, C));
    }

    CHECK_NOT_NULL(t = wa_copy_with_alloc(C->x));
    wa_change_len(t, q->len * 2);

    CHECK_NOT_NULL(r_act = wa_alloc(q->len));
    int_div(t, q, NULL, r_act);

    if (!int_equals(r_act, wr)) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

cleanup:

    wa_free(tmp);
    wa_free(e);
    wa_free(z1);
    wa_free(z2);
    wa_free(wr);
    wa_free(ws);
    wa_free(s_inv);
    wa_free(r_act);
    wa_free(t);
    ec_point_free(C);

    return ret;
}

static int ecdsa_p_self_test(void)
{
    // ДСТУ ISO/IEC 14888-3:2019. F.6.3
    static const uint8_t test_Msg[] = "abc";
    static const uint8_t test_d[] = {
        0x1A, 0x8D, 0x59, 0x8F, 0xC1, 0x5B, 0xF0, 0xFD, 0x89, 0x03, 0x0B, 0x5C, 0xB1, 0x11, 0x1A, 0xEB, 
        0x92, 0xAE, 0x8B, 0xAF, 0x5E, 0xA4, 0x75, 0xFB };
    static const uint8_t test_Qx[] = {
        0x62, 0xB1, 0x2D, 0x60, 0x69, 0x0C, 0xDC, 0xF3, 0x30, 0xBA, 0xBA, 0xB6, 0xE6, 0x97, 0x63, 0xB4, 
        0x71, 0xF9, 0x94, 0xDD, 0x70, 0x2D, 0x16, 0xA5 };
    static const uint8_t test_Qy[] = {
        0x63, 0xBF, 0x5E, 0xC0, 0x80, 0x69, 0x70, 0x5F, 0xFF, 0xF6, 0x5E, 0x5C, 0xA5, 0xC0, 0xD6, 0x97, 
        0x16, 0xDF, 0xCB, 0x34, 0x74, 0x37, 0x39, 0x02 };
    static const uint8_t test_k[] = {
        0xFA, 0x6D, 0xE2, 0x97, 0x46, 0xBB, 0xEB, 0x7F, 0x8B, 0xB1, 0xE7, 0x61, 0xF8, 0x5F, 0x7D, 0xFB, 
        0x29, 0x83, 0x16, 0x9D, 0x82, 0xFA, 0x2F, 0x4E };
    static const uint8_t test_R[] = {
        0x88, 0x50, 0x52, 0x38, 0x0F, 0xF1, 0x47, 0xB7, 0x34, 0xC3, 0x30, 0xC4, 0x3D, 0x39, 0xB2, 0xC4, 
        0xA8, 0x9F, 0x29, 0xB0, 0xF7, 0x49, 0xFE, 0xAD };
    static const uint8_t test_S[] = {
        0xE9, 0xEC, 0xC7, 0x81, 0x06, 0xDE, 0xF8, 0x2B, 0xF1, 0x07, 0x0C, 0xF1, 0xD4, 0xD8, 0x04, 0xC3, 
        0xCB, 0x39, 0x00, 0x46, 0x95, 0x1D, 0xF6, 0x86 };

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

    CHECK_NOT_NULL(ec_ctx = ec_alloc_default(EC_PARAMS_ID_NIST_P192));
    DO(ecdsa_get_pubkey(ec_ctx, &ba_d, &ba_Qx, &ba_Qy));
    if (ba_Qx->len != sizeof(test_Qx) ||
        ba_Qy->len != sizeof(test_Qy) ||
        memcmp(ba_Qx->buf, test_Qx, sizeof(test_Qx)) != 0 ||
        memcmp(ba_Qy->buf, test_Qy, sizeof(test_Qy)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

    CHECK_NOT_NULL(hash_ctx = hash_alloc(HASH_ALG_SHA1));
    DO(hash_update(hash_ctx, &ba_Msg));
    DO(hash_final(hash_ctx, &ba_hash));

    CHECK_NOT_NULL(wa_k = wa_alloc_from_be(test_k, sizeof(test_k)));

    DO(ec_init_sign(ec_ctx, &ba_d));
    DO(ecdsa_sign_internal(ec_ctx, ba_hash, wa_k, &ba_R, &ba_S));

    if (ba_R->len != sizeof(test_R) ||
        ba_S->len != sizeof(test_S) ||
        memcmp(ba_R->buf, test_R, sizeof(test_R)) != 0 ||
        memcmp(ba_S->buf, test_S, sizeof(test_S)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

    DO(ec_init_verify(ec_ctx, ba_Qx, ba_Qy));
    DO(ecdsa_verify(ec_ctx, ba_hash, ba_R, ba_S));

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

static int ecdsa_b_self_test(void)
{
    // ДСТУ ISO/IEC 14888-3:2019. F.6.7
    static const uint8_t test_Msg[] = "abc";
    static const uint8_t test_d[] = {
        0x84, 0x34, 0x61, 0x3F, 0x4B, 0x79, 0x9B, 0x4C, 0x26, 0xE4, 0xD7, 0xAB, 0x8E, 0x94, 0x81, 0xB0,
        0x4B, 0x09, 0xE6, 0x48, 0xC9, 0x4A, 0xFF, 0xD1, 0x4B, 0x61, 0x1A, 0x20 };
    static const uint8_t test_Qx[] = {
        0x01, 0x7C, 0x9D, 0xD7, 0x66, 0xAE, 0xFB, 0xE4, 0xDE, 0x4B, 0x15, 0xF4, 0x6D, 0xB0, 0x67, 0x1D,
        0xC4, 0xCA, 0x07, 0x67, 0xED, 0x51, 0xEC, 0xEA, 0x94, 0x75, 0x7D, 0x9C, 0x66, 0x2E };
    static const uint8_t test_Qy[] = {
        0x01, 0xCD, 0xD7, 0x26, 0x08, 0x48, 0x37, 0xAE, 0x73, 0xC1, 0x1C, 0x27, 0xD6, 0x05, 0xC6, 0xEB,
        0x2D, 0x5E, 0x31, 0x48, 0x23, 0x58, 0x78, 0x03, 0x05, 0xC2, 0x52, 0x2B, 0x15, 0x1B };
    static const uint8_t test_k[] = {
        0x01, 0x90, 0xDA, 0x60, 0xFE, 0x3B, 0x17, 0x9B, 0x96, 0x61, 0x1D, 0xB7, 0xC7, 0xE5, 0x21, 0x7C, 
        0x9A, 0xFF, 0x0A, 0xEE, 0x43, 0x57, 0x82, 0xEB, 0xFB, 0x2D, 0xFF, 0xF2, 0x7F };
    static const uint8_t test_R[] = {
        0x3E, 0xA7, 0x23, 0x16, 0x62, 0xE6, 0x51, 0x6F, 0x11, 0xE3, 0x7D, 0x59, 0xD5, 0x00, 0xD7, 0x0F, 
        0x09, 0xE6, 0x2D, 0x64, 0xFE, 0x6F, 0xF4, 0x45, 0xC9, 0xB4, 0x79, 0xC8, 0xB0 };
    static const uint8_t test_S[] = {
        0x2D, 0x72, 0xC7, 0x3D, 0xA3, 0x3A, 0x9B, 0x26, 0x7F, 0x0B, 0xEC, 0x9E, 0x6C, 0xB6, 0xBE, 0xCE,
        0xED, 0x01, 0x4F, 0x67, 0xD4, 0xA3, 0xD3, 0x00, 0x06, 0xB3, 0xEB, 0xE2, 0xDC };

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

    CHECK_NOT_NULL(ec_ctx = ec_alloc_default(EC_PARAMS_ID_NIST_K233));
    DO(ecdsa_get_pubkey(ec_ctx, &ba_d, &ba_Qx, &ba_Qy));
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
    DO(ecdsa_sign_internal(ec_ctx, ba_hash, wa_k, &ba_R, &ba_S));

    if (ba_R->len != sizeof(test_R) ||
        ba_S->len != sizeof(test_S) ||
        memcmp(ba_R->buf, test_R, sizeof(test_R)) != 0 ||
        memcmp(ba_S->buf, test_S, sizeof(test_S)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

    DO(ec_init_verify(ec_ctx, ba_Qx, ba_Qy));
    DO(ecdsa_verify(ec_ctx, ba_hash, ba_R, ba_S));

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

int ecdsa_self_test(void)
{
    int ret = RET_OK;

    DO(ecdsa_p_self_test());
    DO(ecdsa_b_self_test());

cleanup:
    return ret;
}
