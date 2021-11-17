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
#include "sm2dsa.h"
#include "ec-internal.h"
#include "ec-cache-internal.h"
#include "math-int-internal.h"
#include "macros-internal.h"
#include "sm3.h"

#undef FILE_MARKER
#define FILE_MARKER "uapkic/sm2dsa.c"

int sm2dsa_generate_privkey(const EcCtx *ctx, ByteArray **d)
{
    return ec_generate_privkey(ctx, d);
}

int sm2dsa_get_pubkey(const EcCtx* ctx, const ByteArray* d, ByteArray** qx, ByteArray** qy)
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

static int sm2dsa_sign_internal(const EcCtx* ctx, const ByteArray* H, const WordArray* K, ByteArray** R, ByteArray** S)
{
    ByteArray* r = NULL;
    ByteArray* s = NULL;
    WordArray* e = NULL;
    WordArray* tmp = NULL;
    WordArray* t = NULL;
    WordArray* t_inv = NULL;
    WordArray* wr = NULL;
    WordArray* ws = NULL;
    ECPoint* C = NULL;
    const WordArray* q;
    int ret = RET_OK;
    size_t q_byte_len;

    q = ctx->params->n;
    q_byte_len = (int_bit_len(q) + 7) / 8;

    /* A2 */
    CHECK_NOT_NULL(e = wa_alloc_from_be(H->buf, H->len));
    if (e->len >= q->len) {
        CHECK_NOT_NULL(tmp = wa_alloc(q->len));
        int_div(e, q, NULL, tmp);
        wa_copy(tmp, e);
        wa_free(tmp);
        tmp = NULL;
    }
    wa_change_len(e, q->len);

    /* A4 */
    if (ctx->params->ec_field == EC_FIELD_PRIME) {
        CHECK_NOT_NULL(C = ec_point_alloc(ctx->params->ecp->len));
        DO(ecp_dual_mul_opt(ctx->params->ecp, ctx->params->precomp_p, K, NULL, NULL, C));
    }
    else {
        CHECK_NOT_NULL(C = ec_point_alloc(ctx->params->ec2m->len));
        DO(ec2m_dual_mul_opt(ctx->params->ec2m, ctx->params->precomp_p, K, NULL, NULL, C));
    }

    CHECK_NOT_NULL(tmp = wa_alloc(q->len * 2));
    CHECK_NOT_NULL(wr = wa_alloc(q->len));
    CHECK_NOT_NULL(ws = wa_alloc(q->len));

    /* A5. r=(𝑒+𝑥1)mod𝑛 */
    DO(wa_copy(C->x, tmp));
    int_div(tmp, q, NULL, wr);
    if ((int_add(wr, e, wr) > 0) || (int_cmp(wr, q) >= 0)) {
        //int_sub(wr, q, wr);
        DO(wa_copy(wr, tmp));
        int_div(tmp, q, NULL, wr);
    }

    int_add(wr, K, ws);

    if (int_is_zero(wr) || int_equals(ws, q)) {
        ret = -1;
        goto cleanup;
    }

    /* A6. 𝑠=((𝑘−𝑟*𝑑) / (1+𝑑))mod𝑛 */
    CHECK_NOT_NULL(t = wa_alloc(q->len));
    wa_zero(t);
    t->buf[0] = 1;
    int_add(ctx->priv_key, t, t);
    CHECK_NOT_NULL(t_inv = gfp_mod_inv_core(t, q));
    int_mul(wr, ctx->priv_key, tmp);
    int_div(tmp, q, NULL, ws);
    int_sub(q, ws, ws);

    if ((int_add(K, ws, ws) > 0) || (int_cmp(ws, q) >= 0)) {
        int_sub(ws, q, ws);
    }

    int_mul(ws, t_inv, tmp);
    int_div(tmp, q, NULL, ws);

    /* Якщо s = 0, то повернутися до Шагу 2. */
    if (int_is_zero(ws)) {
        ret = -1;
    }
    else {
        CHECK_NOT_NULL(r = wa_to_ba(wr));
        CHECK_NOT_NULL(s = wa_to_ba(ws));

        DO(ba_change_len(r, q_byte_len));
        DO(ba_change_len(s, q_byte_len));
        DO(ba_swap(r));
        DO(ba_swap(s));

        *R = r;
        *S = s;

        r = NULL;
        s = NULL;
    }

cleanup:

    wa_free_private(tmp);
    wa_free_private(t);
    wa_free_private(t_inv);
    wa_free(e);
    wa_free(wr);
    wa_free(ws);
    ba_free(r);
    ba_free(s);
    ec_point_free(C);

    return ret;
}

int sm2dsa_sign(const EcCtx* ctx, const ByteArray* H, ByteArray** r, ByteArray** s)
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
        ret = sm2dsa_sign_internal(ctx, H, k, r, s);
    } while (ret == -1);

cleanup:

    wa_free_private(k);

    return ret;
}

int sm2dsa_verify(const EcCtx *ctx, const ByteArray *H, const ByteArray *R, const ByteArray *S)
{
    WordArray* r_act = NULL;
    WordArray *e = NULL;
    WordArray* wr = NULL;
    WordArray* ws = NULL;
    WordArray* t = NULL;
    WordArray* tmp = NULL;
    ECPoint *C = NULL;
    const WordArray *q;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(H != NULL);
    CHECK_PARAM(R != NULL);
    CHECK_PARAM(S != NULL);

    if (ctx->verify_status == 0) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    q = ctx->params->n;

    if (ctx->verify_status == 0) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    q = ctx->params->n;

    CHECK_NOT_NULL(wr = wa_alloc_from_be(R->buf, R->len));
    CHECK_NOT_NULL(ws = wa_alloc_from_be(S->buf, S->len));

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
    wa_change_len(e, q->len);

    CHECK_NOT_NULL(t = wa_alloc(q->len));
    if ((int_add(wr, ws, t) > 0) || (int_cmp(t, q) >= 0)) {
        int_sub(t, q, t);
    }

    /* 6. Compute C = tY + sG, where Y is the public key */
    if (ctx->params->ec_field == EC_FIELD_PRIME) {
        CHECK_NOT_NULL(C = ec_point_alloc(ctx->params->ecp->len));
        DO(ecp_dual_mul_opt(ctx->params->ecp, ctx->params->precomp_p, ws, ctx->precomp_q, t, C));
    }
    else {
        CHECK_NOT_NULL(C = ec_point_alloc(ctx->params->ec2m->len));
        DO(ec2m_dual_mul_opt(ctx->params->ec2m, ctx->params->precomp_p, ws, ctx->precomp_q, t, C));
    }

    CHECK_NOT_NULL(tmp = wa_alloc(q->len * 2));
    CHECK_NOT_NULL(r_act = wa_alloc(q->len));

    /* 𝑅=(𝑒′+𝑥1′)mod */
    DO(wa_copy(C->x, tmp));
    int_div(tmp, q, NULL, r_act);
    if ((int_add(r_act, e, r_act) > 0) || (int_cmp(r_act, q) >= 0)) {
        //int_sub(r_act, q, r_act);
        DO(wa_copy(r_act, tmp));
        int_div(tmp, q, NULL, r_act);
    }

    /* Check if r == r' */
    if (wa_cmp(r_act, wr) != 0) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

cleanup:

    wa_free(e);
    wa_free(wr);
    wa_free(ws);
    wa_free(t);
    wa_free(tmp);
    wa_free(r_act);
    ec_point_free(C);

    return ret;
}

HashCtx* sm2dsa_hash_alloc(const EcCtx* ctx, HashAlg hash_alg, const ByteArray* id, const ByteArray* qx, const ByteArray* qy)
{
    int ret = RET_OK;
    HashCtx* hash_ctx = NULL;
    ByteArray* tmp = NULL;
    size_t params_len = 0;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(qx != NULL);
    CHECK_PARAM(qy != NULL);

    CHECK_NOT_NULL(hash_ctx = hash_alloc(hash_alg));

    if (id != NULL) {
        size_t id_bit_len = id->len * 8;

        CHECK_PARAM(id_bit_len <= 65535);
        CHECK_NOT_NULL(tmp = ba_alloc_by_len(2));

        tmp->buf[0] = (id_bit_len >> 8) & 0xFF;
        tmp->buf[1] = id_bit_len & 0xFF;
        DO(hash_update(hash_ctx, tmp));
        DO(hash_update(hash_ctx, id));
        ba_free(tmp);
        tmp = NULL;
    }

    if (ctx->params->ec_field == EC_FIELD_PRIME) {
        params_len = (int_bit_len(ctx->params->ecp->gfp->p) + 7) / 8;
                
        CHECK_NOT_NULL(tmp = wa_to_ba(ctx->params->ecp->a));
        DO(ba_change_len(tmp, params_len));
        DO(ba_swap(tmp));
        DO(hash_update(hash_ctx, tmp));
        ba_free(tmp);
        tmp = NULL;

        CHECK_NOT_NULL(tmp = wa_to_ba(ctx->params->ecp->b));
        DO(ba_change_len(tmp, params_len));
        DO(ba_swap(tmp));
        DO(hash_update(hash_ctx, tmp));
        ba_free(tmp);
        tmp = NULL;
    }
    else {
        params_len = ((size_t)ctx->params->ec2m->gf2m->f[0] + 7) / 8;

        CHECK_NOT_NULL(tmp = ba_alloc_by_len(1));
        tmp->buf[0] = (uint8_t)ctx->params->ec2m->a;
        DO(ba_change_len(tmp, params_len));
        DO(ba_swap(tmp));
        DO(hash_update(hash_ctx, tmp));
        ba_free(tmp);
        tmp = NULL;

        CHECK_NOT_NULL(tmp = wa_to_ba(ctx->params->ec2m->b));
        DO(ba_change_len(tmp, params_len));
        DO(ba_swap(tmp));
        DO(hash_update(hash_ctx, tmp));
        ba_free(tmp);
        tmp = NULL;
    }

    CHECK_NOT_NULL(tmp = wa_to_ba(ctx->params->p->x));
    DO(ba_change_len(tmp, params_len));
    DO(ba_swap(tmp));
    DO(hash_update(hash_ctx, tmp));
    ba_free(tmp);
    tmp = NULL;

    CHECK_NOT_NULL(tmp = wa_to_ba(ctx->params->p->y));
    DO(ba_change_len(tmp, params_len));
    DO(ba_swap(tmp));
    DO(hash_update(hash_ctx, tmp));
    ba_free(tmp);
    tmp = NULL;

    DO(hash_update(hash_ctx, qx));
    DO(hash_update(hash_ctx, qy));
    DO(hash_final(hash_ctx, &tmp));

    DO(hash_update(hash_ctx, tmp));

cleanup:
    if (ret != RET_OK) {
        hash_free(hash_ctx);
        hash_ctx = NULL;
    }
    ba_free(tmp);
    return hash_ctx;
}

static const uint8_t test_Msg[] = "message digest";
static const uint8_t test_ID[] = "ALICE123@YAHOO.COM";
static const ByteArray ba_Msg = { (uint8_t*)test_Msg, sizeof(test_Msg) - 1 };
static const ByteArray ba_ID = { (uint8_t*)test_ID, sizeof(test_ID) - 1 };

static int sm2dsa_p_self_test(void)
{
    // ДСТУ ISO/IEC 14888-3:2019. F.14.1
    static const uint8_t test_d[] = {
        0x12, 0x8B, 0x2F, 0xA8, 0xBD, 0x43, 0x3C, 0x6C, 0x06, 0x8C, 0x8D, 0x80, 0x3D, 0xFF, 0x79, 0x79, 
        0x2A, 0x51, 0x9A, 0x55, 0x17, 0x1B, 0x1B, 0x65, 0x0C, 0x23, 0x66, 0x1D, 0x15, 0x89, 0x72, 0x63 };
    static const uint8_t test_Qx[] = {
        0x0A, 0xE4, 0xC7, 0x79, 0x8A, 0xA0, 0xF1, 0x19, 0x47, 0x1B, 0xEE, 0x11, 0x82, 0x5B, 0xE4, 0x62, 
        0x02, 0xBB, 0x79, 0xE2, 0xA5, 0x84, 0x44, 0x95, 0xE9, 0x7C, 0x04, 0xFF, 0x4D, 0xF2, 0x54, 0x8A };
    static const uint8_t test_Qy[] = {
        0x7C, 0x02, 0x40, 0xF8, 0x8F, 0x1C, 0xD4, 0xE1, 0x63, 0x52, 0xA7, 0x3C, 0x17, 0xB7, 0xF1, 0x6F, 
        0x07, 0x35, 0x3E, 0x53, 0xA1, 0x76, 0xD6, 0x84, 0xA9, 0xFE, 0x0C, 0x6B, 0xB7, 0x98, 0xE8, 0x57 };
    static const uint8_t test_k[] = {
        0x6C, 0xB2, 0x8D, 0x99, 0x38, 0x5C, 0x17, 0x5C, 0x94, 0xF9, 0x4E, 0x93, 0x48, 0x17, 0x66, 0x3F, 
        0xC1, 0x76, 0xD9, 0x25, 0xDD, 0x72, 0xB7, 0x27, 0x26, 0x0D, 0xBA, 0xAE, 0x1F, 0xB2, 0xF9, 0x6F };
    static const uint8_t test_R[] = {
        0x40, 0xF1, 0xEC, 0x59, 0xF7, 0x93, 0xD9, 0xF4, 0x9E, 0x09, 0xDC, 0xEF, 0x49, 0x13, 0x0D, 0x41, 
        0x94, 0xF7, 0x9F, 0xB1, 0xEE, 0xD2, 0xCA, 0xA5, 0x5B, 0xAC, 0xDB, 0x49, 0xC4, 0xE7, 0x55, 0xD1 };
    static const uint8_t test_S[] = {
        0x6F, 0xC6, 0xDA, 0xC3, 0x2C, 0x5D, 0x5C, 0xF1, 0x0C, 0x77, 0xDF, 0xB2, 0x0F, 0x7C, 0x2E, 0xB6, 
        0x67, 0xA4, 0x57, 0x87, 0x2F, 0xB0, 0x9E, 0xC5, 0x63, 0x27, 0xA6, 0x7E, 0xC7, 0xDE, 0xEB, 0xE7 };
    static const uint8_t testH_Z_M[] = {
        0xB5, 0x24, 0xF5, 0x52, 0xCD, 0x82, 0xB8, 0xB0, 0x28, 0x47, 0x6E, 0x00, 0x5C, 0x37, 0x7F, 0xB1,
        0x9A, 0x87, 0xE6, 0xFC, 0x68, 0x2D, 0x48, 0xBB, 0x5D, 0x42, 0xE3, 0xD9, 0xB9, 0xEF, 0xFE, 0x76 };

    static const ByteArray ba_d = { (uint8_t*)test_d, sizeof(test_d) };

    int ret = RET_OK;
    EcCtx* ec_ctx = NULL;
    HashCtx* hash_ctx = NULL;
    ByteArray* ba_hash = NULL;
    WordArray* wa_k = NULL;
    ByteArray* ba_Qx = NULL;
    ByteArray* ba_Qy = NULL;
    ByteArray* ba_R = NULL;
    ByteArray* ba_S = NULL;

    CHECK_NOT_NULL(ec_ctx = ec_alloc_default(EC_PARAMS_ID_CN_P256));
    DO(sm2dsa_get_pubkey(ec_ctx, &ba_d, &ba_Qx, &ba_Qy));
    if (ba_Qx->len != sizeof(test_Qx) || 
        ba_Qy->len != sizeof(test_Qy) ||
        memcmp(ba_Qx->buf, test_Qx, sizeof(test_Qx)) != 0 ||
        memcmp(ba_Qy->buf, test_Qy, sizeof(test_Qy)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

    CHECK_NOT_NULL(hash_ctx = sm2dsa_hash_alloc(ec_ctx, HASH_ALG_SM3, &ba_ID, ba_Qx, ba_Qy));
    DO(hash_update(hash_ctx, &ba_Msg));
    DO(hash_final(hash_ctx, &ba_hash));

    if (memcmp(ba_hash->buf, testH_Z_M, sizeof(testH_Z_M)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

    CHECK_NOT_NULL(wa_k = wa_alloc_from_be(test_k, sizeof(test_k)));

    DO(ec_init_sign(ec_ctx, &ba_d));
    DO(sm2dsa_sign_internal(ec_ctx, ba_hash, wa_k, &ba_R, &ba_S));

    if (ba_R->len != sizeof(test_R) ||
        ba_S->len != sizeof(test_S) ||
        memcmp(ba_R->buf, test_R, sizeof(test_R)) != 0 ||
        memcmp(ba_S->buf, test_S, sizeof(test_S)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

    DO(ec_init_verify(ec_ctx, ba_Qx, ba_Qy));
    DO(sm2dsa_verify(ec_ctx, ba_hash, ba_R, ba_S));

cleanup:
    ba_free(ba_hash);
    ba_free(ba_Qx);
    ba_free(ba_Qy);
    ba_free(ba_R);
    ba_free(ba_S);
    wa_free(wa_k);
    hash_free(hash_ctx);
    ec_free(ec_ctx);
    return ret;
}


static int sm2dsa_b_self_test(void)
{
    // ДСТУ ISO/IEC 14888-3:2019. F.14.2
    static const uint8_t test_d[] = {
        0x77, 0x1E, 0xF3, 0xDB, 0xFF, 0x5F, 0x1C, 0xDC, 0x32, 0xB9, 0xC5, 0x72, 0x93, 0x04, 0x76, 0x19,
        0x19, 0x98, 0xB2, 0xBF, 0x7C, 0xB9, 0x81, 0xD7, 0xF5, 0xB3, 0x92, 0x02, 0x64, 0x5F, 0x09, 0x31 };
    static const uint8_t test_Qx[] = {
        0x01, 0x65, 0x96, 0x16, 0x45, 0x28, 0x1A, 0x86, 0x26, 0x60, 0x7B, 0x91, 0x7F, 0x65, 0x7D, 0x7E,
        0x93, 0x82, 0xF1, 0xEA, 0x5C, 0xD9, 0x31, 0xF4, 0x0F, 0x66, 0x27, 0xF3, 0x57, 0x54, 0x26, 0x53, 0xB2 };
    static const uint8_t test_Qy[] = {
        0x01, 0x68, 0x65, 0x22, 0x13, 0x0D, 0x59, 0x0F, 0xB8, 0xDE, 0x63, 0x5D, 0x8F, 0xCA, 0x71, 0x5C,
        0xC6, 0xBF, 0x3D, 0x05, 0xBE, 0xF3, 0xF7, 0x5D, 0xA5, 0xD5, 0x43, 0x45, 0x44, 0x48, 0x16, 0x66, 0x12 };
    static const uint8_t test_k[] = {
        0x36, 0xCD, 0x79, 0xFC, 0x8E, 0x24, 0xB7, 0x35, 0x7A, 0x8A, 0x7B, 0x4A, 0x46, 0xD4, 0x54, 0xC3,
        0x97, 0x70, 0x3D, 0x64, 0x98, 0x15, 0x8C, 0x60, 0x53, 0x99, 0xB3, 0x41, 0xAD, 0xA1, 0x86, 0xD6 };
    static const uint8_t test_R[] = {
        0x6D, 0x3F, 0xBA, 0x26, 0xEA, 0xB2, 0xA1, 0x05, 0x4F, 0x5D, 0x19, 0x83, 0x32, 0xE3, 0x35, 0x81,
        0x7C, 0x8A, 0xC4, 0x53, 0xED, 0x26, 0xD3, 0x39, 0x1C, 0xD4, 0x43, 0x9D, 0x82, 0x5B, 0xF2, 0x5B };
    static const uint8_t test_S[] = {
        0x31, 0x24, 0xC5, 0x68, 0x8D, 0x95, 0xF0, 0xA1, 0x02, 0x52, 0xA9, 0xBE, 0xD0, 0x33, 0xBE, 0xC8,
        0x44, 0x39, 0xDA, 0x38, 0x46, 0x21, 0xB6, 0xD6, 0xFA, 0xD7, 0x7F, 0x94, 0xB7, 0x4A, 0x95, 0x56 };
    static const uint8_t testH_Z_M[] = {
        0xAD, 0x67, 0x3C, 0xBD, 0xA3, 0x11, 0x41, 0x71, 0x29, 0xA9, 0xEA, 0xA5, 0xF9, 0xAB, 0x1A, 0xA1, 
        0x63, 0x3A, 0xD4, 0x77, 0x18, 0xA8, 0x4D, 0xFD, 0x46, 0xC1, 0x7C, 0x6F, 0xA0, 0xAA, 0x3B, 0x12 };

    static const ByteArray ba_d = { (uint8_t*)test_d, sizeof(test_d) };

    int ret = RET_OK;
    EcCtx* ec_ctx = NULL;
    HashCtx* hash_ctx = NULL;
    ByteArray* ba_hash = NULL;
    WordArray* wa_k = NULL;
    ByteArray* ba_Qx = NULL;
    ByteArray* ba_Qy = NULL;
    ByteArray* ba_R = NULL;
    ByteArray* ba_S = NULL;

    CHECK_NOT_NULL(ec_ctx = ec_alloc_default(EC_PARAMS_ID_CN_B257));
    DO(sm2dsa_get_pubkey(ec_ctx, &ba_d, &ba_Qx, &ba_Qy));
    if (ba_Qx->len != sizeof(test_Qx) ||
        ba_Qy->len != sizeof(test_Qy) ||
        memcmp(ba_Qx->buf, test_Qx, sizeof(test_Qx)) != 0 ||
        memcmp(ba_Qy->buf, test_Qy, sizeof(test_Qy)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

    CHECK_NOT_NULL(hash_ctx = sm2dsa_hash_alloc(ec_ctx, HASH_ALG_SM3, &ba_ID, ba_Qx, ba_Qy));
    DO(hash_update(hash_ctx, &ba_Msg));
    DO(hash_final(hash_ctx, &ba_hash));

    if (memcmp(ba_hash->buf, testH_Z_M, sizeof(testH_Z_M)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

    CHECK_NOT_NULL(wa_k = wa_alloc_from_be(test_k, sizeof(test_k)));

    DO(ec_init_sign(ec_ctx, &ba_d));
    DO(sm2dsa_sign_internal(ec_ctx, ba_hash, wa_k, &ba_R, &ba_S));

    if (ba_R->len != sizeof(test_R) ||
        ba_S->len != sizeof(test_S) ||
        memcmp(ba_R->buf, test_R, sizeof(test_R)) != 0 ||
        memcmp(ba_S->buf, test_S, sizeof(test_S)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

    DO(ec_init_verify(ec_ctx, ba_Qx, ba_Qy));
    DO(sm2dsa_verify(ec_ctx, ba_hash, ba_R, ba_S));

cleanup:
    ba_free(ba_hash);
    ba_free(ba_Qx);
    ba_free(ba_Qy);
    ba_free(ba_R);
    ba_free(ba_S);
    wa_free(wa_k);
    hash_free(hash_ctx);
    ec_free(ec_ctx);
    return ret;
}

int sm2dsa_self_test(void)
{
    int ret = RET_OK;

    DO(sm2dsa_p_self_test());
    DO(sm2dsa_b_self_test());

cleanup:
    return ret;
}