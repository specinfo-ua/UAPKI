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
#include "eckcdsa.h"
#include "ec-internal.h"
#include "ec-cache-internal.h"
#include "math-int-internal.h"
#include "macros-internal.h"

#undef FILE_MARKER
#define FILE_MARKER "uapkic/eckcdsa.c"

int eckcdsa_generate_privkey(const EcCtx *ctx, ByteArray **d)
{
    return ec_generate_privkey(ctx, d);
}

int eckcdsa_get_pubkey(const EcCtx* ctx, const ByteArray* d, ByteArray** qx, ByteArray** qy)
{
    size_t blen;
    WordArray* wd = NULL;
    WordArray* winvd = NULL;
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
    CHECK_NOT_NULL(winvd = gfp_mod_inv_core(wd, ctx->params->n));

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
        DO(ecp_dual_mul_opt(ctx->params->ecp, ctx->params->precomp_p, winvd, NULL, NULL, r));
    }
    else {
        CHECK_NOT_NULL(r = ec_point_alloc(ctx->params->ec2m->len));
        blen = ((size_t)ctx->params->ec2m->gf2m->f[0] + 7) / 8;
        DO(ec2m_dual_mul_opt(ctx->params->ec2m, ctx->params->precomp_p, winvd, NULL, NULL, r));
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
    wa_free_private(winvd);

    return ret;
}

/**
 * - 1. Compute h = H(z || m)
 * 2. If | H | > bitlen(q), set h to beta' rightmost bits of
 *    bitstring h(w / beta' = 8 * ceil(bitlen(q) / 8)), i.e.
 *    set h to I2BS(beta', BS2I(|H|, h) mod 2^beta')
 * 3. Get a random value k in ]0, q[
 * 4. Compute W = (W_x, W_y) = kG
 * 5. Compute r = H(FE2OS(W_x)).
 * 6. If | H | > bitlen(q), set r to beta' rightmost bits of
 *    bitstring r(w / beta' = 8 * ceil(bitlen(q) / 8)), i.e.
 *    set r to I2BS(beta', BS2I(|H|, r) mod 2^beta')
 * 7. Compute e = OS2I(r XOR h) mod q
 * 8. Compute s = x(k - e) mod q
 * 9. if s == 0, restart at step 3.
 * 10. return (r, s)
 */
static int eckcdsa_sign_internal(const EcCtx* ctx, const ByteArray* H, HashAlg hash_alg, const WordArray* K, ByteArray** R, ByteArray** S)
{
    HashCtx *hash_ctx = NULL;
    ByteArray* hzm = NULL;
    ByteArray* h = NULL;
    ByteArray* r = NULL;
    ByteArray* s = NULL;
    WordArray* tmp = NULL;
    WordArray* t = NULL;
    WordArray* ws = NULL;
    ECPoint* C = NULL;
    const WordArray* q;
    int ret = RET_OK;
    size_t i, q_byte_len, r_len, shift;

    q = ctx->params->n;
    q_byte_len = (int_bit_len(q) + 7) / 8;
    r_len = q_byte_len;
    if (r_len > H->len) {
        r_len = H->len;
    }

    shift = H->len > r_len ? H->len - r_len : 0;
    CHECK_NOT_NULL(hzm = ba_copy_with_alloc(H, shift, r_len));

    /* Шаг 3. Обчислити точку ЕК C = kP,
     * c = (cx, cy) та визначити r = cx (mod q). */
    if (ctx->params->ec_field == EC_FIELD_PRIME) {
        CHECK_NOT_NULL(C = ec_point_alloc(ctx->params->ecp->len));
        DO(ecp_dual_mul_opt(ctx->params->ecp, ctx->params->precomp_p, K, NULL, NULL, C));
        CHECK_NOT_NULL(r = wa_to_ba(C->x));
        DO(ba_change_len(r, (int_bit_len(ctx->params->ecp->gfp->p) + 7) / 8));
    }
    else {
        CHECK_NOT_NULL(C = ec_point_alloc(ctx->params->ec2m->len));
        DO(ec2m_dual_mul_opt(ctx->params->ec2m, ctx->params->precomp_p, K, NULL, NULL, C));
        CHECK_NOT_NULL(r = wa_to_ba(C->x));
        DO(ba_change_len(r, ((size_t)ctx->params->ec2m->gf2m->f[0] + 7) / 8));
    }
    
    DO(ba_swap(r));
    CHECK_NOT_NULL(hash_ctx = hash_alloc(hash_alg));
    DO(hash_update(hash_ctx, r));
    DO(hash_final(hash_ctx, &h));

    ba_free(r);
    r = NULL;
    CHECK_NOT_NULL(r = ba_copy_with_alloc(h, shift, r_len));

    for (i = 0; i < r_len; i++) {
        hzm->buf[i] ^= r->buf[i];
    }

    CHECK_NOT_NULL(tmp = wa_alloc_from_be(hzm->buf, r_len));
    wa_change_len(tmp, q->len * 2);
    CHECK_NOT_NULL(ws = wa_alloc(q->len));
    int_div(tmp, q, NULL, ws);

    /* s = d(k - e) (mod q). */
    int_sub(q, ws, ws);
    if ((int_add(K, ws, ws) > 0) || (int_cmp(ws, q) >= 0)) {
        int_sub(ws, q, ws);
    }

    int_mul(ws, ctx->priv_key, tmp);
    int_div(tmp, q, NULL, ws);

    /* Якщо s = 0, то повернутися до Шагу 2. */
    if (int_is_zero(ws)) {
        ret = -1;
    }
    else {
        CHECK_NOT_NULL(s = wa_to_ba(ws));

        DO(ba_change_len(s, q_byte_len));
        DO(ba_swap(s));

        *R = r;
        *S = s;

        r = NULL;
        s = NULL;
    }

cleanup:

    hash_free(hash_ctx);
    wa_free_private(tmp);
    wa_free_private(t);
    wa_free(ws);
    ba_free(hzm);
    ba_free(h);
    ba_free(r);
    ba_free(s);
    ec_point_free(C);

    return ret;
}

int eckcdsa_sign(const EcCtx* ctx, const ByteArray* H, HashAlg hash_alg, ByteArray** r, ByteArray** s)
{
    WordArray* k = NULL;
    const WordArray* q;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(H != NULL);
    CHECK_PARAM(r != NULL);
    CHECK_PARAM(s != NULL);
    CHECK_PARAM(H->len == hash_get_size(hash_alg));

    if (!ctx->sign_status) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    q = ctx->params->n;

    CHECK_NOT_NULL(k = wa_alloc(q->len));

    do {
        /* Шаг 2. Згенерувати випадкове число k (0 < k < q). */
        DO(int_rand(q, k));
        ret = eckcdsa_sign_internal(ctx, H, hash_alg, k, r, s);
    } while (ret == -1);

cleanup:

    wa_free_private(k);

    return ret;
}

int eckcdsa_verify(const EcCtx *ctx, const ByteArray *H, HashAlg hash_alg, const ByteArray *R, const ByteArray *S)
{
    HashCtx* hash_ctx = NULL;
    ByteArray* hzm = NULL;
    ByteArray* h = NULL;
    ByteArray* r = NULL;
    ByteArray* r_act = NULL;
    WordArray *e = NULL;
    WordArray *ws = NULL;
    WordArray* tmp = NULL;
    ECPoint *C = NULL;
    const WordArray *q;
    int ret = RET_OK;
    size_t i, q_byte_len, r_len, shift;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(H != NULL);
    CHECK_PARAM(R != NULL);
    CHECK_PARAM(S != NULL);
    CHECK_PARAM(H->len == hash_get_size(hash_alg));

    if (ctx->verify_status == 0) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    q = ctx->params->n;
    q_byte_len = (int_bit_len(q) + 7) / 8;
    r_len = q_byte_len;
    if (r_len > H->len) {
        r_len = H->len;
    }

    CHECK_PARAM(R->len == r_len);
    CHECK_PARAM(S->len == q_byte_len);

    /*
     * 4. If |H| > bitlen(q), set h to beta' rightmost bits of
     *    bitstring h (w/ beta' = 8 * ceil(bitlen(q) / 8)), i.e.
     *    set h to I2BS(beta', BS2I(|H|, h) mod 2^beta')
     */
    shift = H->len > r_len ? H->len - r_len : 0;
    CHECK_NOT_NULL(hzm = ba_copy_with_alloc(H, shift, r_len));

    /* 5. Compute e = OS2I(r XOR h) mod q */
    for (i = 0; i < r_len; i++) {
        hzm->buf[i] ^= R->buf[i];
    }

    CHECK_NOT_NULL(tmp = wa_alloc_from_be(hzm->buf, r_len));
    wa_change_len(tmp, q->len * 2);
    CHECK_NOT_NULL(e = wa_alloc(q->len));
    int_div(tmp, q, NULL, e);

    CHECK_NOT_NULL(ws = wa_alloc_from_be(S->buf, S->len));
    wa_change_len(ws, q->len);

    /* 6. Compute C = sY + eG, where Y is the public key */
    if (ctx->params->ec_field == EC_FIELD_PRIME) {
        CHECK_NOT_NULL(C = ec_point_alloc(ctx->params->ecp->len));
        DO(ecp_dual_mul_opt(ctx->params->ecp, ctx->params->precomp_p, e, ctx->precomp_q, ws, C));
        CHECK_NOT_NULL(r = wa_to_ba(C->x));
        DO(ba_change_len(r, (int_bit_len(ctx->params->ecp->gfp->p) + 7) / 8));
    }
    else {
        CHECK_NOT_NULL(C = ec_point_alloc(ctx->params->ec2m->len));
        DO(ec2m_dual_mul_opt(ctx->params->ec2m, ctx->params->precomp_p, e, ctx->precomp_q, ws, C));
        CHECK_NOT_NULL(r = wa_to_ba(C->x));
        DO(ba_change_len(r, ((size_t)ctx->params->ec2m->gf2m->f[0] + 7) / 8));
    }

    /* 7. Compute r' = h(W'x) */
    DO(ba_swap(r));
    CHECK_NOT_NULL(hash_ctx = hash_alloc(hash_alg));
    DO(hash_update(hash_ctx, r));
    DO(hash_final(hash_ctx, &h));

    /*
     * 8. If |H| > bitlen(q), set r' to beta' rightmost bits of
     *    bitstring r' (w/ beta' = 8 * ceil(bitlen(q) / 8)), i.e.
     *    set r' to I2BS(beta', BS2I(|H|, r') mod 2^beta')
     */
    CHECK_NOT_NULL(r_act = ba_copy_with_alloc(h, shift, r_len));

    /* 9. Check if r == r' */
    if (ba_cmp(r_act, R) != 0) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

cleanup:

    hash_free(hash_ctx);
    wa_free(e);
    wa_free(ws);
    wa_free(tmp);
    ba_free(hzm);
    ba_free(h);
    ba_free(r);
    ba_free(r_act);
    ec_point_free(C);

    return ret;
}

HashCtx* eckcdsa_hash_alloc(HashAlg hash_alg, const ByteArray* Qx, const ByteArray* Qy)
{
    int ret = RET_OK;
    HashCtx* ctx = NULL;
    ByteArray* ba_Z = NULL;

    CHECK_NOT_NULL(ctx = hash_alloc(hash_alg));
    CHECK_NOT_NULL(ba_Z = ba_join(Qx, Qy));
    DO(ba_change_len(ba_Z, hash_get_block_size(ctx)));
    DO(hash_update(ctx, ba_Z));

cleanup:
    if (ret != RET_OK) {
        hash_free(ctx);
        ctx = NULL;
    }
    ba_free(ba_Z);
    return ctx;
}


static const uint8_t test_Msg[] = "This is a sample message for EC-KCDSA implementation validation.";
static const ByteArray ba_Msg = { (uint8_t*)test_Msg, sizeof(test_Msg) - 1 };

static int eckcdsa_p_self_test(void)
{
    // ДСТУ ISO/IEC 14888-3:2019. F.7.2
    static const uint8_t test_d[] = {
        0x90, 0x51, 0xA2, 0x75, 0xAA, 0x4D, 0x98, 0x43, 0x9E, 0xDD, 0xED, 0x13, 0xFA, 0x1C, 0x6C, 0xBB,
        0xCC, 0xE7, 0x75, 0xD8, 0xCC, 0x94, 0x33, 0xDE, 0xE6, 0x9C, 0x59, 0x84, 0x8B, 0x35, 0x94, 0xDF };
    static const uint8_t test_Qx[] = {
        0x14, 0x8E, 0xDD, 0xD3, 0x73, 0x4F, 0xD5, 0xF1, 0x59, 0x87, 0x57, 0x9F, 0x51, 0x60, 0x89, 0xA8, 
        0xC9, 0xFE, 0xF4, 0xAB, 0x76, 0xB5, 0x9D, 0x7B, 0x8A, 0x01, 0xCD, 0xC5, 0x6C, 0x4E, 0xDF, 0xDF };
    static const uint8_t test_Qy[] = {
        0xA4, 0xE2, 0xE4, 0x2C, 0xB4, 0x37, 0x2A, 0x6F, 0x2F, 0x3F, 0x71, 0xA1, 0x49, 0x48, 0x15, 0x49, 
        0xF6, 0x8D, 0x29, 0x63, 0x53, 0x9C, 0x85, 0x3E, 0x46, 0xB9, 0x46, 0x96, 0x56, 0x9E, 0x8D, 0x61 };
    static const uint8_t test_k[] = {
        0x71, 0xB8, 0x8F, 0x39, 0x89, 0x16, 0xDA, 0x9C, 0x90, 0xF5, 0x55, 0xF1, 0xB5, 0x73, 0x2B, 0x7D,
        0xC6, 0x36, 0xB4, 0x9C, 0x63, 0x81, 0x50, 0xBA, 0xC1, 0x1B, 0xF0, 0x5C, 0xFE, 0x16, 0x59, 0x6A };
    static const uint8_t test_R[] = {
        0x0e, 0xdd, 0xf6, 0x80, 0x60, 0x12, 0x66, 0xee, 0x1d, 0xa8, 0x3e, 0x55, 0xa6, 0xd9, 0x44, 0x5f,
        0xc7, 0x81, 0xda, 0xeb, 0x14, 0xc7, 0x65, 0xe7, 0xe5, 0xd0, 0xcd, 0xba, 0xf1, 0xf1, 0x4a, 0x68 };
    static const uint8_t test_S[] = {
        0x9b, 0x33, 0x34, 0x57, 0x66, 0x1c, 0x7c, 0xf7, 0x41, 0xbd, 0xdb, 0xc0, 0x83, 0x55, 0x53, 0xdf, 
        0xbb, 0x37, 0xee, 0x74, 0xf5, 0x3d, 0xb6, 0x99, 0xe0, 0xa1, 0x77, 0x80, 0xc7, 0xb6, 0xf1, 0xd0 };
    static const uint8_t testH_Z_M[] = {
        0x68, 0x1C, 0x8E, 0xD8, 0x9E, 0x8B, 0x0E, 0x1B, 0xC3, 0x69, 0xAA, 0x10, 0x6F, 0x6B, 0x98, 0x13,
        0xE6, 0x33, 0x8F, 0x0C, 0x54, 0xBE, 0x57, 0x7A, 0x87, 0x62, 0x34, 0x92, 0x52, 0xF9, 0xBE, 0xDF };

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

    CHECK_NOT_NULL(ec_ctx = ec_alloc_default(EC_PARAMS_ID_NIST_P256));
    DO(eckcdsa_get_pubkey(ec_ctx, &ba_d, &ba_Qx, &ba_Qy));
    if (ba_Qx->len != sizeof(test_Qx) || 
        ba_Qy->len != sizeof(test_Qy) ||
        memcmp(ba_Qx->buf, test_Qx, sizeof(test_Qx)) != 0 ||
        memcmp(ba_Qy->buf, test_Qy, sizeof(test_Qy)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

    CHECK_NOT_NULL(hash_ctx = eckcdsa_hash_alloc(HASH_ALG_SHA256, ba_Qx, ba_Qy));
    DO(hash_update(hash_ctx, &ba_Msg));
    DO(hash_final(hash_ctx, &ba_hash));

    if (memcmp(ba_hash->buf, testH_Z_M, sizeof(testH_Z_M)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

    CHECK_NOT_NULL(wa_k = wa_alloc_from_be(test_k, sizeof(test_k)));

    DO(ec_init_sign(ec_ctx, &ba_d));
    DO(eckcdsa_sign_internal(ec_ctx, ba_hash, HASH_ALG_SHA256, wa_k, &ba_R, &ba_S));

    if (ba_R->len != sizeof(test_R) ||
        ba_S->len != sizeof(test_S) ||
        memcmp(ba_R->buf, test_R, sizeof(test_R)) != 0 ||
        memcmp(ba_S->buf, test_S, sizeof(test_S)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

    DO(ec_init_verify(ec_ctx, ba_Qx, ba_Qy));
    DO(eckcdsa_verify(ec_ctx, ba_hash, HASH_ALG_SHA256, ba_R, ba_S));

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


static int eckcdsa_b_self_test(void)
{
    // ДСТУ ISO/IEC 14888-3:2019. F.7.3
    static const uint8_t test_d[] = {
        0x00, 0xBF, 0x83, 0x82, 0x55, 0x05, 0x3D, 0xBF, 0x49, 0x9C, 0xBE, 0x19, 0x0D, 0xE3, 0x5B, 0xC1, 
        0x4A, 0xFC, 0x1E, 0xA1, 0x42, 0xF3, 0x5E, 0xE6, 0x98, 0x38, 0x5B, 0x48, 0xD6, 0x88 };
    static const uint8_t test_Qx[] = {
        0x01, 0xF4, 0x85, 0xA6, 0x5E, 0x59, 0xB3, 0x36, 0xE1, 0x40, 0x1C, 0x8A, 0x31, 0x1F, 0x01, 0xC9, 
        0x26, 0x26, 0xC6, 0x63, 0xE6, 0x9F, 0x12, 0xA6, 0x27, 0xE5, 0x3E, 0x8F, 0x06, 0x75 };
    static const uint8_t test_Qy[] = {
        0x01, 0xBF, 0x33, 0x8C, 0xE7, 0x5A, 0xDF, 0xB0, 0x7D, 0xEB, 0xD9, 0x62, 0xE1, 0xD8, 0x0C, 0x10, 
        0x15, 0x87, 0x26, 0x9A, 0xC9, 0x95, 0x1B, 0x40, 0x42, 0x2B, 0x12, 0xE9, 0xDA, 0x3E };
    static const uint8_t test_k[] = {
        0x00, 0xF4, 0xF0, 0x88, 0x19, 0x2E, 0x8E, 0xB1, 0xCD, 0x8B, 0x4E, 0xCB, 0x3A, 0x53, 0x33, 0x74, 
        0x6B, 0x40, 0xEB, 0xF1, 0x69, 0x66, 0xA2, 0x13, 0xB1, 0x8A, 0x17, 0x6B, 0x2F, 0x62 };
    static const uint8_t test_R[] = {
        0x82, 0xEF, 0x94, 0x27, 0x4A, 0xC7, 0x0A, 0x3D, 0xAC, 0x23, 0x1E, 0x38, 0xAE, 0x0F, 0x0D, 0x31, 
        0x8F, 0xD8, 0xE1, 0x89, 0xEE, 0x40, 0xA3, 0xE0, 0x61, 0xEC, 0x80, 0xBF };
    static const uint8_t test_S[] = {
        0x00, 0xA8, 0xCD, 0x7F, 0x75, 0x73, 0xBA, 0xC3, 0xC4, 0xC4, 0x00, 0xF6, 0x5F, 0xDC, 0xCC, 0xD4, 
        0x6F, 0x58, 0xEB, 0xFC, 0x54, 0xCE, 0x45, 0x57, 0x10, 0x75, 0xFD, 0x77, 0x04, 0xDB };
    static const uint8_t testH_Z_M[] = { 
        0xE7, 0x4B, 0x3C, 0x74, 0x72, 0xF2, 0xE9, 0x7E, 0xC3, 0x18, 0x61, 0xCA, 0x17, 0x73, 0x47, 0x2E, 
        0x58, 0x82, 0x8A, 0x98, 0x02, 0x62, 0x77, 0xCB, 0x00, 0xEF, 0x36, 0xAC };

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

    CHECK_NOT_NULL(ec_ctx = ec_alloc_default(EC_PARAMS_ID_NIST_B233));
    DO(eckcdsa_get_pubkey(ec_ctx, &ba_d, &ba_Qx, &ba_Qy));
    if (ba_Qx->len != sizeof(test_Qx) ||
        ba_Qy->len != sizeof(test_Qy) ||
        memcmp(ba_Qx->buf, test_Qx, sizeof(test_Qx)) != 0 ||
        memcmp(ba_Qy->buf, test_Qy, sizeof(test_Qy)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

    CHECK_NOT_NULL(hash_ctx = eckcdsa_hash_alloc(HASH_ALG_SHA224, ba_Qx, ba_Qy));
    DO(hash_update(hash_ctx, &ba_Msg));
    DO(hash_final(hash_ctx, &ba_hash));

    if (memcmp(ba_hash->buf, testH_Z_M, sizeof(testH_Z_M)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

    CHECK_NOT_NULL(wa_k = wa_alloc_from_be(test_k, sizeof(test_k)));

    DO(ec_init_sign(ec_ctx, &ba_d));
    DO(eckcdsa_sign_internal(ec_ctx, ba_hash, HASH_ALG_SHA224, wa_k, &ba_R, &ba_S));

    if (ba_R->len != sizeof(test_R) ||
        ba_S->len != sizeof(test_S) ||
        memcmp(ba_R->buf, test_R, sizeof(test_R)) != 0 ||
        memcmp(ba_S->buf, test_S, sizeof(test_S)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

    DO(ec_init_verify(ec_ctx, ba_Qx, ba_Qy));
    DO(eckcdsa_verify(ec_ctx, ba_hash, HASH_ALG_SHA224, ba_R, ba_S));

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

int eckcdsa_self_test(void)
{
    int ret = RET_OK;

    DO(eckcdsa_p_self_test());
    DO(eckcdsa_b_self_test());

cleanup:
    return ret;
}