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

#include <memory.h>

#include "rsa.h"
#include "math-int-internal.h"
#include "math-gfp-internal.h"
#include "byte-utils-internal.h"
#include "macros-internal.h"
#include "drbg.h"

#undef FILE_MARKER
#define FILE_MARKER "uapkic/rsa.c"

typedef enum {
    RSA_MODE_NONE = 0,
    RSA_MODE_ENCRYPT_PKCS,
    RSA_MODE_DECRYPT_PKCS,
    RSA_MODE_ENCRYPT_OAEP,
    RSA_MODE_DECRYPT_OAEP,
    RSA_MODE_SIGN_PKCS,
    RSA_MODE_VERIFY_PKCS,
    RSA_MODE_SIGN_PSS,
    RSA_MODE_VERIFY_PSS
} RsaMode;

struct RsaCtx_st {
    RsaMode mode_id;
    HashAlg hash_alg;
    ByteArray *label;
    size_t salt_len;
    GfpCtx *gfp;
    WordArray *e;
    WordArray *d;
};

#define MIN_RSA_BITS     (512)
#define MAX_RSA_BITS    (8192)

#define WA_TO_BE_WITH_TRUNC(wa, ba) {                   \
    CHECK_NOT_NULL(ba = wa_to_ba(wa));                  \
    DO(ba_change_len(ba, (int_bit_len(wa) + 7) >> 3));  \
    DO(ba_swap(ba));                                    \
}

#define WA_TO_BE_WITH_N_LEN(ctx, wa, ba) {                   \
    CHECK_NOT_NULL(ba = wa_to_ba(wa));                  \
    DO(ba_change_len(ba, (int_bit_len((ctx)->gfp->p) + 7) >> 3));  \
    DO(ba_swap(ba));                                    \
}

static int mgf(HashAlg hash_alg, const void *seed, size_t seed_len, uint8_t *mask, size_t mask_len)
{
    int ret = RET_OK;
    ByteArray *bseed = NULL;
    ByteArray *bhash = NULL;
    ByteArray *count = NULL;
    HashCtx *hash_ctx = NULL;
    size_t hlen;
    size_t offset = 0;
    const int idx = 3;
    size_t iter;

    hlen = hash_get_size(hash_alg);
    iter = 1 + (mask_len - 1) / hlen;

    CHECK_NOT_NULL(count = ba_alloc_by_len(4));
    DO(ba_set(count, 0));

    CHECK_NOT_NULL(bseed = ba_alloc_from_uint8(seed, seed_len));

    CHECK_NOT_NULL(hash_ctx = hash_alloc(hash_alg));

    for (count->buf[idx] = 0; count->buf[idx] < iter; count->buf[idx]++) {
        DO(hash_update(hash_ctx, bseed));
        DO(hash_update(hash_ctx, count));
        ba_free(bhash);
        bhash = NULL;
        DO(hash_final(hash_ctx, &bhash));
        memcpy(mask + offset, bhash->buf, hlen < mask_len - offset ? hlen : mask_len - offset);
        offset += hlen;
    }

cleanup:

    ba_free(bseed);
    ba_free(bhash);
    ba_free(count);
    hash_free(hash_ctx);

    return ret;
}

static uint8_t* oaep_get_lhash(HashAlg hash_alg, const ByteArray* label)
{
    int ret = RET_OK;
    uint8_t* H = NULL;
    ByteArray* hash_ba = NULL;
    HashCtx* hash_ctx = NULL;

    CHECK_NOT_NULL(hash_ctx = hash_alloc(hash_alg));
    if (label != NULL) {
        DO(hash_update(hash_ctx, label));
    }
    DO(hash_final(hash_ctx, &hash_ba));
    MALLOC_CHECKED(H, hash_ba->len);
    memcpy(H, ba_get_buf_const(hash_ba), ba_get_len(hash_ba));

cleanup:
    hash_free(hash_ctx);
    ba_free(hash_ba);
    if (ret != RET_OK) {
        free(H);
        H = NULL;
    }
    return H;
}

static int rsaedp(const GfpCtx *gfp, const WordArray *x, WordArray *src, WordArray **dst)
{
    int ret = RET_OK;

    CHECK_NOT_NULL(*dst = wa_alloc(gfp->p->len));
    wa_change_len(src, gfp->p->len);
    gfp_mod_pow(gfp, src, x, *dst);

cleanup:

    return ret;
}

static int rsa_encrypt_pkcs1_v1_5(RsaCtx *ctx, const ByteArray *data, ByteArray **out)
{
    uint8_t *m = NULL;
    size_t len;
    size_t off;
    size_t data_len;
    WordArray *wm = NULL;
    WordArray *wout = NULL;
    ByteArray *seed = NULL;
    int ret = RET_OK;

    if (ctx->mode_id != RSA_MODE_ENCRYPT_PKCS) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    len = ctx->gfp->p->len * WORD_BYTE_LENGTH;
    data_len = ba_get_len(data);

    if (ba_get_len(data) > len - 11) {
        SET_ERROR(RET_DATA_TOO_LONG);
    }

    MALLOC_CHECKED(m, len);

    /* EM = 0x00 || 0x02 || PS || 0x00 || M */
    m[0] = 0;
    m[1] = 2;
    CHECK_NOT_NULL(seed = ba_alloc_by_len(len - data_len - 3));
    DO(drbg_random(seed));
    ba_to_uint8(seed, m + 2, len - data_len - 3);
    ba_free(seed);
    seed = NULL;
    m[len - data_len - 1] = 0;
    DO(ba_to_uint8(data, m + len - data_len, data_len));

    CHECK_NOT_NULL(seed = ba_alloc_by_len(1));
    off = len - data_len - 2;
    while (off >= 2) {
        if (!m[off]) {
            DO(drbg_random(seed));
            DO(ba_to_uint8(seed, m + off, 1));
        } else {
            off--;
        }
    }

    CHECK_NOT_NULL(wm = wa_alloc_from_be(m, len));

    rsaedp(ctx->gfp, ctx->e, wm, &wout);

    WA_TO_BE_WITH_TRUNC(wout, *out);

cleanup:

    wa_free(wout);
    wa_free(wm);
    ba_free(seed);
    free(m);

    return ret;
}

static int rsa_decrypt_pkcs1_v1_5(RsaCtx *ctx, const ByteArray *data, ByteArray **out)
{
    size_t i;
    uint8_t *m = NULL;
    size_t len;
    WordArray *wdata = NULL;
    WordArray *wm = NULL;
    int ret = RET_OK;

    if (ctx->mode_id != RSA_MODE_DECRYPT_PKCS) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    CHECK_NOT_NULL(wdata = wa_alloc_from_be(data->buf, data->len));

    DO(rsaedp(ctx->gfp, ctx->d, wdata, &wm));
    len = ctx->gfp->p->len * WORD_BYTE_LENGTH;
    MALLOC_CHECKED(m, len);
    DO(wa_to_uint8(wm, m, len));
    DO(uint8_swap(m, len, m, len));

    if ((m[0] != 0) || (m[1] != 2)) {
        SET_ERROR(RET_RSA_DECRYPTION_ERROR);
    }

    for (i = 2; (i < len) && (m[i] != 0);) {
        i++;
    }

    i++;

    CHECK_NOT_NULL(*out = ba_alloc_from_uint8(m + i, len - i));

cleanup:

    free(m);
    wa_free(wdata);
    wa_free(wm);

    return ret;
}

static int rsa_encrypt_oaep(RsaCtx *ctx, const ByteArray *msg, const ByteArray *L, const ByteArray* seed, ByteArray **out)
{
    WordArray *wm = NULL;
    WordArray *wout = NULL;
    uint8_t *em = NULL;
    uint8_t *lhash = NULL;
    uint8_t *masked_seed;
    uint8_t *masked_db;
    size_t len;
    size_t hlen;
    size_t i, j;
    size_t dblen;
    int ret = RET_OK;

    hlen = hash_get_size(ctx->hash_alg);
    len = ctx->gfp->p->len * WORD_BYTE_LENGTH;
    dblen = (uint8_t)(len - hlen - 1);

    if (len < (hlen * 2 + 2)) {
        SET_ERROR(RET_INVALID_CTX);
    }

    if (msg->len > (len - hlen * 2 - 2)) {
        SET_ERROR(RET_DATA_TOO_LONG);
    }


    MALLOC_CHECKED(em, len);

    masked_seed = em + 1;
    masked_db = em + 1 + hlen;

    CHECK_NOT_NULL(lhash = oaep_get_lhash(ctx->hash_alg, L));

    /*
     *                     +--------+------+------+-----+
     *                DB = |  lHash |  PS  | 0x01 |  M  |
     *                     +--------+------+------+-----+
     *                                    |
     *          +----------+              V
     *          |   seed   |--> MGF ---> xor
     *          +----------+              |
     *                |                   |
     *       +--+     V                   |
     *       |00|    xor <----- MGF <-----|
     *       +--+     |                   |
     *         |      |                   |
     *         V      V                   V
     *       +--+----------+----------------------------+
     * EM =  |00|maskedSeed|          maskedDB          |
     *       +--+----------+----------------------------+
     */
    em[0] = 0;

    DO(mgf(ctx->hash_alg, seed->buf, hlen, masked_db, dblen));

    for (i = 0, j = 0; i < dblen; i++) {
        if (i < hlen) {
            masked_db[i] ^= lhash[i];
        } else if (i == len - msg->len - hlen - 2) {
            masked_db[i] ^= 1;
        } else if (i > len - msg->len - hlen - 2) {
            masked_db[i] ^= msg->buf[j++];
        }
    }

    DO(mgf(ctx->hash_alg, masked_db, dblen, masked_seed, hlen));

    for (i = 0; i < hlen; i++) {
        masked_seed[i] ^= seed->buf[i];
    }

    CHECK_NOT_NULL(wm = wa_alloc_from_be(em, len));

    DO(rsaedp(ctx->gfp, ctx->e, wm, &wout));

    WA_TO_BE_WITH_TRUNC(wout, *out);

cleanup:

    wa_free(wm);
    wa_free(wout);
    free(em);
    free(lhash);
    return ret;
}

static int rsa_decrypt_oaep(RsaCtx *ctx, const ByteArray *msg, ByteArray **out)
{
    WordArray *wc = NULL;
    WordArray *wem = NULL;
    uint8_t *em = NULL;
    uint8_t *c = NULL;
    uint8_t *lhash = NULL;
    uint8_t *masked_seed;
    uint8_t *masked_db;
    uint8_t *seed;
    uint8_t *db;
    size_t hlen;
    size_t len;
    size_t dblen;
    size_t moff, i;
    size_t c_len;
    int ret = RET_OK;

    CHECK_NOT_NULL(wc = wa_alloc_from_be(msg->buf, msg->len));

    hlen = hash_get_size(ctx->hash_alg);
    len = ctx->gfp->p->len * WORD_BYTE_LENGTH;
    dblen = (uint8_t)(len - hlen - 1);

    DO(ba_to_uint8_with_alloc(msg, &c, &c_len));
    CHECK_NOT_NULL(c);
    DO(uint8_swap(c, c_len, c, c_len));
    seed = (uint8_t *)c + 1;
    db = (uint8_t *)c + 1 + hlen;

    CHECK_NOT_NULL(lhash = oaep_get_lhash(ctx->hash_alg, ctx->label));

    if (len < (2 * hlen + 2)) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

    DO(rsaedp(ctx->gfp, ctx->d, wc, &wem));

    MALLOC_CHECKED(em, len);
    DO(wa_to_uint8(wem, em, len));
    DO(uint8_swap(em, len, em, len));

    masked_seed = em + 1;
    masked_db = em + 1 + hlen;

    DO(mgf(ctx->hash_alg, masked_db, dblen, seed, hlen));

    for (i = 0; i < hlen; i++) {
        seed[i] ^= masked_seed[i];
    }

    DO(mgf(ctx->hash_alg, seed, hlen, db, dblen));

    for (i = 0; i < dblen; i++) {
        db[i] ^= masked_db[i];
    }

    if (memcmp(db, lhash, hlen) || em[0]) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

    moff = hlen;
    while ((moff < dblen) && (db[moff] != 0x01)) {
        moff++;
    }
    moff++;

    CHECK_NOT_NULL(*out = ba_alloc_from_uint8(db + moff, dblen - moff));

cleanup:

    wa_free(wc);
    wa_free(wem);
    free(em);
    free(lhash);
    free(c);

    return ret;
}

RsaCtx *rsa_alloc(void)
{
    RsaCtx *ctx = NULL;
    int ret = RET_OK;

    CALLOC_CHECKED(ctx, sizeof(RsaCtx));

    ctx->e = NULL;
    ctx->d = NULL;
    ctx->gfp = NULL;
    ctx->hash_alg = HASH_ALG_UNDEFINED;

cleanup:

    return ctx;
}

static int rsa_gen_privkey_core(const size_t bits, const ByteArray *e,
                                WordArray **wa_p, WordArray **wa_q, WordArray **wa_fi,
                                WordArray **wa_n, WordArray **wa_d)
{
    WordArray *fi = NULL;
    WordArray *wp = NULL;
    WordArray *wq = NULL;
    WordArray *we = NULL;
    WordArray *wn = NULL;
    WordArray *wd = NULL;
    WordArray *wsub_p_q = NULL;
    WordArray *wmin_val = NULL;
    WordArray *one = NULL;
    WordArray *q_tmp = NULL;
    size_t wplen = 0;
    size_t bitplen = 0;
    bool is_goto_begin = false;
    int comp_p_q = 0;
    int ret = RET_OK;

    CHECK_PARAM((bits >= MIN_RSA_BITS) && (bits <= MAX_RSA_BITS));
    CHECK_PARAM(e != NULL);
    CHECK_PARAM(wa_n != NULL);
    CHECK_PARAM(wa_d != NULL);

    bitplen = (bits + 1) >> 1;

    begin:

    DO(int_gen_prime(bitplen, &wp));

    CHECK_NOT_NULL(one = wa_alloc_with_zero(wp->len));
    one->buf[0] = 1;

    CHECK_NOT_NULL(wmin_val = wa_alloc(wp->len));

    int_lshift(one, bitplen - 100, wmin_val);
    wa_change_len(wmin_val, wp->len);

    do {
        wa_free(wq);
        wq = NULL;

        DO(int_gen_prime(bits - bitplen, &wq));
        ret = int_cmp(wq, wp);
        if (ret != 0) {
            if (ret > 0) {
                q_tmp = wq;
                wq = wp;
                wp = q_tmp;
            }
            CHECK_NOT_NULL(wsub_p_q = wa_alloc_with_zero(wp->len));
            wa_change_len(wq, wp->len);
            int_sub(wp, wq, wsub_p_q);

            // conformance with ANSI X9.31 requirement
            // |p-q| > 2^(prime bit length - 100)
            comp_p_q = int_cmp(wsub_p_q, wmin_val);
            wa_free(wsub_p_q);
            wsub_p_q = NULL;
        }
    } while (comp_p_q != 1);

    ret = RET_OK;

    wplen = wp->len;
    wa_change_len(wq, wplen);

    /* n = p * q */
    CHECK_NOT_NULL(wn = wa_alloc_with_zero(2 * wplen));
    int_mul(wq, wp, wn);

    /* fi = (p - 1) * (q - 1) */
    --wq->buf[0];
    --wp->buf[0];
    CHECK_NOT_NULL(fi = wa_alloc_with_zero(2 * wplen));
    int_mul(wq, wp, fi);
    ++wq->buf[0];
    ++wp->buf[0];

    CHECK_NOT_NULL(we = wa_alloc_from_ba(e));
    wa_change_len(we, 2 * wplen);

    wd = gfp_mod_inv_core(we, fi);
    if (wd == NULL) {
        is_goto_begin = true;
        goto cleanup;
    }

    if (int_bit_len(wn) != bits) {
        is_goto_begin = true;
        goto cleanup;
    }

    *wa_d = wd;
    *wa_n = wn;

    if (wa_p != NULL) {
        *wa_p = wp;
    }
    if (wa_q != NULL) {
        *wa_q = wq;
    }
    if (wa_fi != NULL) {
        *wa_fi = fi;
    }

    wd = NULL;
    wn = NULL;
    wp = NULL;
    wq = NULL;
    fi = NULL;

cleanup:

    wa_free(wn);
    wa_free(wd);
    wa_free(fi);
    wa_free(wq);
    wq = NULL;
    wa_free(wp);
    wa_free(we);
    wa_free(wsub_p_q);
    wa_free(one);
    wa_free(wmin_val);
    if (is_goto_begin) {
        is_goto_begin = false;
        goto begin;
    }

    return ret;
}

int rsa_generate_privkey(const size_t bits, const ByteArray *e, ByteArray **n, ByteArray **d)
{
    WordArray *wn = NULL;
    WordArray *wd = NULL;
    int ret = RET_OK;

    CHECK_PARAM(e != NULL);
    CHECK_PARAM(n != NULL);
    CHECK_PARAM(d != NULL);

    DO(rsa_gen_privkey_core(bits, e, NULL, NULL, NULL, &wn, &wd));

    WA_TO_BE_WITH_TRUNC(wd, *d);
    WA_TO_BE_WITH_TRUNC(wn, *n);

cleanup:

    wa_free(wn);
    wa_free(wd);

    return ret;
}

int rsa_generate_privkey_ext(const size_t bits, const ByteArray *e, ByteArray **n,
                             ByteArray **d, ByteArray **p, ByteArray **q, ByteArray **dmp1, ByteArray **dmq1, ByteArray **iqmp)
{
    WordArray *fi = NULL;
    GfpCtx *gfp = NULL;
    GfpCtx *gfp1 = NULL;
    GfpCtx *gfq1 = NULL;
    WordArray *wp = NULL;
    WordArray *wq = NULL;
    WordArray *we = NULL;
    WordArray *wn = NULL;
    WordArray *wd = NULL;
    WordArray *wdmq1 = NULL;
    WordArray *wdmp1 = NULL;
    WordArray *wiqmp = NULL;
    int ret = RET_OK;
    size_t wplen = 0;

    CHECK_PARAM(e != NULL);
    CHECK_PARAM(n != NULL);
    CHECK_PARAM(d != NULL);
    CHECK_PARAM(p != NULL);
    CHECK_PARAM(q != NULL);
    CHECK_PARAM(dmp1 != NULL);
    CHECK_PARAM(dmq1 != NULL);
    CHECK_PARAM(iqmp != NULL);

    DO(rsa_gen_privkey_core(bits, e, &wp, &wq, &fi, &wn, &wd));
    //https://www.ibm.com/support/knowledgecenter/en/linuxonibm/com.ibm.linux.z.wskc.doc/wskc_c_rsagen.html

    wplen = wp->len;

    /* fi = (p - 1) * (q - 1) */
    --wq->buf[0];
    --wp->buf[0];

    /* e */
    CHECK_NOT_NULL(we = wa_alloc_from_ba(e));
    wa_change_len(we, 2 * wplen);

    /* exponent1 = d mod (p-1) */
    CHECK_NOT_NULL(wdmp1 = wa_alloc_with_zero(wplen));
    CHECK_NOT_NULL(gfp1 = gfp_alloc(wp));
    gfp_mod(gfp1, wd, wdmp1);

    /* exponent2 = d mod (q-1) */
    CHECK_NOT_NULL(wdmq1 = wa_alloc_with_zero(wplen));
    CHECK_NOT_NULL(gfq1 = gfp_alloc(wq));
    gfp_mod(gfq1, wd, wdmq1);

    ++wq->buf[0];
    ++wp->buf[0];

    /* coefficient = (inverse of q) mod p */
    CHECK_NOT_NULL(gfp = gfp_alloc(wp));
    CHECK_NOT_NULL(wiqmp = gfp_mod_inv_core(wq, wp));

    WA_TO_BE_WITH_TRUNC(wn, *n);
    WA_TO_BE_WITH_TRUNC(wp, *p);
    WA_TO_BE_WITH_TRUNC(wq, *q);
    WA_TO_BE_WITH_TRUNC(wd, *d);
    WA_TO_BE_WITH_TRUNC(wdmp1, *dmp1);
    WA_TO_BE_WITH_TRUNC(wdmq1, *dmq1);
    WA_TO_BE_WITH_TRUNC(wiqmp, *iqmp);

cleanup:

    wa_free(wn);
    wa_free(we);
    wa_free_private(wp);
    wa_free_private(wq);
    wa_free_private(wd);
    wa_free_private(wdmp1);
    wa_free_private(wdmq1);
    wa_free_private(wiqmp);
    wa_free_private(fi);
    gfp_free(gfp1);
    gfp_free(gfq1);
    gfp_free(gfp);

    return ret;

}

bool rsa_validate_key(RsaCtx *ctx, const ByteArray *n, const ByteArray *e, const ByteArray *d, const ByteArray *p,
                      const ByteArray *q, const ByteArray *dmp1, const ByteArray *dmq1, const ByteArray *iqmp)
{
    GfpCtx *gfp = NULL;
    GfpCtx *gfp1 = NULL;
    GfpCtx *gfq1 = NULL;
    WordArray *fi = NULL;
    WordArray *wp = NULL;
    WordArray *wq = NULL;
    WordArray *we = NULL;
    WordArray *wn = NULL;
    WordArray *wd = NULL;
    WordArray *wdmq1 = NULL;
    WordArray *wdmp1 = NULL;
    WordArray *wiqmp = NULL;
    WordArray *wa_exp = NULL;
    int ret = RET_OK;
    size_t wplen = 0;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(e != NULL);
    CHECK_PARAM((ba_get_len(n) != 0) && (ba_get_len(n) <= MAX_RSA_BITS / 8));
    CHECK_PARAM(d != NULL);
    CHECK_PARAM(p != NULL);
    CHECK_PARAM(q != NULL);
    CHECK_PARAM(dmp1 != NULL);
    CHECK_PARAM(dmq1 != NULL);
    CHECK_PARAM(iqmp != NULL);

    CHECK_NOT_NULL(wp = wa_alloc_from_be(p->buf, p->len));
    CHECK_NOT_NULL(wq = wa_alloc_from_be(q->buf, q->len));
    wplen = p->len;
    wa_change_len(wq, wp->len);
    CHECK_NOT_NULL(wn = wa_alloc_with_zero(2 * wplen));
    CHECK_NOT_NULL(fi = wa_alloc_with_zero(2 * wplen));

    /* n = p * q */
    int_mul(wq, wp, wn); //Модуль
    CHECK_NOT_NULL(wa_exp = wa_alloc_from_be(n->buf, n->len));
    if (!int_equals(wa_exp, wn)) {
        SET_ERROR(RET_INVALID_RSA_N);
    }
    wa_free(wa_exp);
    wa_exp = NULL;
    /* fi = (p - 1) * (q - 1) */

    --wq->buf[0];
    --wp->buf[0];
    int_mul(wq, wp, fi);

    /* e */
    CHECK_NOT_NULL(we = wa_alloc_from_be(e->buf, e->len));
    wa_change_len(we, 2 * wplen);

    /* d = e^-1 mod fi*/
    CHECK_NOT_NULL(wd = gfp_mod_inv_core(we, fi));
    CHECK_NOT_NULL(wa_exp = wa_alloc_from_be(d->buf, d->len));
    if (!int_equals(wa_exp, wd)) {
        SET_ERROR(RET_INVALID_RSA_D);
    }
    wa_free(wa_exp);
    wa_exp = NULL;

    /* exponent1 = d mod (p-1) */
    CHECK_NOT_NULL(wdmp1 = wa_alloc_with_zero(wplen));
    CHECK_NOT_NULL(gfp1 = gfp_alloc(wp));
    gfp_mod(gfp1, wd, wdmp1);
    CHECK_NOT_NULL(wa_exp = wa_alloc_from_be(dmp1->buf, dmp1->len));
    if (!int_equals(wa_exp, wdmp1)) {
        SET_ERROR(RET_INVALID_RSA_DMP);
    }
    wa_free(wa_exp);
    wa_exp = NULL;

    /* exponent2 = d mod (q-1) */
    CHECK_NOT_NULL(wdmq1 = wa_alloc_with_zero(wplen));
    CHECK_NOT_NULL(gfq1 = gfp_alloc(wq));
    gfp_mod(gfq1, wd, wdmq1);
    CHECK_NOT_NULL(wa_exp = wa_alloc_from_be(dmq1->buf, dmq1->len));
    if (!int_equals(wa_exp, wdmq1)) {
        SET_ERROR(RET_INVALID_RSA_DMQ);
    }
    wa_free(wa_exp);
    wa_exp = NULL;

    ++wq->buf[0];
    ++wp->buf[0];

    /* coefficient = (inverse of q) mod p */
    CHECK_NOT_NULL(gfp = gfp_alloc(wp));
    CHECK_NOT_NULL(wiqmp = gfp_mod_inv_core(wq, wp));
    CHECK_NOT_NULL(wa_exp = wa_alloc_from_be(iqmp->buf, iqmp->len));
    if (!int_equals(wa_exp, wiqmp)) {
        SET_ERROR(RET_INVALID_RSA_IQMP);
    }
    wa_free(wa_exp);
    wa_exp = NULL;

cleanup:

    wa_free(wn);
    wa_free(we);
    wa_free_private(wp);
    wa_free_private(wq);
    wa_free_private(wd);
    wa_free_private(wdmp1);
    wa_free_private(wdmq1);
    wa_free_private(wiqmp);
    wa_free_private(fi);
    gfp_free(gfp1);
    gfp_free(gfq1);
    gfp_free(gfp);

    return ret == RET_OK ? true : false;
}

static int rsa_init_private(RsaCtx* ctx, const ByteArray* n, const ByteArray* d)
{
    int ret = RET_OK;
    WordArray* wn = NULL;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM((ba_get_len(n) != 0) && (ba_get_len(n) <= MAX_RSA_BITS / 8));
    CHECK_PARAM(d != NULL);

    wa_free_private(ctx->d);
    CHECK_NOT_NULL(ctx->d = wa_alloc_from_be(d->buf, d->len));

    wa_free(ctx->e);
    ctx->e = NULL;

    gfp_free(ctx->gfp);
    CHECK_NOT_NULL(wn = wa_alloc_from_be(n->buf, n->len));
    CHECK_NOT_NULL(ctx->gfp = gfp_alloc(wn));

    wa_change_len(ctx->d, ctx->gfp->p->len);

cleanup:
    wa_free(wn);
    return ret;
}

static int rsa_init_public(RsaCtx* ctx, const ByteArray* n, const ByteArray* e)
{
    int ret = RET_OK;
    WordArray* wn = NULL;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM((ba_get_len(n) != 0) && (ba_get_len(n) <= MAX_RSA_BITS / 8));
    CHECK_PARAM(e != NULL);

    wa_free_private(ctx->d);
    ctx->d = NULL;

    wa_free(ctx->e);
    CHECK_NOT_NULL(ctx->e = wa_alloc_from_be(e->buf, e->len));

    gfp_free(ctx->gfp);
    CHECK_NOT_NULL(wn = wa_alloc_from_be(n->buf, n->len));
    CHECK_NOT_NULL(ctx->gfp = gfp_alloc(wn));
    wa_change_len(ctx->e, ctx->gfp->p->len);

cleanup:
    wa_free(wn);
    return ret;
}

int rsa_init_encrypt_pkcs1_v1_5(RsaCtx *ctx, const ByteArray *n, const ByteArray *e)
{
    int ret = RET_OK;
    DO(rsa_init_public(ctx, n, e));
    ctx->mode_id = RSA_MODE_ENCRYPT_PKCS;

cleanup:
    return ret;
}

int rsa_init_decrypt_pkcs1_v1_5(RsaCtx *ctx, const ByteArray *n, const ByteArray *d)
{
    int ret = RET_OK;

    DO(rsa_init_private(ctx, n, d));
    ctx->mode_id = RSA_MODE_DECRYPT_PKCS;

cleanup:
    return ret;
}

int rsa_init_sign_pkcs1_v1_5(RsaCtx *ctx, HashAlg hash_alg, const ByteArray *n, const ByteArray *d)
{
    int ret = RET_OK;

    DO(rsa_init_private(ctx, n, d));
    ctx->hash_alg = hash_alg;
    ctx->mode_id = RSA_MODE_SIGN_PKCS;

cleanup:
    return ret;
}

int rsa_init_verify_pkcs1_v1_5(RsaCtx *ctx, HashAlg hash_alg, const ByteArray *n, const ByteArray *e)
{
    int ret = RET_OK;

    DO(rsa_init_public(ctx, n, e));
    ctx->hash_alg = hash_alg;
    ctx->mode_id = RSA_MODE_VERIFY_PKCS;

cleanup:
    return ret;
}

int rsa_init_encrypt_oaep(RsaCtx *ctx, HashAlg hash_alg, ByteArray *label, const ByteArray *n, const ByteArray *e)
{
    int ret = RET_OK;

    DO(rsa_init_public(ctx, n, e));

    if (ctx->gfp->p->len * WORD_BYTE_LENGTH < (2 * hash_get_size(hash_alg) + 2)) {
        SET_ERROR(RET_INVALID_PARAM);
    }

    ctx->label = label;
    ctx->hash_alg = hash_alg;
    ctx->mode_id = RSA_MODE_ENCRYPT_OAEP;

cleanup:
    return ret;
}

int rsa_init_decrypt_oaep(RsaCtx *ctx, HashAlg hash_alg, ByteArray *label, const ByteArray *n, const ByteArray *d)
{
    int ret = RET_OK;

    DO(rsa_init_private(ctx, n, d));

    ctx->hash_alg = hash_alg;
    ctx->label = label;
    ctx->mode_id = RSA_MODE_DECRYPT_OAEP;

cleanup:
    return ret;
}

int rsa_init_sign_pss(RsaCtx* ctx, HashAlg hash_alg, const ByteArray* n, const ByteArray* d)
{
    int ret = RET_OK;
    size_t hlen, modulus_len;

    hlen = hash_get_size(hash_alg);
    if (hlen == 0) {
        SET_ERROR(RET_INVALID_PARAM);
    }

    DO(rsa_init_private(ctx, n, d));
    modulus_len = (int_bit_len(ctx->gfp->p) + 6) / 8;

    if (modulus_len < hlen * 2) {
        SET_ERROR(RET_INVALID_PARAM);
    }

    if (modulus_len >= hlen * 2 + 2) {
        ctx->salt_len = hlen;
    }
    else {
        ctx->salt_len = modulus_len - hlen - 2;
    }

    ctx->hash_alg = hash_alg;
    ctx->mode_id = RSA_MODE_SIGN_PSS;

cleanup:
    return ret;
}

int rsa_init_verify_pss(RsaCtx* ctx, HashAlg hash_alg, size_t salt_len, const ByteArray* n, const ByteArray* e)
{
    int ret = RET_OK;

    if (hash_get_size(hash_alg) == 0) {
        SET_ERROR(RET_INVALID_PARAM);
    }

    DO(rsa_init_public(ctx, n, e));

    ctx->salt_len = salt_len;
    ctx->hash_alg = hash_alg;
    ctx->mode_id = RSA_MODE_VERIFY_PSS;

cleanup:
    return ret;
}

void rsa_free(RsaCtx* ctx)
{
    if (ctx) {
        wa_free_private(ctx->e);
        wa_free_private(ctx->d);
        gfp_free(ctx->gfp);
    }
    free(ctx);
}

int rsa_encrypt(RsaCtx *ctx, const ByteArray *data, ByteArray **encrypted_data)
{
    int ret = RET_OK;
    ByteArray *salt = NULL;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(data != NULL);
    CHECK_PARAM(encrypted_data != NULL);

    switch (ctx->mode_id) {
        case RSA_MODE_ENCRYPT_OAEP:
            CHECK_NOT_NULL(salt = ba_alloc_by_len(hash_get_size(ctx->hash_alg)));
            DO(drbg_random(salt));
            DO(rsa_encrypt_oaep(ctx, data, ctx->label, salt, encrypted_data));
            break;
        case RSA_MODE_ENCRYPT_PKCS:
            DO(rsa_encrypt_pkcs1_v1_5(ctx, data, encrypted_data));
            break;
        default:
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

cleanup:
    ba_free(salt);
    return ret;
}

int rsa_decrypt(RsaCtx *ctx, const ByteArray *encrypted_data, ByteArray **data)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(data != NULL);
    CHECK_PARAM(encrypted_data != NULL);

    switch (ctx->mode_id) {
        case RSA_MODE_DECRYPT_OAEP:
            DO(rsa_decrypt_oaep(ctx, encrypted_data, data));
            break;
        case RSA_MODE_DECRYPT_PKCS:
            DO(rsa_decrypt_pkcs1_v1_5(ctx, encrypted_data, data));
            break;
        default:
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

cleanup:

    return ret;
}

static const uint8_t* pkcs15_get_aid(HashAlg hash_alg, size_t* aid_len)
{
    static const uint8_t AID_SHA1[] = {
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };
    static const uint8_t AID_SHA256[] = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20 };
    static const uint8_t AID_SHA384[] = {
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
        0x00, 0x04, 0x30 };
    static const uint8_t AID_SHA512[] = {
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
        0x00, 0x04, 0x40 };
    static const uint8_t AID_SHA224[] = {
        0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
        0x00, 0x04, 0x1c };
    static const uint8_t AID_SHA3_224[] = {
        0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07, 0x05,
        0x00, 0x04, 0x1c };
    static const uint8_t AID_SHA3_256[] = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x05,
        0x00, 0x04, 0x20 };
    static const uint8_t AID_SHA3_384[] = {
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09, 0x05,
        0x00, 0x04, 0x30 };
    static const uint8_t AID_SHA3_512[] = {
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A, 0x05,
        0x00, 0x04, 0x40 };
    static const uint8_t AID_RIPEMD160[] = {
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x24, 0x03, 0x02, 0x01, 0x05, 0x00, 0x04, 0x14 };


    if (hash_alg == HASH_ALG_SHA1) {
        *aid_len = sizeof(AID_SHA1);
        return AID_SHA1;
    }
    else if (hash_alg == HASH_ALG_SHA256) {
        *aid_len = sizeof(AID_SHA256);
        return AID_SHA256;
    }
    else if (hash_alg == HASH_ALG_SHA384) {
        *aid_len = sizeof(AID_SHA384);
        return AID_SHA384;
    }
    else if (hash_alg == HASH_ALG_SHA512) {
        *aid_len = sizeof(AID_SHA512);
        return AID_SHA512;
    }
    else if (hash_alg == HASH_ALG_SHA224) {
        *aid_len = sizeof(AID_SHA224);
        return AID_SHA224;
    }
    else if (hash_alg == HASH_ALG_SHA3_224) {
        *aid_len = sizeof(AID_SHA3_224);
        return AID_SHA3_224;
    }
    else if (hash_alg == HASH_ALG_SHA3_256) {
        *aid_len = sizeof(AID_SHA3_256);
        return AID_SHA3_256;
    }
    else if (hash_alg == HASH_ALG_SHA3_384) {
        *aid_len = sizeof(AID_SHA3_384);
        return AID_SHA3_384;
    }
    else if (hash_alg == HASH_ALG_SHA3_512) {
        *aid_len = sizeof(AID_SHA3_512);
        return AID_SHA3_512;
    }
    else if (hash_alg == HASH_ALG_RIPEMD160) {
        *aid_len = sizeof(AID_RIPEMD160);
        return AID_RIPEMD160;
    }

    return NULL;
}

static int rsa_sign_pkcs1_v1_5(RsaCtx *ctx, const ByteArray *H, ByteArray **sign)
{
    WordArray *em_wa = NULL;
    WordArray *sign_wa = NULL;
    size_t len;
    uint8_t *em = NULL;
    const uint8_t* aid;
    size_t aid_len;
    size_t hlen;
    int ret = RET_OK;

    len = (int_bit_len(ctx->gfp->p) + 7) >> 3;
    CHECK_NOT_NULL(aid = pkcs15_get_aid(ctx->hash_alg, &aid_len));
    hlen = hash_get_size(ctx->hash_alg);
    if (H->len < 16) {
        SET_ERROR(RET_INVALID_HASH_LEN);
    }

    CHECK_PARAM((size_t)(aid_len + hlen + 11) <= len);
    CHECK_NOT_NULL(em = malloc(len));

    // EM = 0x00 || 0x01 || PS || 0x00 || AlgorithmIdentifier || HASH.
    em[0] = 0;
    em[1] = 1;
    memset(em + 2, 0xff, len - aid_len - hlen - 3);
    em[len - hlen - aid_len - 1] = 0;
    memcpy(em + len - hlen - aid_len, aid, aid_len);
    DO(ba_to_uint8(H, em + len - hlen, hlen));

    CHECK_NOT_NULL(em_wa = wa_alloc_from_be(em, len));
    DO(rsaedp(ctx->gfp, ctx->d, em_wa, &sign_wa));

    WA_TO_BE_WITH_N_LEN(ctx, sign_wa, *sign);

cleanup:

    wa_free(em_wa);
    wa_free(sign_wa);
    free(em);

    return ret;
}

static int rsa_verify_pkcs1_v1_5(RsaCtx *ctx, const ByteArray* H, const ByteArray *sign)
{
    size_t len;
    uint8_t *em = NULL;
    const uint8_t* aid;
    size_t aid_len;
    size_t hlen;
    WordArray *em_wa = NULL;
    WordArray *sign_wa = NULL;
    int ret = RET_OK;
    size_t i;

    if (ctx->mode_id != RSA_MODE_VERIFY_PKCS) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    len = ctx->gfp->p->len * WORD_BYTE_LENGTH;
    CHECK_NOT_NULL(em = malloc(len));
    CHECK_NOT_NULL(aid = pkcs15_get_aid(ctx->hash_alg, &aid_len));
    hlen = hash_get_size(ctx->hash_alg);
    if (H->len < 16) {
        SET_ERROR(RET_INVALID_HASH_LEN);
    }

    CHECK_NOT_NULL(sign_wa = wa_alloc_from_be(sign->buf, sign->len));
    DO(rsaedp(ctx->gfp, ctx->e, sign_wa, &em_wa));

    DO(wa_to_uint8(em_wa, em, len));
    len = (int_bit_len(ctx->gfp->p) + 7) >> 3;
    DO(uint8_swap(em, len, em, len));

    if ((em[0] != 0) || (em[1] != 1) || (em[len - hlen - aid_len - 1] != 0)) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

    for (i = len - aid_len - hlen - 2; i >= 2; i--) {
        if (em[i] != 0xff) {
            SET_ERROR(RET_VERIFY_FAILED);
        }
    }

    if (memcmp(em + len - aid_len - hlen, aid, aid_len)) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

    if (memcmp(em + len - hlen, ba_get_buf_const(H), hlen)) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

cleanup:

    free(em);
    wa_free(em_wa);
    wa_free(sign_wa);

    return ret;
}

static int rsa_pss_encode(RsaCtx* ctx, const ByteArray* H, const ByteArray* salt, ByteArray** encoded)
{
    int ret = RET_OK;
    HashCtx* hctx = NULL;
    uint8_t* mask = NULL;
    ByteArray* zero = NULL;
    ByteArray* hash = NULL;
    ByteArray* out = NULL;
    size_t i, hlen, modulus_len, msb, salt_len = 0, offset = 0;
    
    hlen = hash_get_size(ctx->hash_alg);
    if (H->len < 16) {
        SET_ERROR(RET_INVALID_HASH_LEN);
    }

    msb = int_bit_len(ctx->gfp->p) - 1;
    modulus_len = (msb + 8) / 8;

    salt_len = salt->len;

    if (modulus_len < hlen + salt_len + 2) {
        SET_ERROR(RET_INVALID_PARAM);
    }

    CHECK_NOT_NULL(hctx = hash_alloc(ctx->hash_alg));

    // hash = H((eight) 0x00 || msghash || salt)
    CHECK_NOT_NULL(zero = ba_alloc_by_len(8));
    memset(zero->buf, 0, 8);
    DO(hash_update(hctx, zero));
    DO(hash_update(hctx, H));
    DO(hash_update(hctx, salt));
    DO(hash_final(hctx, &hash));

    // generate DB = PS || 0x01 || salt, PS == modulus_len - salt_len - hlen - 2 zero bytes
    CHECK_NOT_NULL(out = ba_alloc_by_len(modulus_len));
    memset(out->buf, 0, modulus_len);
    out->buf[modulus_len - salt_len - hlen - 2] = 0x01;
    memcpy(out->buf + (modulus_len - salt_len - hlen - 1), salt->buf, salt_len);

    if ((msb & 7) == 0) {
        offset = 1;
    }

    MALLOC_CHECKED(mask, modulus_len - hlen - 1 - offset);
    DO(mgf(ctx->hash_alg, hash->buf, hash->len, mask, modulus_len - hlen - 1 - offset))

    // mask DB
    for (i = 0; i < (modulus_len - hlen - 1 - offset); i++) {
        out->buf[i + offset] ^= mask[i];
    }

    // out is DB || hash || 0xBC
    memcpy(out->buf + modulus_len - hlen - 1, hash->buf, hash->len);
    out->buf[modulus_len - 1] = 0xBC;
    out->buf[0] &= 0xFF >> ((modulus_len << 3) - msb);

    *encoded = out;
    out = NULL;

cleanup:
    ba_free(hash);
    ba_free(zero);
    ba_free(out);
    hash_free(hctx);
    free(mask);
    return ret;
}

static int rsa_pss_decode_check(RsaCtx* ctx, const ByteArray* H, const ByteArray* encoded)
{
    int ret = RET_OK;
    HashCtx* hctx = NULL;
    uint8_t* mask = NULL;
    ByteArray* zero = NULL;
    ByteArray* salt = NULL;
    ByteArray* hash = NULL;
    size_t i, hlen, modulus_len, msb, received_salt_len, offset = 0;

    hlen = hash_get_size(ctx->hash_alg);
    if (H->len < 16) {
        SET_ERROR(RET_INVALID_HASH_LEN);
    }

    msb = int_bit_len(ctx->gfp->p) - 1;
    modulus_len = (msb + 8) / 8;

    if (modulus_len < hlen * 2) {
        SET_ERROR(RET_INVALID_PARAM);
    }

    if (encoded->buf[modulus_len - 1] != 0xBC) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

    if ((encoded->buf[0] & ~(0xFF >> ((modulus_len << 3) - msb))) != 0) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

    if ((msb & 7) == 0) {
        offset = 1;
    }

    MALLOC_CHECKED(mask, modulus_len - hlen - 1 - offset);
    DO(mgf(ctx->hash_alg, encoded->buf + modulus_len - hlen - 1, hlen, mask, modulus_len - hlen - 1 - offset))

    if (offset == 0) {
        mask[0] &= 0xFF >> ((modulus_len << 3) - msb);
    }

    for (i = 0; i < modulus_len - hlen - 2 - offset; i++) {
        if ((mask[i] ^ encoded->buf[i + offset]) != 0x00) {
            break;
        }
    }

    //check salt len
    received_salt_len = modulus_len - i - hlen - 2 - offset;
    if ((received_salt_len != ctx->salt_len) && (ctx->salt_len != RSASSA_PSS_SALT_LEN_ANY)) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

    if ((mask[i] ^ encoded->buf[i + offset]) != 0x01) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

    CHECK_NOT_NULL(zero = ba_alloc_by_len(8));
    memset(zero->buf, 0, 8);
    CHECK_NOT_NULL(hctx = hash_alloc(ctx->hash_alg));
    DO(hash_update(hctx, zero));
    DO(hash_update(hctx, H));
    if (received_salt_len > 0) {
        CHECK_NOT_NULL(salt = ba_alloc_by_len(received_salt_len));
        for (i = 0; i < received_salt_len; i++) {
            salt->buf[i] = mask[modulus_len - received_salt_len - hlen - 1 - offset + i] ^
                encoded->buf[modulus_len - received_salt_len - hlen - 1 + i];
        }
        DO(hash_update(hctx, salt));
    }
    DO(hash_final(hctx, &hash));

    if (memcmp(encoded->buf + modulus_len - hlen - 1, hash->buf, hash->len) != 0) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

cleanup:
    ba_free(hash);
    ba_free(zero);
    ba_free(salt);
    hash_free(hctx);
    free(mask);
    return ret;
}

static int rsa_sign_pss(RsaCtx* ctx, const ByteArray* H, const ByteArray* salt, ByteArray** sign)
{
    int ret = RET_OK;
    WordArray* wa_sign = NULL;
    WordArray* wa_encoded = NULL;
    ByteArray* ba_encoded = NULL;

    DO(rsa_pss_encode(ctx, H, salt, &ba_encoded));
    CHECK_NOT_NULL(wa_encoded = wa_alloc_from_be(ba_encoded->buf, ba_encoded->len));
    DO(rsaedp(ctx->gfp, ctx->d, wa_encoded, &wa_sign));
    WA_TO_BE_WITH_N_LEN(ctx, wa_sign, *sign);

cleanup:
    wa_free(wa_sign);
    wa_free(wa_encoded);
    ba_free(ba_encoded);
    return ret;
}

static int rsa_verify_pss(RsaCtx* ctx, const ByteArray* H, const ByteArray* sign)
{
    int ret = RET_OK;
    WordArray* wa_sign = NULL;
    WordArray* wa_encoded = NULL;
    ByteArray* ba_encoded = NULL;

    CHECK_NOT_NULL(wa_sign = wa_alloc_from_be(sign->buf, sign->len));
    DO(rsaedp(ctx->gfp, ctx->e, wa_sign, &wa_encoded));
    WA_TO_BE_WITH_N_LEN(ctx, wa_encoded, ba_encoded);
    DO(rsa_pss_decode_check(ctx, H, ba_encoded));

cleanup:
    wa_free(wa_sign);
    wa_free(wa_encoded);
    ba_free(ba_encoded);
    return ret;
}

int rsa_sign(RsaCtx* ctx, const ByteArray* hash, ByteArray** sign)
{
    int ret = RET_OK;
    ByteArray* ba_salt = NULL;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(hash != NULL);
    CHECK_PARAM(sign != NULL);

    switch (ctx->mode_id) {
    case RSA_MODE_SIGN_PKCS:
        DO(rsa_sign_pkcs1_v1_5(ctx, hash, sign));
        break;
    case RSA_MODE_SIGN_PSS:
        if (ctx->salt_len) {
            // generate and hash random salt
            CHECK_NOT_NULL(ba_salt = ba_alloc_by_len(ctx->salt_len));
            DO(drbg_random(ba_salt));
        }
        DO(rsa_sign_pss(ctx, hash, ba_salt, sign));
        break;
    default:
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

cleanup:
    ba_free(ba_salt);
    return ret;
}

int rsa_verify(RsaCtx* ctx, const ByteArray* hash, const ByteArray* sign)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(hash != NULL);
    CHECK_PARAM(sign != NULL);

    switch (ctx->mode_id) {
    case RSA_MODE_VERIFY_PKCS:
        DO(rsa_verify_pkcs1_v1_5(ctx, hash, sign));
        break;
    case RSA_MODE_VERIFY_PSS:
        DO(rsa_verify_pss(ctx, hash, sign));
        break;
    default:
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

cleanup:
    return ret;
}

static int rsa_sign_pss_self_test(void) 
{
    //ДСТУ ISO/IEC 14888-2:2015. C.1.1
    static const uint8_t test_n[128] = {
        0xAC, 0xD1, 0xCC, 0x46, 0xDF, 0xE5, 0x4F, 0xE8, 0xF9, 0x78, 0x66, 0x72, 0x66, 0x4C, 0xA2, 0x69,
        0x0D, 0x0A, 0xD7, 0xE5, 0x00, 0x3B, 0xC6, 0x42, 0x79, 0x54, 0xD9, 0x39, 0xEE, 0xE8, 0xB2, 0x71,
        0x52, 0xE6, 0xA9, 0x47, 0x45, 0x05, 0x0C, 0xC2, 0x67, 0x88, 0x3C, 0xD4, 0x34, 0x87, 0x51, 0x64,
        0x50, 0x19, 0xAF, 0xD5, 0x87, 0x3A, 0x8B, 0x11, 0x11, 0x9F, 0xB9, 0x3F, 0x0A, 0x31, 0xC6, 0x54,
        0xC3, 0xEC, 0xFF, 0x07, 0x32, 0x33, 0x53, 0x0C, 0x79, 0xBE, 0x90, 0xE0, 0x26, 0xE2, 0x42, 0x1D,
        0xD3, 0x78, 0xB8, 0x8B, 0x40, 0x13, 0x6C, 0x48, 0x7D, 0x33, 0x07, 0x5A, 0x16, 0x12, 0xAB, 0x90,
        0xC5, 0xB7, 0x5D, 0x33, 0x26, 0x59, 0xA5, 0xD0, 0xB5, 0xC1, 0x95, 0x76, 0x10, 0x2D, 0x34, 0x24,
        0x31, 0xAC, 0x3B, 0xBB, 0xA8, 0xF9, 0x84, 0x49, 0xBD, 0x58, 0xBC, 0x0B, 0x5E, 0x25, 0x46, 0x33 };
    static const uint8_t test_d[128] = {
        0x1C, 0xCD, 0xA2, 0x0B, 0xCF, 0xFB, 0x8D, 0x51, 0x7E, 0xE9, 0x66, 0x68, 0x66, 0x62, 0x1B, 0x11,
        0x82, 0x2C, 0x79, 0x50, 0xD5, 0x5F, 0x4B, 0xB5, 0xBE, 0xE3, 0x79, 0x89, 0xA7, 0xD1, 0x73, 0x12,
        0xE3, 0x26, 0x71, 0x8B, 0xE0, 0xD6, 0x2C, 0xCB, 0x11, 0x41, 0x5F, 0x78, 0xB3, 0x6B, 0xE2, 0xE6,
        0x0D, 0x59, 0x9D, 0x4E, 0x41, 0x34, 0x6C, 0x82, 0xD8, 0x45, 0x49, 0x8A, 0x81, 0xB2, 0xF6, 0x63,
        0x2F, 0xD7, 0xD1, 0xCC, 0xEF, 0xCA, 0xBF, 0x74, 0x17, 0x35, 0x02, 0x38, 0x10, 0x9E, 0xC2, 0x89,
        0xD5, 0x38, 0x27, 0x62, 0xB7, 0x7A, 0x1C, 0x99, 0x96, 0xDD, 0x1D, 0x2B, 0x71, 0xA5, 0x2F, 0xAF,
        0x52, 0xAB, 0xA9, 0xDE, 0xD1, 0x9F, 0x3F, 0x5D, 0x5D, 0x71, 0xD0, 0x54, 0x73, 0xEC, 0x9C, 0x79,
        0x92, 0xD8, 0x41, 0x28, 0x0B, 0xAC, 0x72, 0xB8, 0x7B, 0xF5, 0x1E, 0xB1, 0xCC, 0xB6, 0x5C, 0x87 };
    static const uint8_t test_e[1] = { 3 };
    static const uint8_t test_m[114] = {
        0x85, 0x9E, 0xEF, 0x2F, 0xD7, 0x8A, 0xCA, 0x00, 0x30, 0x8B, 0xDC, 0x47, 0x11, 0x93, 0xBF, 0x55,
        0xBF, 0x9D, 0x78, 0xDB, 0x8F, 0x8A, 0x67, 0x2B, 0x48, 0x46, 0x34, 0xF3, 0xC9, 0xC2, 0x6E, 0x64,
        0x78, 0xAE, 0x10, 0x26, 0x0F, 0xE0, 0xDD, 0x8C, 0x08, 0x2E, 0x53, 0xA5, 0x29, 0x3A, 0xF2, 0x17,
        0x3C, 0xD5, 0x0C, 0x6D, 0x5D, 0x35, 0x4F, 0xEB, 0xF7, 0x8B, 0x26, 0x02, 0x1C, 0x25, 0xC0, 0x27,
        0x12, 0xE7, 0x8C, 0xD4, 0x69, 0x4C, 0x9F, 0x46, 0x97, 0x77, 0xE4, 0x51, 0xE7, 0xF8, 0xE9, 0xE0,
        0x4C, 0xD3, 0x73, 0x9C, 0x6B, 0xBF, 0xED, 0xAE, 0x48, 0x7F, 0xB5, 0x56, 0x44, 0xE9, 0xCA, 0x74,
        0xFF, 0x77, 0xA5, 0x3C, 0xB7, 0x29, 0x80, 0x2F, 0x6E, 0xD4, 0xA5, 0xFF, 0xA8, 0xBA, 0x15, 0x98,
        0x90, 0xFC };
    static const uint8_t test_salt[20] = {
        0xE3, 0xB5, 0xD5, 0xD0, 0x02, 0xC1, 0xBC, 0xE5, 0x0C, 0x2B, 0x65, 0xEF, 0x88, 0xA1, 0x88, 0xD8,
        0x3B, 0xCE, 0x7E, 0x61 };
    static const uint8_t test_s[128] = {
        0x0F, 0x62, 0x44, 0x06, 0xFC, 0x3A, 0x21, 0x6B, 0x23, 0xD4, 0x4E, 0xCF, 0xF4, 0x30, 0xC0, 0x5A,
        0x45, 0x5B, 0x82, 0x18, 0xE2, 0x2F, 0xE4, 0x7B, 0x1F, 0xEA, 0x06, 0x0C, 0x5A, 0x9C, 0xB2, 0xDE,
        0xA6, 0x98, 0x17, 0x17, 0x80, 0xB5, 0xE6, 0x0C, 0x50, 0xA5, 0x67, 0xA5, 0x58, 0xEF, 0x47, 0xB5,
        0xFE, 0x28, 0xAF, 0x9B, 0xE0, 0x29, 0x61, 0x1C, 0x85, 0xA9, 0x33, 0x45, 0x9B, 0x0E, 0x61, 0x0A,
        0x06, 0x4F, 0x45, 0xCC, 0xC1, 0x26, 0x3A, 0x10, 0x67, 0xE5, 0xBF, 0xC0, 0x10, 0x5B, 0xBF, 0xBC,
        0x92, 0x25, 0xA4, 0x60, 0x83, 0x85, 0xA4, 0x17, 0xEB, 0x80, 0x58, 0x7B, 0x47, 0x02, 0x09, 0xF9,
        0x38, 0x16, 0x58, 0xA7, 0x72, 0x73, 0x9B, 0xA8, 0x2D, 0xA0, 0x18, 0xE1, 0x4A, 0xAE, 0x56, 0x4C,
        0x0A, 0x74, 0x9A, 0x05, 0xD0, 0xC1, 0xE6, 0x1C, 0x93, 0xFD, 0xE7, 0x77, 0x6D, 0x82, 0x48, 0xE6 };
    static const ByteArray ba_n = { (uint8_t*)test_n, sizeof(test_n) };
    static const ByteArray ba_d = { (uint8_t*)test_d, sizeof(test_d) };
    static const ByteArray ba_e = { (uint8_t*)test_e, sizeof(test_e) };
    static const ByteArray ba_salt = { (uint8_t*)test_salt, sizeof(test_salt) };
    static const ByteArray ba_m = { (uint8_t*)test_m, sizeof(test_m) };
    static const ByteArray ba_s = { (uint8_t*)test_s, sizeof(test_s) };

    int ret = RET_OK;
    RsaCtx* rsa_ctx = NULL;
    ByteArray* ba_signature = NULL;
    HashCtx* hash_ctx = NULL;
    ByteArray* ba_hash = NULL;

    CHECK_NOT_NULL(hash_ctx = hash_alloc(HASH_ALG_SHA1));
    DO(hash_update(hash_ctx, &ba_m));
    DO(hash_final(hash_ctx, &ba_hash));
    CHECK_NOT_NULL(rsa_ctx = rsa_alloc());
    DO(rsa_init_sign_pss(rsa_ctx, HASH_ALG_SHA1, &ba_n, &ba_d));
    DO(rsa_sign_pss(rsa_ctx, ba_hash, &ba_salt, &ba_signature));
    if (ba_cmp(ba_signature, &ba_s) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

    DO(rsa_init_verify_pss(rsa_ctx, HASH_ALG_SHA1, sizeof(test_salt), &ba_n, &ba_e));
    DO(rsa_verify(rsa_ctx, ba_hash, ba_signature));

cleanup:
    ba_free(ba_signature);
    ba_free(ba_hash);
    rsa_free(rsa_ctx);
    hash_free(hash_ctx);
    return ret;
}

static int rsa_sign_pkcs_self_test(void)
{
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-3rsatestvectors.zip
    static const uint8_t test_n[256] = {
        0xCE, 0xA8, 0x04, 0x75, 0x32, 0x4C, 0x1D, 0xC8, 0x34, 0x78, 0x27, 0x81, 0x8D, 0xA5, 0x8B, 0xAC,
        0x06, 0x9D, 0x34, 0x19, 0xC6, 0x14, 0xA6, 0xEA, 0x1A, 0xC6, 0xA3, 0xB5, 0x10, 0xDC, 0xD7, 0x2C,
        0xC5, 0x16, 0x95, 0x49, 0x05, 0xE9, 0xFE, 0xF9, 0x08, 0xD4, 0x5E, 0x13, 0x00, 0x6A, 0xDF, 0x27,
        0xD4, 0x67, 0xA7, 0xD8, 0x3C, 0x11, 0x1D, 0x1A, 0x5D, 0xF1, 0x5E, 0xF2, 0x93, 0x77, 0x1A, 0xEF,
        0xB9, 0x20, 0x03, 0x2A, 0x5B, 0xB9, 0x89, 0xF8, 0xE4, 0xF5, 0xE1, 0xB0, 0x50, 0x93, 0xD3, 0xF1,
        0x30, 0xF9, 0x84, 0xC0, 0x7A, 0x77, 0x2A, 0x36, 0x83, 0xF4, 0xDC, 0x6F, 0xB2, 0x8A, 0x96, 0x81,
        0x5B, 0x32, 0x12, 0x3C, 0xCD, 0xD1, 0x39, 0x54, 0xF1, 0x9D, 0x5B, 0x8B, 0x24, 0xA1, 0x03, 0xE7,
        0x71, 0xA3, 0x4C, 0x32, 0x87, 0x55, 0xC6, 0x5E, 0xD6, 0x4E, 0x19, 0x24, 0xFF, 0xD0, 0x4D, 0x30,
        0xB2, 0x14, 0x2C, 0xC2, 0x62, 0xF6, 0xE0, 0x04, 0x8F, 0xEF, 0x6D, 0xBC, 0x65, 0x2F, 0x21, 0x47,
        0x9E, 0xA1, 0xC4, 0xB1, 0xD6, 0x6D, 0x28, 0xF4, 0xD4, 0x6E, 0xF7, 0x18, 0x5E, 0x39, 0x0C, 0xBF,
        0xA2, 0xE0, 0x23, 0x80, 0x58, 0x2F, 0x31, 0x88, 0xBB, 0x94, 0xEB, 0xBF, 0x05, 0xD3, 0x14, 0x87,
        0xA0, 0x9A, 0xFF, 0x01, 0xFC, 0xBB, 0x4C, 0xD4, 0xBF, 0xD1, 0xF0, 0xA8, 0x33, 0xB3, 0x8C, 0x11,
        0x81, 0x3C, 0x84, 0x36, 0x0B, 0xB5, 0x3C, 0x7D, 0x44, 0x81, 0x03, 0x1C, 0x40, 0xBA, 0xD8, 0x71,
        0x3B, 0xB6, 0xB8, 0x35, 0xCB, 0x08, 0x09, 0x8E, 0xD1, 0x5B, 0xA3, 0x1E, 0xE4, 0xBA, 0x72, 0x8A,
        0x8C, 0x8E, 0x10, 0xF7, 0x29, 0x4E, 0x1B, 0x41, 0x63, 0xB7, 0xAE, 0xE5, 0x72, 0x77, 0xBF, 0xD8,
        0x81, 0xA6, 0xF9, 0xD4, 0x3E, 0x02, 0xC6, 0x92, 0x5A, 0xA3, 0xA0, 0x43, 0xFB, 0x7F, 0xB7, 0x8D };
    static const uint8_t test_d[256] = {
        0x09, 0x97, 0x63, 0x4C, 0x47, 0x7C, 0x1A, 0x03, 0x9D, 0x44, 0xC8, 0x10, 0xB2, 0xAA, 0xA3, 0xC7,
        0x86, 0x2B, 0x0B, 0x88, 0xD3, 0x70, 0x82, 0x72, 0xE1, 0xE1, 0x5F, 0x66, 0xFC, 0x93, 0x89, 0x70,
        0x9F, 0x8A, 0x11, 0xF3, 0xEA, 0x6A, 0x5A, 0xF7, 0xEF, 0xFA, 0x2D, 0x01, 0xC1, 0x89, 0xC5, 0x0F,
        0x0D, 0x5B, 0xCB, 0xE3, 0xFA, 0x27, 0x2E, 0x56, 0xCF, 0xC4, 0xA4, 0xE1, 0xD3, 0x88, 0xA9, 0xDC,
        0xD6, 0x5D, 0xF8, 0x62, 0x89, 0x02, 0x55, 0x6C, 0x8B, 0x6B, 0xB6, 0xA6, 0x41, 0x70, 0x9B, 0x5A,
        0x35, 0xDD, 0x26, 0x22, 0xC7, 0x3D, 0x46, 0x40, 0xBF, 0xA1, 0x35, 0x9D, 0x0E, 0x76, 0xE1, 0xF2,
        0x19, 0xF8, 0xE3, 0x3E, 0xB9, 0xBD, 0x0B, 0x59, 0xEC, 0x19, 0x8E, 0xB2, 0xFC, 0xCA, 0xAE, 0x03,
        0x46, 0xBD, 0x8B, 0x40, 0x1E, 0x12, 0xE3, 0xC6, 0x7C, 0xB6, 0x29, 0x56, 0x9C, 0x18, 0x5A, 0x2E,
        0x0F, 0x35, 0xA2, 0xF7, 0x41, 0x64, 0x4C, 0x1C, 0xCA, 0x5E, 0xBB, 0x13, 0x9D, 0x77, 0xA8, 0x9A,
        0x29, 0x53, 0xFC, 0x5E, 0x30, 0x04, 0x8C, 0x0E, 0x61, 0x9F, 0x07, 0xC8, 0xD2, 0x1D, 0x1E, 0x56,
        0xB8, 0xAF, 0x07, 0x19, 0x3D, 0x0F, 0xDF, 0x3F, 0x49, 0xCD, 0x49, 0xF2, 0xEF, 0x31, 0x38, 0xB5,
        0x13, 0x88, 0x62, 0xF1, 0x47, 0x0B, 0xD2, 0xD1, 0x6E, 0x34, 0xA2, 0xB9, 0xE7, 0x77, 0x7A, 0x6C,
        0x8C, 0x8D, 0x4C, 0xB9, 0x4B, 0x4E, 0x8B, 0x5D, 0x61, 0x6C, 0xD5, 0x39, 0x37, 0x53, 0xE7, 0xB0,
        0xF3, 0x1C, 0xC7, 0xDA, 0x55, 0x9B, 0xA8, 0xE9, 0x8D, 0x88, 0x89, 0x14, 0xE3, 0x34, 0x77, 0x3B,
        0xAF, 0x49, 0x8A, 0xD8, 0x8D, 0x96, 0x31, 0xEB, 0x5F, 0xE3, 0x2E, 0x53, 0xA4, 0x14, 0x5B, 0xF0,
        0xBA, 0x54, 0x8B, 0xF2, 0xB0, 0xA5, 0x0C, 0x63, 0xF6, 0x7B, 0x14, 0xE3, 0x98, 0xA3, 0x4B, 0x0D };
    static const uint8_t test_e[3] = { 0x26, 0x04, 0x45 };
    static const uint8_t test_m[128] = {
        0x74, 0x23, 0x04, 0x47, 0xBC, 0xD4, 0x92, 0xF2, 0xF8, 0xA8, 0xC5, 0x94, 0xA0, 0x43, 0x79, 0x27,
        0x16, 0x90, 0xBF, 0x0C, 0x8A, 0x13, 0xDD, 0xFC, 0x1B, 0x7B, 0x96, 0x41, 0x3E, 0x77, 0xAB, 0x26,
        0x64, 0xCB, 0xA1, 0xAC, 0xD7, 0xA3, 0xC5, 0x7E, 0xE5, 0x27, 0x6E, 0x27, 0x41, 0x4F, 0x82, 0x83,
        0xA6, 0xF9, 0x3B, 0x73, 0xBD, 0x39, 0x2B, 0xD5, 0x41, 0xF0, 0x7E, 0xB4, 0x61, 0xA0, 0x80, 0xBB,
        0x66, 0x7E, 0x5F, 0xF0, 0x95, 0xC9, 0x31, 0x9F, 0x57, 0x5B, 0x38, 0x93, 0x97, 0x7E, 0x65, 0x8C,
        0x6C, 0x00, 0x1C, 0xEE, 0xF8, 0x8A, 0x37, 0xB7, 0x90, 0x2D, 0x4D, 0xB3, 0x1C, 0x3E, 0x34, 0xF3,
        0xC1, 0x64, 0xC4, 0x7B, 0xBE, 0xEF, 0xDE, 0x3B, 0x94, 0x6B, 0xAD, 0x41, 0x6A, 0x75, 0x2C, 0x2C,
        0xAF, 0xCE, 0xE9, 0xE4, 0x01, 0xAE, 0x08, 0x88, 0x4E, 0x5B, 0x8A, 0xA8, 0x39, 0xF9, 0xD0, 0xB5 };
    static const uint8_t test_s[256] = {
        0x27, 0xDA, 0x41, 0x04, 0xEA, 0xCE, 0x19, 0x91, 0xE0, 0x8B, 0xD8, 0xE7, 0xCF, 0xCC, 0xD9, 0x7E,
        0xC4, 0x8B, 0x89, 0x6A, 0x0E, 0x15, 0x6C, 0xE7, 0xBD, 0xC2, 0x3F, 0xD5, 0x70, 0xAA, 0xA9, 0xA0,
        0x0E, 0xD0, 0x15, 0x10, 0x1F, 0x0C, 0x62, 0x61, 0xC7, 0x37, 0x1C, 0xEC, 0xA3, 0x27, 0xA7, 0x3C,
        0x3C, 0xEC, 0xFC, 0xF6, 0xB2, 0xD9, 0xED, 0x92, 0x0C, 0x96, 0x98, 0x04, 0x6E, 0x25, 0xC8, 0x9A,
        0xDB, 0x23, 0x60, 0x88, 0x7D, 0x99, 0x98, 0x3B, 0xF6, 0x32, 0xF9, 0xE6, 0xEB, 0x0E, 0x5D, 0xF6,
        0x07, 0x15, 0x90, 0x2B, 0x9A, 0xEA, 0xA7, 0x4B, 0xF5, 0x02, 0x7A, 0xA2, 0x46, 0x51, 0x08, 0x91,
        0xC7, 0x4A, 0xE3, 0x66, 0xA1, 0x6F, 0x39, 0x7E, 0x2C, 0x8C, 0xCD, 0xC8, 0xBD, 0x56, 0xAA, 0x10,
        0xE0, 0xD0, 0x15, 0x85, 0xE6, 0x9F, 0x8C, 0x48, 0x56, 0xE7, 0x6B, 0x53, 0xAC, 0xFD, 0x3D, 0x78,
        0x2B, 0x81, 0x71, 0x52, 0x90, 0x08, 0xFA, 0x5E, 0xFF, 0x03, 0x0F, 0x46, 0x95, 0x67, 0x04, 0xA3,
        0xF5, 0xD9, 0x16, 0x73, 0x48, 0xF3, 0x70, 0x21, 0xFC, 0x27, 0x7C, 0x6C, 0x0A, 0x8F, 0x93, 0xB8,
        0xA2, 0x3C, 0xFB, 0xF9, 0x18, 0x99, 0x0F, 0x98, 0x2A, 0x56, 0xD0, 0xED, 0x2A, 0xA0, 0x81, 0x61,
        0x56, 0x07, 0x55, 0xAD, 0xC0, 0xCE, 0x2C, 0x3E, 0x2A, 0xB2, 0x92, 0x9F, 0x79, 0xBF, 0xC0, 0xB2,
        0x4F, 0xF3, 0xE0, 0xFF, 0x35, 0x2E, 0x64, 0x45, 0xD8, 0xA6, 0x17, 0xF1, 0x78, 0x5D, 0x66, 0xC3,
        0x22, 0x95, 0xBB, 0x36, 0x5D, 0x61, 0xCF, 0xB1, 0x07, 0xE9, 0x99, 0x3B, 0xBD, 0x93, 0x42, 0x1F,
        0x2D, 0x34, 0x4A, 0x86, 0xE4, 0x12, 0x78, 0x27, 0xFA, 0x0D, 0x0B, 0x25, 0x35, 0xF9, 0xB1, 0xD5,
        0x47, 0xDE, 0x12, 0xBA, 0x28, 0x68, 0xAC, 0xDE, 0xCF, 0x2C, 0xB5, 0xF9, 0x2A, 0x6A, 0x15, 0x9A };
    static const ByteArray ba_n = { (uint8_t*)test_n, sizeof(test_n) };
    static const ByteArray ba_d = { (uint8_t*)test_d, sizeof(test_d) };
    static const ByteArray ba_e = { (uint8_t*)test_e, sizeof(test_e) };
    static const ByteArray ba_m = { (uint8_t*)test_m, sizeof(test_m) };
    static const ByteArray ba_s = { (uint8_t*)test_s, sizeof(test_s) };

    int ret = RET_OK;
    RsaCtx* rsa_ctx = NULL;
    ByteArray* ba_signature = NULL;
    HashCtx* hash_ctx = NULL;
    ByteArray* ba_hash = NULL;

    CHECK_NOT_NULL(hash_ctx = hash_alloc(HASH_ALG_SHA224));
    DO(hash_update(hash_ctx, &ba_m));
    DO(hash_final(hash_ctx, &ba_hash));
    CHECK_NOT_NULL(rsa_ctx = rsa_alloc());
    DO(rsa_init_sign_pkcs1_v1_5(rsa_ctx, HASH_ALG_SHA224, &ba_n, &ba_d));
    DO(rsa_sign(rsa_ctx, ba_hash, &ba_signature));
    if (ba_cmp(ba_signature, &ba_s) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

    DO(rsa_init_verify_pkcs1_v1_5(rsa_ctx, HASH_ALG_SHA224, &ba_n, &ba_e));
    DO(rsa_verify(rsa_ctx, ba_hash, ba_signature));

cleanup:
    ba_free(ba_signature);
    ba_free(ba_hash);
    rsa_free(rsa_ctx);
    hash_free(hash_ctx);
    return ret;
}

static int rsa_encrypt_oaep_self_test(void)
{
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-3rsatestvectors.zip
    static const uint8_t test_n[128] = { 
        0xA8, 0xB3, 0xB2, 0x84, 0xAF, 0x8E, 0xB5, 0x0B, 0x38, 0x70, 0x34, 0xA8, 0x60, 0xF1, 0x46, 0xC4,
        0x91, 0x9F, 0x31, 0x87, 0x63, 0xCD, 0x6C, 0x55, 0x98, 0xC8, 0xAE, 0x48, 0x11, 0xA1, 0xE0, 0xAB,
        0xC4, 0xC7, 0xE0, 0xB0, 0x82, 0xD6, 0x93, 0xA5, 0xE7, 0xFC, 0xED, 0x67, 0x5C, 0xF4, 0x66, 0x85,
        0x12, 0x77, 0x2C, 0x0C, 0xBC, 0x64, 0xA7, 0x42, 0xC6, 0xC6, 0x30, 0xF5, 0x33, 0xC8, 0xCC, 0x72,
        0xF6, 0x2A, 0xE8, 0x33, 0xC4, 0x0B, 0xF2, 0x58, 0x42, 0xE9, 0x84, 0xBB, 0x78, 0xBD, 0xBF, 0x97,
        0xC0, 0x10, 0x7D, 0x55, 0xBD, 0xB6, 0x62, 0xF5, 0xC4, 0xE0, 0xFA, 0xB9, 0x84, 0x5C, 0xB5, 0x14,
        0x8E, 0xF7, 0x39, 0x2D, 0xD3, 0xAA, 0xFF, 0x93, 0xAE, 0x1E, 0x6B, 0x66, 0x7B, 0xB3, 0xD4, 0x24, 
        0x76, 0x16, 0xD4, 0xF5, 0xBA, 0x10, 0xD4, 0xCF, 0xD2, 0x26, 0xDE, 0x88, 0xD3, 0x9F, 0x16, 0xFB };
    static const uint8_t test_d[128] = { 
        0x53, 0x33, 0x9C, 0xFD, 0xB7, 0x9F, 0xC8, 0x46, 0x6A, 0x65, 0x5C, 0x73, 0x16, 0xAC, 0xA8, 0x5C,
        0x55, 0xFD, 0x8F, 0x6D, 0xD8, 0x98, 0xFD, 0xAF, 0x11, 0x95, 0x17, 0xEF, 0x4F, 0x52, 0xE8, 0xFD,
        0x8E, 0x25, 0x8D, 0xF9, 0x3F, 0xEE, 0x18, 0x0F, 0xA0, 0xE4, 0xAB, 0x29, 0x69, 0x3C, 0xD8, 0x3B,
        0x15, 0x2A, 0x55, 0x3D, 0x4A, 0xC4, 0xD1, 0x81, 0x2B, 0x8B, 0x9F, 0xA5, 0xAF, 0x0E, 0x7F, 0x55,
        0xFE, 0x73, 0x04, 0xDF, 0x41, 0x57, 0x09, 0x26, 0xF3, 0x31, 0x1F, 0x15, 0xC4, 0xD6, 0x5A, 0x73,
        0x2C, 0x48, 0x31, 0x16, 0xEE, 0x3D, 0x3D, 0x2D, 0x0A, 0xF3, 0x54, 0x9A, 0xD9, 0xBF, 0x7C, 0xBF,
        0xB7, 0x8A, 0xD8, 0x84, 0xF8, 0x4D, 0x5B, 0xEB, 0x04, 0x72, 0x4D, 0xC7, 0x36, 0x9B, 0x31, 0xDE,
        0xF3, 0x7D, 0x0C, 0xF5, 0x39, 0xE9, 0xCF, 0xCD, 0xD3, 0xDE, 0x65, 0x37, 0x29, 0xEA, 0xD5, 0xD1 };
    static const uint8_t test_e[3] = { 0x01, 0x00, 0x01 };
    static const uint8_t test_m[28] = {
        0x66, 0x28, 0x19, 0x4E, 0x12, 0x07, 0x3D, 0xB0, 0x3B, 0xA9, 0x4C, 0xDA, 0x9E, 0xF9, 0x53, 0x23,
        0x97, 0xD5, 0x0D, 0xBA, 0x79, 0xB9, 0x87, 0x00, 0x4A, 0xFE, 0xFE, 0x34 };
    static const uint8_t test_salt[20] = { 
        0x18, 0xB7, 0x76, 0xEA, 0x21, 0x06, 0x9D, 0x69, 0x77, 0x6A, 0x33, 0xE9, 0x6B, 0xAD, 0x48, 0xE1, 
        0xDD, 0xA0, 0xA5, 0xEF };
    static const uint8_t test_ct[128] = { 
        0x35, 0x4F, 0xE6, 0x7B, 0x4A, 0x12, 0x6D, 0x5D, 0x35, 0xFE, 0x36, 0xC7, 0x77, 0x79, 0x1A, 0x3F, 
        0x7B, 0xA1, 0x3D, 0xEF, 0x48, 0x4E, 0x2D, 0x39, 0x08, 0xAF, 0xF7, 0x22, 0xFA, 0xD4, 0x68, 0xFB,
        0x21, 0x69, 0x6D, 0xE9, 0x5D, 0x0B, 0xE9, 0x11, 0xC2, 0xD3, 0x17, 0x4F, 0x8A, 0xFC, 0xC2, 0x01, 
        0x03, 0x5F, 0x7B, 0x6D, 0x8E, 0x69, 0x40, 0x2D, 0xE5, 0x45, 0x16, 0x18, 0xC2, 0x1A, 0x53, 0x5F, 
        0xA9, 0xD7, 0xBF, 0xC5, 0xB8, 0xDD, 0x9F, 0xC2, 0x43, 0xF8, 0xCF, 0x92, 0x7D, 0xB3, 0x13, 0x22,
        0xD6, 0xE8, 0x81, 0xEA, 0xA9, 0x1A, 0x99, 0x61, 0x70, 0xE6, 0x57, 0xA0, 0x5A, 0x26, 0x64, 0x26, 
        0xD9, 0x8C, 0x88, 0x00, 0x3F, 0x84, 0x77, 0xC1, 0x22, 0x70, 0x94, 0xA0, 0xD9, 0xFA, 0x1E, 0x8C, 
        0x40, 0x24, 0x30, 0x9C, 0xE1, 0xEC, 0xCC, 0xB5, 0x21, 0x00, 0x35, 0xD4, 0x7A, 0xC7, 0x2E, 0x8A };
    static const ByteArray ba_n = { (uint8_t*)test_n, sizeof(test_n) };
    static const ByteArray ba_d = { (uint8_t*)test_d, sizeof(test_d) };
    static const ByteArray ba_e = { (uint8_t*)test_e, sizeof(test_e) };
    static const ByteArray ba_m = { (uint8_t*)test_m, sizeof(test_m) };
    static const ByteArray ba_salt = { (uint8_t*)test_salt, sizeof(test_salt) };
    static const ByteArray ba_ct = { (uint8_t*)test_ct, sizeof(test_ct) };

    int ret = RET_OK;
    RsaCtx* rsa_ctx = NULL;
    ByteArray* ba_encrypted = NULL;
    ByteArray* ba_decrypted = NULL;

    CHECK_NOT_NULL(rsa_ctx = rsa_alloc());
    DO(rsa_init_encrypt_oaep(rsa_ctx, HASH_ALG_SHA1, NULL, &ba_n, &ba_e));
    DO(rsa_encrypt_oaep(rsa_ctx, &ba_m, NULL, &ba_salt, &ba_encrypted));
    if (ba_cmp(ba_encrypted, &ba_ct) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

    DO(rsa_init_decrypt_oaep(rsa_ctx, HASH_ALG_SHA1, NULL, &ba_n, &ba_d));
    DO(rsa_decrypt(rsa_ctx, ba_encrypted, &ba_decrypted));
    if (ba_cmp(ba_decrypted, &ba_m) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

cleanup:
    ba_free(ba_encrypted);
    ba_free(ba_decrypted);
    rsa_free(rsa_ctx);
    return ret;
}

int rsa_self_test(void)
{
    int ret = RET_OK;

    DO(rsa_sign_pss_self_test());
    DO(rsa_sign_pkcs_self_test());
    DO(rsa_encrypt_oaep_self_test());

cleanup:
    return ret;
}