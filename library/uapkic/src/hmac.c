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

#include <string.h>

#include "hmac.h"
#include "byte-array-internal.h"
#include "macros-internal.h"

#undef FILE_MARKER
#define FILE_MARKER "uapkic/hmac.c"

#define HMAC_MAX_BLOCK_SIZE   144

/** Контекст выработки хэш-вектора. */

struct HmacCtx_st {
    ByteArray *k_ipad;
    ByteArray *k_opad;
    size_t block_len;
    HashCtx *hctx;
};

HmacCtx* hmac_alloc(HashAlg alg)
{
    int ret = RET_OK;
    HmacCtx *ctx = NULL;

    CALLOC_CHECKED(ctx, sizeof(HmacCtx));
    CHECK_NOT_NULL(ctx->hctx = hash_alloc(alg));
    ctx->block_len = hash_get_block_size(ctx->hctx);
    CHECK_NOT_NULL(ctx->k_ipad = ba_alloc_by_len(ctx->block_len));
    CHECK_NOT_NULL(ctx->k_opad = ba_alloc_by_len(ctx->block_len));

cleanup:

    if (ret != RET_OK) {
        hmac_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

HmacCtx* hmac_alloc_gost34311_with_sbox_id(Gost28147SboxId sbox_id)
{
    int ret = RET_OK;
    HmacCtx* ctx = NULL;

    CALLOC_CHECKED(ctx, sizeof(HmacCtx));
    CHECK_NOT_NULL(ctx->hctx = hash_alloc_gost34311_with_sbox_id(sbox_id));
    ctx->block_len = hash_get_block_size(ctx->hctx);
    CHECK_NOT_NULL(ctx->k_ipad = ba_alloc_by_len(ctx->block_len));
    CHECK_NOT_NULL(ctx->k_opad = ba_alloc_by_len(ctx->block_len));

cleanup:

    if (ret != RET_OK) {
        hmac_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

HmacCtx* hmac_alloc_gost34311_with_sbox(const ByteArray* sbox)
{
    int ret = RET_OK;
    HmacCtx* ctx = NULL;

    CALLOC_CHECKED(ctx, sizeof(HmacCtx));
    CHECK_NOT_NULL(ctx->hctx = hash_alloc_gost34311_with_sbox(sbox));
    ctx->block_len = hash_get_block_size(ctx->hctx);
    CHECK_NOT_NULL(ctx->k_ipad = ba_alloc_by_len(ctx->block_len));
    CHECK_NOT_NULL(ctx->k_opad = ba_alloc_by_len(ctx->block_len));

cleanup:

    if (ret != RET_OK) {
        hmac_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

int hmac_init(HmacCtx *ctx, const ByteArray *key)
{
    ByteArray *key_tmp = NULL;
    size_t i;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);

    if (key->len > ctx->block_len) {
        DO(hash_update(ctx->hctx, key));
        DO(hash_final(ctx->hctx, &key_tmp));
    } else {
        CHECK_NOT_NULL(key_tmp = ba_copy_with_alloc(key, 0, 0));
    }

    memset(ctx->k_ipad->buf, 0, ctx->block_len);
    memset(ctx->k_opad->buf, 0, ctx->block_len);

    DO(ba_to_uint8(key_tmp, ctx->k_ipad->buf, key_tmp->len));
    DO(ba_to_uint8(key_tmp, ctx->k_opad->buf, key_tmp->len));

    /*RFC const*/
    for (i = 0; i < ctx->block_len; i++) {
        ctx->k_ipad->buf[i] ^= 0x36;
        ctx->k_opad->buf[i] ^= 0x5c;
    }

    DO(hash_update(ctx->hctx, ctx->k_ipad));

cleanup:

    ba_free_private(key_tmp);

    return ret;
}

int hmac_update(HmacCtx *ctx, const ByteArray *data)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(data != NULL);

    DO(hash_update(ctx->hctx, data));

cleanup:

    return ret;
}

int hmac_final(HmacCtx* ctx, ByteArray** hmac)
{
    ByteArray* upd_hmac = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(hmac != NULL);

    DO(hash_final(ctx->hctx, &upd_hmac));
    DO(hash_update(ctx->hctx, ctx->k_opad));
    DO(hash_update(ctx->hctx, upd_hmac));
    DO(hash_final(ctx->hctx, hmac));
cleanup:

    ba_free_private(upd_hmac);

    return ret;
}

int hmac_reset(HmacCtx* ctx)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);

    DO(hash_update(ctx->hctx, ctx->k_ipad));

cleanup:

    return ret;
}

void hmac_free(HmacCtx *ctx)
{
    if (ctx) {
        hash_free(ctx->hctx);
        ba_free_private(ctx->k_opad);
        ba_free_private(ctx->k_ipad);
        free(ctx);
    }
}

int hmac_self_test(void)
{
    // RFC 2202 (HMAC-MD5, HMAC-SHA1), HMAC-SHA-512 tested with HMAC-DRBG
    static const uint8_t key[] = {
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA };
    static const uint8_t msg[] = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";
    static const uint8_t hmac_md5[] = {
        0x6F, 0x63, 0x0F, 0xAD, 0x67, 0xCD, 0xA0, 0xEE, 0x1F, 0xB1, 0xF5, 0x62, 0xDB, 0x3A, 0xA5, 0x3E };
    static const uint8_t hmac_sha1[] = {
        0xE8, 0xE9, 0x9D, 0x0F, 0x45, 0x23, 0x7D, 0x78, 0x6D, 0x6B, 0xBA, 0xA7, 0x96, 0x5C, 0x78, 0x08, 
        0xBB, 0xFF, 0x1A, 0x91 };

    // HMAC ГОСТ 34.311. Додаток 2 до Вимог до форматів контейнерів зберігання особистих ключів електронного цифрового підпису, 
    // особистих ключів шифрування та сертифікатів відкритих ключів. Наказ Міністерства юстиції України, Адміністрації Державної 
    // служби спеціального зв'язку та захисту інформації України 27.12.2013 N 2782 / 5 / 689
    static const uint8_t gost34311_key[32] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    static const uint8_t gost34311_msg[32] = {
        0x88, 0x88, 0x88, 0x88, 0x99, 0x99, 0x99, 0x99, 0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB,
        0xCC, 0xCC, 0xCC, 0xCC, 0xDD, 0xDD, 0xDD, 0xDD, 0xEE, 0xEE, 0xEE, 0xEE, 0xFF, 0xFF, 0xFF, 0xFF };
    static const uint8_t hmac_gost34311[32] = {
        0x67, 0x91, 0x42, 0x78, 0x14, 0x55, 0xAC, 0x14, 0xC7, 0xEA, 0x38, 0x4D, 0x6F, 0x81, 0xD9, 0x67,
        0xB7, 0xAF, 0xFB, 0xCF, 0x39, 0xEB, 0x9F, 0x9E, 0x2B, 0x25, 0x69, 0xD4, 0x3C, 0x7A, 0xD8, 0xB7 };

    static const ByteArray ba_key = { (uint8_t*)key , sizeof(key) };
    static const ByteArray ba_msg = { (uint8_t*)msg , sizeof(msg) - 1 };
    static const ByteArray ba_gost34311_key = { (uint8_t*)gost34311_key , sizeof(gost34311_key) };
    static const ByteArray ba_gost34311_msg = { (uint8_t*)gost34311_msg , sizeof(gost34311_msg) };
    static const ByteArray ba_hmac_md5 = { (uint8_t*)hmac_md5 , sizeof(hmac_md5) };
    static const ByteArray ba_hmac_sha1 = { (uint8_t*)hmac_sha1 , sizeof(hmac_sha1) };
    static const ByteArray ba_hmac_gost34311 = { (uint8_t*)hmac_gost34311 , sizeof(hmac_gost34311) };

    int ret = RET_OK;
    HmacCtx *ctx = NULL;
    ByteArray* hmac = NULL;

    CHECK_NOT_NULL(ctx = hmac_alloc(HASH_ALG_MD5));
    DO(hmac_init(ctx, &ba_key));
    DO(hmac_update(ctx, &ba_msg));
    DO(hmac_final(ctx, &hmac));
    if (ba_cmp(hmac, &ba_hmac_md5) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }
    ba_free(hmac);
    hmac = NULL;
    hmac_free(ctx);

    CHECK_NOT_NULL(ctx = hmac_alloc(HASH_ALG_SHA1));
    DO(hmac_init(ctx, &ba_key));
    DO(hmac_update(ctx, &ba_msg));
    DO(hmac_final(ctx, &hmac));
    if (ba_cmp(hmac, &ba_hmac_sha1) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }
    ba_free(hmac);
    hmac = NULL;
    hmac_free(ctx);

    CHECK_NOT_NULL(ctx = hmac_alloc(HASH_ALG_GOST34311));
    DO(hmac_init(ctx, &ba_gost34311_key));
    DO(hmac_update(ctx, &ba_gost34311_msg));
    DO(hmac_final(ctx, &hmac));
    if (ba_cmp(hmac, &ba_hmac_gost34311) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

cleanup:
    ba_free(hmac);
    hmac_free(ctx);
    return ret;
}