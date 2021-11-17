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

#include "ec-cache.h"
#include "ec-cache-internal.h"
#include "ec-internal.h"
#include "pthread-internal.h"
#include "macros-internal.h"

#undef FILE_MARKER
#define FILE_MARKER "uapkic/ec-cache.c"

typedef enum {
    CHACHE_EC_BY_ID,
    CHACHE_EC_BINARY_PB,
    CHACHE_EC_BINARY_ONB,
    CHACHE_EC_PRIME
} EcCacheItemType;

typedef struct EcCache_st {
    EcCacheItemType item_type;
    ByteArray *ba_a;
    ByteArray *ba_b;
    ByteArray *ba_p;
    ByteArray *ba_n;
    ByteArray *ba_px;
    ByteArray *ba_py;
    EcCtx *ctx;
    struct EcCache_st *next;
} EcCache;

static EcCache *ec_cache = NULL;
static pthread_mutex_t ec_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

OptLevelId default_opt_level = 0;

static void ec_cache_append(EcCache *ec_cache_new)
{
    if (ec_cache) {
        EcCache * ec_cache_curr = ec_cache;
        while (ec_cache_curr->next != NULL) {
            ec_cache_curr = ec_cache_curr->next;
        }
        ec_cache_curr->next = ec_cache_new;
    } else {
        ec_cache = ec_cache_new;
    }
}

static EcCache *ec_cache_get_element_by_id(EcParamsId params_id)
{
    if (ec_cache) {
        EcCache *ec_cache_curr = ec_cache;
        while (ec_cache_curr != NULL) {
            if (ec_cache_curr->item_type == CHACHE_EC_BY_ID &&
                ec_cache_curr->ctx->params->params_id == params_id) {
                return ec_cache_curr;
            } else {
                ec_cache_curr = ec_cache_curr->next;
            }
        }
    }

    return NULL;
}

static bool compare_f(const int* f1, const int* f2)
{
    do {
        if (*f1++ != *f2++) return false;
    } while (*f1 != 0);
    return true;
}

static EcCache *ec_cache_get_element_by_pb(const int *f, size_t a, const ByteArray *b,
        const ByteArray *n, const ByteArray *px, const ByteArray *py)
{
    if (ec_cache) {
        EcCache *ec_cache_curr = ec_cache;
        while (ec_cache_curr != NULL) {
            if (ec_cache_curr->item_type == CHACHE_EC_BINARY_PB && 
                ec_cache_curr->ctx->params->is_onb == false && 
                ec_cache_curr->ctx->params->ec2m != NULL && 
                compare_f(ec_cache_curr->ctx->params->ec2m->gf2m->f, f) && 
                ec_cache_curr->ctx->params->ec2m->a == a && 
                ba_cmp(ec_cache_curr->ba_b, b) == 0 && 
                ba_cmp(ec_cache_curr->ba_n, n) == 0 && 
                ba_cmp(ec_cache_curr->ba_px, px) == 0 && 
                ba_cmp(ec_cache_curr->ba_py, py) == 0) {
                return ec_cache_curr;
            } else {
                ec_cache_curr = ec_cache_curr->next;
            }
        }
    }

    return NULL;
}

static EcCache *ec_cache_get_element_by_onb(size_t m, size_t a, const ByteArray *b, const ByteArray *n,
        const ByteArray *px, const ByteArray *py)
{
    if (ec_cache) {
        EcCache *ec_cache_curr = ec_cache;
        while (ec_cache_curr != NULL) {
            if (ec_cache_curr->item_type == CHACHE_EC_BINARY_ONB && 
                ec_cache_curr->ctx->params->is_onb == true && 
                ec_cache_curr->ctx->params->m == m && 
                ec_cache_curr->ctx->params->ec2m != NULL && 
                ec_cache_curr->ctx->params->ec2m->a == a && 
                ba_cmp(ec_cache_curr->ba_b, b) == 0 && 
                ba_cmp(ec_cache_curr->ba_n, n) == 0 && 
                ba_cmp(ec_cache_curr->ba_px, px) == 0 && 
                ba_cmp(ec_cache_curr->ba_py, py) == 0) {
                return ec_cache_curr;
            } else {
                ec_cache_curr = ec_cache_curr->next;
            }
        }
    }

    return NULL;
}

static EcCache *ec_cache_get_element_by_p(const ByteArray *p, const ByteArray *a, const ByteArray *b,
        const ByteArray *n, const ByteArray *px, const ByteArray *py)
{
    if (ec_cache) {
        EcCache * ec_cache_curr = ec_cache;
        while (ec_cache_curr != NULL) {
            if (ec_cache_curr->item_type == CHACHE_EC_PRIME && 
                ec_cache_curr->ctx->params->ecp != NULL && 
                ba_cmp(ec_cache_curr->ba_p, p) == 0 && 
                ba_cmp(ec_cache_curr->ba_a, a) == 0 && 
                ba_cmp(ec_cache_curr->ba_b, b) == 0 && 
                ba_cmp(ec_cache_curr->ba_n, n) == 0 && 
                ba_cmp(ec_cache_curr->ba_px, px) == 0 && 
                ba_cmp(ec_cache_curr->ba_py, py) == 0) {
                return ec_cache_curr;
            } else {
                ec_cache_curr = ec_cache_curr->next;
            }
        }
    }

    return NULL;
}

static void ec_cache_item_free(EcCache* ec_cache_curr)
{
    if (ec_cache_curr) {
        ba_free(ec_cache_curr->ba_a);
        ba_free(ec_cache_curr->ba_b);
        ba_free(ec_cache_curr->ba_p);
        ba_free(ec_cache_curr->ba_n);
        ba_free(ec_cache_curr->ba_px);
        ba_free(ec_cache_curr->ba_py);
        ec_free(ec_cache_curr->ctx);
        free(ec_cache_curr);
    }
}

int ec_cache_add_default(EcParamsId params_id, OptLevelId opt_level)
{
    int ret = RET_OK;
    EcCtx *ctx = NULL;
    EcCache* ec_cache_curr = NULL;
    EcCache* ec_cache_new = NULL;

    pthread_mutex_lock(&ec_cache_mutex);

    ec_cache_curr = ec_cache_get_element_by_id(params_id);
    if (ec_cache_curr != NULL) {
        SET_ERROR(RET_CTX_ALREADY_IN_CACHE);
    } else {
        CALLOC_CHECKED(ec_cache_new, sizeof(EcCache));

        CHECK_NOT_NULL(ctx = ec_alloc_new(params_id));
        DO(ec_set_opt_level(ctx, opt_level));

        ec_cache_new->ctx = ctx;
        ctx = NULL;
        ec_cache_new->item_type = CHACHE_EC_BY_ID;

        ec_cache_append(ec_cache_new);
        ec_cache_new = NULL;
    }

cleanup:

    pthread_mutex_unlock(&ec_cache_mutex);
    ec_cache_item_free(ec_cache_new);
    ec_free(ctx);

    return ret;
}

EcCtx *ec_cache_get_default(EcParamsId params_id)
{
    int ret = RET_OK;
    EcCache *ec_cache_curr = NULL;
    EcCtx *ctx = NULL;

    ec_cache_curr = ec_cache_get_element_by_id(params_id);
    if (ec_cache_curr != NULL) {
        CHECK_NOT_NULL(ctx = ec_copy_params_with_alloc(ec_cache_curr->ctx));
    } else if (default_opt_level != 0) {
        ret = ec_cache_add_default(params_id, default_opt_level);
        if (ret != RET_OK && ret != RET_CTX_ALREADY_IN_CACHE) {
            SET_ERROR(ret);
        }

        ec_cache_curr = ec_cache_get_element_by_id(params_id);
        if (ec_cache_curr != NULL) {
            CHECK_NOT_NULL(ctx = ec_copy_params_with_alloc(ec_cache_curr->ctx));
        }
    }

cleanup:

    return ctx;
}

int ec_cache_add_ec2m_pb(const int *f, size_t f_len, size_t a, const ByteArray *b, const ByteArray *n,
        const ByteArray *px, const ByteArray *py, OptLevelId opt_level)
{
    int ret = RET_OK;
    EcCtx *ctx = NULL;
    EcCache *ec_cache_curr = NULL;
    EcCache *ec_cache_new = NULL;

    pthread_mutex_lock(&ec_cache_mutex);

    ec_cache_curr = ec_cache_get_element_by_pb(f, a, b, n, px, py);
    if (ec_cache_curr != NULL) {
        SET_ERROR(RET_CTX_ALREADY_IN_CACHE);
    } else {
        CALLOC_CHECKED(ec_cache_new, sizeof(EcCache));

        CHECK_NOT_NULL(ctx = ec_alloc_binary_pb_new(f, f_len, a, b, n, px, py));
        DO(ec_set_opt_level(ctx, opt_level));

        ec_cache_new->ctx = ctx;
        ctx = NULL;

        ec_cache_new->item_type = CHACHE_EC_BINARY_PB;
        CHECK_NOT_NULL(ec_cache_new->ba_b = ba_copy_with_alloc(b, 0, 0));
        CHECK_NOT_NULL(ec_cache_new->ba_n = ba_copy_with_alloc(n, 0, 0));
        CHECK_NOT_NULL(ec_cache_new->ba_px = ba_copy_with_alloc(px, 0, 0));
        CHECK_NOT_NULL(ec_cache_new->ba_py = ba_copy_with_alloc(py, 0, 0));

        ec_cache_append(ec_cache_new);
        ec_cache_new = NULL;
    }

cleanup:

    pthread_mutex_unlock(&ec_cache_mutex);
    ec_cache_item_free(ec_cache_new);
    ec_free(ctx);

    return ret;
}

EcCtx *ec_cache_get_ec2m_pb(const int *f, size_t f_len, size_t a, const ByteArray *b, const ByteArray *n,
        const ByteArray *px, const ByteArray *py)
{
    int ret = RET_OK;
    EcCache *ec_cache_curr = NULL;
    EcCtx *ctx = NULL;

    ec_cache_curr = ec_cache_get_element_by_pb(f, a, b, n, px, py);
    if (ec_cache_curr != NULL) {
        CHECK_NOT_NULL(ctx = ec_copy_params_with_alloc(ec_cache_curr->ctx));
    } else if (default_opt_level != 0) {

        DO(ec_cache_add_ec2m_pb(f, f_len, a, b, n, px, py, default_opt_level));

        ec_cache_curr = ec_cache_get_element_by_pb(f, a, b, n, px, py);
        if (ec_cache_curr != NULL) {
            CHECK_NOT_NULL(ctx = ec_copy_params_with_alloc(ec_cache_curr->ctx));
        }
    }

cleanup:

    return ctx;
}

int ec_cache_add_ec2m_onb(size_t m, size_t a, const ByteArray *b, const ByteArray *n, const ByteArray *px,
        const ByteArray *py, OptLevelId opt_level)
{
    int ret = RET_OK;
    EcCtx *ctx = NULL;
    EcCache *ec_cache_curr = NULL;
    EcCache *ec_cache_new = NULL;

    pthread_mutex_lock(&ec_cache_mutex);

    ec_cache_curr = ec_cache_get_element_by_onb(m, a, b, n, px, py);
    if (ec_cache_curr != NULL) {
        SET_ERROR(RET_CTX_ALREADY_IN_CACHE);
    } else {
        CALLOC_CHECKED(ec_cache_new, sizeof(EcCache));

        CHECK_NOT_NULL(ctx = ec_alloc_binary_onb_new(m, a, b, n, px, py));
        DO(ec_set_opt_level(ctx, opt_level));

        ec_cache_new->ctx = ctx;
        ctx = NULL;

        ec_cache_new->item_type = CHACHE_EC_BINARY_ONB;
        CHECK_NOT_NULL(ec_cache_new->ba_b = ba_copy_with_alloc(b, 0, 0));
        CHECK_NOT_NULL(ec_cache_new->ba_n = ba_copy_with_alloc(n, 0, 0));
        CHECK_NOT_NULL(ec_cache_new->ba_px = ba_copy_with_alloc(px, 0, 0));
        CHECK_NOT_NULL(ec_cache_new->ba_py = ba_copy_with_alloc(py, 0, 0));

        ec_cache_append(ec_cache_new);
        ec_cache_new = NULL;
    }

cleanup:

    pthread_mutex_unlock(&ec_cache_mutex);
    ec_cache_item_free(ec_cache_new);
    ec_free(ctx);

    return ret;
}

EcCtx* ec_cache_get_ec2m_onb(size_t m, size_t a, const ByteArray* b, const ByteArray* n,
    const ByteArray* px, const ByteArray* py)
{
    int ret = RET_OK;
    EcCache* ec_cache_curr = NULL;
    EcCtx* ctx = NULL;

    ec_cache_curr = ec_cache_get_element_by_onb(m, a, b, n, px, py);
    if (ec_cache_curr != NULL) {
        CHECK_NOT_NULL(ctx = ec_copy_params_with_alloc(ec_cache_curr->ctx));
    }
    else if (default_opt_level != 0) {

        DO(ec_cache_add_ec2m_onb(m, a, b, n, px, py, default_opt_level));

        ec_cache_curr = ec_cache_get_element_by_onb(m, a, b, n, px, py);
        if (ec_cache_curr != NULL) {
            CHECK_NOT_NULL(ctx = ec_copy_params_with_alloc(ec_cache_curr->ctx));
        }
    }
cleanup:

    return ctx;
}

int ec_cache_add_ecp(const ByteArray *p, const ByteArray *a, const ByteArray *b, const ByteArray *q,
        const ByteArray *px, const ByteArray *py, OptLevelId opt_level)
{
    int ret = RET_OK;
    EcCtx *ctx = NULL;
    EcCache *ec_cache_curr = NULL;
    EcCache *ec_cache_new = NULL;

    pthread_mutex_lock(&ec_cache_mutex);

    ec_cache_curr = ec_cache_get_element_by_p(p, a, b, q, px, py);
    if (ec_cache_curr != NULL) {
        SET_ERROR(RET_CTX_ALREADY_IN_CACHE);
    } else {
        CALLOC_CHECKED(ec_cache_new, sizeof(EcCache));

        CHECK_NOT_NULL(ctx = ec_alloc_prime_new(p, a, b, q, px, py));
        DO(ec_set_opt_level(ctx, opt_level));

        ec_cache_new->ctx = ctx;
        ctx = NULL;

        ec_cache_new->item_type = CHACHE_EC_PRIME;
        CHECK_NOT_NULL(ec_cache_new->ba_p = ba_copy_with_alloc(p, 0, 0));
        CHECK_NOT_NULL(ec_cache_new->ba_a = ba_copy_with_alloc(a, 0, 0));
        CHECK_NOT_NULL(ec_cache_new->ba_b = ba_copy_with_alloc(b, 0, 0));
        CHECK_NOT_NULL(ec_cache_new->ba_n = ba_copy_with_alloc(q, 0, 0));
        CHECK_NOT_NULL(ec_cache_new->ba_px = ba_copy_with_alloc(px, 0, 0));
        CHECK_NOT_NULL(ec_cache_new->ba_py = ba_copy_with_alloc(py, 0, 0));

        ec_cache_append(ec_cache_new);
        ec_cache_new = NULL;
    }

cleanup:

    pthread_mutex_unlock(&ec_cache_mutex);
    ec_cache_item_free(ec_cache_new);
    ec_free(ctx);

    return ret;
}

EcCtx* ec_cache_get_ecp(const ByteArray* p, const ByteArray* a, const ByteArray* b, const ByteArray* q,
    const ByteArray* px, const ByteArray* py)
{
    int ret = RET_OK;
    EcCache* ec_cache_curr = NULL;
    EcCtx* ctx = NULL;

    ec_cache_curr = ec_cache_get_element_by_p(p, a, b, q, px, py);
    if (ec_cache_curr != NULL) {
        CHECK_NOT_NULL(ctx = ec_copy_params_with_alloc(ec_cache_curr->ctx));
    }
    else if (default_opt_level != 0) {
        DO(ec_cache_add_ecp(p, a, b, q, px, py, default_opt_level));

        ec_cache_curr = ec_cache_get_element_by_p(p, a, b, q, px, py);
        if (ec_cache_curr != NULL) {
            CHECK_NOT_NULL(ctx = ec_copy_params_with_alloc(ec_cache_curr->ctx));
        }
    }

cleanup:

    return ctx;
}

int ec_cache_set_default_opt_level(OptLevelId opt_level)
{
    int ret = RET_OK;

    int sign_comb_opt_level = (opt_level >> 12) & 0x0f;
    int sign_win_opt_level = (opt_level >> 8) & 0x0f;
    int verify_comb_opt_level = (opt_level >> 4) & 0x0f;
    int verify_win_opt_level = opt_level & 0x0f;

    CHECK_PARAM(sign_comb_opt_level == 0 || sign_win_opt_level == 0);
    CHECK_PARAM(sign_win_opt_level == 0 || (sign_win_opt_level & 1) == 1);
    CHECK_PARAM(verify_comb_opt_level == 0 || verify_win_opt_level == 0);
    CHECK_PARAM(verify_win_opt_level == 0 || (verify_win_opt_level & 1) == 1);

    default_opt_level = opt_level;

cleanup:

    return ret;
}

void ec_cache_free(void)
{
    pthread_mutex_lock(&ec_cache_mutex);

#if defined(_WIN32)
    Sleep(1000);
#else
    sleep(1);
#endif

    if (ec_cache) {
        EcCache* ec_cache_next = ec_cache;
        ec_cache = NULL;
        EcCache* ec_cache_curr;

        while (ec_cache_next != NULL) {
            ec_cache_curr = ec_cache_next;
            ec_cache_next = ec_cache_curr->next;
            ec_cache_item_free(ec_cache_curr);
        }
    }

    pthread_mutex_unlock(&ec_cache_mutex);
}
