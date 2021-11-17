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
#include <stddef.h>

#include "hash.h"
#include "md5.h"
#include "ripemd.h"
#include "sha1.h"
#include "sha2.h"
#include "sha3.h"
#include "whirlpool.h"
#include "sm3.h"
#include "gost34311.h"
#include "dstu7564.h"
#include "whirlpool.h"
#include "gostr3411-2012.h"
#include "byte-array-internal.h"
#include "macros-internal.h"

typedef int (*f_update)(void* ctx, const ByteArray* data);
typedef int (*f_final)(void* ctx, ByteArray** hash);
typedef void (*f_free)(void* ctx);
typedef size_t (*f_get_block_size)(const void* ctx);
typedef void* (*f_copy_with_alloc)(const void* ctx);

struct HashCtx_st {
    void* ctx;
    HashAlg alg;
    f_update update;
    f_final final;
    f_free free;
    f_get_block_size get_block_size;
    f_copy_with_alloc copy_with_alloc;
};

HashCtx* hash_alloc(HashAlg alg)
{
    int ret = RET_OK;
    HashCtx *ctx = NULL;

    MALLOC_CHECKED(ctx, sizeof(HashCtx));
    ctx->alg = alg;

    switch (ctx->alg)
    {
    case HASH_ALG_DSTU7564_256:
        CHECK_NOT_NULL(ctx->ctx = dstu7564_alloc());
        if ((ret = dstu7564_init(ctx->ctx, 32)) != RET_OK) {
            dstu7564_free(ctx->ctx);
        }
        ctx->update = (f_update)dstu7564_update;
        ctx->final = (f_final)dstu7564_final;
        ctx->free = (f_free)dstu7564_free;
        ctx->get_block_size = (f_get_block_size)dstu7564_get_block_size;
        ctx->copy_with_alloc = (f_copy_with_alloc)dstu7564_copy_with_alloc;
        break;

    case HASH_ALG_DSTU7564_384:
        CHECK_NOT_NULL(ctx->ctx = dstu7564_alloc());
        if ((ret = dstu7564_init(ctx->ctx, 48)) != RET_OK) {
            dstu7564_free(ctx->ctx);
        }
        ctx->update = (f_update)dstu7564_update;
        ctx->final = (f_final)dstu7564_final;
        ctx->free = (f_free)dstu7564_free;
        ctx->get_block_size = (f_get_block_size)dstu7564_get_block_size;
        ctx->copy_with_alloc = (f_copy_with_alloc)dstu7564_copy_with_alloc;
        break;

    case HASH_ALG_DSTU7564_512:
        CHECK_NOT_NULL(ctx->ctx = dstu7564_alloc());
        if ((ret = dstu7564_init(ctx->ctx, 64)) != RET_OK) {
            free(ctx->ctx);
        }
        ctx->update = (f_update)dstu7564_update;
        ctx->final = (f_final)dstu7564_final;
        ctx->free = (f_free)dstu7564_free;
        ctx->get_block_size = (f_get_block_size)dstu7564_get_block_size;
        ctx->copy_with_alloc = (f_copy_with_alloc)dstu7564_copy_with_alloc;
        break;

    case HASH_ALG_GOST34311:
        CHECK_NOT_NULL(ctx->ctx = gost34311_alloc(GOST28147_SBOX_ID_1, NULL));
        ctx->update = (f_update)gost34311_update;
        ctx->final = (f_final)gost34311_final;
        ctx->free = (f_free)gost34311_free;
        ctx->get_block_size = (f_get_block_size)gost34311_get_block_size;
        ctx->copy_with_alloc = (f_copy_with_alloc)gost34311_copy_with_alloc;
        break;

    case HASH_ALG_SHA1:
        CHECK_NOT_NULL(ctx->ctx = sha1_alloc());
        ctx->update = (f_update)sha1_update;
        ctx->final = (f_final)sha1_final;
        ctx->free = (f_free)sha1_free;
        ctx->get_block_size = (f_get_block_size)sha1_get_block_size;
        ctx->copy_with_alloc = (f_copy_with_alloc)sha1_copy_with_alloc;
        break;

    case HASH_ALG_SHA224:
        CHECK_NOT_NULL(ctx->ctx = sha2_alloc(SHA2_VARIANT_224));
        ctx->update = (f_update)sha2_update;
        ctx->final = (f_final)sha2_final;
        ctx->free = (f_free)sha2_free;
        ctx->get_block_size = (f_get_block_size)sha2_get_block_size;
        ctx->copy_with_alloc = (f_copy_with_alloc)sha2_copy_with_alloc;
        break;

    case HASH_ALG_SHA256:
        CHECK_NOT_NULL(ctx->ctx = sha2_alloc(SHA2_VARIANT_256));
        ctx->update = (f_update)sha2_update;
        ctx->final = (f_final)sha2_final;
        ctx->free = (f_free)sha2_free;
        ctx->get_block_size = (f_get_block_size)sha2_get_block_size;
        ctx->copy_with_alloc = (f_copy_with_alloc)sha2_copy_with_alloc;
        break;

    case HASH_ALG_SHA384:
        CHECK_NOT_NULL(ctx->ctx = sha2_alloc(SHA2_VARIANT_384));
        ctx->update = (f_update)sha2_update;
        ctx->final = (f_final)sha2_final;
        ctx->free = (f_free)sha2_free;
        ctx->get_block_size = (f_get_block_size)sha2_get_block_size;
        ctx->copy_with_alloc = (f_copy_with_alloc)sha2_copy_with_alloc;
        break;

    case HASH_ALG_SHA512:
        CHECK_NOT_NULL(ctx->ctx = sha2_alloc(SHA2_VARIANT_512));
        ctx->update = (f_update)sha2_update;
        ctx->final = (f_final)sha2_final;
        ctx->free = (f_free)sha2_free;
        ctx->get_block_size = (f_get_block_size)sha2_get_block_size;
        ctx->copy_with_alloc = (f_copy_with_alloc)sha2_copy_with_alloc;
        break;

    case HASH_ALG_SHA3_224:
        CHECK_NOT_NULL(ctx->ctx = sha3_alloc(SHA3_VARIANT_224));
        ctx->update = (f_update)sha3_update;
        ctx->final = (f_final)sha3_final;
        ctx->free = (f_free)sha3_free;
        ctx->get_block_size = (f_get_block_size)sha3_get_block_size;
        ctx->copy_with_alloc = (f_copy_with_alloc)sha3_copy_with_alloc;
        break;

    case HASH_ALG_SHA3_256:
        CHECK_NOT_NULL(ctx->ctx = sha3_alloc(SHA3_VARIANT_256));
        ctx->update = (f_update)sha3_update;
        ctx->final = (f_final)sha3_final;
        ctx->free = (f_free)sha3_free;
        ctx->get_block_size = (f_get_block_size)sha3_get_block_size;
        ctx->copy_with_alloc = (f_copy_with_alloc)sha3_copy_with_alloc;
        break;

    case HASH_ALG_SHA3_384:
        CHECK_NOT_NULL(ctx->ctx = sha3_alloc(SHA3_VARIANT_384));
        ctx->update = (f_update)sha3_update;
        ctx->final = (f_final)sha3_final;
        ctx->free = (f_free)sha3_free;
        ctx->get_block_size = (f_get_block_size)sha3_get_block_size;
        ctx->copy_with_alloc = (f_copy_with_alloc)sha3_copy_with_alloc;
        break;

    case HASH_ALG_SHA3_512:
        CHECK_NOT_NULL(ctx->ctx = sha3_alloc(SHA3_VARIANT_512));
        ctx->update = (f_update)sha3_update;
        ctx->final = (f_final)sha3_final;
        ctx->free = (f_free)sha3_free;
        ctx->get_block_size = (f_get_block_size)sha3_get_block_size;
        ctx->copy_with_alloc = (f_copy_with_alloc)sha3_copy_with_alloc;
        break;

    case HASH_ALG_WHIRLPOOL:
        CHECK_NOT_NULL(ctx->ctx = whirlpool_alloc());
        ctx->update = (f_update)whirlpool_update;
        ctx->final = (f_final)whirlpool_final;
        ctx->free = (f_free)whirlpool_free;
        ctx->get_block_size = (f_get_block_size)whirlpool_get_block_size;
        ctx->copy_with_alloc = (f_copy_with_alloc)whirlpool_copy_with_alloc;
        break;

    case HASH_ALG_SM3:
        CHECK_NOT_NULL(ctx->ctx = sm3_alloc());
        ctx->update = (f_update)sm3_update;
        ctx->final = (f_final)sm3_final;
        ctx->free = (f_free)sm3_free;
        ctx->get_block_size = (f_get_block_size)sm3_get_block_size;
        ctx->copy_with_alloc = (f_copy_with_alloc)sm3_copy_with_alloc;
        break;

    case HASH_ALG_GOSTR3411_2012_256:
        CHECK_NOT_NULL(ctx->ctx = gostr3411_alloc(GOSTR3411_2012_VARIANT_256));
        ctx->update = (f_update)gostr3411_update;
        ctx->final = (f_final)gostr3411_final;
        ctx->free = (f_free)gostr3411_free;
        ctx->get_block_size = (f_get_block_size)gostr3411_get_block_size;
        ctx->copy_with_alloc = (f_copy_with_alloc)gostr3411_copy_with_alloc;
        break;

    case HASH_ALG_GOSTR3411_2012_512:
        CHECK_NOT_NULL(ctx->ctx = gostr3411_alloc(GOSTR3411_2012_VARIANT_512));
        ctx->update = (f_update)gostr3411_update;
        ctx->final = (f_final)gostr3411_final;
        ctx->free = (f_free)gostr3411_free;
        ctx->get_block_size = (f_get_block_size)gostr3411_get_block_size;
        ctx->copy_with_alloc = (f_copy_with_alloc)gostr3411_copy_with_alloc;
        break;

    case HASH_ALG_RIPEMD128:
        CHECK_NOT_NULL(ctx->ctx = ripemd_alloc(RIPEMD_VARIANT_128));
        ctx->update = (f_update)ripemd_update;
        ctx->final = (f_final)ripemd_final;
        ctx->free = (f_free)ripemd_free;
        ctx->get_block_size = (f_get_block_size)ripemd_get_block_size;
        ctx->copy_with_alloc = (f_copy_with_alloc)ripemd_copy_with_alloc;
        break;

    case HASH_ALG_RIPEMD160:
        CHECK_NOT_NULL(ctx->ctx = ripemd_alloc(RIPEMD_VARIANT_160));
        ctx->update = (f_update)ripemd_update;
        ctx->final = (f_final)ripemd_final;
        ctx->free = (f_free)ripemd_free;
        ctx->get_block_size = (f_get_block_size)ripemd_get_block_size;
        ctx->copy_with_alloc = (f_copy_with_alloc)ripemd_copy_with_alloc;
        break;

    case HASH_ALG_MD5:
        CHECK_NOT_NULL(ctx->ctx = md5_alloc());
        ctx->update = (f_update)md5_update;
        ctx->final = (f_final)md5_final;
        ctx->free = (f_free)md5_free;
        ctx->get_block_size = (f_get_block_size)md5_get_block_size;
        ctx->copy_with_alloc = (f_copy_with_alloc)md5_copy_with_alloc;
        break;

    default:
        SET_ERROR(RET_UNSUPPORTED);
    }

cleanup:
    if (ret != RET_OK) {
        free(ctx);
        ctx = NULL;
    }

    return ctx;
}

HashCtx* hash_alloc_gost34311_with_sbox_id(Gost28147SboxId sbox_id)
{
    int ret = RET_OK;
    HashCtx* ctx = NULL;

    MALLOC_CHECKED(ctx, sizeof(HashCtx));
    ctx->alg = HASH_ALG_GOST34311;

    CHECK_NOT_NULL(ctx->ctx = gost34311_alloc(sbox_id, NULL));
    ctx->update = (f_update)gost34311_update;
    ctx->final = (f_final)gost34311_final;
    ctx->free = (f_free)gost34311_free;
    ctx->get_block_size = (f_get_block_size)gost34311_get_block_size;
    ctx->copy_with_alloc = (f_copy_with_alloc)gost34311_copy_with_alloc;

cleanup:
    if (ret != RET_OK) {
        free(ctx);
        ctx = NULL;
    }

    return ctx;
}

HashCtx* hash_alloc_gost34311_with_sbox(const ByteArray *sbox)
{
    int ret = RET_OK;
    HashCtx* ctx = NULL;

    MALLOC_CHECKED(ctx, sizeof(HashCtx));
    ctx->alg = HASH_ALG_GOST34311;

    CHECK_NOT_NULL(ctx->ctx = gost34311_alloc_user_sbox(sbox, NULL));
    ctx->update = (f_update)gost34311_update;
    ctx->final = (f_final)gost34311_final;
    ctx->free = (f_free)gost34311_free;
    ctx->get_block_size = (f_get_block_size)gost34311_get_block_size;
    ctx->copy_with_alloc = (f_copy_with_alloc)gost34311_copy_with_alloc;
    
cleanup:
    if (ret != RET_OK) {
        free(ctx);
        ctx = NULL;
    }

    return ctx;
}

int hash_update(HashCtx* ctx, const ByteArray* data)
{
    int ret = RET_OK;
    CHECK_PARAM(ctx != NULL);

    DO(ctx->update(ctx->ctx, data));

cleanup:
    return ret;
}

int hash_final(HashCtx* ctx, ByteArray** out)
{
    int ret = RET_OK;
    CHECK_PARAM(ctx != NULL);

    DO(ctx->final(ctx->ctx, out));

cleanup:
    return ret;
}

size_t hash_get_block_size(const HashCtx* ctx)
{
    if (ctx) {
        return ctx->get_block_size(ctx->ctx);
    }

    return 0;
}

void hash_free(HashCtx* ctx)
{
    if (ctx) {
        ctx->free(ctx->ctx);
        free(ctx);
    }
}

int hash(HashAlg alg, const ByteArray* data, ByteArray** out)
{
    int ret = RET_OK;
    HashCtx* ctx = NULL;

    CHECK_PARAM(data != NULL);
    CHECK_PARAM(out != NULL);

    CHECK_NOT_NULL(ctx = hash_alloc(alg));
    DO(ctx->update(ctx->ctx, data));
    DO(ctx->final(ctx->ctx, out));

cleanup:
    hash_free(ctx);
    return ret;
}

size_t hash_get_size(HashAlg alg)
{
    switch (alg)
    {
    case HASH_ALG_DSTU7564_256:
    case HASH_ALG_GOST34311:
    case HASH_ALG_SHA256:
    case HASH_ALG_SHA3_256:
    case HASH_ALG_SM3:
    case HASH_ALG_GOSTR3411_2012_256:
        return 32;

    case HASH_ALG_DSTU7564_384:
    case HASH_ALG_SHA384:
    case HASH_ALG_SHA3_384:
        return 48;

    case HASH_ALG_DSTU7564_512:
    case HASH_ALG_SHA512:
    case HASH_ALG_SHA3_512:
    case HASH_ALG_WHIRLPOOL:
    case HASH_ALG_GOSTR3411_2012_512:
        return 64;

    case HASH_ALG_SHA1:
    case HASH_ALG_RIPEMD160:
        return 20;

    case HASH_ALG_SHA224:
    case HASH_ALG_SHA3_224:
        return 28;

    case HASH_ALG_RIPEMD128:
    case HASH_ALG_MD5:
        return 16;

    default:
        return 0;
    }
}