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

#ifndef UAPKIC_HASH_H
#define UAPKIC_HASH_H

#include "byte-array.h"
#include "gost28147.h"

#define MAX_HASH_SIZE 64

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Контекст алгоритму гешування.
 */
typedef struct HashCtx_st HashCtx;

/**
 * Алгоритми гешування.
 */
typedef enum {
    HASH_ALG_UNDEFINED = 0,
    HASH_ALG_DSTU7564_256,
    HASH_ALG_DSTU7564_384,
    HASH_ALG_DSTU7564_512,
    HASH_ALG_GOST34311,
    HASH_ALG_SHA1,
    HASH_ALG_SHA224,
    HASH_ALG_SHA256,
    HASH_ALG_SHA384,
    HASH_ALG_SHA512,
    HASH_ALG_SHA3_224,
    HASH_ALG_SHA3_256,
    HASH_ALG_SHA3_384,
    HASH_ALG_SHA3_512,
    HASH_ALG_WHIRLPOOL,
    HASH_ALG_SM3,
    HASH_ALG_GOSTR3411_2012_256,
    HASH_ALG_GOSTR3411_2012_512,
    HASH_ALG_RIPEMD128,
    HASH_ALG_RIPEMD160,
    HASH_ALG_MD5
} HashAlg;

/**
 * Створює контекст для визначеного алгоритму гешування (у разі ГОСТ 34.311 з 
 * ДКЕ №1 із доповнення 1 до інструкції №114).
 *
 * @param alg алгоритм гешування
 * @return контекст гешування
 */
UAPKIC_EXPORT HashCtx *hash_alloc(HashAlg alg);

/**
 * Створює контекст для алгоритму гешування ГОСТ 34.311 зі стандартним ДКЕ.
 *
 * @param sbox_id ідентифікатор стандартної ДКЕ для ГОСТ 34.311
 * @return контекст гешування
 */
UAPKIC_EXPORT HashCtx* hash_alloc_gost34311_with_sbox_id(Gost28147SboxId sbox_id);

/**
 * Створює контекст для алгоритму гешування ГОСТ 34.311 з ДКЕ заданим користувачем.
 *
 * @param sbox ДКЕ для ГОСТ 34.311
 * @return контекст гешування
 */
UAPKIC_EXPORT HashCtx* hash_alloc_gost34311_with_sbox(const ByteArray* sbox);

/**
 * Модифікує геш-вектор фрагментом даних.
 *
 * @param ctx контекст гешування
 * @param data дані
 * @return код помилки
 */
UAPKIC_EXPORT int hash_update(HashCtx *ctx, const ByteArray *data);

/**
 * Завершує вироблення гешу й повертає його значення.
 *
 * @param ctx контекст гешування
 * @param out геш від даних
 * @return код помилки
 */
UAPKIC_EXPORT int hash_final(HashCtx *ctx, ByteArray **out);

/**
 * Повертає розмір блоку геш-функції.
 *
 * @param ctx контекст гешування
 * @return розмір блоку, 0 у разі помилки
 */
UAPKIC_EXPORT size_t hash_get_block_size(const HashCtx* ctx);

/**
 * Звільняє контекст гешування.
 *
 * @param ctx контекст гешування
 */
UAPKIC_EXPORT void hash_free(HashCtx *ctx);

/**
 * Обчислює геш-функцію за заданим алгоритмом без ітеративного продовження.
 *
 * @param alg алгоритм гешування
 * @param data дані
 * @param out геш від даних
 * @return код помилки
 */
UAPKIC_EXPORT int hash(HashAlg alg, const ByteArray *data, ByteArray **out);

/**
 * Повертає розмір у байтах геш-значення за заданим алгоритмом.
 *
 * @param alg алгоритм гешування
 * @return розмір у байтах геш-значення, 0 у разі непідтримуваного алгоритму
 */
UAPKIC_EXPORT size_t hash_get_size(HashAlg alg);

#ifdef  __cplusplus
}
#endif

#endif
