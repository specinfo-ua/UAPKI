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

#ifndef UAPKIC_RIPEMD_H
#define UAPKIC_RIPEMD_H

#include "byte-array.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    RIPEMD_VARIANT_128,
    RIPEMD_VARIANT_160
} RipemdVariant;

/**
 * Контекст RIPEMD.
 */
typedef struct RipemdCtx_st RipemdCtx;

/**
 * Выделение памяти для режиму RIPEMD128.
 *
 * @return повертає указатель на выделенную память.
 */
UAPKIC_EXPORT RipemdCtx *ripemd_alloc(RipemdVariant mode);

UAPKIC_EXPORT RipemdCtx* ripemd_copy_with_alloc(const RipemdCtx* ctx);

/**
 * Удаление даних з контексту RIPEMD.
 *
 * @param ctx контекст RIPEMD.
 */
UAPKIC_EXPORT void ripemd_free(RipemdCtx *ctx);

/**
 * Добавление даних для геширования.
 *
 * @param ctx контекст RIPEMD.
 * @param data дані, які нужно загешировать.
 * @return  - 1 у случае успеха і код помилки у обратном.
 */
UAPKIC_EXPORT int ripemd_update(RipemdCtx *ctx, const ByteArray *data);

/**
 * Получение гешавідданих.
 *
 * @param ctx контекст RIPEMD.
 * @param hash_code геш даних.
 * @return код помилки
 */
UAPKIC_EXPORT int ripemd_final(RipemdCtx *ctx, ByteArray **hash_code);

/**
 * Повертає розмір блоку геш-функції.
 *
 * @param ctx контекст RIPEMD
 * @return розмір блоку, 0 у разі помилки
 */
UAPKIC_EXPORT size_t ripemd_get_block_size(const RipemdCtx* ctx);

/**
 * Виконує самотестування реалізації алгоритму RIPEMD.
 * @return код помилки або RET_OK, якщо самотестування пройдено
 */
UAPKIC_EXPORT int ripemd_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* UAPKIC_RIPEMD_H */

