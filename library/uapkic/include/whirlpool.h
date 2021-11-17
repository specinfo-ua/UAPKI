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

#ifndef UAPKIC_WHIRLPOOL_H
#define UAPKIC_WHIRLPOOL_H

#include "byte-array.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Контекст WHIRLPOOL.
 */
typedef struct WhirlpoolCtx_st WhirlpoolCtx;

/**
 * Створює контекст WHIRLPOOL.
 *
 * @return контекст WHIRLPOOL
 */
UAPKIC_EXPORT WhirlpoolCtx *whirlpool_alloc(void);

UAPKIC_EXPORT WhirlpoolCtx *whirlpool_copy_with_alloc(const WhirlpoolCtx *ctx);

/**
 * Модифікує геш-вектор фрагментом даних.
 *
 * @param ctx контекст WHIRLPOOL
 * @param data дані
 * @return код помилки
 */
UAPKIC_EXPORT int whirlpool_update(WhirlpoolCtx* ctx, const ByteArray* data);

/**
 * Завершує обчислення геш-вектора і повертає його значення.
 *
 * @param ctx контекст WHIRLPOOL
 * @param out геш від даних
 * @return код помилки
 */
UAPKIC_EXPORT int whirlpool_final(WhirlpoolCtx *ctx, ByteArray **out);

/**
 * Повертає розмір блоку геш-функції.
 *
 * @param ctx контекст WHIRLPOOL
 * @return розмір блоку, 0 у разі помилки
 */
UAPKIC_EXPORT size_t whirlpool_get_block_size(const WhirlpoolCtx* ctx);

/**
 * Звільняє контекст WHIRLPOOL.
 *
 * @param ctx контекст WHIRLPOOL
 */
UAPKIC_EXPORT void whirlpool_free(WhirlpoolCtx *ctx);

/**
 * Виконує самотестування реалізації алгоритму WHIRLPOOL.
 * @return код помилки або RET_OK, якщо самотестування пройдено
 */
UAPKIC_EXPORT int whirlpool_self_test(void);

#ifdef __cplusplus
}
#endif

#endif

