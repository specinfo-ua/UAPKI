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

#ifndef UAPKIC_DSTU7564_H
#define UAPKIC_DSTU7564_H

#include "byte-array.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct Dstu7564Ctx_st Dstu7564Ctx;

/**
 * Створює контекст ДСТУ 7564
 *
 * @return контекст ДСТУ 7564
 */
UAPKIC_EXPORT Dstu7564Ctx *dstu7564_alloc(void);

Dstu7564Ctx* dstu7564_copy_with_alloc(const Dstu7564Ctx* ctx);

/**
 * Ініціалізація контексту DSTU7564.
 *
 * @param ctx контекст ДСТУ 7564
 * @param hash_len байтовий розмір геша, значення у межі 1..64 байт
 * @return код помилки
 */
UAPKIC_EXPORT int dstu7564_init(Dstu7564Ctx *ctx, size_t hash_len);

/**
 * Модифікує геш-вектор фрагментом даних.
 *
 * @param ctx контекст ДСТУ 7564
 * @param data дані
 * @return код помилки
 */
UAPKIC_EXPORT int dstu7564_update(Dstu7564Ctx *ctx, const ByteArray *data);

/**
 * Завершує вироботку геша і повертає його значення.
 *
 * @param ctx контекст ДСТУ 7564
 * @param H геш від даних
 * @return код помилки
 */
UAPKIC_EXPORT int dstu7564_final(Dstu7564Ctx *ctx, ByteArray **H);

/**
 * Повертає розмір блоку геш-функції.
 *
 * @param ctx контекст ДСТУ 7564
 * @return розмір блоку, 0 у разі помилки
 */
UAPKIC_EXPORT size_t dstu7564_get_block_size(const Dstu7564Ctx* ctx);

/**
 * Ініціалізує контекст ДСТУ 7564 для створення кода аутентификації.
 *
 * @param ctx контекст ДСТУ 7564
 * @param key ключ аутентификации для режиму kmac
 * @param mac_len розмір імітовставки (байт), значення 32, 48, 64
 * @return код помилки
 */
UAPKIC_EXPORT int dstu7564_init_kmac(Dstu7564Ctx *ctx, const ByteArray *key, size_t mac_len);

/**
 * Модифікує геш-вектор фрагментом даних.
 *
 * @param ctx контекст ДСТУ 7564
 * @param data дані
 * @return код помилки
 */
UAPKIC_EXPORT int dstu7564_update_kmac(Dstu7564Ctx *ctx, const ByteArray *data);

/**
 * Завершує вироботку геша і повертає його значення.
 *
 * @param ctx контекст ДСТУ 7564
 * @param mac код аутентификации
 * @return код помилки
 */
UAPKIC_EXPORT int dstu7564_final_kmac(Dstu7564Ctx *ctx, ByteArray **mac);

/**
 * Звільняє контекст ДСТУ 7564.
 *
 * @param ctx контекст ДСТУ 7564
 */
UAPKIC_EXPORT void dstu7564_free(Dstu7564Ctx *ctx);

/**
 * Виконує самотестування реалізації алгоритму ДСТУ 7564.
 * @return код помилки або RET_OK, якщо самотестування пройдено
 */
UAPKIC_EXPORT int dstu7564_self_test(void);

#ifdef  __cplusplus
}
#endif

#endif
