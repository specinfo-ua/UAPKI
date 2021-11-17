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

#ifndef UAPKIC_GOST34311_H
#define UAPKIC_GOST34311_H

#include "byte-array.h"
#include "gost28147.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Контекст ГОСТ 34.311
 */
typedef struct Gost34311Ctx_st Gost34311Ctx;

/**
 * Створює контекст ГОСТ 34.311 зі стандартним sbox.
 *
 * @param sbox_id ідентифікатор стандартной таблиці замін
 * @param sync синхропосилка (опціональний, якщо NULL синхропосилка 0)
 * @return контекст ГОСТ 34.311
 */
UAPKIC_EXPORT Gost34311Ctx *gost34311_alloc(Gost28147SboxId sbox_id, const ByteArray *sync);

/**
 * Створює контекст ГОСТ 34.311 з користувацьким sbox.
 *
 * @param sbox користувацький sbox
 * @param sync синхропосилка
 * @return контекст ГОСТ 34.311
 */
UAPKIC_EXPORT Gost34311Ctx *gost34311_alloc_user_sbox(const ByteArray *sbox, const ByteArray *sync);

UAPKIC_EXPORT Gost34311Ctx *gost34311_copy_with_alloc(const Gost34311Ctx *ctx);

/**
 * Модифікує геш-вектор фрагментом даних.
 *
 * @param ctx контекст ГОСТ 34.311
 * @param data дані для шифрування
 * @return код помилки
 */
UAPKIC_EXPORT int gost34311_update(Gost34311Ctx *ctx, const ByteArray *data);

/**
 * Завершує вироботку геша і повертає його значення.
 *
 * @param ctx контекст ГОСТ 34.311
 * @param H геш вектор
 * @return код помилки
 */
UAPKIC_EXPORT int gost34311_final(Gost34311Ctx *ctx, ByteArray **H);

/**
 * Звільняє контекст ГОСТ 34.311.
 *
 * @param ctx контекст ГОСТ 34.311
 */
UAPKIC_EXPORT void gost34311_free(Gost34311Ctx *ctx);

/**
 * Повертає розмір блоку геш-функції.
 *
 * @param ctx контекст ГОСТ 34.311
 * @return розмір блоку, 0 у разі помилки
 */
UAPKIC_EXPORT size_t gost34311_get_block_size(const Gost34311Ctx* ctx);

/**
 * Виконує самотестування реалізації алгоритму ГОСТ 34.311.
 * @return код помилки або RET_OK, якщо самотестування пройдено
 */
UAPKIC_EXPORT int gost34311_self_test(void);

#ifdef  __cplusplus
}
#endif

#endif
