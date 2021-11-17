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

#ifndef UAPKIC_HMAC_H
#define UAPKIC_HMAC_H

#include "byte-array.h"
#include "hash.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Контекст HMAC
 */
typedef struct HmacCtx_st HmacCtx;

/**
 * Створює контекст HMAC на базі вказаного алгоритму гешування (у разі ГОСТ 34.311 з 
 * ДКЕ №1 із доповнення 1 до інструкції №114).
 *
 * @param alg алгоритм гешування
 * @return контекст HMAC
 */
UAPKIC_EXPORT HmacCtx *hmac_alloc(HashAlg alg);

/**
 * Створює контекст HMAC на базі ГОСТ 34.311 зі стандартним ДКЕ.
 *
 * @param sbox_id ідентифікатор стандартної ДКЕ для ГОСТ 34.311
 * @return контекст HMAC
 */
UAPKIC_EXPORT HmacCtx* hmac_alloc_gost34311_with_sbox_id(Gost28147SboxId sbox_id);

/**
 * Створює контекст HMAC на базі ГОСТ 34.311 з ДКЕ заданим користувачем.
 *
 * @param sbox ДКЕ для ГОСТ 34.311
 * @return контекст HMAC
 */
UAPKIC_EXPORT HmacCtx* hmac_alloc_gost34311_with_sbox(const ByteArray* sbox);

/**
 * Ініціалізує контекст для виробки HMAC ключем.
 *
 * @param ctx контекст
 * @param key секретний ключ
 * @return код помилки
 */
UAPKIC_EXPORT int hmac_init(HmacCtx *ctx, const ByteArray *key);

/**
 * Модифікує HMAC фрагментом даних.
 *
 * @param ctx контекст HMAC
 * @param data дані для шифрування
 * @return код помилки
 */
UAPKIC_EXPORT int hmac_update(HmacCtx *ctx, const ByteArray *data);

/**
 * Завершує виробку HMAC і повертає його значення.
 *
 * @param ctx контекст HMAC
 * @param H геш вектор
 * @return код помилки
 */
UAPKIC_EXPORT int hmac_final(HmacCtx *ctx, ByteArray **H);

/**
 * Ініціалізує контекст для виробки HMAC з попередньо встановленим ключем.
 *
 * @param ctx контекст HMAC
 * @return код помилки
 */
UAPKIC_EXPORT int hmac_reset(HmacCtx* ctx);

/**
 * Звільняє контекст HMAC.
 *
 * @param ctx контекст HMAC
 */
UAPKIC_EXPORT void hmac_free(HmacCtx *ctx);

/**
 * Виконує самотестування реалізації HMAC.
 *
 * @return код помилки або RET_OK, якщо самотестування пройдено
 */
UAPKIC_EXPORT int hmac_self_test(void);

#ifdef  __cplusplus
}
#endif

#endif
