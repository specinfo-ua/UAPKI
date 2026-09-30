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

#ifndef UAPKIC_DRBG_H
#define UAPKIC_DRBG_H

#include "byte-array.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Контекст ГПВП HMAC_DRBG (SHA-512). Кожен контекст має власний стан і м'ютекс,
 * функції *_ex потокобезпечні для одного контексту.
 */
typedef struct DrbgCtx_st DrbgCtx;

/**
 * Створює контекст ГПВП. Стан ініціалізується ентропією з джерел ОС та jitterentropy
 * у drbg_init_ex() або при першому виклику drbg_random_ex().
 *
 * @return контекст ГПВП або NULL
 */
UAPKIC_EXPORT DrbgCtx* drbg_alloc(void);

/**
 * Ініціалізує (або переініціалізує) стан ГПВП ентропією з джерел ОС та jitterentropy.
 *
 * @param ctx контекст ГПВП
 * @return код помилки
 */
UAPKIC_EXPORT int drbg_init_ex(DrbgCtx* ctx);

/**
 * Генерує випадкові дані, розмір визначається довжиною random (не більше 512 КіБ).
 *
 * @param ctx контекст ГПВП
 * @param random буфер для випадкових даних
 * @return код помилки
 */
UAPKIC_EXPORT int drbg_random_ex(DrbgCtx* ctx, ByteArray* random);

/**
 * Оновлює стан ГПВП новою ентропією та додатковими даними.
 *
 * @param ctx контекст ГПВП
 * @param entropy додаткові дані, може бути NULL
 * @return код помилки
 */
UAPKIC_EXPORT int drbg_reseed_ex(DrbgCtx* ctx, const ByteArray* entropy);

/**
 * Затирає стан і звільняє контекст ГПВП.
 *
 * @param ctx контекст ГПВП
 */
UAPKIC_EXPORT void drbg_free(DrbgCtx* ctx);

/**
 * Функції для глобального контексту ГПВП бібліотеки.
 */
UAPKIC_EXPORT int drbg_random(ByteArray* random);
UAPKIC_EXPORT int drbg_reseed(const ByteArray* entropy);

UAPKIC_EXPORT int drbg_self_test(void);

#ifdef __cplusplus
}
#endif

#endif
