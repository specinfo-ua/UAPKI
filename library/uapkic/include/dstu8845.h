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

#ifndef UAPKIC_DSTU8845_H
#define UAPKIC_DSTU8845_H

#include "byte-array.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Контекст ДСТУ 8845.
 */
typedef struct Dstu8845Ctx_st Dstu8845Ctx;

/**
 * Створює контекст потокового шифру ДСТУ 8845:2019 «Струмок».
 *
 * @return контекст ДСТУ 8845
 */
UAPKIC_EXPORT Dstu8845Ctx *dstu8845_alloc(void);

/**
 * Ініціалізує контекст ДСТУ 8845.
 *
 * @param ctx контекст ДСТУ 8845
 * @param key ключ шифрування; його розмір повинен становити 32 або 64 байти
 * @param iv вектор ініціалізації; його розмір повинен становити 32 байти
 *
 * @return код помилки
 */
UAPKIC_EXPORT int dstu8845_init(Dstu8845Ctx *ctx, const ByteArray* key, const ByteArray* iv);

/**
 * Задає в контексті ДСТУ 8845 вектор ініціалізації.
 *
 * @param ctx контекст ДСТУ 8845
 * @param iv вектор ініціалізації; його розмір повинен становити 32 байти
 *
 * @return код помилки
 */
UAPKIC_EXPORT int dstu8845_set_iv(Dstu8845Ctx *ctx, const ByteArray* iv);

/**
 * Здійснює шифрування або розшифрування даних.
 *
 * @param ctx контекст ДСТУ 8845
 * @param inout дані для шифрування або розшифрування
 *
 * @return код помилки
 */
UAPKIC_EXPORT int dstu8845_crypt(Dstu8845Ctx *ctx, ByteArray* inout);

/**
 * Звільняє контекст ДСТУ 8845.
 *
 * @param ctx контекст ДСТУ 8845
 */
UAPKIC_EXPORT void dstu8845_free(Dstu8845Ctx *ctx);

/**
 * Генерує ключ шифрування.
 *
 * @param key_len розмір ключа; повинен становити 32 або 64 байти
 * @param key ключ шифрування
 * @return код помилки
 */
UAPKIC_EXPORT int dstu8845_generate_key(size_t key_len, ByteArray** key);

/**
 * Виконує самотестування реалізації алгоритму ДСТУ 8845.
 *
 * @return код помилки
 */
UAPKIC_EXPORT int dstu8845_self_test(void);

#ifdef  __cplusplus
}
#endif

#endif
