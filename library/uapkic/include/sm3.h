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

#ifndef UAPKIC_SM3_H
#define UAPKIC_SM3_H

#include "byte-array.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Контекст SM3.
 */
typedef struct Sm3Ctx_st Sm3Ctx;

/**
 * Створює контекст SM3.
 *
 * @return контекст SM3
 */
UAPKIC_EXPORT Sm3Ctx *sm3_alloc(void);

UAPKIC_EXPORT Sm3Ctx *sm3_copy_with_alloc(const Sm3Ctx *ctx);

/**
 * Модифікує геш-вектор фрагментом даних.
 *
 * @param ctx контекст SM3
 * @param data дані
 * @return код помилки
 */
UAPKIC_EXPORT int sm3_update(Sm3Ctx* ctx, const ByteArray* data);

/**
 * Завершує обчислення геш-вектора і повертає його значення.
 *
 * @param ctx контекст SM3
 * @param out геш від даних
 * @return код помилки
 */
UAPKIC_EXPORT int sm3_final(Sm3Ctx *ctx, ByteArray **out);

/**
 * Повертає розмір блоку геш-функції.
 *
 * @param ctx контекст SM3
 * @return розмір блоку, 0 у разі помилки
 */
UAPKIC_EXPORT size_t sm3_get_block_size(const Sm3Ctx* ctx);

/**
 * Звільняє контекст SM3.
 *
 * @param ctx контекст SM3
 */
UAPKIC_EXPORT void sm3_free(Sm3Ctx *ctx);

/**
 * Виконує самотестування реалізації алгоритму SM3.
 * @return код помилки або RET_OK, якщо самотестування пройдено
 */
UAPKIC_EXPORT int sm3_self_test(void);

#ifdef __cplusplus
}
#endif

#endif

