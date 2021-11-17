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

#ifndef UAPKIC_GOSTR3411_2012_H
#define UAPKIC_GOSTR3411_2012_H

#include "byte-array.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Контекст GOSTR3411_2012.
 */
typedef struct GostR3411Ctx_st GostR3411Ctx;

typedef enum {
    GOSTR3411_2012_VARIANT_256 = 0,
    GOSTR3411_2012_VARIANT_512 = 1
} GostR3411Variant;

/**
 * Створює контекст GOSTR3411_2012.
 *
 * @return контекст GOSTR3411_2012
 */
UAPKIC_EXPORT GostR3411Ctx *gostr3411_alloc(GostR3411Variant variant);

UAPKIC_EXPORT GostR3411Ctx *gostr3411_copy_with_alloc(const GostR3411Ctx *ctx);

/**
 * Модифікує геш-вектор фрагментом даних.
 *
 * @param ctx контекст GOSTR3411_2012
 * @param data дані
 * @return код помилки
 */
UAPKIC_EXPORT int gostr3411_update(GostR3411Ctx *ctx, const ByteArray *data);

/**
 * Завершує обчислення геш-вектора і повертає його значення.
 *
 * @param ctx контекст GOSTR3411_2012
 * @param out геш від даних
 * @return код помилки
 */
UAPKIC_EXPORT int gostr3411_final(GostR3411Ctx *ctx, ByteArray **out);

/**
 * Повертає розмір блоку геш-функції.
 *
 * @param ctx контекст GOSTR3411_2012
 * @return розмір блоку, 0 у разі помилки
 */
UAPKIC_EXPORT size_t gostr3411_get_block_size(const GostR3411Ctx* ctx);

/**
 * Звільняє контекст GOSTR3411_2012.
 *
 * @param ctx контекст GOSTR3411_2012
 */
UAPKIC_EXPORT void gostr3411_free(GostR3411Ctx *ctx);

/**
 * Виконує самотестування реалізації ГОСТ Р 34.11-2012.
 *
 * @return код помилки
 */
UAPKIC_EXPORT int gostr3411_self_test(void);

#ifdef __cplusplus
}
#endif

#endif

