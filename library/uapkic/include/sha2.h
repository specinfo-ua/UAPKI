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

#ifndef UAPKIC_SHA2_H
#define UAPKIC_SHA2_H

#include "byte-array.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Контекст SHA2.
 */
typedef struct Sha2Ctx_st Sha2Ctx;

typedef enum {
    SHA2_VARIANT_224 = 0,
    SHA2_VARIANT_256 = 1,
    SHA2_VARIANT_384 = 2,
    SHA2_VARIANT_512 = 3
} Sha2Variant;

/**
 * Створює контекст SHA2.
 *
 * @return контекст SHA2
 */
UAPKIC_EXPORT Sha2Ctx *sha2_alloc(Sha2Variant variant);

UAPKIC_EXPORT Sha2Ctx *sha2_copy_with_alloc(const Sha2Ctx *ctx);

/**
 * Модифікує геш-вектор фрагментом даних.
 *
 * @param ctx контекст SHA2
 * @param data дані
 * @return код помилки
 */
UAPKIC_EXPORT int sha2_update(Sha2Ctx *ctx, const ByteArray *data);

/**
 * Завершує обчислення геш-вектора і повертає його значення.
 *
 * @param ctx контекст SHA2
 * @param out геш від даних
 * @return код помилки
 */
UAPKIC_EXPORT int sha2_final(Sha2Ctx *ctx, ByteArray **out);

/**
 * Повертає розмір блоку геш-функції.
 *
 * @param ctx контекст SHA2
 * @return розмір блоку, 0 у разі помилки
 */
UAPKIC_EXPORT size_t sha2_get_block_size(const Sha2Ctx* ctx);

/**
 * Звільняє контекст SHA2.
 *
 * @param ctx контекст SHA2
 */
UAPKIC_EXPORT void sha2_free(Sha2Ctx *ctx);

/**
 * Виконує самотестування реалізації алгоритму SHA2.
 *
 * @return код помилки або RET_OK, якщо самотестування пройдено
 */
UAPKIC_EXPORT int sha2_self_test(void);

#ifdef __cplusplus
}
#endif

#endif

