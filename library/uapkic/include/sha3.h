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

#ifndef UAPKIC_SHA3_H
#define UAPKIC_SHA3_H

#include "byte-array.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Контекст SHA3.
 */
typedef struct Sha3Ctx_st Sha3Ctx;

typedef enum {
    SHA3_VARIANT_224 = 0,
    SHA3_VARIANT_256 = 1,
    SHA3_VARIANT_384 = 2,
    SHA3_VARIANT_512 = 3,
    SHA3_VARIANT_SHAKE128 = 4,
    SHA3_VARIANT_SHAKE256 = 5
} Sha3Variant;

/**
 * Створює контекст SHA3.
 *
 * @return контекст SHA3
 */
UAPKIC_EXPORT Sha3Ctx *sha3_alloc(Sha3Variant variant);

UAPKIC_EXPORT Sha3Ctx *sha3_copy_with_alloc(const Sha3Ctx *ctx);

/**
 * Модифікує геш-вектор фрагментом даних.
 *
 * @param ctx контекст SHA3
 * @param data дані
 * @return код помилки
 */
UAPKIC_EXPORT int sha3_update(Sha3Ctx* ctx, const ByteArray* data);

/**
 * Завершує обчислення геш-вектора і повертає його значення.
 *
 * @param ctx контекст SHA3
 * @param out геш від даних
 * @return код помилки
 */
UAPKIC_EXPORT int sha3_final(Sha3Ctx *ctx, ByteArray **out);

/**
 * Завершує обчислення функції з подовжуваним результатом (XOF).
 * Може викликатися декілька разів.
 *
 * @param ctx контекст SHA3
 * @param out вихід функції
 * @return код помилки
 */
UAPKIC_EXPORT int sha3_shake_final(Sha3Ctx* ctx, ByteArray* out);

/**
 * Повертає розмір блоку геш-функції.
 *
 * @param ctx контекст SHA3
 * @return розмір блоку, 0 у разі помилки
 */
UAPKIC_EXPORT size_t sha3_get_block_size(const Sha3Ctx* ctx);

/**
 * Звільняє контекст SHA3.
 *
 * @param ctx контекст SHA3
 */
UAPKIC_EXPORT void sha3_free(Sha3Ctx *ctx);

/**
 * Виконує самотестування реалізації алгоритму SHA3.
 * @return код помилки або RET_OK, якщо самотестування пройдено
 */
UAPKIC_EXPORT int sha3_self_test(void);

#ifdef __cplusplus
}
#endif

#endif

