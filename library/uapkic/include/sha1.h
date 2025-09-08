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

#ifndef UAPKIC_SHA1_H
#define UAPKIC_SHA1_H

#include "byte-array.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Контекст SHA1.
 */
typedef struct Sha1Ctx_st Sha1Ctx;

/**
 * Створює контекст SHA1.
 *
 * @return контекст SHA1
 */
UAPKIC_EXPORT Sha1Ctx *sha1_alloc(void);

UAPKIC_EXPORT Sha1Ctx *sha1_copy_with_alloc(const Sha1Ctx *ctx);

/**
 * Модифікує геш-вектор фрагментом даних.
 *
 * @param ctx контекст SHA1
 * @param data дані
 * @return код помилки
 */
UAPKIC_EXPORT int sha1_update(Sha1Ctx *ctx, const ByteArray *data);

/**
 * Завершує вироблення гешу й повертає його значення.
 *
 * @param ctx контекст SHA1
 * @param out геш від даних
 * @return код помилки
 */
UAPKIC_EXPORT int sha1_final(Sha1Ctx *ctx, ByteArray **out);

/**
 * Повертає розмір блоку геш-функції.
 *
 * @param ctx контекст SHA1
 * @return розмір блоку, 0 у разі помилки
 */
UAPKIC_EXPORT size_t sha1_get_block_size(const Sha1Ctx* ctx);

/**
 * Звільняє контекст SHA1.
 *
 * @param ctx контекст SHA1
 */
UAPKIC_EXPORT void sha1_free(Sha1Ctx *ctx);

/**
 * Виконує самотестування реалізації SHA1.
 *
 * @return код помилки або RET_OK, якщо самотестування пройдено
 */
UAPKIC_EXPORT int sha1_self_test(void);

#ifdef  __cplusplus
}
#endif

#endif
