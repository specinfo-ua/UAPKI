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

#ifndef UAPKIC_SM2DSADSA_H
#define UAPKIC_SM2DSADSA_H

#include "byte-array.h"
#include "ec.h"
#include "hash.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Генерує закритий ключ SM2DSA.
 *
 * @param ctx контекст SM2DSA
 * @param d закритий ключ SM2DSA
 * @return код помилки
 */
UAPKIC_EXPORT int sm2dsa_generate_privkey(const EcCtx *ctx, ByteArray **d);

/**
 * Формує відкритий ключ по закритому.
 *
 * @param ctx контекст SM2DSA
 * @param d закритий ключ
 * @param qx Х-координата відкритого ключа
 * @param qy Y-координата відкритого ключа
 * @return код помилки
 */
UAPKIC_EXPORT int sm2dsa_get_pubkey(const EcCtx *ctx, const ByteArray *d, ByteArray **qx, ByteArray **qy);

/**
 * Формує підпис по гешу.
 *
 * @param ctx контекст SM2DSA
 * @param H геш
 * @param r частина підпису
 * @param s частина підпису
 * @return код помилки
 */
UAPKIC_EXPORT int sm2dsa_sign(const EcCtx *ctx, const ByteArray *H, ByteArray **r, ByteArray **s);

/**
 * Виконує перевірку підпису по гешу від даних.
 *
 * @param ctx контекст SM2DSA
 * @param H геш
 * @param r частина підпису
 * @param s частина підпису
 * @return код помилки або RET_OK, якщо підпис вірний
 */
UAPKIC_EXPORT int sm2dsa_verify(const EcCtx* ctx, const ByteArray* H, const ByteArray* r, const ByteArray* s);

/**
 * Створює контекст для визначеного алгоритму гешування та гешує відкритий ключ відповідно до вимог SM2DSA.
 *
 * @param alg алгоритм гешування
 * @param qx Х-координата відкритого ключа
 * @param qy Y-координата відкритого ключа
 * @return контекст гешування
 */
UAPKIC_EXPORT HashCtx* sm2dsa_hash_alloc(const EcCtx* ctx, HashAlg hash_alg, const ByteArray* id, const ByteArray* qx, const ByteArray* qy);

/**
 * Виконує самотестування алгоритму SM2DSA.
 * @return код помилки або RET_OK, якщо срмотестування пройдено
 */
UAPKIC_EXPORT int sm2dsa_self_test(void);

#ifdef  __cplusplus
}
#endif

#endif
