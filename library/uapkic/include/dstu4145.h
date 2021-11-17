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

#ifndef UAPKIC_DSTU4145_H
#define UAPKIC_DSTU4145_H

#include "byte-array.h"
#include "ec.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Генерує закритий ключ ДСТУ 4145.
 *
 * @param ctx контекст ДСТУ 4145
 * @param d закритий ключ ДСТУ 4145
 * @return код помилки
 */
UAPKIC_EXPORT int dstu4145_generate_privkey(const EcCtx *ctx, ByteArray **d);

/**
 * Формує відкритий ключ за закритим.
 *
 * @param ctx контекст ДСТУ 4145
 * @param d закритий ключ
 * @param qx Х-координата відкритого ключа
 * @param qy Y-координата відкритого ключа
 * @return код помилки
 */
UAPKIC_EXPORT int dstu4145_get_pubkey(const EcCtx *ctx, const ByteArray *d, ByteArray **qx, ByteArray **qy);

/**
 * Формує стисле представлення відкритого ключа.
 *
 * @param ctx контекст ДСТУ 4145
 * @param qx Х-координата відкритого ключа
 * @param qy Y-координата відкритого ключа
 * @param q стисле представлення відкритого ключа
 * @return код помилки
 */
UAPKIC_EXPORT int dstu4145_compress_pubkey(const EcCtx *ctx, const ByteArray *qx, const ByteArray *qy,
        ByteArray **q);

/**
 * Формує розгорнуте представлення відкритого ключа.
 *
 * @param ctx контекст ДСТУ 4145
 * @param q стисле представлення відкритого ключа
 * @param qx Х-координата відкритого ключа
 * @param qy Y-координата відкритого ключа
 * @return код помилки
 */
UAPKIC_EXPORT int dstu4145_decompress_pubkey(const EcCtx *ctx, const ByteArray *q, ByteArray **qx,
        ByteArray **qy);

/**
 * Формує підпис по гешу.
 *
 * @param ctx контекст ДСТУ 4145
 * @param H геш
 * @param r частина підпису
 * @param s частину підпису
 * @return код помилки
 */
UAPKIC_EXPORT int dstu4145_sign(const EcCtx *ctx, const ByteArray *H, ByteArray **r, ByteArray **s);

/**
 * Виконує перевірку підпису з гешу від даних.
 *
 * @param ctx контекст ДСТУ 4145
 * @param H геш
 * @param r частина підпису
 * @param s частина підпису
 * @return код помилки або RET_OK, якщо підпис вірний
 */
UAPKIC_EXPORT int dstu4145_verify(const EcCtx *ctx, const ByteArray *H, const ByteArray *r,
        const ByteArray *s);

/**
 * Виконує самотестування ДСТУ 4145.
 * @return код помилки або RET_OK, якщо срмотестування пройдено
 */
UAPKIC_EXPORT int dstu4145_self_test(void);

#ifdef  __cplusplus
}
#endif

#endif
