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

#ifndef UAPKIC_DES_H
#define UAPKIC_DES_H

#include "byte-array.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Контекст DES.
 */
typedef struct DesCtx_st DesCtx;

/**
 * Створює контекст DES.
 *
 * @return контекст DES
 */
UAPKIC_EXPORT DesCtx *des_alloc(void);

/**
 * Генерує секретний ключ.
 *
 * @param key_len размер ключа 8, 16 или 24
 * @param key секретний ключ
 * @return код помилки
 */
UAPKIC_EXPORT int des_generate_key(size_t key_len, ByteArray **key);

/**
 * Ініціалізація контексту DES для режиму ECB.
 *
 * @param ctx контекст DES
 * @param key ключ шифрування
 * @return код помилки
 */
UAPKIC_EXPORT int des_init_ecb(DesCtx *ctx, const ByteArray *key);

/**
 * Ініціалізація контексту DES для режиму CBC.
 *
 * @param ctx контекст DES
 * @param key ключ шифрування
 * @param iv синхропосилка
 * @return код помилки
 */
UAPKIC_EXPORT int des_init_cbc(DesCtx *ctx, const ByteArray *key, const ByteArray *iv);

/**
 * Ініціалізація контексту DES для режиму CFB.
 *
 * @param ctx контекст DES
 * @param key ключ шифрування
 * @param iv синхропосилка
 * @return код помилки
 */
UAPKIC_EXPORT int des_init_cfb(DesCtx *ctx, const ByteArray *key, const ByteArray *iv);

/**
 * Ініціалізація контексту DES для режиму OFB.
 *
 * @param ctx контекст DES
 * @param key ключ шифрування
 * @param iv синхропосилка
 * @return код помилки
 */
UAPKIC_EXPORT int des_init_ofb(DesCtx *ctx, const ByteArray *key, const ByteArray *iv);

/**
 * Ініціалізація контексту DES для режиму CTR.
 *
 * @param ctx контекст DES
 * @param key ключ шифрування
 * @param iv синхропосилка
 * @return код помилки
 */
UAPKIC_EXPORT int des_init_ctr(DesCtx *ctx, const ByteArray *key, const ByteArray *iv);

/**
 * Шифрування у режимі DES.
 *
 * @param ctx контекст DES
 * @param data розшифровані дані
 * @param encrypted_data зашифровані дані
 * @return код помилки
 */
UAPKIC_EXPORT int des_encrypt(DesCtx *ctx, const ByteArray *data, ByteArray **encrypted_data);

/**
 * Розшифрування у режимі DES.
 *
 * @param ctx контекст DES
 * @param encrypted_data зашифровані дані
 * @param data розшифровані дані
 * @return код помилки
 */
UAPKIC_EXPORT int des_decrypt(DesCtx *ctx, const ByteArray *encrypted_data, ByteArray **data);

/**
 * Шифрування у режимі TDES EDE.
 *
 * @param ctx контекст DES
 * @param data розшифровані дані
 * @param encrypted_data зашифровані дані
 * @return код помилки
 */
UAPKIC_EXPORT int des3_encrypt(DesCtx *ctx, const ByteArray *data, ByteArray **encrypted_data);

/**
 * Розшифрування у режимі TDES EDE.
 *
 * @param ctx контекст DES
 * @param encrypted_data зашифровані дані
 * @param data розшифровані дані
 * @return код помилки
 */
UAPKIC_EXPORT int des3_decrypt(DesCtx *ctx, const ByteArray *encrypted_data, ByteArray **data);

/**
 * Звільняє контекст DES.
 *
 * @param ctx контекст DES
 */
UAPKIC_EXPORT void des_free(DesCtx *ctx);

/**
 * Виконує самотестування реалізації алгоритму TDES.
 *
 * @return код помилки або RET_OK, якщо самотестування пройдено
 */
UAPKIC_EXPORT int des3_self_test(void);

#ifdef __cplusplus
}
#endif

#endif
