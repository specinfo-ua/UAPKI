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

#ifndef UAPKIC_AES_H
#define UAPKIC_AES_H

#include "byte-array.h"


#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Контекст AES.
 */
typedef struct AesCtx_st AesCtx;

/**
 * Створює контекст AES.
 *
 * @return контекст AES
 */
UAPKIC_EXPORT AesCtx *aes_alloc(void);

/**
 * Генерує секретний ключ.
 *
 * @param key_len размер ключа 16, 24 или 32
 * @param key секретний ключ
 * @return код помилки
 */
UAPKIC_EXPORT int aes_generate_key(size_t key_len, ByteArray **key);

/**
 * Ініціалізація контексту AES для режиму ECB.
 *
 * @param ctx контекст AES
 * @param key ключ шифрування
 * @return код помилки
 */
UAPKIC_EXPORT int aes_init_ecb(AesCtx *ctx, const ByteArray *key);

/**
 * Ініціалізація контексту AES для режиму CBC.
 * Розмір даних при шифруванні/розшифруванні повинет бути кратен розміру блока AES (16 байт),
 * окрім останнього блоку при шифруванні.
 *
 * @param ctx контекст AES
 * @param key ключ шифрування
 * @param iv синхропосилка
 * @return код помилки
 */
UAPKIC_EXPORT int aes_init_cbc(AesCtx *ctx, const ByteArray *key, const ByteArray *iv);

/**
 * Ініціалізація контексту AES для режиму CFB.
 *
 * @param ctx контекст AES
 * @param key ключ шифрування
 * @param iv синхропосилка
 * @return код помилки
 */
UAPKIC_EXPORT int aes_init_cfb(AesCtx *ctx, const ByteArray *key, const ByteArray *iv);

/**
 * Ініціалізація контексту AES для режиму OFB.
 *
 * @param ctx контекст AES
 * @param key ключ шифрування
 * @param iv синхропосилка
 * @return код помилки
 */
UAPKIC_EXPORT int aes_init_ofb(AesCtx *ctx, const ByteArray *key, const ByteArray *iv);

/**
 * Ініціалізація контексту AES для режиму CTR.
 *
 * @param ctx контекст AES
 * @param key ключ шифрування
 * @param iv синхропосилка
 * @return код помилки
 */
UAPKIC_EXPORT int aes_init_ctr(AesCtx *ctx, const ByteArray *key, const ByteArray *iv);

/**
 * Ініціалізує контекст для шифрування у режимі GCM.
 *
 * @param ctx контекст AES
 * @param key ключ шифрування
 * @param iv синхропосилка
 * @param tag_len розмір контрольної суми
 * @return код помилки
 */
UAPKIC_EXPORT int aes_init_gcm(AesCtx* ctx, const ByteArray* key, const ByteArray* iv, const size_t tag_len);

/**
 * Ініціалізує контекст для шифрування у режимі CCM.
 *
 * @param ctx контекст AES
 * @param key ключ шифрування
 * @param iv синхропосилка
 * @param tag_len розмір контрольної суми
 * @return код помилки
 */
UAPKIC_EXPORT int aes_init_ccm(AesCtx* ctx, const ByteArray* key, const ByteArray* iv, const size_t tag_len);

/**
 * Ініціалізує контекст для шифрування у режимі KEY WRAP.
 *
 * @param ctx контекст AES
 * @param key ключ шифрування
 * @param iv синхропосилка
 * @return код помилки
 */
UAPKIC_EXPORT int aes_init_wrap(AesCtx* ctx, const ByteArray* key, const ByteArray* iv);

/**
 * Шифрування у режимі AES.
 *
 * @param ctx контекст AES
 * @param data дані
 * @param encrypted_data зашифровані дані
 * @return код помилки
 */
UAPKIC_EXPORT int aes_encrypt(AesCtx *ctx, const ByteArray *data, ByteArray **encrypted_data);

/**
 * Розшифрування у режимі AES.
 *
 * @param ctx контекст AES
 * @param encrypted_data зашифровані дані
 * @param data розшифровані дані
 * @return код помилки
 */
UAPKIC_EXPORT int aes_decrypt(AesCtx *ctx, const ByteArray *encrypted_data, ByteArray **data);

/**
 * Шифрування та вироблення імітовставки.
 *
 * @param ctx контекст AES
 * @param auth_data відкритий текст повідомлення
 * @param data дані для шифрування
 * @param mac імітовставка
 * @param encrypted_data зашифроване повідомлення
 * @return код помилки
 */
UAPKIC_EXPORT int aes_encrypt_mac(AesCtx* ctx, const ByteArray* auth_data, const ByteArray* data,
    ByteArray** mac, ByteArray** encrypted_data);

/**
 * Розшифрування та забезпечення цілосності.
 *
 * @param ctx контекст AES
 * @param auth_data відкритий текст повідомлення
 * @param encrypted_data дані для розшифрування
 * @param mac імітовставка
 * @param data розшифроване повідомлення
 * @return код помилки
 */
UAPKIC_EXPORT int aes_decrypt_mac(AesCtx* ctx, const ByteArray* auth_data,
    const ByteArray* encrypted_data, const ByteArray* mac, ByteArray** data);

/**
 * Звільняє контекст AES.
 *
 * @param ctx контекст AES
 */
UAPKIC_EXPORT void aes_free(AesCtx *ctx);

/**
 * Виконує самотестування реалізації алгоритму AES.
 *
 * @return код помилки або RET_OK, якщо самотестування пройдено
 */
UAPKIC_EXPORT int aes_self_test(void);

#ifdef  __cplusplus
}
#endif

#endif
