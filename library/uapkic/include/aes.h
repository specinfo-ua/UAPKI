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
 * Метод доповнення даних для CBC-MAC за ISO/IEC 9797-1.
 */
typedef enum {
    AES_CBC_MAC_PADDING_1 = 1,  /* Метод 1: доповнення нульовими бітами до кратності блоку (порожнє повідомлення - один нульовий блок) */
    AES_CBC_MAC_PADDING_2 = 2   /* Метод 2: додається одиничний біт, далі нульові біти до кратності блоку */
} AesCbcMacPadding;

/**
 * Створює контекст AES.
 *
 * @return контекст AES
 */
UAPKIC_EXPORT AesCtx *aes_alloc(void);

/**
 * Генерує секретний ключ.
 *
 * @param key_len розмір ключа 16, 24 або 32
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
 * Розмір даних при шифруванні/розшифруванні повинен бути кратним розміру блоку AES (16 байт),
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
 * Ініціалізує контекст для обгортання ключа з доповненням (KWP: RFC 5649, NIST SP 800-38F).
 * Обгортання - aes_encrypt (дані від 1 байта, результат кратний 8 байтам і не коротший за 16),
 * розгортання - aes_decrypt (RET_INVALID_MAC, якщо перевірка цілісності не пройдена).
 *
 * @param ctx контекст AES
 * @param key ключ шифрування ключа (16, 24 або 32 байти)
 * @return код помилки
 */
UAPKIC_EXPORT int aes_init_wrap_pad(AesCtx* ctx, const ByteArray* key);

/**
 * Ініціалізує контекст для вироблення імітовставки у режимі CMAC (NIST SP 800-38B, RFC 4493).
 * Дані подаються функцією aes_update_mac, імітовставка виробляється функцією aes_final_mac.
 *
 * @param ctx контекст AES
 * @param key ключ (16, 24 або 32 байти)
 * @param mac_len розмір імітовставки в байтах (1..16; рекомендовано не менше 8)
 * @return код помилки
 */
UAPKIC_EXPORT int aes_init_cmac(AesCtx* ctx, const ByteArray* key, const size_t mac_len);

/**
 * Ініціалізує контекст для вироблення імітовставки у режимі CBC-MAC за ISO/IEC 9797-1
 * (MAC-алгоритм 1: початкове перетворення 1, вихідне перетворення 1, усічення до mac_len байтів).
 * Увага: CBC-MAC стійкий лише для повідомлень фіксованої довжини; для повідомлень змінної довжини слід використовувати CMAC.
 * Дані подаються функцією aes_update_mac, імітовставка виробляється функцією aes_final_mac.
 *
 * @param ctx контекст AES
 * @param key ключ (16, 24 або 32 байти)
 * @param padding метод доповнення даних (ISO/IEC 9797-1, метод 1 або 2)
 * @param mac_len розмір імітовставки в байтах (1..16)
 * @return код помилки
 */
UAPKIC_EXPORT int aes_init_cbc_mac(AesCtx* ctx, const ByteArray* key, const AesCbcMacPadding padding, const size_t mac_len);

/**
 * Додає дані для вироблення імітовставки (режими CMAC та CBC-MAC). Може викликатися кілька разів.
 *
 * @param ctx контекст AES
 * @param data дані
 * @return код помилки
 */
UAPKIC_EXPORT int aes_update_mac(AesCtx* ctx, const ByteArray* data);

/**
 * Виробляє імітовставку (режими CMAC та CBC-MAC). Після виклику контекст готовий до обробки
 * наступного повідомлення з тим самим ключем.
 *
 * @param ctx контекст AES
 * @param mac імітовставка
 * @return код помилки
 */
UAPKIC_EXPORT int aes_final_mac(AesCtx* ctx, ByteArray** mac);

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
 * Розшифрування та забезпечення цілісності.
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
