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

#ifndef UAPKIC_RSA_H
#define UAPKIC_RSA_H

#include <stdbool.h>

#include "hash.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define RSASSA_PSS_SALT_LEN_ANY ((size_t)-1)

/**
 * Контекст RSA.
 */
typedef struct RsaCtx_st RsaCtx;

/**
 * Створює контекст RSA.
 *
 * @return контекст RSA
 */
UAPKIC_EXPORT RsaCtx *rsa_alloc(void);

/**
 * Генерує закритий ключ RSA.
 *
 * @param bits довжина ключа в бітах
 * @param e публічна експонента
 * @param n модуль
 * @param d приватна експонента
 * @return код помилки
 */
UAPKIC_EXPORT int rsa_generate_privkey(const size_t bits, const ByteArray *e,
        ByteArray **n, ByteArray **d);

/**
 * Генерує закритий ключ RSA.
 *
 * @param bits довжина ключа в бітах
 * @param e публічна експонента
 * @param n модуль
 * @param d приватна експонента
 * @param p просте число №1
 * @param q просте число №2
 * @param dmp1 d mod (p-1)
 * @param dmq1 d mod (q-1)
 * @param iqmp зворотній елемент q
 * @return код помилки
 */
UAPKIC_EXPORT int rsa_generate_privkey_ext(const size_t bits, const ByteArray *e,
        ByteArray **n, ByteArray **d, ByteArray **p, ByteArray **q, ByteArray **dmp1, ByteArray **dmq1, ByteArray **iqmp);

/**
 * Перевіряє закритий ключ RSA.
 *
 * @param ctx контекст RSA
 * @param n модуль
 * @param e публічна експонента
 * @param d приватна експонента
 * @param p просте число №1
 * @param q просте число №2
 * @param dmp1 d mod (p-1)
 * @param dmq1 d mod (q-1)
 * @param iqmp зворотній елемент q
 * @return код помилки
 */
UAPKIC_EXPORT bool rsa_validate_key(RsaCtx *ctx, const ByteArray *n, const ByteArray *e, const ByteArray *d,
        const ByteArray *p, const ByteArray *q, const ByteArray *dmp1, const ByteArray *dmq1, const ByteArray *iqmp);

/**
 * Ініціалізація контексту RSA для режиму OAEP.
 *
 * @param ctx контекст RSA
 * @param hash_alg алгоритм гешування
 * @param label необов'язкова мітка, яка асоціюється з повідомленням;
 * значення за замовчуванням - пустий рядок
 * @param n модуль
 * @param e публічна експонента
 * @return код помилки
 */
UAPKIC_EXPORT int rsa_init_encrypt_oaep(RsaCtx *ctx, HashAlg hash_alg, ByteArray *label,
        const ByteArray *n, const ByteArray *e);

/**
 * Ініціалізація контексту RSA для режиму OAEP.
 *
 * @param ctx контекст RSA
 * @param hash_alg алгоритм гешування
 * @param label необов'язкова мітка, яка асоціюється з повідомленням;
 * значення за замовчуванням - пустий рядок
 * @param n модуль
 * @param d приватна экспонента
 * @return код помилки
 */
UAPKIC_EXPORT int rsa_init_decrypt_oaep(RsaCtx *ctx, HashAlg hash_alg, ByteArray *label, const ByteArray *n,
        const ByteArray *d);

/**
 * Ініціалізація контексту RSA для режиму PKCS1_5.
 *
 * @param ctx контекст RSA
 * @param n модуль
 * @param e публічна експонента
 * @return код помилки
 */
UAPKIC_EXPORT int rsa_init_encrypt_pkcs1_v1_5(RsaCtx *ctx, const ByteArray *n, const ByteArray *e);

/**
 * Ініціалізація контексту RSA для режиму PKCS1_5.
 *
 * @param ctx контекст RSA
 * @param n модуль
 * @param d приватна экспонента
 * @return код помилки
 */
UAPKIC_EXPORT int rsa_init_decrypt_pkcs1_v1_5(RsaCtx *ctx, const ByteArray *n, const ByteArray *d);

/**
 * Ініціалізує контекст RSA для формування ЕЦП згідно з PKCS№1 v2.1 “RSA  Cryptography  Standard” RSASSA-PKCS1-v1_5.
 *
 * @param ctx контекст RSA
 * @param hash_alg алгоритм гешування
 * @param n модуль
 * @param d приватна експонента
 * @return код помилки
 */
UAPKIC_EXPORT int rsa_init_sign_pkcs1_v1_5(RsaCtx *ctx, HashAlg hash_alg, const ByteArray *n, const ByteArray *d);

/**
 * Ініціалізує контекст RSA для перевірки ЕЦП згідно з PKCS№1 v2.1 “RSA  Cryptography  Standard” RSASSA-PKCS1-v1_5.
 *
 * @param ctx контекст RSA
 * @param hash_alg алгоритм гешування
 * @param n модуль
 * @param e публічна экспонента
 * @return код помилки
 */
UAPKIC_EXPORT int rsa_init_verify_pkcs1_v1_5(RsaCtx *ctx, HashAlg hash_alg, const ByteArray *n, const ByteArray *e);

/**
 * Ініціалізує контекст RSA для формування ЕЦП згідно з RSA-PSS.
 *
 * @param ctx контекст RSA
 * @param hash_alg алгоритм гешування
 * @param n модуль
 * @param d приватна експонента
 * @return код помилки
 */
UAPKIC_EXPORT int rsa_init_sign_pss(RsaCtx* ctx, HashAlg hash_alg, const ByteArray* n, const ByteArray* d);

/**
 * Ініціалізує контекст RSA для перевірки ЕЦП згідно з RSA-PSS.
 *
 * @param ctx контекст RSA
 * @param hash_alg алгоритм гешування
 * @param salt_len очікувана довжина salt
 * @param n модуль
 * @param e публічна экспонента
 * @return код помилки
 */
UAPKIC_EXPORT int rsa_init_verify_pss(RsaCtx* ctx, HashAlg hash_alg, size_t salt_len, const ByteArray* n, const ByteArray* e);

/**
 * Шифрування даних.
 *
 * @param ctx контекст RSA
 * @param data дані для шифрування
 * @param encrypted_data зашифровані дані
 * @return код помилки
 */
UAPKIC_EXPORT int rsa_encrypt(RsaCtx* ctx, const ByteArray* data, ByteArray** encrypted_data);

/**
 * Розшифрування даних.
 *
 * @param ctx контекст RSA
 * @param encrypted_data дані для розшифрування
 * @param data розшифровані дані
 * @return код помилки
 */
UAPKIC_EXPORT int rsa_decrypt(RsaCtx* ctx, const ByteArray* encrypted_data, ByteArray** data);

/**
 * Формує ЕЦП згідно RSASSA-PKCS1-v1_5 або RSA-PSS.
 *
 * @param ctx контекст RSA
 * @param hash значення геша
 * @param sign підпис RSA
 * @return код помилки
 */
UAPKIC_EXPORT int rsa_sign(RsaCtx* ctx, const ByteArray* hash, ByteArray** sign);

/**
 * Перевіряє ЕЦП згідно з RSASSA-PKCS1-v1_5 або RSA-PSS.
 *
 * @param ctx контекст RSA
 * @param hash значення геша
 * @param sign підпис RSA
 * @return код помилки або RET_OK, якщо підпис вірний
 */
UAPKIC_EXPORT int rsa_verify(RsaCtx* ctx, const ByteArray* hash, const ByteArray* sign);

/**
 * Звільняє контекст RSA.
 *
 * @param ctx
 */
UAPKIC_EXPORT void rsa_free(RsaCtx *ctx);

/**
 * Виконує самотестування реалізації алгоритму RSA.
 * @return код помилки або RET_OK, якщо срмотестування пройдено
 */
UAPKIC_EXPORT int rsa_self_test(void);

#ifdef  __cplusplus
}
#endif

#endif
