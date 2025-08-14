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

#ifndef UAPKIC_GOST28147_H
#define UAPKIC_GOST28147_H

#include "byte-array.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Контекст ГОСТ 28147.
 */
typedef struct Gost28147Ctx_st Gost28147Ctx;

/**
 * Ідентифікатори стандартних таблиць замін.
 */
typedef enum {
    GOST28147_SBOX_DEFAULT = 0, /**< Таблиця замін ДКЕ №1 із доповнення 1 до інструкції №114. */
    GOST28147_SBOX_ID_1 = 1,    /**< Таблиця замін ДКЕ №1 із доповнення 1 до інструкції №114. */
    GOST28147_SBOX_ID_2 = 2,    /**< Таблиця замін ДКЕ №1 із доповнення 2 до інструкції №114. */
    GOST28147_SBOX_ID_3 = 3,    /**< Таблиця замін ДКЕ №1 із доповнення 3 до інструкції №114. */
    GOST28147_SBOX_ID_4 = 4,    /**< Таблиця замін ДКЕ №1 із доповнення 4 до інструкції №114. */
    GOST28147_SBOX_ID_5 = 5,    /**< Таблиця замін ДКЕ №1 із доповнення 5 до інструкції №114. */
    GOST28147_SBOX_ID_6 = 6,    /**< Таблиця замін ДКЕ №1 із доповнення 6 до інструкції №114. */
    GOST28147_SBOX_ID_7 = 7,    /**< Таблиця замін ДКЕ №1 із доповнення 7 до інструкції №114. */
    GOST28147_SBOX_ID_8 = 8,    /**< Таблиця замін ДКЕ №1 із доповнення 8 до інструкції №114. */
    GOST28147_SBOX_ID_9 = 9,    /**< Таблиця замін ДКЕ №1 із доповнення 9 до інструкції №114. */
    GOST28147_SBOX_ID_10 = 10,  /**< Таблиця замін ДКЕ №1 із доповнення 10 до інструкції №114. */
    GOST28147_SBOX_ID_11 = 11,  /**< Таблиця замін з ГОСТ 34.311-95. */
    GOST28147_SBOX_ID_12 = 12,  /**< Таблиця замін CryptoPro-Test з RFC-4357. */
    GOST28147_SBOX_ID_13 = 13,  /**< Таблиця замін CryptoPro-A з RFC-4357. */
    GOST28147_SBOX_ID_14 = 14,  /**< Таблиця замін CryptoPro-B з RFC-4357. */
    GOST28147_SBOX_ID_15 = 15,  /**< Таблиця замін CryptoPro-C з RFC-4357. */
    GOST28147_SBOX_ID_16 = 16,  /**< Таблиця замін CryptoPro-D з RFC-4357. */
    GOST28147_SBOX_ID_17 = 17,  /**< Таблиця замін id-GostR3411-94-CryptoProParamSet з RFC-4357. */
    GOST28147_SBOX_ID_18 = 18,  /**< Таблиця замін з openssl */
} Gost28147SboxId;

/**
 * Створює контекст ГОСТ 28147 зі стандартною таблицею замін.
 *
 * @param sbox_id ідентифікатор стандартної таблиці замін
 * @return контекст ГОСТ 28147
 */
UAPKIC_EXPORT Gost28147Ctx *gost28147_alloc(Gost28147SboxId sbox_id);

/**
 * Створює контекст ГОСТ 28147 з користувацьким sbox.
 *
 * @param sbox користувацька таблиця замін разміром 128 байт
 * @return контекст ГОСТ 28147
 */
UAPKIC_EXPORT Gost28147Ctx *gost28147_alloc_user_sbox(const ByteArray *sbox);

UAPKIC_EXPORT Gost28147Ctx *gost28147_copy_with_alloc(const Gost28147Ctx *ctx);

/**
 * Повертає розгорнуту таблицю замін.
 *
 * @param ctx контекст ГОСТ 28147
 * @param sbox таблиця замін разміром 128 байт
 * @return код помилки
 */
UAPKIC_EXPORT int gost28147_get_ext_sbox(const Gost28147Ctx *ctx, ByteArray **sbox);

/**
 * Повертає зжату таблицю замін.
 *
 * @param ctx контекст ГОСТ 28147
 * @param sbox таблиця замін разміром 128 байт
 * @return код помилки
 */
UAPKIC_EXPORT int gost28147_get_compress_sbox(const Gost28147Ctx *ctx, ByteArray **sbox);

/**
 * Генерує секретний ключ відповідно до ГОСТ 28147-89.
 *
 * @param key секретний ключ
 * @return код помилки
 */
UAPKIC_EXPORT int gost28147_generate_key(ByteArray **key);

/**
 * Ініціалізує контекст для шифрування у режимі простої заміни.
 *
 * @param ctx контекст ГОСТ 28147
 * @param key ключ шифрування
 * @return код помилки
 */
UAPKIC_EXPORT int gost28147_init_ecb(Gost28147Ctx *ctx, const ByteArray *key);

/**
 * Ініціалізує контекст для шифрування у режимі гамування.
 *
 * @param ctx контекст ГОСТ 28147
 * @param key ключ шифрування
 * @param iv ініціалізаційний вектор
 * @return код помилки
 */
UAPKIC_EXPORT int gost28147_init_ctr(Gost28147Ctx *ctx, const ByteArray *key, const ByteArray *iv);

/**
 * Ініціалізує контекст для шифрування у режимі гамування зі зворотнім зв'язком.
 *
 * @param ctx контекст ГОСТ 28147
 * @param key ключ шифрування
 * @param iv ініціалізаційний вектор
 * @return код помилки
 */
UAPKIC_EXPORT int gost28147_init_cfb(Gost28147Ctx *ctx, const ByteArray *key, const ByteArray *iv);

/**
 * Ініціалізує контекст для отримання імітовставки.
 *
 * @param ctx контекст ГОСТ 28147
 * @param key ключ шифрування
 * @return код помилки
 */
UAPKIC_EXPORT int gost28147_init_mac(Gost28147Ctx *ctx, const ByteArray *key);

/**
 * Шифрує блок даних.
 *
 * @param ctx контекст ГОСТ 28147
 * @param data дані для шифрування
 * @param encrypted_data зашифровані дані
 *
 * @return код помилки
 */
UAPKIC_EXPORT int gost28147_encrypt(Gost28147Ctx *ctx, const ByteArray *data, ByteArray **encrypted_data);

/**
 * Розшифровує блок даних.
 *
 * @param ctx контекст ГОСТ 28147
 * @param encrypted_data зашифровані дані
 * @param data розшифровані дані
 * @return код помилки
 */
UAPKIC_EXPORT int gost28147_decrypt(Gost28147Ctx *ctx, const ByteArray *encrypted_data, ByteArray **data);

/**
 * Обновлюемо імітовектор блоком даних.
 *
 * @param ctx контекст ГОСТ 28147
 * @param data дані
 * @return код помилки
 */
UAPKIC_EXPORT int gost28147_update_mac(Gost28147Ctx *ctx, const ByteArray *data);

/**
 * Завершує вироблення імітовектору й повертає його значення.
 *
 * @param ctx контекст ГОСТ 28147
 * @param mac імітовектор
 *
 * @return код помилки
 */
UAPKIC_EXPORT int gost28147_final_mac(Gost28147Ctx *ctx, ByteArray **mac);

/**
 * Завершує вироблення імітовектору й повертає його розширене значення.
 *
 * @param ctx контекст ГОСТ 28147
 * @param mac розширений імітовектор
 *
 * @return код помилки
 */
UAPKIC_EXPORT int gost28147_final_mac8(Gost28147Ctx *ctx, ByteArray **mac);

/**
 * Звільняє контекст ГОСТ 28147.
 *
 * @param ctx контекст ГОСТ 28147
 *
 * @return код помилки
 */
UAPKIC_EXPORT void gost28147_free(Gost28147Ctx *ctx);

/**
 * Виконує самотестування реалізації алгоритму ГОСТ 28147.
 *
 * @return код помилки або RET_OK, якщо самотестування пройдено
 */
UAPKIC_EXPORT int gost28147_self_test(void);

#ifdef  __cplusplus
}
#endif

#endif
