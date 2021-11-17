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

#ifndef UAPKIC_EC_PARAMS_H
#define UAPKIC_EC_PARAMS_H

#include <stdint.h>
#include <stdbool.h>
#include "byte-array.h"
#include "ec-default-params.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef enum {
    OPT_LEVEL_COMB_5_WIN_5 = 0x5005,
    OPT_LEVEL_COMB_11_WIN_5 = 0xb005,
    OPT_LEVEL_WIN_5_WIN_5 = 0x0505,
    OPT_LEVEL_WIN_11_WIN_11 = 0x0b0b,
    OPT_LEVEL_COMB_5_COMB_5 = 0x5050,
    OPT_LEVEL_COMB_11_COMB_11 = 0xb0b0
} OptLevelId;

typedef struct EcCtx_st EcCtx;

/**
 * Створює контекст еліптичної кривої зі стандартними параметрами
 *
 * @param params_id ідентифікатор стандартних параметрів
 * @return контекст еліптичної кривої
 */
UAPKIC_EXPORT EcCtx* ec_alloc_default(EcParamsId params_id);

/**
 * Створює контекст еліптичної кривої над простим полем
 *
 * @param p порядок скінченного простого поля GF(p)
 * @param a коефіцієнт a у рівнянні еліптичної кривої
 * @param b коефіцієнт b у рівнянні еліптичної кривої
 * @param q порядок базової точки
 * @param px X-координата базової точки
 * @param py Y-координата базової точки
 * @return контекст еліптичної кривої
 */
UAPKIC_EXPORT EcCtx* ec_alloc_prime(const ByteArray* p, const ByteArray* a, const ByteArray* b, const ByteArray* q,
    const ByteArray* px, const ByteArray* py);

/**
 * Створює контекст еліптичної кривої над розширеним полем з параметрами у поліноміальному базисі
 *
 * @param f примітивний многочлен f(t) (тричлен, п'ятичлен), який визначає поліноміальний базис
 * @param f_len число членів у полиномі f (3 або 5)
 * @param a коефіцієнт у рівнянні еліптичної кривої (0 або 1)
 * @param b коефіцієнт b у рівнянні еліптичної кривої
 * @param n порядок циклічної підгрупи групи точок еліптичної кривої
 * @param px X-координата точки еліптичної кривої порядока n
 * @param py Y-координата точки еліптичної кривої порядока n
 * @return контекст еліптичної кривої
 */
UAPKIC_EXPORT EcCtx* ec_alloc_binary_pb(const int* f, size_t f_len, size_t a, const ByteArray* b, const ByteArray* n,
    const ByteArray* px, const ByteArray* py);

/**
 * Створює контекст еліптичної кривої над розширеним полем з параметрами у оптимальному нормальному базисі
 *
 * @param m степінь основного поля, непарне просте число (163 <= m <= 509)
 * @param a коефіцієнт у рівнянні еліптичної кривої (0 або 1)
 * @param b коефіцієнт b у рівнянні еліптичної кривої
 * @param n порядок циклічної підгрупи групи точок еліптичної кривої
 * @param px X-координата точки еліптичної кривої порядока n
 * @param py Y-координата точки еліптичної кривої порядока n
 * @return контекст еліптичної кривої
 */
UAPKIC_EXPORT EcCtx* ec_alloc_binary_onb(size_t m, size_t a, const ByteArray* b, const ByteArray* n, const ByteArray* px,
    const ByteArray* py);

/**
 * Звільняє контекст еліптичної кривої
 *
 * @param ctx контекст еліптичної кривої
 *
 */
UAPKIC_EXPORT void ec_free(EcCtx* ctx);

/**
 * Встановити рівень передобчислення.
 *
 * @param ctx контекст алгорітмів еліптичної кривої
 * @param opt_level рівень передобчислення
 * @return код помилки
 */
UAPKIC_EXPORT int ec_set_opt_level(EcCtx* ctx, OptLevelId opt_level);

/**
 * Створює новий контекст еліптичної кривої та копіює туди параметри
 *
 * @param param контекст еліптичної кривої
 * @return контекст еліптичної кривої
 */
UAPKIC_EXPORT EcCtx* ec_copy_params_with_alloc(const EcCtx* param);

/**
 * Створює копію контекст еліптичної кривої
 *
 * @param param контекст еліптичної кривої
 * @return контекст еліптичної кривої
 */
UAPKIC_EXPORT EcCtx* ec_copy_with_alloc(const EcCtx* param);

/**
 * Визначає чи є параметри у ОНБ.
 *
 * @param ctx контекст еліптичної кривої
 * @param is_onb_params чи є параметри у ОНБ
 * @return код помилки
 */
UAPKIC_EXPORT int ec_is_onb_params(const EcCtx* ctx, bool* is_onb_params);

/**
 * Визначає чи єліптичні криві однакоі.
 *
 * @param param_a контекст еліптичної кривої
 * @param param_b контекст еліптичної кривої
 * @param equals чи параметри однакові
 * @return код помилки
 */
UAPKIC_EXPORT int ec_equals_params(const EcCtx* param_a, const EcCtx* param_b, bool* equals);

/**
 * Повертає параметри ECDSA.
 *
 * @param ctx контекст ECDSA
 * @param p порядок скінченного простого поля GF(p)
 * @param f примітивний многочлен f(t) (тричлен, п'ятичлен), який визначає поліноміальний базис
 * @param a коефіцієнт a у рівнянні еліптичної кривої
 * @param b коефіцієнт b у рівнянні еліптичної кривої
 * @param n порядок базової точки
 * @param px X-координата базової точки
 * @param py Y-координата базової точки
 *
 * @return код помилки
 */
UAPKIC_EXPORT int ec_get_params(const EcCtx *ctx, EcFieldType *field_type, ByteArray **p, int **f, ByteArray **a, ByteArray **b, 
                                    ByteArray **n, ByteArray **px, ByteArray **py);

/**
 * Стисканя Y-координати точки на ЕК (для ДСТУ 4145 використовується окрема функція).
 *
 * @param ctx контекст ЕК
 * @param qx X-координата точки
 * @param qy Y-координата точки
 * @param compressed_y стиснута Y-координата точки
 * @return код помилки
 */
UAPKIC_EXPORT int ec_point_compress(const EcCtx* ctx, const ByteArray* qx, const ByteArray* qy, int* compressed_y);

/**
 * Відновлення Y-координати точки на ЕК (для ДСТУ 4145 використовується окрема функція).
 *
 * @param ctx контекст ЕК
 * @param q X-координата точки
 * @param compressed_y стиснута Y-координата точки
 * @param qy відновлена Y-координата точки
 * @return код помилки
 */
UAPKIC_EXPORT int ec_point_decompress(const EcCtx* ctx, const ByteArray* q, int compressed_y, ByteArray** qy);

/**
 * Ініціалізує контекст ЕК для формування підписів.
 *
 * @param ctx контекст ЕК
 * @param d особистий ключ
 * @return код помилки
 */
UAPKIC_EXPORT int ec_init_sign(EcCtx* ctx, const ByteArray* d);

/**
 * Ініціалізує контекст ЕК для перевірки підписів.
 *
 * @param ctx контекст ЕК
 * @param qx Х-координата відкритого ключа
 * @param qy Y-координата відкритого ключа
 * @return код помилки
 */
UAPKIC_EXPORT int ec_init_verify(EcCtx* ctx, const ByteArray* qx, const ByteArray* qy);

/**
 * Повертає загальне секретне значення по схемі Диффі-Хеллмана (з кофактором для ЕК над розширеним полем)
 *
 * @param ctx контекст ЕК
 * @param with_cofactor алгоритм з кофакторним множенням
 * @param d закритий ключ
 * @param qx Х-координата відкритого ключа
 * @param qy Y-координата відкритого ключа
 * @param zx Х-координата спільного секретного значення
 * @param zy Y-координата спільного секретного значення
 * @return код помилки
 */
UAPKIC_EXPORT int ec_dh(const EcCtx* ctx, bool with_cofactor, const ByteArray* d, const ByteArray* qx,
    const ByteArray* qy, ByteArray** zx, ByteArray** zy);

/**
 * Виконує самотестування реалізації криптопримітиву протоколу Диффі-Геллмана на ЕК
 *
 * @return код помилки або RET_OK, якщо самотестування пройдено
 */
UAPKIC_EXPORT int ec_dh_self_test(void);

#ifdef __cplusplus
}
#endif

#endif
