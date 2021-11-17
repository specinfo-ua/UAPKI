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

#ifndef UAPKIC_EC_CACHE_H
#define UAPKIC_EC_CACHE_H

#include "byte-array.h"
#include "ec.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Додає до кешу контекст еліптичної кривої зі стандартними параметрами.
 *
 * @param params_id ідентифікатор стандартних параметрів
 * @param opt_level рівень передобчислення
 *
 * @return код помилки
 */
UAPKIC_EXPORT int ec_cache_add_default(EcParamsId params_id, OptLevelId opt_level);

/**
 * Додає до кешу контекст еліптичної кривої над розширеним полем з параметрами у поліноміальному базисі.
 *
 * @param f примітивний многочлен f(t) (тричлен, п'ятичлен), який визначає поліноміальний базис
 * @param f_len число членів у полиномі f (3 або 5)
 * @param a коефіцієнт у рівнянні еліптичної кривої (0 або 1)
 * @param b коефіцієнт b у рівнянні еліптичної кривої
 * @param n порядок циклічної підгрупи групи точок еліптичної кривої
 * @param px X-координата точки еліптичної кривої порядока n
 * @param py Y-координата точки еліптичної кривої порядока n
 * @param opt_level рівень передобчислення
 *
 * @return код помилки
 */
UAPKIC_EXPORT int ec_cache_add_ec2m_pb(const int *f, size_t f_len, size_t a, const ByteArray *b,
        const ByteArray *n, const ByteArray *px, const ByteArray *py, OptLevelId opt_level);

/**
 * Додає до кешу контекст еліптичної кривої над розширеним полем з параметрами у оптимальному нормальному базисі.
 *
 * @param m степінь основного поля, непарне просте число (163 <= m <= 509)
 * @param a коефіцієнт у рівнянні еліптичної кривої (0 або 1)
 * @param b коефіцієнт b у рівнянні еліптичної кривої
 * @param n порядок циклічної підгрупи групи точок еліптичної кривої
 * @param px X-координата точки еліптичної кривої порядока n
 * @param py Y-координата точки еліптичної кривої порядока n
 * @param opt_level рівень передобчислення
 *
 * @return код помилки
 */
UAPKIC_EXPORT int ec_cache_add_ec2m_onb(size_t m, size_t a, const ByteArray *b, const ByteArray *n,
        const ByteArray *px, const ByteArray *py, OptLevelId opt_level);

/**
 * Додає до кешу контекст еліптичної кривої над простим полем.
 *
 * @param p порядок скінченного простого поля GF(p)
 * @param a коефіцієнт a у рівнянні еліптичної кривої
 * @param b коефіцієнт b у рівнянні еліптичної кривої
 * @param q порядок базової точки
 * @param px X-координата базової точки
 * @param py Y-координата базової точки
 * @param opt_level рівень передобчислення
 *
 * @return код помилки
 */
UAPKIC_EXPORT int ec_cache_add_ecp(const ByteArray *p, const ByteArray *a, const ByteArray *b,
        const ByteArray *q, const ByteArray *px, const ByteArray *py, OptLevelId opt_level);

/**
 * Встановлює рівень оптимізації (передобчислень) для нових контекстів еліптичних кривих.
 *
 * @param opt_level рівень передобчислення
 *
 * @return код помилки
 */
UAPKIC_EXPORT int ec_cache_set_default_opt_level(OptLevelId opt_level);

/**
 * Звільняє пам'ять кеша контекстів еліптичних кривих.
 */
UAPKIC_EXPORT void ec_cache_free(void);

#ifdef  __cplusplus
}
#endif

#endif
