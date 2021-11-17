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

#ifndef UAPKIC_MATH_EC2M_H
#define UAPKIC_MATH_EC2M_H

#include <stdbool.h>

#include "math-ec-point-internal.h"
#include "math-ec-precomp-internal.h"
#include "math-gf2m-internal.h"

# ifdef  __cplusplus
extern "C" {
# endif

/** Контекст для работы з группой точек еліптичної кривої. */
typedef struct EC2m_st {
    Gf2mCtx *gf2m;          /* Контекст поля GF(2m). */
    size_t a;               /* коефіцієнт еліптичної кривої a (0 або 1). */
    WordArray *b;           /* коефіцієнт еліптичної кривої b. */
    size_t len;
} EcGf2mCtx;

EcGf2mCtx *ec2m_alloc(const int *f, size_t f_len, size_t a, const WordArray *b);

/**
 * Ініціалізує контекст еліптичної кривої.
 *
 * @param ctx контекст еліптичної кривої
 * @param f не нулевые степени полинома
 * @param f_len розмір f
 * @param a коефіцієнт a еліптичної кривої
 * @param b коефіцієнт b еліптичної кривої
 */
void ec2m_init(EcGf2mCtx *ctx, const int *f, size_t f_len, size_t a, const WordArray *b);

/**
 * Перевіряє принадлежность точки еліптичної кривої.
 *
 * @param ctx контекст еліптичної кривої
 * @param px x-координата точки еліптичної кривої
 * @param py y-координата точки еліптичної кривої
 *
 * @return true - точка лежит на кривої,
 *         false - точка не лежит на кривої
 */
bool ec2m_is_on_curve(const EcGf2mCtx *ctx, const WordArray *px, const WordArray *py);

/**
 * Умножает точку еліптичної кривої на число.
 *
 * @param ctx контекст еліптичної кривої
 * @param p точка еліптичної кривої
 * @param k целое число
 * @param r результат скалярного умножения (k * P)
 */
void ec2m_mul(EcGf2mCtx *ctx, const ECPoint *p, const WordArray *k, ECPoint *r);

int ec2m_dual_mul_opt(const EcGf2mCtx *ctx, const EcPrecomp *p_precomp, const WordArray *m,
        const EcPrecomp *q_precomp, const WordArray *n, ECPoint *r);

/**
 * Вычисляет сумму двух умножений точек еліптичної кривої на число.
 *
 * @param ctx контекст еліптичної кривої
 * @param p точка еліптичної кривої
 * @param k число на яке умножается P
 * @param q точка еліптичної кривої
 * @param n число на яке умножается Q
 * @param r сумма двух умножений точек еліптичної кривої на число (k * P + n * Q)
 */
void ec2m_dual_mul(const EcGf2mCtx *ctx, const ECPoint *p, const WordArray *k,
        const ECPoint *q, const WordArray *n, ECPoint *r);

/**
 * Вычисляет сумму двух умножений точек еліптичної кривої на число.
 *
 * @param ctx контекст еліптичної кривої
 * @param precomp_p предварительные обчислення для точки P
 * @param k число на яке умножается P
 * @param precomp_q предварительные обчислення для точки Q
 * @param n число на яке умножается Q
 * @param r сумма двух умножений точек еліптичної кривої на число (k * P + n * Q)
 */
void ec2m_dual_mul_by_precomp(EcGf2mCtx *ctx, const EcPrecomp *precomp_p, const WordArray *k,
        const EcPrecomp *precomp_q, const WordArray *n, ECPoint *r);

void ec2m_point_to_affine(const EcGf2mCtx *ctx, ECPoint *p);

/**
 * Створює копію контексту еліптичної кривої.
 *
 * @param ctx контекст еліптичної кривої
 * @return копія контексту
 */
EcGf2mCtx *ec2m_copy_with_alloc(EcGf2mCtx *ctx);

/**
 * Рассчитывает предобчислення для оконного метода умножения точки на число.
 *
 * @param ctx контекст еліптичної кривої
 * @param px x-координата точки еліптичної кривої
 * @param py y-координата точки еліптичної кривої
 * @param w ширина окна
 * @param precomp_p буфер для передвичесленням розміра 2^(w - 2) * 2 * sizeof(p)
 *
 * @return код помилки
 */
int ec2m_calc_win_precomp(EcGf2mCtx *ctx, const ECPoint *p, int width, EcPrecomp **precomp1);

/**
 * Рассчитывает предобчислення для метода гребня.
 *
 * @param ctx контекст еліптичної кривої
 * @param px x-координата точка еліптичної кривої
 * @param py y-координата точка еліптичної кривої
 * @param w ширина окна
 * @param precomp_p попередні обчислення
 *
 * @return код помилки
 */
int ec2m_calc_comb_precomp(EcGf2mCtx *ctx, const ECPoint *p, int width, EcPrecomp **precomp1);

void ec2m_free(EcGf2mCtx *ctx);

#ifdef  __cplusplus
}
#endif

#endif
