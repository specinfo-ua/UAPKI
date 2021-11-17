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

#ifndef UAPKIC_MATH_ECP_H
#define UAPKIC_MATH_ECP_H

#include <stdbool.h>

#include "math-ec-point-internal.h"
#include "math-ec-precomp-internal.h"
#include "math-gfp-internal.h"

#ifdef  __cplusplus
extern "C" {
#endif

/** Контекст для работы з группой точек еліптичної кривої. */
typedef struct EcGfpCtx_st {
    GfpCtx *gfp;            /* Контекст поля GF(p). */
    WordArray *a;              /* коефіцієнт еліптичної кривої a. */
    WordArray *b;           /* коефіцієнт еліптичної кривої b. */
    bool a_equal_minus_3;   /* Определяет Виконуєся ли равенство a == -3. */
    size_t len;
} EcGfpCtx;

EcGfpCtx *ecp_alloc(const WordArray *p, const WordArray *a, const WordArray *b);

/**
 * Ініціалізує контекст еліптичної кривої.
 *
 * @param ctx контекст еліптичної кривої
 * @param p порядок кінцевого просте поля
 * @param a коефіцієнт a еліптичної кривої
 * @param b коефіцієнт b еліптичної кривої
 */
void ecp_init(EcGfpCtx *ctx, const WordArray *p, const WordArray *a, const WordArray *b);

EcGfpCtx *ecp_copy_with_alloc(EcGfpCtx *ctx);

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
bool ecp_is_on_curve(const EcGfpCtx *ctx, const WordArray *px, const WordArray *py);

/**
 * Умножает точку еліптичної кривої на число.
 *
 * @param ctx контекст еліптичної кривої
 * @param p точка еліптичної кривої
 * @param k целое число
 * @param r результат скалярного умножения
 */
void ecp_mul(EcGfpCtx *ctx, const ECPoint *p, const WordArray *k, ECPoint *r);


/**
 * Умножает точку (одновременно две точки) еліптичної кривої на число.
 *
 * Заранее должны бути рассчитаны предварительные обчислення для
 * метода гребня або скользящйого окна для каждой точки P і Q.
 *
 * @param ctx контекст еліптичної кривої
 * @param p точка еліптичної кривої
 * @param k целое число
 * @param q точка Q
 * @param n число на яке умножается q
 * @param r = m * P + n * Q
 */
void ecp_dual_mul(EcGfpCtx *ctx, const ECPoint *p, const WordArray *k,
        const ECPoint *q, const WordArray *n, ECPoint *r);

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
int ecp_calc_win_precomp(EcGfpCtx *ctx, const ECPoint *p, int width, EcPrecomp **precomp1);

/**
 * Рассчитывает предобчислення для метода гребня.
 *
 * @param ctx контекст еліптичної кривої
 * @param px x-координата точка еліптичної кривої
 * @param py y-координата точка еліптичної кривої
 * @param w ширина окна
 * @param precomp_p предварительные обчислення
 *
 * @return код помилки
 */
int ecp_calc_comb_precomp(EcGfpCtx *ctx, const ECPoint *p, int width, EcPrecomp **precomp1);

/**
 * Умножает точку (одновременно две точки) еліптичної кривої на число.
 *
 * Заранее должны бути рассчитаны предварительные обчислення для
 * метода гребня або скользящйого окна для каждой точки P і Q.
 *
 * @param ctx контекст еліптичної кривої
 * @param precomp_p предварительные обчислення для точки P
 * @param m число на яке умножается p
 * @param precomp_q предварительные обчислення для точки Q
 * @param n число на яке умножается q
 * @param r = m * P + n * Q
 */
int ecp_dual_mul_opt(EcGfpCtx *ctx, const EcPrecomp *p_precomp, const WordArray *m,
        const EcPrecomp *q_precomp, const WordArray *n, ECPoint *r);

void ecp_free(EcGfpCtx *ctx);

#ifdef  __cplusplus
}
#endif

#endif
