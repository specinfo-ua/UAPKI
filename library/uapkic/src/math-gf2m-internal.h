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

#ifndef UAPKIC_MATH_GF2M_H
#define UAPKIC_MATH_GF2M_H

#include <stdbool.h>
#include "word-internal.h"

# ifdef  __cplusplus
extern "C" {
# endif

typedef struct Gf2mCtx_st {
    int *f;
    WordArray *f_ext;
    size_t len;
    word_t fr_lo;
    word_t fr_hi;
    int hw2;
    int clmul;
} Gf2mCtx;

/* Максимальний степінь многочлена, що породжує поле: DSTU 4145 — до 431, NIST B/K-571 — 571, DSTU 7624 (GCM/XTS) — до 512. */
#define GF2M_MAX_BIT_LENGTH 1024
/* Максимальна довжина елемента поля в словах (gf2m_init: len = (f[0] >> WORD_BIT_LEN_SHIFT) + 1). */
#define GF2M_MAX_LEN ((GF2M_MAX_BIT_LENGTH >> WORD_BIT_LEN_SHIFT) + 1)

Gf2mCtx *gf2m_alloc(const int *f, size_t f_len);

/**
 * Виконує додавання в полі GF(2^m).
 * out = a + b
 *
 * @param a перший доданок
 * @param b другий доданок
 * @param out буфер для результату
 */
void gf2m_mod_add(const WordArray *a, const WordArray *b, WordArray *out);

/**
 * Виконує піднесення до квадрата в полі GF(2^m).
 * out = (a * a) mod p
 *
 * @param ctx Параметри GF(2^m)
 * @param a елемент поля
 * @param out буфер для a^2
 */
void gf2m_mod_sqr(const Gf2mCtx *ctx, const WordArray *a, WordArray *out);

/**
 * Виконує множення в полі GF(2^m).
 * out = (a * b) mod p
 *
 * @param ctx Параметри GF(2^m)
 * @param a перший множник
 * @param b другий множник
 * @param out буфер для добутку
 */
void gf2m_mod_mul(const Gf2mCtx *ctx, const WordArray *a, const WordArray *b, WordArray *out);

/**
 * Обчислює обернений елемент у полі GF(2^m).
 *
 * @param ctx Параметри GF(2^m)
 * @param a елемент поля
 * @param out буфер для оберненого до a елемента
 */
void gf2m_mod_inv(const Gf2mCtx *ctx, const WordArray *a, WordArray *out);

/**
 * Виконує пошук найбільшого спільного дільника двох многочленів.
 *
 * @param a многочлен
 * @param b многочлен
 * @param gcd буфер для найбільшого спільного дільника або NULL
 * @param ka буфер для множника при a або NULL
 * @param kb буфер для множника при b або NULL
 */
void gf2m_mod_gcd(const WordArray *a, const WordArray *b, WordArray *gcd, WordArray *ka, WordArray *kb);

/**
 * Обчислює слід елемента в полі GF(2^m).
 *
 * @param ctx Параметри GF(2^m)
 * @param a елемент поля
 *
 * @return слід елемента
 */
int gf2m_mod_trace(const Gf2mCtx *ctx, const WordArray *a);

/**
 * Знаходить корінь квадратного рівняння x^2 + x = a в полі GF(2^m).
 *
 * @param ctx Параметри GF(2^m)
 * @param a вільний член
 * @param out буфер для кореня розміром n
 *
 * @return true - рівняння має розв'язок, <br>
 *         false - рівняння не має розв'язку.
 */
bool gf2m_mod_solve_quad(const Gf2mCtx *ctx, const WordArray *a, WordArray *out);

/**
 * Знаходить квадратний корінь елемента в полі GF(2^m).
 *
 * @param ctx Параметри GF(2^m)
 * @param a елемент поля
 * @param out буфер для квадратного кореня розміром n
 */
void gf2m_mod_sqrt(const Gf2mCtx *ctx, const WordArray *a, WordArray *out);

/**
 * Створює копію контексту параметрів GF(2^m).
 *
 * @param ctx параметри GF(2^m)
 * @return копія контексту
 */
Gf2mCtx *gf2m_copy_with_alloc(const Gf2mCtx *ctx);

/**
 * Звільняє контекст параметрів GF(2^m).
 *
 * @param ctx Параметри GF(2^m)
 */
void gf2m_free(Gf2mCtx *ctx);


#ifdef  __cplusplus
}
#endif

#endif
