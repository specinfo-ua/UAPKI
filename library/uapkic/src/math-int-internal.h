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

#ifndef UAPKIC_MATH_INT_H
#define UAPKIC_MATH_INT_H

#include <stdbool.h>

#include "word-internal.h"

#define WORD_MASK (word_t)(-1)
#define MAX_WORD (dword_t)((dword_t)WORD_MASK + 1)

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct Dword_st {
    word_t lo;
    word_t hi;
} Dword;

/**
 * Перевіряє рівність нулю великого цілого числа.
 *
 * @param a велике ціле число
 *
 * @return true - число дорівнює нулю, false - число не дорівнює нулю
 */
bool int_is_zero(const WordArray *a);

/**
 * Перевіряє рівність одиниці великого цілого числа.
 *
 * @param a велике ціле число
 *
 * @return true - число дорівнює одиниці, false - число не дорівнює одиниці
 */
bool int_is_one(const WordArray *a);

/**
 * Перевіряє рівність двох великих цілих чисел.
 *
 * @param a велике ціле число
 * @param b велике ціле число
 *
 * @return true - числа рівні, false - числа не рівні
 */
bool int_equals(const WordArray *a, const WordArray *b);

/**
 * Порівнює два великих цілих числа.
 *
 * @param a велике ціле число
 * @param b велике ціле число
 *
 * @return 0 - якщо a = b, -1 - якщо a < b, 1 - якщо a > b
 */
int int_cmp(const WordArray *a, const WordArray *b);

/**
 * Обчислює суму двох великих цілих чисел.
 * out = a + b.
 *
 * @param a велике ціле число довжиною n
 * @param b велике ціле число довжиною n
 * @param out буфер для суми двох великих цілих чисел довжиною n
 *
 * @return перенесення після додавання: 0 або 1
 */
word_t int_add(const WordArray *a, const WordArray *b, WordArray *out);

/**
 * Обчислює різницю двох великих цілих чисел.
 * out = a - b.
 *
 * @param a велике ціле число довжиною n
 * @param b велике ціле число довжиною n
 * @param out буфер для різниці двох великих цілих чисел довжиною n
 *
 * @return позика після віднімання: 0 або -1
 */
int int_sub(const WordArray *a, const WordArray *b, WordArray *out);

/**
 * Повертає довжину великого цілого числа в словах без старших нулів.
 *
 * @param a велике ціле число
 *
 * @return довжина великого цілого числа в словах без старших нулів
 */
size_t int_word_len(const WordArray *a);

/**
 * Повертає довжину в бітах великого цілого числа.
 *
 * @param a велике ціле число
 *
 * @return довжина великого цілого в бітах
 */
size_t int_bit_len(const WordArray *a);

/**
 * Виконує усікання великого цілого числа до заданої кількості бітів.
 *
 * @param a велике ціле число
 * @param bit_len кількість бітів, що залишаються
 */
void int_truncate(WordArray *a, size_t bit_len);

/**
 * Повертає заданий біт великого цілого числа.
 *
 * @param a велике ціле число
 * @param bit_num номер біта
 *
 * @return заданий біт числа
 */
int int_get_bit(const WordArray *a, size_t bit_num);

/**
 * Зсуває велике ціле на задану кількість бітів уліво.
 *
 * @param a велике ціле число
 * @param shift величина зсуву в бітах
 * @param out буфер для результату зсуву
 */
void int_lshift(const WordArray *a, size_t shift, WordArray *out);

/**
 * Зсуває велике ціле на задану кількість бітів управо.
 *
 * @param a_hi старше слово "a"
 * @param a велике ціле число
 * @param shift величина зсуву в бітах
 * @param out буфер для результату зсуву
 */
void int_rshift(word_t a_hi, const WordArray *a, size_t shift, WordArray *out);

/**
 * Обчислює добуток двох великих цілих чисел.
 *
 * @param a перше велике число довжиною n
 * @param b друге велике число довжиною n
 * @param out буфер для добутку довжиною 2n
 */
void int_mul(const WordArray *a, const WordArray *b, WordArray *out);

/**
 * Обчислює квадрат великого цілого числа.
 *
 * @param a велике число довжиною n
 * @param out буфер для результату довжиною 2n
 */
void int_sqr(const WordArray *a, WordArray *out);

/**
 * Обчислює частку та остачу від ділення великих цілих чисел.
 * a = q * b + r
 *
 * @param a ділене довжиною 2n
 * @param b дільник довжиною n
 * @param q буфер для частки довжиною 2n або NULL
 * @param r буфер для остачі довжиною n або NULL
 */
void int_div(const WordArray *a, const WordArray *b, WordArray *q, WordArray *r);

/**
 * Обчислює цілу частину квадратного кореня.
 * Використовується метод Ньютона.
 *
 * @param in велике ціле число
 * @param out ціла частина квадратного кореня з in
 */
void int_sqrt(const WordArray *in, WordArray *out);

int int_rand(const WordArray *in, WordArray *out);
int int_prand(const WordArray *in, WordArray *out);

int int_is_prime(WordArray *a, bool *is_prime);

int int_rabin_miller_primary_test(WordArray *num, bool *is_prime);

int int_fermat_primary_test(WordArray *num, bool *is_prime);

void factorial(size_t n, WordArray *fac);

/**
 * Обчислює a * b / c.
 *
 * Необхідно, щоб b <= c.
 *
 * @param a велике ціле довжиною n
 * @param b ціле
 * @param c ціле
 * @param n розмір a у словах
 * @param abc масив для результату довжиною n
 *
 * @return код помилки в разі помилки виділення пам'яті
 */
int int_mult_and_div(const WordArray *a, word_t b, word_t c, int n, WordArray *abc);

int int_get_naf(const WordArray *in, int width, int **out);

int int_get_naf_extra_add(const WordArray *in, const int *naf, int width, int *extra_addition);

int int_gen_prime(const size_t bits, WordArray **out);

#ifdef  __cplusplus
}
#endif

#endif
