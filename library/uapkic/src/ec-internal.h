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

#ifndef UAPKIC_EC_INTERNAL_H
#define UAPKIC_EC_INTERNAL_H

#include <stdint.h>
#include <stdbool.h>

#include "byte-array.h"
#include "word-internal.h"
#include "ec.h"
#include "math-ec-point-internal.h"
#include "math-ec2m-internal.h"
#include "math-ecp-internal.h"

#define EC_DEFAULT_WIN_WIDTH 5

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct EcParamsCtx_st EcParamsCtx;

struct EcParamsCtx_st {
    EcFieldType ec_field;           /* Тип основного поля (просте чи розширене) */
    ECPoint* p;                     /* Базова точка (генератор підгрупи) */
    WordArray* n;                   /* Порядок підгрупи групи точок еліптичної кривої. */
    EcGfpCtx* ecp;                  /* Параметри простого поля */
    EcGf2mCtx* ec2m;                /* Параметри розширеного поля поля */
    bool is_onb;                    /* Чи є формат подання у розширеному полі ОНБ */
    size_t m;                       /* Степінь основного поля (ОНБ) */
    WordArray** to_pb;              /* Матриця перетворення елемента з ОНБ у ПБ */
    WordArray** to_onb;             /* Матриця перетворення елемента з ПБ у ОНБ */
    EcParamsId params_id;           /* Ідентифікатор стандартних параметрів */
    EcPrecomp* precomp_p;
};

struct EcCtx_st {
    EcParamsCtx* params;            /* Параметри єліптичної кривої */
    WordArray* priv_key;            /* Особистий ключ */
    ECPoint* pub_key;               /* Відкритий ключ */
    EcPrecomp* precomp_q;
    bool sign_status;               /* Готовність контексту для формування підпису */
    bool verify_status;             /* Готовність контексту для перевірки підпису */
};

EcCtx* ec_alloc_new(EcParamsId params_id);

EcCtx* ec_alloc_prime_new(const ByteArray* p, const ByteArray* a, const ByteArray* b, const ByteArray* q,
    const ByteArray* px, const ByteArray* py);

EcCtx* ec_alloc_binary_pb_new(const int* f, size_t f_len, size_t a, const ByteArray* b, const ByteArray* n,
    const ByteArray* px, const ByteArray* py);

EcCtx* ec_alloc_binary_onb_new(size_t m, size_t a, const ByteArray* b, const ByteArray* n, const ByteArray* px,
    const ByteArray* py);

int ec_set_sign_precomp(const EcCtx* ctx, int sign_comb_opt_level, int sign_win_opt_level);

int ec_set_verify_precomp(EcCtx* ctx, int verify_comb_opt_level, int verify_win_opt_level);

const int *get_defaut_f_onb(size_t m);

int init_onb_params(EcParamsCtx *params, size_t m);

/**
 * Преобразовывает елемент з ОНБ в ПБ.
 *
 * @param params Параметри
 * @param x елемент поля
 */
int onb_to_pb(const EcParamsCtx *params, WordArray *x);

/**
 * Выполняет преобразование элемента поля GF(2^m) из ПБ в ОНБ.
 *
 * @param params параметры криптосистемы
 * @param x элемент поля
 */
int pb_to_onb(const EcParamsCtx *params, WordArray *x);

int ec2m_decompress_point_core(const EcParamsCtx* params, const ByteArray* x, int compressed_y, ByteArray** x_out, ByteArray** y_out);

int public_key_to_ec_point(const EcParamsCtx* params, const ByteArray* qx, const ByteArray* qy, ECPoint** q);

/**
 * Генерує особистий ключ для будь якого алгоритму підпису або Д-Х на ЕК.
 *
 * @param ctx контекст ЕК
 * @param d особистий ключ
 * @return код помилки
 */
int ec_generate_privkey(const EcCtx* ctx, ByteArray** d);

#ifdef  __cplusplus
}
#endif

#endif
