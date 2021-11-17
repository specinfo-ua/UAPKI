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

#ifndef UAPKIC_MATH_GFP_H
#define UAPKIC_MATH_GFP_H

#include <stdbool.h>

#include "word-internal.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct GfpCtx_st {
    WordArray *p;
    WordArray *one;
    WordArray *two;
    WordArray *invert_const;
} GfpCtx;

GfpCtx *gfp_alloc(const WordArray *p);
GfpCtx *gfp_copy_with_alloc(const GfpCtx *ctx);
void gfp_init(GfpCtx *ctx, const WordArray *p);
void gfp_mod_add(const GfpCtx *ctx, const WordArray *a, const WordArray *b, WordArray *out);
void gfp_mod_sub(const GfpCtx *ctx, const WordArray *a, const WordArray *b, WordArray *out);
void gfp_mod(const GfpCtx *ctx, const WordArray *a, WordArray *out);
void gfp_mod_mul(const GfpCtx *ctx, const WordArray *a, const WordArray *b, WordArray *out);
void gfp_mod_sqr(const GfpCtx *ctx, const WordArray *a, WordArray *out);
WordArray *gfp_mod_inv(const GfpCtx *ctx, const WordArray *a);
void gfp_mod_pow(const GfpCtx *ctx, const WordArray *a, const WordArray *x, WordArray *out);
void gfp_mod_dual_pow(const GfpCtx *ctx, const WordArray *a, const WordArray *x,
        const WordArray *b, const WordArray *y, WordArray *out);

/**
 * Вычисляет один из квадратных корней элемента поля GF(p).
 *
 * @param a элемент поля
 * @param out массив для a^(1/2) (mod p)
 *
 * @return можно ли получить корень
 */
bool gfp_mod_sqrt(const GfpCtx *ctx, const WordArray *a, WordArray *out);

void gfp_free(GfpCtx *ctx);

WordArray *gfp_mod_inv_core(const WordArray *in, const WordArray *p);

#ifdef  __cplusplus
}
#endif

#endif
