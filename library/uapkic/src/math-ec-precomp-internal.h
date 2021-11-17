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

#ifndef UAPKIC_MATH_EC_PRECOMP_H
#define UAPKIC_MATH_EC_PRECOMP_H

#include "math-ec-point-internal.h"

# ifdef  __cplusplus
extern "C" {
# endif

typedef enum EcPrecompType_st {
    EC_PRECOMP_TYPE_WIN,
    EC_PRECOMP_TYPE_COMB
} EcPrecompType;

typedef struct EcPrecompWin_st {
    ECPoint **precomp;
    int precomp_len;
    int win_width;
} EcPrecompWin;

typedef struct EcPrecompComb_st {
    ECPoint **precomp;
    int comb_width;
} EcPrecompComb;

/** Предварительные обчислення. */
typedef struct EcPrecomp_st {
    EcPrecompType type;
    union {
        EcPrecompWin *win;
        EcPrecompComb *comb;
    } ctx;
} EcPrecomp;

/**
 * Створює копію контексту попередніх обчислень.
 *
 * @param ctx контекст попередні обчислення
 * @return копія контексту
 */
EcPrecomp *ec_copy_precomp_with_alloc(EcPrecomp *precomp_p);

void ec_precomp_free(EcPrecomp *precomp);

#ifdef  __cplusplus
}
#endif

#endif
