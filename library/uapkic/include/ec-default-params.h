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

#ifndef UAPKIC_EC_DEFAULT_PARAMS_H
#define UAPKIC_EC_DEFAULT_PARAMS_H

#include <stdint.h>
#include <stdbool.h>

#ifdef  __cplusplus
extern "C" {
#endif

/**
  * Iдентифікатори стандартних параметрів еліптичних кривих.
  */

typedef enum {
    EC_PARAMS_ID_UNDEFINED = 0,
    EC_PARAMS_ID_DSTU4145_M163_PB = 1,
    EC_PARAMS_ID_DSTU4145_M167_PB = 2,
    EC_PARAMS_ID_DSTU4145_M173_PB = 3,
    EC_PARAMS_ID_DSTU4145_M179_PB = 4,
    EC_PARAMS_ID_DSTU4145_M191_PB = 5,
    EC_PARAMS_ID_DSTU4145_M233_PB = 6,
    EC_PARAMS_ID_DSTU4145_M257_PB = 7,
    EC_PARAMS_ID_DSTU4145_M307_PB = 8,
    EC_PARAMS_ID_DSTU4145_M367_PB = 9,
    EC_PARAMS_ID_DSTU4145_M431_PB = 10,
    EC_PARAMS_ID_DSTU4145_M173_ONB = 11,
    EC_PARAMS_ID_DSTU4145_M179_ONB = 12,
    EC_PARAMS_ID_DSTU4145_M191_ONB = 13,
    EC_PARAMS_ID_DSTU4145_M233_ONB = 14,
    EC_PARAMS_ID_DSTU4145_M431_ONB = 15,
    EC_PARAMS_ID_NIST_P192 = 16,
    EC_PARAMS_ID_NIST_P224 = 17,
    EC_PARAMS_ID_NIST_P256 = 18,
    EC_PARAMS_ID_NIST_P384 = 19,
    EC_PARAMS_ID_NIST_P521 = 20,
    EC_PARAMS_ID_NIST_B163 = 21,
    EC_PARAMS_ID_NIST_B233 = 22,
    EC_PARAMS_ID_NIST_B283 = 23,
    EC_PARAMS_ID_NIST_B409 = 24,
    EC_PARAMS_ID_NIST_B571 = 25,
    EC_PARAMS_ID_NIST_K163 = 26,
    EC_PARAMS_ID_NIST_K233 = 27,
    EC_PARAMS_ID_NIST_K283 = 28,
    EC_PARAMS_ID_NIST_K409 = 29,
    EC_PARAMS_ID_NIST_K571 = 30,
    EC_PARAMS_ID_SEC_P256_K1 = 31,
    EC_PARAMS_ID_BRAINPOOL_P224_R1 = 32,
    EC_PARAMS_ID_BRAINPOOL_P256_R1 = 33,
    EC_PARAMS_ID_BRAINPOOL_P384_R1 = 34,
    EC_PARAMS_ID_BRAINPOOL_P512_R1 = 35,
    EC_PARAMS_ID_GOST_P256_A = 36,
    EC_PARAMS_ID_GOST_P256_B = 37,
    EC_PARAMS_ID_GOST_P256_C = 38,
    EC_PARAMS_ID_GOST_P512_A = 39,
    EC_PARAMS_ID_GOST_P512_B = 40,
    EC_PARAMS_ID_SM2_P256 = 41,
    EC_PARAMS_ID_CN_P256 = 42,
    EC_PARAMS_ID_CN_B257 = 43,
    EC_PARAMS_ID_DSTU4145_M163_PB_TEST = 44,
    EC_PARAMS_ID_GOST_P256_TEST = 45
} EcParamsId;

typedef enum {
    EC_FIELD_PRIME,
    EC_FIELD_BINARY
} EcFieldType;

typedef struct EcpDefaultParamsCtx_st {
    int len;
    uint8_t a[72];        /**< Коэффициент a в уравнении эллиптической кривой. */
    uint8_t b[72];        /**< Коэффициент b в уравнении эллиптической кривой. */
    uint8_t p[72];        /**< Порядок конечного простого поля. */
    uint8_t n[72];        /**< Порядок подгруппы точек эллиптической кривой. */
    uint8_t px[72];       /**< Базовая точка эллиптической кривой. */
    uint8_t py[72];       /**< Базовая точка эллиптической кривой. */
} EcpDefaultParamsCtx;

typedef struct Ec2mDefaultParamsCtx_st {
    int f[5];
    size_t a;
    uint8_t b[72];
    uint8_t n[72];
    uint8_t px[72];
    uint8_t py[72];
    bool is_onb;
} Ec2mDefaultParamsCtx;

const void *ec_get_defaut_params(EcParamsId params_id, EcFieldType *field_type);

#ifdef __cplusplus
}
#endif

#endif
