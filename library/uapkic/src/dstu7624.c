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

#include <stdio.h>
#include <memory.h>

#include "dstu7624.h"
#include "drbg.h"
#include "paddings.h"
#include "byte-utils-internal.h"
#include "byte-array-internal.h"
#include "math-gf2m-internal.h"
#include "macros-internal.h"

#undef FILE_MARKER
#define FILE_MARKER "uapkic/dstu7624.c"

#define REDUCTION_POLYNOMIAL 0x11d  /* x^8 + x^4 + x^3 + x^2 + 1 */
#define ROWS 8
#define MAX_NUM_IN_BYTE 256
#define MAX_BLOCK_LEN 64
#define BITS_IN_BYTE 8
#define KALINA_128_KEY_LEN 16
#define KALINA_256_KEY_LEN 32
#define KALINA_512_KEY_LEN 64
#define KALINA_128_BLOCK_LEN 16
#define KALINA_256_BLOCK_LEN 32
#define KALINA_512_BLOCK_LEN 64
#define SBOX_LEN 1024

#define GALUA_MUL(i, j, k, shift) (uint64_t)((uint64_t)multiply_galua(mds[j * ROWS + k], s_blocks[(k % 4) * MAX_NUM_IN_BYTE + i]) << ((uint64_t)shift))

typedef enum {
    DSTU7624_MODE_ECB,
    DSTU7624_MODE_CTR,
    DSTU7624_MODE_OFB,
    DSTU7624_MODE_CFB,
    DSTU7624_MODE_CBC,
    DSTU7624_MODE_CMAC,
    DSTU7624_MODE_KW,
    DSTU7624_MODE_XTS,
    DSTU7624_MODE_CCM,
    DSTU7624_MODE_GCM,
    DSTU7624_MODE_GMAC
} Dstu7624Mode;

typedef struct Dstu7624CtrCtx_st {
    uint8_t gamma[64];
    uint8_t feed[64];
    size_t used_gamma_len;
} Dstu7624CtrCtx;

typedef struct Dstu7624OfbCtx_st {
    uint8_t gamma[64];
    size_t used_gamma_len;
} Dstu7624OfbCtx;

typedef struct Dstu7624CbcCtx_st {
    uint8_t gamma[64];
} Dstu7624CbcCtx;

typedef struct Dstu7624CfbCtx_st {
    size_t q;
    uint8_t gamma[64];
    uint8_t feed[64];
    size_t used_gamma_len;
} Dstu7624CfbCtx;

typedef struct Dstu7624GmacCtx_st {
    uint64_t H[8];
    uint64_t B[8];
    uint8_t last_block[MAX_BLOCK_LEN];
    size_t last_block_len;
    size_t msg_tot_len;
    size_t q;
    Gf2mCtx *gf2m_ctx;
} Dstu7624GmacCtx;

typedef struct Dstu7624GcmCtx_st {
    uint64_t iv[8];
    size_t q;
    Gf2mCtx *gf2m_ctx;
} Dstu7624GcmCtx;

typedef struct Dstu7624CcmCtx_st {
    size_t q;
    const ByteArray *key;
    const ByteArray *iv_tmp;
    uint8_t iv[MAX_BLOCK_LEN];
    size_t nb;
} Dstu7624CcmCtx;

typedef struct Dstu7624XtsCtx_st {
    uint8_t iv[64];
    Gf2mCtx *gf2m_ctx;
} Dstu7624XtsCtx;

typedef struct Dstu7624CmacCtx_st {
    size_t q;
    uint8_t last_block[ROWS * ROWS];
    size_t lblock_len;
} Dstu7624CmacCtx;

struct Dstu7624Ctx_st {
    Dstu7624Mode mode_id;
    uint64_t p_boxrowcol[ROWS][MAX_NUM_IN_BYTE];
    uint64_t p_inv_boxrowcol[ROWS][MAX_NUM_IN_BYTE];
    uint8_t s_blocks[SBOX_LEN];
    uint8_t inv_s_blocks[SBOX_LEN];
    uint64_t p_rkeys[MAX_BLOCK_LEN * 20];
    uint64_t p_rkeys_rev[MAX_BLOCK_LEN * 20];
    uint64_t state[ROWS];
    size_t key_len;
    size_t block_len;
    size_t rounds;

    union {
        Dstu7624CtrCtx ctr;
        Dstu7624OfbCtx ofb;
        Dstu7624CbcCtx cbc;
        Dstu7624CfbCtx cfb;
        Dstu7624GmacCtx gmac;
        Dstu7624GcmCtx gcm;
        Dstu7624CcmCtx ccm;
        Dstu7624XtsCtx xts;
        Dstu7624CmacCtx cmac;
    } mode;

    void (*basic_transform)(Dstu7624Ctx *, uint64_t *);
    void (*subrowcol)(uint64_t *, Dstu7624Ctx *); /*store pointer on each subshiftmix for all block size type*/
    void (*subrowcol_dec)(Dstu7624Ctx *, uint64_t *); /*store pointer on each subshiftmix for all block size type*/
};


/*
 *             KALYNA G DEFINITION
 * Macros for fast calculating m_col operation.
 * G128, G256, G512 - block length in bits
 * big_table - precomputed table of s_box and m_col operations (uint8_t)
 * in - data before s_box and m_col operations (uint64_t)
 * out - data after m_col operation (uint64_t)
 * z0...z7 - columns number
 * Example:
 * G128 - 128 bit, 16 byte block, kalyna representation state: 8x2, 2 columns,
 * there will be only 4 last values shifted, z0,...,z3 == 0, z4,...,z7 == 1.
 * It means, than z4,...,z7 will be taken from the next column
 */
#define kalyna_G128(big_table, in, out, z0, z1, z2, z3, z4, z5, z6, z7)\
        out[0] =(uint64_t)big_table[ 0 ] [( (in[ z0 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z1 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z2 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z3 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z4 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z5 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z6 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z7 ] >> ( 7 * 8) ) & 0xFF)];\
        out[1] =(uint64_t)big_table[ 0 ] [( (in[ z4 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z5 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z6 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z7 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z0 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z1 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z2 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z3 ] >> ( 7 * 8) ) & 0xFF)]

#define kalyna_G256(big_table, in, out, z0, z1, z2, z3, z4, z5, z6, z7)\
        out[0] =(uint64_t)big_table[ 0 ] [( (in[ z0 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z1 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z2 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z3 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z4 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z5 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z6 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z7 ] >> ( 7 * 8) ) & 0xFF)];\
        out[1] =(uint64_t)big_table[ 0 ] [( (in[ z7 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z6 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z0 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z1 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z2 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z3 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z4 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z5 ] >> ( 7 * 8) ) & 0xFF)];\
        out[2] =(uint64_t)big_table[ 0 ] [( (in[ z4 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z5 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z6 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z7 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z0 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z1 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z2 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z3 ] >> ( 7 * 8) ) & 0xFF)];\
        out[3] =(uint64_t)big_table[ 0 ] [( (in[ z2 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z3 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z4 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z5 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z6 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z7 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z0 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z1 ] >> ( 7 * 8) ) & 0xFF)]

#define kalyna_G512(big_table, in, out, z0, z1, z2, z3, z4, z5, z6, z7)\
        out[0] =(uint64_t)big_table[ 0 ] [( (in[ z0 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z1 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z2 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z3 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z4 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z5 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z6 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z7 ] >> ( 7 * 8) ) & 0xFF)];\
        out[1] =(uint64_t)big_table[ 0 ] [( (in[ z7 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z0 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z1 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z2 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z3 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z4 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z5 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z6 ] >> ( 7 * 8) ) & 0xFF)];\
        out[2] =(uint64_t)big_table[ 0 ] [( (in[ z6 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z7 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z0 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z1 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z2 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z3 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z4 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z5 ] >> ( 7 * 8) ) & 0xFF)];\
        out[3] =(uint64_t)big_table[ 0 ] [( (in[ z5 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z6 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z7 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z0 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z1 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z2 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z3 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z4 ] >> ( 7 * 8) ) & 0xFF)];\
        out[4] =(uint64_t)big_table[ 0 ] [( (in[ z4 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z5 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z6 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z7 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z0 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z1 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z2 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z3 ] >> ( 7 * 8) ) & 0xFF)];\
        out[5] =(uint64_t)big_table[ 0 ] [( (in[ z3 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z4 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z5 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z6 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z7 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z0 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z1 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z2 ] >> ( 7 * 8) ) & 0xFF)];\
        out[6] =(uint64_t)big_table[ 0 ] [( (in[ z2 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z3 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z4 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z5 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z6 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z7 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z0 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z1 ] >> ( 7 * 8) ) & 0xFF)];\
        out[7] =(uint64_t)big_table[ 0 ] [( (in[ z1 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z2 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z3 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z4 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z5 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z6 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z7 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z0 ] >> ( 7 * 8) ) & 0xFF)]

static void kalyna_add(uint64_t *in, uint64_t *out, size_t size)
{
    switch (size) {
    case 2:
        out[0] += in[0];
        out[1] += in[1];
        break;
    case 4:
        out[0] += in[0];
        out[1] += in[1];
        out[2] += in[2];
        out[3] += in[3];
        break;
    case 8:
        out[0] += in[0];
        out[1] += in[1];
        out[2] += in[2];
        out[3] += in[3];
        out[4] += in[4];
        out[5] += in[5];
        out[6] += in[6];
        out[7] += in[7];
        break;
    default:
        break;
    }
}

/*memory safe xor*/
static void kalyna_xor(void *arg1, void *arg2, size_t len, void *out)
{
    uint8_t *a8, *b8, *o8;
    size_t i;

    // побайтно бо на деяких платформах не підтримується 32 або 64 бітовий 
    // доступ до даніх не вирівняних на 4 або 8 байт відповідно
    a8 = (uint8_t *) arg1;
    b8 = (uint8_t *) arg2;
    o8 = (uint8_t *) out;
    for (i = 0; i < len; i++) {
        o8[i] = a8[i] ^ b8[i];
    }
}

/*s_box, s_row, m_col, xor operations*/
static void sub_shift_mix_xor(uint64_t *key, uint64_t *state, Dstu7624Ctx *ctx)
{
    ctx->subrowcol(state, ctx);
    kalyna_xor(state, key, ctx->block_len, state);
}

/*s_box, s_row, m_col, add operations*/
static void sub_shift_mix_add(uint64_t *key, uint64_t *state, Dstu7624Ctx *ctx)
{
    ctx->subrowcol(state, ctx);
    kalyna_add(key, state, ctx->block_len >> 3);
}

/*Matrix for m_col operation*/
static const uint8_t mds_matrix[MAX_BLOCK_LEN] = {
    0x01, 0x01, 0x05, 0x01, 0x08, 0x06, 0x07, 0x04,
    0x04, 0x01, 0x01, 0x05, 0x01, 0x08, 0x06, 0x07,
    0x07, 0x04, 0x01, 0x01, 0x05, 0x01, 0x08, 0x06,
    0x06, 0x07, 0x04, 0x01, 0x01, 0x05, 0x01, 0x08,
    0x08, 0x06, 0x07, 0x04, 0x01, 0x01, 0x05, 0x01,
    0x01, 0x08, 0x06, 0x07, 0x04, 0x01, 0x01, 0x05,
    0x05, 0x01, 0x08, 0x06, 0x07, 0x04, 0x01, 0x01,
    0x01, 0x05, 0x01, 0x08, 0x06, 0x07, 0x04, 0x01
};

static const uint8_t mds_matrix_reverse[MAX_BLOCK_LEN] = {
    0xAD, 0x95, 0x76, 0xA8, 0x2F, 0x49, 0xD7, 0xCA,
    0xCA, 0xAD, 0x95, 0x76, 0xA8, 0x2F, 0x49, 0xD7,
    0xD7, 0xCA, 0xAD, 0x95, 0x76, 0xA8, 0x2F, 0x49,
    0x49, 0xD7, 0xCA, 0xAD, 0x95, 0x76, 0xA8, 0x2F,
    0x2F, 0x49, 0xD7, 0xCA, 0xAD, 0x95, 0x76, 0xA8,
    0xA8, 0x2F, 0x49, 0xD7, 0xCA, 0xAD, 0x95, 0x76,
    0x76, 0xA8, 0x2F, 0x49, 0xD7, 0xCA, 0xAD, 0x95,
    0x95, 0x76, 0xA8, 0x2F, 0x49, 0xD7, 0xCA, 0xAD
};

#define BT_xor128(in, out, rkey) {\
    uint64_t i0 = in[0];\
    uint64_t i1 = in[1];\
    out[0] =(uint64_t) ctx->p_boxrowcol[ 0 ] [((i0 >> (0 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 1 ] [((i0 >> (1 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 2 ] [((i0 >> (2 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 3 ] [((i0 >> (3 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 4 ] [((i1 >> (4 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 5 ] [((i1 >> (5 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 6 ] [((i1 >> (6 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 7 ] [((i1 >> (7 * 8)) & 0xFF)]^*(rkey + 0);\
    out[1] =(uint64_t) ctx->p_boxrowcol[ 0 ] [((i1 >> (0 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 1 ] [((i1 >> (1 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 2 ] [((i1 >> (2 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 3 ] [((i1 >> (3 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 4 ] [((i0 >> (4 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 5 ] [((i0 >> (5 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 6 ] [((i0 >> (6 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 7 ] [((i0 >> (7 * 8)) & 0xFF)]^*(rkey + 1);\
}\

#define BT_add128(in, out, rkey) {\
    uint64_t i0 = in[0];\
    uint64_t i1 = in[1];\
    out[0] =((uint64_t) ctx->p_boxrowcol[ 0 ] [((i0 >> (0 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 1 ] [((i0 >> (1 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 2 ] [((i0 >> (2 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 3 ] [((i0 >> (3 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 4 ] [((i1 >> (4 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 5 ] [((i1 >> (5 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 6 ] [((i1 >> (6 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 7 ] [((i1 >> (7 * 8)) & 0xFF)]) + *(rkey + 0);\
    out[1] =((uint64_t) ctx->p_boxrowcol[ 0 ] [((i1 >> (0 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 1 ] [((i1 >> (1 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 2 ] [((i1 >> (2 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 3 ] [((i1 >> (3 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 4 ] [((i0 >> (4 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 5 ] [((i0 >> (5 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 6 ] [((i0 >> (6 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 7 ] [((i0 >> (7 * 8)) & 0xFF)]) + *(rkey + 1);\
}\

#define BT_xor256(in, out, rkey){\
    uint64_t i0 = in[0];\
    uint64_t i1 = in[1];\
    uint64_t i2 = in[2];\
    uint64_t i3 = in[3];\
    out[0] =    (uint64_t) ctx->p_boxrowcol[ 0 ] [((i0 >> (0 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 1 ] [((i0 >> (1 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 2 ] [((i3 >> (2 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 3 ] [((i3 >> (3 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 4 ] [((i2 >> (4 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 5 ] [((i2 >> (5 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 6 ] [((i1 >> (6 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 7 ] [((i1 >> (7 * 8)) & 0xFF)] ^ *(rkey + 0);\
    out[1] =    (uint64_t) ctx->p_boxrowcol[ 0 ] [((i1 >> (0 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 1 ] [((i1 >> (1 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 2 ] [((i0 >> (2 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 3 ] [((i0 >> (3 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 4 ] [((i3 >> (4 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 5 ] [((i3 >> (5 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 6 ] [((i2 >> (6 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 7 ] [((i2 >> (7 * 8)) & 0xFF)] ^ *(rkey + 1);\
    out[2] =    (uint64_t) ctx->p_boxrowcol[ 0 ] [((i2 >> (0 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 1 ] [((i2 >> (1 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 2 ] [((i1 >> (2 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 3 ] [((i1 >> (3 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 4 ] [((i0 >> (4 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 5 ] [((i0 >> (5 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 6 ] [((i3 >> (6 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 7 ] [((i3 >> (7 * 8)) & 0xFF)] ^ *(rkey + 2);\
    out[3] =  (uint64_t) ctx->p_boxrowcol[ 0 ] [((i3 >> (0 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 1 ] [((i3 >> (1 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 2 ] [((i2 >> (2 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 3 ] [((i2 >> (3 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 4 ] [((i1 >> (4 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 5 ] [((i1 >> (5 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 6 ] [((i0 >> (6 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 7 ] [((i0 >> (7 * 8)) & 0xFF)] ^ *(rkey + 3);\
}\

#define BT_add256(in, out, rkey){\
    uint64_t i0 = in[0];\
    uint64_t i1 = in[1];\
    uint64_t i2 = in[2];\
    uint64_t i3 = in[3];\
    out[0] =    ((uint64_t) ctx->p_boxrowcol[ 0 ] [((i0 >> (0 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 1 ] [((i0 >> (1 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 2 ] [((i3 >> (2 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 3 ] [((i3 >> (3 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 4 ] [((i2 >> (4 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 5 ] [((i2 >> (5 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 6 ] [((i1 >> (6 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 7 ] [((i1 >> (7 * 8)) & 0xFF)]) + *(rkey + 0);\
    out[1] =    ((uint64_t) ctx->p_boxrowcol[ 0 ] [((i1 >> (0 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 1 ] [((i1 >> (1 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 2 ] [((i0 >> (2 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 3 ] [((i0 >> (3 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 4 ] [((i3 >> (4 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 5 ] [((i3 >> (5 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 6 ] [((i2 >> (6 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 7 ] [((i2 >> (7 * 8)) & 0xFF)]) + *(rkey + 1);\
    out[2] =    ((uint64_t) ctx->p_boxrowcol[ 0 ] [((i2 >> (0 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 1 ] [((i2 >> (1 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 2 ] [((i1 >> (2 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 3 ] [((i1 >> (3 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 4 ] [((i0 >> (4 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 5 ] [((i0 >> (5 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 6 ] [((i3 >> (6 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 7 ] [((i3 >> (7 * 8)) & 0xFF)]) + *(rkey + 2);\
    out[3] =  ((uint64_t) ctx->p_boxrowcol[ 0 ] [((i3 >> (0 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 1 ] [((i3 >> (1 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 2 ] [((i2 >> (2 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 3 ] [((i2 >> (3 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 4 ] [((i1 >> (4 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 5 ] [((i1 >> (5 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 6 ] [((i0 >> (6 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 7 ] [((i0 >> (7 * 8)) & 0xFF)]) + *(rkey + 3);\
}\

#define BT_xor512(in, out, rkey) {\
        uint64_t i0 = in[0];\
        uint64_t i1 = in[1];\
        uint64_t i2 = in[2];\
        uint64_t i3 = in[3];\
        uint64_t i4 = in[4];\
        uint64_t i5 = in[5];\
        uint64_t i6 = in[6];\
        uint64_t i7 = in[7];\
        out[0] =(uint64_t)ctx->p_boxrowcol[ 0 ] [( (i0 >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i7 >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i6 >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i5 >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i4 >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i3 >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i2 >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i1 >> ( 7 * 8) ) & 0xFF)] ^ *(rkey + 0);\
        out[1] =(uint64_t)ctx->p_boxrowcol[ 0 ] [( (i1 >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i0 >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i7 >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i6 >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i5 >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i4 >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i3 >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i2 >> ( 7 * 8) ) & 0xFF)] ^ *(rkey + 1);\
        out[2] =(uint64_t)ctx->p_boxrowcol[ 0 ] [( (i2 >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i1 >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i0 >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i7 >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i6 >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i5 >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i4 >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i3 >> ( 7 * 8) ) & 0xFF)] ^ *(rkey + 2);\
        out[3] =(uint64_t)ctx->p_boxrowcol[ 0 ] [( (i3 >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i2 >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i1 >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i0 >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i7 >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i6 >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i5 >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i4 >> ( 7 * 8) ) & 0xFF)] ^ *(rkey + 3);\
        out[4] =(uint64_t)ctx->p_boxrowcol[ 0 ] [( (i4 >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i3 >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i2 >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i1 >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i0 >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i7 >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i6 >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i5 >> ( 7 * 8) ) & 0xFF)] ^ *(rkey + 4);\
        out[5] =(uint64_t)ctx->p_boxrowcol[ 0 ] [( (i5 >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i4 >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i3 >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i2 >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i1 >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i0 >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i7 >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i6 >> ( 7 * 8) ) & 0xFF)] ^ *(rkey + 5);\
        out[6] =(uint64_t)ctx->p_boxrowcol[ 0 ] [( (i6 >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i5 >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i4 >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i3 >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i2 >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i1 >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i0 >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i7 >> ( 7 * 8) ) & 0xFF)] ^ *(rkey + 6);\
        out[7] =(uint64_t)ctx->p_boxrowcol[ 0 ] [( (i7 >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i6 >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i5 >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i4 >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i3 >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i2 >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i1 >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i0 >> ( 7 * 8) ) & 0xFF)] ^ *(rkey + 7);\
}\

#define BT_add512(in, out, rkey) { \
        uint64_t i0 = in[0];\
        uint64_t i1 = in[1];\
        uint64_t i2 = in[2];\
        uint64_t i3 = in[3];\
        uint64_t i4 = in[4];\
        uint64_t i5 = in[5];\
        uint64_t i6 = in[6];\
        uint64_t i7 = in[7];\
        out[0] =((uint64_t)ctx->p_boxrowcol[ 0 ] [( (i0 >>  ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i7 >>  ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i6 >>  ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i5 >>  ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i4 >>  ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i3 >>  ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i2 >>  ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i1 >>  ( 7 * 8) ) & 0xFF)]) + *(rkey + 0);\
        out[1] =((uint64_t)ctx->p_boxrowcol[ 0 ] [( (i1 >>  ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i0 >>  ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i7 >>  ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i6 >>  ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i5 >>  ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i4 >>  ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i3 >>  ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i2 >>  ( 7 * 8) ) & 0xFF)]) + *(rkey + 1);\
        out[2] =((uint64_t)ctx->p_boxrowcol[ 0 ] [( (i2 >>  ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i1 >>  ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i0 >>  ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i7 >>  ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i6 >>  ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i5 >>  ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i4 >>  ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i3 >>  ( 7 * 8) ) & 0xFF)]) + *(rkey + 2);\
        out[3] =((uint64_t)ctx->p_boxrowcol[ 0 ] [( (i3 >>  ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i2 >>  ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i1 >>  ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i0 >>  ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i7 >>  ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i6 >>  ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i5 >>  ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i4 >>  ( 7 * 8) ) & 0xFF)]) + *(rkey + 3);\
        out[4] =((uint64_t)ctx->p_boxrowcol[ 0 ] [( (i4 >>  ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i3 >>  ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i2 >>  ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i1 >>  ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i0 >>  ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i7 >>  ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i6 >>  ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i5 >>  ( 7 * 8) ) & 0xFF)]) + *(rkey + 4);\
        out[5] =((uint64_t)ctx->p_boxrowcol[ 0 ] [( (i5 >>  ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i4 >>  ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i3 >>  ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i2 >>  ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i1 >>  ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i0 >>  ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i7 >>  ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i6 >>  ( 7 * 8) ) & 0xFF)]) + *(rkey + 5);\
        out[6] =((uint64_t)ctx->p_boxrowcol[ 0 ] [( (i6 >>  ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i5 >>  ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i4 >>  ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i3 >>  ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i2 >>  ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i1 >>  ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i0 >>  ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i7 >>  ( 7 * 8) ) & 0xFF)]) + *(rkey + 6);\
        out[7] =((uint64_t)ctx->p_boxrowcol[ 0 ] [( (i7 >>  ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i6 >>  ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i5 >>  ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i4 >>  ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i3 >>  ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i2 >>  ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i1 >>  ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i0 >>  ( 7 * 8) ) & 0xFF)]) + *(rkey + 7);\
}\

const uint64_t subrowcol_default[8][256] = {
    {
        0xa832a829d77f9aa8ULL, 0x4352432297d41143ULL, 0x5f3e5fc2df80615fULL, 0x061e063014121806ULL, 0x6bda6b7f670cb16bULL, 0x75bc758f2356c975ULL, 0x6cc16c477519ad6cULL, 0x592059f2cb927959ULL,
        0x71a871af3b4ad971ULL, 0xdf84dfb6f8275bdfULL, 0x87a1874c35b22687ULL, 0x95fb95dc59cc6e95ULL, 0x174b17b872655c17ULL, 0xf017f0d31aeae7f0ULL, 0xd89fd88eea3247d8ULL, 0x092d0948363f2409ULL,
        0x6dc46d4f731ea96dULL, 0xf318f3cb10e3ebf3ULL, 0x1d691de84e53741dULL, 0xcbc0cb16804b0bcbULL, 0xc9cac9068c4503c9ULL, 0x4d644d52b3fe294dULL, 0x2c9c2c7de8c4b02cULL, 0xaf29af11c56a86afULL,
        0x798079ef0b72f979ULL, 0xe047e0537a9aa7e0ULL, 0x97f197cc55c26697ULL, 0xfd2efdbb34c9d3fdULL, 0x6fce6f5f7f10a16fULL, 0x4b7a4b62a7ec314bULL, 0x454c451283c60945ULL, 0x39dd39d596afe439ULL,
        0x3ec63eed84baf83eULL, 0xdd8edda6f42953ddULL, 0xa315a371ed4eb6a3ULL, 0x4f6e4f42bff0214fULL, 0xb45eb4c99f2beab4ULL, 0xb654b6d99325e2b6ULL, 0x9ac89aa47be1529aULL, 0x0e360e70242a380eULL,
        0x1f631ff8425d7c1fULL, 0xbf79bf91a51ac6bfULL, 0x154115a87e6b5415ULL, 0xe142e15b7c9da3e1ULL, 0x49704972abe23949ULL, 0xd2bdd2ded6046fd2ULL, 0x93e593ec4dde7693ULL, 0xc6f9c67eae683fc6ULL,
        0x92e092e44bd97292ULL, 0x72a772b73143d572ULL, 0x9edc9e8463fd429eULL, 0x61f8612f5b3a9961ULL, 0xd1b2d1c6dc0d63d1ULL, 0x63f2633f57349163ULL, 0xfa35fa8326dccffaULL, 0xee71ee235eb09feeULL,
        0xf403f4f302f6f7f4ULL, 0x197d19c8564f6419ULL, 0xd5a6d5e6c41173d5ULL, 0xad23ad01c9648eadULL, 0x582558facd957d58ULL, 0xa40ea449ff5baaa4ULL, 0xbb6dbbb1bd06d6bbULL, 0xa11fa161e140bea1ULL,
        0xdc8bdcaef22e57dcULL, 0xf21df2c316e4eff2ULL, 0x83b5836c2dae3683ULL, 0x37eb37a5b285dc37ULL, 0x4257422a91d31542ULL, 0xe453e4736286b7e4ULL, 0x7a8f7af7017bf57aULL, 0x32fa328dac9ec832ULL,
        0x9cd69c946ff34a9cULL, 0xccdbcc2e925e17ccULL, 0xab3dab31dd7696abULL, 0x4a7f4a6aa1eb354aULL, 0x8f898f0c058a068fULL, 0x6ecb6e577917a56eULL, 0x04140420181c1004ULL, 0x27bb2725d2f59c27ULL,
        0x2e962e6de4cab82eULL, 0xe75ce76b688fbbe7ULL, 0xe24de2437694afe2ULL, 0x5a2f5aeac19b755aULL, 0x96f496c453c56296ULL, 0x164e16b074625816ULL, 0x23af2305cae98c23ULL, 0x2b872b45fad1ac2bULL,
        0xc2edc25eb6742fc2ULL, 0x65ec650f43268965ULL, 0x66e36617492f8566ULL, 0x0f330f78222d3c0fULL, 0xbc76bc89af13cabcULL, 0xa937a921d1789ea9ULL, 0x474647028fc80147ULL, 0x415841329bda1941ULL,
        0x34e434bdb88cd034ULL, 0x4875487aade53d48ULL, 0xfc2bfcb332ced7fcULL, 0xb751b7d19522e6b7ULL, 0x6adf6a77610bb56aULL, 0x88928834179f1a88ULL, 0xa50ba541f95caea5ULL, 0x530253a2f7a45153ULL,
        0x86a4864433b52286ULL, 0xf93af99b2cd5c3f9ULL, 0x5b2a5be2c79c715bULL, 0xdb90db96e03b4bdbULL, 0x38d838dd90a8e038ULL, 0x7b8a7bff077cf17bULL, 0xc3e8c356b0732bc3ULL, 0x1e661ef0445a781eULL,
        0x22aa220dccee8822ULL, 0x33ff3385aa99cc33ULL, 0x24b4243dd8fc9024ULL, 0x2888285df0d8a028ULL, 0x36ee36adb482d836ULL, 0xc7fcc776a86f3bc7ULL, 0xb240b2f98b39f2b2ULL, 0x3bd73bc59aa1ec3bULL,
        0x8e8c8e04038d028eULL, 0x77b6779f2f58c177ULL, 0xba68bab9bb01d2baULL, 0xf506f5fb04f1f3f5ULL, 0x144414a0786c5014ULL, 0x9fd99f8c65fa469fULL, 0x0828084030382008ULL, 0x551c5592e3b64955ULL,
        0x9bcd9bac7de6569bULL, 0x4c614c5ab5f92d4cULL, 0xfe21fea33ec0dffeULL, 0x60fd60275d3d9d60ULL, 0x5c315cdad5896d5cULL, 0xda95da9ee63c4fdaULL, 0x187818c050486018ULL, 0x4643460a89cf0546ULL,
        0xcddecd26945913cdULL, 0x7d947dcf136ee97dULL, 0x21a52115c6e78421ULL, 0xb04ab0e98737fab0ULL, 0x3fc33fe582bdfc3fULL, 0x1b771bd85a416c1bULL, 0x8997893c11981e89ULL, 0xff24ffab38c7dbffULL,
        0xeb60eb0b40ab8bebULL, 0x84ae84543fbb2a84ULL, 0x69d0696f6b02b969ULL, 0x3ad23acd9ca6e83aULL, 0x9dd39d9c69f44e9dULL, 0xd7acd7f6c81f7bd7ULL, 0xd3b8d3d6d0036bd3ULL, 0x70ad70a73d4ddd70ULL,
        0x67e6671f4f288167ULL, 0x405d403a9ddd1d40ULL, 0xb55bb5c1992ceeb5ULL, 0xde81debefe205fdeULL, 0x5d345dd2d38e695dULL, 0x30f0309da090c030ULL, 0x91ef91fc41d07e91ULL, 0xb14fb1e18130feb1ULL,
        0x788578e70d75fd78ULL, 0x1155118866774411ULL, 0x0105010806070401ULL, 0xe556e57b6481b3e5ULL, 0x0000000000000000ULL, 0x68d568676d05bd68ULL, 0x98c298b477ef5a98ULL, 0xa01aa069e747baa0ULL,
        0xc5f6c566a46133c5ULL, 0x020a02100c0e0802ULL, 0xa604a659f355a2a6ULL, 0x74b974872551cd74ULL, 0x2d992d75eec3b42dULL, 0x0b270b583a312c0bULL, 0xa210a279eb49b2a2ULL, 0x76b37697295fc576ULL,
        0xb345b3f18d3ef6b3ULL, 0xbe7cbe99a31dc2beULL, 0xced1ce3e9e501fceULL, 0xbd73bd81a914cebdULL, 0xae2cae19c36d82aeULL, 0xe96ae91b4ca583e9ULL, 0x8a988a241b91128aULL, 0x31f53195a697c431ULL,
        0x1c6c1ce04854701cULL, 0xec7bec3352be97ecULL, 0xf112f1db1cede3f1ULL, 0x99c799bc71e85e99ULL, 0x94fe94d45fcb6a94ULL, 0xaa38aa39db7192aaULL, 0xf609f6e30ef8fff6ULL, 0x26be262dd4f29826ULL,
        0x2f932f65e2cdbc2fULL, 0xef74ef2b58b79befULL, 0xe86fe8134aa287e8ULL, 0x8c868c140f830a8cULL, 0x35e135b5be8bd435ULL, 0x030f03180a090c03ULL, 0xd4a3d4eec21677d4ULL, 0x7f9e7fdf1f60e17fULL,
        0xfb30fb8b20dbcbfbULL, 0x051105281e1b1405ULL, 0xc1e2c146bc7d23c1ULL, 0x5e3b5ecad987655eULL, 0x90ea90f447d77a90ULL, 0x20a0201dc0e08020ULL, 0x3dc93df58eb3f43dULL, 0x82b082642ba93282ULL,
        0xf70cf7eb08fffbf7ULL, 0xea65ea0346ac8feaULL, 0x0a220a503c36280aULL, 0x0d390d682e23340dULL, 0x7e9b7ed71967e57eULL, 0xf83ff8932ad2c7f8ULL, 0x500d50bafdad5d50ULL, 0x1a721ad05c46681aULL,
        0xc4f3c46ea26637c4ULL, 0x071b073812151c07ULL, 0x57165782efb84157ULL, 0xb862b8a9b70fdab8ULL, 0x3ccc3cfd88b4f03cULL, 0x62f7623751339562ULL, 0xe348e34b7093abe3ULL, 0xc8cfc80e8a4207c8ULL,
        0xac26ac09cf638aacULL, 0x520752aaf1a35552ULL, 0x64e9640745218d64ULL, 0x1050108060704010ULL, 0xd0b7d0ceda0a67d0ULL, 0xd99ad986ec3543d9ULL, 0x135f13986a794c13ULL, 0x0c3c0c602824300cULL,
        0x125a12906c7e4812ULL, 0x298d2955f6dfa429ULL, 0x510851b2fbaa5951ULL, 0xb967b9a1b108deb9ULL, 0xcfd4cf3698571bcfULL, 0xd6a9d6fece187fd6ULL, 0x73a273bf3744d173ULL, 0x8d838d1c09840e8dULL,
        0x81bf817c21a03e81ULL, 0x5419549ae5b14d54ULL, 0xc0e7c04eba7a27c0ULL, 0xed7eed3b54b993edULL, 0x4e6b4e4ab9f7254eULL, 0x4449441a85c10d44ULL, 0xa701a751f552a6a7ULL, 0x2a822a4dfcd6a82aULL,
        0x85ab855c39bc2e85ULL, 0x25b12535defb9425ULL, 0xe659e6636e88bfe6ULL, 0xcac5ca1e864c0fcaULL, 0x7c917cc71569ed7cULL, 0x8b9d8b2c1d96168bULL, 0x5613568ae9bf4556ULL, 0x80ba807427a73a80ULL
    },
    {
        0xd1ce3e9e501fceceULL, 0x6dbbb1bd06d6bbbbULL, 0x60eb0b40ab8bebebULL, 0xe092e44bd9729292ULL, 0x65ea0346ac8feaeaULL, 0xc0cb16804b0bcbcbULL, 0x5f13986a794c1313ULL, 0xe2c146bc7d23c1c1ULL,
        0x6ae91b4ca583e9e9ULL, 0xd23acd9ca6e83a3aULL, 0xa9d6fece187fd6d6ULL, 0x40b2f98b39f2b2b2ULL, 0xbdd2ded6046fd2d2ULL, 0xea90f447d77a9090ULL, 0x4b17b872655c1717ULL, 0x3ff8932ad2c7f8f8ULL,
        0x57422a91d3154242ULL, 0x4115a87e6b541515ULL, 0x13568ae9bf455656ULL, 0x5eb4c99f2beab4b4ULL, 0xec650f4326896565ULL, 0x6c1ce04854701c1cULL, 0x928834179f1a8888ULL, 0x52432297d4114343ULL,
        0xf6c566a46133c5c5ULL, 0x315cdad5896d5c5cULL, 0xee36adb482d83636ULL, 0x68bab9bb01d2babaULL, 0x06f5fb04f1f3f5f5ULL, 0x165782efb8415757ULL, 0xe6671f4f28816767ULL, 0x838d1c09840e8d8dULL,
        0xf53195a697c43131ULL, 0x09f6e30ef8fff6f6ULL, 0xe9640745218d6464ULL, 0x2558facd957d5858ULL, 0xdc9e8463fd429e9eULL, 0x03f4f302f6f7f4f4ULL, 0xaa220dccee882222ULL, 0x38aa39db7192aaaaULL,
        0xbc758f2356c97575ULL, 0x330f78222d3c0f0fULL, 0x0a02100c0e080202ULL, 0x4fb1e18130feb1b1ULL, 0x84dfb6f8275bdfdfULL, 0xc46d4f731ea96d6dULL, 0xa273bf3744d17373ULL, 0x644d52b3fe294d4dULL,
        0x917cc71569ed7c7cULL, 0xbe262dd4f2982626ULL, 0x962e6de4cab82e2eULL, 0x0cf7eb08fffbf7f7ULL, 0x2808403038200808ULL, 0x345dd2d38e695d5dULL, 0x49441a85c10d4444ULL, 0xc63eed84baf83e3eULL,
        0xd99f8c65fa469f9fULL, 0x4414a0786c501414ULL, 0xcfc80e8a4207c8c8ULL, 0x2cae19c36d82aeaeULL, 0x19549ae5b14d5454ULL, 0x5010806070401010ULL, 0x9fd88eea3247d8d8ULL, 0x76bc89af13cabcbcULL,
        0x721ad05c46681a1aULL, 0xda6b7f670cb16b6bULL, 0xd0696f6b02b96969ULL, 0x18f3cb10e3ebf3f3ULL, 0x73bd81a914cebdbdULL, 0xff3385aa99cc3333ULL, 0x3dab31dd7696ababULL, 0x35fa8326dccffafaULL,
        0xb2d1c6dc0d63d1d1ULL, 0xcd9bac7de6569b9bULL, 0xd568676d05bd6868ULL, 0x6b4e4ab9f7254e4eULL, 0x4e16b07462581616ULL, 0xfb95dc59cc6e9595ULL, 0xef91fc41d07e9191ULL, 0x71ee235eb09feeeeULL,
        0x614c5ab5f92d4c4cULL, 0xf2633f5734916363ULL, 0x8c8e04038d028e8eULL, 0x2a5be2c79c715b5bULL, 0xdbcc2e925e17ccccULL, 0xcc3cfd88b4f03c3cULL, 0x7d19c8564f641919ULL, 0x1fa161e140bea1a1ULL,
        0xbf817c21a03e8181ULL, 0x704972abe2394949ULL, 0x8a7bff077cf17b7bULL, 0x9ad986ec3543d9d9ULL, 0xce6f5f7f10a16f6fULL, 0xeb37a5b285dc3737ULL, 0xfd60275d3d9d6060ULL, 0xc5ca1e864c0fcacaULL,
        0x5ce76b688fbbe7e7ULL, 0x872b45fad1ac2b2bULL, 0x75487aade53d4848ULL, 0x2efdbb34c9d3fdfdULL, 0xf496c453c5629696ULL, 0x4c451283c6094545ULL, 0x2bfcb332ced7fcfcULL, 0x5841329bda194141ULL,
        0x5a12906c7e481212ULL, 0x390d682e23340d0dULL, 0x8079ef0b72f97979ULL, 0x56e57b6481b3e5e5ULL, 0x97893c11981e8989ULL, 0x868c140f830a8c8cULL, 0x48e34b7093abe3e3ULL, 0xa0201dc0e0802020ULL,
        0xf0309da090c03030ULL, 0x8bdcaef22e57dcdcULL, 0x51b7d19522e6b7b7ULL, 0xc16c477519ad6c6cULL, 0x7f4a6aa1eb354a4aULL, 0x5bb5c1992ceeb5b5ULL, 0xc33fe582bdfc3f3fULL, 0xf197cc55c2669797ULL,
        0xa3d4eec21677d4d4ULL, 0xf762375133956262ULL, 0x992d75eec3b42d2dULL, 0x1e06301412180606ULL, 0x0ea449ff5baaa4a4ULL, 0x0ba541f95caea5a5ULL, 0xb5836c2dae368383ULL, 0x3e5fc2df80615f5fULL,
        0x822a4dfcd6a82a2aULL, 0x95da9ee63c4fdadaULL, 0xcac9068c4503c9c9ULL, 0x0000000000000000ULL, 0x9b7ed71967e57e7eULL, 0x10a279eb49b2a2a2ULL, 0x1c5592e3b6495555ULL, 0x79bf91a51ac6bfbfULL,
        0x5511886677441111ULL, 0xa6d5e6c41173d5d5ULL, 0xd69c946ff34a9c9cULL, 0xd4cf3698571bcfcfULL, 0x360e70242a380e0eULL, 0x220a503c36280a0aULL, 0xc93df58eb3f43d3dULL, 0x0851b2fbaa595151ULL,
        0x947dcf136ee97d7dULL, 0xe593ec4dde769393ULL, 0x771bd85a416c1b1bULL, 0x21fea33ec0dffefeULL, 0xf3c46ea26637c4c4ULL, 0x4647028fc8014747ULL, 0x2d0948363f240909ULL, 0xa4864433b5228686ULL,
        0x270b583a312c0b0bULL, 0x898f0c058a068f8fULL, 0xd39d9c69f44e9d9dULL, 0xdf6a77610bb56a6aULL, 0x1b073812151c0707ULL, 0x67b9a1b108deb9b9ULL, 0x4ab0e98737fab0b0ULL, 0xc298b477ef5a9898ULL,
        0x7818c05048601818ULL, 0xfa328dac9ec83232ULL, 0xa871af3b4ad97171ULL, 0x7a4b62a7ec314b4bULL, 0x74ef2b58b79befefULL, 0xd73bc59aa1ec3b3bULL, 0xad70a73d4ddd7070ULL, 0x1aa069e747baa0a0ULL,
        0x53e4736286b7e4e4ULL, 0x5d403a9ddd1d4040ULL, 0x24ffab38c7dbffffULL, 0xe8c356b0732bc3c3ULL, 0x37a921d1789ea9a9ULL, 0x59e6636e88bfe6e6ULL, 0x8578e70d75fd7878ULL, 0x3af99b2cd5c3f9f9ULL,
        0x9d8b2c1d96168b8bULL, 0x43460a89cf054646ULL, 0xba807427a73a8080ULL, 0x661ef0445a781e1eULL, 0xd838dd90a8e03838ULL, 0x42e15b7c9da3e1e1ULL, 0x62b8a9b70fdab8b8ULL, 0x32a829d77f9aa8a8ULL,
        0x47e0537a9aa7e0e0ULL, 0x3c0c602824300c0cULL, 0xaf2305cae98c2323ULL, 0xb37697295fc57676ULL, 0x691de84e53741d1dULL, 0xb12535defb942525ULL, 0xb4243dd8fc902424ULL, 0x1105281e1b140505ULL,
        0x12f1db1cede3f1f1ULL, 0xcb6e577917a56e6eULL, 0xfe94d45fcb6a9494ULL, 0x88285df0d8a02828ULL, 0xc89aa47be1529a9aULL, 0xae84543fbb2a8484ULL, 0x6fe8134aa287e8e8ULL, 0x15a371ed4eb6a3a3ULL,
        0x6e4f42bff0214f4fULL, 0xb6779f2f58c17777ULL, 0xb8d3d6d0036bd3d3ULL, 0xab855c39bc2e8585ULL, 0x4de2437694afe2e2ULL, 0x0752aaf1a3555252ULL, 0x1df2c316e4eff2f2ULL, 0xb082642ba9328282ULL,
        0x0d50bafdad5d5050ULL, 0x8f7af7017bf57a7aULL, 0x932f65e2cdbc2f2fULL, 0xb974872551cd7474ULL, 0x0253a2f7a4515353ULL, 0x45b3f18d3ef6b3b3ULL, 0xf8612f5b3a996161ULL, 0x29af11c56a86afafULL,
        0xdd39d596afe43939ULL, 0xe135b5be8bd43535ULL, 0x81debefe205fdedeULL, 0xdecd26945913cdcdULL, 0x631ff8425d7c1f1fULL, 0xc799bc71e85e9999ULL, 0x26ac09cf638aacacULL, 0x23ad01c9648eadadULL,
        0xa772b73143d57272ULL, 0x9c2c7de8c4b02c2cULL, 0x8edda6f42953ddddULL, 0xb7d0ceda0a67d0d0ULL, 0xa1874c35b2268787ULL, 0x7cbe99a31dc2bebeULL, 0x3b5ecad987655e5eULL, 0x04a659f355a2a6a6ULL,
        0x7bec3352be97ececULL, 0x140420181c100404ULL, 0xf9c67eae683fc6c6ULL, 0x0f03180a090c0303ULL, 0xe434bdb88cd03434ULL, 0x30fb8b20dbcbfbfbULL, 0x90db96e03b4bdbdbULL, 0x2059f2cb92795959ULL,
        0x54b6d99325e2b6b6ULL, 0xedc25eb6742fc2c2ULL, 0x0501080607040101ULL, 0x17f0d31aeae7f0f0ULL, 0x2f5aeac19b755a5aULL, 0x7eed3b54b993ededULL, 0x01a751f552a6a7a7ULL, 0xe36617492f856666ULL,
        0xa52115c6e7842121ULL, 0x9e7fdf1f60e17f7fULL, 0x988a241b91128a8aULL, 0xbb2725d2f59c2727ULL, 0xfcc776a86f3bc7c7ULL, 0xe7c04eba7a27c0c0ULL, 0x8d2955f6dfa42929ULL, 0xacd7f6c81f7bd7d7ULL
    },
    {
        0x93ec4dde769393e5ULL, 0xd986ec3543d9d99aULL, 0x9aa47be1529a9ac8ULL, 0xb5c1992ceeb5b55bULL, 0x98b477ef5a9898c2ULL, 0x220dccee882222aaULL, 0x451283c60945454cULL, 0xfcb332ced7fcfc2bULL,
        0xbab9bb01d2baba68ULL, 0x6a77610bb56a6adfULL, 0xdfb6f8275bdfdf84ULL, 0x02100c0e0802020aULL, 0x9f8c65fa469f9fd9ULL, 0xdcaef22e57dcdc8bULL, 0x51b2fbaa59515108ULL, 0x59f2cb9279595920ULL,
        0x4a6aa1eb354a4a7fULL, 0x17b872655c17174bULL, 0x2b45fad1ac2b2b87ULL, 0xc25eb6742fc2c2edULL, 0x94d45fcb6a9494feULL, 0xf4f302f6f7f4f403ULL, 0xbbb1bd06d6bbbb6dULL, 0xa371ed4eb6a3a315ULL,
        0x62375133956262f7ULL, 0xe4736286b7e4e453ULL, 0x71af3b4ad97171a8ULL, 0xd4eec21677d4d4a3ULL, 0xcd26945913cdcddeULL, 0x70a73d4ddd7070adULL, 0x16b074625816164eULL, 0xe15b7c9da3e1e142ULL,
        0x4972abe239494970ULL, 0x3cfd88b4f03c3cccULL, 0xc04eba7a27c0c0e7ULL, 0xd88eea3247d8d89fULL, 0x5cdad5896d5c5c31ULL, 0x9bac7de6569b9bcdULL, 0xad01c9648eadad23ULL, 0x855c39bc2e8585abULL,
        0x53a2f7a451535302ULL, 0xa161e140bea1a11fULL, 0x7af7017bf57a7a8fULL, 0xc80e8a4207c8c8cfULL, 0x2d75eec3b42d2d99ULL, 0xe0537a9aa7e0e047ULL, 0xd1c6dc0d63d1d1b2ULL, 0x72b73143d57272a7ULL,
        0xa659f355a2a6a604ULL, 0x2c7de8c4b02c2c9cULL, 0xc46ea26637c4c4f3ULL, 0xe34b7093abe3e348ULL, 0x7697295fc57676b3ULL, 0x78e70d75fd787885ULL, 0xb7d19522e6b7b751ULL, 0xb4c99f2beab4b45eULL,
        0x0948363f2409092dULL, 0x3bc59aa1ec3b3bd7ULL, 0x0e70242a380e0e36ULL, 0x41329bda19414158ULL, 0x4c5ab5f92d4c4c61ULL, 0xdebefe205fdede81ULL, 0xb2f98b39f2b2b240ULL, 0x90f447d77a9090eaULL,
        0x2535defb942525b1ULL, 0xa541f95caea5a50bULL, 0xd7f6c81f7bd7d7acULL, 0x03180a090c03030fULL, 0x1188667744111155ULL, 0x0000000000000000ULL, 0xc356b0732bc3c3e8ULL, 0x2e6de4cab82e2e96ULL,
        0x92e44bd9729292e0ULL, 0xef2b58b79befef74ULL, 0x4e4ab9f7254e4e6bULL, 0x12906c7e4812125aULL, 0x9d9c69f44e9d9dd3ULL, 0x7dcf136ee97d7d94ULL, 0xcb16804b0bcbcbc0ULL, 0x35b5be8bd43535e1ULL,
        0x1080607040101050ULL, 0xd5e6c41173d5d5a6ULL, 0x4f42bff0214f4f6eULL, 0x9e8463fd429e9edcULL, 0x4d52b3fe294d4d64ULL, 0xa921d1789ea9a937ULL, 0x5592e3b64955551cULL, 0xc67eae683fc6c6f9ULL,
        0xd0ceda0a67d0d0b7ULL, 0x7bff077cf17b7b8aULL, 0x18c0504860181878ULL, 0x97cc55c2669797f1ULL, 0xd3d6d0036bd3d3b8ULL, 0x36adb482d83636eeULL, 0xe6636e88bfe6e659ULL, 0x487aade53d484875ULL,
        0x568ae9bf45565613ULL, 0x817c21a03e8181bfULL, 0x8f0c058a068f8f89ULL, 0x779f2f58c17777b6ULL, 0xcc2e925e17ccccdbULL, 0x9c946ff34a9c9cd6ULL, 0xb9a1b108deb9b967ULL, 0xe2437694afe2e24dULL,
        0xac09cf638aacac26ULL, 0xb8a9b70fdab8b862ULL, 0x2f65e2cdbc2f2f93ULL, 0x15a87e6b54151541ULL, 0xa449ff5baaa4a40eULL, 0x7cc71569ed7c7c91ULL, 0xda9ee63c4fdada95ULL, 0x38dd90a8e03838d8ULL,
        0x1ef0445a781e1e66ULL, 0x0b583a312c0b0b27ULL, 0x05281e1b14050511ULL, 0xd6fece187fd6d6a9ULL, 0x14a0786c50141444ULL, 0x6e577917a56e6ecbULL, 0x6c477519ad6c6cc1ULL, 0x7ed71967e57e7e9bULL,
        0x6617492f856666e3ULL, 0xfdbb34c9d3fdfd2eULL, 0xb1e18130feb1b14fULL, 0xe57b6481b3e5e556ULL, 0x60275d3d9d6060fdULL, 0xaf11c56a86afaf29ULL, 0x5ecad987655e5e3bULL, 0x3385aa99cc3333ffULL,
        0x874c35b2268787a1ULL, 0xc9068c4503c9c9caULL, 0xf0d31aeae7f0f017ULL, 0x5dd2d38e695d5d34ULL, 0x6d4f731ea96d6dc4ULL, 0x3fe582bdfc3f3fc3ULL, 0x8834179f1a888892ULL, 0x8d1c09840e8d8d83ULL,
        0xc776a86f3bc7c7fcULL, 0xf7eb08fffbf7f70cULL, 0x1de84e53741d1d69ULL, 0xe91b4ca583e9e96aULL, 0xec3352be97ecec7bULL, 0xed3b54b993eded7eULL, 0x807427a73a8080baULL, 0x2955f6dfa429298dULL,
        0x2725d2f59c2727bbULL, 0xcf3698571bcfcfd4ULL, 0x99bc71e85e9999c7ULL, 0xa829d77f9aa8a832ULL, 0x50bafdad5d50500dULL, 0x0f78222d3c0f0f33ULL, 0x37a5b285dc3737ebULL, 0x243dd8fc902424b4ULL,
        0x285df0d8a0282888ULL, 0x309da090c03030f0ULL, 0x95dc59cc6e9595fbULL, 0xd2ded6046fd2d2bdULL, 0x3eed84baf83e3ec6ULL, 0x5be2c79c715b5b2aULL, 0x403a9ddd1d40405dULL, 0x836c2dae368383b5ULL,
        0xb3f18d3ef6b3b345ULL, 0x696f6b02b96969d0ULL, 0x5782efb841575716ULL, 0x1ff8425d7c1f1f63ULL, 0x073812151c07071bULL, 0x1ce04854701c1c6cULL, 0x8a241b91128a8a98ULL, 0xbc89af13cabcbc76ULL,
        0x201dc0e0802020a0ULL, 0xeb0b40ab8bebeb60ULL, 0xce3e9e501fceced1ULL, 0x8e04038d028e8e8cULL, 0xab31dd7696abab3dULL, 0xee235eb09feeee71ULL, 0x3195a697c43131f5ULL, 0xa279eb49b2a2a210ULL,
        0x73bf3744d17373a2ULL, 0xf99b2cd5c3f9f93aULL, 0xca1e864c0fcacac5ULL, 0x3acd9ca6e83a3ad2ULL, 0x1ad05c46681a1a72ULL, 0xfb8b20dbcbfbfb30ULL, 0x0d682e23340d0d39ULL, 0xc146bc7d23c1c1e2ULL,
        0xfea33ec0dffefe21ULL, 0xfa8326dccffafa35ULL, 0xf2c316e4eff2f21dULL, 0x6f5f7f10a16f6fceULL, 0xbd81a914cebdbd73ULL, 0x96c453c5629696f4ULL, 0xdda6f42953dddd8eULL, 0x432297d411434352ULL,
        0x52aaf1a355525207ULL, 0xb6d99325e2b6b654ULL, 0x0840303820080828ULL, 0xf3cb10e3ebf3f318ULL, 0xae19c36d82aeae2cULL, 0xbe99a31dc2bebe7cULL, 0x19c8564f6419197dULL, 0x893c11981e898997ULL,
        0x328dac9ec83232faULL, 0x262dd4f2982626beULL, 0xb0e98737fab0b04aULL, 0xea0346ac8feaea65ULL, 0x4b62a7ec314b4b7aULL, 0x640745218d6464e9ULL, 0x84543fbb2a8484aeULL, 0x82642ba9328282b0ULL,
        0x6b7f670cb16b6bdaULL, 0xf5fb04f1f3f5f506ULL, 0x79ef0b72f9797980ULL, 0xbf91a51ac6bfbf79ULL, 0x0108060704010105ULL, 0x5fc2df80615f5f3eULL, 0x758f2356c97575bcULL, 0x633f5734916363f2ULL,
        0x1bd85a416c1b1b77ULL, 0x2305cae98c2323afULL, 0x3df58eb3f43d3dc9ULL, 0x68676d05bd6868d5ULL, 0x2a4dfcd6a82a2a82ULL, 0x650f4326896565ecULL, 0xe8134aa287e8e86fULL, 0x91fc41d07e9191efULL,
        0xf6e30ef8fff6f609ULL, 0xffab38c7dbffff24ULL, 0x13986a794c13135fULL, 0x58facd957d585825ULL, 0xf1db1cede3f1f112ULL, 0x47028fc801474746ULL, 0x0a503c36280a0a22ULL, 0x7fdf1f60e17f7f9eULL,
        0xc566a46133c5c5f6ULL, 0xa751f552a6a7a701ULL, 0xe76b688fbbe7e75cULL, 0x612f5b3a996161f8ULL, 0x5aeac19b755a5a2fULL, 0x063014121806061eULL, 0x460a89cf05464643ULL, 0x441a85c10d444449ULL,
        0x422a91d315424257ULL, 0x0420181c10040414ULL, 0xa069e747baa0a01aULL, 0xdb96e03b4bdbdb90ULL, 0x39d596afe43939ddULL, 0x864433b5228686a4ULL, 0x549ae5b14d545419ULL, 0xaa39db7192aaaa38ULL,
        0x8c140f830a8c8c86ULL, 0x34bdb88cd03434e4ULL, 0x2115c6e7842121a5ULL, 0x8b2c1d96168b8b9dULL, 0xf8932ad2c7f8f83fULL, 0x0c602824300c0c3cULL, 0x74872551cd7474b9ULL, 0x671f4f28816767e6ULL
    },
    {
        0x676d05bd6868d568ULL, 0x1c09840e8d8d838dULL, 0x1e864c0fcacac5caULL, 0x52b3fe294d4d644dULL, 0xbf3744d17373a273ULL, 0x62a7ec314b4b7a4bULL, 0x4ab9f7254e4e6b4eULL, 0x4dfcd6a82a2a822aULL,
        0xeec21677d4d4a3d4ULL, 0xaaf1a35552520752ULL, 0x2dd4f2982626be26ULL, 0xf18d3ef6b3b345b3ULL, 0x9ae5b14d54541954ULL, 0xf0445a781e1e661eULL, 0xc8564f6419197d19ULL, 0xf8425d7c1f1f631fULL,
        0x0dccee882222aa22ULL, 0x180a090c03030f03ULL, 0x0a89cf0546464346ULL, 0xf58eb3f43d3dc93dULL, 0x75eec3b42d2d992dULL, 0x6aa1eb354a4a7f4aULL, 0xa2f7a45153530253ULL, 0x6c2dae368383b583ULL,
        0x986a794c13135f13ULL, 0x241b91128a8a988aULL, 0xd19522e6b7b751b7ULL, 0xe6c41173d5d5a6d5ULL, 0x35defb942525b125ULL, 0xef0b72f979798079ULL, 0xfb04f1f3f5f506f5ULL, 0x81a914cebdbd73bdULL,
        0xfacd957d58582558ULL, 0x65e2cdbc2f2f932fULL, 0x682e23340d0d390dULL, 0x100c0e0802020a02ULL, 0x3b54b993eded7eedULL, 0xb2fbaa5951510851ULL, 0x8463fd429e9edc9eULL, 0x8866774411115511ULL,
        0xc316e4eff2f21df2ULL, 0xed84baf83e3ec63eULL, 0x92e3b64955551c55ULL, 0xcad987655e5e3b5eULL, 0xc6dc0d63d1d1b2d1ULL, 0xb074625816164e16ULL, 0xfd88b4f03c3ccc3cULL, 0x17492f856666e366ULL,
        0xa73d4ddd7070ad70ULL, 0xd2d38e695d5d345dULL, 0xcb10e3ebf3f318f3ULL, 0x1283c60945454c45ULL, 0x3a9ddd1d40405d40ULL, 0x2e925e17ccccdbccULL, 0x134aa287e8e86fe8ULL, 0xd45fcb6a9494fe94ULL,
        0x8ae9bf4556561356ULL, 0x4030382008082808ULL, 0x3e9e501fceced1ceULL, 0xd05c46681a1a721aULL, 0xcd9ca6e83a3ad23aULL, 0xded6046fd2d2bdd2ULL, 0x5b7c9da3e1e142e1ULL, 0xb6f8275bdfdf84dfULL,
        0xc1992ceeb5b55bb5ULL, 0xdd90a8e03838d838ULL, 0x577917a56e6ecb6eULL, 0x70242a380e0e360eULL, 0x7b6481b3e5e556e5ULL, 0xf302f6f7f4f403f4ULL, 0x9b2cd5c3f9f93af9ULL, 0x4433b5228686a486ULL,
        0x1b4ca583e9e96ae9ULL, 0x42bff0214f4f6e4fULL, 0xfece187fd6d6a9d6ULL, 0x5c39bc2e8585ab85ULL, 0x05cae98c2323af23ULL, 0x3698571bcfcfd4cfULL, 0x8dac9ec83232fa32ULL, 0xbc71e85e9999c799ULL,
        0x95a697c43131f531ULL, 0xa0786c5014144414ULL, 0x19c36d82aeae2caeULL, 0x235eb09feeee71eeULL, 0x0e8a4207c8c8cfc8ULL, 0x7aade53d48487548ULL, 0xd6d0036bd3d3b8d3ULL, 0x9da090c03030f030ULL,
        0x61e140bea1a11fa1ULL, 0xe44bd9729292e092ULL, 0x329bda1941415841ULL, 0xe18130feb1b14fb1ULL, 0xc050486018187818ULL, 0x6ea26637c4c4f3c4ULL, 0x7de8c4b02c2c9c2cULL, 0xaf3b4ad97171a871ULL,
        0xb73143d57272a772ULL, 0x1a85c10d44444944ULL, 0xa87e6b5415154115ULL, 0xbb34c9d3fdfd2efdULL, 0xa5b285dc3737eb37ULL, 0x99a31dc2bebe7cbeULL, 0xc2df80615f5f3e5fULL, 0x39db7192aaaa38aaULL,
        0xac7de6569b9bcd9bULL, 0x34179f1a88889288ULL, 0x8eea3247d8d89fd8ULL, 0x31dd7696abab3dabULL, 0x3c11981e89899789ULL, 0x946ff34a9c9cd69cULL, 0x8326dccffafa35faULL, 0x275d3d9d6060fd60ULL,
        0x0346ac8feaea65eaULL, 0x89af13cabcbc76bcULL, 0x375133956262f762ULL, 0x602824300c0c3c0cULL, 0x3dd8fc902424b424ULL, 0x59f355a2a6a604a6ULL, 0x29d77f9aa8a832a8ULL, 0x3352be97ecec7becULL,
        0x1f4f28816767e667ULL, 0x1dc0e0802020a020ULL, 0x96e03b4bdbdb90dbULL, 0xc71569ed7c7c917cULL, 0x5df0d8a028288828ULL, 0xa6f42953dddd8eddULL, 0x09cf638aacac26acULL, 0xe2c79c715b5b2a5bULL,
        0xbdb88cd03434e434ULL, 0xd71967e57e7e9b7eULL, 0x8060704010105010ULL, 0xdb1cede3f1f112f1ULL, 0xff077cf17b7b8a7bULL, 0x0c058a068f8f898fULL, 0x3f5734916363f263ULL, 0x69e747baa0a01aa0ULL,
        0x281e1b1405051105ULL, 0xa47be1529a9ac89aULL, 0x2297d41143435243ULL, 0x9f2f58c17777b677ULL, 0x15c6e7842121a521ULL, 0x91a51ac6bfbf79bfULL, 0x25d2f59c2727bb27ULL, 0x48363f2409092d09ULL,
        0x56b0732bc3c3e8c3ULL, 0x8c65fa469f9fd99fULL, 0xd99325e2b6b654b6ULL, 0xf6c81f7bd7d7acd7ULL, 0x55f6dfa429298d29ULL, 0x5eb6742fc2c2edc2ULL, 0x0b40ab8bebeb60ebULL, 0x4eba7a27c0c0e7c0ULL,
        0x49ff5baaa4a40ea4ULL, 0x2c1d96168b8b9d8bULL, 0x140f830a8c8c868cULL, 0xe84e53741d1d691dULL, 0x8b20dbcbfbfb30fbULL, 0xab38c7dbffff24ffULL, 0x46bc7d23c1c1e2c1ULL, 0xf98b39f2b2b240b2ULL,
        0xcc55c2669797f197ULL, 0x6de4cab82e2e962eULL, 0x932ad2c7f8f83ff8ULL, 0x0f4326896565ec65ULL, 0xe30ef8fff6f609f6ULL, 0x8f2356c97575bc75ULL, 0x3812151c07071b07ULL, 0x20181c1004041404ULL,
        0x72abe23949497049ULL, 0x85aa99cc3333ff33ULL, 0x736286b7e4e453e4ULL, 0x86ec3543d9d99ad9ULL, 0xa1b108deb9b967b9ULL, 0xceda0a67d0d0b7d0ULL, 0x2a91d31542425742ULL, 0x76a86f3bc7c7fcc7ULL,
        0x477519ad6c6cc16cULL, 0xf447d77a9090ea90ULL, 0x0000000000000000ULL, 0x04038d028e8e8c8eULL, 0x5f7f10a16f6fce6fULL, 0xbafdad5d50500d50ULL, 0x0806070401010501ULL, 0x66a46133c5c5f6c5ULL,
        0x9ee63c4fdada95daULL, 0x028fc80147474647ULL, 0xe582bdfc3f3fc33fULL, 0x26945913cdcddecdULL, 0x6f6b02b96969d069ULL, 0x79eb49b2a2a210a2ULL, 0x437694afe2e24de2ULL, 0xf7017bf57a7a8f7aULL,
        0x51f552a6a7a701a7ULL, 0x7eae683fc6c6f9c6ULL, 0xec4dde769393e593ULL, 0x78222d3c0f0f330fULL, 0x503c36280a0a220aULL, 0x3014121806061e06ULL, 0x636e88bfe6e659e6ULL, 0x45fad1ac2b2b872bULL,
        0xc453c5629696f496ULL, 0x71ed4eb6a3a315a3ULL, 0xe04854701c1c6c1cULL, 0x11c56a86afaf29afULL, 0x77610bb56a6adf6aULL, 0x906c7e4812125a12ULL, 0x543fbb2a8484ae84ULL, 0xd596afe43939dd39ULL,
        0x6b688fbbe7e75ce7ULL, 0xe98737fab0b04ab0ULL, 0x642ba9328282b082ULL, 0xeb08fffbf7f70cf7ULL, 0xa33ec0dffefe21feULL, 0x9c69f44e9d9dd39dULL, 0x4c35b2268787a187ULL, 0xdad5896d5c5c315cULL,
        0x7c21a03e8181bf81ULL, 0xb5be8bd43535e135ULL, 0xbefe205fdede81deULL, 0xc99f2beab4b45eb4ULL, 0x41f95caea5a50ba5ULL, 0xb332ced7fcfc2bfcULL, 0x7427a73a8080ba80ULL, 0x2b58b79befef74efULL,
        0x16804b0bcbcbc0cbULL, 0xb1bd06d6bbbb6dbbULL, 0x7f670cb16b6bda6bULL, 0x97295fc57676b376ULL, 0xb9bb01d2baba68baULL, 0xeac19b755a5a2f5aULL, 0xcf136ee97d7d947dULL, 0xe70d75fd78788578ULL,
        0x583a312c0b0b270bULL, 0xdc59cc6e9595fb95ULL, 0x4b7093abe3e348e3ULL, 0x01c9648eadad23adULL, 0x872551cd7474b974ULL, 0xb477ef5a9898c298ULL, 0xc59aa1ec3b3bd73bULL, 0xadb482d83636ee36ULL,
        0x0745218d6464e964ULL, 0x4f731ea96d6dc46dULL, 0xaef22e57dcdc8bdcULL, 0xd31aeae7f0f017f0ULL, 0xf2cb927959592059ULL, 0x21d1789ea9a937a9ULL, 0x5ab5f92d4c4c614cULL, 0xb872655c17174b17ULL,
        0xdf1f60e17f7f9e7fULL, 0xfc41d07e9191ef91ULL, 0xa9b70fdab8b862b8ULL, 0x068c4503c9c9cac9ULL, 0x82efb84157571657ULL, 0xd85a416c1b1b771bULL, 0x537a9aa7e0e047e0ULL, 0x2f5b3a996161f861ULL
    },
    {
        0xd77f9aa8a832a829ULL, 0x97d4114343524322ULL, 0xdf80615f5f3e5fc2ULL, 0x14121806061e0630ULL, 0x670cb16b6bda6b7fULL, 0x2356c97575bc758fULL, 0x7519ad6c6cc16c47ULL, 0xcb927959592059f2ULL,
        0x3b4ad97171a871afULL, 0xf8275bdfdf84dfb6ULL, 0x35b2268787a1874cULL, 0x59cc6e9595fb95dcULL, 0x72655c17174b17b8ULL, 0x1aeae7f0f017f0d3ULL, 0xea3247d8d89fd88eULL, 0x363f2409092d0948ULL,
        0x731ea96d6dc46d4fULL, 0x10e3ebf3f318f3cbULL, 0x4e53741d1d691de8ULL, 0x804b0bcbcbc0cb16ULL, 0x8c4503c9c9cac906ULL, 0xb3fe294d4d644d52ULL, 0xe8c4b02c2c9c2c7dULL, 0xc56a86afaf29af11ULL,
        0x0b72f979798079efULL, 0x7a9aa7e0e047e053ULL, 0x55c2669797f197ccULL, 0x34c9d3fdfd2efdbbULL, 0x7f10a16f6fce6f5fULL, 0xa7ec314b4b7a4b62ULL, 0x83c60945454c4512ULL, 0x96afe43939dd39d5ULL,
        0x84baf83e3ec63eedULL, 0xf42953dddd8edda6ULL, 0xed4eb6a3a315a371ULL, 0xbff0214f4f6e4f42ULL, 0x9f2beab4b45eb4c9ULL, 0x9325e2b6b654b6d9ULL, 0x7be1529a9ac89aa4ULL, 0x242a380e0e360e70ULL,
        0x425d7c1f1f631ff8ULL, 0xa51ac6bfbf79bf91ULL, 0x7e6b5415154115a8ULL, 0x7c9da3e1e142e15bULL, 0xabe2394949704972ULL, 0xd6046fd2d2bdd2deULL, 0x4dde769393e593ecULL, 0xae683fc6c6f9c67eULL,
        0x4bd9729292e092e4ULL, 0x3143d57272a772b7ULL, 0x63fd429e9edc9e84ULL, 0x5b3a996161f8612fULL, 0xdc0d63d1d1b2d1c6ULL, 0x5734916363f2633fULL, 0x26dccffafa35fa83ULL, 0x5eb09feeee71ee23ULL,
        0x02f6f7f4f403f4f3ULL, 0x564f6419197d19c8ULL, 0xc41173d5d5a6d5e6ULL, 0xc9648eadad23ad01ULL, 0xcd957d58582558faULL, 0xff5baaa4a40ea449ULL, 0xbd06d6bbbb6dbbb1ULL, 0xe140bea1a11fa161ULL,
        0xf22e57dcdc8bdcaeULL, 0x16e4eff2f21df2c3ULL, 0x2dae368383b5836cULL, 0xb285dc3737eb37a5ULL, 0x91d315424257422aULL, 0x6286b7e4e453e473ULL, 0x017bf57a7a8f7af7ULL, 0xac9ec83232fa328dULL,
        0x6ff34a9c9cd69c94ULL, 0x925e17ccccdbcc2eULL, 0xdd7696abab3dab31ULL, 0xa1eb354a4a7f4a6aULL, 0x058a068f8f898f0cULL, 0x7917a56e6ecb6e57ULL, 0x181c100404140420ULL, 0xd2f59c2727bb2725ULL,
        0xe4cab82e2e962e6dULL, 0x688fbbe7e75ce76bULL, 0x7694afe2e24de243ULL, 0xc19b755a5a2f5aeaULL, 0x53c5629696f496c4ULL, 0x74625816164e16b0ULL, 0xcae98c2323af2305ULL, 0xfad1ac2b2b872b45ULL,
        0xb6742fc2c2edc25eULL, 0x4326896565ec650fULL, 0x492f856666e36617ULL, 0x222d3c0f0f330f78ULL, 0xaf13cabcbc76bc89ULL, 0xd1789ea9a937a921ULL, 0x8fc8014747464702ULL, 0x9bda194141584132ULL,
        0xb88cd03434e434bdULL, 0xade53d484875487aULL, 0x32ced7fcfc2bfcb3ULL, 0x9522e6b7b751b7d1ULL, 0x610bb56a6adf6a77ULL, 0x179f1a8888928834ULL, 0xf95caea5a50ba541ULL, 0xf7a45153530253a2ULL,
        0x33b5228686a48644ULL, 0x2cd5c3f9f93af99bULL, 0xc79c715b5b2a5be2ULL, 0xe03b4bdbdb90db96ULL, 0x90a8e03838d838ddULL, 0x077cf17b7b8a7bffULL, 0xb0732bc3c3e8c356ULL, 0x445a781e1e661ef0ULL,
        0xccee882222aa220dULL, 0xaa99cc3333ff3385ULL, 0xd8fc902424b4243dULL, 0xf0d8a0282888285dULL, 0xb482d83636ee36adULL, 0xa86f3bc7c7fcc776ULL, 0x8b39f2b2b240b2f9ULL, 0x9aa1ec3b3bd73bc5ULL,
        0x038d028e8e8c8e04ULL, 0x2f58c17777b6779fULL, 0xbb01d2baba68bab9ULL, 0x04f1f3f5f506f5fbULL, 0x786c5014144414a0ULL, 0x65fa469f9fd99f8cULL, 0x3038200808280840ULL, 0xe3b64955551c5592ULL,
        0x7de6569b9bcd9bacULL, 0xb5f92d4c4c614c5aULL, 0x3ec0dffefe21fea3ULL, 0x5d3d9d6060fd6027ULL, 0xd5896d5c5c315cdaULL, 0xe63c4fdada95da9eULL, 0x50486018187818c0ULL, 0x89cf05464643460aULL,
        0x945913cdcddecd26ULL, 0x136ee97d7d947dcfULL, 0xc6e7842121a52115ULL, 0x8737fab0b04ab0e9ULL, 0x82bdfc3f3fc33fe5ULL, 0x5a416c1b1b771bd8ULL, 0x11981e898997893cULL, 0x38c7dbffff24ffabULL,
        0x40ab8bebeb60eb0bULL, 0x3fbb2a8484ae8454ULL, 0x6b02b96969d0696fULL, 0x9ca6e83a3ad23acdULL, 0x69f44e9d9dd39d9cULL, 0xc81f7bd7d7acd7f6ULL, 0xd0036bd3d3b8d3d6ULL, 0x3d4ddd7070ad70a7ULL,
        0x4f28816767e6671fULL, 0x9ddd1d40405d403aULL, 0x992ceeb5b55bb5c1ULL, 0xfe205fdede81debeULL, 0xd38e695d5d345dd2ULL, 0xa090c03030f0309dULL, 0x41d07e9191ef91fcULL, 0x8130feb1b14fb1e1ULL,
        0x0d75fd78788578e7ULL, 0x6677441111551188ULL, 0x0607040101050108ULL, 0x6481b3e5e556e57bULL, 0x0000000000000000ULL, 0x6d05bd6868d56867ULL, 0x77ef5a9898c298b4ULL, 0xe747baa0a01aa069ULL,
        0xa46133c5c5f6c566ULL, 0x0c0e0802020a0210ULL, 0xf355a2a6a604a659ULL, 0x2551cd7474b97487ULL, 0xeec3b42d2d992d75ULL, 0x3a312c0b0b270b58ULL, 0xeb49b2a2a210a279ULL, 0x295fc57676b37697ULL,
        0x8d3ef6b3b345b3f1ULL, 0xa31dc2bebe7cbe99ULL, 0x9e501fceced1ce3eULL, 0xa914cebdbd73bd81ULL, 0xc36d82aeae2cae19ULL, 0x4ca583e9e96ae91bULL, 0x1b91128a8a988a24ULL, 0xa697c43131f53195ULL,
        0x4854701c1c6c1ce0ULL, 0x52be97ecec7bec33ULL, 0x1cede3f1f112f1dbULL, 0x71e85e9999c799bcULL, 0x5fcb6a9494fe94d4ULL, 0xdb7192aaaa38aa39ULL, 0x0ef8fff6f609f6e3ULL, 0xd4f2982626be262dULL,
        0xe2cdbc2f2f932f65ULL, 0x58b79befef74ef2bULL, 0x4aa287e8e86fe813ULL, 0x0f830a8c8c868c14ULL, 0xbe8bd43535e135b5ULL, 0x0a090c03030f0318ULL, 0xc21677d4d4a3d4eeULL, 0x1f60e17f7f9e7fdfULL,
        0x20dbcbfbfb30fb8bULL, 0x1e1b140505110528ULL, 0xbc7d23c1c1e2c146ULL, 0xd987655e5e3b5ecaULL, 0x47d77a9090ea90f4ULL, 0xc0e0802020a0201dULL, 0x8eb3f43d3dc93df5ULL, 0x2ba9328282b08264ULL,
        0x08fffbf7f70cf7ebULL, 0x46ac8feaea65ea03ULL, 0x3c36280a0a220a50ULL, 0x2e23340d0d390d68ULL, 0x1967e57e7e9b7ed7ULL, 0x2ad2c7f8f83ff893ULL, 0xfdad5d50500d50baULL, 0x5c46681a1a721ad0ULL,
        0xa26637c4c4f3c46eULL, 0x12151c07071b0738ULL, 0xefb8415757165782ULL, 0xb70fdab8b862b8a9ULL, 0x88b4f03c3ccc3cfdULL, 0x5133956262f76237ULL, 0x7093abe3e348e34bULL, 0x8a4207c8c8cfc80eULL,
        0xcf638aacac26ac09ULL, 0xf1a35552520752aaULL, 0x45218d6464e96407ULL, 0x6070401010501080ULL, 0xda0a67d0d0b7d0ceULL, 0xec3543d9d99ad986ULL, 0x6a794c13135f1398ULL, 0x2824300c0c3c0c60ULL,
        0x6c7e4812125a1290ULL, 0xf6dfa429298d2955ULL, 0xfbaa5951510851b2ULL, 0xb108deb9b967b9a1ULL, 0x98571bcfcfd4cf36ULL, 0xce187fd6d6a9d6feULL, 0x3744d17373a273bfULL, 0x09840e8d8d838d1cULL,
        0x21a03e8181bf817cULL, 0xe5b14d545419549aULL, 0xba7a27c0c0e7c04eULL, 0x54b993eded7eed3bULL, 0xb9f7254e4e6b4e4aULL, 0x85c10d444449441aULL, 0xf552a6a7a701a751ULL, 0xfcd6a82a2a822a4dULL,
        0x39bc2e8585ab855cULL, 0xdefb942525b12535ULL, 0x6e88bfe6e659e663ULL, 0x864c0fcacac5ca1eULL, 0x1569ed7c7c917cc7ULL, 0x1d96168b8b9d8b2cULL, 0xe9bf45565613568aULL, 0x27a73a8080ba8074ULL
    },
    {
        0x501fceced1ce3e9eULL, 0x06d6bbbb6dbbb1bdULL, 0xab8bebeb60eb0b40ULL, 0xd9729292e092e44bULL, 0xac8feaea65ea0346ULL, 0x4b0bcbcbc0cb1680ULL, 0x794c13135f13986aULL, 0x7d23c1c1e2c146bcULL,
        0xa583e9e96ae91b4cULL, 0xa6e83a3ad23acd9cULL, 0x187fd6d6a9d6feceULL, 0x39f2b2b240b2f98bULL, 0x046fd2d2bdd2ded6ULL, 0xd77a9090ea90f447ULL, 0x655c17174b17b872ULL, 0xd2c7f8f83ff8932aULL,
        0xd315424257422a91ULL, 0x6b5415154115a87eULL, 0xbf45565613568ae9ULL, 0x2beab4b45eb4c99fULL, 0x26896565ec650f43ULL, 0x54701c1c6c1ce048ULL, 0x9f1a888892883417ULL, 0xd411434352432297ULL,
        0x6133c5c5f6c566a4ULL, 0x896d5c5c315cdad5ULL, 0x82d83636ee36adb4ULL, 0x01d2baba68bab9bbULL, 0xf1f3f5f506f5fb04ULL, 0xb8415757165782efULL, 0x28816767e6671f4fULL, 0x840e8d8d838d1c09ULL,
        0x97c43131f53195a6ULL, 0xf8fff6f609f6e30eULL, 0x218d6464e9640745ULL, 0x957d58582558facdULL, 0xfd429e9edc9e8463ULL, 0xf6f7f4f403f4f302ULL, 0xee882222aa220dccULL, 0x7192aaaa38aa39dbULL,
        0x56c97575bc758f23ULL, 0x2d3c0f0f330f7822ULL, 0x0e0802020a02100cULL, 0x30feb1b14fb1e181ULL, 0x275bdfdf84dfb6f8ULL, 0x1ea96d6dc46d4f73ULL, 0x44d17373a273bf37ULL, 0xfe294d4d644d52b3ULL,
        0x69ed7c7c917cc715ULL, 0xf2982626be262dd4ULL, 0xcab82e2e962e6de4ULL, 0xfffbf7f70cf7eb08ULL, 0x3820080828084030ULL, 0x8e695d5d345dd2d3ULL, 0xc10d444449441a85ULL, 0xbaf83e3ec63eed84ULL,
        0xfa469f9fd99f8c65ULL, 0x6c5014144414a078ULL, 0x4207c8c8cfc80e8aULL, 0x6d82aeae2cae19c3ULL, 0xb14d545419549ae5ULL, 0x7040101050108060ULL, 0x3247d8d89fd88eeaULL, 0x13cabcbc76bc89afULL,
        0x46681a1a721ad05cULL, 0x0cb16b6bda6b7f67ULL, 0x02b96969d0696f6bULL, 0xe3ebf3f318f3cb10ULL, 0x14cebdbd73bd81a9ULL, 0x99cc3333ff3385aaULL, 0x7696abab3dab31ddULL, 0xdccffafa35fa8326ULL,
        0x0d63d1d1b2d1c6dcULL, 0xe6569b9bcd9bac7dULL, 0x05bd6868d568676dULL, 0xf7254e4e6b4e4ab9ULL, 0x625816164e16b074ULL, 0xcc6e9595fb95dc59ULL, 0xd07e9191ef91fc41ULL, 0xb09feeee71ee235eULL,
        0xf92d4c4c614c5ab5ULL, 0x34916363f2633f57ULL, 0x8d028e8e8c8e0403ULL, 0x9c715b5b2a5be2c7ULL, 0x5e17ccccdbcc2e92ULL, 0xb4f03c3ccc3cfd88ULL, 0x4f6419197d19c856ULL, 0x40bea1a11fa161e1ULL,
        0xa03e8181bf817c21ULL, 0xe2394949704972abULL, 0x7cf17b7b8a7bff07ULL, 0x3543d9d99ad986ecULL, 0x10a16f6fce6f5f7fULL, 0x85dc3737eb37a5b2ULL, 0x3d9d6060fd60275dULL, 0x4c0fcacac5ca1e86ULL,
        0x8fbbe7e75ce76b68ULL, 0xd1ac2b2b872b45faULL, 0xe53d484875487aadULL, 0xc9d3fdfd2efdbb34ULL, 0xc5629696f496c453ULL, 0xc60945454c451283ULL, 0xced7fcfc2bfcb332ULL, 0xda1941415841329bULL,
        0x7e4812125a12906cULL, 0x23340d0d390d682eULL, 0x72f979798079ef0bULL, 0x81b3e5e556e57b64ULL, 0x981e898997893c11ULL, 0x830a8c8c868c140fULL, 0x93abe3e348e34b70ULL, 0xe0802020a0201dc0ULL,
        0x90c03030f0309da0ULL, 0x2e57dcdc8bdcaef2ULL, 0x22e6b7b751b7d195ULL, 0x19ad6c6cc16c4775ULL, 0xeb354a4a7f4a6aa1ULL, 0x2ceeb5b55bb5c199ULL, 0xbdfc3f3fc33fe582ULL, 0xc2669797f197cc55ULL,
        0x1677d4d4a3d4eec2ULL, 0x33956262f7623751ULL, 0xc3b42d2d992d75eeULL, 0x121806061e063014ULL, 0x5baaa4a40ea449ffULL, 0x5caea5a50ba541f9ULL, 0xae368383b5836c2dULL, 0x80615f5f3e5fc2dfULL,
        0xd6a82a2a822a4dfcULL, 0x3c4fdada95da9ee6ULL, 0x4503c9c9cac9068cULL, 0x0000000000000000ULL, 0x67e57e7e9b7ed719ULL, 0x49b2a2a210a279ebULL, 0xb64955551c5592e3ULL, 0x1ac6bfbf79bf91a5ULL,
        0x7744111155118866ULL, 0x1173d5d5a6d5e6c4ULL, 0xf34a9c9cd69c946fULL, 0x571bcfcfd4cf3698ULL, 0x2a380e0e360e7024ULL, 0x36280a0a220a503cULL, 0xb3f43d3dc93df58eULL, 0xaa5951510851b2fbULL,
        0x6ee97d7d947dcf13ULL, 0xde769393e593ec4dULL, 0x416c1b1b771bd85aULL, 0xc0dffefe21fea33eULL, 0x6637c4c4f3c46ea2ULL, 0xc80147474647028fULL, 0x3f2409092d094836ULL, 0xb5228686a4864433ULL,
        0x312c0b0b270b583aULL, 0x8a068f8f898f0c05ULL, 0xf44e9d9dd39d9c69ULL, 0x0bb56a6adf6a7761ULL, 0x151c07071b073812ULL, 0x08deb9b967b9a1b1ULL, 0x37fab0b04ab0e987ULL, 0xef5a9898c298b477ULL,
        0x486018187818c050ULL, 0x9ec83232fa328dacULL, 0x4ad97171a871af3bULL, 0xec314b4b7a4b62a7ULL, 0xb79befef74ef2b58ULL, 0xa1ec3b3bd73bc59aULL, 0x4ddd7070ad70a73dULL, 0x47baa0a01aa069e7ULL,
        0x86b7e4e453e47362ULL, 0xdd1d40405d403a9dULL, 0xc7dbffff24ffab38ULL, 0x732bc3c3e8c356b0ULL, 0x789ea9a937a921d1ULL, 0x88bfe6e659e6636eULL, 0x75fd78788578e70dULL, 0xd5c3f9f93af99b2cULL,
        0x96168b8b9d8b2c1dULL, 0xcf05464643460a89ULL, 0xa73a8080ba807427ULL, 0x5a781e1e661ef044ULL, 0xa8e03838d838dd90ULL, 0x9da3e1e142e15b7cULL, 0x0fdab8b862b8a9b7ULL, 0x7f9aa8a832a829d7ULL,
        0x9aa7e0e047e0537aULL, 0x24300c0c3c0c6028ULL, 0xe98c2323af2305caULL, 0x5fc57676b3769729ULL, 0x53741d1d691de84eULL, 0xfb942525b12535deULL, 0xfc902424b4243dd8ULL, 0x1b1405051105281eULL,
        0xede3f1f112f1db1cULL, 0x17a56e6ecb6e5779ULL, 0xcb6a9494fe94d45fULL, 0xd8a0282888285df0ULL, 0xe1529a9ac89aa47bULL, 0xbb2a8484ae84543fULL, 0xa287e8e86fe8134aULL, 0x4eb6a3a315a371edULL,
        0xf0214f4f6e4f42bfULL, 0x58c17777b6779f2fULL, 0x036bd3d3b8d3d6d0ULL, 0xbc2e8585ab855c39ULL, 0x94afe2e24de24376ULL, 0xa35552520752aaf1ULL, 0xe4eff2f21df2c316ULL, 0xa9328282b082642bULL,
        0xad5d50500d50bafdULL, 0x7bf57a7a8f7af701ULL, 0xcdbc2f2f932f65e2ULL, 0x51cd7474b9748725ULL, 0xa45153530253a2f7ULL, 0x3ef6b3b345b3f18dULL, 0x3a996161f8612f5bULL, 0x6a86afaf29af11c5ULL,
        0xafe43939dd39d596ULL, 0x8bd43535e135b5beULL, 0x205fdede81debefeULL, 0x5913cdcddecd2694ULL, 0x5d7c1f1f631ff842ULL, 0xe85e9999c799bc71ULL, 0x638aacac26ac09cfULL, 0x648eadad23ad01c9ULL,
        0x43d57272a772b731ULL, 0xc4b02c2c9c2c7de8ULL, 0x2953dddd8edda6f4ULL, 0x0a67d0d0b7d0cedaULL, 0xb2268787a1874c35ULL, 0x1dc2bebe7cbe99a3ULL, 0x87655e5e3b5ecad9ULL, 0x55a2a6a604a659f3ULL,
        0xbe97ecec7bec3352ULL, 0x1c10040414042018ULL, 0x683fc6c6f9c67eaeULL, 0x090c03030f03180aULL, 0x8cd03434e434bdb8ULL, 0xdbcbfbfb30fb8b20ULL, 0x3b4bdbdb90db96e0ULL, 0x927959592059f2cbULL,
        0x25e2b6b654b6d993ULL, 0x742fc2c2edc25eb6ULL, 0x0704010105010806ULL, 0xeae7f0f017f0d31aULL, 0x9b755a5a2f5aeac1ULL, 0xb993eded7eed3b54ULL, 0x52a6a7a701a751f5ULL, 0x2f856666e3661749ULL,
        0xe7842121a52115c6ULL, 0x60e17f7f9e7fdf1fULL, 0x91128a8a988a241bULL, 0xf59c2727bb2725d2ULL, 0x6f3bc7c7fcc776a8ULL, 0x7a27c0c0e7c04ebaULL, 0xdfa429298d2955f6ULL, 0x1f7bd7d7acd7f6c8ULL
    },
    {
        0x769393e593ec4ddeULL, 0x43d9d99ad986ec35ULL, 0x529a9ac89aa47be1ULL, 0xeeb5b55bb5c1992cULL, 0x5a9898c298b477efULL, 0x882222aa220dcceeULL, 0x0945454c451283c6ULL, 0xd7fcfc2bfcb332ceULL,
        0xd2baba68bab9bb01ULL, 0xb56a6adf6a77610bULL, 0x5bdfdf84dfb6f827ULL, 0x0802020a02100c0eULL, 0x469f9fd99f8c65faULL, 0x57dcdc8bdcaef22eULL, 0x5951510851b2fbaaULL, 0x7959592059f2cb92ULL,
        0x354a4a7f4a6aa1ebULL, 0x5c17174b17b87265ULL, 0xac2b2b872b45fad1ULL, 0x2fc2c2edc25eb674ULL, 0x6a9494fe94d45fcbULL, 0xf7f4f403f4f302f6ULL, 0xd6bbbb6dbbb1bd06ULL, 0xb6a3a315a371ed4eULL,
        0x956262f762375133ULL, 0xb7e4e453e4736286ULL, 0xd97171a871af3b4aULL, 0x77d4d4a3d4eec216ULL, 0x13cdcddecd269459ULL, 0xdd7070ad70a73d4dULL, 0x5816164e16b07462ULL, 0xa3e1e142e15b7c9dULL,
        0x394949704972abe2ULL, 0xf03c3ccc3cfd88b4ULL, 0x27c0c0e7c04eba7aULL, 0x47d8d89fd88eea32ULL, 0x6d5c5c315cdad589ULL, 0x569b9bcd9bac7de6ULL, 0x8eadad23ad01c964ULL, 0x2e8585ab855c39bcULL,
        0x5153530253a2f7a4ULL, 0xbea1a11fa161e140ULL, 0xf57a7a8f7af7017bULL, 0x07c8c8cfc80e8a42ULL, 0xb42d2d992d75eec3ULL, 0xa7e0e047e0537a9aULL, 0x63d1d1b2d1c6dc0dULL, 0xd57272a772b73143ULL,
        0xa2a6a604a659f355ULL, 0xb02c2c9c2c7de8c4ULL, 0x37c4c4f3c46ea266ULL, 0xabe3e348e34b7093ULL, 0xc57676b37697295fULL, 0xfd78788578e70d75ULL, 0xe6b7b751b7d19522ULL, 0xeab4b45eb4c99f2bULL,
        0x2409092d0948363fULL, 0xec3b3bd73bc59aa1ULL, 0x380e0e360e70242aULL, 0x1941415841329bdaULL, 0x2d4c4c614c5ab5f9ULL, 0x5fdede81debefe20ULL, 0xf2b2b240b2f98b39ULL, 0x7a9090ea90f447d7ULL,
        0x942525b12535defbULL, 0xaea5a50ba541f95cULL, 0x7bd7d7acd7f6c81fULL, 0x0c03030f03180a09ULL, 0x4411115511886677ULL, 0x0000000000000000ULL, 0x2bc3c3e8c356b073ULL, 0xb82e2e962e6de4caULL,
        0x729292e092e44bd9ULL, 0x9befef74ef2b58b7ULL, 0x254e4e6b4e4ab9f7ULL, 0x4812125a12906c7eULL, 0x4e9d9dd39d9c69f4ULL, 0xe97d7d947dcf136eULL, 0x0bcbcbc0cb16804bULL, 0xd43535e135b5be8bULL,
        0x4010105010806070ULL, 0x73d5d5a6d5e6c411ULL, 0x214f4f6e4f42bff0ULL, 0x429e9edc9e8463fdULL, 0x294d4d644d52b3feULL, 0x9ea9a937a921d178ULL, 0x4955551c5592e3b6ULL, 0x3fc6c6f9c67eae68ULL,
        0x67d0d0b7d0ceda0aULL, 0xf17b7b8a7bff077cULL, 0x6018187818c05048ULL, 0x669797f197cc55c2ULL, 0x6bd3d3b8d3d6d003ULL, 0xd83636ee36adb482ULL, 0xbfe6e659e6636e88ULL, 0x3d484875487aade5ULL,
        0x45565613568ae9bfULL, 0x3e8181bf817c21a0ULL, 0x068f8f898f0c058aULL, 0xc17777b6779f2f58ULL, 0x17ccccdbcc2e925eULL, 0x4a9c9cd69c946ff3ULL, 0xdeb9b967b9a1b108ULL, 0xafe2e24de2437694ULL,
        0x8aacac26ac09cf63ULL, 0xdab8b862b8a9b70fULL, 0xbc2f2f932f65e2cdULL, 0x5415154115a87e6bULL, 0xaaa4a40ea449ff5bULL, 0xed7c7c917cc71569ULL, 0x4fdada95da9ee63cULL, 0xe03838d838dd90a8ULL,
        0x781e1e661ef0445aULL, 0x2c0b0b270b583a31ULL, 0x1405051105281e1bULL, 0x7fd6d6a9d6fece18ULL, 0x5014144414a0786cULL, 0xa56e6ecb6e577917ULL, 0xad6c6cc16c477519ULL, 0xe57e7e9b7ed71967ULL,
        0x856666e36617492fULL, 0xd3fdfd2efdbb34c9ULL, 0xfeb1b14fb1e18130ULL, 0xb3e5e556e57b6481ULL, 0x9d6060fd60275d3dULL, 0x86afaf29af11c56aULL, 0x655e5e3b5ecad987ULL, 0xcc3333ff3385aa99ULL,
        0x268787a1874c35b2ULL, 0x03c9c9cac9068c45ULL, 0xe7f0f017f0d31aeaULL, 0x695d5d345dd2d38eULL, 0xa96d6dc46d4f731eULL, 0xfc3f3fc33fe582bdULL, 0x1a8888928834179fULL, 0x0e8d8d838d1c0984ULL,
        0x3bc7c7fcc776a86fULL, 0xfbf7f70cf7eb08ffULL, 0x741d1d691de84e53ULL, 0x83e9e96ae91b4ca5ULL, 0x97ecec7bec3352beULL, 0x93eded7eed3b54b9ULL, 0x3a8080ba807427a7ULL, 0xa429298d2955f6dfULL,
        0x9c2727bb2725d2f5ULL, 0x1bcfcfd4cf369857ULL, 0x5e9999c799bc71e8ULL, 0x9aa8a832a829d77fULL, 0x5d50500d50bafdadULL, 0x3c0f0f330f78222dULL, 0xdc3737eb37a5b285ULL, 0x902424b4243dd8fcULL,
        0xa0282888285df0d8ULL, 0xc03030f0309da090ULL, 0x6e9595fb95dc59ccULL, 0x6fd2d2bdd2ded604ULL, 0xf83e3ec63eed84baULL, 0x715b5b2a5be2c79cULL, 0x1d40405d403a9dddULL, 0x368383b5836c2daeULL,
        0xf6b3b345b3f18d3eULL, 0xb96969d0696f6b02ULL, 0x415757165782efb8ULL, 0x7c1f1f631ff8425dULL, 0x1c07071b07381215ULL, 0x701c1c6c1ce04854ULL, 0x128a8a988a241b91ULL, 0xcabcbc76bc89af13ULL,
        0x802020a0201dc0e0ULL, 0x8bebeb60eb0b40abULL, 0x1fceced1ce3e9e50ULL, 0x028e8e8c8e04038dULL, 0x96abab3dab31dd76ULL, 0x9feeee71ee235eb0ULL, 0xc43131f53195a697ULL, 0xb2a2a210a279eb49ULL,
        0xd17373a273bf3744ULL, 0xc3f9f93af99b2cd5ULL, 0x0fcacac5ca1e864cULL, 0xe83a3ad23acd9ca6ULL, 0x681a1a721ad05c46ULL, 0xcbfbfb30fb8b20dbULL, 0x340d0d390d682e23ULL, 0x23c1c1e2c146bc7dULL,
        0xdffefe21fea33ec0ULL, 0xcffafa35fa8326dcULL, 0xeff2f21df2c316e4ULL, 0xa16f6fce6f5f7f10ULL, 0xcebdbd73bd81a914ULL, 0x629696f496c453c5ULL, 0x53dddd8edda6f429ULL, 0x11434352432297d4ULL,
        0x5552520752aaf1a3ULL, 0xe2b6b654b6d99325ULL, 0x2008082808403038ULL, 0xebf3f318f3cb10e3ULL, 0x82aeae2cae19c36dULL, 0xc2bebe7cbe99a31dULL, 0x6419197d19c8564fULL, 0x1e898997893c1198ULL,
        0xc83232fa328dac9eULL, 0x982626be262dd4f2ULL, 0xfab0b04ab0e98737ULL, 0x8feaea65ea0346acULL, 0x314b4b7a4b62a7ecULL, 0x8d6464e964074521ULL, 0x2a8484ae84543fbbULL, 0x328282b082642ba9ULL,
        0xb16b6bda6b7f670cULL, 0xf3f5f506f5fb04f1ULL, 0xf979798079ef0b72ULL, 0xc6bfbf79bf91a51aULL, 0x0401010501080607ULL, 0x615f5f3e5fc2df80ULL, 0xc97575bc758f2356ULL, 0x916363f2633f5734ULL,
        0x6c1b1b771bd85a41ULL, 0x8c2323af2305cae9ULL, 0xf43d3dc93df58eb3ULL, 0xbd6868d568676d05ULL, 0xa82a2a822a4dfcd6ULL, 0x896565ec650f4326ULL, 0x87e8e86fe8134aa2ULL, 0x7e9191ef91fc41d0ULL,
        0xfff6f609f6e30ef8ULL, 0xdbffff24ffab38c7ULL, 0x4c13135f13986a79ULL, 0x7d58582558facd95ULL, 0xe3f1f112f1db1cedULL, 0x0147474647028fc8ULL, 0x280a0a220a503c36ULL, 0xe17f7f9e7fdf1f60ULL,
        0x33c5c5f6c566a461ULL, 0xa6a7a701a751f552ULL, 0xbbe7e75ce76b688fULL, 0x996161f8612f5b3aULL, 0x755a5a2f5aeac19bULL, 0x1806061e06301412ULL, 0x05464643460a89cfULL, 0x0d444449441a85c1ULL,
        0x15424257422a91d3ULL, 0x100404140420181cULL, 0xbaa0a01aa069e747ULL, 0x4bdbdb90db96e03bULL, 0xe43939dd39d596afULL, 0x228686a4864433b5ULL, 0x4d545419549ae5b1ULL, 0x92aaaa38aa39db71ULL,
        0x0a8c8c868c140f83ULL, 0xd03434e434bdb88cULL, 0x842121a52115c6e7ULL, 0x168b8b9d8b2c1d96ULL, 0xc7f8f83ff8932ad2ULL, 0x300c0c3c0c602824ULL, 0xcd7474b974872551ULL, 0x816767e6671f4f28ULL
    },
    {
        0x6868d568676d05bdULL, 0x8d8d838d1c09840eULL, 0xcacac5ca1e864c0fULL, 0x4d4d644d52b3fe29ULL, 0x7373a273bf3744d1ULL, 0x4b4b7a4b62a7ec31ULL, 0x4e4e6b4e4ab9f725ULL, 0x2a2a822a4dfcd6a8ULL,
        0xd4d4a3d4eec21677ULL, 0x52520752aaf1a355ULL, 0x2626be262dd4f298ULL, 0xb3b345b3f18d3ef6ULL, 0x545419549ae5b14dULL, 0x1e1e661ef0445a78ULL, 0x19197d19c8564f64ULL, 0x1f1f631ff8425d7cULL,
        0x2222aa220dccee88ULL, 0x03030f03180a090cULL, 0x464643460a89cf05ULL, 0x3d3dc93df58eb3f4ULL, 0x2d2d992d75eec3b4ULL, 0x4a4a7f4a6aa1eb35ULL, 0x53530253a2f7a451ULL, 0x8383b5836c2dae36ULL,
        0x13135f13986a794cULL, 0x8a8a988a241b9112ULL, 0xb7b751b7d19522e6ULL, 0xd5d5a6d5e6c41173ULL, 0x2525b12535defb94ULL, 0x79798079ef0b72f9ULL, 0xf5f506f5fb04f1f3ULL, 0xbdbd73bd81a914ceULL,
        0x58582558facd957dULL, 0x2f2f932f65e2cdbcULL, 0x0d0d390d682e2334ULL, 0x02020a02100c0e08ULL, 0xeded7eed3b54b993ULL, 0x51510851b2fbaa59ULL, 0x9e9edc9e8463fd42ULL, 0x1111551188667744ULL,
        0xf2f21df2c316e4efULL, 0x3e3ec63eed84baf8ULL, 0x55551c5592e3b649ULL, 0x5e5e3b5ecad98765ULL, 0xd1d1b2d1c6dc0d63ULL, 0x16164e16b0746258ULL, 0x3c3ccc3cfd88b4f0ULL, 0x6666e36617492f85ULL,
        0x7070ad70a73d4dddULL, 0x5d5d345dd2d38e69ULL, 0xf3f318f3cb10e3ebULL, 0x45454c451283c609ULL, 0x40405d403a9ddd1dULL, 0xccccdbcc2e925e17ULL, 0xe8e86fe8134aa287ULL, 0x9494fe94d45fcb6aULL,
        0x565613568ae9bf45ULL, 0x0808280840303820ULL, 0xceced1ce3e9e501fULL, 0x1a1a721ad05c4668ULL, 0x3a3ad23acd9ca6e8ULL, 0xd2d2bdd2ded6046fULL, 0xe1e142e15b7c9da3ULL, 0xdfdf84dfb6f8275bULL,
        0xb5b55bb5c1992ceeULL, 0x3838d838dd90a8e0ULL, 0x6e6ecb6e577917a5ULL, 0x0e0e360e70242a38ULL, 0xe5e556e57b6481b3ULL, 0xf4f403f4f302f6f7ULL, 0xf9f93af99b2cd5c3ULL, 0x8686a4864433b522ULL,
        0xe9e96ae91b4ca583ULL, 0x4f4f6e4f42bff021ULL, 0xd6d6a9d6fece187fULL, 0x8585ab855c39bc2eULL, 0x2323af2305cae98cULL, 0xcfcfd4cf3698571bULL, 0x3232fa328dac9ec8ULL, 0x9999c799bc71e85eULL,
        0x3131f53195a697c4ULL, 0x14144414a0786c50ULL, 0xaeae2cae19c36d82ULL, 0xeeee71ee235eb09fULL, 0xc8c8cfc80e8a4207ULL, 0x484875487aade53dULL, 0xd3d3b8d3d6d0036bULL, 0x3030f0309da090c0ULL,
        0xa1a11fa161e140beULL, 0x9292e092e44bd972ULL, 0x41415841329bda19ULL, 0xb1b14fb1e18130feULL, 0x18187818c0504860ULL, 0xc4c4f3c46ea26637ULL, 0x2c2c9c2c7de8c4b0ULL, 0x7171a871af3b4ad9ULL,
        0x7272a772b73143d5ULL, 0x444449441a85c10dULL, 0x15154115a87e6b54ULL, 0xfdfd2efdbb34c9d3ULL, 0x3737eb37a5b285dcULL, 0xbebe7cbe99a31dc2ULL, 0x5f5f3e5fc2df8061ULL, 0xaaaa38aa39db7192ULL,
        0x9b9bcd9bac7de656ULL, 0x8888928834179f1aULL, 0xd8d89fd88eea3247ULL, 0xabab3dab31dd7696ULL, 0x898997893c11981eULL, 0x9c9cd69c946ff34aULL, 0xfafa35fa8326dccfULL, 0x6060fd60275d3d9dULL,
        0xeaea65ea0346ac8fULL, 0xbcbc76bc89af13caULL, 0x6262f76237513395ULL, 0x0c0c3c0c60282430ULL, 0x2424b4243dd8fc90ULL, 0xa6a604a659f355a2ULL, 0xa8a832a829d77f9aULL, 0xecec7bec3352be97ULL,
        0x6767e6671f4f2881ULL, 0x2020a0201dc0e080ULL, 0xdbdb90db96e03b4bULL, 0x7c7c917cc71569edULL, 0x282888285df0d8a0ULL, 0xdddd8edda6f42953ULL, 0xacac26ac09cf638aULL, 0x5b5b2a5be2c79c71ULL,
        0x3434e434bdb88cd0ULL, 0x7e7e9b7ed71967e5ULL, 0x1010501080607040ULL, 0xf1f112f1db1cede3ULL, 0x7b7b8a7bff077cf1ULL, 0x8f8f898f0c058a06ULL, 0x6363f2633f573491ULL, 0xa0a01aa069e747baULL,
        0x05051105281e1b14ULL, 0x9a9ac89aa47be152ULL, 0x434352432297d411ULL, 0x7777b6779f2f58c1ULL, 0x2121a52115c6e784ULL, 0xbfbf79bf91a51ac6ULL, 0x2727bb2725d2f59cULL, 0x09092d0948363f24ULL,
        0xc3c3e8c356b0732bULL, 0x9f9fd99f8c65fa46ULL, 0xb6b654b6d99325e2ULL, 0xd7d7acd7f6c81f7bULL, 0x29298d2955f6dfa4ULL, 0xc2c2edc25eb6742fULL, 0xebeb60eb0b40ab8bULL, 0xc0c0e7c04eba7a27ULL,
        0xa4a40ea449ff5baaULL, 0x8b8b9d8b2c1d9616ULL, 0x8c8c868c140f830aULL, 0x1d1d691de84e5374ULL, 0xfbfb30fb8b20dbcbULL, 0xffff24ffab38c7dbULL, 0xc1c1e2c146bc7d23ULL, 0xb2b240b2f98b39f2ULL,
        0x9797f197cc55c266ULL, 0x2e2e962e6de4cab8ULL, 0xf8f83ff8932ad2c7ULL, 0x6565ec650f432689ULL, 0xf6f609f6e30ef8ffULL, 0x7575bc758f2356c9ULL, 0x07071b073812151cULL, 0x0404140420181c10ULL,
        0x4949704972abe239ULL, 0x3333ff3385aa99ccULL, 0xe4e453e4736286b7ULL, 0xd9d99ad986ec3543ULL, 0xb9b967b9a1b108deULL, 0xd0d0b7d0ceda0a67ULL, 0x424257422a91d315ULL, 0xc7c7fcc776a86f3bULL,
        0x6c6cc16c477519adULL, 0x9090ea90f447d77aULL, 0x0000000000000000ULL, 0x8e8e8c8e04038d02ULL, 0x6f6fce6f5f7f10a1ULL, 0x50500d50bafdad5dULL, 0x0101050108060704ULL, 0xc5c5f6c566a46133ULL,
        0xdada95da9ee63c4fULL, 0x47474647028fc801ULL, 0x3f3fc33fe582bdfcULL, 0xcdcddecd26945913ULL, 0x6969d0696f6b02b9ULL, 0xa2a210a279eb49b2ULL, 0xe2e24de2437694afULL, 0x7a7a8f7af7017bf5ULL,
        0xa7a701a751f552a6ULL, 0xc6c6f9c67eae683fULL, 0x9393e593ec4dde76ULL, 0x0f0f330f78222d3cULL, 0x0a0a220a503c3628ULL, 0x06061e0630141218ULL, 0xe6e659e6636e88bfULL, 0x2b2b872b45fad1acULL,
        0x9696f496c453c562ULL, 0xa3a315a371ed4eb6ULL, 0x1c1c6c1ce0485470ULL, 0xafaf29af11c56a86ULL, 0x6a6adf6a77610bb5ULL, 0x12125a12906c7e48ULL, 0x8484ae84543fbb2aULL, 0x3939dd39d596afe4ULL,
        0xe7e75ce76b688fbbULL, 0xb0b04ab0e98737faULL, 0x8282b082642ba932ULL, 0xf7f70cf7eb08fffbULL, 0xfefe21fea33ec0dfULL, 0x9d9dd39d9c69f44eULL, 0x8787a1874c35b226ULL, 0x5c5c315cdad5896dULL,
        0x8181bf817c21a03eULL, 0x3535e135b5be8bd4ULL, 0xdede81debefe205fULL, 0xb4b45eb4c99f2beaULL, 0xa5a50ba541f95caeULL, 0xfcfc2bfcb332ced7ULL, 0x8080ba807427a73aULL, 0xefef74ef2b58b79bULL,
        0xcbcbc0cb16804b0bULL, 0xbbbb6dbbb1bd06d6ULL, 0x6b6bda6b7f670cb1ULL, 0x7676b37697295fc5ULL, 0xbaba68bab9bb01d2ULL, 0x5a5a2f5aeac19b75ULL, 0x7d7d947dcf136ee9ULL, 0x78788578e70d75fdULL,
        0x0b0b270b583a312cULL, 0x9595fb95dc59cc6eULL, 0xe3e348e34b7093abULL, 0xadad23ad01c9648eULL, 0x7474b974872551cdULL, 0x9898c298b477ef5aULL, 0x3b3bd73bc59aa1ecULL, 0x3636ee36adb482d8ULL,
        0x6464e9640745218dULL, 0x6d6dc46d4f731ea9ULL, 0xdcdc8bdcaef22e57ULL, 0xf0f017f0d31aeae7ULL, 0x59592059f2cb9279ULL, 0xa9a937a921d1789eULL, 0x4c4c614c5ab5f92dULL, 0x17174b17b872655cULL,
        0x7f7f9e7fdf1f60e1ULL, 0x9191ef91fc41d07eULL, 0xb8b862b8a9b70fdaULL, 0xc9c9cac9068c4503ULL, 0x5757165782efb841ULL, 0x1b1b771bd85a416cULL, 0xe0e047e0537a9aa7ULL, 0x6161f8612f5b3a99ULL
    }
};

static const uint64_t inv_subrowcol_default[8][256] = {
    {
        0x7826942b9f5f8a9aULL, 0x210f43c934970c53ULL, 0x5f028fdd9d0551b8ULL, 0x14facd82b494c83bULL, 0x2b72ab886edd68c0ULL, 0xa6a87e5bff19d9b4ULL, 0xa29ae571db6443eaULL, 0x039b2c911be8e5b6ULL,
        0xd9275dcb5fd32cc6ULL, 0x10c856a890e95265ULL, 0x7d96e085b27ab85dULL, 0x31c71561a47e5e36ULL, 0x74702455f3d83978ULL, 0xe8e048aafbad72f0ULL, 0x9b39db4437e03460ULL, 0x75f2cbd1fa8091e1ULL,
        0x1ab5bee9caa336f6ULL, 0x8395a6b8eff34fb9ULL, 0x64b872fd63316b1dULL, 0xe1068c7aba0ff3d5ULL, 0xeecb1095cd60a581ULL, 0xbc1dc0b235baef42ULL, 0xf04c355623be0929ULL, 0xb252b3d94b8d118fULL,
        0x18ac7dfcd8137bd9ULL, 0xbbb477090a2f90aaULL, 0x8625d216c2d67d7eULL, 0x66a1b1e871812632ULL, 0x6f4775383023a717ULL, 0x92df1f947642b545ULL, 0xe962a72ef2f5da69ULL, 0x8bf18deca7096605ULL,
        0xc86de4e7c662d63aULL, 0xaafece25939e6a56ULL, 0x5c99a34c86edb40eULL, 0x52d6d027f8da4ac3ULL, 0x6b75ee12145e3d49ULL, 0x54fd8818ce179db2ULL, 0xa3180af5d23ceb73ULL, 0xbe0403a7270aa26dULL,
        0xfe03463d5d89f7e4ULL, 0xf1cedad22ae6a1b0ULL, 0xd143769f1729057aULL, 0xc7a07808b10d806eULL, 0xfc1a85284f39bacbULL, 0xa4b1bd4eeda9949bULL, 0x0bff07c55312cc0aULL, 0xef49ff11c4380d18ULL,
        0xc392e32295701a30ULL, 0x7f8f2390a0caf572ULL, 0x62932ac255fcbc6cULL, 0xc9ef0b63cf3a7ea3ULL, 0xf9aaf186621c880cULL, 0x818c65adfd430296ULL, 0x325c39f0bf96bb80ULL, 0x0c56b07e6c87b3e2ULL,
        0x4bf8425f29919983ULL, 0xb5fb046274186e67ULL, 0x462c1da54c4e82f8ULL, 0x90c6dc8164f2f86aULL, 0xf8281e026b442095ULL, 0x6af701961d0695d0ULL, 0x5766a489d5ff7804ULL, 0xf3d719c73856ec9fULL,
        0xad57799eac0b15beULL, 0x1b37516dc3fb9e6fULL, 0xc009cfb38e98ff86ULL, 0x9576a82f49d7caadULL, 0xe6af3bc1859a8c3dULL, 0x208dac4d3dcfa4caULL, 0x8ddad5d391c4b174ULL, 0x8e41f9428a2c54c2ULL,
        0x6cdc59a92bcb42a1ULL, 0xe53417509e72698bULL, 0xd0c1991b1e71ade3ULL, 0x8217493ce6abe720ULL, 0xd4f302313a0c37bdULL, 0x5e806059945df921ULL, 0x73d993eecc4d4690ULL, 0xf5fc41f80e9b3beeULL,
        0x13537a398b01b7d3ULL, 0x53543fa3f182e25aULL, 0x2d59f3b75810bfb1ULL, 0x35f58e4b8003c468ULL, 0x886aa17dbce183b3ULL, 0x4c51f5e41604e66bULL, 0x98a2f7d52c08d1d6ULL, 0xa101c9e0c08ca65cULL,
        0x4007459a7a835589ULL, 0xcc5f7fcde21f4c64ULL, 0xa965e2b488768fe0ULL, 0x12d195bd82591f4aULL, 0x2f4030a24aa0f29eULL, 0x56e44b0ddca7d09dULL, 0x914433056daa50f3ULL, 0x37ec4d5e92b38947ULL,
        0xe31f4f6fa8bfbefaULL, 0x50cf1332ea6a07ecULL, 0x6d5eb62d2293ea38ULL, 0x09e6c4d041a28125ULL, 0x8fc316c68374fc5bULL, 0x421e868f683318a6ULL, 0xe08463feb3575b4cULL, 0x3821d1b1e5dcdf13ULL,
        0xed503c04d6884037ULL, 0xd35ab58a05994855ULL, 0x976f6b3a5b678782ULL, 0x6ec59abc397b0f8eULL, 0x5929d7e2abc886c9ULL, 0xa53352cae4f13c02ULL, 0x89e84ef9b5b92b2aULL, 0x1761e113af7c2d8dULL,
        0x28e9871975358d76ULL, 0xdc97296572f61e01ULL, 0x67235e6c78d98eabULL, 0x3d91a51fc8f9edd4ULL, 0x68eec2830fb6d8ffULL, 0xfbb3329370acc523ULL, 0x062b583f36cdd771ULL, 0x15782206bdcc60a2ULL,
        0x16e30e97a6248514ULL, 0x79a47baf96072203ULL, 0xf7e582ed1c2b76c1ULL, 0xde8eea706046532eULL, 0xaf4eba8bbebb5891ULL, 0x08642b5448fa29bcULL, 0x24bf376719b23e94ULL, 0x231680dc2627417cULL,
        0x0dd45ffa65df1b7bULL, 0x1d1c0952f536491eULL, 0xff81a9b954d15f7dULL, 0x992018512550794fULL, 0x71c050fbdefd0bbfULL, 0xc18b203787c0571fULL, 0x253dd8e310ea960dULL, 0xeb7b643be0459746ULL,
        0x0219c31512b04d2fULL, 0xc43b5499aae565d8ULL, 0xeaf98bbfe91d3fdfULL, 0x3a3812a4f76c923cULL, 0x4dd31a601f5c4ef2ULL, 0xa8e70d30812e2779ULL, 0x800e8a29f41baa0fULL, 0x1c9ee6d6fc6ee187ULL,
        0x5d1b4cc88fb51c97ULL, 0x610806534e1459daULL, 0xf255f643310e4406ULL, 0xd2d85a0e0cc1e0ccULL, 0x0182ef840958a899ULL, 0x7e0dcc14a9925debULL, 0x653a9d796a69c384ULL, 0x4e4836f104b4ab44ULL,
        0x4fcad9750dec03ddULL, 0xcddd9049eb47e4fdULL, 0x0e4f736b7e37fecdULL, 0x4185aa1e73dbfd10ULL, 0x725b7c6ac515ee09ULL, 0x8a736268ae51ce9cULL, 0xc5b9bb1da3bdcd41ULL, 0x7bbdb8ba84b76f2cULL,
        0xdabc715a443bc970ULL, 0xe29da0eba1e71663ULL, 0x935df0107f1a1ddcULL, 0x608ae9d7474cf143ULL, 0xd571edb533549f24ULL, 0xa0832664c9d40ec5ULL, 0xfd986aac46611252ULL, 0x4435deb05efecfd7ULL,
        0x0000000000000000ULL, 0x2cdb1c3351481728ULL, 0x94f447ab408f6234ULL, 0x45b7313457a6674eULL, 0xb82f5b9811c7751cULL, 0x8c583a57989c19edULL, 0xdd15c6e17baeb698ULL, 0x696c2d0706ee7066ULL,
        0x3f88660ada49a0fbULL, 0xf47eae7c07c39377ULL, 0x05b074ae2d2532c7ULL, 0xb3d05c5d42d5b916ULL, 0x39a33e35ec84778aULL, 0x0fcd9cef776f5654ULL, 0xacd5961aa553bd27ULL, 0x5b3014f7b978cbe6ULL,
        0x347761cf895b6cf1ULL, 0xc622978cb85528f7ULL, 0xb7e2c77766a82348ULL, 0x77eb08c4e830dcceULL, 0xb9adb41c189fdd85ULL, 0x114ab92c99b1fafcULL, 0x26a6f4720b0273bbULL, 0x1e8725c3eedeaca8ULL,
        0x2af0440c6785c059ULL, 0x04329b2a247d9a5eULL, 0xd7682ea021e4d20bULL, 0x7c140f01bb2210c4ULL, 0x96ed84be523f2f1bULL, 0xca7427f2d4d29b15ULL, 0x47aef22145162a61ULL, 0xa72a91dff641712dULL,
        0x5ab2fb73b020637fULL, 0xcbf6c876dd8a338cULL, 0x6311c5465ca414f5ULL, 0x07a9b7bb3f957fe8ULL, 0xe72dd4458cc224a4ULL, 0x9d12837b012de311ULL, 0x843c1103d0663051ULL, 0x0a7de8415a4a6493ULL,
        0xd6eac12428bc7a92ULL, 0x9c906cff08754b88ULL, 0x7042bf7fd7a5a326ULL, 0xbd9f2f363ce247dbULL, 0xb66028f36ff08bd1ULL, 0x192e9278d14bd340ULL, 0x9f0b406e139dae3eULL, 0x1f05ca47e7860431ULL,
        0x85befe87d93e98c8ULL, 0x439c690b616bb03fULL, 0xba36988d03773833ULL, 0x87a73d92cb8ed5e7ULL, 0xaecc550fb7e3f008ULL, 0xc2100ca69c28b2a9ULL, 0x9abb34c03eb89cf9ULL, 0x49e1814a3b21d4acULL,
        0xecd2d380dfd0e8aeULL, 0x296b689d7c6d25efULL, 0x3c134a9bc1a1454dULL, 0xcfc4535cf9f7a9d2ULL, 0x557f679cc74f352bULL, 0xb479ebe67d40c6feULL, 0xf6676d691573de58ULL, 0x9e89afea1ac506a7ULL,
        0xd8a5b24f568b845fULL, 0x48636ece32797c35ULL, 0xdf0c05f4691efbb7ULL, 0xe4b6f8d4972ac112ULL, 0xfa31dd1779f46dbaULL, 0xbf86ec232e520af4ULL, 0x3e0a898ed3110862ULL, 0x7a3f573e8defc7b5ULL,
        0x27241bf6025adb22ULL, 0x58ab3866a2902e50ULL, 0x3bbafd20fe343aa5ULL, 0x3045fae5ad26f6afULL, 0x2ec2df2643f85a07ULL, 0x22946f582f7fe9e5ULL, 0x366ea2da9beb21deULL, 0x4a7aaddb20c9311aULL,
        0xb1c99f485065f439ULL, 0xb04b70cc593d5ca0ULL, 0xab7c21a19ac6c2cfULL, 0x33ded674b6ce1319ULL, 0xce46bcd8f0af014bULL, 0xdb3e9ede4d6361e9ULL, 0x7669e740e1687457ULL, 0x514dfcb6e332af75ULL
    },
    {
        0x1f4f6fa8bfbefae3ULL, 0xf0440c6785c0592aULL, 0x1dc0b235baef42bcULL, 0x22978cb85528f7c6ULL, 0xcedad22ae6a1b0f1ULL, 0x180af5d23ceb73a3ULL, 0x946f582f7fe9e522ULL, 0xe44b0ddca7d09d56ULL,
        0x906cff08754b889cULL, 0x9f2f363ce247dbbdULL, 0xa1b1e87181263266ULL, 0x21d1b1e5dcdf1338ULL, 0x31dd1779f46dbafaULL, 0x4b70cc593d5ca0b0ULL, 0xd719c73856ec9ff3ULL, 0x8725c3eedeaca81eULL,
        0x71edb533549f24d5ULL, 0x12837b012de3119dULL, 0x3dd8e310ea960d25ULL, 0x29d7e2abc886c959ULL, 0xb477090a2f90aabbULL, 0x45fae5ad26f6af30ULL, 0x9ee6d6fc6ee1871cULL, 0xbefe87d93e98c885ULL,
        0xe30e97a624851416ULL, 0xd6d027f8da4ac352ULL, 0xcc550fb7e3f008aeULL, 0x5ab58a05994855d3ULL, 0x806059945df9215eULL, 0x82ef840958a89901ULL, 0x4ab92c99b1fafc11ULL, 0x281e026b442095f8ULL,
        0x62a72ef2f5da69e9ULL, 0x8b203787c0571fc1ULL, 0x4f736b7e37fecd0eULL, 0xab3866a2902e5058ULL, 0x6ea2da9beb21de36ULL, 0xf447ab408f623494ULL, 0x235e6c78d98eab67ULL, 0x11c5465ca414f563ULL,
        0xd31a601f5c4ef24dULL, 0xa2f7d52c08d1d698ULL, 0x85aa1e73dbfd1041ULL, 0xdc59a92bcb42a16cULL, 0x59f3b75810bfb12dULL, 0xe2c77766a82348b7ULL, 0xb9bb1da3bdcd41c5ULL, 0x96e085b27ab85d7dULL,
        0x99a34c86edb40e5cULL, 0x66a489d5ff780457ULL, 0x95a6b8eff34fb983ULL, 0x7f679cc74f352b55ULL, 0x7de8415a4a64930aULL, 0x9b2c911be8e5b603ULL, 0x4836f104b4ab444eULL, 0xdb1c33514817282cULL,
        0x15c6e17baeb698ddULL, 0xed84be523f2f1b96ULL, 0xe1814a3b21d4ac49ULL, 0x503c04d6884037edULL, 0x4c355623be0929f0ULL, 0x3b5499aae565d8c4ULL, 0x0a898ed31108623eULL, 0xb074ae2d2532c705ULL,
        0x028fdd9d0551b85fULL, 0xf58e4b8003c46835ULL, 0x3352cae4f13c02a5ULL, 0x6c2d0706ee706669ULL, 0x7c21a19ac6c2cfabULL, 0x19c31512b04d2f02ULL, 0xa6f4720b0273bb26ULL, 0x05ca47e78604311fULL,
        0x46bcd8f0af014bceULL, 0x1e868f683318a642ULL, 0x5c39f0bf96bb8032ULL, 0x79ebe67d40c6feb4ULL, 0xff07c55312cc0a0bULL, 0xaef22145162a6147ULL, 0xc1991b1e71ade3d0ULL, 0xded674b6ce131933ULL,
        0x7aaddb20c9311a4aULL, 0x4dfcb6e332af7551ULL, 0x6de4e7c662d63ac8ULL, 0xbf376719b23e9424ULL, 0x07459a7a83558940ULL, 0xac7dfcd8137bd918ULL, 0xdf1f947642b54592ULL, 0x17493ce6abe72082ULL,
        0xfc41f80e9b3beef5ULL, 0xe70d30812e2779a8ULL, 0xd993eecc4d469073ULL, 0x65e2b488768fe0a9ULL, 0xd2d380dfd0e8aeecULL, 0xe6c4d041a2812509ULL, 0x068c7aba0ff3d5e1ULL, 0x51f5e41604e66b4cULL,
        0x41f9428a2c54c28eULL, 0x537a398b01b7d313ULL, 0x782206bdcc60a215ULL, 0x89afea1ac506a79eULL, 0x8ae9d7474cf14360ULL, 0xf6c876dd8a338ccbULL, 0x43769f1729057ad1ULL, 0x8dac4d3dcfa4ca20ULL,
        0xb7313457a6674e45ULL, 0x2018512550794f99ULL, 0xbb34c03eb89cf99aULL, 0xbafd20fe343aa53bULL, 0x03463d5d89f7e4feULL, 0x42bf7fd7a5a32670ULL, 0x3f573e8defc7b57aULL, 0xadb41c189fdd85b9ULL,
        0xcad9750dec03dd4fULL, 0x0f43c934970c5321ULL, 0x2f5b9811c7751cb8ULL, 0xd85a0e0cc1e0ccd2ULL, 0xe048aafbad72f0e8ULL, 0xf18deca70966058bULL, 0xdd9049eb47e4fdcdULL, 0xa87e5bff19d9b4a6ULL,
        0x5df0107f1a1ddc93ULL, 0xd195bd82591f4a12ULL, 0x0c05f4691efbb7dfULL, 0x8463feb3575b4ce0ULL, 0x55f643310e4406f2ULL, 0xb6f8d4972ac112e4ULL, 0x4030a24aa0f29e2fULL, 0xfd8818ce179db254ULL,
        0x3c1103d066305184ULL, 0x682ea021e4d20bd7ULL, 0x81a9b954d15f7dffULL, 0x275dcb5fd32cc6d9ULL, 0xfacd82b494c83b14ULL, 0x4433056daa50f391ULL, 0xe9871975358d7628ULL, 0xeac12428bc7a92d6ULL,
        0x1a85284f39bacbfcULL, 0xf8425f299199834bULL, 0x676d691573de58f6ULL, 0xd05c5d42d5b916b3ULL, 0x8eea706046532edeULL, 0xfb046274186e67b5ULL, 0x134a9bc1a1454d3cULL, 0x57799eac0b15beadULL,
        0x241bf6025adb2227ULL, 0x72ab886edd68c02bULL, 0x9ae571db6443eaa2ULL, 0xc050fbdefd0bbf71ULL, 0xa5b24f568b845fd8ULL, 0xe84ef9b5b92b2a89ULL, 0x6f6b3a5b67878297ULL, 0xc6dc8164f2f86a90ULL,
        0x7eae7c07c39377f4ULL, 0x5eb62d2293ea386dULL, 0x8c65adfd43029681ULL, 0x2dd4458cc224a4e7ULL, 0xfece25939e6a56aaULL, 0xcd9cef776f56540fULL, 0xa33e35ec84778a39ULL, 0xc2df2643f85a072eULL,
        0xbc715a443bc970daULL, 0xa07808b10d806ec7ULL, 0x36988d03773833baULL, 0x1680dc2627417c23ULL, 0xcb1095cd60a581eeULL, 0xbdb8ba84b76f2c7bULL, 0x702455f3d8397874ULL, 0x35deb05efecfd744ULL,
        0x8f2390a0caf5727fULL, 0xb1bd4eeda9949ba4ULL, 0x39db4437e034609bULL, 0xe582ed1c2b76c1f7ULL, 0xc4535cf9f7a9d2cfULL, 0xb2fb73b020637f5aULL, 0x583a57989c19ed8cULL, 0x25d216c2d67d7e86ULL,
        0x0806534e1459da61ULL, 0x6b689d7c6d25ef29ULL, 0x0dcc14a9925deb7eULL, 0xc99f485065f439b1ULL, 0xa9b7bb3f957fe807ULL, 0x2a91dff641712da7ULL, 0x1c0952f536491e1dULL, 0x75ee12145e3d496bULL,
        0xf98bbfe91d3fdfeaULL, 0x92e32295701a30c3ULL, 0x3e9ede4d6361e9dbULL, 0x76a82f49d7caad95ULL, 0x9da0eba1e71663e2ULL, 0x09cfb38e98ff86c0ULL, 0x9c690b616bb03f43ULL, 0xdad5d391c4b1748dULL,
        0x3812a4f76c923c3aULL, 0x5f7fcde21f4c64ccULL, 0x6aa17dbce183b388ULL, 0xeec2830fb6d8ff68ULL, 0x736268ae51ce9c8aULL, 0xa47baf9607220379ULL, 0x543fa3f182e25a53ULL, 0x4eba8bbebb5891afULL,
        0x2e9278d14bd34019ULL, 0x69e740e168745776ULL, 0x37516dc3fb9e6f1bULL, 0xb3329370acc523fbULL, 0x3a9d796a69c38465ULL, 0x7761cf895b6cf134ULL, 0x0000000000000000ULL, 0x88660ada49a0fb3fULL,
        0xb5bee9caa336f61aULL, 0x5b7c6ac515ee0972ULL, 0x52b3d94b8d118fb2ULL, 0x329b2a247d9a5e04ULL, 0x0e8a29f41baa0f80ULL, 0x642b5448fa29bc08ULL, 0x7b643be0459746ebULL, 0xd45ffa65df1b7b0dULL,
        0xeb08c4e830dcce77ULL, 0xf2cbd1fa8091e175ULL, 0xf302313a0c37bdd4ULL, 0x91a51fc8f9edd43dULL, 0xef0b63cf3a7ea3c9ULL, 0xc316c68374fc5b8fULL, 0x01c9e0c08ca65ca1ULL, 0x3417509e72698be5ULL,
        0x4775383023a7176fULL, 0x636ece32797c3548ULL, 0x1b4cc88fb51c975dULL, 0x140f01bb2210c47cULL, 0x7427f2d4d29b15caULL, 0xa73d92cb8ed5e787ULL, 0xc71561a47e5e3631ULL, 0xaaf186621c880cf9ULL,
        0x6028f36ff08bd1b6ULL, 0x97296572f61e01dcULL, 0xc59abc397b0f8e6eULL, 0xec4d5e92b3894737ULL, 0xb872fd63316b1d64ULL, 0xaf3bc1859a8c3de6ULL, 0x0403a7270aa26dbeULL, 0x26942b9f5f8a9a78ULL,
        0x86ec232e520af4bfULL, 0x49ff11c4380d18efULL, 0xf701961d0695d06aULL, 0x56b07e6c87b3e20cULL, 0xd5961aa553bd27acULL, 0x61e113af7c2d8d17ULL, 0x100ca69c28b2a9c2ULL, 0xcf1332ea6a07ec50ULL,
        0xc856a890e9526510ULL, 0x2b583f36cdd77106ULL, 0x932ac255fcbc6c62ULL, 0x0b406e139dae3e9fULL, 0x832664c9d40ec5a0ULL, 0x3014f7b978cbe65bULL, 0x2c1da54c4e82f846ULL, 0x986aac46611252fdULL
    },
    {
        0x679cc74f352b557fULL, 0x376719b23e9424bfULL, 0xcc14a9925deb7e0dULL, 0xb07e6c87b3e20c56ULL, 0xa17dbce183b3886aULL, 0xee12145e3d496b75ULL, 0x406e139dae3e9f0bULL, 0x942b9f5f8a9a7826ULL,
        0xb24f568b845fd8a5ULL, 0xdf2643f85a072ec2ULL, 0x8c7aba0ff3d5e106ULL, 0x0b63cf3a7ea3c9efULL, 0x12a4f76c923c3a38ULL, 0x8bbfe91d3fdfeaf9ULL, 0x9278d14bd340192eULL, 0xca47e78604311f05ULL,
        0x07c55312cc0a0bffULL, 0xcfb38e98ff86c009ULL, 0x991b1e71ade3d0c1ULL, 0x16c68374fc5b8fc3ULL, 0x39f0bf96bb80325cULL, 0x3d92cb8ed5e787a7ULL, 0xac4d3dcfa4ca208dULL, 0xfae5ad26f6af3045ULL,
        0x63feb3575b4ce084ULL, 0x28f36ff08bd1b660ULL, 0xc6e17baeb698dd15ULL, 0x84be523f2f1b96edULL, 0x3c04d6884037ed50ULL, 0xce25939e6a56aafeULL, 0xa34c86edb40e5c99ULL, 0xebe67d40c6feb479ULL,
        0x27f2d4d29b15ca74ULL, 0x6d691573de58f667ULL, 0x329370acc523fbb3ULL, 0x2c911be8e5b6039bULL, 0x871975358d7628e9ULL, 0x550fb7e3f008aeccULL, 0x7e5bff19d9b4a6a8ULL, 0xf8d4972ac112e4b6ULL,
        0xd1b1e5dcdf133821ULL, 0xfcb6e332af75514dULL, 0x1e026b442095f828ULL, 0x1f947642b54592dfULL, 0x5e6c78d98eab6723ULL, 0x17509e72698be534ULL, 0x2ac255fcbc6c6293ULL, 0x95bd82591f4a12d1ULL,
        0x799eac0b15bead57ULL, 0xf0107f1a1ddc935dULL, 0xd674b6ce131933deULL, 0xf5e41604e66b4c51ULL, 0x8818ce179db254fdULL, 0x03a7270aa26dbe04ULL, 0x1c33514817282cdbULL, 0x2f363ce247dbbd9fULL,
        0xa72ef2f5da69e962ULL, 0x93eecc4d469073d9ULL, 0xb92c99b1fafc114aULL, 0x77090a2f90aabbb4ULL, 0x0ca69c28b2a9c210ULL, 0xc9e0c08ca65ca101ULL, 0x4b0ddca7d09d56e4ULL, 0x988d03773833ba36ULL,
        0x06534e1459da6108ULL, 0x3a57989c19ed8c58ULL, 0x0952f536491e1d1cULL, 0x0af5d23ceb73a318ULL, 0x0d30812e2779a8e7ULL, 0xd7e2abc886c95929ULL, 0xa51fc8f9edd43d91ULL, 0x690b616bb03f439cULL,
        0x516dc3fb9e6f1b37ULL, 0xa489d5ff78045766ULL, 0x52cae4f13c02a533ULL, 0x4cc88fb51c975d1bULL, 0x459a7a8355894007ULL, 0x9d796a69c384653aULL, 0x313457a6674e45b7ULL, 0x4a9bc1a1454d3c13ULL,
        0x6268ae51ce9c8a73ULL, 0xfe87d93e98c885beULL, 0xff11c4380d18ef49ULL, 0x8deca70966058bf1ULL, 0xdeb05efecfd74435ULL, 0xd027f8da4ac352d6ULL, 0xf186621c880cf9aaULL, 0x43c934970c53210fULL,
        0xbee9caa336f61ab5ULL, 0x56a890e9526510c8ULL, 0xe8415a4a64930a7dULL, 0xe32295701a30c392ULL, 0x3e35ec84778a39a3ULL, 0x4f6fa8bfbefae31fULL, 0x5dcb5fd32cc6d927ULL, 0x9f485065f439b1c9ULL,
        0x1095cd60a581eecbULL, 0x978cb85528f7c622ULL, 0x7baf9607220379a4ULL, 0xd216c2d67d7e8625ULL, 0xe4e7c662d63ac86dULL, 0xb62d2293ea386d5eULL, 0x8a29f41baa0f800eULL, 0x5ffa65df1b7b0dd4ULL,
        0x61cf895b6cf13477ULL, 0xa6b8eff34fb98395ULL, 0x814a3b21d4ac49e1ULL, 0xaddb20c9311a4a7aULL, 0x74ae2d2532c705b0ULL, 0x30a24aa0f29e2f40ULL, 0x91dff641712da72aULL, 0x9049eb47e4fdcdddULL,
        0x493ce6abe7208217ULL, 0x36f104b4ab444e48ULL, 0xf22145162a6147aeULL, 0x5c5d42d5b916b3d0ULL, 0xf7d52c08d1d698a2ULL, 0x7a398b01b7d31353ULL, 0x6cff08754b889c90ULL, 0x14f7b978cbe65b30ULL,
        0xc4d041a2812509e6ULL, 0xe085b27ab85d7d96ULL, 0xc0b235baef42bc1dULL, 0x868f683318a6421eULL, 0xea706046532ede8eULL, 0x4ef9b5b92b2a89e8ULL, 0xdc8164f2f86a90c6ULL, 0x2455f3d839787470ULL,
        0x5499aae565d8c43bULL, 0x59a92bcb42a16cdcULL, 0xa9b954d15f7dff81ULL, 0xae7c07c39377f47eULL, 0x01961d0695d06af7ULL, 0xdb4437e034609b39ULL, 0x3bc1859a8c3de6afULL, 0xaa1e73dbfd104185ULL,
        0x7dfcd8137bd918acULL, 0x80dc2627417c2316ULL, 0xd9750dec03dd4fcaULL, 0xc5465ca414f56311ULL, 0x203787c0571fc18bULL, 0xd5d391c4b1748ddaULL, 0xc2830fb6d8ff68eeULL, 0xbcd8f0af014bce46ULL,
        0xa0eba1e71663e29dULL, 0xfb73b020637f5ab2ULL, 0x7c6ac515ee09725bULL, 0x0000000000000000ULL, 0xc876dd8a338ccbf6ULL, 0x9cef776f56540fcdULL, 0x47ab408f623494f4ULL, 0xcbd1fa8091e175f2ULL,
        0x9abc397b0f8e6ec5ULL, 0xb58a05994855d35aULL, 0x4d5e92b3894737ecULL, 0x961aa553bd27acd5ULL, 0xc31512b04d2f0219ULL, 0xe6d6fc6ee1871c9eULL, 0xe2b488768fe0a965ULL, 0xb3d94b8d118fb252ULL,
        0x440c6785c0592af0ULL, 0x25c3eedeaca81e87ULL, 0x583f36cdd771062bULL, 0x2d0706ee7066696cULL, 0x425f299199834bf8ULL, 0xfd20fe343aa53bbaULL, 0xf643310e4406f255ULL, 0xdad22ae6a1b0f1ceULL,
        0x1da54c4e82f8462cULL, 0x355623be0929f04cULL, 0x769f1729057ad143ULL, 0xbd4eeda9949ba4b1ULL, 0xd8e310ea960d253dULL, 0x736b7e37fecd0e4fULL, 0x65adfd430296818cULL, 0xb8ba84b76f2c7bbdULL,
        0x9b2a247d9a5e0432ULL, 0xc77766a82348b7e2ULL, 0x08c4e830dcce77ebULL, 0x0e97a624851416e3ULL, 0x898ed31108623e0aULL, 0xe571db6443eaa29aULL, 0x573e8defc7b57a3fULL, 0x21a19ac6c2cfab7cULL,
        0x70cc593d5ca0b04bULL, 0x2664c9d40ec5a083ULL, 0x296572f61e01dc97ULL, 0x85284f39bacbfc1aULL, 0x715a443bc970dabcULL, 0xef840958a8990182ULL, 0xcd82b494c83b14faULL, 0x48aafbad72f0e8e0ULL,
        0xe9d7474cf143608aULL, 0x2390a0caf5727f8fULL, 0xb7bb3f957fe807a9ULL, 0x82ed1c2b76c1f7e5ULL, 0xbb1da3bdcd41c5b9ULL, 0x72fd63316b1d64b8ULL, 0x7808b10d806ec7a0ULL, 0x837b012de3119d12ULL,
        0x689d7c6d25ef296bULL, 0x02313a0c37bdd4f3ULL, 0x1103d0663051843cULL, 0xab886edd68c02b72ULL, 0x6b3a5b678782976fULL, 0xe113af7c2d8d1761ULL, 0x6aac46611252fd98ULL, 0x50fbdefd0bbf71c0ULL,
        0x2ea021e4d20bd768ULL, 0x5a0e0cc1e0ccd2d8ULL, 0x34c03eb89cf99abbULL, 0xb41c189fdd85b9adULL, 0x9ede4d6361e9db3eULL, 0xafea1ac506a79e89ULL, 0x463d5d89f7e4fe03ULL, 0x18512550794f9920ULL,
        0x41f80e9b3beef5fcULL, 0xa82f49d7caad9576ULL, 0x0f01bb2210c47c14ULL, 0xec232e520af4bf86ULL, 0x1bf6025adb222724ULL, 0xa2da9beb21de366eULL, 0xedb533549f24d571ULL, 0x643be0459746eb7bULL,
        0xbf7fd7a5a3267042ULL, 0x046274186e67b5fbULL, 0x8e4b8003c46835f5ULL, 0x1332ea6a07ec50cfULL, 0xd380dfd0e8aeecd2ULL, 0x6f582f7fe9e52294ULL, 0xf9428a2c54c28e41ULL, 0x3fa3f182e25a5354ULL,
        0x535cf9f7a9d2cfc4ULL, 0x660ada49a0fb3f88ULL, 0x33056daa50f39144ULL, 0x8fdd9d0551b85f02ULL, 0x19c73856ec9ff3d7ULL, 0xb1e87181263266a1ULL, 0x1561a47e5e3631c7ULL, 0xd4458cc224a4e72dULL,
        0xe740e16874577669ULL, 0xc12428bc7a92d6eaULL, 0x3866a2902e5058abULL, 0x1a601f5c4ef24dd3ULL, 0x6059945df9215e80ULL, 0x05f4691efbb7df0cULL, 0x5b9811c7751cb82fULL, 0x2b5448fa29bc0864ULL,
        0xba8bbebb5891af4eULL, 0xf4720b0273bb26a6ULL, 0xdd1779f46dbafa31ULL, 0x6ece32797c354863ULL, 0x7fcde21f4c64cc5fULL, 0x2206bdcc60a21578ULL, 0x75383023a7176f47ULL, 0xf3b75810bfb12d59ULL
    },
    {
        0x03d0663051843c11ULL, 0xbfe91d3fdfeaf98bULL, 0xf80e9b3beef5fc41ULL, 0xe5ad26f6af3045faULL, 0x5a443bc970dabc71ULL, 0x7b012de3119d1283ULL, 0x82b494c83b14facdULL, 0x750dec03dd4fcad9ULL,
        0x090a2f90aabbb477ULL, 0xb6e332af75514dfcULL, 0xadfd430296818c65ULL, 0xfd63316b1d64b872ULL, 0x3d5d89f7e4fe0346ULL, 0xd7474cf143608ae9ULL, 0x7e6c87b3e20c56b0ULL, 0x601f5c4ef24dd31aULL,
        0x40e16874577669e7ULL, 0x4437e034609b39dbULL, 0xe7c662d63ac86de4ULL, 0xaf9607220379a47bULL, 0xea1ac506a79e89afULL, 0xd8f0af014bce46bcULL, 0x7fd7a5a3267042bfULL, 0x9f1729057ad14376ULL,
        0x1c189fdd85b9adb4ULL, 0x87d93e98c885befeULL, 0x57989c19ed8c583aULL, 0xa4f76c923c3a3812ULL, 0x2a247d9a5e04329bULL, 0xc03eb89cf99abb34ULL, 0xf6025adb2227241bULL, 0xa890e9526510c856ULL,
        0x06bdcc60a2157822ULL, 0xc73856ec9ff3d719ULL, 0xcae4f13c02a53352ULL, 0xd6fc6ee1871c9ee6ULL, 0xf0bf96bb80325c39ULL, 0x13af7c2d8d1761e1ULL, 0x3be0459746eb7b64ULL, 0x99aae565d8c43b54ULL,
        0x95cd60a581eecb10ULL, 0x68ae51ce9c8a7362ULL, 0xcde21f4c64cc5f7fULL, 0xdc2627417c231680ULL, 0x428a2c54c28e41f9ULL, 0x76dd8a338ccbf6c8ULL, 0xb8eff34fb98395a6ULL, 0xa69c28b2a9c2100cULL,
        0x08b10d806ec7a078ULL, 0xc55312cc0a0bff07ULL, 0x886edd68c02b72abULL, 0xdd9d0551b85f028fULL, 0x1e73dbfd104185aaULL, 0x911be8e5b6039b2cULL, 0x30812e2779a8e70dULL, 0x3a5b678782976f6bULL,
        0x20fe343aa53bbafdULL, 0xb954d15f7dff81a9ULL, 0x9a7a835589400745ULL, 0x1fc8f9edd43d91a5ULL, 0x0e0cc1e0ccd2d85aULL, 0xbb3f957fe807a9b7ULL, 0xc3eedeaca81e8725ULL, 0x66a2902e5058ab38ULL,
        0xff08754b889c906cULL, 0xfeb3575b4ce08463ULL, 0x107f1a1ddc935df0ULL, 0x25939e6a56aafeceULL, 0xa92bcb42a16cdc59ULL, 0x32ea6a07ec50cf13ULL, 0x947642b54592df1fULL, 0x1779f46dbafa31ddULL,
        0x5623be0929f04c35ULL, 0xf2d4d29b15ca7427ULL, 0x59945df9215e8060ULL, 0x9370acc523fbb332ULL, 0xb05efecfd74435deULL, 0x71db6443eaa29ae5ULL, 0xe2abc886c95929d7ULL, 0x458cc224a4e72dd4ULL,
        0xce32797c3548636eULL, 0x1aa553bd27acd596ULL, 0x4a3b21d4ac49e181ULL, 0x284f39bacbfc1a85ULL, 0xd94b8d118fb252b3ULL, 0xb235baef42bc1dc0ULL, 0x2643f85a072ec2dfULL, 0x8bbebb5891af4ebaULL,
        0x89d5ff78045766a4ULL, 0xeecc4d469073d993ULL, 0x0b616bb03f439c69ULL, 0xe41604e66b4c51f5ULL, 0x16c2d67d7e8625d2ULL, 0x6c78d98eab67235eULL, 0x9d7c6d25ef296b68ULL, 0x64c9d40ec5a08326ULL,
        0x2ef2f5da69e962a7ULL, 0xfa65df1b7b0dd45fULL, 0x12145e3d496b75eeULL, 0xfcd8137bd918ac7dULL, 0x52f536491e1d1c09ULL, 0xe67d40c6feb479ebULL, 0x2145162a6147aef2ULL, 0x29f41baa0f800e8aULL,
        0x0000000000000000ULL, 0x840958a8990182efULL, 0xc88fb51c975d1b4cULL, 0xc68374fc5b8fc316ULL, 0x5d42d5b916b3d05cULL, 0x7dbce183b3886aa1ULL, 0x512550794f992018ULL, 0xe17baeb698dd15c6ULL,
        0x43310e4406f255f6ULL, 0x6dc3fb9e6f1b3751ULL, 0x86621c880cf9aaf1ULL, 0xbc397b0f8e6ec59aULL, 0x415a4a64930a7de8ULL, 0x04d6884037ed503cULL, 0xe9caa336f61ab5beULL, 0x0ada49a0fb3f8866ULL,
        0x55f3d83978747024ULL, 0x3ce6abe720821749ULL, 0xf5d23ceb73a3180aULL, 0xa24aa0f29e2f4030ULL, 0x582f7fe9e522946fULL, 0x7aba0ff3d5e1068cULL, 0x313a0c37bdd4f302ULL, 0x3787c0571fc18b20ULL,
        0x5cf9f7a9d2cfc453ULL, 0xbe523f2f1b96ed84ULL, 0x85b27ab85d7d96e0ULL, 0x0706ee7066696c2dULL, 0x961d0695d06af701ULL, 0x1b1e71ade3d0c199ULL, 0xc255fcbc6c62932aULL, 0x398b01b7d313537aULL,
        0xcc593d5ca0b04b70ULL, 0x5f299199834bf842ULL, 0x80dfd0e8aeecd2d3ULL, 0x9eac0b15bead5779ULL, 0xef776f56540fcd9cULL, 0x2f49d7caad9576a8ULL, 0x2c99b1fafc114ab9ULL, 0x8d03773833ba3698ULL,
        0x720b0273bb26a6f4ULL, 0x18ce179db254fd88ULL, 0x8f683318a6421e86ULL, 0x4f568b845fd8a5b2ULL, 0x8ed31108623e0a89ULL, 0xd22ae6a1b0f1cedaULL, 0x74b6ce131933ded6ULL, 0x97a624851416e30eULL,
        0x6e139dae3e9f0b40ULL, 0xa7270aa26dbe0403ULL, 0x5448fa29bc08642bULL, 0xe310ea960d253dd8ULL, 0x706046532ede8eeaULL, 0x485065f439b1c99fULL, 0x6b7e37fecd0e4f73ULL, 0xfbdefd0bbf71c050ULL,
        0xd391c4b1748ddad5ULL, 0xa021e4d20bd7682eULL, 0xab408f623494f447ULL, 0x5bff19d9b4a6a87eULL, 0xb1e5dcdf133821d1ULL, 0x026b442095f8281eULL, 0xdff641712da72a91ULL, 0x11c4380d18ef49ffULL,
        0xae2d2532c705b074ULL, 0xc1859a8c3de6af3bULL, 0x4b8003c46835f58eULL, 0x92cb8ed5e787a73dULL, 0xcb5fd32cc6d9275dULL, 0x8cb85528f7c62297ULL, 0x9bc1a1454d3c134aULL, 0x056daa50f3914433ULL,
        0xf4691efbb7df0c05ULL, 0xd1fa8091e175f2cbULL, 0x7c07c39377f47eaeULL, 0x14a9925deb7e0dccULL, 0xcf895b6cf1347761ULL, 0x0fb7e3f008aecc55ULL, 0x8a05994855d35ab5ULL, 0xf104b4ab444e4836ULL,
        0x691573de58f6676dULL, 0x4eeda9949ba4b1bdULL, 0x2428bc7a92d6eac1ULL, 0xb75810bfb12d59f3ULL, 0x63cf3a7ea3c9ef0bULL, 0x6274186e67b5fb04ULL, 0x1512b04d2f0219c3ULL, 0xe87181263266a1b1ULL,
        0x1975358d7628e987ULL, 0x534e1459da610806ULL, 0x47e78604311f05caULL, 0xd4972ac112e4b6f8ULL, 0x33514817282cdb1cULL, 0x90a0caf5727f8f23ULL, 0x3e8defc7b57a3f57ULL, 0x3f36cdd771062b58ULL,
        0x796a69c384653a9dULL, 0x465ca414f56311c5ULL, 0x5e92b3894737ec4dULL, 0x9811c7751cb82f5bULL, 0xd041a2812509e6c4ULL, 0x49eb47e4fdcddd90ULL, 0x78d14bd340192e92ULL, 0xf9b5b92b2a89e84eULL,
        0x61a47e5e3631c715ULL, 0x509e72698be53417ULL, 0xb533549f24d571edULL, 0x27f8da4ac352d6d0ULL, 0x6572f61e01dc9729ULL, 0xde4d6361e9db3e9eULL, 0x3457a6674e45b731ULL, 0xa54c4e82f8462c1dULL,
        0xbd82591f4a12d195ULL, 0x830fb6d8ff68eec2ULL, 0x383023a7176f4775ULL, 0x7766a82348b7e2c7ULL, 0x0c6785c0592af044ULL, 0xba84b76f2c7bbdb8ULL, 0xe0c08ca65ca101c9ULL, 0xeba1e71663e29da0ULL,
        0xd52c08d1d698a2f7ULL, 0xc4e830dcce77eb08ULL, 0xda9beb21de366ea2ULL, 0xa3f182e25a53543fULL, 0xac46611252fd986aULL, 0xb38e98ff86c009cfULL, 0xf36ff08bd1b66028ULL, 0xdb20c9311a4a7aadULL,
        0xa19ac6c2cfab7c21ULL, 0x6ac515ee09725b7cULL, 0x4c86edb40e5c99a3ULL, 0x363ce247dbbd9f2fULL, 0x8164f2f86a90c6dcULL, 0x35ec84778a39a33eULL, 0xb488768fe0a965e2ULL, 0x73b020637f5ab2fbULL,
        0x232e520af4bf86ecULL, 0x6fa8bfbefae31f4fULL, 0xeca70966058bf18dULL, 0x1da3bdcd41c5b9bbULL, 0x9cc74f352b557f67ULL, 0x4d3dcfa4ca208dacULL, 0x2b9f5f8a9a782694ULL, 0xaafbad72f0e8e048ULL,
        0xc934970c53210f43ULL, 0xed1c2b76c1f7e582ULL, 0x01bb2210c47c140fULL, 0x0ddca7d09d56e44bULL, 0x2d2293ea386d5eb6ULL, 0xf7b978cbe65b3014ULL, 0x6719b23e9424bf37ULL, 0x2295701a30c392e3ULL
    },
    {
        0x9f5f8a9a7826942bULL, 0x34970c53210f43c9ULL, 0x9d0551b85f028fddULL, 0xb494c83b14facd82ULL, 0x6edd68c02b72ab88ULL, 0xff19d9b4a6a87e5bULL, 0xdb6443eaa29ae571ULL, 0x1be8e5b6039b2c91ULL,
        0x5fd32cc6d9275dcbULL, 0x90e9526510c856a8ULL, 0xb27ab85d7d96e085ULL, 0xa47e5e3631c71561ULL, 0xf3d8397874702455ULL, 0xfbad72f0e8e048aaULL, 0x37e034609b39db44ULL, 0xfa8091e175f2cbd1ULL,
        0xcaa336f61ab5bee9ULL, 0xeff34fb98395a6b8ULL, 0x63316b1d64b872fdULL, 0xba0ff3d5e1068c7aULL, 0xcd60a581eecb1095ULL, 0x35baef42bc1dc0b2ULL, 0x23be0929f04c3556ULL, 0x4b8d118fb252b3d9ULL,
        0xd8137bd918ac7dfcULL, 0x0a2f90aabbb47709ULL, 0xc2d67d7e8625d216ULL, 0x7181263266a1b1e8ULL, 0x3023a7176f477538ULL, 0x7642b54592df1f94ULL, 0xf2f5da69e962a72eULL, 0xa70966058bf18decULL,
        0xc662d63ac86de4e7ULL, 0x939e6a56aafece25ULL, 0x86edb40e5c99a34cULL, 0xf8da4ac352d6d027ULL, 0x145e3d496b75ee12ULL, 0xce179db254fd8818ULL, 0xd23ceb73a3180af5ULL, 0x270aa26dbe0403a7ULL,
        0x5d89f7e4fe03463dULL, 0x2ae6a1b0f1cedad2ULL, 0x1729057ad143769fULL, 0xb10d806ec7a07808ULL, 0x4f39bacbfc1a8528ULL, 0xeda9949ba4b1bd4eULL, 0x5312cc0a0bff07c5ULL, 0xc4380d18ef49ff11ULL,
        0x95701a30c392e322ULL, 0xa0caf5727f8f2390ULL, 0x55fcbc6c62932ac2ULL, 0xcf3a7ea3c9ef0b63ULL, 0x621c880cf9aaf186ULL, 0xfd430296818c65adULL, 0xbf96bb80325c39f0ULL, 0x6c87b3e20c56b07eULL,
        0x299199834bf8425fULL, 0x74186e67b5fb0462ULL, 0x4c4e82f8462c1da5ULL, 0x64f2f86a90c6dc81ULL, 0x6b442095f8281e02ULL, 0x1d0695d06af70196ULL, 0xd5ff78045766a489ULL, 0x3856ec9ff3d719c7ULL,
        0xac0b15bead57799eULL, 0xc3fb9e6f1b37516dULL, 0x8e98ff86c009cfb3ULL, 0x49d7caad9576a82fULL, 0x859a8c3de6af3bc1ULL, 0x3dcfa4ca208dac4dULL, 0x91c4b1748ddad5d3ULL, 0x8a2c54c28e41f942ULL,
        0x2bcb42a16cdc59a9ULL, 0x9e72698be5341750ULL, 0x1e71ade3d0c1991bULL, 0xe6abe7208217493cULL, 0x3a0c37bdd4f30231ULL, 0x945df9215e806059ULL, 0xcc4d469073d993eeULL, 0x0e9b3beef5fc41f8ULL,
        0x8b01b7d313537a39ULL, 0xf182e25a53543fa3ULL, 0x5810bfb12d59f3b7ULL, 0x8003c46835f58e4bULL, 0xbce183b3886aa17dULL, 0x1604e66b4c51f5e4ULL, 0x2c08d1d698a2f7d5ULL, 0xc08ca65ca101c9e0ULL,
        0x7a8355894007459aULL, 0xe21f4c64cc5f7fcdULL, 0x88768fe0a965e2b4ULL, 0x82591f4a12d195bdULL, 0x4aa0f29e2f4030a2ULL, 0xdca7d09d56e44b0dULL, 0x6daa50f391443305ULL, 0x92b3894737ec4d5eULL,
        0xa8bfbefae31f4f6fULL, 0xea6a07ec50cf1332ULL, 0x2293ea386d5eb62dULL, 0x41a2812509e6c4d0ULL, 0x8374fc5b8fc316c6ULL, 0x683318a6421e868fULL, 0xb3575b4ce08463feULL, 0xe5dcdf133821d1b1ULL,
        0xd6884037ed503c04ULL, 0x05994855d35ab58aULL, 0x5b678782976f6b3aULL, 0x397b0f8e6ec59abcULL, 0xabc886c95929d7e2ULL, 0xe4f13c02a53352caULL, 0xb5b92b2a89e84ef9ULL, 0xaf7c2d8d1761e113ULL,
        0x75358d7628e98719ULL, 0x72f61e01dc972965ULL, 0x78d98eab67235e6cULL, 0xc8f9edd43d91a51fULL, 0x0fb6d8ff68eec283ULL, 0x70acc523fbb33293ULL, 0x36cdd771062b583fULL, 0xbdcc60a215782206ULL,
        0xa624851416e30e97ULL, 0x9607220379a47bafULL, 0x1c2b76c1f7e582edULL, 0x6046532ede8eea70ULL, 0xbebb5891af4eba8bULL, 0x48fa29bc08642b54ULL, 0x19b23e9424bf3767ULL, 0x2627417c231680dcULL,
        0x65df1b7b0dd45ffaULL, 0xf536491e1d1c0952ULL, 0x54d15f7dff81a9b9ULL, 0x2550794f99201851ULL, 0xdefd0bbf71c050fbULL, 0x87c0571fc18b2037ULL, 0x10ea960d253dd8e3ULL, 0xe0459746eb7b643bULL,
        0x12b04d2f0219c315ULL, 0xaae565d8c43b5499ULL, 0xe91d3fdfeaf98bbfULL, 0xf76c923c3a3812a4ULL, 0x1f5c4ef24dd31a60ULL, 0x812e2779a8e70d30ULL, 0xf41baa0f800e8a29ULL, 0xfc6ee1871c9ee6d6ULL,
        0x8fb51c975d1b4cc8ULL, 0x4e1459da61080653ULL, 0x310e4406f255f643ULL, 0x0cc1e0ccd2d85a0eULL, 0x0958a8990182ef84ULL, 0xa9925deb7e0dcc14ULL, 0x6a69c384653a9d79ULL, 0x04b4ab444e4836f1ULL,
        0x0dec03dd4fcad975ULL, 0xeb47e4fdcddd9049ULL, 0x7e37fecd0e4f736bULL, 0x73dbfd104185aa1eULL, 0xc515ee09725b7c6aULL, 0xae51ce9c8a736268ULL, 0xa3bdcd41c5b9bb1dULL, 0x84b76f2c7bbdb8baULL,
        0x443bc970dabc715aULL, 0xa1e71663e29da0ebULL, 0x7f1a1ddc935df010ULL, 0x474cf143608ae9d7ULL, 0x33549f24d571edb5ULL, 0xc9d40ec5a0832664ULL, 0x46611252fd986aacULL, 0x5efecfd74435deb0ULL,
        0x0000000000000000ULL, 0x514817282cdb1c33ULL, 0x408f623494f447abULL, 0x57a6674e45b73134ULL, 0x11c7751cb82f5b98ULL, 0x989c19ed8c583a57ULL, 0x7baeb698dd15c6e1ULL, 0x06ee7066696c2d07ULL,
        0xda49a0fb3f88660aULL, 0x07c39377f47eae7cULL, 0x2d2532c705b074aeULL, 0x42d5b916b3d05c5dULL, 0xec84778a39a33e35ULL, 0x776f56540fcd9cefULL, 0xa553bd27acd5961aULL, 0xb978cbe65b3014f7ULL,
        0x895b6cf1347761cfULL, 0xb85528f7c622978cULL, 0x66a82348b7e2c777ULL, 0xe830dcce77eb08c4ULL, 0x189fdd85b9adb41cULL, 0x99b1fafc114ab92cULL, 0x0b0273bb26a6f472ULL, 0xeedeaca81e8725c3ULL,
        0x6785c0592af0440cULL, 0x247d9a5e04329b2aULL, 0x21e4d20bd7682ea0ULL, 0xbb2210c47c140f01ULL, 0x523f2f1b96ed84beULL, 0xd4d29b15ca7427f2ULL, 0x45162a6147aef221ULL, 0xf641712da72a91dfULL,
        0xb020637f5ab2fb73ULL, 0xdd8a338ccbf6c876ULL, 0x5ca414f56311c546ULL, 0x3f957fe807a9b7bbULL, 0x8cc224a4e72dd445ULL, 0x012de3119d12837bULL, 0xd0663051843c1103ULL, 0x5a4a64930a7de841ULL,
        0x28bc7a92d6eac124ULL, 0x08754b889c906cffULL, 0xd7a5a3267042bf7fULL, 0x3ce247dbbd9f2f36ULL, 0x6ff08bd1b66028f3ULL, 0xd14bd340192e9278ULL, 0x139dae3e9f0b406eULL, 0xe78604311f05ca47ULL,
        0xd93e98c885befe87ULL, 0x616bb03f439c690bULL, 0x03773833ba36988dULL, 0xcb8ed5e787a73d92ULL, 0xb7e3f008aecc550fULL, 0x9c28b2a9c2100ca6ULL, 0x3eb89cf99abb34c0ULL, 0x3b21d4ac49e1814aULL,
        0xdfd0e8aeecd2d380ULL, 0x7c6d25ef296b689dULL, 0xc1a1454d3c134a9bULL, 0xf9f7a9d2cfc4535cULL, 0xc74f352b557f679cULL, 0x7d40c6feb479ebe6ULL, 0x1573de58f6676d69ULL, 0x1ac506a79e89afeaULL,
        0x568b845fd8a5b24fULL, 0x32797c3548636eceULL, 0x691efbb7df0c05f4ULL, 0x972ac112e4b6f8d4ULL, 0x79f46dbafa31dd17ULL, 0x2e520af4bf86ec23ULL, 0xd31108623e0a898eULL, 0x8defc7b57a3f573eULL,
        0x025adb2227241bf6ULL, 0xa2902e5058ab3866ULL, 0xfe343aa53bbafd20ULL, 0xad26f6af3045fae5ULL, 0x43f85a072ec2df26ULL, 0x2f7fe9e522946f58ULL, 0x9beb21de366ea2daULL, 0x20c9311a4a7aaddbULL,
        0x5065f439b1c99f48ULL, 0x593d5ca0b04b70ccULL, 0x9ac6c2cfab7c21a1ULL, 0xb6ce131933ded674ULL, 0xf0af014bce46bcd8ULL, 0x4d6361e9db3e9edeULL, 0xe16874577669e740ULL, 0xe332af75514dfcb6ULL
    },
    {
        0xbfbefae31f4f6fa8ULL, 0x85c0592af0440c67ULL, 0xbaef42bc1dc0b235ULL, 0x5528f7c622978cb8ULL, 0xe6a1b0f1cedad22aULL, 0x3ceb73a3180af5d2ULL, 0x7fe9e522946f582fULL, 0xa7d09d56e44b0ddcULL,
        0x754b889c906cff08ULL, 0xe247dbbd9f2f363cULL, 0x81263266a1b1e871ULL, 0xdcdf133821d1b1e5ULL, 0xf46dbafa31dd1779ULL, 0x3d5ca0b04b70cc59ULL, 0x56ec9ff3d719c738ULL, 0xdeaca81e8725c3eeULL,
        0x549f24d571edb533ULL, 0x2de3119d12837b01ULL, 0xea960d253dd8e310ULL, 0xc886c95929d7e2abULL, 0x2f90aabbb477090aULL, 0x26f6af3045fae5adULL, 0x6ee1871c9ee6d6fcULL, 0x3e98c885befe87d9ULL,
        0x24851416e30e97a6ULL, 0xda4ac352d6d027f8ULL, 0xe3f008aecc550fb7ULL, 0x994855d35ab58a05ULL, 0x5df9215e80605994ULL, 0x58a8990182ef8409ULL, 0xb1fafc114ab92c99ULL, 0x442095f8281e026bULL,
        0xf5da69e962a72ef2ULL, 0xc0571fc18b203787ULL, 0x37fecd0e4f736b7eULL, 0x902e5058ab3866a2ULL, 0xeb21de366ea2da9bULL, 0x8f623494f447ab40ULL, 0xd98eab67235e6c78ULL, 0xa414f56311c5465cULL,
        0x5c4ef24dd31a601fULL, 0x08d1d698a2f7d52cULL, 0xdbfd104185aa1e73ULL, 0xcb42a16cdc59a92bULL, 0x10bfb12d59f3b758ULL, 0xa82348b7e2c77766ULL, 0xbdcd41c5b9bb1da3ULL, 0x7ab85d7d96e085b2ULL,
        0xedb40e5c99a34c86ULL, 0xff78045766a489d5ULL, 0xf34fb98395a6b8efULL, 0x4f352b557f679cc7ULL, 0x4a64930a7de8415aULL, 0xe8e5b6039b2c911bULL, 0xb4ab444e4836f104ULL, 0x4817282cdb1c3351ULL,
        0xaeb698dd15c6e17bULL, 0x3f2f1b96ed84be52ULL, 0x21d4ac49e1814a3bULL, 0x884037ed503c04d6ULL, 0xbe0929f04c355623ULL, 0xe565d8c43b5499aaULL, 0x1108623e0a898ed3ULL, 0x2532c705b074ae2dULL,
        0x0551b85f028fdd9dULL, 0x03c46835f58e4b80ULL, 0xf13c02a53352cae4ULL, 0xee7066696c2d0706ULL, 0xc6c2cfab7c21a19aULL, 0xb04d2f0219c31512ULL, 0x0273bb26a6f4720bULL, 0x8604311f05ca47e7ULL,
        0xaf014bce46bcd8f0ULL, 0x3318a6421e868f68ULL, 0x96bb80325c39f0bfULL, 0x40c6feb479ebe67dULL, 0x12cc0a0bff07c553ULL, 0x162a6147aef22145ULL, 0x71ade3d0c1991b1eULL, 0xce131933ded674b6ULL,
        0xc9311a4a7aaddb20ULL, 0x32af75514dfcb6e3ULL, 0x62d63ac86de4e7c6ULL, 0xb23e9424bf376719ULL, 0x8355894007459a7aULL, 0x137bd918ac7dfcd8ULL, 0x42b54592df1f9476ULL, 0xabe7208217493ce6ULL,
        0x9b3beef5fc41f80eULL, 0x2e2779a8e70d3081ULL, 0x4d469073d993eeccULL, 0x768fe0a965e2b488ULL, 0xd0e8aeecd2d380dfULL, 0xa2812509e6c4d041ULL, 0x0ff3d5e1068c7abaULL, 0x04e66b4c51f5e416ULL,
        0x2c54c28e41f9428aULL, 0x01b7d313537a398bULL, 0xcc60a215782206bdULL, 0xc506a79e89afea1aULL, 0x4cf143608ae9d747ULL, 0x8a338ccbf6c876ddULL, 0x29057ad143769f17ULL, 0xcfa4ca208dac4d3dULL,
        0xa6674e45b7313457ULL, 0x50794f9920185125ULL, 0xb89cf99abb34c03eULL, 0x343aa53bbafd20feULL, 0x89f7e4fe03463d5dULL, 0xa5a3267042bf7fd7ULL, 0xefc7b57a3f573e8dULL, 0x9fdd85b9adb41c18ULL,
        0xec03dd4fcad9750dULL, 0x970c53210f43c934ULL, 0xc7751cb82f5b9811ULL, 0xc1e0ccd2d85a0e0cULL, 0xad72f0e8e048aafbULL, 0x0966058bf18deca7ULL, 0x47e4fdcddd9049ebULL, 0x19d9b4a6a87e5bffULL,
        0x1a1ddc935df0107fULL, 0x591f4a12d195bd82ULL, 0x1efbb7df0c05f469ULL, 0x575b4ce08463feb3ULL, 0x0e4406f255f64331ULL, 0x2ac112e4b6f8d497ULL, 0xa0f29e2f4030a24aULL, 0x179db254fd8818ceULL,
        0x663051843c1103d0ULL, 0xe4d20bd7682ea021ULL, 0xd15f7dff81a9b954ULL, 0xd32cc6d9275dcb5fULL, 0x94c83b14facd82b4ULL, 0xaa50f3914433056dULL, 0x358d7628e9871975ULL, 0xbc7a92d6eac12428ULL,
        0x39bacbfc1a85284fULL, 0x9199834bf8425f29ULL, 0x73de58f6676d6915ULL, 0xd5b916b3d05c5d42ULL, 0x46532ede8eea7060ULL, 0x186e67b5fb046274ULL, 0xa1454d3c134a9bc1ULL, 0x0b15bead57799eacULL,
        0x5adb2227241bf602ULL, 0xdd68c02b72ab886eULL, 0x6443eaa29ae571dbULL, 0xfd0bbf71c050fbdeULL, 0x8b845fd8a5b24f56ULL, 0xb92b2a89e84ef9b5ULL, 0x678782976f6b3a5bULL, 0xf2f86a90c6dc8164ULL,
        0xc39377f47eae7c07ULL, 0x93ea386d5eb62d22ULL, 0x430296818c65adfdULL, 0xc224a4e72dd4458cULL, 0x9e6a56aafece2593ULL, 0x6f56540fcd9cef77ULL, 0x84778a39a33e35ecULL, 0xf85a072ec2df2643ULL,
        0x3bc970dabc715a44ULL, 0x0d806ec7a07808b1ULL, 0x773833ba36988d03ULL, 0x27417c231680dc26ULL, 0x60a581eecb1095cdULL, 0xb76f2c7bbdb8ba84ULL, 0xd8397874702455f3ULL, 0xfecfd74435deb05eULL,
        0xcaf5727f8f2390a0ULL, 0xa9949ba4b1bd4eedULL, 0xe034609b39db4437ULL, 0x2b76c1f7e582ed1cULL, 0xf7a9d2cfc4535cf9ULL, 0x20637f5ab2fb73b0ULL, 0x9c19ed8c583a5798ULL, 0xd67d7e8625d216c2ULL,
        0x1459da610806534eULL, 0x6d25ef296b689d7cULL, 0x925deb7e0dcc14a9ULL, 0x65f439b1c99f4850ULL, 0x957fe807a9b7bb3fULL, 0x41712da72a91dff6ULL, 0x36491e1d1c0952f5ULL, 0x5e3d496b75ee1214ULL,
        0x1d3fdfeaf98bbfe9ULL, 0x701a30c392e32295ULL, 0x6361e9db3e9ede4dULL, 0xd7caad9576a82f49ULL, 0xe71663e29da0eba1ULL, 0x98ff86c009cfb38eULL, 0x6bb03f439c690b61ULL, 0xc4b1748ddad5d391ULL,
        0x6c923c3a3812a4f7ULL, 0x1f4c64cc5f7fcde2ULL, 0xe183b3886aa17dbcULL, 0xb6d8ff68eec2830fULL, 0x51ce9c8a736268aeULL, 0x07220379a47baf96ULL, 0x82e25a53543fa3f1ULL, 0xbb5891af4eba8bbeULL,
        0x4bd340192e9278d1ULL, 0x6874577669e740e1ULL, 0xfb9e6f1b37516dc3ULL, 0xacc523fbb3329370ULL, 0x69c384653a9d796aULL, 0x5b6cf1347761cf89ULL, 0x0000000000000000ULL, 0x49a0fb3f88660adaULL,
        0xa336f61ab5bee9caULL, 0x15ee09725b7c6ac5ULL, 0x8d118fb252b3d94bULL, 0x7d9a5e04329b2a24ULL, 0x1baa0f800e8a29f4ULL, 0xfa29bc08642b5448ULL, 0x459746eb7b643be0ULL, 0xdf1b7b0dd45ffa65ULL,
        0x30dcce77eb08c4e8ULL, 0x8091e175f2cbd1faULL, 0x0c37bdd4f302313aULL, 0xf9edd43d91a51fc8ULL, 0x3a7ea3c9ef0b63cfULL, 0x74fc5b8fc316c683ULL, 0x8ca65ca101c9e0c0ULL, 0x72698be53417509eULL,
        0x23a7176f47753830ULL, 0x797c3548636ece32ULL, 0xb51c975d1b4cc88fULL, 0x2210c47c140f01bbULL, 0xd29b15ca7427f2d4ULL, 0x8ed5e787a73d92cbULL, 0x7e5e3631c71561a4ULL, 0x1c880cf9aaf18662ULL,
        0xf08bd1b66028f36fULL, 0xf61e01dc97296572ULL, 0x7b0f8e6ec59abc39ULL, 0xb3894737ec4d5e92ULL, 0x316b1d64b872fd63ULL, 0x9a8c3de6af3bc185ULL, 0x0aa26dbe0403a727ULL, 0x5f8a9a7826942b9fULL,
        0x520af4bf86ec232eULL, 0x380d18ef49ff11c4ULL, 0x0695d06af701961dULL, 0x87b3e20c56b07e6cULL, 0x53bd27acd5961aa5ULL, 0x7c2d8d1761e113afULL, 0x28b2a9c2100ca69cULL, 0x6a07ec50cf1332eaULL,
        0xe9526510c856a890ULL, 0xcdd771062b583f36ULL, 0xfcbc6c62932ac255ULL, 0x9dae3e9f0b406e13ULL, 0xd40ec5a0832664c9ULL, 0x78cbe65b3014f7b9ULL, 0x4e82f8462c1da54cULL, 0x611252fd986aac46ULL
    },
    {
        0x352b557f679cc74fULL, 0x3e9424bf376719b2ULL, 0x5deb7e0dcc14a992ULL, 0xb3e20c56b07e6c87ULL, 0x83b3886aa17dbce1ULL, 0x3d496b75ee12145eULL, 0xae3e9f0b406e139dULL, 0x8a9a7826942b9f5fULL,
        0x845fd8a5b24f568bULL, 0x5a072ec2df2643f8ULL, 0xf3d5e1068c7aba0fULL, 0x7ea3c9ef0b63cf3aULL, 0x923c3a3812a4f76cULL, 0x3fdfeaf98bbfe91dULL, 0xd340192e9278d14bULL, 0x04311f05ca47e786ULL,
        0xcc0a0bff07c55312ULL, 0xff86c009cfb38e98ULL, 0xade3d0c1991b1e71ULL, 0xfc5b8fc316c68374ULL, 0xbb80325c39f0bf96ULL, 0xd5e787a73d92cb8eULL, 0xa4ca208dac4d3dcfULL, 0xf6af3045fae5ad26ULL,
        0x5b4ce08463feb357ULL, 0x8bd1b66028f36ff0ULL, 0xb698dd15c6e17baeULL, 0x2f1b96ed84be523fULL, 0x4037ed503c04d688ULL, 0x6a56aafece25939eULL, 0xb40e5c99a34c86edULL, 0xc6feb479ebe67d40ULL,
        0x9b15ca7427f2d4d2ULL, 0xde58f6676d691573ULL, 0xc523fbb3329370acULL, 0xe5b6039b2c911be8ULL, 0x8d7628e987197535ULL, 0xf008aecc550fb7e3ULL, 0xd9b4a6a87e5bff19ULL, 0xc112e4b6f8d4972aULL,
        0xdf133821d1b1e5dcULL, 0xaf75514dfcb6e332ULL, 0x2095f8281e026b44ULL, 0xb54592df1f947642ULL, 0x8eab67235e6c78d9ULL, 0x698be53417509e72ULL, 0xbc6c62932ac255fcULL, 0x1f4a12d195bd8259ULL,
        0x15bead57799eac0bULL, 0x1ddc935df0107f1aULL, 0x131933ded674b6ceULL, 0xe66b4c51f5e41604ULL, 0x9db254fd8818ce17ULL, 0xa26dbe0403a7270aULL, 0x17282cdb1c335148ULL, 0x47dbbd9f2f363ce2ULL,
        0xda69e962a72ef2f5ULL, 0x469073d993eecc4dULL, 0xfafc114ab92c99b1ULL, 0x90aabbb477090a2fULL, 0xb2a9c2100ca69c28ULL, 0xa65ca101c9e0c08cULL, 0xd09d56e44b0ddca7ULL, 0x3833ba36988d0377ULL,
        0x59da610806534e14ULL, 0x19ed8c583a57989cULL, 0x491e1d1c0952f536ULL, 0xeb73a3180af5d23cULL, 0x2779a8e70d30812eULL, 0x86c95929d7e2abc8ULL, 0xedd43d91a51fc8f9ULL, 0xb03f439c690b616bULL,
        0x9e6f1b37516dc3fbULL, 0x78045766a489d5ffULL, 0x3c02a53352cae4f1ULL, 0x1c975d1b4cc88fb5ULL, 0x55894007459a7a83ULL, 0xc384653a9d796a69ULL, 0x674e45b7313457a6ULL, 0x454d3c134a9bc1a1ULL,
        0xce9c8a736268ae51ULL, 0x98c885befe87d93eULL, 0x0d18ef49ff11c438ULL, 0x66058bf18deca709ULL, 0xcfd74435deb05efeULL, 0x4ac352d6d027f8daULL, 0x880cf9aaf186621cULL, 0x0c53210f43c93497ULL,
        0x36f61ab5bee9caa3ULL, 0x526510c856a890e9ULL, 0x64930a7de8415a4aULL, 0x1a30c392e3229570ULL, 0x778a39a33e35ec84ULL, 0xbefae31f4f6fa8bfULL, 0x2cc6d9275dcb5fd3ULL, 0xf439b1c99f485065ULL,
        0xa581eecb1095cd60ULL, 0x28f7c622978cb855ULL, 0x220379a47baf9607ULL, 0x7d7e8625d216c2d6ULL, 0xd63ac86de4e7c662ULL, 0xea386d5eb62d2293ULL, 0xaa0f800e8a29f41bULL, 0x1b7b0dd45ffa65dfULL,
        0x6cf1347761cf895bULL, 0x4fb98395a6b8eff3ULL, 0xd4ac49e1814a3b21ULL, 0x311a4a7aaddb20c9ULL, 0x32c705b074ae2d25ULL, 0xf29e2f4030a24aa0ULL, 0x712da72a91dff641ULL, 0xe4fdcddd9049eb47ULL,
        0xe7208217493ce6abULL, 0xab444e4836f104b4ULL, 0x2a6147aef2214516ULL, 0xb916b3d05c5d42d5ULL, 0xd1d698a2f7d52c08ULL, 0xb7d313537a398b01ULL, 0x4b889c906cff0875ULL, 0xcbe65b3014f7b978ULL,
        0x812509e6c4d041a2ULL, 0xb85d7d96e085b27aULL, 0xef42bc1dc0b235baULL, 0x18a6421e868f6833ULL, 0x532ede8eea706046ULL, 0x2b2a89e84ef9b5b9ULL, 0xf86a90c6dc8164f2ULL, 0x397874702455f3d8ULL,
        0x65d8c43b5499aae5ULL, 0x42a16cdc59a92bcbULL, 0x5f7dff81a9b954d1ULL, 0x9377f47eae7c07c3ULL, 0x95d06af701961d06ULL, 0x34609b39db4437e0ULL, 0x8c3de6af3bc1859aULL, 0xfd104185aa1e73dbULL,
        0x7bd918ac7dfcd813ULL, 0x417c231680dc2627ULL, 0x03dd4fcad9750decULL, 0x14f56311c5465ca4ULL, 0x571fc18b203787c0ULL, 0xb1748ddad5d391c4ULL, 0xd8ff68eec2830fb6ULL, 0x014bce46bcd8f0afULL,
        0x1663e29da0eba1e7ULL, 0x637f5ab2fb73b020ULL, 0xee09725b7c6ac515ULL, 0x0000000000000000ULL, 0x338ccbf6c876dd8aULL, 0x56540fcd9cef776fULL, 0x623494f447ab408fULL, 0x91e175f2cbd1fa80ULL,
        0x0f8e6ec59abc397bULL, 0x4855d35ab58a0599ULL, 0x894737ec4d5e92b3ULL, 0xbd27acd5961aa553ULL, 0x4d2f0219c31512b0ULL, 0xe1871c9ee6d6fc6eULL, 0x8fe0a965e2b48876ULL, 0x118fb252b3d94b8dULL,
        0xc0592af0440c6785ULL, 0xaca81e8725c3eedeULL, 0xd771062b583f36cdULL, 0x7066696c2d0706eeULL, 0x99834bf8425f2991ULL, 0x3aa53bbafd20fe34ULL, 0x4406f255f643310eULL, 0xa1b0f1cedad22ae6ULL,
        0x82f8462c1da54c4eULL, 0x0929f04c355623beULL, 0x057ad143769f1729ULL, 0x949ba4b1bd4eeda9ULL, 0x960d253dd8e310eaULL, 0xfecd0e4f736b7e37ULL, 0x0296818c65adfd43ULL, 0x6f2c7bbdb8ba84b7ULL,
        0x9a5e04329b2a247dULL, 0x2348b7e2c77766a8ULL, 0xdcce77eb08c4e830ULL, 0x851416e30e97a624ULL, 0x08623e0a898ed311ULL, 0x43eaa29ae571db64ULL, 0xc7b57a3f573e8defULL, 0xc2cfab7c21a19ac6ULL,
        0x5ca0b04b70cc593dULL, 0x0ec5a0832664c9d4ULL, 0x1e01dc97296572f6ULL, 0xbacbfc1a85284f39ULL, 0xc970dabc715a443bULL, 0xa8990182ef840958ULL, 0xc83b14facd82b494ULL, 0x72f0e8e048aafbadULL,
        0xf143608ae9d7474cULL, 0xf5727f8f2390a0caULL, 0x7fe807a9b7bb3f95ULL, 0x76c1f7e582ed1c2bULL, 0xcd41c5b9bb1da3bdULL, 0x6b1d64b872fd6331ULL, 0x806ec7a07808b10dULL, 0xe3119d12837b012dULL,
        0x25ef296b689d7c6dULL, 0x37bdd4f302313a0cULL, 0x3051843c1103d066ULL, 0x68c02b72ab886eddULL, 0x8782976f6b3a5b67ULL, 0x2d8d1761e113af7cULL, 0x1252fd986aac4661ULL, 0x0bbf71c050fbdefdULL,
        0xd20bd7682ea021e4ULL, 0xe0ccd2d85a0e0cc1ULL, 0x9cf99abb34c03eb8ULL, 0xdd85b9adb41c189fULL, 0x61e9db3e9ede4d63ULL, 0x06a79e89afea1ac5ULL, 0xf7e4fe03463d5d89ULL, 0x794f992018512550ULL,
        0x3beef5fc41f80e9bULL, 0xcaad9576a82f49d7ULL, 0x10c47c140f01bb22ULL, 0x0af4bf86ec232e52ULL, 0xdb2227241bf6025aULL, 0x21de366ea2da9bebULL, 0x9f24d571edb53354ULL, 0x9746eb7b643be045ULL,
        0xa3267042bf7fd7a5ULL, 0x6e67b5fb04627418ULL, 0xc46835f58e4b8003ULL, 0x07ec50cf1332ea6aULL, 0xe8aeecd2d380dfd0ULL, 0xe9e522946f582f7fULL, 0x54c28e41f9428a2cULL, 0xe25a53543fa3f182ULL,
        0xa9d2cfc4535cf9f7ULL, 0xa0fb3f88660ada49ULL, 0x50f3914433056daaULL, 0x51b85f028fdd9d05ULL, 0xec9ff3d719c73856ULL, 0x263266a1b1e87181ULL, 0x5e3631c71561a47eULL, 0x24a4e72dd4458cc2ULL,
        0x74577669e740e168ULL, 0x7a92d6eac12428bcULL, 0x2e5058ab3866a290ULL, 0x4ef24dd31a601f5cULL, 0xf9215e806059945dULL, 0xfbb7df0c05f4691eULL, 0x751cb82f5b9811c7ULL, 0x29bc08642b5448faULL,
        0x5891af4eba8bbebbULL, 0x73bb26a6f4720b02ULL, 0x6dbafa31dd1779f4ULL, 0x7c3548636ece3279ULL, 0x4c64cc5f7fcde21fULL, 0x60a215782206bdccULL, 0xa7176f4775383023ULL, 0xbfb12d59f3b75810ULL
    },
    {
        0x51843c1103d06630ULL, 0xdfeaf98bbfe91d3fULL, 0xeef5fc41f80e9b3bULL, 0xaf3045fae5ad26f6ULL, 0x70dabc715a443bc9ULL, 0x119d12837b012de3ULL, 0x3b14facd82b494c8ULL, 0xdd4fcad9750dec03ULL,
        0xaabbb477090a2f90ULL, 0x75514dfcb6e332afULL, 0x96818c65adfd4302ULL, 0x1d64b872fd63316bULL, 0xe4fe03463d5d89f7ULL, 0x43608ae9d7474cf1ULL, 0xe20c56b07e6c87b3ULL, 0xf24dd31a601f5c4eULL,
        0x577669e740e16874ULL, 0x609b39db4437e034ULL, 0x3ac86de4e7c662d6ULL, 0x0379a47baf960722ULL, 0xa79e89afea1ac506ULL, 0x4bce46bcd8f0af01ULL, 0x267042bf7fd7a5a3ULL, 0x7ad143769f172905ULL,
        0x85b9adb41c189fddULL, 0xc885befe87d93e98ULL, 0xed8c583a57989c19ULL, 0x3c3a3812a4f76c92ULL, 0x5e04329b2a247d9aULL, 0xf99abb34c03eb89cULL, 0x2227241bf6025adbULL, 0x6510c856a890e952ULL,
        0xa215782206bdcc60ULL, 0x9ff3d719c73856ecULL, 0x02a53352cae4f13cULL, 0x871c9ee6d6fc6ee1ULL, 0x80325c39f0bf96bbULL, 0x8d1761e113af7c2dULL, 0x46eb7b643be04597ULL, 0xd8c43b5499aae565ULL,
        0x81eecb1095cd60a5ULL, 0x9c8a736268ae51ceULL, 0x64cc5f7fcde21f4cULL, 0x7c231680dc262741ULL, 0xc28e41f9428a2c54ULL, 0x8ccbf6c876dd8a33ULL, 0xb98395a6b8eff34fULL, 0xa9c2100ca69c28b2ULL,
        0x6ec7a07808b10d80ULL, 0x0a0bff07c55312ccULL, 0xc02b72ab886edd68ULL, 0xb85f028fdd9d0551ULL, 0x104185aa1e73dbfdULL, 0xb6039b2c911be8e5ULL, 0x79a8e70d30812e27ULL, 0x82976f6b3a5b6787ULL,
        0xa53bbafd20fe343aULL, 0x7dff81a9b954d15fULL, 0x894007459a7a8355ULL, 0xd43d91a51fc8f9edULL, 0xccd2d85a0e0cc1e0ULL, 0xe807a9b7bb3f957fULL, 0xa81e8725c3eedeacULL, 0x5058ab3866a2902eULL,
        0x889c906cff08754bULL, 0x4ce08463feb3575bULL, 0xdc935df0107f1a1dULL, 0x56aafece25939e6aULL, 0xa16cdc59a92bcb42ULL, 0xec50cf1332ea6a07ULL, 0x4592df1f947642b5ULL, 0xbafa31dd1779f46dULL,
        0x29f04c355623be09ULL, 0x15ca7427f2d4d29bULL, 0x215e806059945df9ULL, 0x23fbb3329370acc5ULL, 0xd74435deb05efecfULL, 0xeaa29ae571db6443ULL, 0xc95929d7e2abc886ULL, 0xa4e72dd4458cc224ULL,
        0x3548636ece32797cULL, 0x27acd5961aa553bdULL, 0xac49e1814a3b21d4ULL, 0xcbfc1a85284f39baULL, 0x8fb252b3d94b8d11ULL, 0x42bc1dc0b235baefULL, 0x072ec2df2643f85aULL, 0x91af4eba8bbebb58ULL,
        0x045766a489d5ff78ULL, 0x9073d993eecc4d46ULL, 0x3f439c690b616bb0ULL, 0x6b4c51f5e41604e6ULL, 0x7e8625d216c2d67dULL, 0xab67235e6c78d98eULL, 0xef296b689d7c6d25ULL, 0xc5a0832664c9d40eULL,
        0x69e962a72ef2f5daULL, 0x7b0dd45ffa65df1bULL, 0x496b75ee12145e3dULL, 0xd918ac7dfcd8137bULL, 0x1e1d1c0952f53649ULL, 0xfeb479ebe67d40c6ULL, 0x6147aef22145162aULL, 0x0f800e8a29f41baaULL,
        0x0000000000000000ULL, 0x990182ef840958a8ULL, 0x975d1b4cc88fb51cULL, 0x5b8fc316c68374fcULL, 0x16b3d05c5d42d5b9ULL, 0xb3886aa17dbce183ULL, 0x4f99201851255079ULL, 0x98dd15c6e17baeb6ULL,
        0x06f255f643310e44ULL, 0x6f1b37516dc3fb9eULL, 0x0cf9aaf186621c88ULL, 0x8e6ec59abc397b0fULL, 0x930a7de8415a4a64ULL, 0x37ed503c04d68840ULL, 0xf61ab5bee9caa336ULL, 0xfb3f88660ada49a0ULL,
        0x7874702455f3d839ULL, 0x208217493ce6abe7ULL, 0x73a3180af5d23cebULL, 0x9e2f4030a24aa0f2ULL, 0xe522946f582f7fe9ULL, 0xd5e1068c7aba0ff3ULL, 0xbdd4f302313a0c37ULL, 0x1fc18b203787c057ULL,
        0xd2cfc4535cf9f7a9ULL, 0x1b96ed84be523f2fULL, 0x5d7d96e085b27ab8ULL, 0x66696c2d0706ee70ULL, 0xd06af701961d0695ULL, 0xe3d0c1991b1e71adULL, 0x6c62932ac255fcbcULL, 0xd313537a398b01b7ULL,
        0xa0b04b70cc593d5cULL, 0x834bf8425f299199ULL, 0xaeecd2d380dfd0e8ULL, 0xbead57799eac0b15ULL, 0x540fcd9cef776f56ULL, 0xad9576a82f49d7caULL, 0xfc114ab92c99b1faULL, 0x33ba36988d037738ULL,
        0xbb26a6f4720b0273ULL, 0xb254fd8818ce179dULL, 0xa6421e868f683318ULL, 0x5fd8a5b24f568b84ULL, 0x623e0a898ed31108ULL, 0xb0f1cedad22ae6a1ULL, 0x1933ded674b6ce13ULL, 0x1416e30e97a62485ULL,
        0x3e9f0b406e139daeULL, 0x6dbe0403a7270aa2ULL, 0xbc08642b5448fa29ULL, 0x0d253dd8e310ea96ULL, 0x2ede8eea70604653ULL, 0x39b1c99f485065f4ULL, 0xcd0e4f736b7e37feULL, 0xbf71c050fbdefd0bULL,
        0x748ddad5d391c4b1ULL, 0x0bd7682ea021e4d2ULL, 0x3494f447ab408f62ULL, 0xb4a6a87e5bff19d9ULL, 0x133821d1b1e5dcdfULL, 0x95f8281e026b4420ULL, 0x2da72a91dff64171ULL, 0x18ef49ff11c4380dULL,
        0xc705b074ae2d2532ULL, 0x3de6af3bc1859a8cULL, 0x6835f58e4b8003c4ULL, 0xe787a73d92cb8ed5ULL, 0xc6d9275dcb5fd32cULL, 0xf7c622978cb85528ULL, 0x4d3c134a9bc1a145ULL, 0xf3914433056daa50ULL,
        0xb7df0c05f4691efbULL, 0xe175f2cbd1fa8091ULL, 0x77f47eae7c07c393ULL, 0xeb7e0dcc14a9925dULL, 0xf1347761cf895b6cULL, 0x08aecc550fb7e3f0ULL, 0x55d35ab58a059948ULL, 0x444e4836f104b4abULL,
        0x58f6676d691573deULL, 0x9ba4b1bd4eeda994ULL, 0x92d6eac12428bc7aULL, 0xb12d59f3b75810bfULL, 0xa3c9ef0b63cf3a7eULL, 0x67b5fb046274186eULL, 0x2f0219c31512b04dULL, 0x3266a1b1e8718126ULL,
        0x7628e9871975358dULL, 0xda610806534e1459ULL, 0x311f05ca47e78604ULL, 0x12e4b6f8d4972ac1ULL, 0x282cdb1c33514817ULL, 0x727f8f2390a0caf5ULL, 0xb57a3f573e8defc7ULL, 0x71062b583f36cdd7ULL,
        0x84653a9d796a69c3ULL, 0xf56311c5465ca414ULL, 0x4737ec4d5e92b389ULL, 0x1cb82f5b9811c775ULL, 0x2509e6c4d041a281ULL, 0xfdcddd9049eb47e4ULL, 0x40192e9278d14bd3ULL, 0x2a89e84ef9b5b92bULL,
        0x3631c71561a47e5eULL, 0x8be53417509e7269ULL, 0x24d571edb533549fULL, 0xc352d6d027f8da4aULL, 0x01dc97296572f61eULL, 0xe9db3e9ede4d6361ULL, 0x4e45b7313457a667ULL, 0xf8462c1da54c4e82ULL,
        0x4a12d195bd82591fULL, 0xff68eec2830fb6d8ULL, 0x176f4775383023a7ULL, 0x48b7e2c77766a823ULL, 0x592af0440c6785c0ULL, 0x2c7bbdb8ba84b76fULL, 0x5ca101c9e0c08ca6ULL, 0x63e29da0eba1e716ULL,
        0xd698a2f7d52c08d1ULL, 0xce77eb08c4e830dcULL, 0xde366ea2da9beb21ULL, 0x5a53543fa3f182e2ULL, 0x52fd986aac466112ULL, 0x86c009cfb38e98ffULL, 0xd1b66028f36ff08bULL, 0x1a4a7aaddb20c931ULL,
        0xcfab7c21a19ac6c2ULL, 0x09725b7c6ac515eeULL, 0x0e5c99a34c86edb4ULL, 0xdbbd9f2f363ce247ULL, 0x6a90c6dc8164f2f8ULL, 0x8a39a33e35ec8477ULL, 0xe0a965e2b488768fULL, 0x7f5ab2fb73b02063ULL,
        0xf4bf86ec232e520aULL, 0xfae31f4f6fa8bfbeULL, 0x058bf18deca70966ULL, 0x41c5b9bb1da3bdcdULL, 0x2b557f679cc74f35ULL, 0xca208dac4d3dcfa4ULL, 0x9a7826942b9f5f8aULL, 0xf0e8e048aafbad72ULL,
        0x53210f43c934970cULL, 0xc1f7e582ed1c2b76ULL, 0xc47c140f01bb2210ULL, 0x9d56e44b0ddca7d0ULL, 0x386d5eb62d2293eaULL, 0xe65b3014f7b978cbULL, 0x9424bf376719b23eULL, 0x30c392e32295701aULL
    }
};

static const uint8_t s_blocks_default[SBOX_LEN] = {
    0xa8, 0x43, 0x5f, 0x06, 0x6b, 0x75, 0x6c, 0x59, 0x71, 0xdf, 0x87, 0x95, 0x17, 0xf0, 0xd8, 0x09,
    0x6d, 0xf3, 0x1d, 0xcb, 0xc9, 0x4d, 0x2c, 0xaf, 0x79, 0xe0, 0x97, 0xfd, 0x6f, 0x4b, 0x45, 0x39,
    0x3e, 0xdd, 0xa3, 0x4f, 0xb4, 0xb6, 0x9a, 0x0e, 0x1f, 0xbf, 0x15, 0xe1, 0x49, 0xd2, 0x93, 0xc6,
    0x92, 0x72, 0x9e, 0x61, 0xd1, 0x63, 0xfa, 0xee, 0xf4, 0x19, 0xd5, 0xad, 0x58, 0xa4, 0xbb, 0xa1,
    0xdc, 0xf2, 0x83, 0x37, 0x42, 0xe4, 0x7a, 0x32, 0x9c, 0xcc, 0xab, 0x4a, 0x8f, 0x6e, 0x04, 0x27,
    0x2e, 0xe7, 0xe2, 0x5a, 0x96, 0x16, 0x23, 0x2b, 0xc2, 0x65, 0x66, 0x0f, 0xbc, 0xa9, 0x47, 0x41,
    0x34, 0x48, 0xfc, 0xb7, 0x6a, 0x88, 0xa5, 0x53, 0x86, 0xf9, 0x5b, 0xdb, 0x38, 0x7b, 0xc3, 0x1e,
    0x22, 0x33, 0x24, 0x28, 0x36, 0xc7, 0xb2, 0x3b, 0x8e, 0x77, 0xba, 0xf5, 0x14, 0x9f, 0x08, 0x55,
    0x9b, 0x4c, 0xfe, 0x60, 0x5c, 0xda, 0x18, 0x46, 0xcd, 0x7d, 0x21, 0xb0, 0x3f, 0x1b, 0x89, 0xff,
    0xeb, 0x84, 0x69, 0x3a, 0x9d, 0xd7, 0xd3, 0x70, 0x67, 0x40, 0xb5, 0xde, 0x5d, 0x30, 0x91, 0xb1,
    0x78, 0x11, 0x01, 0xe5, 0x00, 0x68, 0x98, 0xa0, 0xc5, 0x02, 0xa6, 0x74, 0x2d, 0x0b, 0xa2, 0x76,
    0xb3, 0xbe, 0xce, 0xbd, 0xae, 0xe9, 0x8a, 0x31, 0x1c, 0xec, 0xf1, 0x99, 0x94, 0xaa, 0xf6, 0x26,
    0x2f, 0xef, 0xe8, 0x8c, 0x35, 0x03, 0xd4, 0x7f, 0xfb, 0x05, 0xc1, 0x5e, 0x90, 0x20, 0x3d, 0x82,
    0xf7, 0xea, 0x0a, 0x0d, 0x7e, 0xf8, 0x50, 0x1a, 0xc4, 0x07, 0x57, 0xb8, 0x3c, 0x62, 0xe3, 0xc8,
    0xac, 0x52, 0x64, 0x10, 0xd0, 0xd9, 0x13, 0x0c, 0x12, 0x29, 0x51, 0xb9, 0xcf, 0xd6, 0x73, 0x8d,
    0x81, 0x54, 0xc0, 0xed, 0x4e, 0x44, 0xa7, 0x2a, 0x85, 0x25, 0xe6, 0xca, 0x7c, 0x8b, 0x56, 0x80,

    0xce, 0xbb, 0xeb, 0x92, 0xea, 0xcb, 0x13, 0xc1, 0xe9, 0x3a, 0xd6, 0xb2, 0xd2, 0x90, 0x17, 0xf8,
    0x42, 0x15, 0x56, 0xb4, 0x65, 0x1c, 0x88, 0x43, 0xc5, 0x5c, 0x36, 0xba, 0xf5, 0x57, 0x67, 0x8d,
    0x31, 0xf6, 0x64, 0x58, 0x9e, 0xf4, 0x22, 0xaa, 0x75, 0x0f, 0x02, 0xb1, 0xdf, 0x6d, 0x73, 0x4d,
    0x7c, 0x26, 0x2e, 0xf7, 0x08, 0x5d, 0x44, 0x3e, 0x9f, 0x14, 0xc8, 0xae, 0x54, 0x10, 0xd8, 0xbc,
    0x1a, 0x6b, 0x69, 0xf3, 0xbd, 0x33, 0xab, 0xfa, 0xd1, 0x9b, 0x68, 0x4e, 0x16, 0x95, 0x91, 0xee,
    0x4c, 0x63, 0x8e, 0x5b, 0xcc, 0x3c, 0x19, 0xa1, 0x81, 0x49, 0x7b, 0xd9, 0x6f, 0x37, 0x60, 0xca,
    0xe7, 0x2b, 0x48, 0xfd, 0x96, 0x45, 0xfc, 0x41, 0x12, 0x0d, 0x79, 0xe5, 0x89, 0x8c, 0xe3, 0x20,
    0x30, 0xdc, 0xb7, 0x6c, 0x4a, 0xb5, 0x3f, 0x97, 0xd4, 0x62, 0x2d, 0x06, 0xa4, 0xa5, 0x83, 0x5f,
    0x2a, 0xda, 0xc9, 0x00, 0x7e, 0xa2, 0x55, 0xbf, 0x11, 0xd5, 0x9c, 0xcf, 0x0e, 0x0a, 0x3d, 0x51,
    0x7d, 0x93, 0x1b, 0xfe, 0xc4, 0x47, 0x09, 0x86, 0x0b, 0x8f, 0x9d, 0x6a, 0x07, 0xb9, 0xb0, 0x98,
    0x18, 0x32, 0x71, 0x4b, 0xef, 0x3b, 0x70, 0xa0, 0xe4, 0x40, 0xff, 0xc3, 0xa9, 0xe6, 0x78, 0xf9,
    0x8b, 0x46, 0x80, 0x1e, 0x38, 0xe1, 0xb8, 0xa8, 0xe0, 0x0c, 0x23, 0x76, 0x1d, 0x25, 0x24, 0x05,
    0xf1, 0x6e, 0x94, 0x28, 0x9a, 0x84, 0xe8, 0xa3, 0x4f, 0x77, 0xd3, 0x85, 0xe2, 0x52, 0xf2, 0x82,
    0x50, 0x7a, 0x2f, 0x74, 0x53, 0xb3, 0x61, 0xaf, 0x39, 0x35, 0xde, 0xcd, 0x1f, 0x99, 0xac, 0xad,
    0x72, 0x2c, 0xdd, 0xd0, 0x87, 0xbe, 0x5e, 0xa6, 0xec, 0x04, 0xc6, 0x03, 0x34, 0xfb, 0xdb, 0x59,
    0xb6, 0xc2, 0x01, 0xf0, 0x5a, 0xed, 0xa7, 0x66, 0x21, 0x7f, 0x8a, 0x27, 0xc7, 0xc0, 0x29, 0xd7,

    0x93, 0xd9, 0x9a, 0xb5, 0x98, 0x22, 0x45, 0xfc, 0xba, 0x6a, 0xdf, 0x02, 0x9f, 0xdc, 0x51, 0x59,
    0x4a, 0x17, 0x2b, 0xc2, 0x94, 0xf4, 0xbb, 0xa3, 0x62, 0xe4, 0x71, 0xd4, 0xcd, 0x70, 0x16, 0xe1,
    0x49, 0x3c, 0xc0, 0xd8, 0x5c, 0x9b, 0xad, 0x85, 0x53, 0xa1, 0x7a, 0xc8, 0x2d, 0xe0, 0xd1, 0x72,
    0xa6, 0x2c, 0xc4, 0xe3, 0x76, 0x78, 0xb7, 0xb4, 0x09, 0x3b, 0x0e, 0x41, 0x4c, 0xde, 0xb2, 0x90,
    0x25, 0xa5, 0xd7, 0x03, 0x11, 0x00, 0xc3, 0x2e, 0x92, 0xef, 0x4e, 0x12, 0x9d, 0x7d, 0xcb, 0x35,
    0x10, 0xd5, 0x4f, 0x9e, 0x4d, 0xa9, 0x55, 0xc6, 0xd0, 0x7b, 0x18, 0x97, 0xd3, 0x36, 0xe6, 0x48,
    0x56, 0x81, 0x8f, 0x77, 0xcc, 0x9c, 0xb9, 0xe2, 0xac, 0xb8, 0x2f, 0x15, 0xa4, 0x7c, 0xda, 0x38,
    0x1e, 0x0b, 0x05, 0xd6, 0x14, 0x6e, 0x6c, 0x7e, 0x66, 0xfd, 0xb1, 0xe5, 0x60, 0xaf, 0x5e, 0x33,
    0x87, 0xc9, 0xf0, 0x5d, 0x6d, 0x3f, 0x88, 0x8d, 0xc7, 0xf7, 0x1d, 0xe9, 0xec, 0xed, 0x80, 0x29,
    0x27, 0xcf, 0x99, 0xa8, 0x50, 0x0f, 0x37, 0x24, 0x28, 0x30, 0x95, 0xd2, 0x3e, 0x5b, 0x40, 0x83,
    0xb3, 0x69, 0x57, 0x1f, 0x07, 0x1c, 0x8a, 0xbc, 0x20, 0xeb, 0xce, 0x8e, 0xab, 0xee, 0x31, 0xa2,
    0x73, 0xf9, 0xca, 0x3a, 0x1a, 0xfb, 0x0d, 0xc1, 0xfe, 0xfa, 0xf2, 0x6f, 0xbd, 0x96, 0xdd, 0x43,
    0x52, 0xb6, 0x08, 0xf3, 0xae, 0xbe, 0x19, 0x89, 0x32, 0x26, 0xb0, 0xea, 0x4b, 0x64, 0x84, 0x82,
    0x6b, 0xf5, 0x79, 0xbf, 0x01, 0x5f, 0x75, 0x63, 0x1b, 0x23, 0x3d, 0x68, 0x2a, 0x65, 0xe8, 0x91,
    0xf6, 0xff, 0x13, 0x58, 0xf1, 0x47, 0x0a, 0x7f, 0xc5, 0xa7, 0xe7, 0x61, 0x5a, 0x06, 0x46, 0x44,
    0x42, 0x04, 0xa0, 0xdb, 0x39, 0x86, 0x54, 0xaa, 0x8c, 0x34, 0x21, 0x8b, 0xf8, 0x0c, 0x74, 0x67,

    0x68, 0x8d, 0xca, 0x4d, 0x73, 0x4b, 0x4e, 0x2a, 0xd4, 0x52, 0x26, 0xb3, 0x54, 0x1e, 0x19, 0x1f,
    0x22, 0x03, 0x46, 0x3d, 0x2d, 0x4a, 0x53, 0x83, 0x13, 0x8a, 0xb7, 0xd5, 0x25, 0x79, 0xf5, 0xbd,
    0x58, 0x2f, 0x0d, 0x02, 0xed, 0x51, 0x9e, 0x11, 0xf2, 0x3e, 0x55, 0x5e, 0xd1, 0x16, 0x3c, 0x66,
    0x70, 0x5d, 0xf3, 0x45, 0x40, 0xcc, 0xe8, 0x94, 0x56, 0x08, 0xce, 0x1a, 0x3a, 0xd2, 0xe1, 0xdf,
    0xb5, 0x38, 0x6e, 0x0e, 0xe5, 0xf4, 0xf9, 0x86, 0xe9, 0x4f, 0xd6, 0x85, 0x23, 0xcf, 0x32, 0x99,
    0x31, 0x14, 0xae, 0xee, 0xc8, 0x48, 0xd3, 0x30, 0xa1, 0x92, 0x41, 0xb1, 0x18, 0xc4, 0x2c, 0x71,
    0x72, 0x44, 0x15, 0xfd, 0x37, 0xbe, 0x5f, 0xaa, 0x9b, 0x88, 0xd8, 0xab, 0x89, 0x9c, 0xfa, 0x60,
    0xea, 0xbc, 0x62, 0x0c, 0x24, 0xa6, 0xa8, 0xec, 0x67, 0x20, 0xdb, 0x7c, 0x28, 0xdd, 0xac, 0x5b,
    0x34, 0x7e, 0x10, 0xf1, 0x7b, 0x8f, 0x63, 0xa0, 0x05, 0x9a, 0x43, 0x77, 0x21, 0xbf, 0x27, 0x09,
    0xc3, 0x9f, 0xb6, 0xd7, 0x29, 0xc2, 0xeb, 0xc0, 0xa4, 0x8b, 0x8c, 0x1d, 0xfb, 0xff, 0xc1, 0xb2,
    0x97, 0x2e, 0xf8, 0x65, 0xf6, 0x75, 0x07, 0x04, 0x49, 0x33, 0xe4, 0xd9, 0xb9, 0xd0, 0x42, 0xc7,
    0x6c, 0x90, 0x00, 0x8e, 0x6f, 0x50, 0x01, 0xc5, 0xda, 0x47, 0x3f, 0xcd, 0x69, 0xa2, 0xe2, 0x7a,
    0xa7, 0xc6, 0x93, 0x0f, 0x0a, 0x06, 0xe6, 0x2b, 0x96, 0xa3, 0x1c, 0xaf, 0x6a, 0x12, 0x84, 0x39,
    0xe7, 0xb0, 0x82, 0xf7, 0xfe, 0x9d, 0x87, 0x5c, 0x81, 0x35, 0xde, 0xb4, 0xa5, 0xfc, 0x80, 0xef,
    0xcb, 0xbb, 0x6b, 0x76, 0xba, 0x5a, 0x7d, 0x78, 0x0b, 0x95, 0xe3, 0xad, 0x74, 0x98, 0x3b, 0x36,
    0x64, 0x6d, 0xdc, 0xf0, 0x59, 0xa9, 0x4c, 0x17, 0x7f, 0x91, 0xb8, 0xc9, 0x57, 0x1b, 0xe0, 0x61
};

static const uint8_t inv_s_blocks_default[SBOX_LEN] = {
    0xA4, 0xA2, 0xA9, 0xC5, 0x4E, 0xC9, 0x03, 0xD9, 0x7E, 0x0F, 0xD2, 0xAD, 0xE7, 0xD3, 0x27, 0x5B,
    0xE3, 0xA1, 0xE8, 0xE6, 0x7C, 0x2A, 0x55, 0x0C, 0x86, 0x39, 0xD7, 0x8D, 0xB8, 0x12, 0x6F, 0x28,
    0xCD, 0x8A, 0x70, 0x56, 0x72, 0xF9, 0xBF, 0x4F, 0x73, 0xE9, 0xF7, 0x57, 0x16, 0xAC, 0x50, 0xC0,
    0x9D, 0xB7, 0x47, 0x71, 0x60, 0xC4, 0x74, 0x43, 0x6C, 0x1F, 0x93, 0x77, 0xDC, 0xCE, 0x20, 0x8C,
    0x99, 0x5F, 0x44, 0x01, 0xF5, 0x1E, 0x87, 0x5E, 0x61, 0x2C, 0x4B, 0x1D, 0x81, 0x15, 0xF4, 0x23,
    0xD6, 0xEA, 0xE1, 0x67, 0xF1, 0x7F, 0xFE, 0xDA, 0x3C, 0x07, 0x53, 0x6A, 0x84, 0x9C, 0xCB, 0x02,
    0x83, 0x33, 0xDD, 0x35, 0xE2, 0x59, 0x5A, 0x98, 0xA5, 0x92, 0x64, 0x04, 0x06, 0x10, 0x4D, 0x1C,
    0x97, 0x08, 0x31, 0xEE, 0xAB, 0x05, 0xAF, 0x79, 0xA0, 0x18, 0x46, 0x6D, 0xFC, 0x89, 0xD4, 0xC7,
    0xFF, 0xF0, 0xCF, 0x42, 0x91, 0xF8, 0x68, 0x0A, 0x65, 0x8E, 0xB6, 0xFD, 0xC3, 0xEF, 0x78, 0x4C,
    0xCC, 0x9E, 0x30, 0x2E, 0xBC, 0x0B, 0x54, 0x1A, 0xA6, 0xBB, 0x26, 0x80, 0x48, 0x94, 0x32, 0x7D,
    0xA7, 0x3F, 0xAE, 0x22, 0x3D, 0x66, 0xAA, 0xF6, 0x00, 0x5D, 0xBD, 0x4A, 0xE0, 0x3B, 0xB4, 0x17,
    0x8B, 0x9F, 0x76, 0xB0, 0x24, 0x9A, 0x25, 0x63, 0xDB, 0xEB, 0x7A, 0x3E, 0x5C, 0xB3, 0xB1, 0x29,
    0xF2, 0xCA, 0x58, 0x6E, 0xD8, 0xA8, 0x2F, 0x75, 0xDF, 0x14, 0xFB, 0x13, 0x49, 0x88, 0xB2, 0xEC,
    0xE4, 0x34, 0x2D, 0x96, 0xC6, 0x3A, 0xED, 0x95, 0x0E, 0xE5, 0x85, 0x6B, 0x40, 0x21, 0x9B, 0x09,
    0x19, 0x2B, 0x52, 0xDE, 0x45, 0xA3, 0xFA, 0x51, 0xC2, 0xB5, 0xD1, 0x90, 0xB9, 0xF3, 0x37, 0xC1,
    0x0D, 0xBA, 0x41, 0x11, 0x38, 0x7B, 0xBE, 0xD0, 0xD5, 0x69, 0x36, 0xC8, 0x62, 0x1B, 0x82, 0x8F,

    0x83, 0xF2, 0x2A, 0xEB, 0xE9, 0xBF, 0x7B, 0x9C, 0x34, 0x96, 0x8D, 0x98, 0xB9, 0x69, 0x8C, 0x29,
    0x3D, 0x88, 0x68, 0x06, 0x39, 0x11, 0x4C, 0x0E, 0xA0, 0x56, 0x40, 0x92, 0x15, 0xBC, 0xB3, 0xDC,
    0x6F, 0xF8, 0x26, 0xBA, 0xBE, 0xBD, 0x31, 0xFB, 0xC3, 0xFE, 0x80, 0x61, 0xE1, 0x7A, 0x32, 0xD2,
    0x70, 0x20, 0xA1, 0x45, 0xEC, 0xD9, 0x1A, 0x5D, 0xB4, 0xD8, 0x09, 0xA5, 0x55, 0x8E, 0x37, 0x76,
    0xA9, 0x67, 0x10, 0x17, 0x36, 0x65, 0xB1, 0x95, 0x62, 0x59, 0x74, 0xA3, 0x50, 0x2F, 0x4B, 0xC8,
    0xD0, 0x8F, 0xCD, 0xD4, 0x3C, 0x86, 0x12, 0x1D, 0x23, 0xEF, 0xF4, 0x53, 0x19, 0x35, 0xE6, 0x7F,
    0x5E, 0xD6, 0x79, 0x51, 0x22, 0x14, 0xF7, 0x1E, 0x4A, 0x42, 0x9B, 0x41, 0x73, 0x2D, 0xC1, 0x5C,
    0xA6, 0xA2, 0xE0, 0x2E, 0xD3, 0x28, 0xBB, 0xC9, 0xAE, 0x6A, 0xD1, 0x5A, 0x30, 0x90, 0x84, 0xF9,
    0xB2, 0x58, 0xCF, 0x7E, 0xC5, 0xCB, 0x97, 0xE4, 0x16, 0x6C, 0xFA, 0xB0, 0x6D, 0x1F, 0x52, 0x99,
    0x0D, 0x4E, 0x03, 0x91, 0xC2, 0x4D, 0x64, 0x77, 0x9F, 0xDD, 0xC4, 0x49, 0x8A, 0x9A, 0x24, 0x38,
    0xA7, 0x57, 0x85, 0xC7, 0x7C, 0x7D, 0xE7, 0xF6, 0xB7, 0xAC, 0x27, 0x46, 0xDE, 0xDF, 0x3B, 0xD7,
    0x9E, 0x2B, 0x0B, 0xD5, 0x13, 0x75, 0xF0, 0x72, 0xB6, 0x9D, 0x1B, 0x01, 0x3F, 0x44, 0xE5, 0x87,
    0xFD, 0x07, 0xF1, 0xAB, 0x94, 0x18, 0xEA, 0xFC, 0x3A, 0x82, 0x5F, 0x05, 0x54, 0xDB, 0x00, 0x8B,
    0xE3, 0x48, 0x0C, 0xCA, 0x78, 0x89, 0x0A, 0xFF, 0x3E, 0x5B, 0x81, 0xEE, 0x71, 0xE2, 0xDA, 0x2C,
    0xB8, 0xB5, 0xCC, 0x6E, 0xA8, 0x6B, 0xAD, 0x60, 0xC6, 0x08, 0x04, 0x02, 0xE8, 0xF5, 0x4F, 0xA4,
    0xF3, 0xC0, 0xCE, 0x43, 0x25, 0x1C, 0x21, 0x33, 0x0F, 0xAF, 0x47, 0xED, 0x66, 0x63, 0x93, 0xAA,

    0x45, 0xD4, 0x0B, 0x43, 0xF1, 0x72, 0xED, 0xA4, 0xC2, 0x38, 0xE6, 0x71, 0xFD, 0xB6, 0x3A, 0x95,
    0x50, 0x44, 0x4B, 0xE2, 0x74, 0x6B, 0x1E, 0x11, 0x5A, 0xC6, 0xB4, 0xD8, 0xA5, 0x8A, 0x70, 0xA3,
    0xA8, 0xFA, 0x05, 0xD9, 0x97, 0x40, 0xC9, 0x90, 0x98, 0x8F, 0xDC, 0x12, 0x31, 0x2C, 0x47, 0x6A,
    0x99, 0xAE, 0xC8, 0x7F, 0xF9, 0x4F, 0x5D, 0x96, 0x6F, 0xF4, 0xB3, 0x39, 0x21, 0xDA, 0x9C, 0x85,
    0x9E, 0x3B, 0xF0, 0xBF, 0xEF, 0x06, 0xEE, 0xE5, 0x5F, 0x20, 0x10, 0xCC, 0x3C, 0x54, 0x4A, 0x52,
    0x94, 0x0E, 0xC0, 0x28, 0xF6, 0x56, 0x60, 0xA2, 0xE3, 0x0F, 0xEC, 0x9D, 0x24, 0x83, 0x7E, 0xD5,
    0x7C, 0xEB, 0x18, 0xD7, 0xCD, 0xDD, 0x78, 0xFF, 0xDB, 0xA1, 0x09, 0xD0, 0x76, 0x84, 0x75, 0xBB,
    0x1D, 0x1A, 0x2F, 0xB0, 0xFE, 0xD6, 0x34, 0x63, 0x35, 0xD2, 0x2A, 0x59, 0x6D, 0x4D, 0x77, 0xE7,
    0x8E, 0x61, 0xCF, 0x9F, 0xCE, 0x27, 0xF5, 0x80, 0x86, 0xC7, 0xA6, 0xFB, 0xF8, 0x87, 0xAB, 0x62,
    0x3F, 0xDF, 0x48, 0x00, 0x14, 0x9A, 0xBD, 0x5B, 0x04, 0x92, 0x02, 0x25, 0x65, 0x4C, 0x53, 0x0C,
    0xF2, 0x29, 0xAF, 0x17, 0x6C, 0x41, 0x30, 0xE9, 0x93, 0x55, 0xF7, 0xAC, 0x68, 0x26, 0xC4, 0x7D,
    0xCA, 0x7A, 0x3E, 0xA0, 0x37, 0x03, 0xC1, 0x36, 0x69, 0x66, 0x08, 0x16, 0xA7, 0xBC, 0xC5, 0xD3,
    0x22, 0xB7, 0x13, 0x46, 0x32, 0xE8, 0x57, 0x88, 0x2B, 0x81, 0xB2, 0x4E, 0x64, 0x1C, 0xAA, 0x91,
    0x58, 0x2E, 0x9B, 0x5C, 0x1B, 0x51, 0x73, 0x42, 0x23, 0x01, 0x6E, 0xF3, 0x0D, 0xBE, 0x3D, 0x0A,
    0x2D, 0x1F, 0x67, 0x33, 0x19, 0x7B, 0x5E, 0xEA, 0xDE, 0x8B, 0xCB, 0xA9, 0x8C, 0x8D, 0xAD, 0x49,
    0x82, 0xE4, 0xBA, 0xC3, 0x15, 0xD1, 0xE0, 0x89, 0xFC, 0xB1, 0xB9, 0xB5, 0x07, 0x79, 0xB8, 0xE1,

    0xB2, 0xB6, 0x23, 0x11, 0xA7, 0x88, 0xC5, 0xA6, 0x39, 0x8F, 0xC4, 0xE8, 0x73, 0x22, 0x43, 0xC3,
    0x82, 0x27, 0xCD, 0x18, 0x51, 0x62, 0x2D, 0xF7, 0x5C, 0x0E, 0x3B, 0xFD, 0xCA, 0x9B, 0x0D, 0x0F,
    0x79, 0x8C, 0x10, 0x4C, 0x74, 0x1C, 0x0A, 0x8E, 0x7C, 0x94, 0x07, 0xC7, 0x5E, 0x14, 0xA1, 0x21,
    0x57, 0x50, 0x4E, 0xA9, 0x80, 0xD9, 0xEF, 0x64, 0x41, 0xCF, 0x3C, 0xEE, 0x2E, 0x13, 0x29, 0xBA,
    0x34, 0x5A, 0xAE, 0x8A, 0x61, 0x33, 0x12, 0xB9, 0x55, 0xA8, 0x15, 0x05, 0xF6, 0x03, 0x06, 0x49,
    0xB5, 0x25, 0x09, 0x16, 0x0C, 0x2A, 0x38, 0xFC, 0x20, 0xF4, 0xE5, 0x7F, 0xD7, 0x31, 0x2B, 0x66,
    0x6F, 0xFF, 0x72, 0x86, 0xF0, 0xA3, 0x2F, 0x78, 0x00, 0xBC, 0xCC, 0xE2, 0xB0, 0xF1, 0x42, 0xB4,
    0x30, 0x5F, 0x60, 0x04, 0xEC, 0xA5, 0xE3, 0x8B, 0xE7, 0x1D, 0xBF, 0x84, 0x7B, 0xE6, 0x81, 0xF8,
    0xDE, 0xD8, 0xD2, 0x17, 0xCE, 0x4B, 0x47, 0xD6, 0x69, 0x6C, 0x19, 0x99, 0x9A, 0x01, 0xB3, 0x85,
    0xB1, 0xF9, 0x59, 0xC2, 0x37, 0xE9, 0xC8, 0xA0, 0xED, 0x4F, 0x89, 0x68, 0x6D, 0xD5, 0x26, 0x91,
    0x87, 0x58, 0xBD, 0xC9, 0x98, 0xDC, 0x75, 0xC0, 0x76, 0xF5, 0x67, 0x6B, 0x7E, 0xEB, 0x52, 0xCB,
    0xD1, 0x5B, 0x9F, 0x0B, 0xDB, 0x40, 0x92, 0x1A, 0xFA, 0xAC, 0xE4, 0xE1, 0x71, 0x1F, 0x65, 0x8D,
    0x97, 0x9E, 0x95, 0x90, 0x5D, 0xB7, 0xC1, 0xAF, 0x54, 0xFB, 0x02, 0xE0, 0x35, 0xBB, 0x3A, 0x4D,
    0xAD, 0x2C, 0x3D, 0x56, 0x08, 0x1B, 0x4A, 0x93, 0x6A, 0xAB, 0xB8, 0x7A, 0xF2, 0x7D, 0xDA, 0x3F,
    0xFE, 0x3E, 0xBE, 0xEA, 0xAA, 0x44, 0xC6, 0xD0, 0x36, 0x48, 0x70, 0x96, 0x77, 0x24, 0x53, 0xDF,
    0xF3, 0x83, 0x28, 0x32, 0x45, 0x1E, 0xA4, 0xD3, 0xA2, 0x46, 0x6E, 0x9C, 0xDD, 0x63, 0xD4, 0x9D
};

/*Russian peasant multiplication algorithm*/
static uint8_t multiply_galua(uint8_t x, uint8_t y)
{
    int i;
    uint8_t r = 0;
    uint8_t hbit = 0;
    for (i = 0; i < BITS_IN_BYTE; ++i) {
        if ((y & 0x1) == 1) {
            r ^= x;
        }
        hbit = (uint8_t) (x & 0x80);
        x <<= 1;
        if (hbit == 0x80) {
            x ^= REDUCTION_POLYNOMIAL;
        }
        y >>= 1;
    }
    return r;
}

static void generate_reverse_table(const uint8_t * s_blocks, uint8_t *inv_s_blocks)
{
    size_t i, j;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < MAX_NUM_IN_BYTE; j++) {
            inv_s_blocks[i * MAX_NUM_IN_BYTE + s_blocks[i * MAX_NUM_IN_BYTE + j]] = (uint8_t) j;
        }
    }
}

static void p_sub_row_col(const uint8_t * s_blocks, uint64_t p_boxrowcol[ROWS][MAX_NUM_IN_BYTE], const uint8_t *mds)
{
    size_t i, k;

    for (k = 0; k < ROWS; k++) {
        for (i = 0; i < MAX_NUM_IN_BYTE; i++) {
            p_boxrowcol[k][i] = GALUA_MUL(i, 0, k, 0) ^ GALUA_MUL(i, 1, k, 8) ^ GALUA_MUL(i, 2, k, 16) ^ GALUA_MUL(i, 3, k, 24) ^
                    GALUA_MUL(i, 4, k, 32) ^ GALUA_MUL(i, 5, k, 40) ^ GALUA_MUL(i, 6, k, 48) ^ GALUA_MUL(i, 7, k, 56);
        }
    }
}

static void crypt_basic_transform(Dstu7624Ctx *ctx, const uint8_t *plain_data, uint8_t *cipher_data)
{
    uint64_t state[8] = {0};
    uint8_to_uint64(plain_data, ctx->block_len, state, ctx->block_len >> 3);

    ctx->basic_transform(ctx, state);

    uint64_to_uint8(state, ctx->block_len >> 3, cipher_data, ctx->block_len);
}

Dstu7624Ctx *dstu7624_alloc(Dstu7624SboxId sbox_id)
{
    int ret = RET_OK;
    Dstu7624Ctx *ctx = NULL;

    CALLOC_CHECKED(ctx, sizeof(Dstu7624Ctx));

    switch (sbox_id) {
    case DSTU7624_SBOX_1:
        memcpy(ctx->s_blocks, s_blocks_default, SBOX_LEN);
        memcpy(ctx->inv_s_blocks, inv_s_blocks_default, SBOX_LEN);
        memcpy(ctx->p_boxrowcol, subrowcol_default, 8 * 256 * sizeof(uint64_t));
        memcpy(ctx->p_inv_boxrowcol, inv_subrowcol_default, 8 * 256 * sizeof(uint64_t));
        break;
    default:
        SET_ERROR(RET_INVALID_PARAM);
    }

cleanup:

    return ctx;
}

static Dstu7624Ctx *dstu7624_alloc_user_sbox_core(const uint8_t *s_blocks, size_t sbox_len)
{
    Dstu7624Ctx *ctx = NULL;
    int ret = RET_OK;

    CHECK_PARAM(s_blocks != NULL);
    CHECK_PARAM(sbox_len == SBOX_LEN);

    CALLOC_CHECKED(ctx, sizeof (Dstu7624Ctx));

    memcpy(ctx->s_blocks, s_blocks, SBOX_LEN);
    p_sub_row_col(s_blocks, ctx->p_boxrowcol, mds_matrix);
    generate_reverse_table(s_blocks, ctx->inv_s_blocks);
    p_sub_row_col(ctx->inv_s_blocks, ctx->p_inv_boxrowcol, mds_matrix_reverse);

cleanup:

    return ctx;
}

Dstu7624Ctx *dstu7624_alloc_user_sbox(ByteArray *sblocks)
{
    Dstu7624Ctx *ctx = NULL;
    uint8_t *sblocks_buf = NULL;
    size_t sblock_len;
    int ret = RET_OK;

    CHECK_PARAM(sblocks != NULL);
    DO(ba_to_uint8_with_alloc(sblocks, &sblocks_buf, &sblock_len));

    CHECK_NOT_NULL(ctx = dstu7624_alloc_user_sbox_core(sblocks_buf, sblock_len));
cleanup:
    free(sblocks_buf);
    return ctx;
}

void dstu7624_free(Dstu7624Ctx *ctx)
{
    if (ctx) {
        switch (ctx->mode_id) {
        case DSTU7624_MODE_CTR:
            break;
        case DSTU7624_MODE_CBC:
            break;
        case DSTU7624_MODE_OFB:
            break;
        case DSTU7624_MODE_CFB:
            break;
        case DSTU7624_MODE_CCM:
            break;
        case DSTU7624_MODE_CMAC:
            break;
        case DSTU7624_MODE_XTS:
            gf2m_free(ctx->mode.xts.gf2m_ctx);
            break;
        case DSTU7624_MODE_GCM:
            gf2m_free(ctx->mode.gcm.gf2m_ctx);
            break;
        case DSTU7624_MODE_GMAC:
            gf2m_free(ctx->mode.gmac.gf2m_ctx);
            break;
        default:
            break;
        }
        secure_zero(ctx, sizeof (Dstu7624Ctx));
        free(ctx);
    }
}

int dstu7624_generate_key(size_t key_len, ByteArray **key)
{
    int ret = RET_OK;

    CHECK_PARAM(key_len == 16 || key_len == 32 || key_len == 64)

    CHECK_NOT_NULL(*key = ba_alloc_by_len(key_len));
    DO(drbg_random(*key));

cleanup:

    return ret;
}

static __inline void basic_transform_128(Dstu7624Ctx *ctx, uint64_t *state)
{
    uint64_t point[2] = {0, 0};
    uint64_t *rkey = (uint64_t *) ctx->p_rkeys;

    state[0] += rkey[0];
    state[1] += rkey[1];
    BT_xor128(state, point, rkey + 2);
    BT_xor128(point, state, rkey + 4);
    BT_xor128(state, point, rkey + 6);
    BT_xor128(point, state, rkey + 8);
    BT_xor128(state, point, rkey + 10);
    BT_xor128(point, state, rkey + 12);
    BT_xor128(state, point, rkey + 14);
    BT_xor128(point, state, rkey + 16);
    BT_xor128(state, point, rkey + 18);
    BT_add128(point, state, rkey + 20);
}

static __inline void basic_transform_128_256(Dstu7624Ctx *ctx, uint64_t *state)
{
    uint64_t point[2] = {0, 0};
    uint64_t *rkey = (uint64_t *) ctx->p_rkeys;

    state[0] += rkey[0];
    state[1] += rkey[1];
    BT_xor128(state, point, rkey + 2);
    BT_xor128(point, state, rkey + 4);
    BT_xor128(state, point, rkey + 6);
    BT_xor128(point, state, rkey + 8);
    BT_xor128(state, point, rkey + 10);
    BT_xor128(point, state, rkey + 12);
    BT_xor128(state, point, rkey + 14);
    BT_xor128(point, state, rkey + 16);
    BT_xor128(state, point, rkey + 18);
    BT_xor128(point, state, rkey + 20);
    BT_xor128(state, point, rkey + 22);
    BT_xor128(point, state, rkey + 24);
    BT_xor128(state, point, rkey + 26);
    BT_add128(point, state, rkey + 28);
}

static __inline void basic_transform_256(Dstu7624Ctx *ctx, uint64_t *state)
{
    uint64_t point[4] = {0, 0, 0, 0};
    uint64_t *rkey = (uint64_t *) ctx->p_rkeys;

    state[0] += rkey[0];
    state[1] += rkey[1];
    state[2] += rkey[2];
    state[3] += rkey[3];
    BT_xor256(state, point, rkey + 4);
    BT_xor256(point, state, rkey + 8);
    BT_xor256(state, point, rkey + 12);
    BT_xor256(point, state, rkey + 16);
    BT_xor256(state, point, rkey + 20);
    BT_xor256(point, state, rkey + 24);
    BT_xor256(state, point, rkey + 28);
    BT_xor256(point, state, rkey + 32);
    BT_xor256(state, point, rkey + 36);
    BT_xor256(point, state, rkey + 40);
    BT_xor256(state, point, rkey + 44);
    BT_xor256(point, state, rkey + 48);
    BT_xor256(state, point, rkey + 52);
    BT_add256(point, state, rkey + 56);
}

static __inline void basic_transform_256_512(Dstu7624Ctx *ctx, uint64_t *state)
{
    uint64_t point[4] = {0, 0, 0, 0};
    uint64_t *rkey = (uint64_t *) ctx->p_rkeys;

    state[0] += rkey[0];
    state[1] += rkey[1];
    state[2] += rkey[2];
    state[3] += rkey[3];
    BT_xor256(state, point, rkey + 4);
    BT_xor256(point, state, rkey + 8);
    BT_xor256(state, point, rkey + 12);
    BT_xor256(point, state, rkey + 16);
    BT_xor256(state, point, rkey + 20);
    BT_xor256(point, state, rkey + 24);
    BT_xor256(state, point, rkey + 28);
    BT_xor256(point, state, rkey + 32);
    BT_xor256(state, point, rkey + 36);
    BT_xor256(point, state, rkey + 40);
    BT_xor256(state, point, rkey + 44);
    BT_xor256(point, state, rkey + 48);
    BT_xor256(state, point, rkey + 52);
    BT_xor256(point, state, rkey + 56);
    BT_xor256(state, point, rkey + 60);
    BT_xor256(point, state, rkey + 64);
    BT_xor256(state, point, rkey + 68);
    BT_add256(point, state, rkey + 72);
}

static __inline void basic_transform_512(Dstu7624Ctx *ctx, uint64_t *state)
{
    uint64_t point[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint64_t *rkey = ctx->p_rkeys;

    state[0] += rkey[0];
    state[1] += rkey[1];
    state[2] += rkey[2];
    state[3] += rkey[3];
    state[4] += rkey[4];
    state[5] += rkey[5];
    state[6] += rkey[6];
    state[7] += rkey[7];

    BT_xor512(state, point, &rkey[8]);
    BT_xor512(point, state, rkey + 16);
    BT_xor512(state, point, rkey + 24);
    BT_xor512(point, state, rkey + 32);
    BT_xor512(state, point, rkey + 40);
    BT_xor512(point, state, rkey + 48);
    BT_xor512(state, point, rkey + 56);
    BT_xor512(point, state, rkey + 64);
    BT_xor512(state, point, rkey + 72);
    BT_xor512(point, state, rkey + 80);
    BT_xor512(state, point, rkey + 88);
    BT_xor512(point, state, rkey + 96);
    BT_xor512(state, point, rkey + 104);
    BT_xor512(point, state, rkey + 112);
    BT_xor512(state, point, rkey + 120);
    BT_xor512(point, state, rkey + 128);
    BT_xor512(state, point, rkey + 136);
    BT_add512(point, state, rkey + 144);
}

static __inline void subrowcol128(uint64_t *state, Dstu7624Ctx *ctx)
{
    uint64_t point[2] = {0, 0};
    kalyna_G128(ctx->p_boxrowcol, state, point, 0, 0, 0, 0, 1, 1, 1, 1);
    memcpy(state, point, ctx->block_len);
}

static __inline void subrowcol256(uint64_t *state, Dstu7624Ctx *ctx)
{
    uint64_t point[4] = {0, 0, 0, 0};
    kalyna_G256(ctx->p_boxrowcol, state, point, 0, 0, 3, 3, 2, 2, 1, 1);
    memcpy(state, point, ctx->block_len);
}

static __inline void subrowcol512(uint64_t *state, Dstu7624Ctx *ctx)
{
    uint64_t point[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    kalyna_G512(ctx->p_boxrowcol, state, point, 0, 7, 6, 5, 4, 3, 2, 1);
    memcpy(state, point, ctx->block_len);
}

__inline static void inv_subrowcol_xor128(const uint64_t *state, uint64_t *out, const uint64_t *rkey,
        uint64_t boxrowcol[8][256])
{
    uint64_t s0 = state[0];
    uint64_t s1 = state[1];
    out[0] = rkey[0] ^
            boxrowcol[0][s0 & 255] ^
            boxrowcol[1][(s0 >> 8) & 255] ^
            boxrowcol[2][(s0 >> 16) & 255] ^
            boxrowcol[3][(s0 >> 24) & 255] ^
            boxrowcol[4][(s1 >> 32) & 255] ^
            boxrowcol[5][(s1 >> 40) & 255] ^
            boxrowcol[6][(s1 >> 48) & 255] ^
            boxrowcol[7][(s1 >> 56) & 255];
    out[1] = rkey[1] ^
            boxrowcol[0][s1 & 255] ^
            boxrowcol[1][(s1 >> 8) & 255] ^
            boxrowcol[2][(s1 >> 16) & 255] ^
            boxrowcol[3][(s1 >> 24) & 255] ^
            boxrowcol[4][(s0 >> 32) & 255] ^
            boxrowcol[5][(s0 >> 40) & 255] ^
            boxrowcol[6][(s0 >> 48) & 255] ^
            boxrowcol[7][(s0 >> 56) & 255];
}

__inline static void inv_subrowcol_xor256(const uint64_t *state, uint64_t *out, const uint64_t *rkey,
        uint64_t boxrowcol[8][256])
{
    uint64_t s0 = state[0];
    uint64_t s1 = state[1];
    uint64_t s2 = state[2];
    uint64_t s3 = state[3];
    out[0] = rkey[0] ^ boxrowcol[0][s0 & 255] ^
            boxrowcol[1][((s0 >> 8) & 255)] ^
            boxrowcol[2][((s1 >> 16) & 255)] ^
            boxrowcol[3][((s1 >> 24) & 255)] ^
            boxrowcol[4][((s2 >> 32) & 255)] ^
            boxrowcol[5][((s2 >> 40) & 255)] ^
            boxrowcol[6][((s3 >> 48) & 255)] ^
            boxrowcol[7][((s3 >> 56) & 255)];
    out[1] = rkey[1] ^ boxrowcol[0][s1 & 255] ^
            boxrowcol[1][((s1 >> 8) & 255)] ^
            boxrowcol[2][((s2 >> 16) & 255)] ^
            boxrowcol[3][((s2 >> 24) & 255)] ^
            boxrowcol[4][((s3 >> 32) & 255)] ^
            boxrowcol[5][((s3 >> 40) & 255)] ^
            boxrowcol[6][((s0 >> 48) & 255)] ^
            boxrowcol[7][((s0 >> 56) & 255)];
    out[2] = rkey[2] ^ boxrowcol[0][s2 & 255] ^
            boxrowcol[1][((s2 >> 8) & 255)] ^
            boxrowcol[2][((s3 >> 16) & 255)] ^
            boxrowcol[3][((s3 >> 24) & 255)] ^
            boxrowcol[4][((s0 >> 32) & 255)] ^
            boxrowcol[5][((s0 >> 40) & 255)] ^
            boxrowcol[6][((s1 >> 48) & 255)] ^
            boxrowcol[7][((s1 >> 56) & 255)];
    out[3] = rkey[3] ^ boxrowcol[0][s3 & 255] ^
            boxrowcol[1][((s3 >> 8) & 255)] ^
            boxrowcol[2][((s0 >> 16) & 255)] ^
            boxrowcol[3][((s0 >> 24) & 255)] ^
            boxrowcol[4][((s1 >> 32) & 255)] ^
            boxrowcol[5][((s1 >> 40) & 255)] ^
            boxrowcol[6][((s2 >> 48) & 255)] ^
            boxrowcol[7][((s2 >> 56) & 255)];
}

__inline static void inv_subrowcol_xor512(const uint64_t *state, uint64_t *out, const uint64_t *rkey,
        uint64_t boxrowcol[8][256])
{
    uint64_t s0 = state[0];
    uint64_t s1 = state[1];
    uint64_t s2 = state[2];
    uint64_t s3 = state[3];
    uint64_t s4 = state[4];
    uint64_t s5 = state[5];
    uint64_t s6 = state[6];
    uint64_t s7 = state[7];
    out[0] = rkey[0] ^ boxrowcol[0][s0 & 255] ^
            boxrowcol[1][((s1 >> 8) & 255)] ^
            boxrowcol[2][((s2 >> 16) & 255)] ^
            boxrowcol[3][((s3 >> 24) & 255)] ^
            boxrowcol[4][((s4 >> 32) & 255)] ^
            boxrowcol[5][((s5 >> 40) & 255)] ^
            boxrowcol[6][((s6 >> 48) & 255)] ^
            boxrowcol[7][((s7 >> 56) & 255)];
    out[1] = rkey[1] ^ boxrowcol[0][s1 & 255] ^
            boxrowcol[1][((s2 >> 8) & 255)] ^
            boxrowcol[2][((s3 >> 16) & 255)] ^
            boxrowcol[3][((s4 >> 24) & 255)] ^
            boxrowcol[4][((s5 >> 32) & 255)] ^
            boxrowcol[5][((s6 >> 40) & 255)] ^
            boxrowcol[6][((s7 >> 48) & 255)] ^
            boxrowcol[7][((s0 >> 56) & 255)];
    out[2] = rkey[2] ^ boxrowcol[0][s2 & 255] ^
            boxrowcol[1][((s3 >> 8) & 255)] ^
            boxrowcol[2][((s4 >> 16) & 255)] ^
            boxrowcol[3][((s5 >> 24) & 255)] ^
            boxrowcol[4][((s6 >> 32) & 255)] ^
            boxrowcol[5][((s7 >> 40) & 255)] ^
            boxrowcol[6][((s0 >> 48) & 255)] ^
            boxrowcol[7][((s1 >> 56) & 255)];
    out[3] = rkey[3] ^ boxrowcol[0][s3 & 255] ^
            boxrowcol[1][((s4 >> 8) & 255)] ^
            boxrowcol[2][((s5 >> 16) & 255)] ^
            boxrowcol[3][((s6 >> 24) & 255)] ^
            boxrowcol[4][((s7 >> 32) & 255)] ^
            boxrowcol[5][((s0 >> 40) & 255)] ^
            boxrowcol[6][((s1 >> 48) & 255)] ^
            boxrowcol[7][((s2 >> 56) & 255)];
    out[4] = rkey[4] ^ boxrowcol[0][s4 & 255] ^
            boxrowcol[1][((s5 >> 8) & 255)] ^
            boxrowcol[2][((s6 >> 16) & 255)] ^
            boxrowcol[3][((s7 >> 24) & 255)] ^
            boxrowcol[4][((s0 >> 32) & 255)] ^
            boxrowcol[5][((s1 >> 40) & 255)] ^
            boxrowcol[6][((s2 >> 48) & 255)] ^
            boxrowcol[7][((s3 >> 56) & 255)];
    out[5] = rkey[5] ^ boxrowcol[0][s5 & 255] ^
            boxrowcol[1][((s6 >> 8) & 255)] ^
            boxrowcol[2][((s7 >> 16) & 255)] ^
            boxrowcol[3][((s0 >> 24) & 255)] ^
            boxrowcol[4][((s1 >> 32) & 255)] ^
            boxrowcol[5][((s2 >> 40) & 255)] ^
            boxrowcol[6][((s3 >> 48) & 255)] ^
            boxrowcol[7][((s4 >> 56) & 255)];
    out[6] = rkey[6] ^ boxrowcol[0][s6 & 255 ] ^
            boxrowcol[1][((s7 >> 8) & 255)] ^
            boxrowcol[2][((s0 >> 16) & 255)] ^
            boxrowcol[3][((s1 >> 24) & 255)] ^
            boxrowcol[4][((s2 >> 32) & 255)] ^
            boxrowcol[5][((s3 >> 40) & 255)] ^
            boxrowcol[6][((s4 >> 48) & 255)] ^
            boxrowcol[7][((s5 >> 56) & 255)];
    out[7] = rkey[7] ^ boxrowcol[0][s7 & 255 ] ^
            boxrowcol[1][((s0 >> 8) & 255)] ^
            boxrowcol[2][((s1 >> 16) & 255)] ^
            boxrowcol[3][((s2 >> 24) & 255)] ^
            boxrowcol[4][((s3 >> 32) & 255)] ^
            boxrowcol[5][((s4 >> 40) & 255)] ^
            boxrowcol[6][((s5 >> 48) & 255)] ^
            boxrowcol[7][((s6 >> 56) & 255)];
}

static __inline void inv_subrowcol_sub(const uint64_t *state, uint64_t *out, const uint64_t *rkey, Dstu7624Ctx *ctx)
{
    size_t block_len = ctx->block_len;

    if (block_len == KALINA_128_BLOCK_LEN) {
        uint64_t s0 = state[0];
        uint64_t s1 = state[1];
        out[0] = ((uint64_t) (ctx->inv_s_blocks[0 * 256 + (s0 & 255)]) ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s0 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s0 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s0 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->inv_s_blocks[0 * 256 + ((s1 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s1 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s1 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s1 >> 56) & 255)]) << 56) - rkey[0];
        out[1] = ((uint64_t) (ctx->inv_s_blocks[0 * 256 + (s1 & 255)]) ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s1 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s1 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s1 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->inv_s_blocks[0 * 256 + ((s0 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s0 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s0 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s0 >> 56) & 255)]) << 56) - rkey[1];
    }
    if (block_len == KALINA_256_BLOCK_LEN) {
        uint64_t s0 = state[0];
        uint64_t s1 = state[1];
        uint64_t s2 = state[2];
        uint64_t s3 = state[3];
        out[0] = ((uint64_t) (ctx->inv_s_blocks[0 * 256 + (s0 & 255)]) ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s0 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s1 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s1 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->inv_s_blocks[0 * 256 + ((s2 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s2 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s3 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s3 >> 56) & 255)]) << 56) - rkey[0];
        out[1] = ((uint64_t) (ctx->inv_s_blocks[0 * 256 + (s1 & 255)]) ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s1 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s2 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s2 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->inv_s_blocks[0 * 256 + ((s3 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s3 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s0 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s0 >> 56) & 255)]) << 56) - rkey[1];
        out[2] = ((uint64_t) (ctx->inv_s_blocks[0 * 256 + (s2 & 255)]) ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s2 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s3 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s3 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->inv_s_blocks[0 * 256 + ((s0 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s0 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s1 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s1 >> 56) & 255)]) << 56) - rkey[2];
        out[3] = ((uint64_t) (ctx->inv_s_blocks[0 * 256 + (s3 & 255)]) ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s3 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s0 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s0 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->inv_s_blocks[0 * 256 + ((s1 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s1 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s2 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s2 >> 56) & 255)]) << 56) - rkey[3];
    }
    if (block_len == KALINA_512_BLOCK_LEN) {
        uint64_t s0 = state[0];
        uint64_t s1 = state[1];
        uint64_t s2 = state[2];
        uint64_t s3 = state[3];
        uint64_t s4 = state[4];
        uint64_t s5 = state[5];
        uint64_t s6 = state[6];
        uint64_t s7 = state[7];
        out[0] = ((uint64_t) (ctx->inv_s_blocks[0 * 256 + (s0 & 255)]) ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s1 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s2 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s3 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->inv_s_blocks[0 * 256 + ((s4 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s5 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s6 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s7 >> 56) & 255)]) << 56) - rkey[0];
        out[1] = ((uint64_t) (ctx->inv_s_blocks[0 * 256 + (s1 & 255)]) ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s2 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s3 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s4 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->inv_s_blocks[0 * 256 + ((s5 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s6 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s7 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s0 >> 56) & 255)]) << 56) - rkey[1];
        out[2] = ((uint64_t) (ctx->inv_s_blocks[0 * 256 + (s2 & 255)]) ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s3 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s4 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s5 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->inv_s_blocks[0 * 256 + ((s6 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s7 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s0 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s1 >> 56) & 255)]) << 56) - rkey[2];
        out[3] = ((uint64_t) (ctx->inv_s_blocks[0 * 256 + (s3 & 255)]) ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s4 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s5 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s6 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->inv_s_blocks[0 * 256 + ((s7 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s0 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s1 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s2 >> 56) & 255)]) << 56) - rkey[3];
        out[4] = ((uint64_t) (ctx->inv_s_blocks[0 * 256 + (s4 & 255)]) ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s5 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s6 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s7 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->inv_s_blocks[0 * 256 + ((s0 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s1 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s2 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s3 >> 56) & 255)]) << 56) - rkey[4];
        out[5] = ((uint64_t) (ctx->inv_s_blocks[0 * 256 + (s5 & 255)]) ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s6 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s7 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s0 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->inv_s_blocks[0 * 256 + ((s1 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s2 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s3 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s4 >> 56) & 255)]) << 56) - rkey[5];
        out[6] = ((uint64_t) (ctx->inv_s_blocks[0 * 256 + (s6 & 255)]) ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s7 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s0 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s1 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->inv_s_blocks[0 * 256 + ((s2 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s3 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s4 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s5 >> 56) & 255)]) << 56) - rkey[6];
        out[7] = ((uint64_t) (ctx->inv_s_blocks[0 * 256 + (s7 & 255)]) ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s0 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s1 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s2 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->inv_s_blocks[0 * 256 + ((s3 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->inv_s_blocks[1 * 256 + ((s4 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->inv_s_blocks[2 * 256 + ((s5 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->inv_s_blocks[3 * 256 + ((s6 >> 56) & 255)]) << 56) - rkey[7];
    }
}

static __inline void invert_state(uint64_t *state, Dstu7624Ctx *ctx)
{
    size_t block_len = ctx->block_len;
    uint8_t *s_blocks = ctx->s_blocks;

    if (block_len == KALINA_128_BLOCK_LEN) {
        state[0] = ctx->p_inv_boxrowcol[0][s_blocks[0 * 256 + (state[0] & 0xFF)]] ^
                ctx->p_inv_boxrowcol[1][s_blocks[1 * 256 + ((state[0] >> 8) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[2][s_blocks[2 * 256 + ((state[0] >> 16) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[3][s_blocks[3 * 256 + ((state[0] >> 24) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[4][s_blocks[0 * 256 + ((state[0] >> 32) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[5][s_blocks[1 * 256 + ((state[0] >> 40) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[6][s_blocks[2 * 256 + ((state[0] >> 48) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[7][s_blocks[3 * 256 + ((state[0] >> 56) & 0xFF)]];
        state[1] = ctx->p_inv_boxrowcol[0][s_blocks[0 * 256 + (state[1] & 0xFF)]] ^
                ctx->p_inv_boxrowcol[1][s_blocks[1 * 256 + ((state[1] >> 8) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[2][s_blocks[2 * 256 + ((state[1] >> 16) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[3][s_blocks[3 * 256 + ((state[1] >> 24) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[4][s_blocks[0 * 256 + ((state[1] >> 32) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[5][s_blocks[1 * 256 + ((state[1] >> 40) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[6][s_blocks[2 * 256 + ((state[1] >> 48) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[7][s_blocks[3 * 256 + ((state[1] >> 56) & 0xFF)]];
    }
    if (block_len == KALINA_256_BLOCK_LEN) {
        state[0] = ctx->p_inv_boxrowcol[0][s_blocks[0 * 256 + (state[0] & 0xFF)]] ^
                ctx->p_inv_boxrowcol[1][s_blocks[1 * 256 + ((state[0] >> 8) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[2][s_blocks[2 * 256 + ((state[0] >> 16) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[3][s_blocks[3 * 256 + ((state[0] >> 24) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[4][s_blocks[0 * 256 + ((state[0] >> 32) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[5][s_blocks[1 * 256 + ((state[0] >> 40) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[6][s_blocks[2 * 256 + ((state[0] >> 48) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[7][s_blocks[3 * 256 + ((state[0] >> 56) & 0xFF)]];
        state[1] = ctx->p_inv_boxrowcol[0][s_blocks[0 * 256 + (state[1] & 0xFF)]] ^
                ctx->p_inv_boxrowcol[1][s_blocks[1 * 256 + ((state[1] >> 8) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[2][s_blocks[2 * 256 + ((state[1] >> 16) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[3][s_blocks[3 * 256 + ((state[1] >> 24) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[4][s_blocks[0 * 256 + ((state[1] >> 32) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[5][s_blocks[1 * 256 + ((state[1] >> 40) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[6][s_blocks[2 * 256 + ((state[1] >> 48) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[7][s_blocks[3 * 256 + ((state[1] >> 56) & 0xFF)]];
        state[2] = ctx->p_inv_boxrowcol[0][s_blocks[0 * 256 + (state[2] & 0xFF)]] ^
                ctx->p_inv_boxrowcol[1][s_blocks[1 * 256 + ((state[2] >> 8) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[2][s_blocks[2 * 256 + ((state[2] >> 16) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[3][s_blocks[3 * 256 + ((state[2] >> 24) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[4][s_blocks[0 * 256 + ((state[2] >> 32) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[5][s_blocks[1 * 256 + ((state[2] >> 40) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[6][s_blocks[2 * 256 + ((state[2] >> 48) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[7][s_blocks[3 * 256 + ((state[2] >> 56) & 0xFF)]];
        state[3] = ctx->p_inv_boxrowcol[0][s_blocks[0 * 256 + (state[3] & 0xFF)]] ^
                ctx->p_inv_boxrowcol[1][s_blocks[1 * 256 + ((state[3] >> 8) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[2][s_blocks[2 * 256 + ((state[3] >> 16) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[3][s_blocks[3 * 256 + ((state[3] >> 24) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[4][s_blocks[0 * 256 + ((state[3] >> 32) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[5][s_blocks[1 * 256 + ((state[3] >> 40) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[6][s_blocks[2 * 256 + ((state[3] >> 48) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[7][s_blocks[3 * 256 + ((state[3] >> 56) & 0xFF)]];
    }
    if (block_len == KALINA_512_BLOCK_LEN) {
        state[0] = ctx->p_inv_boxrowcol[0][s_blocks[0 * 256 + (state[0] & 0xFF)]] ^
                ctx->p_inv_boxrowcol[1][s_blocks[1 * 256 + ((state[0] >> 8) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[2][s_blocks[2 * 256 + ((state[0] >> 16) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[3][s_blocks[3 * 256 + ((state[0] >> 24) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[4][s_blocks[0 * 256 + ((state[0] >> 32) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[5][s_blocks[1 * 256 + ((state[0] >> 40) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[6][s_blocks[2 * 256 + ((state[0] >> 48) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[7][s_blocks[3 * 256 + ((state[0] >> 56) & 0xFF)]];
        state[1] = ctx->p_inv_boxrowcol[0][s_blocks[0 * 256 + (state[1] & 0xFF)]] ^
                ctx->p_inv_boxrowcol[1][s_blocks[1 * 256 + ((state[1] >> 8) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[2][s_blocks[2 * 256 + ((state[1] >> 16) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[3][s_blocks[3 * 256 + ((state[1] >> 24) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[4][s_blocks[0 * 256 + ((state[1] >> 32) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[5][s_blocks[1 * 256 + ((state[1] >> 40) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[6][s_blocks[2 * 256 + ((state[1] >> 48) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[7][s_blocks[3 * 256 + ((state[1] >> 56) & 0xFF)]];
        state[2] = ctx->p_inv_boxrowcol[0][s_blocks[0 * 256 + (state[2] & 0xFF)]] ^
                ctx->p_inv_boxrowcol[1][s_blocks[1 * 256 + ((state[2] >> 8) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[2][s_blocks[2 * 256 + ((state[2] >> 16) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[3][s_blocks[3 * 256 + ((state[2] >> 24) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[4][s_blocks[0 * 256 + ((state[2] >> 32) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[5][s_blocks[1 * 256 + ((state[2] >> 40) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[6][s_blocks[2 * 256 + ((state[2] >> 48) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[7][s_blocks[3 * 256 + ((state[2] >> 56) & 0xFF)]];
        state[3] = ctx->p_inv_boxrowcol[0][s_blocks[0 * 256 + (state[3] & 0xFF)]] ^
                ctx->p_inv_boxrowcol[1][s_blocks[1 * 256 + ((state[3] >> 8) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[2][s_blocks[2 * 256 + ((state[3] >> 16) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[3][s_blocks[3 * 256 + ((state[3] >> 24) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[4][s_blocks[0 * 256 + ((state[3] >> 32) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[5][s_blocks[1 * 256 + ((state[3] >> 40) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[6][s_blocks[2 * 256 + ((state[3] >> 48) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[7][s_blocks[3 * 256 + ((state[3] >> 56) & 0xFF)]];
        state[4] = ctx->p_inv_boxrowcol[0][s_blocks[0 * 256 + (state[4] & 0xFF)]] ^
                ctx->p_inv_boxrowcol[1][s_blocks[1 * 256 + ((state[4] >> 8) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[2][s_blocks[2 * 256 + ((state[4] >> 16) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[3][s_blocks[3 * 256 + ((state[4] >> 24) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[4][s_blocks[0 * 256 + ((state[4] >> 32) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[5][s_blocks[1 * 256 + ((state[4] >> 40) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[6][s_blocks[2 * 256 + ((state[4] >> 48) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[7][s_blocks[3 * 256 + ((state[4] >> 56) & 0xFF)]];
        state[5] = ctx->p_inv_boxrowcol[0][s_blocks[0 * 256 + (state[5] & 0xFF)]] ^
                ctx->p_inv_boxrowcol[1][s_blocks[1 * 256 + ((state[5] >> 8) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[2][s_blocks[2 * 256 + ((state[5] >> 16) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[3][s_blocks[3 * 256 + ((state[5] >> 24) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[4][s_blocks[0 * 256 + ((state[5] >> 32) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[5][s_blocks[1 * 256 + ((state[5] >> 40) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[6][s_blocks[2 * 256 + ((state[5] >> 48) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[7][s_blocks[3 * 256 + ((state[5] >> 56) & 0xFF)]];
        state[6] = ctx->p_inv_boxrowcol[0][s_blocks[0 * 256 + (state[6] & 0xFF)]] ^
                ctx->p_inv_boxrowcol[1][s_blocks[1 * 256 + ((state[6] >> 8) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[2][s_blocks[2 * 256 + ((state[6] >> 16) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[3][s_blocks[3 * 256 + ((state[6] >> 24) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[4][s_blocks[0 * 256 + ((state[6] >> 32) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[5][s_blocks[1 * 256 + ((state[6] >> 40) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[6][s_blocks[2 * 256 + ((state[6] >> 48) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[7][s_blocks[3 * 256 + ((state[6] >> 56) & 0xFF)]];
        state[7] = ctx->p_inv_boxrowcol[0][s_blocks[0 * 256 + (state[7] & 0xFF)]] ^
                ctx->p_inv_boxrowcol[1][s_blocks[1 * 256 + ((state[7] >> 8) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[2][s_blocks[2 * 256 + ((state[7] >> 16) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[3][s_blocks[3 * 256 + ((state[7] >> 24) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[4][s_blocks[0 * 256 + ((state[7] >> 32) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[5][s_blocks[1 * 256 + ((state[7] >> 40) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[6][s_blocks[2 * 256 + ((state[7] >> 48) & 0xFF)]] ^
                ctx->p_inv_boxrowcol[7][s_blocks[3 * 256 + ((state[7] >> 56) & 0xFF)]];
    }
}

static void reverse_rkey(uint64_t *rkey, Dstu7624Ctx *ctx)
{
    size_t block_len = ctx->block_len;
    size_t key_len  = ctx->key_len;

    if (block_len == KALINA_128_BLOCK_LEN && key_len == KALINA_128_KEY_LEN) {
        invert_state(&rkey[18], ctx);
        invert_state(&rkey[16], ctx);
        invert_state(&rkey[14], ctx);
        invert_state(&rkey[12], ctx);
        invert_state(&rkey[10], ctx);
        invert_state(&rkey[8], ctx);
        invert_state(&rkey[6], ctx);
        invert_state(&rkey[4], ctx);
        invert_state(&rkey[2], ctx);
    }
    if (block_len == KALINA_128_BLOCK_LEN && key_len == KALINA_256_KEY_LEN) {
        invert_state(&rkey[26], ctx);
        invert_state(&rkey[24], ctx);
        invert_state(&rkey[22], ctx);
        invert_state(&rkey[20], ctx);
        invert_state(&rkey[18], ctx);
        invert_state(&rkey[16], ctx);
        invert_state(&rkey[14], ctx);
        invert_state(&rkey[12], ctx);
        invert_state(&rkey[10], ctx);
        invert_state(&rkey[8], ctx);
        invert_state(&rkey[6], ctx);
        invert_state(&rkey[4], ctx);
        invert_state(&rkey[2], ctx);
    }
    if (block_len == KALINA_256_BLOCK_LEN && key_len == KALINA_256_KEY_LEN) {
        invert_state(&rkey[52], ctx);
        invert_state(&rkey[48], ctx);
        invert_state(&rkey[44], ctx);
        invert_state(&rkey[40], ctx);
        invert_state(&rkey[36], ctx);
        invert_state(&rkey[32], ctx);
        invert_state(&rkey[28], ctx);
        invert_state(&rkey[24], ctx);
        invert_state(&rkey[20], ctx);
        invert_state(&rkey[16], ctx);
        invert_state(&rkey[12], ctx);
        invert_state(&rkey[8], ctx);
        invert_state(&rkey[4], ctx);
    }
    if (block_len == KALINA_256_BLOCK_LEN && key_len == KALINA_512_KEY_LEN) {
        invert_state(&rkey[68], ctx);
        invert_state(&rkey[64], ctx);
        invert_state(&rkey[60], ctx);
        invert_state(&rkey[56], ctx);
        invert_state(&rkey[52], ctx);
        invert_state(&rkey[48], ctx);
        invert_state(&rkey[44], ctx);
        invert_state(&rkey[40], ctx);
        invert_state(&rkey[36], ctx);
        invert_state(&rkey[32], ctx);
        invert_state(&rkey[28], ctx);
        invert_state(&rkey[24], ctx);
        invert_state(&rkey[20], ctx);
        invert_state(&rkey[16], ctx);
        invert_state(&rkey[12], ctx);
        invert_state(&rkey[8], ctx);
        invert_state(&rkey[4], ctx);
    }
    if (block_len == KALINA_512_BLOCK_LEN && key_len == KALINA_512_KEY_LEN) {
        invert_state(&rkey[136], ctx);
        invert_state(&rkey[128], ctx);
        invert_state(&rkey[120], ctx);
        invert_state(&rkey[112], ctx);
        invert_state(&rkey[104], ctx);
        invert_state(&rkey[96], ctx);
        invert_state(&rkey[88], ctx);
        invert_state(&rkey[80], ctx);
        invert_state(&rkey[72], ctx);
        invert_state(&rkey[64], ctx);
        invert_state(&rkey[56], ctx);
        invert_state(&rkey[48], ctx);
        invert_state(&rkey[40], ctx);
        invert_state(&rkey[32], ctx);
        invert_state(&rkey[24], ctx);
        invert_state(&rkey[16], ctx);
        invert_state(&rkey[8], ctx);
    }
}

static __inline void subrowcol128_dec(Dstu7624Ctx *ctx, uint64_t *state)
{
    uint64_t point[2];
    uint64_t *rkey = ctx->p_rkeys_rev;

    state[0] -= rkey[20];
    state[1] -= rkey[21];

    state[0] = ctx->p_inv_boxrowcol[0][ctx->s_blocks[0 * 256 + (uint8_t) state[0]]] ^
            ctx->p_inv_boxrowcol[1][ctx->s_blocks[1 * 256 + (uint8_t) (state[0] >> 8)]] ^
            ctx->p_inv_boxrowcol[2][ctx->s_blocks[2 * 256 + (uint8_t) (state[0] >> 16)]] ^
            ctx->p_inv_boxrowcol[3][ctx->s_blocks[3 * 256 + (uint8_t) (state[0] >> 24)]] ^
            ctx->p_inv_boxrowcol[4][ctx->s_blocks[0 * 256 + (uint8_t) (state[0] >> 32)]] ^
            ctx->p_inv_boxrowcol[5][ctx->s_blocks[1 * 256 + (uint8_t) (state[0] >> 40)]] ^
            ctx->p_inv_boxrowcol[6][ctx->s_blocks[2 * 256 + (uint8_t) (state[0] >> 48)]] ^
            ctx->p_inv_boxrowcol[7][ctx->s_blocks[3 * 256 + (uint8_t) (state[0] >> 56)]];
    state[1] = ctx->p_inv_boxrowcol[0][ctx->s_blocks[0 * 256 + (uint8_t) state[1]]] ^
            ctx->p_inv_boxrowcol[1][ctx->s_blocks[1 * 256 + (uint8_t) (state[1] >> 8)]] ^
            ctx->p_inv_boxrowcol[2][ctx->s_blocks[2 * 256 + (uint8_t) (state[1] >> 16)]] ^
            ctx->p_inv_boxrowcol[3][ctx->s_blocks[3 * 256 + (uint8_t) (state[1] >> 24)]] ^
            ctx->p_inv_boxrowcol[4][ctx->s_blocks[0 * 256 + (uint8_t) (state[1] >> 32)]] ^
            ctx->p_inv_boxrowcol[5][ctx->s_blocks[1 * 256 + (uint8_t) (state[1] >> 40)]] ^
            ctx->p_inv_boxrowcol[6][ctx->s_blocks[2 * 256 + (uint8_t) (state[1] >> 48)]] ^
            ctx->p_inv_boxrowcol[7][ctx->s_blocks[3 * 256 + (uint8_t) (state[1] >> 56)]];

    inv_subrowcol_xor128(state, point, &rkey[18], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor128(point, state, &rkey[16], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor128(state, point, &rkey[14], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor128(point, state, &rkey[12], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor128(state, point, &rkey[10], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor128(point, state, &rkey[8], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor128(state, point, &rkey[6], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor128(point, state, &rkey[4], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor128(state, point, &rkey[2], ctx->p_inv_boxrowcol);

    state[0] = ((uint64_t) (ctx->inv_s_blocks[0 * 256 + (uint8_t) point[0]]) ^
            (uint64_t) (ctx->inv_s_blocks[1 * 256 + (uint8_t) (point[0] >> 8)]) << 8 ^
            (uint64_t) (ctx->inv_s_blocks[2 * 256 + (uint8_t) (point[0] >> 16)]) << 16 ^
            (uint64_t) (ctx->inv_s_blocks[3 * 256 + (uint8_t) (point[0] >> 24)]) << 24 ^
            (uint64_t) (ctx->inv_s_blocks[0 * 256 + (uint8_t) (point[1] >> 32)]) << 32 ^
            (uint64_t) (ctx->inv_s_blocks[1 * 256 + (uint8_t) (point[1] >> 40)]) << 40 ^
            (uint64_t) (ctx->inv_s_blocks[2 * 256 + (uint8_t) (point[1] >> 48)]) << 48 ^
            (uint64_t) (ctx->inv_s_blocks[3 * 256 + (uint8_t) (point[1] >> 56)]) << 56) -
            rkey[0];
    state[1] = ((uint64_t) (ctx->inv_s_blocks[0 * 256 + (uint8_t) point[1]]) ^
            (uint64_t) (ctx->inv_s_blocks[1 * 256 + (uint8_t) (point[1] >> 8)]) << 8 ^
            (uint64_t) (ctx->inv_s_blocks[2 * 256 + (uint8_t) (point[1] >> 16)]) << 16 ^
            (uint64_t) (ctx->inv_s_blocks[3 * 256 + (uint8_t) (point[1] >> 24)]) << 24 ^
            (uint64_t) (ctx->inv_s_blocks[0 * 256 + (uint8_t) (point[0] >> 32)]) << 32 ^
            (uint64_t) (ctx->inv_s_blocks[1 * 256 + (uint8_t) (point[0] >> 40)]) << 40 ^
            (uint64_t) (ctx->inv_s_blocks[2 * 256 + (uint8_t) (point[0] >> 48)]) << 48 ^
            (uint64_t) (ctx->inv_s_blocks[3 * 256 + (uint8_t) (point[0] >> 56)]) << 56) -
            rkey[1];
}

static __inline void subrowcol128_256_dec(Dstu7624Ctx *ctx, uint64_t *state)
{
    uint64_t point[2];
    uint64_t *rkey = ctx->p_rkeys_rev;

    state[0] -= rkey[28];
    state[1] -= rkey[29];

    invert_state(state, ctx);
    inv_subrowcol_xor128(state, point, &rkey[26], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor128(point, state, &rkey[24], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor128(state, point, &rkey[22], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor128(point, state, &rkey[20], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor128(state, point, &rkey[18], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor128(point, state, &rkey[16], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor128(state, point, &rkey[14], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor128(point, state, &rkey[12], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor128(state, point, &rkey[10], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor128(point, state, &rkey[8], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor128(state, point, &rkey[6], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor128(point, state, &rkey[4], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor128(state, point, &rkey[2], ctx->p_inv_boxrowcol);
    inv_subrowcol_sub(point, state, &rkey[0], ctx);
}

static __inline void subrowcol256_dec(Dstu7624Ctx *ctx, uint64_t *state)
{
    uint64_t point[4];
    uint64_t *rkey = ctx->p_rkeys_rev;

    state[0] -= rkey[56];
    state[1] -= rkey[57];
    state[2] -= rkey[58];
    state[3] -= rkey[59];

    invert_state(state, ctx);
    inv_subrowcol_xor256(state, point, &rkey[52], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(point, state, &rkey[48], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(state, point, &rkey[44], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(point, state, &rkey[40], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(state, point, &rkey[36], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(point, state, &rkey[32], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(state, point, &rkey[28], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(point, state, &rkey[24], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(state, point, &rkey[20], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(point, state, &rkey[16], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(state, point, &rkey[12], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(point, state, &rkey[8], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(state, point, &rkey[4], ctx->p_inv_boxrowcol);
    inv_subrowcol_sub(point, state, &rkey[0], ctx);
}

static __inline void subrowcol256_512_dec(Dstu7624Ctx *ctx, uint64_t *state)
{

    uint64_t point[4];
    uint64_t *rkey = ctx->p_rkeys_rev;

    state[0] -= rkey[72];
    state[1] -= rkey[73];
    state[2] -= rkey[74];
    state[3] -= rkey[75];

    invert_state(state, ctx);
    inv_subrowcol_xor256(state, point, &rkey[68], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(point, state, &rkey[64], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(state, point, &rkey[60], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(point, state, &rkey[56], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(state, point, &rkey[52], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(point, state, &rkey[48], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(state, point, &rkey[44], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(point, state, &rkey[40], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(state, point, &rkey[36], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(point, state, &rkey[32], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(state, point, &rkey[28], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(point, state, &rkey[24], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(state, point, &rkey[20], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(point, state, &rkey[16], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(state, point, &rkey[12], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(point, state, &rkey[8], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor256(state, point, &rkey[4], ctx->p_inv_boxrowcol);
    inv_subrowcol_sub(point, state, &rkey[0], ctx);
}

static __inline void subrowcol512_dec(Dstu7624Ctx *ctx, uint64_t *state)
{
    uint64_t point[8];
    uint64_t *rkey = ctx->p_rkeys_rev;

    state[0] -= rkey[144];
    state[1] -= rkey[145];
    state[2] -= rkey[146];
    state[3] -= rkey[147];
    state[4] -= rkey[148];
    state[5] -= rkey[149];
    state[6] -= rkey[150];
    state[7] -= rkey[151];

    invert_state(state, ctx);
    inv_subrowcol_xor512(state, point, &rkey[136], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor512(point, state, &rkey[128], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor512(state, point, &rkey[120], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor512(point, state, &rkey[112], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor512(state, point, &rkey[104], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor512(point, state, &rkey[96], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor512(state, point, &rkey[88], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor512(point, state, &rkey[80], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor512(state, point, &rkey[72], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor512(point, state, &rkey[64], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor512(state, point, &rkey[56], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor512(point, state, &rkey[48], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor512(state, point, &rkey[40], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor512(point, state, &rkey[32], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor512(state, point, &rkey[24], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor512(point, state, &rkey[16], ctx->p_inv_boxrowcol);
    inv_subrowcol_xor512(state, point, &rkey[8], ctx->p_inv_boxrowcol);
    inv_subrowcol_sub(point, state, &rkey[0], ctx);
}

static int precomputed_rkeys(Dstu7624Ctx *ctx, uint64_t *precompute_keyshifts, uint64_t *p_hrkey)
{
    uint8_t swap[64];
    uint8_t id8[64];
    uint64_t id64[8];
    uint64_t rkey[8];
    uint8_t tmp[64] = {0};
    size_t i = 0, j = 0;
    size_t shift;
    size_t key_len;
    size_t wblock_len;
    size_t block_len;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(precompute_keyshifts != NULL);
    CHECK_PARAM(p_hrkey != NULL);

    block_len = ctx->block_len;
    key_len = ctx->key_len >> 3;
    wblock_len = block_len >> 3;
    memset(id8, 0, block_len);

    /*Вычисляем четные раундовые ключи.*/
    for (i = 0; i <= ctx->rounds >> 1; i++) {
        for (j = 0; j < block_len; j++) {
            shift = ((size_t)1 << i) >> 8;
            if (shift > 0) {
                j++;
                id8[j] = (uint8_t) (1 << (shift - 1));
            } else {
                id8[j] = (uint8_t) (1 << i);
                j++;
            }
        }

        DO(uint8_to_uint64(id8, block_len, id64, wblock_len));

        memcpy(&ctx->p_rkeys[i * (wblock_len * 2)], p_hrkey, block_len);
        kalyna_add(id64, &ctx->p_rkeys[i * (wblock_len * 2)], wblock_len);
        memcpy(rkey, &ctx->p_rkeys[i * (wblock_len * 2)], block_len);
        kalyna_add(&precompute_keyshifts[i * key_len], &ctx->p_rkeys[i * (wblock_len * 2)], wblock_len);
        sub_shift_mix_xor(rkey, &ctx->p_rkeys[i * (wblock_len * 2)], ctx);
        sub_shift_mix_add(rkey, &ctx->p_rkeys[i * (wblock_len * 2)], ctx);

        memset(id8, 0, block_len);
    }

    shift = block_len - (block_len / 4 + 3);
    /*Вычисляем нечетные раундовые ключи путем смещения четных*/
    for (i = 0; i < ctx->rounds; i += 2) {
        DO(uint64_to_uint8(&ctx->p_rkeys[(i * wblock_len)], block_len >> 3, swap, block_len));
        for (j = 0; j < block_len; j++) {

            tmp[(j + shift) % block_len] = swap[j];
        }
        DO(uint8_to_uint64(tmp, block_len, &ctx->p_rkeys[(i + 1) * wblock_len], block_len >> 3));
    }

cleanup:

    return ret;
}

static int p_help_round_key(const ByteArray *key, Dstu7624Ctx *ctx, uint64_t *hrkey)
{
    uint64_t *key64 = NULL;
    int ret = RET_OK;
    size_t key64_len = 0;
    size_t block64_len;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(hrkey != NULL);

    DO(ba_to_uint64_with_alloc(key, &key64, &key64_len));
    block64_len = ctx->block_len >> 3;

    if (ctx->block_len == ctx->key_len) {
        kalyna_add(key64, hrkey, block64_len);
        sub_shift_mix_xor(key64, hrkey, ctx);
        sub_shift_mix_add(key64, hrkey, ctx);
        ctx->subrowcol(hrkey, ctx);
    } else {
        kalyna_add(key64, hrkey, (ctx->block_len >> 3));
        sub_shift_mix_xor((key64 + (ctx->block_len >> 3)), hrkey, ctx);
        sub_shift_mix_add(key64, hrkey, ctx);
        ctx->subrowcol(hrkey, ctx);
    }

cleanup:

    if (key64) {
        memset(key64, 0, key64_len * sizeof(uint64_t));
    }
    free(key64);

    return ret;
}

/*Функция для обчислення зсуву таємного ключа.*/
static int p_key_shift(const uint8_t *key, Dstu7624Ctx *ctx, uint64_t **key_shifts)
{
    uint8_t *key_shift;
    uint8_t *key_shift_ptr = NULL;
    size_t i, j = 0;
    size_t shift_key_size = 0;
    size_t shift;
    size_t key_len;
    size_t block_len;
    int ret = RET_OK;

    CHECK_PARAM(key != NULL);
    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key_shifts != NULL);

    block_len = ctx->block_len;
    key_len = ctx->key_len;
    shift_key_size = key_len * ((ctx->rounds >> 1) + 1);

    MALLOC_CHECKED(key_shift, shift_key_size);
    key_shift_ptr = key_shift;
    memset(key_shift, 0, shift_key_size);

    MALLOC_CHECKED(*key_shifts, shift_key_size);

    if (block_len == key_len) {
        for (i = 0; i <= ctx->rounds >> 1; ++i) {
            for (j = 0; j < key_len; ++j) {
                shift = 56 * i;
                key_shift[(j + shift) % key_len] = key[j];
            }
            key_shift += key_len;
        }
    } else {
        for (i = 0; i <= ctx->rounds >> 1; ++i) {
            for (j = 0; j < key_len; ++j) {
                if (i % 2 == 0) {
                    shift = 60 * i;
                    key_shift[(j + shift) % key_len] = key[j];
                } else {
                    if (key_len == KALINA_256_KEY_LEN) {
                        shift = 48 - ((i >> 1) << 3);
                    } else {
                        shift = 96 - ((i >> 1) << 3);
                    }
                    key_shift[(j + shift) % key_len] = key[j];
                }
            }
            key_shift += key_len;
        }
    }

    DO(uint8_to_uint64(key_shift_ptr, shift_key_size, *key_shifts, shift_key_size >> 3));

cleanup:

    if (key_shift_ptr) {
        memset(key_shift_ptr, 0, shift_key_size);
    }
    free(key_shift_ptr);

    return ret;
}

static int dstu7624_init(Dstu7624Ctx *ctx, const ByteArray *key, const size_t block_size)
{
    const uint8_t *key_buf = NULL;
    uint64_t *p_hrkey = NULL;
    uint64_t *p_key_shifts = NULL;
    size_t key_buf_len = 0;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(block_size == KALINA_128_BLOCK_LEN || block_size == KALINA_256_BLOCK_LEN || 
        block_size == KALINA_512_BLOCK_LEN);

    gf2m_free(ctx->mode.gmac.gf2m_ctx);
    ctx->mode.gmac.gf2m_ctx = NULL;

    key_buf = key->buf;
    key_buf_len = key->len;

    CHECK_PARAM(key_buf_len == KALINA_128_KEY_LEN || key_buf_len == KALINA_256_KEY_LEN
            || key_buf_len == KALINA_512_KEY_LEN);

    MALLOC_CHECKED(p_hrkey, key_buf_len);
    memset(p_hrkey, 0, key_buf_len);

    /*Ініціалізація початкових даних ДСТУ7624 у відповідності з розміром блока та ключа.*/
    if (key_buf_len == KALINA_128_KEY_LEN && block_size == KALINA_128_BLOCK_LEN) {
        p_hrkey[0] = 0x05;
        ctx->subrowcol = subrowcol128; // операція швидкого обчислення s_blocks, srow, mcol
        ctx->basic_transform = basic_transform_128; // операція базового перетворення
        ctx->subrowcol_dec = subrowcol128_dec; // операція зворотнього базового перетворення
        ctx->rounds = 10; // кількість раундів для генерування раундового ключа
    } else if (key_buf_len == KALINA_256_KEY_LEN && block_size == KALINA_128_BLOCK_LEN) {
        p_hrkey[0] = 0x07;
        ctx->subrowcol = subrowcol128;
        ctx->basic_transform = basic_transform_128_256;
        ctx->subrowcol_dec = subrowcol128_256_dec;
        ctx->rounds = 14;
    } else if (key_buf_len == KALINA_256_KEY_LEN && block_size == KALINA_256_BLOCK_LEN) {
        p_hrkey[0] = 0x09;
        ctx->subrowcol = subrowcol256;
        ctx->basic_transform = basic_transform_256;
        ctx->subrowcol_dec = subrowcol256_dec;
        ctx->rounds = 14;
    } else if (key_buf_len == KALINA_512_KEY_LEN && block_size == KALINA_256_BLOCK_LEN) {
        p_hrkey[0] = 0x0D;
        ctx->subrowcol = subrowcol256;
        ctx->basic_transform = basic_transform_256_512;
        ctx->subrowcol_dec = subrowcol256_512_dec;
        ctx->rounds = 18;
    } else if (key_buf_len == KALINA_512_KEY_LEN && block_size == KALINA_512_BLOCK_LEN) {
        p_hrkey[0] = 0x11;
        ctx->subrowcol = subrowcol512;
        ctx->basic_transform = basic_transform_512;
        ctx->subrowcol_dec = subrowcol512_dec;
        ctx->rounds = 18;
    } else {
        SET_ERROR(RET_INVALID_PARAM);
    }

    ctx->key_len = key_buf_len;
    memset(ctx->state, 0, MAX_BLOCK_LEN);
    ctx->block_len = block_size;

    DO(p_key_shift(key_buf, ctx, &p_key_shifts));
    DO(p_help_round_key(key, ctx, p_hrkey));
    DO(precomputed_rkeys(ctx, p_key_shifts, p_hrkey));

    memcpy(&ctx->p_rkeys_rev[0], &ctx->p_rkeys[0], MAX_BLOCK_LEN * 20);
    reverse_rkey(ctx->p_rkeys_rev, ctx);

cleanup:

    if (p_hrkey) {
        secure_zero(p_hrkey, key_buf_len);
    }
    free(p_hrkey);

    if (p_key_shifts) {
        secure_zero(p_key_shifts, key_buf_len * ((ctx->rounds >> 1) + 1));
    }
    free(p_key_shifts);

    return ret;
}

static __inline void decrypt_basic_transform(Dstu7624Ctx *ctx, const uint8_t *cipher_data, uint8_t *plain_data)
{
    uint64_t block[8];

    uint8_to_uint64(cipher_data, ctx->block_len, block, ctx->block_len >> 3);
    ctx->subrowcol_dec(ctx, block);
    uint64_to_uint8(block, ctx->block_len >> 3, plain_data, ctx->block_len);
}

static uint8_t padding(Dstu7624Ctx *ctx, uint8_t *plain_data, size_t *data_size_byte, uint8_t *padded)
{
    size_t padded_byte;
    size_t block_len;

    block_len = ctx->block_len;

    padded_byte = (block_len - *data_size_byte % block_len);
    if (plain_data != padded) {
        memcpy(padded, plain_data, *data_size_byte);
    }

    if (*data_size_byte % block_len != 0) {
        padded[*data_size_byte] = 0x80;
        memset(&padded[*data_size_byte + 1], 0, padded_byte - 1);
        *data_size_byte = *data_size_byte + padded_byte;

        return 1; //Not error value; 1 if there was some padd el, 0 - if not.
    }
    return 0;
}

static uint8_t unpadding(uint8_t *padded_data, size_t *data_size_byte, uint8_t *plain_data)
{
    size_t i;

    i = *data_size_byte - 1;

    while (padded_data[i] == 0) {
        i--;
    }

    if (i == 0) {
        /*must be an error*/
        return 0;
    }

    if (i == *data_size_byte - 1) {
        return 0;
    }

    *data_size_byte = i + 1;
    if (plain_data != padded_data) {
        memcpy(plain_data, padded_data, *data_size_byte);
    }

    return 1;
}

static int ccm_padd(Dstu7624Ctx *ctx, const ByteArray *auth_data, const ByteArray *plain_data,
        uint8_t **h_out, size_t Nb)
{
    uint8_t *a_data_buf = NULL;
    uint8_t *p_data_buf = NULL;
    uint8_t *h = NULL;
    uint8_t G1[64];
    uint8_t G2[64];
    uint8_t B[64];
    uint64_t B64[8];
    size_t i;
    size_t tmp;
    size_t block_len;
    size_t a_data_len, p_data_len;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(auth_data != NULL);
    CHECK_PARAM(plain_data != NULL);
    CHECK_PARAM(h_out != NULL);
    CHECK_PARAM(ctx->block_len >= Nb + 1);

    /*Начало виробки імітовставки*/
    tmp = ctx->block_len - Nb - 1;
    block_len = ctx->block_len;

    memset(G1, 0, 64);
    memset(G2, 0, 64);
    memset(B, 0, 64);
    memcpy(G1, ctx->mode.ccm.iv, tmp);
    a_data_len = ba_get_len(auth_data);
    CALLOC_CHECKED(a_data_buf, a_data_len + block_len);
    DO(ba_to_uint8(auth_data, a_data_buf, a_data_len));

    p_data_len = ba_get_len(plain_data);
    CALLOC_CHECKED(p_data_buf, p_data_len + block_len);
    DO(ba_to_uint8(plain_data, p_data_buf, p_data_len));

    //Создание заголовка аутентификации
    G1[tmp] = (uint8_t) p_data_len;

    if (ba_get_len(plain_data) > 0) {
        G1[block_len - 1] = 1 << 7; //0b10000000
    } else {
        G1[block_len - 1] = 0;
    }
    //Код довжини імітовставки. Определен у стандарте.
    switch (ctx->mode.ccm.q) {
    case 8:
        G1[block_len - 1] |= 2 << 4;
        break;
    case 16:
        G1[block_len - 1] |= 3 << 4;
        break;
    case 32:
        G1[block_len - 1] |= 4 << 4;
        break;
    case 48:
        G1[block_len - 1] |= 5 << 4;
        break;
    case 64:
        G1[block_len - 1] |= 6 << 4;
        break;
    default:
        break;
    }
    G1[block_len - 1] |= ((Nb - 1));
    //Конец создания заголовка аутентификации

    G2[0] = (uint8_t) a_data_len;

    MALLOC_CHECKED(h, block_len * 2 + a_data_len);

    tmp = a_data_len % block_len;

    memcpy(h, G1, block_len);
    memcpy(&h[block_len], G2, block_len - tmp);
    memcpy(&h[block_len + block_len - tmp], a_data_buf, a_data_len);

    for (i = 0; i < a_data_len + block_len + (block_len - tmp); i += block_len) {
        kalyna_xor(B, &h[i], block_len, B);
        uint8_to_uint64(B, block_len, B64, block_len >> 3);
        ctx->basic_transform(ctx, B64);
        DO(uint64_to_uint8(B64, block_len >> 3, B, block_len));
    }

    padding(ctx, p_data_buf, &p_data_len, p_data_buf);
    for (i = 0; i < p_data_len; i += block_len) {
        kalyna_xor(B, &p_data_buf[i], block_len, B);
        uint8_to_uint64(B, block_len, B64, block_len >> 3);
        ctx->basic_transform(ctx, B64);
        DO(uint64_to_uint8(B64, block_len >> 3, B, block_len));
    }
    memcpy(h, B, ctx->mode.ccm.q);

    *h_out = h;
    h = NULL;

    /*Конец виробки імітовставки*/

cleanup:

    free(a_data_buf);
    free(p_data_buf);
    free(h);

    return ret;
}

static void gamma_gen(uint8_t *gamma)
{
    size_t i = 0;

    do {
        gamma[i]++;
    } while (gamma[i++] == 0);
}

static int encrypt_ctr(Dstu7624Ctx *ctx, const ByteArray *src, ByteArray **dst)
{
    uint8_t *gamma = ctx->mode.ctr.gamma;
    uint8_t *feed = ctx->mode.ctr.feed;
    size_t offset = ctx->mode.ctr.used_gamma_len;
    ByteArray *out = NULL;
    int ret = RET_OK;
    size_t data_off = 0;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(src != NULL);
    CHECK_PARAM(dst != NULL);

    CHECK_NOT_NULL(out = ba_alloc_by_len(src->len));

    /* Использование оставшейся гаммы. */
    if (offset != 0) {
        while (offset < ctx->block_len && data_off < src->len) {
            out->buf[data_off] = src->buf[data_off] ^ gamma[offset];
            data_off++;
            offset++;
        }

        if (offset == ctx->block_len) {
            gamma_gen(feed);
            crypt_basic_transform(ctx, feed, gamma);
            offset = 0;
        }
    }

    if (data_off < src->len) {
        /* Шифрування блоками по 8 байт. */
        for (; data_off + ctx->block_len <= src->len; data_off += ctx->block_len) {
            kalyna_xor(&src->buf[data_off], gamma, ctx->block_len, &out->buf[data_off]);

            gamma_gen(feed);
            crypt_basic_transform(ctx, feed, gamma);
        }
        /* Шифрування последнйого неполного блока. */
        for (; data_off < src->len; data_off++) {
            out->buf[data_off] = src->buf[data_off] ^ gamma[offset];
            offset++;
        }
    }

    ctx->mode.ctr.used_gamma_len = offset;
    *dst = out;

cleanup:

    return ret;
}

static int dstu7624_encrypt_ccm(Dstu7624Ctx *ctx, const ByteArray *auth_data, const ByteArray *plain_data,
        ByteArray **h_ba, ByteArray **cipher_data)
{
    uint8_t *p_data_buf = NULL;
    uint8_t *h = NULL;
    uint8_t *h_tmp = NULL;
    size_t p_data_len;
    size_t block_len;
    size_t q;
    Dstu7624CcmCtx *ccm;
    Dstu7624Ctx *ctr = NULL;
    ByteArray *pdata_buf_part = NULL;
    ByteArray *h_part = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(auth_data != NULL);
    CHECK_PARAM(plain_data != NULL);
    CHECK_PARAM(h_ba != NULL);
    CHECK_PARAM(cipher_data != NULL);

    if (ctx->mode_id != DSTU7624_MODE_CCM) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    ccm = &ctx->mode.ccm;
    DO(ccm_padd(ctx, auth_data, plain_data, &h_tmp, ccm->nb));

    q = ccm->q;
    block_len = ctx->block_len;

    CHECK_NOT_NULL(*h_ba = ba_alloc_from_uint8(h_tmp, q));
    p_data_len = ba_get_len(plain_data);
    MALLOC_CHECKED(p_data_buf, p_data_len + block_len);
    DO(ba_to_uint8(plain_data, p_data_buf, p_data_len));

    MALLOC_CHECKED(h, p_data_len + block_len);

    CHECK_NOT_NULL(ctr = dstu7624_alloc(DSTU7624_SBOX_1));
    DO(dstu7624_init_ctr(ctr, ccm->key, ccm->iv_tmp));
    DO(encrypt_ctr(ctr, plain_data, &pdata_buf_part));
    DO(encrypt_ctr(ctr, *h_ba, &h_part));

    CHECK_NOT_NULL(*cipher_data = ba_join(pdata_buf_part, h_part));

cleanup:

    dstu7624_free(ctr);
    ba_free(h_part);
    ba_free(pdata_buf_part);
    free(p_data_buf);
    free(h);
    free(h_tmp);

    return ret;
}

static int dstu7624_decrypt_ccm(Dstu7624Ctx *ctx, const ByteArray *auth_data, const ByteArray *cipher_data,
        ByteArray *h_ba, ByteArray **plain_data)
{
    uint8_t *p_data_buf = NULL;
    uint8_t *check_h = NULL;
    int ret = RET_OK;
    Dstu7624CcmCtx *ccm;
    Dstu7624Ctx *ctr = NULL;
    ByteArray *p_data_part = NULL;
    size_t part_len;
    ByteArray *ans = NULL;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(auth_data != NULL);
    CHECK_PARAM(cipher_data != NULL);
    CHECK_PARAM(h_ba != NULL);
    CHECK_PARAM(plain_data != NULL);

    if (ctx->mode_id != DSTU7624_MODE_CCM) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    ccm = &ctx->mode.ccm;

    CHECK_NOT_NULL(ctr = dstu7624_alloc(DSTU7624_SBOX_1));
    DO(dstu7624_init_ctr(ctr, ccm->key, ccm->iv_tmp));
    DO(encrypt_ctr(ctr, cipher_data, &p_data_part));

    DO(ba_to_uint8_with_alloc(p_data_part, &p_data_buf, &part_len));
    CHECK_NOT_NULL(ans = ba_alloc_from_uint8(p_data_buf, part_len - ccm->q));
    DO(ccm_padd(ctx, auth_data, ans, &check_h, ctx->mode.ccm.nb));

    if (memcmp(check_h, ba_get_buf_const(h_ba), ccm->q) != 0) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

    *plain_data = ans;
    ans = NULL;

cleanup:

    free(p_data_buf);
    dstu7624_free(ctr);
    ba_free(p_data_part);
    free(check_h);
    ba_free(ans);

    return ret;
}

static int encrypt_ecb(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **out)
{
    uint64_t *plain_data = NULL;
    size_t block_len_word;
    size_t plain_data_size_word;
    size_t i;
    int ret = RET_OK;
    block_len_word = ctx->block_len >> 3;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    if (in->len % ctx->block_len != 0) {
        SET_ERROR(RET_INVALID_DATA_LEN);
    }

    DO(ba_to_uint64_with_alloc(in, &plain_data, &plain_data_size_word));

    for (i = 0; i < plain_data_size_word; i += block_len_word) {
        ctx->basic_transform(ctx, &plain_data[i]);
    }

    CHECK_NOT_NULL(*out = ba_alloc_from_uint64(plain_data, plain_data_size_word));

cleanup:

    free(plain_data);

    return ret;
}

static int decrypt_ecb(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **out)
{
    uint64_t *plain_data = NULL;
    size_t block_len_word;
    size_t plain_data_size_word;
    size_t i;
    int ret = RET_OK;
    block_len_word = ctx->block_len >> 3;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    if (in->len % ctx->block_len != 0) {
        SET_ERROR(RET_INVALID_DATA_LEN);
    }

    DO(ba_to_uint64_with_alloc(in, &plain_data, &plain_data_size_word));

    for (i = 0; i < plain_data_size_word; i += block_len_word) {
        ctx->subrowcol_dec(ctx, &plain_data[i]);
    }

    CHECK_NOT_NULL(*out = ba_alloc_from_uint64(plain_data, plain_data_size_word));

cleanup:

    free(plain_data);

    return ret;
}

static int gf2m_mul(Gf2mCtx *ctx, size_t block_len, uint8_t *arg1, uint8_t *arg2, uint8_t *out)
{
    WordArray *wa_arg1 = NULL;
    WordArray *wa_arg2 = NULL;
    WordArray *wa_res = NULL;
    int ret = RET_OK;
    size_t mod_len;
    size_t old_len;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(arg1 != NULL);
    CHECK_PARAM(arg2 != NULL);
    CHECK_PARAM(out != NULL);

    CHECK_NOT_NULL(wa_arg2 = wa_alloc_from_uint8(arg2, block_len));
    CHECK_NOT_NULL(wa_arg1 = wa_alloc_from_uint8(arg1, block_len));

    mod_len = ctx->len;
    old_len = wa_arg1->len;

    CHECK_NOT_NULL(wa_res = wa_alloc(mod_len));

    wa_change_len(wa_arg1, mod_len);
    wa_change_len(wa_arg2, mod_len);

    gf2m_mod_mul(ctx, wa_arg1, wa_arg2, wa_res);

    wa_res->len = old_len;
    DO(wa_to_uint8(wa_res, out, block_len));
    wa_res->len = mod_len;

cleanup:

    wa_free(wa_res);
    wa_free(wa_arg2);
    wa_free(wa_arg1);

    return ret;
}

static int encrypt_xts(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **out)
{
    uint8_t *plain_data = NULL;
    uint8_t two[64] = {0};
    uint8_t gamma[64] = {0};
    size_t plain_size;
    size_t i;
    size_t block_len;
    size_t loop_len;
    size_t padded_len = 0;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    block_len = ctx->block_len;
    two[0] = 2;

    plain_size = ba_get_len(in);

    padded_len = block_len - (plain_size % block_len);
    MALLOC_CHECKED(plain_data, plain_size + padded_len);
    DO(ba_to_uint8(in, plain_data, plain_size));

    crypt_basic_transform(ctx, ctx->mode.xts.iv, gamma);

    if (padded_len == block_len) {
        loop_len = plain_size;
    } else {
        loop_len = plain_size - block_len;
    }

    for (i = 0; i < loop_len; i += block_len) {
        DO(gf2m_mul(ctx->mode.xts.gf2m_ctx, block_len, gamma, two, gamma));
        kalyna_xor(&plain_data[i], gamma, block_len, &plain_data[i]);
        crypt_basic_transform(ctx, &plain_data[i], &plain_data[i]);
        kalyna_xor(&plain_data[i], gamma, block_len, &plain_data[i]);
    }

    if (padded_len != block_len) {
        //Дополняем последний блок шифротекстом предпоследнего
        i += plain_size % block_len;
        memcpy(&plain_data[i], &plain_data[i - block_len], padded_len);
        i -= plain_size % block_len;

        //Конвертируем а для бе машин.
        DO(gf2m_mul(ctx->mode.xts.gf2m_ctx, block_len, gamma, two, gamma));
        kalyna_xor(&plain_data[i], gamma, block_len, &plain_data[i]);
        crypt_basic_transform(ctx, &plain_data[i], &plain_data[i]);
        kalyna_xor(&plain_data[i], gamma, block_len, &plain_data[i]);
        //Меняем n-1 блок и nй местами.
        memcpy(gamma, &plain_data[i - block_len], block_len);
        memcpy(&plain_data[i - block_len], &plain_data[i], block_len);
        memcpy(&plain_data[i], gamma, block_len - padded_len);
    }

    CHECK_NOT_NULL(*out = ba_alloc_from_uint8(plain_data, plain_size));

cleanup:

    free(plain_data);

    return ret;
}

static int decrypt_xts(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **out)
{
    uint8_t *plain_data = NULL;
    uint8_t gamma[64];
    uint8_t two[64] = {0};
    size_t plain_size;
    size_t block_len;
    size_t i;
    int ret = RET_OK;
    size_t padded_len;
    size_t loop_num;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    two[0] = 2;

    block_len = ctx->block_len;

    memset(gamma, 0, 64);

    plain_size = ba_get_len(in);
    padded_len = block_len - (plain_size % block_len);
    MALLOC_CHECKED(plain_data, plain_size + padded_len);
    DO(ba_to_uint8(in, plain_data, plain_size));

    crypt_basic_transform(ctx, ctx->mode.xts.iv, gamma);

    if (padded_len == block_len) {
        loop_num = plain_size;
    } else {
        loop_num = plain_size < 2 * block_len ? 0 : plain_size - 2 * block_len;
    }

    for (i = 0; i < loop_num; i += block_len) {
        DO(gf2m_mul(ctx->mode.xts.gf2m_ctx, block_len, gamma, two, gamma));
        kalyna_xor(&plain_data[i], gamma, block_len, &plain_data[i]);
        decrypt_basic_transform(ctx, &plain_data[i], &plain_data[i]);
        kalyna_xor(&plain_data[i], gamma, block_len, &plain_data[i]);
    }

    if (padded_len != block_len) {
        //Если было дополнение, на вход приходят последний и предпоследний блок
        //Так как при дополнении в шифровании меняются местами последний и предпоследний блоки, расшифровуем последний блок, как предпоследний
        DO(gf2m_mul(ctx->mode.xts.gf2m_ctx, block_len, gamma, two, gamma));
        DO(gf2m_mul(ctx->mode.xts.gf2m_ctx, block_len, gamma, two, two));
        kalyna_xor(&plain_data[i], two, block_len, &plain_data[i]);
        decrypt_basic_transform(ctx, &plain_data[i], &plain_data[i]);
        kalyna_xor(&plain_data[i], two, block_len, &plain_data[i]);

        //В конце предпоследнего блока хранится дополнение к последнему блоку
        i += block_len;
        i += plain_size % block_len;
        //Записываем полученое дополнение и расшифровуем
        memcpy(&plain_data[i], &plain_data[i - block_len], padded_len);
        i -= plain_size % block_len;

        kalyna_xor(&plain_data[i], gamma, block_len, &plain_data[i]);
        decrypt_basic_transform(ctx, &plain_data[i], &plain_data[i]);
        kalyna_xor(&plain_data[i], gamma, block_len, &plain_data[i]);

        //Меняем n-1 блок и nй местами.
        memcpy(gamma, &plain_data[i - block_len], block_len);
        memcpy(&plain_data[i - block_len], &plain_data[i], block_len);
        memcpy(&plain_data[i], gamma, block_len - padded_len);
    }
    CHECK_NOT_NULL(*out = ba_alloc_from_uint8(plain_data, plain_size));

cleanup:

    free(plain_data);

    return ret;
}

static int encrypt_cbc(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **out)
{
    uint8_t *cipher_data = NULL;
    size_t block_len;
    size_t plain_data_size_byte;
    size_t i;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    block_len = ctx->block_len;

    if (in->len % block_len != 0) {
        SET_ERROR(RET_INVALID_DATA_LEN);
    }

    plain_data_size_byte = in->len;

    CALLOC_CHECKED(cipher_data, (plain_data_size_byte + (block_len - plain_data_size_byte % block_len)));
    memcpy(cipher_data, in->buf, in->len);

    for (i = 0; i < plain_data_size_byte; i += block_len) {
        kalyna_xor(&cipher_data[i], ctx->mode.cbc.gamma, block_len, ctx->mode.cbc.gamma);
        crypt_basic_transform(ctx, ctx->mode.cbc.gamma, ctx->mode.cbc.gamma);
        memcpy(&cipher_data[i], ctx->mode.cbc.gamma, block_len);
    }

    CHECK_NOT_NULL(*out = ba_alloc());
    (*out)->buf = cipher_data;
    (*out)->len = plain_data_size_byte;
    cipher_data = NULL;

cleanup:

    free(cipher_data);

    return ret;
}

static int encrypt_cfb(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **dst)
{
    size_t offset = ctx->mode.cfb.used_gamma_len;
    uint8_t *gamma = ctx->mode.cfb.gamma;
    uint8_t *feed = ctx->mode.cfb.feed;
    ByteArray *out = NULL;
    int ret = RET_OK;
    size_t data_off = 0;
    size_t q = ctx->mode.cfb.q;

    CHECK_NOT_NULL(out = ba_alloc_by_len(in->len));

    /* Использование оставшейся гаммы. */
    if (offset != 0) {
        while (offset < q && data_off < in->len) {
            out->buf[data_off] = in->buf[data_off] ^ gamma[offset];
            feed[offset++] = out->buf[data_off++];
        }

        if (offset == ctx->block_len) {
            crypt_basic_transform(ctx, feed, gamma);
            offset = ctx->block_len - q;
        }
    }

    if (data_off < in->len) {
        /* Шифрування блоками по ctx->block_len байт. */
        for (; data_off + q <= in->len; data_off += q) {
            kalyna_xor(&in->buf[data_off], &gamma[offset], q, &out->buf[data_off]);

            memcpy(feed, gamma, ctx->block_len);
            memcpy(&feed[offset], &out->buf[data_off], q);

            crypt_basic_transform(ctx, feed, gamma);
        }
        /* Шифрування последнйого неполного блока. */
        for (; data_off < in->len; data_off++) {
            out->buf[data_off] = in->buf[data_off] ^ gamma[ctx->block_len - (in->len - data_off)];
            feed[offset++] = out->buf[data_off];
        }
    }

    ctx->mode.cfb.used_gamma_len = offset;
    *dst = out;

cleanup:

    return ret;
}

static int dstu7624_encrypt_gcm(Dstu7624Ctx *ctx, const ByteArray *plain_data, const ByteArray *auth_data,
        ByteArray **h, ByteArray **cipher_text)
{
    uint8_t *auth_buf = NULL;
    uint8_t *plain_buf = NULL;
    uint64_t gamma[8];
    uint8_t gamma8[64];
    uint64_t gamma_old[8];
    uint64_t H[8];
    uint64_t B[8];
    uint8_t H8[64];
    uint8_t B8[64];
    size_t auth_len;
    size_t plain_len;
    size_t i = 0;
    size_t block_len;
    size_t block_len_word;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(plain_data != NULL);
    CHECK_PARAM(auth_data != NULL);
    CHECK_PARAM(h != NULL);
    CHECK_PARAM(cipher_text != NULL);

    block_len = ctx->block_len;
    block_len_word = block_len >> 3;

    memset(gamma, 0, 64);
    memset(gamma_old, 0, 64);
    memset(B, 0, 64);
    memset(H, 0, 64);

    auth_len = ba_get_len(auth_data);
    MALLOC_CHECKED(auth_buf, auth_len + block_len);
    plain_len = ba_get_len(plain_data);
    MALLOC_CHECKED(plain_buf, plain_len + block_len);

    memcpy(gamma_old, ctx->mode.gcm.iv, ctx->block_len);
    ctx->basic_transform(ctx, gamma_old);

    DO(ba_to_uint8(auth_data, auth_buf, auth_len));
    DO(ba_to_uint8(plain_data, plain_buf, plain_len));

    /*Шифрування і обеспечение целостности.*/
    for (i = 0; i < plain_len; i += block_len) {
        gamma_old[0]++;
        memcpy(gamma, gamma_old, block_len);
        ctx->basic_transform(ctx, gamma);
        uint64_to_uint8(gamma, block_len_word, gamma8, block_len);
        kalyna_xor(&plain_buf[i], gamma8, block_len, &plain_buf[i]);
    }

    CHECK_NOT_NULL(*cipher_text = ba_alloc_from_uint8(plain_buf, plain_len));

    /*Выработка імітовставки.*/
    padding(ctx, plain_buf, &plain_len, plain_buf);
    ctx->basic_transform(ctx, H);
    /*H - у ле формате. Для умножения нам нужно 2 бе формата. auth_buf - бе.*/
    DO(uint64_to_uint8(H, block_len_word, H8, block_len));
    for (i = 0; i < auth_len; i += block_len) {
        kalyna_xor(&auth_buf[i], B, block_len, B);
        DO(gf2m_mul(ctx->mode.gcm.gf2m_ctx, block_len, (uint8_t *) B, H8, (uint8_t *) B));
    }

    for (i = 0; i < plain_len; i += block_len) {
        kalyna_xor(&plain_buf[i], B, block_len, B);
        DO(gf2m_mul(ctx->mode.gcm.gf2m_ctx, block_len, (uint8_t *) B, H8, (uint8_t *) B));
    }

    memset(H, 0, 64);
    auth_len <<= 3;
    plain_len <<= 3;
    for (i = 0; auth_len != 0; i++) {
        H[0] ^= (auth_len & 255) << (i << 3);
        auth_len >>= 8;
    }
    for (i = 0; plain_len != 0; i++) {
        H[((block_len / 2) >> 3)] ^= (plain_len & 255) << (i << 3);
        plain_len >>= 8;
    }

    DO(uint64_to_uint8(B, block_len_word, B8, block_len));
    kalyna_xor(H, B8, block_len, H);
    ctx->basic_transform(ctx, H);
    DO(uint64_to_uint8(H, block_len_word, H8, block_len));
    CHECK_NOT_NULL(*h = ba_alloc_from_uint8(H8, ctx->mode.gcm.q));

cleanup:

    free(plain_buf);
    free(auth_buf);

    return ret;
}

static int dstu7624_decrypt_gcm(Dstu7624Ctx *ctx, const ByteArray *cipher_data, const ByteArray *h_ba,
        const ByteArray *auth_data, ByteArray **out)
{
    uint8_t *auth_buf = NULL;
    uint8_t *plain_buf = NULL;
    uint64_t *h = NULL;
    uint64_t gamma[8];
    uint8_t gamma8[64];
    uint64_t gamma_old[8];
    uint64_t H[8];
    uint8_t H8[64];
    uint64_t B[8];
    uint8_t B8[64];
    size_t auth_len;
    size_t plain_len;
    size_t h_len;
    size_t block_len;
    size_t block_len_word;
    size_t i = 0;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(cipher_data != NULL);
    CHECK_PARAM(h_ba != NULL);
    CHECK_PARAM(auth_data != NULL);
    CHECK_PARAM(out != NULL);

    block_len = ctx->block_len;
    block_len_word = block_len >> 3;

    memset(gamma, 0, 64);
    memset(gamma_old, 0, 64);
    memset(B, 0, 64);
    memset(H, 0, 64);

    auth_len = ba_get_len(auth_data);
    MALLOC_CHECKED(auth_buf, auth_len + block_len);
    plain_len = ba_get_len(cipher_data);
    MALLOC_CHECKED(plain_buf, plain_len + block_len);

    memcpy(gamma_old, ctx->mode.gcm.iv, ctx->block_len);
    ctx->basic_transform(ctx, gamma_old);

    DO(ba_to_uint8(auth_data, auth_buf, auth_len));
    DO(ba_to_uint8(cipher_data, plain_buf, plain_len));

    /*Выработка імітовставки.*/
    padding(ctx, plain_buf, &plain_len, plain_buf);

    ctx->basic_transform(ctx, H);
    /*H - у ле формате. Для умножения нам нужно 2 бе формата. auth_buf - бе.*/
    uint64_to_uint8(H, block_len_word, H8, block_len);
    for (i = 0; i < auth_len; i += block_len) {
        kalyna_xor(&auth_buf[i], B, block_len, B);
        DO(gf2m_mul(ctx->mode.gcm.gf2m_ctx, block_len, (uint8_t *) B, (uint8_t *) H8, (uint8_t *) B));
    }

    for (i = 0; i < plain_len; i += block_len) {
        kalyna_xor(&plain_buf[i], B, block_len, B);
        DO(gf2m_mul(ctx->mode.gcm.gf2m_ctx, block_len, (uint8_t *) B, H8, (uint8_t *) B));
    }

    memset(H, 0, 64);

    auth_len <<= 3;
    plain_len <<= 3;
    for (i = 0; auth_len != 0; i++) {
        H[0] ^= (auth_len & 255) << (i << 3);
        auth_len >>= 8;
    }
    for (i = 0; plain_len != 0; i++) {
        H[((block_len / 2) >> 3)] ^= (plain_len & 255) << (i << 3);
        plain_len >>= 8;
    }

    DO(uint64_to_uint8(B, block_len_word, B8, block_len));
    kalyna_xor(H, B8, block_len, H);
    ctx->basic_transform(ctx, H);

    DO(ba_to_uint64_with_alloc(h_ba, &h, &h_len));

    if (memcmp(H, h, ctx->mode.gcm.q)) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

    /*Шифрування і забезпечення цілісності.*/
    auth_len = ba_get_len(auth_data);
    plain_len = ba_get_len(cipher_data);

    for (i = 0; i < plain_len; i += ctx->block_len) {
        gamma_old[0]++;
        memcpy(gamma, gamma_old, ctx->block_len);
        ctx->basic_transform(ctx, gamma);
        DO(uint64_to_uint8(gamma, block_len_word, gamma8, block_len));
        kalyna_xor(&plain_buf[i], gamma8, block_len, &plain_buf[i]);
    }

    CHECK_NOT_NULL(*out = ba_alloc_from_uint8(plain_buf, plain_len));

cleanup:

    free(h);
    free(plain_buf);
    free(auth_buf);

    return ret;
}

static int gmac_update(Dstu7624Ctx *ctx, const ByteArray *plain_data)
{
    uint8_t *data_buf = NULL;
    uint8_t *last_block = NULL;
    uint64_t *B = NULL;
    uint64_t *H = NULL;
    uint8_t H8[MAX_BLOCK_LEN];
    uint8_t B8[MAX_BLOCK_LEN];
    size_t data_len;
    size_t block_len;
    size_t tail_len;
    size_t last_block_len;
    size_t i;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(plain_data != NULL);

    B = ctx->mode.gmac.B;
    H = ctx->mode.gmac.H;
    block_len = ctx->block_len;
    last_block = ctx->mode.gmac.last_block;
    last_block_len = ctx->mode.gmac.last_block_len;

    //Приводим данные к u8 типу
    DO(uint64_to_uint8(B, block_len >> 3, B8, block_len));
    DO(uint64_to_uint8(H, block_len >> 3, H8, block_len));

    data_buf = plain_data->buf;
    data_len = plain_data->len;

    ctx->mode.gmac.msg_tot_len += data_len;
    //Если последний блок не пустой:
    if (last_block_len != 0) {
        /*Если длинна последнего блока и данных в сумме меньше размера блока*/
        if (last_block_len + data_len < block_len) {
            //Добавляем в конец последнего блока новые данные
            memcpy(&last_block[last_block_len], data_buf, data_len);
            ctx->mode.gmac.last_block_len += data_len;
            goto cleanup;
        } else {
            //Ксорим последний блок с текущими данными
            kalyna_xor(last_block, B8, last_block_len, B8);
            tail_len = block_len - last_block_len;
            //Ксорим первые байты из пришедшего блока, до размера блока.
            kalyna_xor(data_buf, &B8[last_block_len], tail_len, &B[last_block_len]);
            data_len -= tail_len;
        }
    } else {

        if (data_len >= block_len) {
            kalyna_xor(&data_buf[0], B8, block_len, B8);
        } else {
            memcpy(last_block, data_buf, data_len);
            ctx->mode.gmac.last_block_len = data_len;
            goto cleanup;
        }
    }
    //Высчитываем остаток
    tail_len = (block_len - data_len % block_len) % block_len;

    data_len -= tail_len;
    for (i = 0; i < data_len; i += block_len) {
        DO(gf2m_mul(ctx->mode.gmac.gf2m_ctx, block_len, B8, H8, B8));
        if ((i + block_len) < data_len) {
            kalyna_xor(&data_buf[i], B8, block_len, B8);
        }
    }

    if (tail_len != 0) {
        memcpy(last_block, &data_buf[i], tail_len);
        ctx->mode.gmac.last_block_len = tail_len;
    }

    DO(uint8_to_uint64(B8, block_len, B, block_len >> 3));

cleanup:

    return ret;
}

static int gmac_final(Dstu7624Ctx *ctx, ByteArray **mac)
{
    uint8_t *last_block = NULL;
    uint64_t *H;
    uint64_t *B;
    uint8_t B8[MAX_BLOCK_LEN];
    uint8_t H8[MAX_BLOCK_LEN];
    size_t last_block_len;
    size_t block_len;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(mac != NULL);

    B = ctx->mode.gmac.B;
    H = ctx->mode.gmac.H;
    block_len = ctx->block_len;
    last_block = ctx->mode.gmac.last_block;
    last_block_len = ctx->mode.gmac.last_block_len;

    DO(uint64_to_uint8(B, block_len >> 3, B8, block_len));
    DO(uint64_to_uint8(H, block_len >> 3, H8, block_len));

    // Проверяем, нужно ли достчитывать последний блок.
    if (last_block_len != 0) {
        //Если последний блок не нулевой, дополняем его.
        padding(ctx, last_block, &last_block_len, last_block);

        kalyna_xor(&last_block, B8, last_block_len, B8);
        DO(gf2m_mul(ctx->mode.gmac.gf2m_ctx, block_len, B8, H8, B8));
    }
    memset(H, 0, MAX_BLOCK_LEN);

    //Записываем длинну всего сообщения в битах
    H[0] = ctx->mode.gmac.msg_tot_len << 3;

    DO(uint64_to_uint8(H, block_len >> 3, H8, block_len));
    kalyna_xor(H8, B8, block_len, H8);
    DO(uint8_to_uint64(H8, block_len, H, block_len >> 3));
    ctx->basic_transform(ctx, H);

    DO(uint64_to_uint8(H, block_len >> 3, H8, block_len));
    CHECK_NOT_NULL(*mac = ba_alloc_from_uint8(H8, ctx->mode.gmac.q));

cleanup:

    return ret;
}

static int encrypt_gmac(Dstu7624Ctx *ctx, const ByteArray *plain_data, ByteArray **out)
{
    uint8_t *data_buf = NULL;
    uint64_t H[8];
    uint8_t H8[64];
    uint64_t B[8];
    uint8_t B8[64];
    size_t data_len;
    size_t i;
    size_t block_len;
    size_t block_len_word;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(plain_data != NULL);
    CHECK_PARAM(out != NULL);

    block_len = ctx->block_len;
    block_len_word = block_len >> 3;
    memset(H, 0, 64);
    memset(B, 0, 64);
    memset(H8, 0, 64);
    memset(B8, 0, 64);
    data_len = ba_get_len(plain_data);
    MALLOC_CHECKED(data_buf, data_len + block_len);
    DO(ba_to_uint8(plain_data, data_buf, data_len));

    padding(ctx, data_buf, &data_len, data_buf);
    ctx->basic_transform(ctx, H);
    DO(uint64_to_uint8(H, block_len_word, H8, block_len));
    for (i = 0; i < data_len; i += block_len) {
        kalyna_xor(&data_buf[i], B, block_len, B);
        DO(gf2m_mul(ctx->mode.gmac.gf2m_ctx, block_len, (uint8_t *) B, H8, (uint8_t *) B));
    }

    memset(H, 0, 64);

    H[0] = data_len << 3;
    DO(uint64_to_uint8(B, block_len_word, B8, block_len));
    kalyna_xor(H, B8, block_len, H);
    ctx->basic_transform(ctx, H);
    DO(uint64_to_uint8(H, block_len_word, H8, block_len));

    CHECK_NOT_NULL(*out = ba_alloc_from_uint8(H8, ctx->mode.gmac.q));

cleanup:

    free(data_buf);

    return ret;
}

static int encrypt_ofb(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **out)
{
    uint8_t *plain_data = NULL;
    uint8_t *gamma = NULL;
    size_t plain_data_size_byte;
    size_t i;
    size_t block_len;
    size_t used_gamma_len;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    block_len = ctx->block_len;
    plain_data_size_byte = ba_get_len(in);
    CALLOC_CHECKED(plain_data, ((plain_data_size_byte / block_len) + 1) * block_len);
    DO(ba_to_uint8(in, plain_data, plain_data_size_byte));

    gamma = ctx->mode.ofb.gamma;
    used_gamma_len = ctx->mode.ofb.used_gamma_len;
    if (used_gamma_len != 0) {
        //Если размер пришедших данных меньше чем оставшегося хеша, то шифруем только пришедших данные.
        kalyna_xor(plain_data, &gamma[used_gamma_len],
                (block_len - used_gamma_len) > plain_data_size_byte ? plain_data_size_byte : (block_len - used_gamma_len),
                plain_data);
    }

    i = used_gamma_len == block_len ? block_len : used_gamma_len;
    for (; i < plain_data_size_byte; i += block_len) {
        crypt_basic_transform(ctx, gamma, gamma);
        kalyna_xor(&plain_data[i], gamma, block_len, &plain_data[i]);
    }

    CHECK_NOT_NULL(*out = ba_alloc());
    (*out)->buf = plain_data;
    (*out)->len = plain_data_size_byte;
    plain_data = NULL;

    ctx->mode.ofb.used_gamma_len = (ctx->mode.ofb.used_gamma_len + plain_data_size_byte) % ctx->block_len;

cleanup:

    free(plain_data);

    return ret;
}

static int encrypt_kw(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **out)
{
    uint8_t *cipher_data = NULL;
    uint8_t *b = NULL;
    uint8_t *shift = NULL;
    uint8_t B[MAX_BLOCK_LEN / 2];
    uint8_t swap[MAX_BLOCK_LEN];
    size_t plain_data_size_bit;
    size_t i;
    size_t block_size_kw_byte;
    size_t plain_data_size_byte;
    size_t b_last_el;
    size_t b_el_count;
    size_t r;
    size_t n;
    size_t v;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    block_size_kw_byte = ctx->block_len >> 1;
    plain_data_size_byte = ba_get_len(in);
    MALLOC_CHECKED(cipher_data, plain_data_size_byte + (ctx->block_len << 2));
    memset(cipher_data, 0, plain_data_size_byte + (ctx->block_len << 2));
    DO(ba_to_uint8(in, cipher_data, plain_data_size_byte));

    i = 0;
    if (plain_data_size_byte % ctx->block_len != 0) {
        plain_data_size_bit = plain_data_size_byte << 3;

        while (plain_data_size_bit != 0) {
            cipher_data[plain_data_size_byte + i] = (plain_data_size_bit & 255);
            i++;
            plain_data_size_bit >>= 8;
        }

        plain_data_size_byte += block_size_kw_byte;
        padding(ctx, cipher_data, &plain_data_size_byte, cipher_data);
    }

    r = plain_data_size_byte / ctx->block_len;
    n = 2 * (r + 1);
    v = (n - 1) * 6;

    plain_data_size_byte += ctx->block_len;

    b_el_count = ((n - 1) * (block_size_kw_byte));
    b_last_el = (n - 2) * (block_size_kw_byte);

    MALLOC_CHECKED(b, n * block_size_kw_byte);
    MALLOC_CHECKED(shift, n * block_size_kw_byte);

    memcpy(B, cipher_data, block_size_kw_byte);
    memcpy(b, cipher_data + block_size_kw_byte, b_el_count);

    for (i = 1; i <= v; i++) {
        memcpy(swap, B, block_size_kw_byte);
        memcpy(swap + (block_size_kw_byte), b, block_size_kw_byte);
        crypt_basic_transform(ctx, swap, swap);
        swap[block_size_kw_byte] ^= i;
        memcpy(B, swap + (block_size_kw_byte), block_size_kw_byte);
        memcpy(shift, b + (block_size_kw_byte), b_el_count);
        memcpy(b, shift, b_el_count - block_size_kw_byte);
        memcpy(b + b_last_el, swap, block_size_kw_byte);
    }

    memcpy(cipher_data, B, block_size_kw_byte);
    memcpy(cipher_data + block_size_kw_byte, b, b_el_count);

    CHECK_NOT_NULL(*out = ba_alloc());
    (*out)->buf = cipher_data;
    (*out)->len = b_el_count + block_size_kw_byte;
    cipher_data = NULL;

cleanup:

    free(shift);
    free(b);
    free(cipher_data);

    return ret;
}

static int decrypt_ctr(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **out)
{
    return encrypt_ctr(ctx, in, out);
}

static int decrypt_cfb(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **dst)
{
    size_t offset = ctx->mode.cfb.used_gamma_len;
    uint8_t *gamma = ctx->mode.cfb.gamma;
    uint8_t *feed = ctx->mode.cfb.feed;
    ByteArray *out = NULL;
    int ret = RET_OK;
    size_t data_off = 0;
    size_t q = ctx->mode.cfb.q;

    CHECK_NOT_NULL(out = ba_alloc_by_len(in->len));

    /* Использование оставшейся гаммы. */
    if (offset != 0) {
        while (offset < q && data_off < in->len) {
            out->buf[data_off] = in->buf[data_off] ^ gamma[offset];
            feed[offset++] = in->buf[data_off++];
        }

        if (offset == ctx->block_len) {
            crypt_basic_transform(ctx, feed, gamma);
            offset = ctx->block_len - q;
        }
    }

    if (data_off < in->len) {
        /* Шифрування блоками по ctx->block_len байт. */
        for (; data_off + q <= in->len; data_off += q) {
            kalyna_xor(&in->buf[data_off], &gamma[offset], q, &out->buf[data_off]);

            memcpy(feed, gamma, ctx->block_len);
            memcpy(&feed[offset], &in->buf[data_off], q);

            crypt_basic_transform(ctx, feed, gamma);
        }
        /* Шифрування последнйого неполного блока. */
        for (; data_off < in->len; data_off++) {
            out->buf[data_off] = in->buf[data_off] ^ gamma[ctx->block_len - (in->len - data_off)];
            feed[offset++] = in->buf[data_off];
        }
    }

    ctx->mode.cfb.used_gamma_len = offset;
    *dst = out;

cleanup:

    return ret;
}

static int decrypt_kw(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **out)
{
    uint8_t *cipher_data = NULL;
    uint8_t *b = NULL;
    uint8_t swap[MAX_BLOCK_LEN];
    uint8_t *shift = NULL;
    uint8_t B[MAX_BLOCK_LEN >> 1];
    size_t i;
    size_t cipher_data_size_byte;
    size_t block_size_kw_byte;
    size_t b_last_el;
    size_t b_el_count;
    size_t r;
    size_t n;
    size_t v;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    DO(ba_to_uint8_with_alloc(in, &cipher_data, &cipher_data_size_byte));

    block_size_kw_byte = ctx->block_len >> 1;

    r = (cipher_data_size_byte / ctx->block_len) - 1;
    n = 2 * (r + 1);
    v = (n - 1) * 6;

    memcpy(B, cipher_data, block_size_kw_byte);

    MALLOC_CHECKED(b, cipher_data_size_byte);

    b_el_count = ((n - 1) * block_size_kw_byte);

    memcpy(b, cipher_data + block_size_kw_byte, b_el_count);

    b_last_el = (n - 2) * block_size_kw_byte;

    MALLOC_CHECKED(shift, cipher_data_size_byte);
    for (i = v; i >= 1; i--) {
        memcpy(swap, b + b_last_el, block_size_kw_byte);
        B[0] ^= i;
        memcpy(swap + block_size_kw_byte, B, block_size_kw_byte);
        decrypt_basic_transform(ctx, swap, swap);
        memcpy(B, swap, block_size_kw_byte);
        memcpy(shift, b, cipher_data_size_byte - block_size_kw_byte);
        memcpy(b + block_size_kw_byte, shift, b_el_count);
        memcpy(b, swap + block_size_kw_byte, block_size_kw_byte);
    }

    memcpy(cipher_data, B, block_size_kw_byte);
    memcpy(cipher_data + block_size_kw_byte, b, b_el_count);

    unpadding(cipher_data, &cipher_data_size_byte, cipher_data);

    if (cipher_data_size_byte % ctx->block_len != 0) {
        cipher_data_size_byte -= block_size_kw_byte + 1;
    }

    CHECK_NOT_NULL(*out = ba_alloc());
    (*out)->buf = cipher_data;
    (*out)->len = cipher_data_size_byte;
    cipher_data = NULL;

cleanup:

    free(cipher_data);
    free(b);
    free(shift);

    return ret;
}

static int decrypt_cbc(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **out)
{
    uint8_t *cipher_data = NULL;
    uint8_t *plain_data = NULL;
    size_t block_len;
    size_t data_len;
    size_t i;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    block_len = ctx->block_len;

    cipher_data = in->buf;
    data_len = in->len;
    MALLOC_CHECKED(plain_data, data_len);

    for (i = 0; i < data_len; i += block_len) {
        decrypt_basic_transform(ctx, &cipher_data[i], &plain_data[i]);
        kalyna_xor(ctx->mode.cbc.gamma, &plain_data[i], block_len, &plain_data[i]);
        memcpy(ctx->mode.cbc.gamma, &cipher_data[i], ctx->block_len);
    }

    CHECK_NOT_NULL(*out = ba_alloc_from_uint8(plain_data, data_len));

cleanup:

    free(plain_data);

    return ret;
}

int dstu7624_init_ecb(Dstu7624Ctx *ctx, const ByteArray *key, const size_t block_size)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);

    DO(dstu7624_init(ctx, key, block_size));

    ctx->mode_id = DSTU7624_MODE_ECB;

cleanup:

    return ret;
}

int dstu7624_init_cbc(Dstu7624Ctx *ctx, const ByteArray *key, const ByteArray *iv)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(iv != NULL);

    DO(dstu7624_init(ctx, key, iv->len));

    memcpy(ctx->mode.cbc.gamma, iv->buf, ctx->block_len);

    ctx->mode_id = DSTU7624_MODE_CBC;

cleanup:

    return ret;
}

int dstu7624_init_kw(Dstu7624Ctx *ctx, const ByteArray *key, const size_t block_size)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);

    DO(dstu7624_init(ctx, key, block_size));

    ctx->mode_id = DSTU7624_MODE_KW;

cleanup:

    return ret;
}

int dstu7624_init_cfb(Dstu7624Ctx *ctx, const ByteArray *key, const ByteArray *iv, const size_t q)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(iv != NULL);
    CHECK_PARAM(q != 0 && q <= iv->len);
    CHECK_PARAM(q == 1 || q == 8 || q == 16 || q == 32 || q == 64);

    DO(dstu7624_init(ctx, key, ba_get_len(iv)));
    DO(ba_to_uint8(iv, ctx->mode.cfb.gamma, ctx->block_len));

    ctx->mode.cfb.q = q;

    DO(ba_to_uint8(iv, ctx->mode.cfb.feed, ctx->block_len));
    ctx->mode.cfb.used_gamma_len = ctx->block_len;

    ctx->mode_id = DSTU7624_MODE_CFB;

cleanup:

    return ret;
}

int dstu7624_init_ofb(Dstu7624Ctx *ctx, const ByteArray *key, const ByteArray *iv)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(iv != NULL);

    DO(dstu7624_init(ctx, key, ba_get_len(iv)));

    DO(ba_to_uint8(iv, ctx->mode.ofb.gamma, ctx->block_len));
    ctx->mode.ofb.used_gamma_len = 0;
    ctx->mode_id = DSTU7624_MODE_OFB;

cleanup:

    return ret;
}

int dstu7624_init_gmac(Dstu7624Ctx *ctx, const ByteArray *key, const size_t block_size, const size_t q)
{
    int ret = RET_OK;
    int f[5] = {0};

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(block_size == 16 || block_size == 32 || block_size == 64);
    CHECK_PARAM( (8 <= q) && (q <= block_size) );

    DO(dstu7624_init(ctx, key, block_size));

    ctx->mode.gmac.q = q;

    switch (block_size) {
    case 16:
        f[0] = 128;
        f[1] = 7;
        f[2] = 2;
        f[3] = 1;
        f[4] = 0;
        break;
    case 32:
        f[0] = 256;
        f[1] = 10;
        f[2] = 5;
        f[3] = 2;
        f[4] = 0;
        break;
    case 64:
        f[0] = 512;
        f[1] = 8;
        f[2] = 5;
        f[3] = 2;
        f[4] = 0;
        break;
    default:
        break;
    }

    CHECK_NOT_NULL(ctx->mode.gmac.gf2m_ctx = gf2m_alloc(f, 5));
    memset(ctx->mode.gmac.B, 0, MAX_BLOCK_LEN);
    memset(ctx->mode.gmac.last_block, 0, MAX_BLOCK_LEN);
    memset(ctx->mode.gmac.H, 0, MAX_BLOCK_LEN);
    ctx->basic_transform(ctx, ctx->mode.gmac.H);
    ctx->mode.gmac.last_block_len = 0;
    ctx->mode.gmac.msg_tot_len = 0;

    ctx->mode_id = DSTU7624_MODE_GMAC;

cleanup:

    return ret;
}

int dstu7624_init_cmac(Dstu7624Ctx *ctx, const ByteArray *key, const size_t block_size, const size_t q)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(q > 0 && q <= block_size);

    DO(dstu7624_init(ctx, key, block_size));

    ctx->mode.cmac.q = q;
    ctx->mode.cmac.lblock_len = 0;
    ctx->mode_id = DSTU7624_MODE_CMAC;

cleanup:

    return ret;
}

int dstu7624_init_xts(Dstu7624Ctx *ctx, const ByteArray *key, const ByteArray *iv)
{
    int f[5] = {0};
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(iv != NULL);

    DO(dstu7624_init(ctx, key, ba_get_len(iv)));
    DO(ba_to_uint8(iv, ctx->mode.xts.iv, ctx->block_len));

    switch (ctx->block_len) {
    case 16:
        f[0] = 128;
        f[1] = 7;
        f[2] = 2;
        f[3] = 1;
        f[4] = 0;
        break;
    case 32:
        f[0] = 256;
        f[1] = 10;
        f[2] = 5;
        f[3] = 2;
        f[4] = 0;
        break;
    case 64:
        f[0] = 512;
        f[1] = 8;
        f[2] = 5;
        f[3] = 2;
        f[4] = 0;
        break;
    default:
        break;
    }

    gf2m_free(ctx->mode.xts.gf2m_ctx);
    ctx->mode.xts.gf2m_ctx = NULL;

    CHECK_NOT_NULL(ctx->mode.xts.gf2m_ctx = gf2m_alloc(f, 5));

    ctx->mode_id = DSTU7624_MODE_XTS;

cleanup:

    return ret;
}

int dstu7624_init_ccm(Dstu7624Ctx *ctx, const ByteArray *key, const ByteArray *iv, const size_t q, uint64_t n_max)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(iv != NULL);
    CHECK_PARAM(q > 0);
    CHECK_PARAM(n_max >= 8);

    DO(dstu7624_init(ctx, key, ba_get_len(iv)));

    CHECK_PARAM(q <= ctx->block_len);

    ctx->mode.ccm.key = key;

    DO(ba_to_uint8(iv, ctx->mode.ccm.iv, ctx->block_len));
    ctx->mode.ccm.iv_tmp = iv;
    ctx->mode.ccm.q = q;
    ctx->mode.ccm.nb = (size_t) (((n_max - 3) >> 3) + 1);

    ctx->mode_id = DSTU7624_MODE_CCM;

cleanup:

    return ret;
}

int dstu7624_init_gcm(Dstu7624Ctx *ctx, const ByteArray *key, const ByteArray *iv, const size_t q)
{
    int f[5] = {0};
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(iv != NULL);
    CHECK_PARAM( (8 <= q) && (q <= iv->len) );

    DO(dstu7624_init(ctx, key, ba_get_len(iv)));

    DO(ba_to_uint64(iv, ctx->mode.gcm.iv, ctx->block_len >> 3));

    ctx->mode.gcm.q = q;

    switch (ctx->block_len) {
    case 16:
        f[0] = 128;
        f[1] = 7;
        f[2] = 2;
        f[3] = 1;
        f[4] = 0;
        break;
    case 32:
        f[0] = 256;
        f[1] = 10;
        f[2] = 5;
        f[3] = 2;
        f[4] = 0;
        break;
    case 64:
        f[0] = 512;
        f[1] = 8;
        f[2] = 5;
        f[3] = 2;
        f[4] = 0;
        break;
    default:
        break;
    }

    gf2m_free(ctx->mode.gcm.gf2m_ctx);
    ctx->mode.gcm.gf2m_ctx = NULL;

    CHECK_NOT_NULL(ctx->mode.gcm.gf2m_ctx = gf2m_alloc(f, 5));

    ctx->mode_id = DSTU7624_MODE_GCM;

cleanup:

    return ret;
}

static int cmac_update(Dstu7624Ctx *ctx, const ByteArray *in)
{
    uint8_t *shifted_data = NULL;
    uint8_t *plain_data = NULL;
    uint8_t cipher_data[64];
    size_t plain_data_len;
    size_t i, j;
    size_t block_len;
    Dstu7624CmacCtx *cmac = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(in != NULL);

    if (ctx->mode_id != DSTU7624_MODE_CMAC) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    block_len = ctx->block_len;
    cmac = &ctx->mode.cmac;

    /*State in be format -> cipher data in be.*/
    DO(uint64_to_uint8(ctx->state, block_len >> 3, cipher_data, block_len));

    plain_data = in->buf;
    plain_data_len = in->len;

    //Если длинна блока и входных данных меньше размера блока, то записываем данные в последний блок и выходим.
    if (cmac->lblock_len + plain_data_len <= block_len) {
        memcpy(&cmac->last_block[cmac->lblock_len], plain_data, plain_data_len);
        cmac->lblock_len += plain_data_len;
        goto cleanup;
    }
    //Ищем преобразование от последнего блока и остальных данных
    memcpy(&cmac->last_block[cmac->lblock_len], plain_data, block_len - cmac->lblock_len);
    kalyna_xor(cmac->last_block, cipher_data, block_len, cipher_data);
    crypt_basic_transform(ctx, cipher_data, cipher_data);
    shifted_data = plain_data + (block_len - cmac->lblock_len);
    plain_data_len -= (block_len - cmac->lblock_len);

    for (i = 0, j = block_len; j < plain_data_len; i += block_len, j += block_len) {
        kalyna_xor(&shifted_data[i], cipher_data, block_len, cipher_data);
        crypt_basic_transform(ctx, cipher_data, cipher_data);
    }

    cmac->lblock_len = plain_data_len - i;
    if (cmac->lblock_len != 0) {
        memcpy(cmac->last_block, shifted_data + i, cmac->lblock_len);
    }

    DO(uint8_to_uint64(cipher_data, block_len, ctx->state, block_len >> 3));

cleanup:

    return ret;
}

static int cmac_final(Dstu7624Ctx *ctx, ByteArray **out)
{
    uint8_t cipher_data[64];
    uint8_t rkey[64];
    size_t block_len;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(out != NULL);

    if (ctx->mode_id != DSTU7624_MODE_CMAC) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    block_len = ctx->block_len;
    DO(uint64_to_uint8(ctx->state, block_len >> 3, cipher_data, block_len));
    memset(rkey, 0, 64);

    rkey[0] = padding(ctx, ctx->mode.cmac.last_block, &ctx->mode.cmac.lblock_len, ctx->mode.cmac.last_block);
    crypt_basic_transform(ctx, rkey, rkey);

    kalyna_xor(ctx->mode.cmac.last_block, cipher_data, block_len, cipher_data);

    kalyna_xor(rkey, cipher_data, block_len, cipher_data);

    crypt_basic_transform(ctx, cipher_data, cipher_data);

    CHECK_NOT_NULL(*out = ba_alloc_from_uint8(cipher_data, ctx->mode.cmac.q));

cleanup:

    return ret;
}

int dstu7624_encrypt(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **out)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    if (ctx->mode_id == DSTU7624_MODE_CCM || ctx->mode_id == DSTU7624_MODE_CMAC) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    switch (ctx->mode_id) {
    case DSTU7624_MODE_ECB:
        DO(encrypt_ecb(ctx, in, out));
        break;
    case DSTU7624_MODE_CTR:
        DO(encrypt_ctr(ctx, in, out));
        break;
    case DSTU7624_MODE_CBC:
        DO(encrypt_cbc(ctx, in, out));
        break;
    case DSTU7624_MODE_CFB:
        DO(encrypt_cfb(ctx, in, out));
        break;
    case DSTU7624_MODE_OFB:
        DO(encrypt_ofb(ctx, in, out));
        break;
    case DSTU7624_MODE_XTS:
        DO(encrypt_xts(ctx, in, out));
        break;
    case DSTU7624_MODE_KW:
        DO(encrypt_kw(ctx, in, out));
        break;
    case DSTU7624_MODE_GMAC:
        DO(encrypt_gmac(ctx, in, out));
        break;
    default:
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

cleanup:

    return ret;
}

int dstu7624_decrypt(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **out)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    switch (ctx->mode_id) {
    case DSTU7624_MODE_ECB:
        DO(decrypt_ecb(ctx, in, out));
        break;
    case DSTU7624_MODE_CTR:
        DO(decrypt_ctr(ctx, in, out));
        break;
    case DSTU7624_MODE_CBC:
        DO(decrypt_cbc(ctx, in, out));
        break;
    case DSTU7624_MODE_CFB:
        DO(decrypt_cfb(ctx, in, out));
        break;
    case DSTU7624_MODE_OFB:
        DO(encrypt_ofb(ctx, in, out));
        break;
    case DSTU7624_MODE_XTS:
        DO(decrypt_xts(ctx, in, out));
        break;
    case DSTU7624_MODE_KW:
        DO(decrypt_kw(ctx, in, out));
        break;
    default:
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

cleanup:

    return ret;
}

int dstu7624_init_ctr(Dstu7624Ctx *ctx, const ByteArray *key, const ByteArray *iv)
{
    size_t block_len;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(iv != NULL);

    block_len = ba_get_len(iv);
    DO(dstu7624_init(ctx, key, block_len));

    block_len = ctx->block_len;

    DO(ba_to_uint8(iv, ctx->mode.ctr.gamma, block_len));
    ctx->mode.ctr.used_gamma_len = 0;
    crypt_basic_transform(ctx, ctx->mode.ctr.gamma, ctx->mode.ctr.gamma);
    ctx->mode_id = DSTU7624_MODE_CTR;
    memcpy(ctx->mode.ctr.feed, ctx->mode.ctr.gamma, block_len);
    ctx->mode.ctr.used_gamma_len  = block_len;

cleanup:

    return ret;
}

int dstu7624_update_mac(Dstu7624Ctx *ctx, const ByteArray *data)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(data != NULL);

    switch (ctx->mode_id) {
    case DSTU7624_MODE_GMAC:
        DO(gmac_update(ctx, data));
        break;
    case DSTU7624_MODE_CMAC:
        DO(cmac_update(ctx, data));
        break;
    default:
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

cleanup:

    return ret;
}

int dstu7624_final_mac(Dstu7624Ctx *ctx, ByteArray **mac)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(mac != NULL);

    switch (ctx->mode_id) {
    case DSTU7624_MODE_GMAC:
        DO(gmac_final(ctx, mac));
        break;
    case DSTU7624_MODE_CMAC:
        DO(cmac_final(ctx, mac));
        break;
    default:
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

cleanup:

    return ret;
}

int dstu7624_encrypt_mac(Dstu7624Ctx *ctx, const ByteArray *auth_data, const ByteArray *data, ByteArray **mac,
        ByteArray **encrypted_data)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(auth_data != NULL);
    CHECK_PARAM(data != NULL);
    CHECK_PARAM(mac != NULL);
    CHECK_PARAM(encrypted_data != NULL);

    switch (ctx->mode_id) {
    case DSTU7624_MODE_GCM:
        DO(dstu7624_encrypt_gcm(ctx, data, auth_data, mac, encrypted_data));
        break;
    case DSTU7624_MODE_CCM:
        DO(dstu7624_encrypt_ccm(ctx, auth_data, data, mac, encrypted_data));
        break;
    default:
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

cleanup:

    return ret;
}

int dstu7624_decrypt_mac(Dstu7624Ctx *ctx, const ByteArray *auth_data, const ByteArray *encrypted_data, ByteArray *mac,
        ByteArray **data)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(auth_data != NULL);
    CHECK_PARAM(encrypted_data != NULL);
    CHECK_PARAM(mac != NULL);
    CHECK_PARAM(data != NULL);

    switch (ctx->mode_id) {
    case DSTU7624_MODE_GCM:
        DO(dstu7624_decrypt_gcm(ctx, encrypted_data, mac, auth_data, data));
        break;
    case DSTU7624_MODE_CCM:
        DO(dstu7624_decrypt_ccm(ctx, auth_data, encrypted_data, mac, data));
        break;
    default:
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

cleanup:

    return ret;
}

static int dstu7624_ecb_self_test(void)
{
    static const struct {
        const char* key;
        const char* data;
        const char* exp;
    } ecb_test_data[10] = {
        {
            "000102030405060708090A0B0C0D0E0F",
            "101112131415161718191A1B1C1D1E1F",
            "81BF1C7D779BAC20E1C9EA39B4D2AD06"
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "202122232425262728292A2B2C2D2E2F",
            "58EC3E091000158A1148F7166F334F14"
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "F66E3D570EC92135AEDAE323DCBD2A8CA03963EC206A0D5A88385C24617FD92C"
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
            "606990E9E6B7B67A4BD6D893D72268B78E02C83C3CD7E102FD2E74A8FDFE5DD9"
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
            "4A26E31B811C356AA61DD6CA0596231A67BA8354AA47F3A13E1DEEC320EB56B895D0F417175BAB662FD6F134BB15C86CCB906A26856EFEB7C5BC6472940DD9D9"
        },
        {
            "0F0E0D0C0B0A09080706050403020100",
            "7291EF2B470CC7846F09C2303973DAD7",
            "1F1E1D1C1B1A19181716151413121110"
        },
        {
            "1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100",
            "F36DB456CEFDDFE1B45B5F7030CAD996",
            "2F2E2D2C2B2A29282726252423222120",
        },
        {
            "1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100",
            "7FC5237896674E8603C1E9B03F8B4BA3AB5B7C592C3FC3D361EDD12586B20FE3",
            "3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A29282726252423222120"
        },
        {
            "3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A292827262524232221201F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100",
            "18317A2767DAD482BCCD07B9A1788D075E7098189E5F84972D0B916D79BA6AE0",
            "5F5E5D5C5B5A595857565554535251504F4E4D4C4B4A49484746454443424140"
        },
        {
            "3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A292827262524232221201F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100",
            "CE80843325A052521BEAD714E6A9D829FD381E0EE9A845BD92044554D9FA46A3757FEFDB853BB1F297FF9D833B75E66AAF4157ABB5291BDCF094BB13AA5AFF22",
            "7F7E7D7C7B7A797877767574737271706F6E6D6C6B6A696867666564636261605F5E5D5C5B5A595857565554535251504F4E4D4C4B4A49484746454443424140",
        }
    };

    int i, ret = RET_OK;
    ByteArray* data_ba = NULL;
    ByteArray* key_ba = NULL;
    ByteArray* expected_ba = NULL;
    ByteArray* actual_ba = NULL;
    Dstu7624Ctx* ctx = NULL;

    CHECK_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));

    for (i = 0; i < 10; i++) {
        key_ba = ba_alloc_from_hex(ecb_test_data[i].key);
        data_ba = ba_alloc_from_hex(ecb_test_data[i].data);
        expected_ba = ba_alloc_from_hex(ecb_test_data[i].exp);

        DO(dstu7624_init_ecb(ctx, key_ba, ba_get_len(data_ba)));
        DO(dstu7624_encrypt(ctx, data_ba, &actual_ba));
        if (ba_cmp(expected_ba, actual_ba) != 0) {
            SET_ERROR(RET_SELF_TEST_FAIL);
        }

        ba_free(actual_ba);
        actual_ba = NULL;

        DO(dstu7624_decrypt(ctx, expected_ba, &actual_ba));

        if (ba_cmp(data_ba, actual_ba) != 0) {
            SET_ERROR(RET_SELF_TEST_FAIL);
        }

        ba_free(actual_ba);
        actual_ba = NULL;
        ba_free(expected_ba);
        expected_ba = NULL;
        ba_free(data_ba);
        data_ba = NULL;
        ba_free(key_ba);
        key_ba = NULL;
    }

cleanup:
    ba_free(actual_ba);
    ba_free(expected_ba);
    ba_free(data_ba);
    ba_free(key_ba);
    dstu7624_free(ctx);
    return ret;
}

static int dstu7624_cbc_self_test(void)
{
    static const struct {
        const char* key;
        const char* iv;
        const char* data;
        const char* exp;
    } cbc_test_data[10] = {
        {
            "000102030405060708090A0B0C0D0E0F",
            "101112131415161718191A1B1C1D1E1F",
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F",
            "A73625D7BE994E85469A9FAABCEDAAB6DBC5F65DD77BB35E06BD7D1D8EAFC8624D6CB31CE189C82B8979F2936DE9BF14",
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "202122232425262728292A2B2C2D2E2F",
            "303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D",
            "13EA15843AD14C50BC03ECEF1F43E398E4217752D3EB046AC393DACC5CA1D6FA0EB9FCEB229362B4F1565527EE3D8433",
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F"\
            "707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F",
            "9CDFDAA75929E7C2A5CFC1BF16B42C5AE3886D0258E8C577DC01DAF62D185FB999B9867736B87110F5F1BC7481912C59"\
            "3F48FF79E2AFDFAB9F704A277EC3E557B1B0A9F223DAE6ED5AF591C4F2D6FB22E48334F5E9B96B1A2EA5200F30A406CE",
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
            "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F"\
            "909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF",
            "B8A2474578C2FEBF3F94703587BD5FDC3F4A4D2F43575B6144A1E1031FB3D1452B7FD52F5E3411461DAC506869FF8D2F"\
            "AEF4FEE60379AE00B33AA3EAF911645AF8091CD8A45D141D1FB150E5A01C1F26FF3DBD26AC4225EC7577B2CE57A5B0FF",
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F"\
            "303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F"\
            "707172737475767778797A7B7C7D7E7F",
            "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAF"\
            "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"\
            "E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
            "D4739B829EF901B24C1162AE4FDEF897EDA41FAC7F5770CDC90E1D1CDF124E8D7831E06B4498A4B6F6EC815DF2461DC9"\
            "9BB0449B0F09FCAA2C84090534BCC9329626FD74EF8F0A0BCB5765184629C3CBF53B0FB134F6D0421174B1C4E884D1CD"\
            "1069A7AD19752DCEBF655842E79B7858BDE01390A760D85E88925BFE38B0FA57",
        },
        {
            "0F0E0D0C0B0A09080706050403020100",
            "1F1E1D1C1B1A19181716151413121110",
            "88F2F048BA696170E3818915E0DBC0AFA6F141FEBC2F817138DA4AAB2DBF9CE490A488C9C82AC83FB0A6C0EEB64CFD22",
            "4F4E4D4C4B4A494847464544434241403F3E3D3C3B3A393837363534333231302F2E2D2C2B2A29282726252423222120",
        },
        {
            "1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100",
            "2F2E2D2C2B2A29282726252423222120",
            "BC8F026FC603ECE05C24FDE87542730999B381870882AC0535D4368C4BABD81B884E96E853EE7E055262D9D204FBE212",
            "5F5E5D5C5B5A595857565554535251504F4E4D4C4B4A494847464544434241403F3E3D3C3B3A39383736353433323130"
        },
        {
            "1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100",
            "3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A29282726252423222120",
            "AD1C64FFA7EC7C733B1857C08BC76E3FCFA60629913AFDDC6DF5F06498D0664E68B0C2DAD5986FDBF0C8204BD7FECC39"\
            "3AE5FE473ED5EA4D8D08FC414634A2B688954443C979ABF9224D09DD2F6CD436CBB2857DF85A12AD8DCA0AEEE997C18B",
            "9F9E9D9C9B9A999897969594939291908F8E8D8C8B8A898887868584838281807F7E7D7C7B7A79787776757473727170"\
            "6F6E6D6C6B6A696867666564636261605F5E5D5C5B5A595857565554535251504F4E4D4C4B4A49484746454443424140"
        },
        {
            "3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A292827262524232221201F1E1D1C1B1A19181716151413121110"\
            "0F0E0D0C0B0A09080706050403020100",
            "5F5E5D5C5B5A595857565554535251504F4E4D4C4B4A49484746454443424140",
            "C69A59E10D00F087319B62288A57417C074EAD07C732A87055F0A5AD2BB288105705C45E091A9A6726E9672DC7D8C76F"\
            "C45C782BCFEF7C39D94DEB84B17035BC8651255A0D34373451B6E1A2C827DB97566C9FF5506C5579F982A0EFC5BA7C28",
            "BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A99989796959493929190"\
            "8F8E8D8C8B8A898887868584838281807F7E7D7C7B7A797877767574737271706F6E6D6C6B6A69686766656463626160"
        },
        {
            "3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A292827262524232221201F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100",
            "7F7E7D7C7B7A797877767574737271706F6E6D6C6B6A696867666564636261605F5E5D5C5B5A595857565554535251504F4E4D4C4B4A49484746454443424140",
            "5D5B3E3DE5BAA70E0A0684D458856CE759C6018D0B3F087FC1DAC101D380236DD934F2880B02D56A575BCA35A0CE4B0D"\
            "9BA1F4A39C16CA7D80D59956630F09E54EC91E32B6830FE08323ED393F8028D150BF03CAD0629A5AFEEFF6E442579806"\
            "18DB2F32B7B2B65B96E8451F1090829D2FFFC615CC1581E9221438DCEAD1FD12",
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0"\
            "CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A0"\
            "9F9E9D9C9B9A999897969594939291908F8E8D8C8B8A89888786858483828180"
        }
    };

    int i, ret = RET_OK;
    ByteArray* data_ba = NULL;
    ByteArray* key_ba = NULL;
    ByteArray* iv_ba = NULL;
    ByteArray* expected_ba = NULL;
    ByteArray* actual_ba = NULL;
    ByteArray* padded_ba = NULL;
    Dstu7624Ctx* ctx = NULL;

    CHECK_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));

    for (i = 0; i < 9; i++) {
        CHECK_NOT_NULL(data_ba = ba_alloc_from_hex(cbc_test_data[i].data));
        CHECK_NOT_NULL(key_ba = ba_alloc_from_hex(cbc_test_data[i].key));
        CHECK_NOT_NULL(iv_ba = ba_alloc_from_hex(cbc_test_data[i].iv));
        CHECK_NOT_NULL(expected_ba = ba_alloc_from_hex(cbc_test_data[i].exp));

        DO(dstu7624_init_cbc(ctx, key_ba, iv_ba));
        if (ba_get_len(data_ba) % ba_get_len(iv_ba) != 0) {
            DO(make_iso_7816_4_padding(data_ba, (uint8_t)ba_get_len(iv_ba), &padded_ba));
            ba_free(data_ba);
            data_ba = padded_ba;
            padded_ba = NULL;
        }

        DO(dstu7624_encrypt(ctx, data_ba, &actual_ba));

        if (ba_cmp(expected_ba, actual_ba) != 0) {
            SET_ERROR(RET_SELF_TEST_FAIL);
        }

        ba_free(actual_ba);
        actual_ba = NULL;

        DO(dstu7624_init_cbc(ctx, key_ba, iv_ba));
        DO(dstu7624_decrypt(ctx, expected_ba, &actual_ba));

        if (ba_cmp(data_ba, actual_ba) != 0) {
            SET_ERROR(RET_SELF_TEST_FAIL);
        }

        ba_free(actual_ba);
        actual_ba = NULL;
        ba_free(data_ba);
        ba_free(key_ba);
        ba_free(iv_ba);
        ba_free(expected_ba);
        data_ba = NULL;
        key_ba = NULL;
        iv_ba = NULL;
        expected_ba = NULL;
    }

cleanup:
    ba_free(data_ba);
    ba_free(key_ba);
    ba_free(actual_ba);
    ba_free(iv_ba);
    ba_free(expected_ba);
    dstu7624_free(ctx);
    return ret;
}

static int dstu7624_ofb_self_test(void)
{
    static const struct {
        const char* key;
        const char* iv;
        const char* data;
        const char* exp;
    } ofb_test_data[9] = {
        {
            "000102030405060708090A0B0C0D0E0F",
            "101112131415161718191A1B1C1D1E1F",
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F",
            "A19E3E5E53BE8A07C9E0C01298FF832953205C661BD85A51F3A94113BC785CAB634B36E89A8FDD16A12E4467F5CC5A26",
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F"\
            "707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F90",
            "B62F7F144A8C6772E693A96890F064C3F06831BF743F5B0DD061067F3D22877331AA6A99D939F05B7550E9402BD1615C"\
            "C7B2D4A167E83EC0D8A894F92C72E176F3880B61C311D69CE1210C59184E818E19",
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F"\
            "303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
            "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F"\
            "909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0",
            "0008F28A82D2D01D23BFB2F8BB4F06D8FE73BA4F48A2977585570ED3818323A668883C9DCFF610CC7E3EA5C025FBBC5C"\
            "A6520F8F11CA35CEB9B07031E6DBFABE39001E9A3CC0A24BBC565939592B4DEDBD",
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F"\
            "303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F"\
            "707172737475767778797A7B7C7D7E7F",
            "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAF"\
            "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"\
            "E0",
            "CAA761980599B3ED2E945C41891BAD95F72B11C73ED26536A6847458BC76C827357156B4B3FE0DC1877F5B9F17B866C3"\
            "7B21D89531DB48007D05DEC928B06766C014BB9080385EDF0677E48A0A39B5E7489E28E82FFFD1F84694F17296CB7016"\
            "56",
        },
        {
            "0F0E0D0C0B0A09080706050403020100",
            "1F1E1D1C1B1A19181716151413121110",
            "649A1EAAE160AF20F5B3EF2F58D66C1178B82E00D26F30689C8EC22E8E86E9CBB0BD4FFEE39EB13C2311276A906DD636",
            "4F4E4D4C4B4A494847464544434241403F3E3D3C3B3A393837363534333231302F2E2D2C2B2A29282726252423222120",
        },
        {
            "1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100",
            "2F2E2D2C2B2A29282726252423222120",
            "1A66CFBFEC00C6D52E39923E858DD64B214AB787798D3D5059A6B498AD66B34EAC48C4074BEC0D98C6",
            "5F5E5D5C5B5A595857565554535251504F4E4D4C4B4A494847464544434241403F3E3D3C3B3A393837",
        },
        {
            "1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100",
            "3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A29282726252423222120",
            "7758A939DD6BD00CAF9153E5A5D5A66129105CA1EA54A97C06FA4A40960A068F55E34F9339A14436216948F92FA2FB52"\
            "86D3AB1E81543FC0018A0C4E8C493475F4D35DCFB0A7A5377F6669B857CDC978E4",
            "9F9E9D9C9B9A999897969594939291908F8E8D8C8B8A898887868584838281807F7E7D7C7B7A79787776757473727170"\
            "6F6E6D6C6B6A696867666564636261605F5E5D5C5B5A595857565554535251504F",
        },
        {
            "3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A292827262524232221201F1E1D1C1B1A19181716151413121110"\
            "0F0E0D0C0B0A09080706050403020100",
            "5F5E5D5C5B5A595857565554535251504F4E4D4C4B4A49484746454443424140",
            "98E122708FDABB1B1A5765C396DC79D7573221EC486ADDABD1770B147A6DD00B5FBC4F1EC68C59775B7AAA4D43C4CCE4"\
            "F396D982DF64D30B03EF6C3B997BA0ED940BBC590BD30D64B5AE207147D71086B5",
            "BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A99989796959493929190"\
            "8F8E8D8C8B8A898887868584838281807F7E7D7C7B7A797877767574737271706F",
        },
        {
            "3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A292827262524232221201F1E1D1C1B1A19181716151413121110"\
            "0F0E0D0C0B0A09080706050403020100",
            "7F7E7D7C7B7A797877767574737271706F6E6D6C6B6A696867666564636261605F5E5D5C5B5A59585756555453525150"\
            "4F4E4D4C4B4A49484746454443424140",
            "06C061A4A66DFC0910034B3CFBDC4206D8908241C56BF41C4103CFD6DF322210B87F57EAE9F9AD815E606A7D1E8E6BD7"\
            "CB1EBFBDBCB085C2D06BF3CC1586CB2EE1D81D38437F425131321647E42F5DE309D33F25B89DE37124683E4B44824FC5"\
            "6D",
            "EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0"\
            "BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A99989796959493929190"\
            "8F",
        }
    };

    int i, ret = RET_OK;
    ByteArray* data_ba = NULL;
    ByteArray* key_ba = NULL;
    ByteArray* iv_ba = NULL;
    ByteArray* expected_ba = NULL;
    ByteArray* actual_ba = NULL;
    Dstu7624Ctx* ctx = NULL;

    CHECK_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));

    for (i = 0; i < 9; i++) {
        CHECK_NOT_NULL(data_ba = ba_alloc_from_hex(ofb_test_data[i].data));
        CHECK_NOT_NULL(key_ba = ba_alloc_from_hex(ofb_test_data[i].key));
        CHECK_NOT_NULL(iv_ba = ba_alloc_from_hex(ofb_test_data[i].iv));
        CHECK_NOT_NULL(expected_ba = ba_alloc_from_hex(ofb_test_data[i].exp));

        DO(dstu7624_init_ofb(ctx, key_ba, iv_ba));
        DO(dstu7624_encrypt(ctx, data_ba, &actual_ba));

        if (ba_cmp(expected_ba, actual_ba) != 0) {
            SET_ERROR(RET_SELF_TEST_FAIL);
        }

        ba_free(actual_ba);
        actual_ba = NULL;

        DO(dstu7624_init_ofb(ctx, key_ba, iv_ba));
        DO(dstu7624_decrypt(ctx, expected_ba, &actual_ba));

        if (ba_cmp(data_ba, actual_ba) != 0) {
            SET_ERROR(RET_SELF_TEST_FAIL);
        }

        ba_free(actual_ba);
        actual_ba = NULL;
        ba_free(data_ba);
        ba_free(key_ba);
        ba_free(iv_ba);
        ba_free(expected_ba);
        data_ba = NULL;
        key_ba = NULL;
        iv_ba = NULL;
        expected_ba = NULL;
    }

cleanup:
    ba_free(data_ba);
    ba_free(key_ba);
    ba_free(actual_ba);
    ba_free(iv_ba);
    ba_free(expected_ba);
    dstu7624_free(ctx);
    return ret;
}

static int dstu7624_cfb_self_test(void)
{
    static const struct {
        const char* key;
        const char* iv;
        const char* data;
        const char* exp;
        size_t q;
    } cfb_test_data[8] = {
        {
            "000102030405060708090A0B0C0D0E0F",
            "101112131415161718191A1B1C1D1E1F",
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F",
            "A19E3E5E53BE8A07C9E0C01298FF83291F8EE6212110BE3FA5C72C88A082520B265570FE28680719D9B4465E169BC37A",
            16,
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F"\
            "707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F90",
            "E07821AF642F4B1DC071166F2D329763C2CF3B9E39CD0B52BDD33A0DC7B6B6BB201C4A1CD0F5DCB693ABEEA120DACA3A"\
            "29C73D1D6E87FD75B7DE9E3BE4D256791C2E44583DE8E061E45834A24262BDEBBE",
            16
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F"\
            "303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
            "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F"\
            "909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0",
            "0008F28A82D2D01D23BFB2F8BB4F06D8FE73BA4F48A2977585570ED3818323A6DBAD3D9DD580D9D8F787CE55FAB90735"\
            "F6B2D6152D56C0C787E6F4B6A2F557DF707A671D06AED196DD7D7E2320D8E45C4C",
            32
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F"\
            "303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F"\
            "707172737475767778797A7B7C7D7E7F",
            "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAF"\
            "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"\
            "E0",
            "CAA761980599B3ED2E945C41891BAD95F72B11C73ED26536A6847458BC76C827357156B4B3FE0DC1877F5B9F17B866C3"\
            "7B21D89531DB48007D05DEC928B06766C67D6F3F4C2B82D7A836FAD160905C1C7576243877DC3ADE4AA057966E0023F0"\
            "69",
            64
        },
        {
            "1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100",
            "2F2E2D2C2B2A29282726252423222120",
            "26319A368D85DE43DD5FDB928D91A441493D8CE07B64797C8F9676C5921CD1EA743F5E2777C327AC58",
            "5F5E5D5C5B5A595857565554535251504F4E4D4C4B4A494847464544434241403F3E3D3C3B3A393837",
            8
        },
        {
            "1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100",
            "3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A29282726252423222120",
            "7758A939DD6BD00CAF9153E5A5D5A66129105CA1EA54A97C06FA4A40960A068F61C3E424DE950151AC46879D84A3BCC2"\
            "4EC8FB69008DAF016EF9832FFD3DB39D02185FDB782DC28EAC27B35179FCA40640",
            "9F9E9D9C9B9A999897969594939291908F8E8D8C8B8A898887868584838281807F7E7D7C7B7A79787776757473727170"\
            "6F6E6D6C6B6A696867666564636261605F5E5D5C5B5A595857565554535251504F",
            32
        },
        {
            "3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A292827262524232221201F1E1D1C1B1A19181716151413121110"\
            "0F0E0D0C0B0A09080706050403020100",
            "5F5E5D5C5B5A595857565554535251504F4E4D4C4B4A49484746454443424140",
            "98E122708FDABB1B1A5765C396DC79D7573221EC486ADDABD1770B147A6DD00BDD5E4F1496D4D573923F9809EEEEF46B"\
            "063C64A5E875E77E65EC6832ECE3C24A4B8FD40B04088CBEE2CDECE4DC3CC5573A",
            "BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A99989796959493929190"\
            "8F8E8D8C8B8A898887868584838281807F7E7D7C7B7A797877767574737271706F",
            32
        },
        {
            "3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A292827262524232221201F1E1D1C1B1A19181716151413121110"\
            "0F0E0D0C0B0A09080706050403020100",
            "7F7E7D7C7B7A797877767574737271706F6E6D6C6B6A696867666564636261605F5E5D5C5B5A59585756555453525150"\
            "4F4E4D4C4B4A49484746454443424140",
            "06C061A4A66DFC0910034B3CFBDC4206D8908241C56BF41C4103CFD6DF322210B87F57EAE9F9AD815E606A7D1E8E6BD7"\
            "CB1EBFBDBCB085C2D06BF3CC1586CB2E88C9155E95B4872D86B49D80F5745B605EAF488AA520A717A92F4D68838E42C995",
            "EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0"\
            "BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A999897969594939291908F",
            64
        }
    };

    int i, ret = RET_OK;
    ByteArray* data_ba = NULL;
    ByteArray* key_ba = NULL;
    ByteArray* iv_ba = NULL;
    ByteArray* expected_ba = NULL;
    ByteArray* actual_ba = NULL;
    Dstu7624Ctx* ctx = NULL;

    CHECK_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));

    for (i = 0; i < 8; i++) {
        CHECK_NOT_NULL(data_ba = ba_alloc_from_hex(cfb_test_data[i].data));
        CHECK_NOT_NULL(key_ba = ba_alloc_from_hex(cfb_test_data[i].key));
        CHECK_NOT_NULL(iv_ba = ba_alloc_from_hex(cfb_test_data[i].iv));
        CHECK_NOT_NULL(expected_ba = ba_alloc_from_hex(cfb_test_data[i].exp));

        DO(dstu7624_init_cfb(ctx, key_ba, iv_ba, cfb_test_data[i].q));
        DO(dstu7624_encrypt(ctx, data_ba, &actual_ba));

        if (ba_cmp(expected_ba, actual_ba) != 0) {
            SET_ERROR(RET_SELF_TEST_FAIL);
        }

        ba_free(actual_ba);
        actual_ba = NULL;

        DO(dstu7624_init_cfb(ctx, key_ba, iv_ba, cfb_test_data[i].q));
        DO(dstu7624_decrypt(ctx, expected_ba, &actual_ba));

        if (ba_cmp(data_ba, actual_ba) != 0) {
            SET_ERROR(RET_SELF_TEST_FAIL);
        }

        ba_free(actual_ba);
        actual_ba = NULL;
        ba_free(data_ba);
        ba_free(key_ba);
        ba_free(iv_ba);
        ba_free(expected_ba);
        data_ba = NULL;
        key_ba = NULL;
        iv_ba = NULL;
        expected_ba = NULL;
    }

cleanup:
    ba_free(data_ba);
    ba_free(key_ba);
    ba_free(actual_ba);
    ba_free(iv_ba);
    ba_free(expected_ba);
    dstu7624_free(ctx);
    return ret;
}

static int dstu7624_ctr_self_test(void)
{
    int ret = RET_OK;
    ByteArray* key_ba = NULL;
    ByteArray* iv_ba = NULL;
    ByteArray* data_ba = NULL;
    ByteArray* exp_ba = NULL;
    ByteArray* act_ba = NULL;
    Dstu7624Ctx* ctx = NULL;

    CHECK_NOT_NULL(key_ba = ba_alloc_from_hex("000102030405060708090A0B0C0D0E0F"));
    CHECK_NOT_NULL(iv_ba = ba_alloc_from_hex("101112131415161718191A1B1C1D1E1F"));
    CHECK_NOT_NULL(data_ba = ba_alloc_from_hex("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748"));
    CHECK_NOT_NULL(exp_ba = ba_alloc_from_hex("A90A6B9780ABDFDFF64D14F5439E88F266DC50EDD341528DD5E698E2F000CE21F872DAF9FE1811844A"));

    CHECK_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    DO(dstu7624_init_ctr(ctx, key_ba, iv_ba));
    DO(dstu7624_encrypt(ctx, data_ba, &act_ba));
    if (ba_cmp(exp_ba, act_ba) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

cleanup:
    ba_free(key_ba);
    ba_free(iv_ba);
    ba_free(data_ba);
    ba_free(exp_ba);
    ba_free(act_ba);
    dstu7624_free(ctx);
    return ret;
}

static int dstu7624_cmac_self_test(void)
{
    static const struct {
        const char* key;
        const char* data;
        const char* exp;
        size_t q;
        size_t block_size;
    } cmac_test_data[3] = {
        {
            "000102030405060708090A0B0C0D0E0F",
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F",
            "123B4EAB8E63ECF3E645A99C1115E241",
            16,
            16
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F"\
            "707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D",
            "4CF52D7D5B0C47F05F6F5F5E73C3B508",
            16,
            16
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"\
            "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF",
            "7279FA6BC8EF7525B2B35260D00A1743",
            16,
            64
        }
    };

    int i, ret = RET_OK;
    ByteArray* data_ba = NULL;
    ByteArray* key_ba = NULL;
    ByteArray* expected_ba = NULL;
    ByteArray* actual_ba = NULL;
    Dstu7624Ctx* ctx = NULL;

    CHECK_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));

    for (i = 0; i < 3; i++) {
        key_ba = ba_alloc_from_hex(cmac_test_data[i].key);
        data_ba = ba_alloc_from_hex(cmac_test_data[i].data);
        expected_ba = ba_alloc_from_hex(cmac_test_data[i].exp);

        DO(dstu7624_init_cmac(ctx, key_ba, cmac_test_data[i].block_size, cmac_test_data[i].q));
        DO(dstu7624_update_mac(ctx, data_ba));
        DO(dstu7624_final_mac(ctx, &actual_ba));
        if (ba_cmp(expected_ba, actual_ba) != 0) {
            SET_ERROR(RET_SELF_TEST_FAIL);
        }

        ba_free(actual_ba);
        actual_ba = NULL;
        ba_free(expected_ba);
        expected_ba = NULL;
        ba_free(data_ba);
        data_ba = NULL;
        ba_free(key_ba);
        key_ba = NULL;
    }

cleanup:
    ba_free(actual_ba);
    ba_free(expected_ba);
    ba_free(data_ba);
    ba_free(key_ba);
    dstu7624_free(ctx);
    return ret;
}

static int dstu7624_xts_self_test(void)
{
    static const struct {
        const char* key;
        const char* iv;
        const char* data;
        const char* exp;
    } xts_test_data[10] = {
        {
            "000102030405060708090A0B0C0D0E0F",
            "101112131415161718191A1B1C1D1E1F",
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "B3E431B3FBAF31108C302669EE7116D1CF518B6D329D30618DF5628E426BDEF1",
        },
        {
            "000102030405060708090A0B0C0D0E0F",
            "101112131415161718191A1B1C1D1E1F",
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D",
            "48F3055ED2832222085005209C9D4D41B3E431B3FBAF31108C302669EE71",
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "202122232425262728292A2B2C2D2E2F",
            "303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F",
            "830AC78A6F629CB4C7D5D156FD84955BD0998CA1E0BC1FF135676BF2A2598FA1",
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "202122232425262728292A2B2C2D2E2F",
            "303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758",
            "830AC78A6F629CB4C7D5D156FD84955B470EEFDDEE38B59F0D836B65635B0A63D0998CA1E0BC1FF135",
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F"\
            "707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F",
            "E0E51EAEA6A3134600758EA7F87E88025D8B82897C8DB099B843054C3A51883756913571530BA8FA23003E337627E698"\
            "674B807E847EC6B2292627736562F9F62B2DE9E6AAC5DF74C09A0C5CF80280174AEC9BDD4E73F7D63EDBC29A6922637A",
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F"\
            "707172737475767778797A7B7C7D7E7F80",
            "E0E51EAEA6A3134600758EA7F87E88025D8B82897C8DB099B843054C3A5188374F5254E38066B77FA14FEE3292464B60"\
            "7E8AF1398B2A91C4480B698D64D13AE856",
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F"\
            "303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
            "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F"\
            "909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF",
            "30663E4686574B343A1898E46973CD37DB9D775D356512EB59E723397F2A333CE2C0E96538781FF48EA1D93BDF88FFF8"\
            "BB7BC4FB80A609881220C7FE21881C7374F65B232A8F94CD0E3DDC7614830C23CFCE98ADC5113496F9E106E8C8BFF3AB",
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F"\
            "303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
            "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F"\
            "909192939495969798999A9B9C9D9E9FA0",
            "30663E4686574B343A1898E46973CD37DB9D775D356512EB59E723397F2A333C6DE04CB3235A2DA92493537248DE4368"\
            "879A7CC4166B25C9BFD1AD8EAEA3484BE2",
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F"\
            "303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F"\
            "707172737475767778797A7B7C7D7E7F",
            "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAF"\
            "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"\
            "E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
            "5C6250BD2E40AAE27E1E57512CD38E6A51D0C2B04F0D6A50E0CB43358B8C4E8BA361331436C6FFD38D77BBBBF5FEC56A"\
            "234108A6CC8CB298360943E849E5BD64D26ECA2FA8AEAD070656C3777BA412BCAF3D2F08C26CF86CA8F0921043A15D70"\
            "9AE1112611E22D4396E582CCB661E0F778B6F38561BC338AFD5D1036ED8B322D",
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F"\
            "303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F"\
            "707172737475767778797A7B7C7D7E7F",
            "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAF"\
            "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"\
            "E0",
            "C2822787D3CB2D13168B126583CF28E3B194F153088CF46BD745B22D1776BCB035C6CB17D8C1FBD127954C2A5D5F5AFB"\
            "ECF976E34966AB85142192A2463A541F5C6250BD2E40AAE27E1E57512CD38E6A51D0C2B04F0D6A50E0CB43358B8C4E8B"\
            "A3",
        }
    };

    int i, ret = RET_OK;
    ByteArray* data_ba = NULL;
    ByteArray* key_ba = NULL;
    ByteArray* iv_ba = NULL;
    ByteArray* expected_ba = NULL;
    ByteArray* actual_ba = NULL;
    Dstu7624Ctx* ctx = NULL;

    CHECK_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));

    for (i = 0; i < 10; i++) {
        CHECK_NOT_NULL(data_ba = ba_alloc_from_hex(xts_test_data[i].data));
        CHECK_NOT_NULL(key_ba = ba_alloc_from_hex(xts_test_data[i].key));
        CHECK_NOT_NULL(iv_ba = ba_alloc_from_hex(xts_test_data[i].iv));
        CHECK_NOT_NULL(expected_ba = ba_alloc_from_hex(xts_test_data[i].exp));

        DO(dstu7624_init_xts(ctx, key_ba, iv_ba));
        DO(dstu7624_encrypt(ctx, data_ba, &actual_ba));

        if (ba_cmp(expected_ba, actual_ba) != 0) {
            SET_ERROR(RET_SELF_TEST_FAIL);
        }

        ba_free(actual_ba);
        actual_ba = NULL;

        DO(dstu7624_init_xts(ctx, key_ba, iv_ba));
        DO(dstu7624_decrypt(ctx, expected_ba, &actual_ba));

        if (ba_cmp(data_ba, actual_ba) != 0) {
            SET_ERROR(RET_SELF_TEST_FAIL);
        }

        ba_free(actual_ba);
        actual_ba = NULL;
        ba_free(data_ba);
        data_ba = NULL;
        ba_free(key_ba);
        key_ba = NULL;
        ba_free(iv_ba);
        iv_ba = NULL;
        ba_free(expected_ba);
        expected_ba = NULL;
    }

cleanup:
    ba_free(data_ba);
    ba_free(key_ba);
    ba_free(actual_ba);
    ba_free(iv_ba);
    ba_free(expected_ba);
    dstu7624_free(ctx);
    return ret;
}

static int dstu7624_kw_self_test(void)
{
    static const struct {
        const char* key;
        const char* data;
        const char* exp;
        size_t block_size;
    } kw_test_data[9] = {
        {
            "000102030405060708090A0B0C0D0E0F",
            "101112131415161718191A1B1C1D1E1F",
            "1DC91DC6E52575F6DBED25ADDA95A1B6AD3E15056E489738972C199FB9EE2913",
            16
        },
        {
            "000102030405060708090A0B0C0D0E0F",
            "101112131415161718191A1B1C1D1E1F2021",
            "0EA983D6CE48484D51462C32CC61672210FCC44196ABE635BAF878FDB83E1A63114128585D49DB355C5819FD38039169",
            16
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F",
            "2D09A7C18E6A5A0816331EC27CEA596903F77EC8D63F3BDB73299DE7FD9F4558E05992B0B24B39E02EA496368E0841CC"\
            "1E3FA44556A3048C5A6E9E335717D17D",
            16
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F"\
            "505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
            "BE59D3C3C31B2685A8FA57CD000727F16AF303F0D87BC2D7ABD80DC2796BBC4CDBC4E0408943AF4DAF7DE9084DC81BFE"\
            "F15FDCDD0DF399983DF69BF730D7AE2A199CA4F878E4723B7171DD4D1E8DF59C0F25FA0C20946BA64F9037D724BB1D50"\
            "B6C2BD9788B2AF83EF6163087CD2D4488BC19F3A858D813E3A8947A529B6D65D",
            32
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F"\
            "505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70",
            "CC41D643B08592F509432E3C6F4B73156907A53B9FFB99B157DEC708F917AEA1E41D76475EDFB138A8B0220A152B673E"\
            "9713DE7A2791E3573FE257C3FF3C0DAA9AD13477E52770F54CBF94D1603AED7CA876FB7913BC359D2B89562299FA92D3"\
            "2A9C17DBE4CC21CCE097089B9FBC245580D6DB59F8731D864B604E654397E5F5E7A79A6A777C75856039C8C86140D0CB"\
            "359CA3923D902D08269F8D48E7F0F085",
            32
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F"\
            "303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F"\
            "707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F",
            "599217EB2B5270ECEF0BB716D70E251234A2451CE04FCFBAEEA92022C581F19B7C9386BB7476B4AD721D40778F49062C"\
            "3605F1E8FAC9F3F3AC04E46E89E1844DBF4F18FA9303B288741ABD71013CF208F31B4C76FBE342F89B1ABFD97E830457"\
            "555651B74D3CCDBF94CC5E5EEC22821536A96F44C8BC4346B0271303E67FD313",
            32
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F"\
            "303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F"\
            "707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F90",
            "B92E58F53C38F7D23F1068FA98B921AC800AD0D1947BD620700D0B6088F87D03D6A516F54198154D0C71169C2BCF520F"\
            "3DF3DF527FC23E800E9A65158D45BB253A3BD0493E4822DF0DB5A366BC2F47551C5D477DDDE724A0B869F562223CEDB9"\
            "D4AA36C750FA864ADF938273FBC859F7D4930F6B70C6474304AB670BA32CB0C41023769338A29EA1555F526CDFEB75C7"\
            "2212CD2D29F4BA49C2A62ACBE4F3272B",
            32
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F"\
            "303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F"\
            "707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"\
            "A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF",
            "9618AE6065069D5054464040F17337D58BEB51AE92391D740BDF7ABB239709C46270832039FF045BCF7878E7DA9C3B4C"\
            "F89326CA8B4D29DB8680EEAE1B5A18463284713A323A69AEBF33CFC4B11283C7C8041FFC97668EDF727823411C955981"\
            "6C108C11EC401643765527860D8DA0ED7254792C21DB775DEB1D6971C924CC83EB626173D894694943B1828ABDE8F949"\
            "5BCEBA9AC3A4A03592C085AA29CC9A0C65786E631A702D589B819C89E79EEFF29C4EC312C8860BB68F02272EA770FB8D",
            64
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F"\
            "303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F"\
            "707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"\
            "A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"\
            "D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0",
            "3A05BB41513555F171E9234D4834EDAD16C0BAA6136197650138219C5DA406A703C39259E9DCCF6F2691EC691CE7414B"\
            "5D3CDA006DE6D6C62142FAAA742C5F8AF64FCE95BE7ABA7FE5E06C3C33EE67BAEAB196E3A71132CAE78CD605A22E34D5"\
            "3CD159217E7B692CC79FAC66BF5E08DBC4FE274299474E176DDDF9F462AC63F4872E9B7F16B98AA56707EE5F2F94616C"\
            "FC6A9548ADBD7DCB73664C331213964593F712ECCDFA7A94E3ABA7995176EA4B7E77096A3A3FF4E4087F430B62D5DEE6"\
            "4999F235FA9EAC79896A1C2258BF1DFC8A6AD0E5E7E06EAEEA0CCC2DEF62F67ECE8D12EFF432277C40A7BF1A23440B35"\
            "33AF1E2F7AE1BBC076D12628BB4BC7B2E4D4B4353BCEAF9A67276B3FA23CADCA80062B95EBB2D51510AFA16F97249DF9"\
            "8E7B845C9A410F24B3C8B3E838E58D22BC2D14F46190FC1BFDB60C9691404F99",
            64
        }
    };

    int i, ret = RET_OK;
    ByteArray* data_ba = NULL;
    ByteArray* key_ba = NULL;
    ByteArray* expected_ba = NULL;
    ByteArray* actual_ba = NULL;
    Dstu7624Ctx* ctx = NULL;

    CHECK_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));

    for (i = 0; i < 9; i++) {
        key_ba = ba_alloc_from_hex(kw_test_data[i].key);
        data_ba = ba_alloc_from_hex(kw_test_data[i].data);
        expected_ba = ba_alloc_from_hex(kw_test_data[i].exp);

        DO(dstu7624_init_kw(ctx, key_ba, kw_test_data[i].block_size));
        DO(dstu7624_encrypt(ctx, data_ba, &actual_ba));
        if (ba_cmp(expected_ba, actual_ba) != 0) {
            SET_ERROR(RET_SELF_TEST_FAIL);
        }

        ba_free(actual_ba);
        actual_ba = NULL;

        DO(dstu7624_init_kw(ctx, key_ba, kw_test_data[i].block_size));
        DO(dstu7624_decrypt(ctx, expected_ba, &actual_ba));

        if (ba_cmp(data_ba, actual_ba) != 0) {
            SET_ERROR(RET_SELF_TEST_FAIL);
        }

        ba_free(actual_ba);
        actual_ba = NULL;
        ba_free(expected_ba);
        expected_ba = NULL;
        ba_free(data_ba);
        data_ba = NULL;
        ba_free(key_ba);
        key_ba = NULL;
    }

cleanup:
    ba_free(actual_ba);
    ba_free(expected_ba);
    ba_free(data_ba);
    ba_free(key_ba);
    dstu7624_free(ctx);
    return ret;
}

static int dstu7624_ccm_self_test(void)
{
    static const struct {
        const char* key;
        const char* iv;
        const char* auth_data;
        const char* plain_data;
        const char* exp_h;
        const char* exp_cip;
        size_t q;
        size_t Nb;
    } ccm_test_data[5] = {
        {
            "000102030405060708090A0B0C0D0E0F",
            "101112131415161718191A1B1C1D1E1F",
            "202122232425262728292A2B2C2D2E2F",
            "303132333435363738393A3B3C3D3E3F",
            "26A936173A4DC9160D6E3FDA3A974060",
            "B91A7B8790BBCFCFE65D04E5538E98E2704454C9DD39ADACE0B19D03F6AAB07E",
            16,
            32
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "202122232425262728292A2B2C2D2E2F",
            "303132333435363738393A3B",
            "404142434445464748494A4B4C4D4E",
            "6C47296FF6F64D3FB8351B8407E791D5",
            "EF93E26C7D5EB27111A188722593043585DF9998FE26308ACBA4FC0EB5F2C7",
            16,
            32
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
            "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F",
            "9AB831B4B0BF0FDBC36E4B4FD58F0F00",
            "7EC15C54BB553CB1437BE0EFDD2E810F6058497EBCE4408A08A73FADF3F459D56B0103702D13AB73ACD2EB33A8B5E9CFFF5EB21865A6B499C10C810C4BAEBE80"\
            "9C48AD90A9E12A68380EF1C1B7C83EE1",
            16,
            32
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
            "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
            "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF",
            "924FA0326824355595C98028E84D86279CEA9135FAB35F22054AE3203E68AE46",
            "3EBDB4584B5169A26FBEBA0295B4223F58D5D8A031F2950A1D7764FAB97BA058E9E2DAB90FF0C519AA88435155A71B7B"\
            "53BB100F5D20AFFAC0552F5F2813DEE8DD3653491737B9615A5CCD83DB32F1E479BF227C050325BBBFF60BCA9558D7FE",
            32,
            48
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
            "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF",
            "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
            "D4155EC3D888C8D32FE184AC260FD60F567705E1DF362A6F1F9C287156AA96D91BC4C56F9709E72F3D79CF0A9AC8BDC2BA836BE50E823AB50FB1B39080390923",
            "220642D7277D104788CF97B10210984F506435512F7BF153C5CDABFECC10AFB4A2E2FC51F616AF80FFDD0607FAD4F542B8EF0667717CE3EAAA8FBC303CE76C99"\
            "BD8F80CE149143C04FC2490272A31B029DDADA82F055FE4ABEF452A7D438B21E59C1D8B3DD4606BAD66A6F36300EF3CE0E5F3BB59F11416E80B7FC5A8E8B057A",
            64,
            64
        }
    };

    int i, ret = RET_OK;
    ByteArray* key_ba = NULL;
    ByteArray* iv_ba = NULL;
    ByteArray* au_ba = NULL;
    ByteArray* pl_ba = NULL;
    ByteArray* exp_ba_h = NULL;
    ByteArray* exp_ba_cip = NULL;
    ByteArray* h_ba = NULL;
    ByteArray* actual_ba = NULL;
    Dstu7624Ctx* ctx = NULL;

    CHECK_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));

    for (i = 0; i < 5; i++) {
        CHECK_NOT_NULL(key_ba = ba_alloc_from_hex(ccm_test_data[i].key));
        CHECK_NOT_NULL(iv_ba = ba_alloc_from_hex(ccm_test_data[i].iv));
        CHECK_NOT_NULL(au_ba = ba_alloc_from_hex(ccm_test_data[i].auth_data));
        CHECK_NOT_NULL(pl_ba = ba_alloc_from_hex(ccm_test_data[i].plain_data));
        CHECK_NOT_NULL(exp_ba_h = ba_alloc_from_hex(ccm_test_data[i].exp_h));
        CHECK_NOT_NULL(exp_ba_cip = ba_alloc_from_hex(ccm_test_data[i].exp_cip));

        DO(dstu7624_init_ccm(ctx, key_ba, iv_ba, ccm_test_data[i].q, ccm_test_data[i].Nb));
        DO(dstu7624_encrypt_mac(ctx, au_ba, pl_ba, &h_ba, &actual_ba));

        if (ba_cmp(exp_ba_h, h_ba) != 0) {
            SET_ERROR(RET_SELF_TEST_FAIL);
        }

        ba_free(actual_ba);
        actual_ba = NULL;

        DO(dstu7624_decrypt_mac(ctx, au_ba, exp_ba_cip, h_ba, &actual_ba));

        if (ba_cmp(pl_ba, actual_ba) != 0) {
            SET_ERROR(RET_SELF_TEST_FAIL);
        }

        ba_free(key_ba);
        key_ba = NULL;
        ba_free(iv_ba);
        iv_ba = NULL;
        ba_free(au_ba);
        au_ba = NULL;
        ba_free(pl_ba);
        pl_ba = NULL;
        ba_free(exp_ba_h);
        exp_ba_h = NULL;
        ba_free(h_ba);
        h_ba = NULL;
        ba_free(exp_ba_cip);
        exp_ba_cip = NULL;
        ba_free(actual_ba);
        actual_ba = NULL;
    }

cleanup:
    ba_free(key_ba);
    ba_free(iv_ba);
    ba_free(au_ba);
    ba_free(pl_ba);
    ba_free(exp_ba_h);
    ba_free(h_ba);
    ba_free(exp_ba_cip);
    ba_free(actual_ba);
    dstu7624_free(ctx);
    return ret;
}

static int dstu7624_gmac_self_test(void)
{
    static const struct {
        const char* key;
        const char* data;
        const char* exp;
        size_t q;
        size_t block_size;
    } gmac_test_data[5] = {
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "303132333435363738393A3B3C3D3E3F",
            "5AE309EE80B583C6523397ADCB5704C4",
            16,
            16
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
            "FF48B56F2C26CC484B8F5952D7B3E1FE",
            16,
            32
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
            "FF48B56F2C26CC484B8F5952D7B3E1FE69577701C50BE96517B33921E44634CD",
            32,
            32
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
            "96F61FA0FDE92883C5041D748F9AE91F3A0A50415BFA1466855340A5714DC01F",
            32,
            32
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF",
            "897C32E05E776FD988C5171FE70BB72949172E514E3308A871BA5BD898FB6EBD6E3897D2D55697D90D6428216C08052E3A5E7D4626F4DBBF1546CE21637357A3",
            64,
            64
        }
    };

    int i, ret = RET_OK;
    ByteArray* data_ba = NULL;
    ByteArray* key_ba = NULL;
    ByteArray* expected_ba = NULL;
    ByteArray* actual_ba = NULL;
    Dstu7624Ctx* ctx = NULL;

    CHECK_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));

    for (i = 0; i < 5; i++) {
        CHECK_NOT_NULL(key_ba = ba_alloc_from_hex(gmac_test_data[i].key));
        CHECK_NOT_NULL(data_ba = ba_alloc_from_hex(gmac_test_data[i].data));
        CHECK_NOT_NULL(expected_ba = ba_alloc_from_hex(gmac_test_data[i].exp));

        DO(dstu7624_init_gmac(ctx, key_ba, gmac_test_data[i].block_size, gmac_test_data[i].q));
        DO(dstu7624_update_mac(ctx, data_ba));
        DO(dstu7624_final_mac(ctx, &actual_ba));

        if (ba_cmp(expected_ba, actual_ba) != 0) {
            SET_ERROR(RET_SELF_TEST_FAIL);
        }

        ba_free(actual_ba);
        actual_ba = NULL;
        ba_free(data_ba);
        data_ba = NULL;
        ba_free(key_ba);
        key_ba = NULL;
        ba_free(expected_ba);
        expected_ba = NULL;
    }

cleanup:
    ba_free(data_ba);
    ba_free(key_ba);
    ba_free(actual_ba);
    ba_free(expected_ba);
    dstu7624_free(ctx);
    return ret;
}

static int dstu7624_gcm_self_test(void)
{
    static const struct {
        const char* key;
        const char* iv;
        const char* auth_data;
        const char* plain_data;
        const char* exp_h;
        const char* exp_cip;
        size_t q;
    } gcm_test_data[6] = {
        {
            "000102030405060708090A0B0C0D0E0F",
            "101112131415161718191A1B1C1D1E1F",
            "202122232425262728292A2B2C2D2E2F",
            "303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F",
            "C8310571CD60F9584B45C1B4ECE179AF",
            "B91A7B8790BBCFCFE65D04E5538E98E216AC209DA33122FDA596E8928070BE51",
            16
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "202122232425262728292A2B2C2D2E2F",
            "303132333435363738393A3B3C3D3E3F",
            "505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F",
            "3C474281AFEAE4FD6D61E995258747AB",
            "FF83F27C6D4EA26101B1986235831406A297940D6C0E695596D612623E0E7CDC",
            16
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
            "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F",
            "1D61B0A3018F6B849CBA20AF1DDDA245",
            "7EC15C54BB553CB1437BE0EFDD2E810F6058497EBCE4408A08A73FADF3F459D56B0103702D13AB73ACD2EB33A8B5E9CFFF5EB21865A6B499C10C810C4BAEBE80",
            16
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
            "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F",
            "1D61B0A3018F6B849CBA20AF1DDDA245B1B296258AC0352A52D3F372E72224CE",
            "7EC15C54BB553CB1437BE0EFDD2E810F6058497EBCE4408A08A73FADF3F459D56B0103702D13AB73ACD2EB33A8B5E9CFFF5EB21865A6B499C10C810C4BAEBE80",
            32
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
            "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
            "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF",
            "8555FD3D9B02C2325ACA3CC9309D6B4B9AFC697D13BBBFF067198D5D86CB9820",
            "3EBDB4584B5169A26FBEBA0295B4223F58D5D8A031F2950A1D7764FAB97BA058E9E2DAB90FF0C519AA88435155A71B7B53BB100F5D20AFFAC0552F5F2813DEE8",
            32
        },
        {
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
            "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF",
            "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
            "78A77E5948F5DC05F551486FDBB44898C9AB1BD439D7519841AE31007C09E1B312E5EA5929F952F6A3EEF5CBEAEF262B8EC1884DFCF4BAAF7B5C9291A22489E1",
            "220642D7277D104788CF97B10210984F506435512F7BF153C5CDABFECC10AFB4A2E2FC51F616AF80FFDD0607FAD4F542B8EF0667717CE3EAAA8FBC303CE76C99",
            64
        }
    };

    int i, ret = RET_OK;
    ByteArray* key_ba = NULL;
    ByteArray* iv_ba = NULL;
    ByteArray* au_ba = NULL;
    ByteArray* pl_ba = NULL;
    ByteArray* exp_ba_h = NULL;
    ByteArray* exp_ba_cip = NULL;
    ByteArray* act_h_ba = NULL;
    ByteArray* act_cip_ba = NULL;
    ByteArray* exp_dec_ba = NULL;
    Dstu7624Ctx* ctx = NULL;

    CHECK_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));

    for (i = 0; i < 6; i++) {
        CHECK_NOT_NULL(key_ba = ba_alloc_from_hex(gcm_test_data[i].key));
        CHECK_NOT_NULL(iv_ba = ba_alloc_from_hex(gcm_test_data[i].iv));
        CHECK_NOT_NULL(au_ba = ba_alloc_from_hex(gcm_test_data[i].auth_data));
        CHECK_NOT_NULL(pl_ba = ba_alloc_from_hex(gcm_test_data[i].plain_data));
        CHECK_NOT_NULL(exp_ba_h = ba_alloc_from_hex(gcm_test_data[i].exp_h));
        CHECK_NOT_NULL(exp_ba_cip = ba_alloc_from_hex(gcm_test_data[i].exp_cip));

        DO(dstu7624_init_gcm(ctx, key_ba, iv_ba, gcm_test_data[i].q));
        DO(dstu7624_encrypt_mac(ctx, au_ba, pl_ba, &act_h_ba, &act_cip_ba));
        if ((ba_cmp(exp_ba_h, act_h_ba) != 0) || (ba_cmp(exp_ba_cip, act_cip_ba) != 0)) {
            SET_ERROR(RET_SELF_TEST_FAIL);
        }

        DO(dstu7624_decrypt_mac(ctx, au_ba, act_cip_ba, act_h_ba, &exp_dec_ba));
        if (ba_cmp(pl_ba, exp_dec_ba) != 0) {
            SET_ERROR(RET_SELF_TEST_FAIL);
        }

        ba_free(key_ba);
        key_ba = NULL;
        ba_free(iv_ba);
        iv_ba = NULL;
        ba_free(au_ba);
        au_ba = NULL;
        ba_free(pl_ba);
        pl_ba = NULL;
        ba_free(exp_ba_h);
        exp_ba_h = NULL;
        ba_free(act_h_ba);
        act_h_ba = NULL;
        ba_free(exp_ba_cip);
        exp_ba_cip = NULL;
        ba_free(act_cip_ba);
        act_cip_ba = NULL; 
        ba_free(exp_dec_ba);
        exp_dec_ba = NULL;
    }

cleanup:
    ba_free(key_ba);
    ba_free(iv_ba);
    ba_free(au_ba);
    ba_free(pl_ba);
    ba_free(exp_ba_h);
    ba_free(act_h_ba);
    ba_free(exp_ba_cip);
    ba_free(act_cip_ba);
    ba_free(exp_dec_ba);
    dstu7624_free(ctx);
    return ret;
}

int dstu7624_self_test(void)
{
    int ret = RET_OK;

    DO(dstu7624_ecb_self_test());
    DO(dstu7624_cbc_self_test());
    DO(dstu7624_ofb_self_test());
    DO(dstu7624_cfb_self_test());
    DO(dstu7624_ctr_self_test());
    DO(dstu7624_cmac_self_test());
    DO(dstu7624_xts_self_test());
    DO(dstu7624_kw_self_test());
    DO(dstu7624_ccm_self_test());
    DO(dstu7624_gmac_self_test());
    DO(dstu7624_gcm_self_test());

cleanup:
    return ret;
}