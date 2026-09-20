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

/* Kalyna-256/256 forward cipher, sixteen independent blocks per call.
 * Row-pair layout: R[k][8*b + 4*h + c] holds row k+4*h, column c,
 * block b. The initial/final modular additions use column layout.
 * Only the default S-box and 14-round 256/256 schedule enter this kernel.
 */
#include "dstu-cpu-internal.h"
#if DSTU_AVX512
#include <immintrin.h>
#include "dstu7624-avx512-tables.h"

typedef struct {
    uint64_t k0x2[8], kNx2[8];
    uint64_t rk_rp[15][4];
} K256Simd;

static void k256_prepare(const uint64_t *rk, K256Simd *p)
{
    int i, k, h, c;
    memset(p, 0, sizeof(*p));
    for (c = 0; c < 8; c++) {
        p->k0x2[c] = rk[c % 4];
        p->kNx2[c] = rk[56 + c % 4];
    }
    for (i = 1; i < 14; i++)
        for (k = 0; k < 4; k++)
            for (h = 0; h < 2; h++)
                for (c = 0; c < 4; c++)
                    p->rk_rp[i][k] |= ((rk[4*i+c] >> (8*(k+4*h))) & 255) << (8*(4*h+c));
}

#define A_MUL2 0x8001828488102040ULL
#define A_MUL4 0x408041c2c4881020ULL
#define A_MUL5 0x418245cad4a850a0ULL
#define A_MUL6 0xc081c3464c983060ULL
#define A_MUL7 0xc183c74e5cb870e0ULL
#define A_MUL8 0x2040a061e2c48810ULL

#define LD(p) _mm512_loadu_si512((const void *)(p))
#define BCST(q) _mm512_set1_epi64((long long)(q))
#define TERN(a,b,c,imm) _mm512_ternarylogic_epi64((a),(b),(c),(imm))
#define X3(a,b,c) TERN((a),(b),(c),0x96)
#define AFF(x, m) _mm512_gf2p8affine_epi64_epi8((x), BCST(m), 0)
#define CONV_IN(in, z0,z1,z2,z3, R0,R1,R2,R3) \
    z0 = _mm512_loadu_si512(in); z1 = _mm512_loadu_si512(in + 64); z2 = _mm512_loadu_si512(in + 128); z3 = _mm512_loadu_si512(in + 192); \
    z0 = _mm512_add_epi64(z0, k0); z1 = _mm512_add_epi64(z1, k0); z2 = _mm512_add_epi64(z2, k0); z3 = _mm512_add_epi64(z3, k0); \
    { __m512i va = _mm512_permutex2var_epi8(z0, ia, z1), vb = _mm512_permutex2var_epi8(z0, ib, z1); \
      __m512i vc = _mm512_permutex2var_epi8(z2, ia, z3), vd = _mm512_permutex2var_epi8(z2, ib, z3); \
      R0 = _mm512_shuffle_i64x2(va, vc, 0x44); R1 = _mm512_shuffle_i64x2(va, vc, 0xEE); \
      R2 = _mm512_shuffle_i64x2(vb, vd, 0x44); R3 = _mm512_shuffle_i64x2(vb, vd, 0xEE); }
#define CONV_OUT(out, R0,R1,R2,R3) \
    { __m512i va = _mm512_shuffle_i64x2(R0, R1, 0x44), vc = _mm512_shuffle_i64x2(R0, R1, 0xEE); \
      __m512i vb = _mm512_shuffle_i64x2(R2, R3, 0x44), vd = _mm512_shuffle_i64x2(R2, R3, 0xEE); \
      __m512i o0 = LD(idx_out_0), o1 = LD(idx_out_1); \
      _mm512_storeu_si512(out,       _mm512_add_epi64(_mm512_permutex2var_epi8(va, o0, vb), kN)); \
      _mm512_storeu_si512(out + 64,  _mm512_add_epi64(_mm512_permutex2var_epi8(va, o1, vb), kN)); \
      _mm512_storeu_si512(out + 128, _mm512_add_epi64(_mm512_permutex2var_epi8(vc, o0, vd), kN)); \
      _mm512_storeu_si512(out + 192, _mm512_add_epi64(_mm512_permutex2var_epi8(vc, o1, vd), kN)); }

#define SR8_SHUFD(B0,B1,B2,B3,W) \
    W[0] = _mm512_shuffle_epi8(B0, sR0); W[1] = _mm512_shuffle_epi8(B1, sR1); W[2] = _mm512_shuffle_epi8(B2, sR2); W[3] = _mm512_shuffle_epi8(B3, sR3); \
    W[4] = _mm512_shuffle_epi32(W[0], (_MM_PERM_ENUM)0xB1); W[5] = _mm512_shuffle_epi32(W[1], (_MM_PERM_ENUM)0xB1); \
    W[6] = _mm512_shuffle_epi32(W[2], (_MM_PERM_ENUM)0xB1); W[7] = _mm512_shuffle_epi32(W[3], (_MM_PERM_ENUM)0xB1);
DSTU_TARGET static inline __attribute__((always_inline)) __m512i sbox_mem(__m512i x, const uint8_t (*t)[64], __m512i ones) {
    __m512i lo = _mm512_permutex2var_epi8(LD(t[0]), x, LD(t[1]));
    __m512i hi = _mm512_permutex2var_epi8(LD(t[2]), x, LD(t[3]));
    __m512i m  = _mm512_shuffle_epi8(ones, x);
    return TERN(m, lo, hi, 0xCA);
}
DSTU_TARGET static inline __attribute__((always_inline)) __m512i mc_xtime_p(const __m512i *W, int j, const uint64_t *kq) {
    __m512i w0 = W[(j+0)&7], w1 = W[(j+1)&7], w2 = W[(j+2)&7], w3 = W[(j+3)&7];
    __m512i w4 = W[(j+4)&7], w5 = W[(j+5)&7], w6 = W[(j+6)&7], w7 = W[(j+7)&7];
    __m512i a = X3(X3(w0, w1, w2), w3, w6);
    __m512i b = _mm512_xor_si512(w5, w6);
    __m512i c = X3(b, w2, w7);
    __m512i r = X3(a, AFF(b, A_MUL2), AFF(c, A_MUL4));
    return X3(r, AFF(w4, A_MUL8), _mm512_set1_epi64((long long)kq[j]));
}
DSTU_TARGET static inline __attribute__((always_inline)) __m512i mc_direct_p(const __m512i *W, int j, const uint64_t *kq) {
    __m512i w0 = W[(j+0)&7], w1 = W[(j+1)&7], w2 = W[(j+2)&7], w3 = W[(j+3)&7];
    __m512i w4 = W[(j+4)&7], w5 = W[(j+5)&7], w6 = W[(j+6)&7], w7 = W[(j+7)&7];
    __m512i t1 = X3(w0, w1, w3);
    __m512i t2 = X3(AFF(w2, A_MUL5), AFF(w4, A_MUL8), AFF(w5, A_MUL6));
    __m512i t3 = X3(AFF(w6, A_MUL7), AFF(w7, A_MUL4), _mm512_set1_epi64((long long)kq[j]));
    return X3(t1, t2, t3);
}
DSTU_TARGET static void kalyna256_encrypt16(const K256Simd *p, const uint8_t *in, uint8_t *out) {
    __m512i k0 = LD(p->k0x2), kN = LD(p->kNx2), ia = LD(idx_in_a), ib = LD(idx_in_b);
    __m512i z0, z1, z2, z3, R0, R1, R2, R3, Q0, Q1, Q2, Q3;
    CONV_IN(in, z0,z1,z2,z3, R0,R1,R2,R3)
    CONV_IN(in + 256, z0,z1,z2,z3, Q0,Q1,Q2,Q3)
    __m512i sR0 = LD(shuf_R[0]), sR1 = LD(shuf_R[1]), sR2 = LD(shuf_R[2]), sR3 = LD(shuf_R[3]);
    __m512i ones = _mm512_set1_epi8((char)0xff);
    for (int rnd = 1; rnd <= 14; rnd++) {
        __m512i W[8], V[8], b0, b1, b2, b3;
        b0 = sbox_mem(R0, kalyna_sbox[0], ones); b1 = sbox_mem(R1, kalyna_sbox[1], ones); b2 = sbox_mem(R2, kalyna_sbox[2], ones); b3 = sbox_mem(R3, kalyna_sbox[3], ones);
        SR8_SHUFD(b0,b1,b2,b3,W)
        b0 = sbox_mem(Q0, kalyna_sbox[0], ones); b1 = sbox_mem(Q1, kalyna_sbox[1], ones); b2 = sbox_mem(Q2, kalyna_sbox[2], ones); b3 = sbox_mem(Q3, kalyna_sbox[3], ones);
        SR8_SHUFD(b0,b1,b2,b3,V)
        const uint64_t *kq = p->rk_rp[rnd];
        R0 = mc_direct_p(W, 0, kq); R1 = mc_xtime_p(W, 1, kq); R2 = mc_direct_p(W, 2, kq); R3 = mc_xtime_p(W, 3, kq);
        Q0 = mc_direct_p(V, 0, kq); Q1 = mc_xtime_p(V, 1, kq); Q2 = mc_direct_p(V, 2, kq); Q3 = mc_xtime_p(V, 3, kq);
    }
    CONV_OUT(out, R0,R1,R2,R3)
    CONV_OUT(out + 256, Q0,Q1,Q2,Q3)
}

#undef A_MUL2
#undef A_MUL4
#undef A_MUL5
#undef A_MUL6
#undef A_MUL7
#undef A_MUL8
#undef LD
#undef BCST
#undef TERN
#undef X3
#undef AFF
#undef CONV_IN
#undef CONV_OUT
#undef SR8_SHUFD
#endif
