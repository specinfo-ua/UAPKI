/*
 * Copyright 2026 The UAPKI Project Authors.
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

/* Kupyna compression and final transform. The S-box stays in registers;
 * byte permutations and GFNI implement the DSTU 7564 linear transform.
 * Tables are immutable. Dispatch happens before entering any vector function.
 */
#include "dstu-cpu-internal.h"
#if DSTU_AVX512
#include <immintrin.h>
#include <stddef.h>
#include <stdint.h>
#include "dstu7564-avx512-tables.h"

typedef struct { __m512i t[4][4]; } SboxRegs;
DSTU_TARGET static inline __attribute__((always_inline)) __m512i sub_bytes(const SboxRegs *T, __m512i x)
{
    const __mmask64 K1 = 0x2222222222222222ULL,
                    K2 = 0x4444444444444444ULL, K3 = 0x8888888888888888ULL;
    __mmask64 m7 = _mm512_movepi8_mask(x);
    __m512i l0 = _mm512_permutex2var_epi8(T->t[0][0], x, (T->t[0][1]));
    __m512i h0 = _mm512_permutex2var_epi8(T->t[0][2], x, (T->t[0][3]));
    __m512i l1 = _mm512_permutex2var_epi8(T->t[1][0], x, (T->t[1][1]));
    __m512i h1 = _mm512_permutex2var_epi8(T->t[1][2], x, (T->t[1][3]));
    __m512i r0 = _mm512_mask_blend_epi8(m7, l0, h0);
    __m512i l2 = _mm512_permutex2var_epi8(T->t[2][0], x, (T->t[2][1]));
    __m512i h2 = _mm512_permutex2var_epi8(T->t[2][2], x, (T->t[2][3]));
    __m512i r1 = _mm512_mask_blend_epi8(m7, l1, h1);
    __m512i l3 = _mm512_permutex2var_epi8(T->t[3][0], x, (T->t[3][1]));
    __m512i h3 = _mm512_permutex2var_epi8(T->t[3][2], x, (T->t[3][3]));
    __m512i r01 = _mm512_mask_blend_epi8(K1, r0, r1);
    __m512i r2 = _mm512_mask_blend_epi8(m7, l2, h2);
    __m512i r012 = _mm512_mask_blend_epi8(K2, r01, r2);
    __m512i r3 = _mm512_mask_blend_epi8(m7, l3, h3);
    return _mm512_mask_blend_epi8(K3, r012, r3);
}
DSTU_TARGET static inline __attribute__((always_inline)) __m512i shift_mix(__m512i y, __m512i extra, const __m512i *shidx, const __m512i *fused)
{
    (void)shidx;
    __m512i a4 = _mm512_gf2p8affine_epi64_epi8(y, _mm512_set1_epi64((long long)0x408041c2c4881020ULL), 0);
    __m512i a8 = _mm512_gf2p8affine_epi64_epi8(y, _mm512_set1_epi64((long long)0x2040a061e2c48810ULL), 0);
    __m512i a6 = _mm512_gf2p8affine_epi64_epi8(y, _mm512_set1_epi64((long long)0xc081c3464c983060ULL), 0);
    __m512i w0 = _mm512_permutexvar_epi8(fused[0], y);
    __m512i w1 = _mm512_permutexvar_epi8(fused[1], y);
    __m512i w3 = _mm512_permutexvar_epi8(fused[3], y);
    __m512i t1 = _mm512_ternarylogic_epi64(w0, w1, w3, 0x96);
    __m512i w4 = _mm512_permutexvar_epi8(fused[4], a8);
    __m512i w7 = _mm512_permutexvar_epi8(fused[7], a4);
    __m512i w5 = _mm512_permutexvar_epi8(fused[5], a6);
    __m512i a5 = _mm512_xor_si512(a4, y);
    __m512i a7 = _mm512_xor_si512(a6, y);
    __m512i t2 = _mm512_ternarylogic_epi64(t1, w4, extra, 0x96);
    __m512i w2 = _mm512_permutexvar_epi8(fused[2], a5);
    __m512i w6 = _mm512_permutexvar_epi8(fused[6], a7);
    __m512i t3 = _mm512_ternarylogic_epi64(t2, w7, w5, 0x96);
    return _mm512_ternarylogic_epi64(t3, w2, w6, 0x96);
}
DSTU_TARGET static inline __attribute__((always_inline)) __m512i round_P(const SboxRegs *T, __m512i p, __m512i next_const, const __m512i *shidx, const __m512i *fused)
{
    return shift_mix(sub_bytes(T, p), next_const, shidx, fused);
}
DSTU_TARGET static inline __attribute__((always_inline)) __m512i round_Q(const SboxRegs *T, __m512i q, const __m512i *qc, const __m512i *shidx, const __m512i *fused)
{
    return shift_mix(sub_bytes(T, _mm512_add_epi64(q, *qc)), _mm512_setzero_si512(), shidx, fused);
}
DSTU_TARGET static inline __attribute__((always_inline)) void kupyna512_blocks(uint64_t state[8], const uint8_t *msg, size_t nblocks, const SboxRegs *T)
{
    const __m512i shidx = _mm512_load_si512(shift512_idx);
    __m512i fused[8];
    for (int t = 0; t < 8; t++) fused[t] = _mm512_load_si512(shrot512_idx[t]);
    __m512i h = _mm512_loadu_si512(state);
    const __m512i *PC = (const __m512i *)pconst512, *QC = (const __m512i *)qconst512;
    while (nblocks--) {
        __m512i m = _mm512_loadu_si512(msg);
        msg += 64;
        __m512i p = _mm512_ternarylogic_epi64(h, m, PC[0], 0x96);
        __m512i q = m;
        for (int r = 0; r < 10; r++) {
            p = round_P(T, p, (r < 9) ? PC[r + 1] : h, &shidx, fused);
            q = round_Q(T, q, QC + r, &shidx, fused);
        }
        h = _mm512_xor_si512(p, q);
    }
    _mm512_storeu_si512(state, h);
}
DSTU_TARGET static inline __attribute__((always_inline)) void kupyna512_output_transform(uint64_t state[8], const SboxRegs *T)
{
    const __m512i shidx = _mm512_load_si512(shift512_idx);
    __m512i fused[8];
    for (int t = 0; t < 8; t++) fused[t] = _mm512_load_si512(shrot512_idx[t]);
    const __m512i *PC = (const __m512i *)pconst512;
    __m512i h = _mm512_loadu_si512(state);
    __m512i p = _mm512_xor_si512(h, PC[0]);
    for (int r = 0; r < 10; r++) p = round_P(T, p, (r < 9) ? PC[r + 1] : h, &shidx, fused);
    _mm512_storeu_si512(state, p);
}
DSTU_TARGET static inline __attribute__((always_inline)) void shift_mix_1024(__m512i *y0, __m512i *y1, __m512i e0, __m512i e1, const __m512i *sh, const __m512i (*fused)[2])
{
    (void)sh;
    __m512i y0v = *y0, y1v = *y1;
    __m512i a4_0 = _mm512_gf2p8affine_epi64_epi8(y0v, _mm512_set1_epi64((long long)0x408041c2c4881020ULL), 0), a4_1 = _mm512_gf2p8affine_epi64_epi8(y1v, _mm512_set1_epi64((long long)0x408041c2c4881020ULL), 0);
    __m512i a8_0 = _mm512_gf2p8affine_epi64_epi8(y0v, _mm512_set1_epi64((long long)0x2040a061e2c48810ULL), 0), a8_1 = _mm512_gf2p8affine_epi64_epi8(y1v, _mm512_set1_epi64((long long)0x2040a061e2c48810ULL), 0);
    __m512i a6_0 = _mm512_gf2p8affine_epi64_epi8(y0v, _mm512_set1_epi64((long long)0xc081c3464c983060ULL), 0), a6_1 = _mm512_gf2p8affine_epi64_epi8(y1v, _mm512_set1_epi64((long long)0xc081c3464c983060ULL), 0);
    __m512i a5_0 = _mm512_xor_si512(a4_0, y0v), a5_1 = _mm512_xor_si512(a4_1, y1v);
    __m512i a7_0 = _mm512_xor_si512(a6_0, y0v), a7_1 = _mm512_xor_si512(a6_1, y1v);
    __m512i n[2];
    for (int half = 0; half < 2; half++) {
        __m512i w0 = _mm512_permutex2var_epi8(y0v, fused[0][half], y1v);
        __m512i w1 = _mm512_permutex2var_epi8(y0v, fused[1][half], y1v);
        __m512i w3 = _mm512_permutex2var_epi8(y0v, fused[3][half], y1v);
        __m512i t1 = _mm512_ternarylogic_epi64(w0, w1, w3, 0x96);
        __m512i w4 = _mm512_permutex2var_epi8(a8_0, fused[4][half], a8_1);
        __m512i w7 = _mm512_permutex2var_epi8(a4_0, fused[7][half], a4_1);
        __m512i w5 = _mm512_permutex2var_epi8(a6_0, fused[5][half], a6_1);
        __m512i t2 = _mm512_ternarylogic_epi64(t1, w4, half ? e1 : e0, 0x96);
        __m512i w2 = _mm512_permutex2var_epi8(a5_0, fused[2][half], a5_1);
        __m512i w6 = _mm512_permutex2var_epi8(a7_0, fused[6][half], a7_1);
        __m512i t3 = _mm512_ternarylogic_epi64(t2, w7, w5, 0x96);
        n[half] = _mm512_ternarylogic_epi64(t3, w2, w6, 0x96);
    }
    *y0 = n[0]; *y1 = n[1];
}
DSTU_TARGET static inline __attribute__((always_inline)) void kupyna1024_blocks(uint64_t state[16], const uint8_t *msg, size_t nblocks, const SboxRegs *T)
{
    __m512i sh[2] = { _mm512_load_si512(shift1024_idx[0]), _mm512_load_si512(shift1024_idx[1]) };
    __m512i fused[8][2];
    for (int t = 0; t < 8; t++) { fused[t][0] = _mm512_load_si512(shrot1024_idx[t][0]); fused[t][1] = _mm512_load_si512(shrot1024_idx[t][1]); }
    const __m512i *PC = (const __m512i *)pconst1024, *QC = (const __m512i *)qconst1024;
    __m512i h0 = _mm512_loadu_si512(state), h1 = _mm512_loadu_si512(state + 8);
    while (nblocks--) {
        __m512i m0 = _mm512_loadu_si512(msg), m1 = _mm512_loadu_si512(msg + 64);
        msg += 128;
        __m512i p0 = _mm512_ternarylogic_epi64(h0, m0, PC[0], 0x96);
        __m512i p1 = _mm512_ternarylogic_epi64(h1, m1, PC[1], 0x96);
        __m512i q0 = m0, q1 = m1;
        for (int r = 0; r < 14; r++) {
            p0 = sub_bytes(T, p0); p1 = sub_bytes(T, p1);
            shift_mix_1024(&p0, &p1, (r < 13) ? PC[2 * r + 2] : h0, (r < 13) ? PC[2 * r + 3] : h1, sh, fused);
            q0 = sub_bytes(T, _mm512_add_epi64(q0, QC[2 * r])); q1 = sub_bytes(T, _mm512_add_epi64(q1, QC[2 * r + 1]));
            shift_mix_1024(&q0, &q1, _mm512_setzero_si512(), _mm512_setzero_si512(), sh, fused);
        }
        h0 = _mm512_xor_si512(p0, q0);
        h1 = _mm512_xor_si512(p1, q1);
    }
    _mm512_storeu_si512(state, h0);
    _mm512_storeu_si512(state + 8, h1);
}
DSTU_TARGET static inline __attribute__((always_inline)) void kupyna1024_output_transform(uint64_t state[16], const SboxRegs *T)
{
    __m512i sh[2] = { _mm512_load_si512(shift1024_idx[0]), _mm512_load_si512(shift1024_idx[1]) };
    __m512i fused[8][2];
    for (int t = 0; t < 8; t++) { fused[t][0] = _mm512_load_si512(shrot1024_idx[t][0]); fused[t][1] = _mm512_load_si512(shrot1024_idx[t][1]); }
    const __m512i *PC = (const __m512i *)pconst1024;
    __m512i h0 = _mm512_loadu_si512(state), h1 = _mm512_loadu_si512(state + 8);
    __m512i p0 = _mm512_xor_si512(h0, PC[0]), p1 = _mm512_xor_si512(h1, PC[1]);
    for (int r = 0; r < 14; r++) {
        p0 = sub_bytes(T, p0); p1 = sub_bytes(T, p1);
        shift_mix_1024(&p0, &p1, (r < 13) ? PC[2 * r + 2] : h0, (r < 13) ? PC[2 * r + 3] : h1, sh, fused);
    }
    _mm512_storeu_si512(state, p0);
    _mm512_storeu_si512(state + 8, p1);
}
DSTU_TARGET
static void load_sbox_regs(SboxRegs *T)
{
    for (int s = 0; s < 4; s++) for (int q = 0; q < 4; q++) T->t[s][q] = _mm512_load_si512(sbox[s] + 64 * q);
}

DSTU_TARGET static void digest_avx512(uint64_t *state, const uint8_t *data,
    size_t blocks, size_t columns)
{
    SboxRegs tables;
    load_sbox_regs(&tables);
    if (columns == 8) kupyna512_blocks(state, data, blocks, &tables);
    else kupyna1024_blocks(state, data, blocks, &tables);
}

DSTU_TARGET static void output_avx512(uint64_t *state, size_t columns)
{
    SboxRegs tables;
    load_sbox_regs(&tables);
    if (columns == 8) kupyna512_output_transform(state, &tables);
    else kupyna1024_output_transform(state, &tables);
}
#endif
