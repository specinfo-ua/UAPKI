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

/* Forward rounds for full-feedback 256/256 CFB. Used only with the
 * immutable default S-box. Inlining keeps feedback words in registers between
 * blocks; the two-block form also serves the portable decryption path.
 */
#if defined(__GNUC__)
#define KALYNA_INLINE static __inline __attribute__((always_inline))
#define KALYNA_UNROLL _Pragma("GCC unroll 8")
#else
#define KALYNA_INLINE static __inline
#define KALYNA_UNROLL
#endif
#define T subrowcol_default
#define B(x, k) ((uint8_t)((x) >> (8 * (k))))
#define NB 4
#define TL(s, c, k) T[k][B(s[((c) - (((k) * NB) >> 3)) & (NB - 1)], k)]
#define COLN(s, c) (TL(s,c,0) ^ TL(s,c,1) ^ TL(s,c,2) ^ TL(s,c,3) ^ TL(s,c,4) ^ TL(s,c,5) ^ TL(s,c,6) ^ TL(s,c,7))

// one block, words in/out (in-place), rounds from ctx
KALYNA_INLINE void kalyna256_scalar1(const uint64_t *rk, size_t rounds, uint64_t *s)
{
    uint64_t p[NB]; const uint64_t *k = rk;
    KALYNA_UNROLL for (int w = 0; w < NB; w++) s[w] += k[w];
    k += NB;
    for (size_t r = 1; r + 2 < rounds; r += 2) {
        KALYNA_UNROLL for (int c = 0; c < NB; c++) p[c] = COLN(s, c) ^ k[c];
        k += NB;
        KALYNA_UNROLL for (int c = 0; c < NB; c++) s[c] = COLN(p, c) ^ k[c];
        k += NB;
    }
    KALYNA_UNROLL for (int c = 0; c < NB; c++) p[c] = COLN(s, c) ^ k[c];
    k += NB;
    KALYNA_UNROLL for (int c = 0; c < NB; c++) s[c] = COLN(p, c) + k[c];
}
// two independent blocks interleaved
KALYNA_INLINE void kalyna256_scalar2(const uint64_t *rk, size_t rounds, uint64_t *s, uint64_t *t)
{
    uint64_t p[NB], q[NB]; const uint64_t *k = rk;
    KALYNA_UNROLL for (int w = 0; w < NB; w++) { s[w] += k[w]; t[w] += k[w]; }
    k += NB;
    for (size_t r = 1; r + 2 < rounds; r += 2) {
        KALYNA_UNROLL for (int c = 0; c < NB; c++) p[c] = COLN(s, c) ^ k[c];
        KALYNA_UNROLL for (int c = 0; c < NB; c++) q[c] = COLN(t, c) ^ k[c];
        k += NB;
        KALYNA_UNROLL for (int c = 0; c < NB; c++) s[c] = COLN(p, c) ^ k[c];
        KALYNA_UNROLL for (int c = 0; c < NB; c++) t[c] = COLN(q, c) ^ k[c];
        k += NB;
    }
    KALYNA_UNROLL for (int c = 0; c < NB; c++) p[c] = COLN(s, c) ^ k[c];
    KALYNA_UNROLL for (int c = 0; c < NB; c++) q[c] = COLN(t, c) ^ k[c];
    k += NB;
    KALYNA_UNROLL for (int c = 0; c < NB; c++) s[c] = COLN(p, c) + k[c];
    KALYNA_UNROLL for (int c = 0; c < NB; c++) t[c] = COLN(q, c) + k[c];
}


#undef T
#undef B
#undef NB
#undef TL
#undef COLN
#undef KALYNA_INLINE
#undef KALYNA_UNROLL
