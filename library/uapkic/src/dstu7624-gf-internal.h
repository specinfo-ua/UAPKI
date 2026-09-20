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

/* Fixed-field multiplication for Kalyna GCM/GMAC (no per-block allocation).
 * Byte i, bit j represents x^(8*i+j), with no AES-GCM bit reflection.
 * Moduli: x^128 + 0x87, x^256 + 0x425, x^512 + 0x125.
 * Inputs and output may alias. The generic field context owns CPU dispatch.
 */
#define KGF_MAX_LIMBS 8
static inline uint64_t kgf_reduction_const(int m)
{
    return m == 128 ? 0x87u : (m == 256 ? 0x425u : 0x125u);
}

static inline void kgf_bmul64(uint64_t x, uint64_t y, uint64_t *lo, uint64_t *hi)
{
#if defined(__SIZEOF_INT128__)
    typedef unsigned __int128 u128;
    const uint64_t M0 = 0x1084210842108421ull;   /* bits 0, 5, 10, ..., 60 */
    const uint64_t M1 = M0 << 1, M2 = M0 << 2, M3 = M0 << 3, M4 = M0 << 4;
    uint64_t x0 = x & M0, x1 = x & M1, x2 = x & M2, x3 = x & M3, x4 = x & M4;
    uint64_t y0 = y & M0, y1 = y & M1, y2 = y & M2, y3 = y & M3, y4 = y & M4;
    u128 z0, z1, z2, z3, z4;

    z0 = (u128)x0 * y0 ^ (u128)x1 * y4 ^ (u128)x2 * y3 ^ (u128)x3 * y2 ^ (u128)x4 * y1;
    z1 = (u128)x0 * y1 ^ (u128)x1 * y0 ^ (u128)x2 * y4 ^ (u128)x3 * y3 ^ (u128)x4 * y2;
    z2 = (u128)x0 * y2 ^ (u128)x1 * y1 ^ (u128)x2 * y0 ^ (u128)x3 * y4 ^ (u128)x4 * y3;
    z3 = (u128)x0 * y3 ^ (u128)x1 * y2 ^ (u128)x2 * y1 ^ (u128)x3 * y0 ^ (u128)x4 * y4;
    z4 = (u128)x0 * y4 ^ (u128)x1 * y3 ^ (u128)x2 * y2 ^ (u128)x3 * y1 ^ (u128)x4 * y0;

    /* positions p == k (mod 5) in [0,128): low half mask M_k; high half bit q = p - 64, q == k - 64 == k + 1 (mod 5) */
    {
        uint64_t l = (uint64_t)z0 & M0, h = (uint64_t)(z0 >> 64) & M1;
        l |= (uint64_t)z1 & M1; h |= (uint64_t)(z1 >> 64) & M2;
        l |= (uint64_t)z2 & M2; h |= (uint64_t)(z2 >> 64) & M3;
        l |= (uint64_t)z3 & M3; h |= (uint64_t)(z3 >> 64) & M4;
        l |= (uint64_t)z4 & M4; h |= (uint64_t)(z4 >> 64) & M0;
        *lo = l;
        *hi = h;
    }
#else
    /* Compilers without 128-bit integers still have a fixed-work fallback. */
    uint64_t l = x & (0 - (y & 1)), h = 0;
    unsigned int i;
    for (i = 1; i < 64; i++) {
        uint64_t mask = 0 - ((y >> i) & 1);
        l ^= (x << i) & mask;
        h ^= (x >> (64-i)) & mask;
    }
    *lo = l; *hi = h;
#endif
}

/* r[0..2n) = a[0..n) * b[0..n) (schoolbook, unreduced) */
static inline void kgf_mul_limbs_portable(const uint64_t *a, const uint64_t *b, int n, uint64_t *r)
{
    int i, j;
    memset(r, 0, 2 * n * sizeof(uint64_t));
    for (i = 0; i < n; i++) {
        for (j = 0; j < n; j++) {
            uint64_t lo, hi;
            kgf_bmul64(a[i], b[j], &lo, &hi);
            r[i + j] ^= lo;
            r[i + j + 1] ^= hi;
        }
    }
}

/* v * R as 128 bits, R = x^t3 + x^t2 + x^t1 + 1 given by the constant word rc (bit pattern). */
static inline void kgf_mul_rc(uint64_t v, uint64_t rc, uint64_t *lo, uint64_t *hi)
{
    uint64_t l = 0, h = 0;
    while (rc) {
        int t = 0;
        while (!((rc >> t) & 1)) t++;
        l ^= v << t;
        h ^= t ? (v >> (64 - t)) : 0;
        rc &= rc - 1;
    }
    *lo = l;
    *hi = h;
}

/* out[0..n) = p[0..2n) mod f (p destroyed).  Descending fold: limb i (i >= n) * R lands at limbs i-n, i-n+1. */
static inline void kgf_reduce_portable(uint64_t *p, int n, uint64_t rc, uint64_t *out)
{
    int i;
    for (i = 2 * n - 1; i >= n; i--) {
        uint64_t lo, hi;
        kgf_mul_rc(p[i], rc, &lo, &hi);
        p[i - n] ^= lo;
        p[i - n + 1] ^= hi;
    }
    memcpy(out, p, n * sizeof(uint64_t));
}

static void kgf_mul_portable(int m, const uint64_t *a, const uint64_t *b, uint64_t *out)
{
    int n = m >> 6;
    uint64_t p[2 * KGF_MAX_LIMBS];
    kgf_mul_limbs_portable(a, b, n, p);
    kgf_reduce_portable(p, n, kgf_reduction_const(m), out);
}


#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#include <immintrin.h>
#define KGF_CLMUL_TARGET __attribute__((target("pclmul,sse2")))
/* [hi:lo] = a * b, 128 x 128 -> 256 */
KGF_CLMUL_TARGET
static inline void kgf_clmul128(__m128i a, __m128i b, __m128i *lo, __m128i *hi)
{
    __m128i t00 = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i t11 = _mm_clmulepi64_si128(a, b, 0x11);
    __m128i mid;
    mid = _mm_xor_si128(_mm_clmulepi64_si128(a, b, 0x10), _mm_clmulepi64_si128(a, b, 0x01));

    *lo = _mm_xor_si128(t00, _mm_slli_si128(mid, 8));
    *hi = _mm_xor_si128(t11, _mm_srli_si128(mid, 8));
}

/* r[0..3] = a[0..1] * b[0..1], 256 x 256 -> 512, Karatsuba on lane-aligned 128-bit halves (12 clmul) */
KGF_CLMUL_TARGET
static inline void kgf_clmul256(const __m128i *a, const __m128i *b, __m128i *r)
{
    __m128i p0l, p0h, p2l, p2h, p1l, p1h;
    kgf_clmul128(a[0], b[0], &p0l, &p0h);
    kgf_clmul128(a[1], b[1], &p2l, &p2h);
    kgf_clmul128(_mm_xor_si128(a[0], a[1]), _mm_xor_si128(b[0], b[1]), &p1l, &p1h);
    p1l = _mm_xor_si128(_mm_xor_si128(p1l, p0l), p2l);
    p1h = _mm_xor_si128(_mm_xor_si128(p1h, p0h), p2h);
    r[0] = p0l;
    r[1] = _mm_xor_si128(p0h, p1l);
    r[2] = _mm_xor_si128(p2l, p1h);
    r[3] = p2h;
}

/* r[0..7] = a[0..3] * b[0..3], 512 x 512 -> 1024, Karatsuba on 256-bit halves (36 clmul) */
KGF_CLMUL_TARGET
static inline void kgf_clmul512(const __m128i *a, const __m128i *b, __m128i *r)
{
    __m128i p0[4], p2[4], p1[4], as[2], bs[2];
    int i;
    kgf_clmul256(a, b, p0);
    kgf_clmul256(a + 2, b + 2, p2);
    as[0] = _mm_xor_si128(a[0], a[2]);
    as[1] = _mm_xor_si128(a[1], a[3]);
    bs[0] = _mm_xor_si128(b[0], b[2]);
    bs[1] = _mm_xor_si128(b[1], b[3]);
    kgf_clmul256(as, bs, p1);
    for (i = 0; i < 4; i++) {
        p1[i] = _mm_xor_si128(_mm_xor_si128(p1[i], p0[i]), p2[i]);
    }
    r[0] = p0[0];
    r[1] = p0[1];
    r[2] = _mm_xor_si128(p0[2], p1[0]);
    r[3] = _mm_xor_si128(p0[3], p1[1]);
    r[4] = _mm_xor_si128(p2[0], p1[2]);
    r[5] = _mm_xor_si128(p2[1], p1[3]);
    r[6] = p2[2];
    r[7] = p2[3];
}

/*
 * Reduction: every high limb p_i (i >= n) is folded in parallel, T_i = p_i * R lands on limbs (i-n, i-n+1);
 * only the top limb's fold spills above x^m (into limb n): those <= 11 bits, s, are computed directly from
 * p_(2n-1) with shifts (s = p >> (64-t) for each tap t) and folded again as s * R (shift-xor) into limb 0.
 * Chain depth is one clmul + ~3 ops instead of two dependent clmuls.
 */
#define KGF_SPILL(h, t1, t2, t3) \
    _mm_xor_si128(_mm_xor_si128(_mm_srli_epi64(h, 64 - (t1)), _mm_srli_epi64(h, 64 - (t2))), _mm_srli_epi64(h, 64 - (t3)))
#define KGF_MULR_SMALL(s, t1, t2, t3) \
    _mm_xor_si128(_mm_xor_si128(s, _mm_slli_epi64(s, t1)), _mm_xor_si128(_mm_slli_epi64(s, t2), _mm_slli_epi64(s, t3)))

/* mod x^128 + x^7 + x^2 + x + 1: [hi:lo] = [p3:p2:p1:p0] -> 128 bits. 2 clmul, depth 1 clmul. */
KGF_CLMUL_TARGET
static inline __m128i kgf_red128(__m128i lo, __m128i hi)
{
    const __m128i R = _mm_set_epi64x(0, 0x87);
    __m128i t1 = _mm_clmulepi64_si128(hi, R, 0x01);   /* p3*R -> limbs 1,2 (limb 2 part = spill) */
    __m128i t0 = _mm_clmulepi64_si128(hi, R, 0x00);   /* p2*R -> limbs 0,1 */
    __m128i s = KGF_SPILL(hi, 7, 2, 1);            /* lane 1: bits of p3*R above x^128 (7 bits) */
    __m128i sR = KGF_MULR_SMALL(s, 7, 2, 1);          /* lane 1: spill * R (14 bits) -> limb 0 */
    lo = _mm_xor_si128(lo, t0);
    lo = _mm_xor_si128(lo, _mm_slli_si128(t1, 8));
    return _mm_xor_si128(lo, _mm_srli_si128(sR, 8));
}

/* mod x^256 + x^10 + x^5 + x^2 + 1: r[0..3] (8 limbs) -> out[0..1]. 4 clmul, all independent. */
KGF_CLMUL_TARGET
static inline void kgf_red256(__m128i *r, __m128i *out)
{
    const __m128i R = _mm_set_epi64x(0, 0x425);
    __m128i s = KGF_SPILL(r[3], 10, 5, 2);          /* lane 1: p7*R bits above x^256 (11 bits) */
    __m128i sR = KGF_MULR_SMALL(s, 10, 5, 2);          /* lane 1 -> limb 0 */
    __m128i t7 = _mm_clmulepi64_si128(r[3], R, 0x01);  /* -> limbs 3,(4) */
    __m128i t6 = _mm_clmulepi64_si128(r[3], R, 0x00);  /* -> limbs 2,3 */
    __m128i t5 = _mm_clmulepi64_si128(r[2], R, 0x01);  /* -> limbs 1,2 */
    __m128i t4 = _mm_clmulepi64_si128(r[2], R, 0x00);  /* -> limbs 0,1 */
    out[0] = _mm_xor_si128(_mm_xor_si128(r[0], t4), _mm_xor_si128(_mm_slli_si128(t5, 8), _mm_srli_si128(sR, 8)));
    out[1] = _mm_xor_si128(_mm_xor_si128(r[1], t6), _mm_xor_si128(_mm_slli_si128(t7, 8), _mm_srli_si128(t5, 8)));
}

/* mod x^512 + x^8 + x^5 + x^2 + 1: r[0..7] (16 limbs) -> out[0..3]. 8 clmul, all independent. */
KGF_CLMUL_TARGET
static inline void kgf_red512(__m128i *r, __m128i *out)
{
    const __m128i R = _mm_set_epi64x(0, 0x125);
    __m128i s = KGF_SPILL(r[7], 8, 5, 2);
    __m128i sR = KGF_MULR_SMALL(s, 8, 5, 2);
    __m128i tb[4], ta[4];
    int i;
    for (i = 0; i < 4; i++) {
        tb[i] = _mm_clmulepi64_si128(r[4 + i], R, 0x01);   /* limb 2i+9 -> limbs 2i+1, (2i+2) */
        ta[i] = _mm_clmulepi64_si128(r[4 + i], R, 0x00);   /* limb 2i+8 -> limbs 2i, 2i+1 */
    }
    out[0] = _mm_xor_si128(_mm_xor_si128(r[0], ta[0]), _mm_xor_si128(_mm_slli_si128(tb[0], 8), _mm_srli_si128(sR, 8)));
    for (i = 1; i < 4; i++) {
        out[i] = _mm_xor_si128(_mm_xor_si128(r[i], ta[i]), _mm_xor_si128(_mm_slli_si128(tb[i], 8), _mm_srli_si128(tb[i - 1], 8)));
    }
}

KGF_CLMUL_TARGET
static void kgf_mul_clmul(int m, const uint64_t *a, const uint64_t *b, uint64_t *out)
{
    if (m == 128) {
        __m128i lo, hi;
        kgf_clmul128(_mm_loadu_si128((const __m128i *)a), _mm_loadu_si128((const __m128i *)b), &lo, &hi);
        _mm_storeu_si128((__m128i *)out, kgf_red128(lo, hi));
    } else if (m == 256) {
        __m128i av[2], bv[2], r[4], o[2];
        av[0] = _mm_loadu_si128((const __m128i *)a);
        av[1] = _mm_loadu_si128((const __m128i *)a + 1);
        bv[0] = _mm_loadu_si128((const __m128i *)b);
        bv[1] = _mm_loadu_si128((const __m128i *)b + 1);
        kgf_clmul256(av, bv, r);
        kgf_red256(r, o);
        _mm_storeu_si128((__m128i *)out, o[0]);
        _mm_storeu_si128((__m128i *)out + 1, o[1]);
    } else {
        __m128i av[4], bv[4], r[8], o[4];
        int i;
        for (i = 0; i < 4; i++) {
            av[i] = _mm_loadu_si128((const __m128i *)a + i);
            bv[i] = _mm_loadu_si128((const __m128i *)b + i);
        }
        kgf_clmul512(av, bv, r);
        kgf_red512(r, o);
        for (i = 0; i < 4; i++) {
            _mm_storeu_si128((__m128i *)out + i, o[i]);
        }
    }
}


#undef KGF_CLMUL_TARGET
#undef KGF_SPILL
#undef KGF_MULR_SMALL
#endif

static void kalyna_field_mul(int accelerated, size_t bytes, const uint8_t *a,
    const uint8_t *b, uint8_t *out)
{
    uint64_t av[8], bv[8], result[8];
    size_t i;
    for (i = 0; i < bytes / 8; i++) {
        av[i] = load64le(a + 8*i);
        bv[i] = load64le(b + 8*i);
    }
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
    if (accelerated) kgf_mul_clmul((int)bytes * 8, av, bv, result);
    else
#endif
    kgf_mul_portable((int)bytes * 8, av, bv, result);
    for (i = 0; i < bytes / 8; i++) store64le(out + 8*i, result[i]);
}

static void kalyna_field_mulx(size_t bytes, uint8_t *a)
{
    uint8_t carry = 0;
    uint64_t reduction = kgf_reduction_const((int)bytes * 8);
    size_t i;
    for (i = 0; i < bytes; i++) {
        uint8_t next = a[i] >> 7;
        a[i] = (uint8_t)((a[i] << 1) | carry);
        carry = next;
    }
    a[0] ^= (uint8_t)reduction & (uint8_t)(0 - carry);
    a[1] ^= (uint8_t)(reduction >> 8) & (uint8_t)(0 - carry);
}
#undef KGF_MAX_LIMBS
