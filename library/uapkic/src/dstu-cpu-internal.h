/* Internal, baseline-ISA dispatch for the optional DSTU vector kernels. */
#ifndef DSTU_CPU_INTERNAL_H
#define DSTU_CPU_INTERNAL_H

/* Older compilers and non-x86 targets compile only the portable implementation. */
#if !defined(UAPKIC_NO_AVX512) && defined(__x86_64__) && \
    ((defined(__clang__) && __clang_major__ >= 10) || \
     (!defined(__clang__) && defined(__GNUC__) && __GNUC__ >= 9))
#define DSTU_AVX512 1
#define DSTU_TARGET __attribute__((target("avx512f,avx512bw,avx512vl,avx512vbmi,gfni")))
#else
#define DSTU_AVX512 0
#endif

int dstu_avx512_available(void);

#endif
