/*
 * Copyright 2021 The UAPKI Project Authors.
 * Copyright 2004 Lev Walkin <vlm@lionet.info>. All rights reserved.
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

#ifndef    _PER_SUPPORT_H_
#define    _PER_SUPPORT_H_

#include "asn_system.h"        /* Platform-specific types */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Pre-computed PER constraints.
 */
typedef const struct asn_per_constraint_s {
    enum asn_per_constraint_flags {
        APC_UNCONSTRAINED    = 0x0,    /* No PER visible constraints */
        APC_SEMI_CONSTRAINED    = 0x1,    /* Constrained at "lb" */
        APC_CONSTRAINED        = 0x2,    /* Fully constrained */
        APC_EXTENSIBLE        = 0x4    /* May have extension */
    } flags;
    int  range_bits;        /* Full number of bits in the range */
    int  effective_bits;        /* Effective bits */
    long lower_bound;        /* "lb" value */
    long upper_bound;        /* "ub" value */
} asn_per_constraint_t;
typedef const struct asn_per_constraints_s {
    struct asn_per_constraint_s value;
    struct asn_per_constraint_s size;
    int (*value2code)(unsigned int value);
    int (*code2value)(unsigned int code);
} asn_per_constraints_t;

/*
 * This structure describes a position inside an incoming PER bit stream.
 */
typedef struct asn_per_data_s {
    const uint8_t *buffer;  /* Pointer to the octet stream */
    size_t  nboff;   /* Bit offset to the meaningful bit */
    size_t  nbits;   /* Number of bits in the stream */
    size_t  moved;   /* Number of bits moved through this bit stream */
    int (*refill)(struct asn_per_data_s *);
    void *refill_key;
} asn_per_data_t;

/*
 * Extract a small number of bits (<= 31) from the specified PER data pointer.
 * This function returns -1 if the specified number of bits could not be
 * extracted due to EOD or other conditions.
 */
UAPKIF_EXPORT int32_t per_get_few_bits(asn_per_data_t *per_data, int get_nbits);

/* Undo the immediately preceeding "get_few_bits" operation */
UAPKIF_EXPORT void per_get_undo(asn_per_data_t *per_data, int get_nbits);

/*
 * Extract a large number of bits from the specified PER data pointer.
 * This function returns -1 if the specified number of bits could not be
 * extracted due to EOD or other conditions.
 */
UAPKIF_EXPORT int per_get_many_bits(asn_per_data_t *pd, uint8_t *dst, int right_align,
        int get_nbits);

/*
 * Get the length "n" from the Unaligned PER stream.
 */
UAPKIF_EXPORT ssize_t   uper_get_length(asn_per_data_t *pd,
        int effective_bound_bits,
        int *repeat);

/*
 * Get the normally small length "n".
 */
UAPKIF_EXPORT ssize_t   uper_get_nslength(asn_per_data_t *pd);

/*
 * Get the normally small non-negative whole number.
 */
UAPKIF_EXPORT ssize_t   uper_get_nsnnwn(asn_per_data_t *pd);

/* X.691-2008/11, #11.5.6 */
UAPKIF_EXPORT int uper_get_constrained_whole_number(asn_per_data_t *pd, unsigned long *v, int nbits);

/* Non-thread-safe debugging function, don't use it */
char *per_data_string(asn_per_data_t *pd);

/*
 * This structure supports forming PER output.
 */
typedef struct asn_per_outp_s {
    uint8_t *buffer;    /* Pointer into the (tmpspace) */
    size_t nboff;        /* Bit offset to the meaningful bit */
    size_t nbits;        /* Number of bits left in (tmpspace) */
    uint8_t tmpspace[32];    /* Preliminary storage to hold data */
    int (*outper)(const void *data, size_t size, void *op_key);
    void *op_key;        /* Key for (outper) data callback */
    size_t flushed_bytes;    /* Bytes already flushed through (outper) */
} asn_per_outp_t;

/* Output a small number of bits (<= 31) */
UAPKIF_EXPORT int per_put_few_bits(asn_per_outp_t *per_data, uint32_t bits, int obits);

/* Output a large number of bits */
UAPKIF_EXPORT int per_put_many_bits(asn_per_outp_t *po, const uint8_t *src, int put_nbits);

/* X.691-2008/11, #11.5 */
UAPKIF_EXPORT int uper_put_constrained_whole_number_s(asn_per_outp_t *po, long v, int nbits);
UAPKIF_EXPORT int uper_put_constrained_whole_number_u(asn_per_outp_t *po, unsigned long v, int nbits);

/*
 * Put the length "n" to the Unaligned PER stream.
 * This function returns the number of units which may be flushed
 * in the next units saving iteration.
 */
UAPKIF_EXPORT ssize_t   uper_put_length(asn_per_outp_t *po, size_t whole_length);

/*
 * Put the normally small length "n" to the Unaligned PER stream.
 * Returns 0 or -1.
 */
UAPKIF_EXPORT int uper_put_nslength(asn_per_outp_t *po, size_t length);

/*
 * Put the normally small non-negative whole number.
 */
UAPKIF_EXPORT int uper_put_nsnnwn(asn_per_outp_t *po, int n);

#ifdef __cplusplus
}
#endif

#endif
