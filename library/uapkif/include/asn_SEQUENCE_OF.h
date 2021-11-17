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

#ifndef    ASN_SEQUENCE_OF_H
#define    ASN_SEQUENCE_OF_H

#include "asn_SET_OF.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * SEQUENCE OF is the same as SET OF with a tiny difference:
 * the delete operation preserves the initial order of elements
 * and thus MAY operate in non-constant time.
 */
#define    A_SEQUENCE_OF(type)    A_SET_OF(type)

#define    ASN_SEQUENCE_ADD(headptr, ptr)        \
    asn_sequence_add((headptr), (ptr))

/***********************************************
 * Implementation of the SEQUENCE OF structure.
 */

#define    asn_sequence_add    asn_set_add
#define    asn_sequence_empty    asn_set_empty

/*
 * Delete the element from the set by its number (base 0).
 * This is NOT a constant-time operation.
 * The order of elements is preserved.
 * If _do_free is given AND the (*free) is initialized, the element
 * will be freed using the custom (*free) function as well.
 */
UAPKIF_EXPORT void asn_sequence_del(void *asn_sequence_of_x, int number, int _do_free);

/*
 * Cope with different conversions requirements to/from void in C and C++.
 * This is mostly useful for support library.
 */
typedef A_SEQUENCE_OF(void) asn_anonymous_sequence_;
#define _A_SEQUENCE_FROM_VOID(ptr)    ((asn_anonymous_sequence_ *)(ptr))
#define _A_CSEQUENCE_FROM_VOID(ptr)     ((const asn_anonymous_sequence_ *)(ptr))

#ifdef __cplusplus
}
#endif

#endif
