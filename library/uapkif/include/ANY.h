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

#ifndef ASN_TYPE_ANY_H
#define ASN_TYPE_ANY_H

#include "OCTET_STRING.h"    /* Implemented via OCTET STRING type */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ANY {
    uint8_t *buf;    /* BER-encoded ANY contents */
    int size;        /* Size of the above buffer */

    asn_struct_ctx_t _asn_ctx;    /* Parsing across buffer boundaries */
} ANY_t;

extern asn_TYPE_descriptor_t ANY_desc;
UAPKIF_EXPORT asn_TYPE_descriptor_t *get_ANY_desc(void);

asn_struct_free_f ANY_free;
asn_struct_print_f ANY_print;
ber_type_decoder_f ANY_decode_ber;
der_type_encoder_f ANY_encode_der;
xer_type_encoder_f ANY_encode_xer;

/******************************
 * Handy conversion routines. *
 ******************************/

/* Convert another ASN.1 type into the ANY. This implies DER encoding. */
UAPKIF_EXPORT int ANY_fromType(ANY_t *, asn_TYPE_descriptor_t *td, void *struct_ptr);
UAPKIF_EXPORT ANY_t *ANY_new_fromType(asn_TYPE_descriptor_t *td, void *struct_ptr);

/* Convert the contents of the ANY type into the specified type. */
UAPKIF_EXPORT int ANY_to_type(const ANY_t *, asn_TYPE_descriptor_t *td, void **struct_ptr);

#define    ANY_fromBuf(s, buf, size)    OCTET_STRING_fromBuf((s), (buf), (size))
#define    ANY_new_fromBuf(buf, size)    OCTET_STRING_new_fromBuf(    \
                        &ANY_desc, (buf), (size))

#ifdef __cplusplus
}
#endif

#endif
