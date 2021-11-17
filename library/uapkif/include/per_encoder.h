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

#ifndef    _PER_ENCODER_H_
#define    _PER_ENCODER_H_

#include "asn_application.h"
#include "per_support.h"

#ifdef __cplusplus
extern "C" {
#endif

struct asn_TYPE_descriptor_s;    /* Forward declaration */

/*
 * Unaligned PER encoder of any ASN.1 type. May be invoked by the application.
 * WARNING: This function returns the number of encoded bits in the .encoded
 * field of the return value. Use the following formula to convert to bytes:
 *     bytes = ((.encoded + 7) / 8)
 */
UAPKIF_EXPORT asn_enc_rval_t uper_encode(struct asn_TYPE_descriptor_s *type_descriptor,
        void *struct_ptr,    /* Structure to be encoded */
        asn_app_consume_bytes_f *consume_bytes_cb,    /* Data collector */
        void *app_key        /* Arbitrary callback argument */
                                            );

/*
 * A variant of uper_encode() which encodes data into the existing buffer
 * WARNING: This function returns the number of encoded bits in the .encoded
 * field of the return value.
 */
UAPKIF_EXPORT asn_enc_rval_t uper_encode_to_buffer(
        struct asn_TYPE_descriptor_s *type_descriptor,
        void *struct_ptr,    /* Structure to be encoded */
        void *buffer,        /* Pre-allocated buffer */
        size_t buffer_size    /* Initial buffer size (max) */
);

/*
 * A variant of uper_encode_to_buffer() which allocates buffer itself.
 * Returns the number of bytes in the buffer or -1 in case of failure.
 * WARNING: This function produces a "Production of the complete encoding",
 * with length of at least one octet. Contrast this to precise bit-packing
 * encoding of uper_encode() and uper_encode_to_buffer().
 */
UAPKIF_EXPORT ssize_t   uper_encode_to_new_buffer(
        struct asn_TYPE_descriptor_s *type_descriptor,
        asn_per_constraints_t *constraints,
        void *struct_ptr,    /* Structure to be encoded */
        void **buffer_r        /* Buffer allocated and returned */
);

/*
 * Type of the generic PER encoder function.
 */
typedef asn_enc_rval_t (per_type_encoder_f)(
        struct asn_TYPE_descriptor_s *type_descriptor,
        asn_per_constraints_t *constraints,
        void *struct_ptr,
        asn_per_outp_t *per_output
);

#ifdef __cplusplus
}
#endif

#endif
