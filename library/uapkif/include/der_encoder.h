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

#ifndef    _DER_ENCODER_H_
#define    _DER_ENCODER_H_

#include "asn_application.h"

#ifdef __cplusplus
extern "C" {
#endif

struct asn_TYPE_descriptor_s;    /* Forward declaration */

/*
 * The DER encoder of any type. May be invoked by the application.
 * The ber_decode() function (ber_decoder.h) is an opposite of der_encode().
 */
UAPKIF_EXPORT asn_enc_rval_t der_encode(struct asn_TYPE_descriptor_s *type_descriptor,
        void *struct_ptr,    /* Structure to be encoded */
        asn_app_consume_bytes_f *consume_bytes_cb,
        void *app_key        /* Arbitrary callback argument */
                                           );

/* A variant of der_encode() which encodes data into the pre-allocated buffer */
UAPKIF_EXPORT asn_enc_rval_t der_encode_to_buffer(
        struct asn_TYPE_descriptor_s *type_descriptor,
        void *struct_ptr,    /* Structure to be encoded */
        void *buffer,        /* Pre-allocated buffer */
        size_t buffer_size    /* Initial buffer size (maximum) */
);

/*
 * Type of the generic DER encoder.
 */
typedef asn_enc_rval_t (der_type_encoder_f)(
        struct asn_TYPE_descriptor_s *type_descriptor,
        void *struct_ptr,    /* Structure to be encoded */
        int tag_mode,        /* {-1,0,1}: IMPLICIT, no, EXPLICIT */
        ber_tlv_tag_t tag,
        asn_app_consume_bytes_f *consume_bytes_cb,    /* Callback */
        void *app_key        /* Arbitrary callback argument */
);


/*******************************
 * INTERNALLY USEFUL FUNCTIONS *
 *******************************/

/*
 * Write out leading TL[v] sequence according to the type definition.
 */
UAPKIF_EXPORT ssize_t der_write_tags(
        struct asn_TYPE_descriptor_s *type_descriptor,
        size_t struct_length,
        int tag_mode,        /* {-1,0,1}: IMPLICIT, no, EXPLICIT */
        int last_tag_form,    /* {0,!0}: prim, constructed */
        ber_tlv_tag_t tag,
        asn_app_consume_bytes_f *consume_bytes_cb,
        void *app_key
);

#ifdef __cplusplus
}
#endif

#endif
