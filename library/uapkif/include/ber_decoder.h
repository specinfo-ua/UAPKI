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

#ifndef    _BER_DECODER_H_
#define    _BER_DECODER_H_

#include "asn_application.h"

#ifdef __cplusplus
extern "C" {
#endif

struct asn_TYPE_descriptor_s;    /* Forward declaration */
struct asn_codec_ctx_s;        /* Forward declaration */

/*
 * The BER decoder of any type.
 * This function may be invoked directly from the application.
 * The der_encode() function (der_encoder.h) is an opposite to ber_decode().
 */
UAPKIF_EXPORT asn_dec_rval_t ber_decode(struct asn_codec_ctx_s *opt_codec_ctx,
        struct asn_TYPE_descriptor_s *type_descriptor,
        void **struct_ptr,    /* Pointer to a target structure's pointer */
        const void *buffer,    /* Data to be decoded */
        size_t size        /* Size of that buffer */
                                           );

/*
 * Type of generic function which decodes the byte stream into the structure.
 */
typedef asn_dec_rval_t (ber_type_decoder_f)(
        struct asn_codec_ctx_s *opt_codec_ctx,
        struct asn_TYPE_descriptor_s *type_descriptor,
        void **struct_ptr, const void *buf_ptr, size_t size,
        int tag_mode);

/*******************************
 * INTERNALLY USEFUL FUNCTIONS *
 *******************************/

/*
 * Check that all tags correspond to the type definition (as given in head).
 * On return, last_length would contain either a non-negative length of the
 * value part of the last TLV, or the negative number of expected
 * "end of content" sequences. The number may only be negative if the
 * head->last_tag_form is non-zero.
 */
UAPKIF_EXPORT asn_dec_rval_t ber_check_tags(
        struct asn_codec_ctx_s *opt_codec_ctx,    /* codec options */
        struct asn_TYPE_descriptor_s *type_descriptor,
        asn_struct_ctx_t *opt_ctx,    /* saved decoding context */
        const void *ptr, size_t size,
        int tag_mode,        /* {-1,0,1}: IMPLICIT, no, EXPLICIT */
        int last_tag_form,    /* {-1,0:1}: any, primitive, constr */
        ber_tlv_len_t *last_length,
        int *opt_tlv_form    /* optional tag form */
);

#ifdef __cplusplus
}
#endif

#endif
