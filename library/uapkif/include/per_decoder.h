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

#ifndef    _PER_DECODER_H_
#define    _PER_DECODER_H_

#include "asn_application.h"
#include "per_support.h"

#ifdef __cplusplus
extern "C" {
#endif

struct asn_TYPE_descriptor_s;    /* Forward declaration */

/*
 * Unaligned PER decoder of a "complete encoding" as per X.691#10.1.
 * On success, this call always returns (.consumed >= 1), as per X.691#10.1.3.
 */
UAPKIF_EXPORT asn_dec_rval_t uper_decode_complete(struct asn_codec_ctx_s *opt_codec_ctx,
        struct asn_TYPE_descriptor_s *type_descriptor,    /* Type to decode */
        void **struct_ptr,    /* Pointer to a target structure's pointer */
        const void *buffer,    /* Data to be decoded */
        size_t size        /* Size of data buffer */
                                                     );

/*
 * Unaligned PER decoder of any ASN.1 type. May be invoked by the application.
 * WARNING: This call returns the number of BITS read from the stream. Beware.
 */
UAPKIF_EXPORT asn_dec_rval_t uper_decode(struct asn_codec_ctx_s *opt_codec_ctx,
        struct asn_TYPE_descriptor_s *type_descriptor,    /* Type to decode */
        void **struct_ptr,    /* Pointer to a target structure's pointer */
        const void *buffer,    /* Data to be decoded */
        size_t size,        /* Size of data buffer */
        int skip_bits,        /* Number of unused leading bits, 0..7 */
        int unused_bits        /* Number of unused tailing bits, 0..7 */
                                            );


/*
 * Type of the type-specific PER decoder function.
 */
typedef asn_dec_rval_t (per_type_decoder_f)(asn_codec_ctx_t *opt_codec_ctx,
        struct asn_TYPE_descriptor_s *type_descriptor,
        asn_per_constraints_t *constraints,
        void **struct_ptr,
        asn_per_data_t *per_data
                                           );

#ifdef __cplusplus
}
#endif

#endif
