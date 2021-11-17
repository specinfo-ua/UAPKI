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

#ifndef    _CONSTR_CHOICE_H_
#define    _CONSTR_CHOICE_H_

#include "asn_application.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef const struct asn_CHOICE_specifics_s {
    /*
     * Target structure description.
     */
    int struct_size;    /* Size of the target structure. */
    int ctx_offset;        /* Offset of the asn_codec_ctx_t member */
    int pres_offset;    /* Identifier of the present member */
    int pres_size;        /* Size of the identifier (enum) */

    /*
     * Tags to members mapping table.
     */
    const asn_TYPE_tag2member_t *tag2el;
    int tag2el_count;

    /* Canonical ordering of CHOICE elements, for PER */
    int *canonical_order;

    /*
     * Extensions-related stuff.
     */
    int ext_start;        /* First member of extensions, or -1 */
} asn_CHOICE_specifics_t;

/*
 * A set specialized functions dealing with the CHOICE type.
 */
asn_struct_free_f CHOICE_free;
asn_struct_print_f CHOICE_print;
asn_constr_check_f CHOICE_constraint;
ber_type_decoder_f CHOICE_decode_ber;
der_type_encoder_f CHOICE_encode_der;
xer_type_decoder_f CHOICE_decode_xer;
xer_type_encoder_f CHOICE_encode_xer;
per_type_decoder_f CHOICE_decode_uper;
per_type_encoder_f CHOICE_encode_uper;
asn_outmost_tag_f CHOICE_outmost_tag;

#ifdef __cplusplus
}
#endif

#endif
