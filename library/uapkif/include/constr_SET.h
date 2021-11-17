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

#ifndef    _CONSTR_SET_H_
#define    _CONSTR_SET_H_

#include "asn_application.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef const struct asn_SET_specifics_s {
    /*
     * Target structure description.
     */
    int struct_size;    /* Size of the target structure. */
    int ctx_offset;        /* Offset of the asn_struct_ctx_t member */
    int pres_offset;    /* Offset of _presence_map member */

    /*
     * Tags to members mapping table (sorted).
     * Sometimes suitable for DER encoding (untagged CHOICE is present);
     * if so, tag2el_count will be greater than td->elements_count.
     */
    const asn_TYPE_tag2member_t *tag2el;
    int tag2el_count;

    /*
     * Tags to members mapping table, second edition.
     * Suitable for CANONICAL-XER encoding.
     */
    const asn_TYPE_tag2member_t *tag2el_cxer;
    int tag2el_cxer_count;

    /*
     * Extensions-related stuff.
     */
    int extensible;                /* Whether SET is extensible */
    const unsigned int *_mandatory_elements;    /* Bitmask of mandatory ones */
} asn_SET_specifics_t;

/*
 * A set specialized functions dealing with the SET type.
 */
asn_struct_free_f SET_free;
asn_struct_print_f SET_print;
asn_constr_check_f SET_constraint;
ber_type_decoder_f SET_decode_ber;
der_type_encoder_f SET_encode_der;
xer_type_decoder_f SET_decode_xer;
xer_type_encoder_f SET_encode_xer;
per_type_decoder_f SET_decode_uper;
per_type_encoder_f SET_encode_uper;

/***********************
 * Some handy helpers. *
 ***********************/

/*
 * Figure out whether the SET member indicated by PR_x has already been decoded.
 * It is very simple bitfield test, despite its visual complexity.
 */
#define    ASN_SET_ISPRESENT(set_ptr, PR_x)                \
    ASN_SET_ISPRESENT2(&((set_ptr)->_presence_map), PR_x)
#define    ASN_SET_ISPRESENT2(map_ptr, PR_x)                \
    (((unsigned int *)(map_ptr))                    \
        [(PR_x)    / (8 * sizeof(unsigned int))]            \
        & (1 << ((8 * sizeof(unsigned int)) - 1            \
        - ((PR_x) % (8 * sizeof(unsigned int))))))

#define    ASN_SET_MKPRESENT(map_ptr, PR_x)                \
    (((unsigned int *)(map_ptr))                    \
        [(PR_x)    / (8 * sizeof(unsigned int))]            \
        |= (1 << ((8 * sizeof(unsigned int)) - 1        \
        - ((PR_x) % (8 * sizeof(unsigned int))))))

#ifdef __cplusplus
}
#endif

#endif
