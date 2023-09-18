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

#define FILE_MARKER "uapkif/asn1/enumerated.c"

#include "asn_internal.h"
#include "ENUMERATED.h"
#include "NativeEnumerated.h"
#include "asn_codecs_prim.h"    /* Encoder and decoder of a primitive type */

/*
 * ENUMERATED basic type description.
 */
static const ber_tlv_tag_t asn_DEF_ENUMERATED_tags[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t ENUMERATED_desc = {
    "ENUMERATED",
    "ENUMERATED",
    ASN__PRIMITIVE_TYPE_free,
    INTEGER_print,            /* Implemented in terms of INTEGER */
    asn_generic_no_constraint,
    ber_decode_primitive,
    INTEGER_encode_der,        /* Implemented in terms of INTEGER */
    INTEGER_decode_xer,    /* This is temporary! */
    INTEGER_encode_xer,
    ENUMERATED_decode_uper,    /* Unaligned PER decoder */
    ENUMERATED_encode_uper,    /* Unaligned PER encoder */
    0, /* Use generic outmost tag fetcher */
    asn_DEF_ENUMERATED_tags,
    sizeof(asn_DEF_ENUMERATED_tags) / sizeof(asn_DEF_ENUMERATED_tags[0]),
    asn_DEF_ENUMERATED_tags,    /* Same as above */
    sizeof(asn_DEF_ENUMERATED_tags) / sizeof(asn_DEF_ENUMERATED_tags[0]),
    0,    /* No PER visible constraints */
    0, 0,    /* No members */
    0    /* No specifics */
};

asn_TYPE_descriptor_t *get_ENUMERATED_desc(void)
{
    return &ENUMERATED_desc;
}

asn_dec_rval_t
ENUMERATED_decode_uper(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
        asn_per_constraints_t *constraints, void **sptr, asn_per_data_t *pd)
{
    asn_dec_rval_t rval;
    ENUMERATED_t *st = (ENUMERATED_t *)*sptr;
    long value;
    void *vptr = &value;

    if (!st) {
        st = (ENUMERATED_t *)(*sptr = CALLOC(1, sizeof(*st)));
        if (!st) {
            ASN__DECODE_FAILED;
        }
    }

    rval = NativeEnumerated_decode_uper(opt_codec_ctx, td, constraints,
            (void **)&vptr, pd);
    if (rval.code == RC_OK)
        if (asn_long2INTEGER(st, value)) {
            rval.code = RC_FAIL;
        }
    return rval;
}

asn_enc_rval_t
ENUMERATED_encode_uper(asn_TYPE_descriptor_t *td,
        asn_per_constraints_t *constraints, void *sptr, asn_per_outp_t *po)
{
    ENUMERATED_t *st = (ENUMERATED_t *)sptr;
    long value;

    if (asn_INTEGER2long(st, &value)) {
        ASN__ENCODE_FAILED;
    }

    return NativeEnumerated_encode_uper(td, constraints, &value, po);
}


