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

#include "asn_internal.h"
#include "NumericString.h"

#undef FILE_MARKER
#define FILE_MARKER "asn1/NumericString.c"

/*
 * NumericString basic type description.
 */
static const ber_tlv_tag_t asn_DEF_NumericString_tags[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (18 << 2)),    /* [UNIVERSAL 18] IMPLICIT ...*/
    (ASN_TAG_CLASS_UNIVERSAL | (4 << 2))    /* ... OCTET STRING */
};
static int asn_DEF_NumericString_v2c(unsigned int value)
{
    switch (value) {
    case 0x20:
        return 0;
    case 0x30:
    case 0x31:
    case 0x32:
    case 0x33:
    case 0x34:
    case 0x35:
    case 0x36:
    case 0x37:
    case 0x38:
    case 0x39:
        return value - (0x30 - 1);
    }
    return -1;
}
static int asn_DEF_NumericString_c2v(unsigned int code)
{
    if (code > 0) {
        if (code <= 10) {
            return code + (0x30 - 1);
        } else {
            return -1;
        }
    } else {
        return 0x20;
    }
}
static asn_per_constraints_t asn_DEF_NumericString_constraints = {
    { APC_CONSTRAINED, 4, 4, 0x20, 0x39 },    /* Value */
    { APC_SEMI_CONSTRAINED, -1, -1, 0, 0 },    /* Size */
    asn_DEF_NumericString_v2c,
    asn_DEF_NumericString_c2v
};
asn_TYPE_descriptor_t NumericString_desc = {
    "NumericString",
    "NumericString",
    OCTET_STRING_free,
    OCTET_STRING_print_utf8,   /* ASCII subset */
    NumericString_constraint,
    OCTET_STRING_decode_ber,    /* Implemented in terms of OCTET STRING */
    OCTET_STRING_encode_der,
    OCTET_STRING_decode_xer_utf8,
    OCTET_STRING_encode_xer_utf8,
    OCTET_STRING_decode_uper,
    OCTET_STRING_encode_uper,
    0, /* Use generic outmost tag fetcher */
    asn_DEF_NumericString_tags,
    sizeof(asn_DEF_NumericString_tags)
    / sizeof(asn_DEF_NumericString_tags[0]) - 1,
    asn_DEF_NumericString_tags,
    sizeof(asn_DEF_NumericString_tags)
    / sizeof(asn_DEF_NumericString_tags[0]),
    &asn_DEF_NumericString_constraints,
    0, 0,    /* No members */
    0    /* No specifics */
};

asn_TYPE_descriptor_t *get_NumericString_desc(void)
{
    return &NumericString_desc;
}

int
NumericString_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
        asn_app_constraint_failed_f *ctfailcb, void *app_key)
{
    const NumericString_t *st = (const NumericString_t *)sptr;

    if (st && st->buf) {
        uint8_t *buf = st->buf;
        uint8_t *end = buf + st->size;

        /*
         * Check the alphabet of the NumericString.
         * ASN.1:1984 (X.409)
         */
        for (; buf < end; buf++) {
            switch (*buf) {
            case 0x20:
            case 0x30:
            case 0x31:
            case 0x32:
            case 0x33:
            case 0x34:
            case 0x35:
            case 0x36:
            case 0x37:
            case 0x38:
            case 0x39:
                continue;
            }
            ASN__CTFAIL(app_key, td, sptr,
                    "%s: value byte %ld (%d) "
                    "not in NumericString alphabet (%s:%d)",
                    td->name,
                    (long)((buf - st->buf) + 1),
                    *buf,
                    FILE_MARKER, __LINE__);
            return -1;
        }
    } else {
        ASN__CTFAIL(app_key, td, sptr,
                "%s: value not given (%s:%d)",
                td->name, FILE_MARKER, __LINE__);
        return -1;
    }

    return 0;
}
