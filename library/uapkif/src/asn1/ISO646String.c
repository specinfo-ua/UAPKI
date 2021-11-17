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
#include "ISO646String.h"

#undef FILE_MARKER
#define FILE_MARKER "asn1/ISO646String.c"
/*
 * ISO646String basic type description.
 */
static const ber_tlv_tag_t asn_DEF_ISO646String_tags[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (26 << 2)),    /* [UNIVERSAL 26] IMPLICIT ...*/
    (ASN_TAG_CLASS_UNIVERSAL | (4 << 2))    /* ... OCTET STRING */
};
static asn_per_constraints_t asn_DEF_ISO646String_constraints = {
    { APC_CONSTRAINED, 7, 7, 0x20, 0x7e },    /* Value */
    { APC_SEMI_CONSTRAINED, -1, -1, 0, 0 },    /* Size */
    0, 0
};
asn_TYPE_descriptor_t ISO646String_desc = {
    "ISO646String",
    "ISO646String",
    OCTET_STRING_free,
    OCTET_STRING_print_utf8,    /* ASCII subset */
    VisibleString_constraint,
    OCTET_STRING_decode_ber,    /* Implemented in terms of OCTET STRING */
    OCTET_STRING_encode_der,
    OCTET_STRING_decode_xer_utf8,
    OCTET_STRING_encode_xer_utf8,
    OCTET_STRING_decode_uper,
    OCTET_STRING_encode_uper,
    0, /* Use generic outmost tag fetcher */
    asn_DEF_ISO646String_tags,
    sizeof(asn_DEF_ISO646String_tags)
    / sizeof(asn_DEF_ISO646String_tags[0]) - 1,
    asn_DEF_ISO646String_tags,
    sizeof(asn_DEF_ISO646String_tags)
    / sizeof(asn_DEF_ISO646String_tags[0]),
    &asn_DEF_ISO646String_constraints,
    0, 0,    /* No members */
    0    /* No specifics */
};

asn_TYPE_descriptor_t *get_ISO646String_desc(void)
{
    return &ISO646String_desc;
}
