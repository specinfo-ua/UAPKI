/*
 * Copyright 2021 The UAPKI Project Authors.
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
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

#define FILE_MARKER "uapkif/struct/PrivateDomainName.c"

#include "PrivateDomainName.h"

#include "asn_internal.h"

static asn_TYPE_member_t asn_MBR_PrivateDomainName_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct PrivateDomainName, choice.numeric),
        (ASN_TAG_CLASS_UNIVERSAL | (18 << 2)),
        0,
        &NumericString_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "numeric"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct PrivateDomainName, choice.printable),
        (ASN_TAG_CLASS_UNIVERSAL | (19 << 2)),
        0,
        &PrintableString_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "printable"
    },
};
static const asn_TYPE_tag2member_t asn_MAP_PrivateDomainName_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (18 << 2)), 0, 0, 0 }, /* numeric */
    { (ASN_TAG_CLASS_UNIVERSAL | (19 << 2)), 1, 0, 0 } /* printable */
};
static asn_CHOICE_specifics_t asn_SPC_PrivateDomainName_specs_1 = {
    sizeof(struct PrivateDomainName),
    offsetof(struct PrivateDomainName, _asn_ctx),
    offsetof(struct PrivateDomainName, present),
    sizeof(((struct PrivateDomainName *)0)->present),
    asn_MAP_PrivateDomainName_tag2el_1,
    2,    /* Count of tags in the map */
    0,
    -1    /* Extensions start */
};
asn_TYPE_descriptor_t PrivateDomainName_desc = {
    "PrivateDomainName",
    "PrivateDomainName",
    CHOICE_free,
    CHOICE_print,
    CHOICE_constraint,
    CHOICE_decode_ber,
    CHOICE_encode_der,
    CHOICE_decode_xer,
    CHOICE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    CHOICE_outmost_tag,
    0,    /* No effective tags (pointer) */
    0,    /* No effective tags (count) */
    0,    /* No tags (pointer) */
    0,    /* No tags (count) */
    0,    /* No PER visible constraints */
    asn_MBR_PrivateDomainName_1,
    2,    /* Elements count */
    &asn_SPC_PrivateDomainName_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_PrivateDomainName_desc(void)
{
    return &PrivateDomainName_desc;
}


