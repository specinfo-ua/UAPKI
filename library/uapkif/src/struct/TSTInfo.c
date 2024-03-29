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

#define FILE_MARKER "uapkif/struct/TSTInfo.c"

#include "TSTInfo.h"

#include "asn_internal.h"

#include "Accuracy.h"
#include "GeneralName.h"
#include "Extensions.h"

static asn_TYPE_member_t asn_MBR_TSTInfo_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct TSTInfo, version),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &TSVersion_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "version"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct TSTInfo, policy),
        (ASN_TAG_CLASS_UNIVERSAL | (6 << 2)),
        0,
        &TSAPolicyId_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "policy"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct TSTInfo, messageImprint),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &MessageImprint_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "messageImprint"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct TSTInfo, serialNumber),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &INTEGER_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "serialNumber"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct TSTInfo, genTime),
        (ASN_TAG_CLASS_UNIVERSAL | (24 << 2)),
        0,
        &GeneralizedTime_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "genTime"
    },
    {
        ATF_POINTER, 4, offsetof(struct TSTInfo, accuracy),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &Accuracy_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "accuracy"
    },
    {
        ATF_POINTER, 3, offsetof(struct TSTInfo, nonce),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &INTEGER_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "nonce"
    },
    {
        ATF_POINTER, 2, offsetof(struct TSTInfo, tsa),
        (ASN_TAG_CLASS_CONTEXT | (0 << 2)),
        +1,    /* EXPLICIT tag at current level */
        &GeneralName_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "tsa"
    },
    {
        ATF_POINTER, 1, offsetof(struct TSTInfo, extensions),
        (ASN_TAG_CLASS_CONTEXT | (1 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &Extensions_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "extensions"
    },
};
static const ber_tlv_tag_t TSTInfo_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_TSTInfo_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 0, 0, 2 }, /* version */
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 3, -1, 1 }, /* serialNumber */
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 6, -2, 0 }, /* nonce */
    { (ASN_TAG_CLASS_UNIVERSAL | (6 << 2)), 1, 0, 0 }, /* policy */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 2, 0, 1 }, /* messageImprint */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 5, -1, 0 }, /* accuracy */
    { (ASN_TAG_CLASS_UNIVERSAL | (24 << 2)), 4, 0, 0 }, /* genTime */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 7, 0, 0 }, /* tsa */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 8, 0, 0 } /* extensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_TSTInfo_specs_1 = {
    sizeof(struct TSTInfo),
    offsetof(struct TSTInfo, _asn_ctx),
    asn_MAP_TSTInfo_tag2el_1,
    9,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t TSTInfo_desc = {
    "TSTInfo",
    "TSTInfo",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    TSTInfo_desc_tags_1,
    sizeof(TSTInfo_desc_tags_1)
    / sizeof(TSTInfo_desc_tags_1[0]), /* 1 */
    TSTInfo_desc_tags_1,    /* Same as above */
    sizeof(TSTInfo_desc_tags_1)
    / sizeof(TSTInfo_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_TSTInfo_1,
    9,    /* Elements count */
    &asn_SPC_TSTInfo_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_TSTInfo_desc(void)
{
    return &TSTInfo_desc;
}


