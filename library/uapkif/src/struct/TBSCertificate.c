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

#define FILE_MARKER "uapkif/struct/TBSCertificate.c"

#include "TBSCertificate.h"

#include "asn_internal.h"

#include "Extensions.h"

static int asn_DFL_2_set_0(int set_value, void **sptr)
{
    Version_t *st = *sptr;

    if (!st) {
        if (!set_value) {
            return -1;    /* Not a default value */
        }
        st = (*sptr = CALLOC(1, sizeof(*st)));
        if (!st) {
            return -1;
        }
    }

    if (set_value) {
        /* Install default value 0 */
        return asn_long2INTEGER(st, 0);
    } else {
        /* Test default value 0 */
        long value;
        if (asn_INTEGER2long(st, &value)) {
            return -1;
        }
        return (value == 0);
    }
}
static asn_TYPE_member_t asn_MBR_TBSCertificate_1[] = {
    {
        ATF_POINTER, 1, offsetof(struct TBSCertificate, version),
        (ASN_TAG_CLASS_CONTEXT | (0 << 2)),
        +1,    /* EXPLICIT tag at current level */
        &Version_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        asn_DFL_2_set_0,    /* DEFAULT 0 */
        "version"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct TBSCertificate, serialNumber),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &CertificateSerialNumber_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "serialNumber"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct TBSCertificate, signature),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &AlgorithmIdentifier_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "signature"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct TBSCertificate, issuer),
        (ber_tlv_tag_t)-1 /* Ambiguous tag (CHOICE?) */,
        0,
        &Name_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "issuer"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct TBSCertificate, validity),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &Validity_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "validity"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct TBSCertificate, subject),
        (ber_tlv_tag_t)-1 /* Ambiguous tag (CHOICE?) */,
        0,
        &Name_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "subject"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct TBSCertificate, subjectPublicKeyInfo),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &SubjectPublicKeyInfo_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "subjectPublicKeyInfo"
    },
    {
        ATF_POINTER, 3, offsetof(struct TBSCertificate, issuerUniqueID),
        (ASN_TAG_CLASS_CONTEXT | (1 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &UniqueIdentifier_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "issuerUniqueID"
    },
    {
        ATF_POINTER, 2, offsetof(struct TBSCertificate, subjectUniqueID),
        (ASN_TAG_CLASS_CONTEXT | (2 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &UniqueIdentifier_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "subjectUniqueID"
    },
    {
        ATF_POINTER, 1, offsetof(struct TBSCertificate, extensions),
        (ASN_TAG_CLASS_CONTEXT | (3 << 2)),
        +1,    /* EXPLICIT tag at current level */
        &Extensions_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "extensions"
    },
};
static const ber_tlv_tag_t TBSCertificate_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_TBSCertificate_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 1, 0, 0 }, /* serialNumber */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 2, 0, 4 }, /* signature */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 3, -1, 3 }, /* rdnSequence */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 4, -2, 2 }, /* validity */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 5, -3, 1 }, /* rdnSequence */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 6, -4, 0 }, /* subjectPublicKeyInfo */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* version */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 7, 0, 0 }, /* issuerUniqueID */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 8, 0, 0 }, /* subjectUniqueID */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 9, 0, 0 } /* extensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_TBSCertificate_specs_1 = {
    sizeof(struct TBSCertificate),
    offsetof(struct TBSCertificate, _asn_ctx),
    asn_MAP_TBSCertificate_tag2el_1,
    10,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t TBSCertificate_desc = {
    "TBSCertificate",
    "TBSCertificate",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    TBSCertificate_desc_tags_1,
    sizeof(TBSCertificate_desc_tags_1)
    / sizeof(TBSCertificate_desc_tags_1[0]), /* 1 */
    TBSCertificate_desc_tags_1,    /* Same as above */
    sizeof(TBSCertificate_desc_tags_1)
    / sizeof(TBSCertificate_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_TBSCertificate_1,
    10,    /* Elements count */
    &asn_SPC_TBSCertificate_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_TBSCertificate_desc(void)
{
    return &TBSCertificate_desc;
}


