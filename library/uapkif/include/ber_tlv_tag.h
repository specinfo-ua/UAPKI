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

#ifndef    _BER_TLV_TAG_H_
#define    _BER_TLV_TAG_H_

#ifdef __cplusplus
extern "C" {
#endif

enum asn_tag_class {
    ASN_TAG_CLASS_UNIVERSAL        = 0,    /* 0b00 */
    ASN_TAG_CLASS_APPLICATION      = 1,    /* 0b01 */
    ASN_TAG_CLASS_CONTEXT          = 2,    /* 0b10 */
    ASN_TAG_CLASS_PRIVATE          = 3     /* 0b11 */
};
typedef unsigned ber_tlv_tag_t;    /* BER TAG from Tag-Length-Value */

/*
 * Tag class is encoded together with tag value for optimization purposes.
 */
#define    BER_TAG_CLASS(tag)    ((tag) & 0x3)
#define    BER_TAG_VALUE(tag)    ((tag) >> 2)
#define    BER_TLV_CONSTRUCTED(tagptr)    (((*(const uint8_t *)tagptr)&0x20)?1:0)

#define    BER_TAGS_EQUAL(tag1, tag2)    ((tag1) == (tag2))

/*
 * Several functions for printing the TAG in the canonical form
 * (i.e. "[PRIVATE 0]").
 * Return values correspond to their libc counterparts (if any).
 */
UAPKIF_EXPORT ssize_t ber_tlv_tag_snprint(ber_tlv_tag_t tag, char *buf, size_t buflen);
UAPKIF_EXPORT ssize_t ber_tlv_tag_fwrite(ber_tlv_tag_t tag, FILE *);
UAPKIF_EXPORT char *ber_tlv_tag_string(ber_tlv_tag_t tag);

/*
 * This function tries to fetch the tag from the input stream.
 * RETURN VALUES:
 *      0:    More data expected than bufptr contains.
 *     -1:    Fatal error deciphering tag.
 *    >0:    Number of bytes used from bufptr. tag_r will contain the tag.
 */
UAPKIF_EXPORT ssize_t ber_fetch_tag(const void *bufptr, size_t size, ber_tlv_tag_t *tag_r);

/*
 * This function serializes the tag (T from TLV) in BER format.
 * It always returns number of bytes necessary to represent the tag,
 * it is a caller's responsibility to check the return value
 * against the supplied buffer's size.
 */
UAPKIF_EXPORT size_t ber_tlv_tag_serialize(ber_tlv_tag_t tag, void *bufptr, size_t size);

#ifdef __cplusplus
}
#endif

#endif
