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

#ifndef    _OCTET_STRING_H_
#define    _OCTET_STRING_H_

#include "asn_application.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct OCTET_STRING {
    uint8_t *buf;    /* Buffer with consecutive OCTET_STRING bits */
    int size;    /* Size of the buffer */

    asn_struct_ctx_t _asn_ctx;    /* Parsing across buffer boundaries */
} OCTET_STRING_t;

extern asn_TYPE_descriptor_t OCTET_STRING_desc;

UAPKIF_EXPORT asn_TYPE_descriptor_t *get_OCTET_STRING_desc(void);

asn_struct_free_f OCTET_STRING_free;
asn_struct_print_f OCTET_STRING_print;
asn_struct_print_f OCTET_STRING_print_utf8;
ber_type_decoder_f OCTET_STRING_decode_ber;
der_type_encoder_f OCTET_STRING_encode_der;
xer_type_decoder_f OCTET_STRING_decode_xer_hex;        /* Hexadecimal */
xer_type_decoder_f OCTET_STRING_decode_xer_binary;    /* 01010111010 */
xer_type_decoder_f OCTET_STRING_decode_xer_utf8;    /* ASCII/UTF-8 */
xer_type_encoder_f OCTET_STRING_encode_xer;
xer_type_encoder_f OCTET_STRING_encode_xer_utf8;
per_type_decoder_f OCTET_STRING_decode_uper;
per_type_encoder_f OCTET_STRING_encode_uper;

/******************************
 * Handy conversion routines. *
 ******************************/

/*
 * This function clears the previous value of the OCTET STRING (if any)
 * and then allocates a new memory with the specified content (str/size).
 * If size = -1, the size of the original string will be determined
 * using strlen(str).
 * If str equals to NULL, the function will silently clear the
 * current contents of the OCTET STRING.
 * Returns 0 if it was possible to perform operation, -1 otherwise.
 */
UAPKIF_EXPORT int OCTET_STRING_fromBuf(OCTET_STRING_t *s, const char *str, int size);

/* Handy conversion from the C string into the OCTET STRING. */
#define    OCTET_STRING_fromString(s, str)    OCTET_STRING_fromBuf(s, str, -1)

/*
 * Allocate and fill the new OCTET STRING and return a pointer to the newly
 * allocated object. NULL is permitted in str: the function will just allocate
 * empty OCTET STRING.
 */
OCTET_STRING_t *OCTET_STRING_new_fromBuf(asn_TYPE_descriptor_t *td,
        const char *str, int size);

/****************************
 * Internally useful stuff. *
 ****************************/

typedef const struct asn_OCTET_STRING_specifics_s {
    /*
     * Target structure description.
     */
    int struct_size;    /* Size of the structure */
    int ctx_offset;        /* Offset of the asn_struct_ctx_t member */

    enum asn_OS_Subvariant {
        ASN_OSUBV_ANY,    /* The open type (ANY) */
        ASN_OSUBV_BIT,    /* BIT STRING */
        ASN_OSUBV_STR,    /* String types, not {BMP,Universal}String  */
        ASN_OSUBV_U16,    /* 16-bit character (BMPString) */
        ASN_OSUBV_U32    /* 32-bit character (UniversalString) */
    } subvariant;
} asn_OCTET_STRING_specifics_t;

#ifdef __cplusplus
}
#endif

#endif
