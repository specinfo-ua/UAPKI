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

#ifndef    _SigPolicyHash_H_
#define    _SigPolicyHash_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OtherHashAlgAndValue.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SigPolicyHash */
typedef OtherHashAlgAndValue_t     SigPolicyHash_t;

/* Implementation */
extern asn_TYPE_descriptor_t SigPolicyHash_desc;
UAPKIF_EXPORT asn_TYPE_descriptor_t *get_SigPolicyHash_desc(void);
asn_struct_free_f SigPolicyHash_free;
asn_struct_print_f SigPolicyHash_print;
asn_constr_check_f SigPolicyHash_constraint;
ber_type_decoder_f SigPolicyHash_decode_ber;
der_type_encoder_f SigPolicyHash_encode_der;
xer_type_decoder_f SigPolicyHash_decode_xer;
xer_type_encoder_f SigPolicyHash_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
