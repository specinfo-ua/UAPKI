/*
 * Copyright (c) 2021, The UAPKI Project Authors.
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

//  Last update: 2021-09-15

#ifndef UAPKI_EXTENSION_UTILS_H
#define UAPKI_EXTENSION_UTILS_H


#include "uapkic.h"
#include "uapkif.h"


#ifdef __cplusplus
extern "C" {
#endif


//int build_extension (const char* oidExtnId, const bool critical, const ByteArray* baExtnValue, Extension_t** extension);//depr
int extns_add_extension (Extensions_t* extns, const char* extnId, const bool critical, const ByteArray* baEncoded);

int extns_add_ocsp_nonce (Extensions_t* extns, const ByteArray* baNonce);
int extns_add_subject_keyid (Extensions_t* extns, const ByteArray* baSubjectKeyId);

const Extension_t* extns_get_extn_by_oid (const Extensions_t* extns, const char* oidExtnId);
int extns_get_extnvalue_by_oid (const Extensions_t* extns, const char* oidExtnId, bool* critical, ByteArray** baEncoded);

int extns_get_authority_infoaccess (const Extensions_t* extns, char** urlOcsp);
int extns_get_authority_keyid (const Extensions_t* extns, ByteArray** baKeyId);
int extns_get_basic_constrains (const Extensions_t* extns, bool* cA, int* pathLenConstraint);
int extns_get_crl_distribution_points (const Extensions_t* extns, char** urlFull);
int extns_get_crl_invalidity_date (const Extensions_t* extns, uint64_t* invalidityDate);
int extns_get_crl_number (const Extensions_t* extns, ByteArray** baCrlNumber);
int extns_get_crl_reason (const Extensions_t* extns, uint32_t* crlReason);
int extns_get_delta_crl_indicator (const Extensions_t* extns, ByteArray** baDeltaCrlIndicator);
int extns_get_freshest_crl (const Extensions_t* extns, char** urlDelta);
int extns_get_key_usage (const Extensions_t* extns, uint32_t* keyUsage);
int extns_get_ocsp_nonce (const Extensions_t* extns, ByteArray** baNonce);
int extns_get_subject_directory_attrs (const Extensions_t* extns, const char* oidType, ByteArray** baEncoded);
int extns_get_subject_keyid (const Extensions_t* extns, ByteArray** baKeyId);
int extns_get_tsp_url (const Extensions_t* extns, char** urlTsp);


#ifdef __cplusplus
}
#endif


#endif
