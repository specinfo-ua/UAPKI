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

#ifndef UAPKI_ASN1_BA_UTILS_H
#define UAPKI_ASN1_BA_UTILS_H


#include "uapkic.h"
#include "uapkif.h"


#ifdef __cplusplus
extern "C" {
#endif


int asn_decode_anystring (const uint8_t* buf, const size_t len, char** str);
int asn_decodevalue_bitstring_encap_octet (const BIT_STRING_t* bsEncapOctet, ByteArray** baData);
int asn_decodevalue_bitstring_to_uint32 (const BIT_STRING_t* bs, uint32_t* bits);
int asn_decodevalue_bmpstring (const BMPString_t* bmpStr, char** str);
int asn_decodevalue_enumerated (const ENUMERATED_t* enumerated, uint32_t* enumValue);
int asn_decodevalue_gentime (const GeneralizedTime_t* genTime, uint64_t* msTime);
int asn_decodevalue_octetstring_to_stime (const OCTET_STRING_t* octetTime, char** stime);
int asn_decodevalue_octetstring_to_str (const OCTET_STRING_t* octetString, char** str);
int asn_decodevalue_pkixtime (const PKIXTime_t* pkixTime, uint64_t* msTime);
int asn_decodevalue_utctime (const UTCTime_t* utcTime, uint64_t* msTime);
int asn_encodevalue_gentime (GeneralizedTime_t* genTime, const char* stime);

bool asn_octetstring_data_is_equals (const OCTET_STRING_t* octetStr1, const OCTET_STRING_t* octetStr2);
bool asn_primitive_data_is_equals (const ASN__PRIMITIVE_TYPE_t* primType1, const ASN__PRIMITIVE_TYPE_t* primType2);

int ba_decode_anystring (const ByteArray* baEncoded, char** str);
int ba_decode_bmpstring (const ByteArray* baEncoded, char** str);
int ba_decode_enumerated (const ByteArray* baEncoded, uint32_t* enumValue);
int ba_decode_octetstring (const ByteArray* baEncoded, ByteArray** baData);
int ba_decode_oid (const ByteArray* baEncoded, char** oid);
int ba_decode_pkixtime (const ByteArray* baEncoded, uint64_t* unixTime);
int ba_decode_time (const ByteArray* baEncoded, uint64_t* unixTime, char** stime);

int ba_encode_bmpstring (const char* strUtf8, ByteArray** baEncoded);
int ba_encode_ia5string (const char* strLatin, ByteArray** baEncoded);
int ba_encode_integer (const ByteArray* baData, ByteArray** baEncoded);
int ba_encode_integer_int32 (const int32_t value, ByteArray** baEncoded);
int ba_encode_octetstring (const ByteArray* baData, ByteArray** baEncoded);
int ba_encode_oid (const char* oid, ByteArray** baEncoded);
int ba_encode_pkixtime (const PKIXTime_PR frmTime, const uint64_t msTime, ByteArray** baEncoded);
int ba_encode_printablestring (const char* strLatin, ByteArray** baEncoded);
int ba_encode_utf8string (const char* strUtf8, ByteArray** baEncoded);

int uint8_to_str_with_alloc (const uint8_t* buf, const size_t len, char** str);


#ifdef __cplusplus
}
#endif

#endif
