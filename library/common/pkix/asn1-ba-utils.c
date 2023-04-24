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

#include "asn1-ba-utils.h"
#include "ba-utils.h"
#include "iconv-utils.h"
#include "macros-internal.h"
#include "uapki-errors.h"


int asn_decode_anystring (const uint8_t* buf, const size_t len, char** str)
{
    int ret = RET_OK;
    OCTET_STRING_t* octet_str = NULL;
    asn_TYPE_descriptor_t* desc = NULL;

    CHECK_PARAM(buf != NULL);
    CHECK_PARAM(str != NULL);

    if (len < 2) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }
    switch (buf[0])
    {
    case 0x0C: desc = get_UTF8String_desc(); break;
    case 0x13: desc = get_PrintableString_desc(); break;
    case 0x16: desc = get_IA5String_desc(); break;
    default:
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

    octet_str = (OCTET_STRING_t*)asn_decode_with_alloc(desc, buf, len);
    if (octet_str == NULL) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

    DO(uint8_to_str_with_alloc(octet_str->buf, (size_t)octet_str->size, str));

cleanup:
    asn_free(get_OCTET_STRING_desc(), octet_str);
    return ret;
}

int asn_decodevalue_bitstring_encap_octet (const BIT_STRING_t* bsEncapOctet, ByteArray** baData)
{
    int ret = RET_OK;
    OCTET_STRING_t* octet_str = NULL;
    ByteArray* ba_encoded = NULL;

    CHECK_PARAM(bsEncapOctet != NULL);
    CHECK_PARAM(baData != NULL);

    if (bsEncapOctet->bits_unused != 0) {
        SET_ERROR(RET_UAPKI_UNEXPECTED_BIT_STRING);
    }

    DO(asn_BITSTRING2ba(bsEncapOctet, &ba_encoded));
    CHECK_NOT_NULL(octet_str = asn_decode_ba_with_alloc(get_OCTET_STRING_desc(), ba_encoded));
    DO(asn_OCTSTRING2ba(octet_str, baData));

cleanup:
    asn_free(get_OCTET_STRING_desc(), octet_str);
    ba_free(ba_encoded);
    return ret;
}

int asn_decodevalue_bitstring_to_uint32 (const BIT_STRING_t* bs, uint32_t* bits)
{
    int ret = RET_OK;
    ByteArray* ba_bitvalues = NULL;
    uint32_t i, value = 0;
    const uint8_t* buf = NULL;

    CHECK_PARAM(bs != NULL);
    CHECK_PARAM(bits != NULL);

    if (bs->bits_unused > 7) {
        SET_ERROR(RET_UAPKI_INVALID_BIT_STRING);
    }
    if (bs->size > 4) {
        SET_ERROR(RET_UAPKI_TOO_LONG_BIT_STRING);
    }

    *bits = 0;
    DO(asn_BITSTRING2ba(bs, &ba_bitvalues));

    buf = ba_get_buf_const(ba_bitvalues);
    for (i = 0; i < (uint32_t)ba_get_len(ba_bitvalues); i++) {
        value <<= 8;
        value |= buf[i];
    }
    value >>= bs->bits_unused;
    *bits = value;

cleanup:
    ba_free(ba_bitvalues);
    return ret;
}

int asn_decodevalue_bmpstring (const BMPString_t* bmpStr, char** str)
{
    int ret = RET_OK;

    CHECK_PARAM(bmpStr != NULL);
    CHECK_PARAM(str != NULL);

    DO(utf16be_to_utf8(bmpStr->buf, bmpStr->size, str));

cleanup:
    return ret;
}

int asn_decodevalue_enumerated (const ENUMERATED_t* enumerated, uint32_t* enumValue)
{
    int ret = RET_OK;
    unsigned long value = 0;

    CHECK_PARAM(enumerated != NULL);
    CHECK_PARAM(enumValue != NULL);

    if ((enumerated->size > 0) && (enumerated->size < 4)) {
        DO(asn_INTEGER2ulong(enumerated, &value));
        *enumValue = (uint32_t)value;
    }
    else {
        SET_ERROR(RET_INVALID_PARAM);
    }

cleanup:
    return ret;
}

int asn_decodevalue_gentime (const GeneralizedTime_t* genTime, uint64_t* msTime)
{
    int ret = RET_OK;

    CHECK_PARAM(genTime != NULL);
    CHECK_PARAM(msTime != NULL);

    *msTime = asn_GT2msec(genTime, NULL, false);

cleanup:
    return ret;
}

int asn_decodevalue_octetstring_to_stime(const OCTET_STRING_t* octetTime, char** stime)
{
    int ret = RET_OK;
    size_t len = 0;
    const uint8_t* buf = NULL;
    char* s = NULL;

    CHECK_PARAM(octetTime != NULL);
    CHECK_PARAM(octetTime->size > 0);
    CHECK_PARAM(stime != NULL);

    buf = (const uint8_t*)octetTime->buf;
    len = (size_t)octetTime->size - 1;
    if (len >= 14) {
        DO(uint8_to_str_with_alloc(buf, len, stime));
    }
    else if (len == 12) {
        CALLOC_CHECKED(s, 15);
        if (buf[0] >= '5') {
            s[0] = '1';
            s[1] = '9';
        }
        else {
            s[0] = '2';
            s[1] = '0';
        }
        memcpy(&s[2], buf, 12);
        *stime = s;
        s = NULL;
    }
    else {
        SET_ERROR(RET_ASN1_TIME_ERROR);
    }

cleanup:
    free(s);
    return ret;
}

int asn_decodevalue_octetstring_to_str (const OCTET_STRING_t* octetString, char** str)
{
    int ret = RET_OK;

    CHECK_PARAM(octetString != NULL);
    CHECK_PARAM(str != NULL);

    DO(uint8_to_str_with_alloc(octetString->buf, (size_t)octetString->size, str));

cleanup:
    return ret;
}

int asn_decodevalue_pkixtime (const PKIXTime_t* pkixTime, uint64_t* msTime)
{
    int ret = RET_OK;

    CHECK_PARAM(pkixTime != NULL);
    CHECK_PARAM(msTime != NULL);

    *msTime = 0;
    switch (pkixTime->present) {
    case PKIXTime_PR_utcTime:
        *msTime = asn_UT2msec(&pkixTime->choice.utcTime, NULL, false);
        break;
    case PKIXTime_PR_generalTime:
        *msTime = asn_GT2msec(&pkixTime->choice.generalTime, NULL, false);
        break;
    default:
        SET_ERROR(RET_INVALID_PARAM);
    }

cleanup:
    return ret;
}

int asn_decodevalue_utctime (const UTCTime_t* utcTime, uint64_t* msTime)
{
    int ret = RET_OK;

    CHECK_PARAM(utcTime != NULL);
    CHECK_PARAM(msTime != NULL);

    *msTime = asn_UT2msec(utcTime, NULL, false);

cleanup:
    return ret;
}

int asn_encodevalue_gentime (GeneralizedTime_t* genTime, const char* stime)
{
    int ret = RET_OK;
    ByteArray* ba_date = NULL;
    size_t len;

    CHECK_PARAM(genTime != NULL);
    CHECK_PARAM(stime != NULL);

    len = strlen(stime);
    if (len < 14) {
        SET_ERROR(RET_INVALID_PARAM);
    }

    CHECK_NOT_NULL(ba_date = ba_alloc_from_str(stime));
    DO(ba_change_len(ba_date, len + 1));
    DO(ba_set_byte(ba_date, len, 'Z'));
    DO(asn_ba2OCTSTRING(ba_date, genTime));

cleanup:
    ba_free(ba_date);
    return ret;
}

bool asn_octetstring_data_is_equals (const OCTET_STRING_t* octetStr1, const OCTET_STRING_t* octetStr2)
{
    if ((octetStr1 == NULL) || (octetStr2 == NULL) || (octetStr1->size != octetStr2->size)) return false;

    return (memcmp(octetStr1->buf, octetStr2->buf, (size_t)octetStr2->size) == 0);
}

bool asn_primitive_data_is_equals (const ASN__PRIMITIVE_TYPE_t* primType1, const ASN__PRIMITIVE_TYPE_t* primType2)
{
    if ((primType1 == NULL) || (primType2 == NULL) || (primType1->size != primType2->size)) return false;

    return (memcmp(primType1->buf, primType2->buf, (size_t)primType2->size) == 0);
}

int ba_decode_anystring (const ByteArray* baEncoded, char** str)
{
    return asn_decode_anystring(ba_get_buf_const(baEncoded), ba_get_len(baEncoded), str);
}

int ba_decode_bmpstring (const ByteArray* baEncoded, char** str)
{
    int ret = RET_OK;
    BMPString_t* prim_bmpstr = NULL;

    CHECK_PARAM(baEncoded != NULL);
    CHECK_PARAM(str != NULL);

    CHECK_NOT_NULL(prim_bmpstr = asn_decode_ba_with_alloc(get_BMPString_desc(), baEncoded));
    DO(asn_decodevalue_bmpstring(prim_bmpstr, str));

cleanup:
    asn_free(get_BMPString_desc(), prim_bmpstr);
    return ret;
}

int ba_decode_enumerated (const ByteArray* baEncoded, uint32_t* enumValue)
{
    int ret = RET_OK;
    ENUMERATED_t* prim_enum = NULL;

    CHECK_PARAM(baEncoded != NULL);
    CHECK_PARAM(enumValue != NULL);

    CHECK_NOT_NULL(prim_enum = asn_decode_ba_with_alloc(get_ENUMERATED_desc(), baEncoded));
    DO(asn_decodevalue_enumerated(prim_enum, enumValue));

cleanup:
    asn_free(get_ENUMERATED_desc(), prim_enum);
    return ret;
}

int ba_decode_octetstring (const ByteArray* baEncoded, ByteArray** baData)
{
    int ret = RET_OK;
    OCTET_STRING_t* prim_octetstr = NULL;

    CHECK_PARAM(baEncoded != NULL);
    CHECK_PARAM(baData != NULL);

    CHECK_NOT_NULL(prim_octetstr = asn_decode_ba_with_alloc(get_OCTET_STRING_desc(), baEncoded));
    DO(asn_OCTSTRING2ba(prim_octetstr, baData));

cleanup:
    asn_free(get_OCTET_STRING_desc(), prim_octetstr);
    return ret;
}

int ba_decode_oid (const ByteArray* baEncoded, char** oid)
{
    int ret = RET_OK;
    OBJECT_IDENTIFIER_t* prim_oid = NULL;

    CHECK_PARAM(baEncoded != NULL);
    CHECK_PARAM(oid != NULL);

    CHECK_NOT_NULL(prim_oid = asn_decode_ba_with_alloc(get_OBJECT_IDENTIFIER_desc(), baEncoded));
    DO(asn_oid_to_text(prim_oid, oid));

cleanup:
    asn_free(get_OBJECT_IDENTIFIER_desc(), prim_oid);
    return ret;
}

int ba_decode_pkixtime (const ByteArray* baEncoded, uint64_t* unixTime)
{
    int ret = RET_OK;
    PKIXTime_t* pkix_time = NULL;

    CHECK_PARAM(baEncoded != NULL);
    CHECK_PARAM(unixTime != NULL);

    CHECK_NOT_NULL(pkix_time = asn_decode_ba_with_alloc(get_PKIXTime_desc(), baEncoded));
    DO(asn_decodevalue_pkixtime(pkix_time, unixTime));

cleanup:
    asn_free(get_PKIXTime_desc(), pkix_time);
    return ret;
}

int ba_decode_time (const ByteArray* baEncoded, uint64_t* unixTime, char** stime)
{
    int ret = RET_OK;
    PKIXTime_t* pkix_time = NULL;
    bool ok = false;

    CHECK_PARAM(baEncoded != NULL);

    CHECK_NOT_NULL(pkix_time = asn_decode_ba_with_alloc(get_PKIXTime_desc(), baEncoded));
    switch (pkix_time->present)
    {
    case PKIXTime_PR_utcTime:
        if (unixTime != NULL) {
            DO(asn_decodevalue_pkixtime(pkix_time, unixTime));
            ok = true;
        }
        if (stime != NULL) {
            DO(asn_decodevalue_octetstring_to_stime(&pkix_time->choice.utcTime, stime));
            ok = true;
        }
        break;
    case PKIXTime_PR_generalTime:
        if (unixTime != NULL) {
            DO(asn_decodevalue_pkixtime(pkix_time, unixTime));
            ok = true;
        }
        if (stime != NULL) {
            DO(asn_decodevalue_octetstring_to_stime(&pkix_time->choice.generalTime, stime));
            ok = true;
        }
        break;
    default:
        break;
    }

    if (!ok) {
        SET_ERROR(RET_UAPKI_TIME_ERROR);
    }

cleanup:
    asn_free(get_PKIXTime_desc(), pkix_time);
    return ret;
}

int ba_encode_bmpstring (const char* strUtf8, ByteArray** baEncoded)
{
    int ret = RET_OK;
    ByteArray* ba_utf16be = NULL;
    uint8_t* utf16 = NULL;
    size_t utf16_len = 0;

    CHECK_PARAM(strUtf8 != NULL);
    CHECK_PARAM(baEncoded != NULL);

    DO(utf8_to_utf16be(strUtf8, &utf16, &utf16_len));
    CHECK_NOT_NULL(ba_utf16be = ba_alloc_from_uint8(utf16, utf16_len));
    DO(ba_encode_octetstring(ba_utf16be, baEncoded));
    DO(ba_set_byte(*baEncoded, 0, 0x1E));

cleanup:
    ba_free(ba_utf16be);
    free(utf16);
    return ret;
}

int ba_encode_ia5string (const char* strLatin, ByteArray** baEncoded)
{
    int ret = RET_OK;
    IA5String_t* ia5_str = NULL;

    CHECK_PARAM(strLatin != NULL);
    CHECK_PARAM(baEncoded != NULL);

    ASN_ALLOC(ia5_str);
    if (strLatin) {
        DO(asn_bytes2OCTSTRING(ia5_str, (const uint8_t*)strLatin, strlen(strLatin)));
    }
    DO(asn_encode_ba(get_IA5String_desc(), ia5_str, baEncoded));

cleanup:
    asn_free(get_IA5String_desc(), ia5_str);
    return ret;
}

int ba_encode_integer (const ByteArray* baData, ByteArray** baEncoded)
{
    int ret = RET_OK;
    INTEGER_t* prim_integer = NULL;

    CHECK_PARAM(baData != NULL);
    CHECK_PARAM(baEncoded != NULL);

    ASN_ALLOC(prim_integer);
    DO(asn_ba2INTEGER(baData, prim_integer));
    DO(asn_encode_ba(get_INTEGER_desc(), prim_integer, baEncoded));

cleanup:
    asn_free(get_INTEGER_desc(), prim_integer);
    return ret;
}

int ba_encode_integer_int32 (const int32_t value, ByteArray** baEncoded)
{
    int ret = RET_OK;
    INTEGER_t* prim_integer = NULL;

    CHECK_PARAM(baEncoded != NULL);

    ASN_ALLOC(prim_integer);
    DO(asn_long2INTEGER(prim_integer, value));
    DO(asn_encode_ba(get_INTEGER_desc(), prim_integer, baEncoded));

cleanup:
    asn_free(get_INTEGER_desc(), prim_integer);
    return ret;
}

int ba_encode_octetstring (const ByteArray* baData, ByteArray** baEncoded)
{
    int ret = RET_OK;
    OCTET_STRING_t* octet_str = NULL;

    CHECK_PARAM(baData != NULL);
    CHECK_PARAM(baEncoded != NULL);

    ASN_ALLOC(octet_str);
    DO(asn_ba2OCTSTRING(baData, octet_str));
    DO(asn_encode_ba(get_OCTET_STRING_desc(), octet_str, baEncoded));

cleanup:
    asn_free(get_OCTET_STRING_desc(), octet_str);
    return ret;
}

int ba_encode_oid (const char* oid, ByteArray** baEncoded)
{
    int ret = RET_OK;
    OBJECT_IDENTIFIER_t* asn_oid = NULL;

    CHECK_PARAM(oid != NULL);
    CHECK_PARAM(baEncoded != NULL);

    ASN_ALLOC(asn_oid);
    DO(asn_set_oid_from_text(oid, asn_oid));
    DO(asn_encode_ba(get_OBJECT_IDENTIFIER_desc(), asn_oid, baEncoded));

cleanup:
    asn_free(get_OBJECT_IDENTIFIER_desc(), asn_oid);
    return ret;
}

int ba_encode_printablestring (const char* strLatin, ByteArray** baEncoded)
{
    int ret = RET_OK;
    PrintableString_t* printable_str = NULL;

    CHECK_PARAM(strLatin != NULL);
    CHECK_PARAM(baEncoded != NULL);

    ASN_ALLOC(printable_str);
    if (strLatin) {
        DO(asn_bytes2OCTSTRING(printable_str, (const uint8_t*)strLatin, strlen(strLatin)));
    }
    DO(asn_encode_ba(get_PrintableString_desc(), printable_str, baEncoded));

cleanup:
    asn_free(get_PrintableString_desc(), printable_str);
    return ret;
}

int ba_encode_utf8string (const char* strUtf8, ByteArray** baEncoded)
{
    int ret = RET_OK;
    UTF8String_t* utf8_str = NULL;

    CHECK_PARAM(strUtf8 != NULL);
    CHECK_PARAM(baEncoded != NULL);

    ASN_ALLOC(utf8_str);
    if (strUtf8) {
        DO(asn_bytes2OCTSTRING(utf8_str, (const uint8_t*)strUtf8, strlen(strUtf8)));
    }
    DO(asn_encode_ba(get_UTF8String_desc(), utf8_str, baEncoded));

cleanup:
    asn_free(get_UTF8String_desc(), utf8_str);
    return ret;
}


int uint8_to_str_with_alloc (const uint8_t* buf, const size_t len, char** str)
{
    int ret = RET_OK;

    CHECK_PARAM(buf != NULL);
    CHECK_PARAM(str != NULL);

    if (len > 0) {
        *str = calloc(1, len + 1);
        if (*str == NULL) {
            ret = RET_MEMORY_ALLOC_ERROR;
        }
        memcpy(*str, buf, len);
    }
    else {
        *str = NULL;
    }

cleanup:
    return ret;
}

