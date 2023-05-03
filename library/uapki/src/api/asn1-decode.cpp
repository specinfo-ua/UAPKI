/*
 * Copyright (c) 2023, The UAPKI Project Authors.
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

#include "api-json-internal.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include "time-util.h"
#include "uapki-ns-util.h"


#undef FILE_MARKER
#define FILE_MARKER "api/asn1-decode.cpp"


using namespace std;


static const char* ASN1_TAG_NAMES[31] = {
    NULL,   //  [0x00] EOC
    "BOOLEAN",
    "INTEGER",
    "BIT_STRING",
    "OCTET_STRING",
    "NULL",
    "OID",
    NULL,   //  [0x07] OBJECT_DESCRIPTOR
    NULL,   //  [0x08] EXTERNAL
    NULL,   //  [0x09] REAL
    "ENUMERATED",
    NULL,   //  [0x0B]
    "UTF8_STRING",
    NULL,   //  [0x0D] RELATIVE_OID
    NULL,   //  [0x0E]
    NULL,   //  [0x0F]
    NULL,   //  [0x10] SEQUENCE
    NULL,   //  [0x11] SET
    NULL,   //  [0x12] NUMERIC_STRING
    "PRINTABLE_STRING",
    NULL,   //  [0x14] T61_STRING
    NULL,   //  [0x15] VIDEOTEXT_STRING
    "IA5_STRING",
    "UTC_TIME",
    "GENERALIZED_TIME",
    NULL,   //  [0x19] GRAPHIC_STRING
    NULL,   //  [0x1A] VISIBLE_STRING
    NULL,   //  [0x1B] GENERAL_STRING
    NULL,   //  [0x1C] UNIVERSAL_STRING
    NULL,   //  [0x1D]
    "BMP_STRING"
};

static const char* asn1_tag_to_name (const uint8_t tag)
{
    const char* rv_s = NULL;
    if (tag < 31) rv_s = ASN1_TAG_NAMES[tag];
    else if (tag == 0x30) rv_s = "SEQUENCE";
    else if (tag == 0x31) rv_s = "SET";
    //0x80..0x87 CONTEXT_0..CONTEXT_7
    //0xA0..0xA7 CONTEXT_A..CONTEXT_H
    return rv_s;
}

static int asn1_decode_bit_string (const ByteArray* baEncoded, JSON_Object* joResult)
{
    int ret = RET_OK;
    BIT_STRING_t* prim_bitstr = NULL;
    ByteArray* ba_data = NULL;
    uint32_t bits = 0;

    CHECK_NOT_NULL(prim_bitstr = (BIT_STRING_t*)asn_decode_ba_with_alloc(get_BIT_STRING_desc(), baEncoded));
    DO(asn_BITSTRING2ba(prim_bitstr, &ba_data));
    DO_JSON(json_object_set_base64(joResult, "value", ba_data));
    if ((ba_get_len(ba_data) > 0) && (ba_get_len(ba_data) < 4)) {
        DO(UapkiNS::Util::bitStringFromAsn1(prim_bitstr, &bits));
        DO_JSON(json_object_set_number(joResult, "integer", (double)bits));
    }

cleanup:
    asn_free(get_BIT_STRING_desc(), prim_bitstr);
    ba_free(ba_data);
    return ret;
}

static int asn1_decode_bmp_string (const ByteArray* baEncoded, JSON_Object* joResult)
{
    int ret = RET_OK;
    BMPString_t* bmp_str = NULL;
    ByteArray* ba_value = NULL;
    char* s_value = NULL;

    CHECK_NOT_NULL(bmp_str = (BMPString_t*)asn_decode_ba_with_alloc(get_BMPString_desc(), baEncoded));
    DO(UapkiNS::Util::bmpStringFromAsn1(bmp_str, &s_value));
    DO_JSON(json_object_set_string(joResult, "value", s_value));
    if ((bmp_str->buf != NULL) && (bmp_str->size > 0)) {
        CHECK_NOT_NULL(ba_value = ba_alloc_from_uint8(bmp_str->buf, bmp_str->size));
        DO_JSON(json_object_set_base64(joResult, "bytes", ba_value));
    }

cleanup:
    asn_free(get_BMPString_desc(), bmp_str);
    ba_free(ba_value);
    ::free(s_value);
    return ret;
}

static int asn1_decode_boolean (const ByteArray* baEncoded, JSON_Object* joResult)
{
    int ret = RET_OK;
    BOOLEAN_t* prim_boolean = NULL;

    CHECK_NOT_NULL(prim_boolean = (BOOLEAN_t*)asn_decode_ba_with_alloc(get_BOOLEAN_desc(), baEncoded));
    DO_JSON(json_object_set_boolean(joResult, "value", *prim_boolean));

cleanup:
    asn_free(get_BOOLEAN_desc(), prim_boolean);
    return ret;
}

static int asn1_decode_enumerated (const ByteArray* baEncoded, JSON_Object* joResult)
{
    int ret = RET_OK;
    ENUMERATED_t* prim_enum = NULL;
    uint32_t value = 0;

    CHECK_NOT_NULL(prim_enum = (ENUMERATED_t*)asn_decode_ba_with_alloc(get_ENUMERATED_desc(), baEncoded));
    DO(UapkiNS::Util::enumeratedFromAsn1(prim_enum, &value));
    DO_JSON(json_object_set_number(joResult, "value", (double)value));

cleanup:
    asn_free(get_ENUMERATED_desc(), prim_enum);
    return ret;
}

static int asn1_decode_gentime (const ByteArray* baEncoded, JSON_Object* joResult)
{
    int ret = RET_OK;
    GeneralizedTime_t* gen_time = nullptr;
    uint64_t ms_time;
    string stime;
    ::tm tm_data;

    CHECK_NOT_NULL(gen_time = (GeneralizedTime_t*)asn_decode_ba_with_alloc(get_GeneralizedTime_desc(), baEncoded));

    ms_time = asn_GT2time(gen_time, &tm_data);
    if (ms_time > 0) {
        stime = TimeUtil::tmToFtime(tm_data);
    }
    DO_JSON(json_object_set_string(joResult, "value", stime.c_str()));
    DO_JSON(ParsonHelper::jsonObjectSetUint64(joResult, "integer", ms_time));

cleanup:
    asn_free(get_GeneralizedTime_desc(), gen_time);
    return ret;
}

static int asn1_decode_integer (const ByteArray* baEncoded, JSON_Object* joResult)
{
    int ret = RET_OK;
    INTEGER_t* prim_integer = NULL;
    ByteArray* ba_data = NULL;
    long value = 0;

    CHECK_NOT_NULL(prim_integer = (INTEGER_t*)asn_decode_ba_with_alloc(get_INTEGER_desc(), baEncoded));
    DO(asn_INTEGER2ba(prim_integer, &ba_data));
    DO_JSON(json_object_set_base64(joResult, "value", ba_data));
    if ((ba_get_len(ba_data) > 0) && (ba_get_len(ba_data) < 4)) {
        DO(asn_INTEGER2long(prim_integer, &value));
        DO_JSON(json_object_set_number(joResult, "integer", (double)value));
    }

cleanup:
    asn_free(get_INTEGER_desc(), prim_integer);
    ba_free(ba_data);
    return ret;
}

static int asn1_decode_null (const ByteArray* baEncoded, JSON_Object* joResult)
{
    int ret = RET_OK;
    NULL_t* prim_null = NULL;

    CHECK_NOT_NULL(prim_null = (NULL_t*)asn_decode_ba_with_alloc(get_NULL_desc(), baEncoded));

cleanup:
    asn_free(get_NULL_desc(), prim_null);
    return ret;
}

static int asn1_decode_octet_string (const ByteArray* baEncoded, JSON_Object* joResult)
{
    int ret = RET_OK;
    OCTET_STRING_t* prim_octetstr = NULL;
    ByteArray* ba_data = NULL;

    CHECK_NOT_NULL(prim_octetstr = (OCTET_STRING_t*)asn_decode_ba_with_alloc(get_OCTET_STRING_desc(), baEncoded));
    DO(asn_OCTSTRING2ba(prim_octetstr, &ba_data));
    DO_JSON(json_object_set_base64(joResult, "value", ba_data));

cleanup:
    asn_free(get_OCTET_STRING_desc(), prim_octetstr);
    ba_free(ba_data);
    return ret;
}

static int asn1_decode_oid (const ByteArray* baEncoded, JSON_Object* joResult)
{
    int ret = RET_OK;
    OBJECT_IDENTIFIER_t* prim_oid = NULL;
    char* s_oid = NULL;

    CHECK_NOT_NULL(prim_oid = (OBJECT_IDENTIFIER_t*)asn_decode_ba_with_alloc(get_OBJECT_IDENTIFIER_desc(), baEncoded));
    DO(asn_oid_to_text(prim_oid, &s_oid));
    DO_JSON(json_object_set_string(joResult, "value", s_oid));

cleanup:
    asn_free(get_OBJECT_IDENTIFIER_desc(), prim_oid);
    ::free(s_oid);
    return ret;
}

static int asn1_decode_string (asn_TYPE_descriptor_t* desc, const ByteArray* baEncoded, JSON_Object* joResult)
{
    int ret = RET_OK;
    OCTET_STRING_t* octet_str = nullptr;
    ByteArray* ba_value = nullptr;
    char* s_value = nullptr;

    CHECK_NOT_NULL(octet_str = (OCTET_STRING_t*)asn_decode_ba_with_alloc(desc, baEncoded));
    DO(UapkiNS::Util::pbufToStr(octet_str->buf, (size_t)octet_str->size, &s_value));
    DO_JSON(json_object_set_string(joResult, "value", s_value));

    if ((octet_str->buf != NULL) && (octet_str->size > 0)) {
        CHECK_NOT_NULL(ba_value = ba_alloc_from_uint8(octet_str->buf, octet_str->size));
        DO_JSON(json_object_set_base64(joResult, "bytes", ba_value));
    }

cleanup:
    asn_free(desc, octet_str);
    ba_free(ba_value);
    ::free(s_value);
    return ret;
}

static int asn1_decode_utctime (const ByteArray* baEncoded, JSON_Object* joResult)
{
    int ret = RET_OK;
    UTCTime_t* utc_time = nullptr;
    char* s_value = nullptr;
    uint64_t ms_time;
    string stime;
    ::tm tm_data;

    CHECK_NOT_NULL(utc_time = (UTCTime_t*)asn_decode_ba_with_alloc(get_UTCTime_desc(), baEncoded));

    ms_time = asn_UT2time(utc_time, &tm_data);
    if (ms_time > 0) {
        stime = TimeUtil::tmToFtime(tm_data);
    }
    DO_JSON(json_object_set_string(joResult, "value", stime.c_str()));
    DO_JSON(ParsonHelper::jsonObjectSetUint64(joResult, "integer", ms_time));

cleanup:
    asn_free(get_UTCTime_desc(), utc_time);
    ::free(s_value);
    return ret;
}


int uapki_asn1_decode (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    JSON_Array* ja_items = NULL;
    JSON_Array* ja_results = NULL;
    JSON_Object* jo_result = NULL;
    ByteArray* ba_encoded = NULL;
    const char* s_id = NULL;
    const char* s_tag = NULL;
    uint8_t tag = 0;
    size_t cnt_items = 0;

    ja_items = json_object_get_array(joParams, "items");
    cnt_items = json_array_get_count(ja_items);
    if (cnt_items == 0) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    DO_JSON(json_object_set_value(joResult, "decoded", json_value_init_array()));
    ja_results = json_object_get_array(joResult, "decoded");

    for (size_t i = 0; i < cnt_items; i++) {
        JSON_Object* jo_item = NULL;

        DO_JSON(json_array_append_value(ja_results, json_value_init_object()));
        jo_result = json_array_get_object(ja_results, i);

        jo_item = json_array_get_object(ja_items, i);
        ba_encoded = json_object_get_base64(jo_item, "bytes");
        ret = (ba_get_len(ba_encoded) > 0) ? RET_OK : RET_INVALID_PARAM;
        s_id = json_object_get_string(jo_item, "id");
        if (s_id) {
            DO_JSON(json_object_set_string(jo_result, "id", s_id));
        }
        //a need processing optional param "implicit"
        //a need processing constructed sequence and set

        tag = 0;
        s_tag = NULL;
        if (ret == RET_OK) {
            ba_get_byte(ba_encoded, 0, &tag);
            s_tag = asn1_tag_to_name(tag);
            if (s_tag != NULL) {
                DO_JSON(json_object_set_string(jo_result, "tag", s_tag));
            }
            else {
                DO_JSON(json_object_set_number(jo_result, "tag", (double)tag));
            }

            switch (tag) {
            case 0x01:
                ret = asn1_decode_boolean(ba_encoded, jo_result);
                break;
            case 0x02:
                ret = asn1_decode_integer(ba_encoded, jo_result);
                break;
            case 0x03:
                ret = asn1_decode_bit_string(ba_encoded, jo_result);
                break;
            case 0x04:
                ret = asn1_decode_octet_string(ba_encoded, jo_result);
                break;
            case 0x05:
                ret = asn1_decode_null(ba_encoded, jo_result);
                break;
            case 0x06:
                ret = asn1_decode_oid(ba_encoded, jo_result);
                break;
            case 0x0A:
                ret = asn1_decode_enumerated(ba_encoded, jo_result);
                break;
            case 0x0C:
                ret = asn1_decode_string(get_UTF8String_desc(), ba_encoded, jo_result);
                break;
            case 0x13:
                ret = asn1_decode_string(get_PrintableString_desc(), ba_encoded, jo_result);
                break;
            case 0x16:
                ret = asn1_decode_string(get_IA5String_desc(), ba_encoded, jo_result);
                break;
            case 0x17:
                ret = asn1_decode_utctime(ba_encoded, jo_result);
                break;
            case 0x18:
                ret = asn1_decode_gentime(ba_encoded, jo_result);
                break;
            case 0x1E:
                ret = asn1_decode_bmp_string(ba_encoded, jo_result);
                break;
            }
        }

        if (ret != RET_OK) {
            json_object_set_boolean(jo_result, "error", 1);
            ret = RET_OK;
        }

        ba_free(ba_encoded);
        ba_encoded = NULL;
    }

cleanup:
    ba_free(ba_encoded);
    return ret;
}
