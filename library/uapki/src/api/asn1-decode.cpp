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

#define FILE_MARKER "uapki/api/asn1-decode.cpp"

#include "api-json-internal.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include "time-util.h"
#include "uapki-ns-util.h"


using namespace std;
using namespace UapkiNS;


static const char* ASN1_TAG_NAMES[31] = {
    nullptr,    //  [0x00] EOC
    "BOOLEAN",
    "INTEGER",
    "BIT_STRING",
    "OCTET_STRING",
    "NULL",
    "OID",
    nullptr,    //  [0x07] OBJECT_DESCRIPTOR
    nullptr,    //  [0x08] EXTERNAL
    nullptr,    //  [0x09] REAL
    "ENUMERATED",
    nullptr,    //  [0x0B]
    "UTF8_STRING",
    nullptr,    //  [0x0D] RELATIVE_OID
    nullptr,    //  [0x0E]
    nullptr,    //  [0x0F]
    nullptr,    //  [0x10] SEQUENCE
    nullptr,    //  [0x11] SET
    nullptr,    //  [0x12] NUMERIC_STRING
    "PRINTABLE_STRING",
    nullptr,    //  [0x14] T61_STRING
    nullptr,    //  [0x15] VIDEOTEXT_STRING
    "IA5_STRING",
    "UTC_TIME",
    "GENERALIZED_TIME",
    nullptr,    //  [0x19] GRAPHIC_STRING
    nullptr,    //  [0x1A] VISIBLE_STRING
    nullptr,    //  [0x1B] GENERAL_STRING
    nullptr,    //  [0x1C] UNIVERSAL_STRING
    nullptr,    //  [0x1D]
    "BMP_STRING"
};

static const char* asn1_tag_to_name (
        const uint8_t tag
)
{
    const char* rv_s = nullptr;
    if (tag < 31) rv_s = ASN1_TAG_NAMES[tag];
    else if (tag == 0x30) rv_s = "SEQUENCE";
    else if (tag == 0x31) rv_s = "SET";
    //0x80..0x87 CONTEXT_0..CONTEXT_7
    //0xA0..0xA7 CONTEXT_A..CONTEXT_H
    return rv_s;
}

static int asn1_decode_bit_string (
        const ByteArray* baEncoded,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    BIT_STRING_t* prim_bitstr = nullptr;
    SmartBA sba_data;
    uint32_t bits = 0;

    CHECK_NOT_NULL(prim_bitstr = (BIT_STRING_t*)asn_decode_ba_with_alloc(get_BIT_STRING_desc(), baEncoded));
    DO(asn_BITSTRING2ba(prim_bitstr, &sba_data));
    DO_JSON(json_object_set_base64(joResult, "value", sba_data.get()));
    if ((sba_data.size() > 0) && (sba_data.size() < 4)) {
        DO(Util::bitStringFromAsn1(prim_bitstr, &bits));
        DO_JSON(json_object_set_number(joResult, "integer", (double)bits));
    }

cleanup:
    asn_free(get_BIT_STRING_desc(), prim_bitstr);
    return ret;
}

static int asn1_decode_bmp_string (
        const ByteArray* baEncoded,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    BMPString_t* bmp_str = nullptr;
    SmartBA sba_value;
    string s_value;

    CHECK_NOT_NULL(bmp_str = (BMPString_t*)asn_decode_ba_with_alloc(get_BMPString_desc(), baEncoded));
    DO(Util::bmpStringFromAsn1(bmp_str, s_value));
    DO_JSON(json_object_set_string(joResult, "value", s_value.c_str()));
    if (bmp_str->buf && (bmp_str->size > 0)) {
        if (!sba_value.set(ba_alloc_from_uint8(bmp_str->buf, bmp_str->size))) {
            SET_ERROR(RET_UAPKI_GENERAL_ERROR);
        }
        DO_JSON(json_object_set_base64(joResult, "bytes", sba_value.get()));
    }

cleanup:
    asn_free(get_BMPString_desc(), bmp_str);
    return ret;
}

static int asn1_decode_boolean (
        const ByteArray* baEncoded,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    bool value = false;

    DO(Util::decodeBoolean(baEncoded, value));
    DO_JSON(json_object_set_boolean(joResult, "value", value));

cleanup:
    return ret;
}

static int asn1_decode_enumerated (
        const ByteArray* baEncoded,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    ENUMERATED_t* prim_enum = nullptr;
    uint32_t value = 0;

    CHECK_NOT_NULL(prim_enum = (ENUMERATED_t*)asn_decode_ba_with_alloc(get_ENUMERATED_desc(), baEncoded));
    DO(Util::enumeratedFromAsn1(prim_enum, &value));
    DO_JSON(json_object_set_number(joResult, "value", (double)value));

cleanup:
    asn_free(get_ENUMERATED_desc(), prim_enum);
    return ret;
}

static int asn1_decode_gentime (
        const ByteArray* baEncoded,
        JSON_Object* joResult
)
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

static int asn1_decode_integer (
        const ByteArray* baEncoded,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    INTEGER_t* prim_integer = nullptr;
    SmartBA sba_data;
    long value = 0;

    CHECK_NOT_NULL(prim_integer = (INTEGER_t*)asn_decode_ba_with_alloc(get_INTEGER_desc(), baEncoded));
    DO(asn_INTEGER2ba(prim_integer, &sba_data));
    DO_JSON(json_object_set_base64(joResult, "value", sba_data.get()));
    if ((sba_data.size() > 0) && (sba_data.size() < 4)) {
        DO(asn_INTEGER2long(prim_integer, &value));
        DO_JSON(json_object_set_number(joResult, "integer", (double)value));
    }

cleanup:
    asn_free(get_INTEGER_desc(), prim_integer);
    return ret;
}

static int asn1_decode_null (
        const ByteArray* baEncoded,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    NULL_t* prim_null = nullptr;

    CHECK_NOT_NULL(prim_null = (NULL_t*)asn_decode_ba_with_alloc(get_NULL_desc(), baEncoded));

cleanup:
    asn_free(get_NULL_desc(), prim_null);
    return ret;
}

static int asn1_decode_octet_string (
        const ByteArray* baEncoded,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    SmartBA sba_data;

    DO(Util::decodeOctetString(baEncoded, &sba_data));
    DO_JSON(json_object_set_base64(joResult, "value", sba_data.get()));

cleanup:
    return ret;
}

static int asn1_decode_oid (
        const ByteArray* baEncoded,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    string s_oid;

    DO(Util::decodeOid(baEncoded, s_oid));
    DO_JSON(json_object_set_string(joResult, "value", s_oid.c_str()));

cleanup:
    return ret;
}

static int asn1_decode_string (
        asn_TYPE_descriptor_t* desc,
        const ByteArray* baEncoded,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    OCTET_STRING_t* octet_str = nullptr;
    SmartBA sba_value;
    string s_value;

    CHECK_NOT_NULL(octet_str = (OCTET_STRING_t*)asn_decode_ba_with_alloc(desc, baEncoded));
    DO(Util::pbufToStr(octet_str->buf, (size_t)octet_str->size, s_value));
    DO_JSON(json_object_set_string(joResult, "value", s_value.c_str()));

    if (octet_str->buf && (octet_str->size > 0)) {
        if (!sba_value.set(ba_alloc_from_uint8(octet_str->buf, octet_str->size))) {
            SET_ERROR(RET_UAPKI_GENERAL_ERROR);
        }
        DO_JSON(json_object_set_base64(joResult, "bytes", sba_value.get()));
    }

cleanup:
    asn_free(desc, octet_str);
    return ret;
}

static int asn1_decode_utctime (
        const ByteArray* baEncoded,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    UTCTime_t* utc_time = nullptr;
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
    return ret;
}


int uapki_asn1_decode (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    JSON_Array* ja_items = json_object_get_array(joParams, "items");
    JSON_Array* ja_results = nullptr;
    JSON_Object* jo_result = nullptr;
    const size_t cnt_items = json_array_get_count(ja_items);

    if (cnt_items == 0) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    DO_JSON(json_object_set_value(joResult, "decoded", json_value_init_array()));
    ja_results = json_object_get_array(joResult, "decoded");

    for (size_t i = 0; i < cnt_items; i++) {
        JSON_Object* jo_item = nullptr;
        SmartBA sba_encoded;
        string s_id;

        DO_JSON(json_array_append_value(ja_results, json_value_init_object()));
        jo_result = json_array_get_object(ja_results, i);

        jo_item = json_array_get_object(ja_items, i);
        (void)sba_encoded.set(json_object_get_base64(jo_item, "bytes"));
        ret = (sba_encoded.size() >= 2) ? RET_OK : RET_UAPKI_INVALID_PARAMETER;
        s_id = ParsonHelper::jsonObjectGetString(jo_item, "id");
        if (!s_id.empty()) {
            DO_JSON(json_object_set_string(jo_result, "id", s_id.c_str()));
        }

        if (ret == RET_OK) {
            uint8_t tag = 0;
            ba_get_byte(sba_encoded.get(), 0, &tag);

            const char* s_tag = asn1_tag_to_name(tag);
            if (s_tag) {
                DO_JSON(json_object_set_string(jo_result, "tag", s_tag));
            }
            else {
                DO_JSON(ParsonHelper::jsonObjectSetUint32(jo_result, "tag", (uint32_t)tag));
            }

            switch (tag) {
            case 0x01:
                ret = asn1_decode_boolean(sba_encoded.get(), jo_result);
                break;
            case 0x02:
                ret = asn1_decode_integer(sba_encoded.get(), jo_result);
                break;
            case 0x03:
                ret = asn1_decode_bit_string(sba_encoded.get(), jo_result);
                break;
            case 0x04:
                ret = asn1_decode_octet_string(sba_encoded.get(), jo_result);
                break;
            case 0x05:
                ret = asn1_decode_null(sba_encoded.get(), jo_result);
                break;
            case 0x06:
                ret = asn1_decode_oid(sba_encoded.get(), jo_result);
                break;
            case 0x0A:
                ret = asn1_decode_enumerated(sba_encoded.get(), jo_result);
                break;
            case 0x0C:
                ret = asn1_decode_string(get_UTF8String_desc(), sba_encoded.get(), jo_result);
                break;
            case 0x13:
                ret = asn1_decode_string(get_PrintableString_desc(), sba_encoded.get(), jo_result);
                break;
            case 0x16:
                ret = asn1_decode_string(get_IA5String_desc(), sba_encoded.get(), jo_result);
                break;
            case 0x17:
                ret = asn1_decode_utctime(sba_encoded.get(), jo_result);
                break;
            case 0x18:
                ret = asn1_decode_gentime(sba_encoded.get(), jo_result);
                break;
            case 0x1E:
                ret = asn1_decode_bmp_string(sba_encoded.get(), jo_result);
                break;
            }
        }

        if (ret != RET_OK) {
            ParsonHelper::jsonObjectSetBoolean(jo_result, "error", true);
            ret = RET_OK;
        }
    }

cleanup:
    return ret;
}
