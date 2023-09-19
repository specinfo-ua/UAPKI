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

#define FILE_MARKER "uapki/api/asn1-encode.cpp"

#include "api-json-internal.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include "time-util.h"
#include "uapki-ns-util.h"


using namespace std;
using namespace UapkiNS;


static uint8_t asn1_tagname_to_tagcode (
        const char* name
)
{
    uint8_t rv = 0;
    if (name) {
        const string s_name = string(name);
        if (     s_name == string("BOOLEAN"))           rv = 0x01;
        else if (s_name == string("INTEGER"))           rv = 0x02;
        else if (s_name == string("OCTET_STRING"))      rv = 0x04;
        else if (s_name == string("NULL"))              rv = 0x05;
        else if (s_name == string("OID"))               rv = 0x06;
        else if (s_name == string("UTF8_STRING"))       rv = 0x0C;
        else if (s_name == string("PRINTABLE_STRING"))  rv = 0x13;
        else if (s_name == string("IA5_STRING"))        rv = 0x16;
        else if (s_name == string("UTC_TIME"))          rv = 0x17;
        else if (s_name == string("GENERALIZED_TIME"))  rv = 0x18;
    }
    return rv;
}

static bool check_string_to_charmap (
        const string& str,
        const char firstCode,
        const char lastCode
)
{
    for (const auto& it : str) {
        if ((it < firstCode) || (it > lastCode)) {
            return false;
        }
    }
    return true;
}

static int asn1_encode_boolean (
        JSON_Object* joItem,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    bool value = false;

    if (!ParsonHelper::jsonObjectHasValue(joItem, "value", JSONBoolean)) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    value = ParsonHelper::jsonObjectGetBoolean(joItem, "value", false);
    DO(Util::encodeBoolean(value, baEncoded));

cleanup:
    return ret;
}

static int asn1_encode_integer (
        JSON_Object* joItem,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    SmartBA sba_value;

    const bool detect_integer = (json_object_has_value_of_type(joItem, "integer", JSONNumber) > 0);
    const bool detect_b64value = (json_object_has_value_of_type(joItem, "value", JSONString) > 0);

    if (detect_integer && !detect_b64value) {
        const int32_t value = (int32_t)json_object_get_number(joItem, "integer");
        DO(Util::encodeInteger(value, baEncoded));
    }
    else if (!detect_integer && detect_b64value) {
        if (!sba_value.set(json_object_get_base64(joItem, "value"))) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
        DO(Util::encodeInteger(sba_value.get(), baEncoded));
    }
    else {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

cleanup:
    return ret;
}

static int asn1_encode_null (
        ByteArray** baEncoded
)
{
    int ret = RET_OK;

    CHECK_NOT_NULL(*baEncoded = ba_alloc_from_hex("0500"));

cleanup:
    return ret;
}

static int asn1_encode_octetstring (
        JSON_Object* joItem,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    SmartBA sba_value;

    if (!sba_value.set(json_object_get_base64(joItem, "value"))) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }
    DO(Util::encodeOctetString(sba_value.get(), baEncoded));

cleanup:
    return ret;
}

static int asn1_encode_oid (
        JSON_Object* joItem,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;

    const string s_oid = ParsonHelper::jsonObjectGetString(joItem, "value");
    if (s_oid.length() >= 3) {
        DO(Util::encodeOid(s_oid.c_str(), baEncoded));
    }
    else {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

cleanup:
    return ret;
}

static int asn1_encode_string (
        JSON_Object* joItem,
        const uint8_t tag,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;

    const string s_value = ParsonHelper::jsonObjectGetString(joItem, "value");
    switch (tag) {
    case 0x0C:
        DO(Util::encodeUtf8string(s_value.c_str(), baEncoded));
        break;
    case 0x13:
        if (check_string_to_charmap(s_value, 0x20, 0x7A)) {
            DO(Util::encodePrintableString(s_value.c_str(), baEncoded));
        }
        else {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
        break;
    case 0x16:
        if (check_string_to_charmap(s_value, 0x00, 0x7F)) {
            DO(Util::encodeIa5String(s_value.c_str(), baEncoded));
        }
        else {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
        break;
        break;
    default:
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        break;
    }

cleanup:
    return ret;
}

static int asn1_encode_time (
        JSON_Object* joItem,
        const uint8_t tag,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    const bool is_gentime = (tag == 0x18);

    if (ParsonHelper::jsonObjectHasValue(joItem, "integer", JSONNumber)) {
        const uint64_t ms_time = (uint64_t)json_object_get_number(joItem, "integer");
        if (is_gentime) {
            DO(Util::encodeGenTime(ms_time, baEncoded));
        }
        else {
            DO(Util::encodeUtcTime(ms_time, baEncoded));
        }
    }
    else if (ParsonHelper::jsonObjectHasValue(joItem, "value", JSONString)) {
        const string s_ftime = ParsonHelper::jsonObjectGetString(joItem, "value");
        string s_stime;

        DO(TimeUtil::ftimeToStime(s_ftime, s_stime));
        s_stime.push_back('Z');
        if (is_gentime) {
            DO(Util::encodePrintableString(s_stime.c_str(), baEncoded));
        }
        else {
            DO(Util::encodePrintableString(s_stime.c_str() + 2, baEncoded));
        }
        DO(ba_set_byte(*baEncoded, 0, tag));
    }
    else {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

cleanup:
    return ret;
}


int uapki_asn1_encode (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    JSON_Array* ja_items = json_object_get_array(joParams, "items");
    JSON_Array* ja_results = nullptr;
    JSON_Object* jo_result = nullptr;
    const size_t cnt_items = json_array_get_count(ja_items);

    if (cnt_items == 0) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    DO_JSON(json_object_set_value(joResult, "encoded", json_value_init_array()));
    ja_results = json_object_get_array(joResult, "encoded");

    for (size_t i = 0; i < cnt_items; i++) {
        JSON_Object* jo_item = nullptr;
        SmartBA sba_encoded;
        string s_id;
        uint8_t tag = 0;

        DO_JSON(json_array_append_value(ja_results, json_value_init_object()));
        jo_result = json_array_get_object(ja_results, i);

        jo_item = json_array_get_object(ja_items, i);
        tag = asn1_tagname_to_tagcode(json_object_get_string(jo_item, "tag"));
        switch (tag)
        {
        case 0x01:
            DO(asn1_encode_boolean(jo_item, &sba_encoded));
            break;
        case 0x02:
            DO(asn1_encode_integer(jo_item, &sba_encoded));
            break;
        case 0x04:
            DO(asn1_encode_octetstring(jo_item, &sba_encoded));
            break;
        case 0x05:
            DO(asn1_encode_null(&sba_encoded));
            break;
        case 0x06:
            DO(asn1_encode_oid(jo_item, &sba_encoded));
            break;
        case 0x0C:
        case 0x13:
        case 0x16:
            DO(asn1_encode_string(jo_item, tag, &sba_encoded));
            break;
        case 0x17:
        case 0x18:
            DO(asn1_encode_time(jo_item, tag, &sba_encoded));
            break;
        default:
            SET_ERROR(RET_UAPKI_NOT_SUPPORTED);
            break;
        }

        s_id = ParsonHelper::jsonObjectGetString(jo_item, "id");
        if (!s_id.empty()) {
            DO_JSON(json_object_set_string(jo_result, "id", s_id.c_str()));
        }

        if (ret == RET_OK) {
            json_object_set_base64(jo_result, "bytes", sba_encoded.get());
        }
        else {
            ParsonHelper::jsonObjectSetBoolean(jo_result, "error", true);
            ret = RET_OK;
        }
    }

cleanup:
    return ret;
}
