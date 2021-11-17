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

#include "api-json-internal.h"
#include "asn1-ba-utils.h"
#include "oid-utils.h"
#include "parson-helper.h"


#undef FILE_MARKER
#define FILE_MARKER "api/asn1-encode.cpp"


using namespace std;


static uint8_t asn1_name_to_tag (const char* name)
{
    uint8_t rv = 0;
    if (name != NULL) {
        if (     strcmp(name, "INTEGER")        == 0) rv = 0x02;
        else if (strcmp(name, "OCTET_STRING")   == 0) rv = 0x04;
        else if (strcmp(name, "NULL")           == 0) rv = 0x05;
        else if (strcmp(name, "OID")            == 0) rv = 0x06;
    }
    return rv;
}

static int asn1_encode_integer (JSON_Object* joItem, ByteArray** baEncoded)
{
    int ret = RET_OK;
    ByteArray* ba_value = NULL;

    const bool detect_integer = (json_object_has_value_of_type(joItem, "integer", JSONNumber) > 0);
    const bool detect_b64value = (json_object_has_value_of_type(joItem, "value", JSONString) > 0);

    if (detect_integer && !detect_b64value) {
        const int32_t value = (int32_t)json_object_get_number(joItem, "integer");
        DO(ba_encode_integer_int32(value, baEncoded));
    }
    else if (!detect_integer && detect_b64value) {
        CHECK_NOT_NULL(ba_value = json_object_get_base64(joItem, "value"));
        DO(ba_encode_integer(ba_value, baEncoded));
    }
    else {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

cleanup:
    ba_free(ba_value);
    return ret;
}

static int asn1_encode_null (ByteArray** baEncoded)
{
    int ret = RET_OK;

    CHECK_NOT_NULL(*baEncoded = ba_alloc_from_hex("0500"));

cleanup:
    return ret;
}

static int asn1_encode_octetstring (JSON_Object* joItem, ByteArray** baEncoded)
{
    int ret = RET_OK;
    ByteArray* ba_value = NULL;

    CHECK_NOT_NULL(ba_value = json_object_get_base64(joItem, "value"));
    DO(ba_encode_octetstring(ba_value, baEncoded));

cleanup:
    ba_free(ba_value);
    return ret;
}

static int asn1_encode_oid (JSON_Object* joItem, ByteArray** baEncoded)
{
    int ret = RET_OK;
    const char* s_oid = NULL;

    CHECK_NOT_NULL(s_oid = json_object_get_string(joItem, "value"));
    if (strlen(s_oid) >= 3) {
        DO(ba_encode_oid(s_oid, baEncoded));
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
    JSON_Array* ja_items = NULL;
    JSON_Array* ja_results = NULL;
    JSON_Object* jo_result = NULL;
    ByteArray* ba_encoded = NULL;
    const char* s_id = NULL;
    uint8_t tag = 0;
    size_t cnt_items = 0;

    ja_items = json_object_get_array(joParams, "items");
    cnt_items = json_array_get_count(ja_items);
    if (cnt_items == 0) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    DO_JSON(json_object_set_value(joResult, "encoded", json_value_init_array()));
    ja_results = json_object_get_array(joResult, "encoded");

    for (size_t i = 0; i < cnt_items; i++) {
        JSON_Object* jo_item = NULL;

        DO_JSON(json_array_append_value(ja_results, json_value_init_object()));
        jo_result = json_array_get_object(ja_results, i);

        jo_item = json_array_get_object(ja_items, i);
        tag = asn1_name_to_tag(json_object_get_string(jo_item, "tag"));
        switch (tag)
        {
        case 0x02:
            DO(asn1_encode_integer(jo_item, &ba_encoded));
            break;
        case 0x04:
            DO(asn1_encode_octetstring(jo_item, &ba_encoded));
            break;
        case 0x05:
            DO(asn1_encode_null(&ba_encoded));
            break;
        case 0x06:
            DO(asn1_encode_oid(jo_item, &ba_encoded));
            break;
        //TODO: need process other tag
        default:
            break;
        }
        //a need processing optional param "implicit"
        //a need processing constructed sequence and set

        s_id = json_object_get_string(jo_item, "id");
        if (s_id) {
            DO_JSON(json_object_set_string(jo_result, "id", s_id));
        }

        if (ret == RET_OK) {
            json_object_set_base64(jo_result, "bytes", ba_encoded);
        }
        else {
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
