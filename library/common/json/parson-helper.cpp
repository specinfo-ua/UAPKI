/*
 * Copyright (c) 2022, The UAPKI Project Authors.
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

#include "parson-helper.h"
#include <string.h>


#define MIN_INT32 (-2147483647l)
#define MIN_INT52 (-4503599627370496ll)
#define MAX_INT32 (2147483647l)
#define MAX_INT52  (4503599627370495ll)
#define MAX_UINT32 (0xFFFFFFFF)
#define MAX_UINT52 (4503599627370495ul)


using namespace std;


ParsonHelper::ParsonHelper (void)
    : m_JsonValue(nullptr), m_JsonRefObj(nullptr)
{
}

ParsonHelper::~ParsonHelper (void)
{
    cleanup();
}

void ParsonHelper::cleanup (void)
{
    m_JsonRefObj = nullptr;
    json_value_free(m_JsonValue);
    m_JsonValue = nullptr;
}

JSON_Object* ParsonHelper::create (void)
{
    m_JsonValue = json_value_init_object();
    m_JsonRefObj = json_value_get_object(m_JsonValue);
    return m_JsonRefObj;
}

bool ParsonHelper::serialize (char** sJson)
{
    bool rv_ok = false;
    if (sJson) {
        *sJson = nullptr;
        const size_t size = json_serialization_size(m_JsonValue);
        char* out_buf = (char*)malloc(size);
        if (out_buf) {
            rv_ok = (json_serialize_to_buffer(m_JsonValue, out_buf, size) == JSONSuccess);
            if (!rv_ok) {
                free(out_buf);
                out_buf = nullptr;
            }
            *sJson = out_buf;
        }
    }
    cleanup();
    return rv_ok;
}

bool ParsonHelper::serialize (string& sJson)
{
    bool rv_ok = false;
    const size_t size = json_serialization_size(m_JsonValue);
    sJson.clear();
    if (size > 1) {
        sJson.resize(size - 1);
        if (!sJson.empty()) {
            rv_ok = (json_serialize_to_buffer(m_JsonValue, (char*)sJson.data(), size) == JSONSuccess);
            if (!rv_ok) {
                sJson.clear();
            }
        }
    }
    cleanup();
    return rv_ok;
}


JSON_Array* ParsonHelper::setArray (const char* key)
{
    json_object_set_value(m_JsonRefObj, key, json_value_init_array());
    return json_object_get_array(m_JsonRefObj, key);
}

bool ParsonHelper::setBoolean (const char* key, const bool value)
{
    return (json_object_set_boolean(m_JsonRefObj, key, (value) ? 1 : 0) == JSONSuccess);
}

bool ParsonHelper::setInt32 (const char* key, const int32_t value)
{
    return (json_object_set_number(m_JsonRefObj, key, (double)value) == JSONSuccess);
}

bool ParsonHelper::setInt64 (const char* key, const int64_t value)
{
    return (value >= MIN_INT52) && (value <= MAX_INT52) && (json_object_set_number(m_JsonRefObj, key, (double)value) == JSONSuccess);
}

JSON_Object* ParsonHelper::setObject (const char* key)
{
    json_object_set_value(m_JsonRefObj, key, json_value_init_object());
    return json_object_get_object(m_JsonRefObj, key);
}

bool ParsonHelper::setString (const char* key, const char* value)
{
    return (json_object_set_string(m_JsonRefObj, key, value) == JSONSuccess);
}

bool ParsonHelper::setString (const char* key, const string &value)
{
    return (json_object_set_string(m_JsonRefObj, key, value.c_str()) == JSONSuccess);
}

bool ParsonHelper::setUint32 (const char* key, const uint32_t value)
{
    return (json_object_set_number(m_JsonRefObj, key, (double)value) == JSONSuccess);
}

bool ParsonHelper::setUint64 (const char* key, const uint64_t value)
{
    return (value <= MAX_UINT52) && (json_object_set_number(m_JsonRefObj, key, (double)value) == JSONSuccess);
}

JSON_Object* ParsonHelper::parse (const char* sJson, const bool withComments)
{
    m_JsonValue = (withComments) ? json_parse_string_with_comments(sJson) : json_parse_string(sJson);
    m_JsonRefObj = json_value_get_object(m_JsonValue);
    return m_JsonRefObj;
}

JSON_Array* ParsonHelper::getArray (const char* key)
{
    return json_object_get_array(m_JsonRefObj, key);
}

bool ParsonHelper::getBoolean (const char* key, const bool defValue)
{
    return jsonObjectGetBoolean(m_JsonRefObj, key, defValue);
}

JSON_Object* ParsonHelper::getObject (const char* key)
{
    return json_object_get_object(m_JsonRefObj, key);
}

int ParsonHelper::getInt (const char* key)
{
    return (int)json_object_get_number(m_JsonRefObj, key);
}

const char* ParsonHelper::getString (const char* key)
{
    return json_object_get_string(m_JsonRefObj, key);
}

const char* ParsonHelper::getString (const char* key, string& s)
{
    const char* rv_s = json_object_get_string(m_JsonRefObj, key);
    if (rv_s) {
        s = string(rv_s);
    }
    return rv_s;
}

bool ParsonHelper::hasValue (const char* key)
{
    return jsonObjectHasValue(m_JsonRefObj, key);
}

bool ParsonHelper::hasValue (const char* key, const JSON_Value_Type type)
{
    return jsonObjectHasValue(m_JsonRefObj, key, type);
}

void ParsonHelper::setEscapeSlashes (const int escapeSlashes)
{
    json_set_escape_slashes(escapeSlashes);
}

string ParsonHelper::jsonArrayGetString (JSON_Array* ja, const size_t index, const string& defValue)
{
    string rv_s = defValue;
    const char* s = json_array_get_string(ja, index);
    if (s && (strlen(s) > 0)) {
        rv_s.resize(strlen(s));
        memcpy((void*)rv_s.data(), s, rv_s.size());
    }
    return rv_s;
}

bool ParsonHelper::jsonObjectGetBoolean (JSON_Object* jo, const char* key, const bool defValue)
{
    const int b_val = json_object_get_boolean(jo, key);
    return (b_val > 0) ? true : ((b_val == 0) ? false : defValue);
}

int32_t ParsonHelper::jsonObjectGetInt32 (JSON_Object* jo, const char* key, const int32_t defValue)
{
    int32_t rv = defValue;
    if (json_object_has_value_of_type(jo, key, JSONNumber)) {
        const double f_value = json_object_get_number(jo, key);
        if ((f_value >= MIN_INT32) && (f_value <= MAX_INT32)) {
            rv = (int32_t)f_value;
        }
    }
    return rv;
}

uint32_t ParsonHelper::jsonObjectGetUint32 (JSON_Object* jo, const char* key, const uint32_t defValue)
{
    uint32_t rv = defValue;
    if (json_object_has_value_of_type(jo, key, JSONNumber)) {
        const double f_value = json_object_get_number(jo, key);
        if ((f_value >= 0) && (f_value <= MAX_UINT32)) {
            rv = (uint32_t)f_value;
        }
    }
    return rv;
}

string ParsonHelper::jsonObjectGetString (JSON_Object* jo, const char* key, const string& defValue)
{
    string rv_s = defValue;
    const char* s = json_object_get_string(jo, key);
    if (s && (strlen(s) > 0)) {
        rv_s.resize(strlen(s));
        memcpy((void*)rv_s.data(), s, rv_s.size());
    }
    return rv_s;
}

bool ParsonHelper::jsonObjectHasValue (JSON_Object* jo, const char* key)
{
    return (json_object_has_value(jo, key) > 0);
}

bool ParsonHelper::jsonObjectHasValue (JSON_Object* jo, const char* key, const JSON_Value_Type type)
{
    return (json_object_has_value_of_type(jo, key, type) > 0);
}

JSON_Status ParsonHelper::jsonObjectSetBoolean (JSON_Object* jo, const char* key, const bool value)
{
    return json_object_set_boolean(jo, key, (value) ? 1 : 0);
}

JSON_Status ParsonHelper::jsonObjectSetInt32 (JSON_Object* jo, const char* key, const int32_t value)
{
    return json_object_set_number(jo, key, (double)value);
}

JSON_Status ParsonHelper::jsonObjectSetInt64 (JSON_Object* jo, const char* key, const int64_t value)
{
    JSON_Status rv = JSONFailure;
    if ((value >= MIN_INT52) && (value <= MAX_INT52)) {
        rv = json_object_set_number(jo, key, (double)value);
    }
    return rv;
}

JSON_Status ParsonHelper::jsonObjectSetUint32 (JSON_Object* jo, const char* key, const uint32_t value)
{
    return json_object_set_number(jo, key, (double)value);
}

JSON_Status ParsonHelper::jsonObjectSetUint64 (JSON_Object* jo, const char* key, const uint64_t value)
{
    JSON_Status rv = JSONFailure;
    if (value <= MAX_UINT52) {
        rv = json_object_set_number(jo, key, (double)value);
    }
    return rv;
}
