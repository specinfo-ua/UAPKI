/*
 SPDX-License-Identifier: MIT

 Copyright (c) 2021, The UAPKI Project Authors.
 Copyright (c) 2012 - 2020 Krzysztof Gabis
 Parson 1.1.0 ( http://kgabis.github.com/parson/ )

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.

*/

#define FILE_MARKER "common/json/parson-ba-utils.c"

#include <stdlib.h>
#include <string.h>
#include "parson-ba-utils.h"
#include "parson-private.h"
#include "uapkic-errors.h"

/* Both encoders emit ASCII. Fill the JSON string's final allocation directly,
 * avoiding a temporary string, UTF-8 validation and a second copy. */
static JSON_Value* json_value_init_encoded(const ByteArray* baData, int hex, int* ret)
{
    size_t length, capacity;
    char* buffer = NULL;
    JSON_Value* value;
    if (!baData) {
        *ret = RET_INVALID_PARAM;
        return NULL;
    }
    length = ba_get_len(baData);
    if (hex) {
        if (length > ((size_t)-1 - 1) / 2) {
            *ret = RET_DATA_TOO_LONG;
            return NULL;
        }
        length *= 2;
    }
    else {
        const size_t groups = length / 3 + (length % 3 != 0);
        if (groups > ((size_t)-1 - 1) / 4) {
            *ret = RET_DATA_TOO_LONG;
            return NULL;
        }
        length = groups * 4;
    }
    value = json_value_init_string_buffer(length, &buffer);
    if (!value) {
        *ret = RET_UAPKI_JSON_FAILURE;
        return NULL;
    }
    capacity = length + 1;
    *ret = hex ? ba_to_hex(baData, buffer, &capacity) : ba_to_base64(baData, buffer, &capacity);
    if (*ret != RET_OK) {
        json_value_free(value);
        return NULL;
    }
    return value;
}

int json_object_set_hex (JSON_Object* jsonObject, const char* name, const ByteArray* baData)
{
    int ret;
    JSON_Value* value = json_value_init_encoded(baData, 1, &ret);
    if (value && json_object_set_value(jsonObject, name, value) != JSONSuccess) {
        json_value_free(value);
        ret = RET_UAPKI_JSON_FAILURE;
    }
    return ret;
}

ByteArray* json_object_get_hex (const JSON_Object* jsonObject, const char* name)
{
    const char* str = json_object_get_string(jsonObject, name);
    if (!str) return NULL;
    return ba_alloc_from_hex(str);
}

int json_array_append_hex (JSON_Array* jsonArray, const ByteArray* baData)
{
    int ret;
    JSON_Value* value = json_value_init_encoded(baData, 1, &ret);
    if (value && json_array_append_value(jsonArray, value) != JSONSuccess) {
        json_value_free(value);
        ret = RET_UAPKI_JSON_FAILURE;
    }
    return ret;
}

ByteArray* json_array_get_hex (const JSON_Array* jsonArray, size_t index)
{
    const char* str = json_array_get_string(jsonArray, index);
    if (!str) return NULL;
    return ba_alloc_from_hex(str);
}

int json_object_set_base64 (JSON_Object* jsonObject, const char* name, const ByteArray* baData)
{
    int ret;
    JSON_Value* value = json_value_init_encoded(baData, 0, &ret);
    if (value && json_object_set_value(jsonObject, name, value) != JSONSuccess) {
        json_value_free(value);
        ret = RET_UAPKI_JSON_FAILURE;
    }
    return ret;
}

ByteArray* json_object_get_base64 (const JSON_Object* jsonObject, const char* name)
{
    const char* str = json_object_get_string(jsonObject, name);
    if (!str) return NULL;
    return ba_alloc_from_base64(str);
}

int json_array_append_base64 (JSON_Array* jsonArray, const ByteArray* baData)
{
    int ret;
    JSON_Value* value = json_value_init_encoded(baData, 0, &ret);
    if (value && json_array_append_value(jsonArray, value) != JSONSuccess) {
        json_value_free(value);
        ret = RET_UAPKI_JSON_FAILURE;
    }
    return ret;
}

ByteArray* json_array_get_base64 (const JSON_Array* jsonArray, size_t index)
{
    const char* str = json_array_get_string(jsonArray, index);
    if (!str) return NULL;
    return ba_alloc_from_base64(str);
}
