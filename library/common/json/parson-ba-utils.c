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
#include "uapkic-errors.h"


int json_object_set_hex (JSON_Object* jsonObject, const char* name, const ByteArray* baData)
{
    char* str = NULL;
    int ret = ba_to_hex_with_alloc(baData, &str);
    if (ret == RET_OK) {
        ret = (json_object_set_string(jsonObject, name, str) == JSONSuccess) ? RET_OK : RET_UAPKI_JSON_FAILURE;
        free(str);
    }
    return ret;
}

ByteArray* json_object_get_hex (const JSON_Object* jsonObject, const char* name)
{
    const char* str = json_object_get_string(jsonObject, name);
    if (!str) return NULL;
    return ba_alloc_from_hex(str);
}

int json_object_set_base64 (JSON_Object* jsonObject, const char* name, const ByteArray* baData)
{
    char* str = NULL;
    int ret = ba_to_base64_with_alloc(baData, &str);
    if (ret == RET_OK) {
        ret = (json_object_set_string(jsonObject, name, str) == JSONSuccess) ? RET_OK : RET_UAPKI_JSON_FAILURE;
        free(str);
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
    char* str = NULL;
    int ret = ba_to_base64_with_alloc(baData, &str);
    if (ret == RET_OK) {
        ret = (json_array_append_string(jsonArray, (const char*)str) == JSONSuccess) ? RET_OK : RET_UAPKI_JSON_FAILURE;
        free(str);
    }
    return ret;
}

ByteArray* json_array_get_base64 (const JSON_Array* jsonArray, size_t index)
{
    const char* str = json_array_get_string(jsonArray, index);
    if (!str) return NULL;
    return ba_alloc_from_base64(str);
}
