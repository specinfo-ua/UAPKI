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

#ifndef PARSON_BA_UTILS_H
#define PARSON_BA_UTILS_H


#include "parson.h"
#include "byte-array.h"
#include "uapki-errors.h"


#ifdef __cplusplus
extern "C" {
#endif

#define DO_JSON(func)                       \
    {                                       \
        if ((func) != JSONSuccess) {        \
            ret = RET_UAPKI_JSON_FAILURE;   \
            goto cleanup;                   \
        }                                   \
    }

    int json_object_set_hex (JSON_Object* jsonObject, const char* name, const ByteArray* baData);
    ByteArray* json_object_get_hex (const JSON_Object* jsonObject, const char* name);

    int json_object_set_base64 (JSON_Object* jsonObject, const char* name, const ByteArray* baData);
    ByteArray* json_object_get_base64 (const JSON_Object* jsonObject, const char* name);

    int json_array_append_base64 (JSON_Array* jsonArray, const ByteArray* baData);
    ByteArray* json_array_get_base64 (const JSON_Array* jsonArray, size_t index);


#ifdef __cplusplus
}
#endif

#endif
