/*
 SPDX-License-Identifier: MIT

 Copyright (c) 2026, The UAPKI Project Authors.

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

#ifndef PARSON_PRIVATE_H
#define PARSON_PRIVATE_H

#include "parson.h"

#ifdef __cplusplus
extern "C" {
#endif

/* UAPKI internal: allocate a string whose characters are filled by a trusted
 * encoder. The caller must write exactly length bytes of valid UTF-8 before
 * using the value. The terminator is initialized here. Free with json_value_free.
 * Ordinary strings must use json_value_init_string[_with_len] for validation. */
JSON_Value *json_value_init_string_buffer(size_t length, char **buffer);

#ifdef __cplusplus
}
#endif

#endif
