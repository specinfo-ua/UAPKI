/* SPDX-License-Identifier: MIT */
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
