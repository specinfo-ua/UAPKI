//  Last update: 2021-09-20

#ifndef PARSON_BA_UTILS_H
#define PARSON_BA_UTILS_H


#include "parson.h"
#include "uapkic.h"
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
