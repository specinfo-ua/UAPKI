//  Last update: 2022-11-22

#include <stdlib.h>
#include <string.h>
#include "parson-ba-utils.h"
#include "uapkic-errors.h"


#undef FILE_MARKER
#define FILE_MARKER "common/json/parson-ba-utils.c"


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
    if (!str || (strlen(str) == 0)) return NULL;
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
    if (!str || (strlen(str) == 0)) return NULL;
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
    if (!str || (strlen(str) == 0)) return NULL;
    return ba_alloc_from_base64(str);
}
