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

#ifdef _MSC_VER
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif /* _CRT_SECURE_NO_WARNINGS */
#endif /* _MSC_VER */

#include "parson.h"
#include "parson-private.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <errno.h>

/* Apparently sscanf is not implemented in some "standard" libraries, so don't use it, if you
 * don't have to. */
#define sscanf THINK_TWICE_ABOUT_USING_SSCANF

#define STARTING_CAPACITY 16
#define MAX_NESTING       2048

#define FLOAT_FORMAT "%1.17g" /* do not increase precision without incresing NUM_BUF_SIZE */
#define NUM_BUF_SIZE 64 /* double printed with "%1.17g" shouldn't be longer than 25 bytes so let's be paranoid and use 64 */

#define SIZEOF_TOKEN(a)       (sizeof(a) - 1)
#define SKIP_CHAR(str)        ((*str)++)
#define SKIP_WHITESPACES(str) while (isspace((unsigned char)(**str))) { SKIP_CHAR(str); }
#define MAX(a, b)             ((a) > (b) ? (a) : (b))

#undef malloc
#undef free

#if defined(isnan) && defined(isinf)
#define IS_NUMBER_INVALID(x) (isnan((x)) || isinf((x)))
#else
#define IS_NUMBER_INVALID(x) (((x) * 0.0) != 0.0)
#endif

static JSON_Malloc_Function parson_malloc = malloc;
static JSON_Free_Function parson_free = free;

static int parson_escape_slashes = 0;/*UAPKI-MOD original value: 1*/

#define IS_CONT(b) (((unsigned char)(b) & 0xC0) == 0x80) /* is utf-8 continuation byte */

/* UAPKI-MOD: scan eight bytes at a time for control characters and escapes. */
#define SWAR_ONES  0x0101010101010101ULL
#define SWAR_HIGHS 0x8080808080808080ULL
#define SWAR_HAS_LESS_32(x)  ((x) - SWAR_ONES * 0x20)
#define SWAR_BYTE_EQ(x, c)   (((x) ^ (SWAR_ONES * (c))) - SWAR_ONES)
#define SWAR_HITS(x, tests)  ((tests) & ~(x) & SWAR_HIGHS)

typedef struct json_string {
    char *chars;
    size_t length;
} JSON_String;

/* Type definitions */
typedef union json_value_value {
    JSON_String  string;
    double       number;
    JSON_Object *object;
    JSON_Array  *array;
    int          boolean;
    int          null;
} JSON_Value_Value;

/* UAPKI-MOD: value payloads share their allocation; object names have a size_t prefix. */
struct json_value_t {
    JSON_Value      *parent;
    JSON_Value_Type  type;
    JSON_Value_Value value;
};

struct json_object_t {
    JSON_Value  *wrapping_value;
    char       **names;
    JSON_Value **values;
    size_t       count;
    size_t       capacity;
};

struct json_array_t {
    JSON_Value  *wrapping_value;
    JSON_Value **items;
    size_t       count;
    size_t       capacity;
};

/* Various */
static char * read_file(const char *filename);
static void   remove_comments(char *string, const char *start_token, const char *end_token);
static char * parson_strndup(const char *string, size_t n);
static char * parson_strdup(const char *string);
static int    hex_char_to_int(char c);
static int    parse_utf16_hex(const char *string, unsigned int *result);
static int    num_bytes_in_utf8_sequence(unsigned char c);
static int    verify_utf8_sequence(const unsigned char *string, int *len);
static int    is_valid_utf8(const char *string, size_t string_len);
static int    is_decimal(const char *string, size_t length);

/* JSON Object */
static void          json_object_init(JSON_Object *object, JSON_Value *wrapping_value);
static JSON_Status   json_object_add(JSON_Object *object, const char *name, JSON_Value *value);
static JSON_Status   json_object_addn(JSON_Object *object, const char *name, size_t name_len, JSON_Value *value);
static JSON_Status   json_object_add_owned(JSON_Object *object, char *name, JSON_Value *value);
static JSON_Status   json_object_resize(JSON_Object *object, size_t new_capacity);
static size_t        json_object_find(const JSON_Object *object, const char *name, size_t name_len);
static JSON_Value  * json_object_getn_value(const JSON_Object *object, const char *name, size_t name_len);
static JSON_Status   json_object_remove_internal(JSON_Object *object, const char *name, int free_value);
static JSON_Status   json_object_dotremove_internal(JSON_Object *object, const char *name, int free_value);
static void          json_object_free(JSON_Object *object);

/* JSON Array */
static void         json_array_init(JSON_Array *array, JSON_Value *wrapping_value);
static JSON_Status  json_array_add(JSON_Array *array, JSON_Value *value);
static JSON_Status  json_array_resize(JSON_Array *array, size_t new_capacity);
static void         json_array_free(JSON_Array *array);

/* JSON Value */
static JSON_Value * json_value_alloc(JSON_Value_Type type, size_t payload_size);
static JSON_Value * json_value_init_string_alloc(size_t length);
static const JSON_String * json_value_get_string_desc(const JSON_Value *value);

/* Parser */
static JSON_Status  skip_quotes(const char **string);
static int          parse_utf16(const char **unprocessed, char **processed);
static JSON_Status  process_string(const char *input, size_t input_len, char *output, size_t *output_len);
static char *       parse_object_key(const char **string, size_t *key_len);
static JSON_Value * parse_object_value(const char **string, size_t nesting);
static JSON_Value * parse_array_value(const char **string, size_t nesting);
static JSON_Value * parse_string_value(const char **string);
static JSON_Value * parse_boolean_value(const char **string);
static JSON_Value * parse_number_value(const char **string);
static JSON_Value * parse_null_value(const char **string);
static JSON_Value * parse_value(const char **string, size_t nesting);

/* Serialization */
typedef struct json_sink_t JSON_Sink;
static int    json_serialize_to_sink_r(const JSON_Value *value, JSON_Sink *sink, int level, int is_pretty);
static int    json_serialize_string(const char *string, size_t len, JSON_Sink *sink);
static int    append_indent(JSON_Sink *sink, int level);
static int    json_serialize_to_buffer_r(const JSON_Value *value, char *buf, size_t buf_size, int is_pretty, size_t *written);
static char * json_serialize_to_string_r(const JSON_Value *value, int is_pretty, JSON_Malloc_Function malloc_fun, JSON_Free_Function free_fun);

extern double strtod_no_locale(const char* string, char** endPtr);/*UAPKI locale independent*/

static void str_comma2point(char* string){/*UAPKI, change locale dependent ',' to '.'*/
    char* ptr = strchr(string, ',');
    if (ptr != NULL) {
        *ptr = '.';
    }
}

/* Various */
static char * parson_strndup(const char *string, size_t n) {
    /* We expect the caller has validated that 'n' fits within the input buffer. */
    char *output_string = (char*)parson_malloc(n + 1);
    if (!output_string) {
        return NULL;
    }
    output_string[n] = '\0';
    memcpy(output_string, string, n);
    return output_string;
}

static char * parson_strdup(const char *string) {
    return parson_strndup(string, strlen(string));
}

#define JSON_NOT_FOUND ((size_t)-1)

static char * json_name_alloc(size_t length) {
    size_t *block;
    if (length > (size_t)-1 - sizeof(size_t) - 1) {
        return NULL;
    }
    block = (size_t*)parson_malloc(sizeof(size_t) + length + 1);
    if (!block) {
        return NULL;
    }
    *block = length;
    return (char*)(block + 1);
}

static char * json_name_new(const char *name, size_t length) {
    char *output = json_name_alloc(length);
    if (!output) {
        return NULL;
    }
    memcpy(output, name, length);
    output[length] = '\0';
    return output;
}

static void json_name_set_len(char *name, size_t length) {
    ((size_t*)name)[-1] = length;
}

static size_t json_name_len(const char *name) {
    return ((const size_t*)name)[-1];
}

static void json_name_free(char *name) {
    if (name) {
        parson_free((size_t*)name - 1);
    }
}

static int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int parse_utf16_hex(const char *s, unsigned int *result) {
    int x1, x2, x3, x4;
    if (s[0] == '\0' || s[1] == '\0' || s[2] == '\0' || s[3] == '\0') {
        return 0;
    }
    x1 = hex_char_to_int(s[0]);
    x2 = hex_char_to_int(s[1]);
    x3 = hex_char_to_int(s[2]);
    x4 = hex_char_to_int(s[3]);
    if (x1 == -1 || x2 == -1 || x3 == -1 || x4 == -1) {
        return 0;
    }
    *result = (unsigned int)((x1 << 12) | (x2 << 8) | (x3 << 4) | x4);
    return 1;
}

static int num_bytes_in_utf8_sequence(unsigned char c) {
    if (c == 0xC0 || c == 0xC1 || c > 0xF4 || IS_CONT(c)) {
        return 0;
    } else if ((c & 0x80) == 0) {    /* 0xxxxxxx */
        return 1;
    } else if ((c & 0xE0) == 0xC0) { /* 110xxxxx */
        return 2;
    } else if ((c & 0xF0) == 0xE0) { /* 1110xxxx */
        return 3;
    } else if ((c & 0xF8) == 0xF0) { /* 11110xxx */
        return 4;
    }
    return 0; /* won't happen */
}

static int verify_utf8_sequence(const unsigned char *string, int *len) {
    unsigned int cp = 0;
    *len = num_bytes_in_utf8_sequence(string[0]);

    if (*len == 1) {
        cp = string[0];
    } else if (*len == 2 && IS_CONT(string[1])) {
        cp = string[0] & 0x1F;
        cp = (cp << 6) | (string[1] & 0x3F);
    } else if (*len == 3 && IS_CONT(string[1]) && IS_CONT(string[2])) {
        cp = ((unsigned char)string[0]) & 0xF;
        cp = (cp << 6) | (string[1] & 0x3F);
        cp = (cp << 6) | (string[2] & 0x3F);
    } else if (*len == 4 && IS_CONT(string[1]) && IS_CONT(string[2]) && IS_CONT(string[3])) {
        cp = string[0] & 0x7;
        cp = (cp << 6) | (string[1] & 0x3F);
        cp = (cp << 6) | (string[2] & 0x3F);
        cp = (cp << 6) | (string[3] & 0x3F);
    } else {
        return 0;
    }

    /* overlong encodings */
    if ((cp < 0x80    && *len > 1) ||
        (cp < 0x800   && *len > 2) ||
        (cp < 0x10000 && *len > 3)) {
        return 0;
    }

    /* invalid unicode */
    if (cp > 0x10FFFF) {
        return 0;
    }

    /* surrogate halves */
    if (cp >= 0xD800 && cp <= 0xDFFF) {
        return 0;
    }

    return 1;
}

static int is_valid_utf8(const char *string, size_t string_len) {
    int len = 0;
    const char *string_end =  string + string_len;
    unsigned long long w = 0;
    while (string < string_end) {
        while ((size_t)(string_end - string) >= 8) {
            memcpy(&w, string, 8);
            if (w & SWAR_HIGHS) {
                break;
            }
            string += 8;
        }
        if (string >= string_end) {
            break;
        }
        if (!verify_utf8_sequence((const unsigned char*)string, &len)) {
            return 0;
        }
        string += len;
    }
    return 1;
}

static int is_decimal(const char *string, size_t length) {
    if (length > 1 && string[0] == '0' && string[1] != '.') {
        return 0;
    }
    if (length > 2 && !strncmp(string, "-0", 2) && string[2] != '.') {
        return 0;
    }
    while (length--) {
        if (strchr("xX", string[length])) {
            return 0;
        }
    }
    return 1;
}

static char * read_file(const char * filename) {
    FILE *fp = fopen(filename, "r");
    size_t size_to_read = 0;
    size_t size_read = 0;
    long pos;
    char *file_contents;
    if (!fp) {
        return NULL;
    }
    fseek(fp, 0L, SEEK_END);
    pos = ftell(fp);
    if (pos < 0) {
        fclose(fp);
        return NULL;
    }
    size_to_read = pos;
    rewind(fp);
    file_contents = (char*)parson_malloc(sizeof(char) * (size_to_read + 1));
    if (!file_contents) {
        fclose(fp);
        return NULL;
    }
    size_read = fread(file_contents, 1, size_to_read, fp);
    if (size_read == 0 || ferror(fp)) {
        fclose(fp);
        parson_free(file_contents);
        return NULL;
    }
    fclose(fp);
    file_contents[size_read] = '\0';
    return file_contents;
}

static void remove_comments(char *string, const char *start_token, const char *end_token) {
    int in_string = 0, escaped = 0;
    size_t i;
    char *ptr = NULL, current_char;
    size_t start_token_len = strlen(start_token);
    size_t end_token_len = strlen(end_token);
    if (start_token_len == 0 || end_token_len == 0) {
        return;
    }
    while ((current_char = *string) != '\0') {
        if (current_char == '\\' && !escaped) {
            escaped = 1;
            string++;
            continue;
        } else if (current_char == '\"' && !escaped) {
            in_string = !in_string;
        } else if (!in_string && strncmp(string, start_token, start_token_len) == 0) {
            for(i = 0; i < start_token_len; i++) {
                string[i] = ' ';
            }
            string = string + start_token_len;
            ptr = strstr(string, end_token);
            if (!ptr) {
                return;
            }
            for (i = 0; i < (ptr - string) + end_token_len; i++) {
                string[i] = ' ';
            }
            string = ptr + end_token_len - 1;
        }
        escaped = 0;
        string++;
    }
}

/* JSON Object */
static void json_object_init(JSON_Object *object, JSON_Value *wrapping_value) {
    object->wrapping_value = wrapping_value;
    object->names = (char**)NULL;
    object->values = (JSON_Value**)NULL;
    object->capacity = 0;
    object->count = 0;
}

static JSON_Status json_object_add(JSON_Object *object, const char *name, JSON_Value *value) {
    if (name == NULL) {
        return JSONFailure;
    }
    return json_object_addn(object, name, strlen(name), value);
}

static JSON_Status json_object_addn(JSON_Object *object, const char *name, size_t name_len, JSON_Value *value) {
    char *new_name = NULL;
    if (object == NULL || name == NULL || value == NULL) {
        return JSONFailure;
    }
    if (json_object_find(object, name, name_len) != JSON_NOT_FOUND) {
        return JSONFailure;
    }
    new_name = json_name_new(name, name_len);
    if (new_name == NULL) {
        return JSONFailure;
    }
    if (json_object_add_owned(object, new_name, value) == JSONFailure) {
        json_name_free(new_name);
        return JSONFailure;
    }
    return JSONSuccess;
}

/* takes ownership of name (a json_name_* block) on success; the caller has checked for duplicates */
static JSON_Status json_object_add_owned(JSON_Object *object, char *name, JSON_Value *value) {
    size_t index = 0;
    if (object->count >= object->capacity) {
        size_t new_capacity = MAX(object->capacity * 2, STARTING_CAPACITY);
        if (json_object_resize(object, new_capacity) == JSONFailure) {
            return JSONFailure;
        }
    }
    index = object->count;
    object->names[index] = name;
    value->parent = json_object_get_wrapping_value(object);
    object->values[index] = value;
    object->count++;
    return JSONSuccess;
}

static JSON_Status json_object_resize(JSON_Object *object, size_t new_capacity) {
    char **temp_names = NULL;
    JSON_Value **temp_values = NULL;

    if ((object->names == NULL && object->values != NULL) ||
        (object->names != NULL && object->values == NULL) ||
        new_capacity == 0) {
            return JSONFailure; /* Shouldn't happen */
    }
    temp_names = (char**)parson_malloc(new_capacity * (sizeof(char*) + sizeof(JSON_Value*)));
    if (temp_names == NULL) {
        return JSONFailure;
    }
    temp_values = (JSON_Value**)(temp_names + new_capacity);
    if (object->names != NULL && object->values != NULL && object->count > 0) {
        memcpy(temp_names, object->names, object->count * sizeof(char*));
        memcpy(temp_values, object->values, object->count * sizeof(JSON_Value*));
    }
    parson_free(object->names);
    object->names = temp_names;
    object->values = temp_values;
    object->capacity = new_capacity;
    return JSONSuccess;
}

static size_t json_object_find(const JSON_Object *object, const char *name, size_t name_len) {
    size_t i;
    for (i = 0; i < object->count; i++) {
        if (json_name_len(object->names[i]) == name_len && memcmp(object->names[i], name, name_len) == 0) {
            return i;
        }
    }
    return JSON_NOT_FOUND;
}

static JSON_Value * json_object_getn_value(const JSON_Object *object, const char *name, size_t name_len) {
    size_t i;
    if (object == NULL) {
        return NULL;
    }
    i = json_object_find(object, name, name_len);
    return (i != JSON_NOT_FOUND) ? object->values[i] : NULL;
}

static JSON_Status json_object_remove_internal(JSON_Object *object, const char *name, int free_value) {
    size_t i = 0, last_item_index = 0;
    if (object == NULL || name == NULL) {
        return JSONFailure;
    }
    i = json_object_find(object, name, strlen(name));
    if (i == JSON_NOT_FOUND) {
        return JSONFailure;
    }
    last_item_index = object->count - 1;
    json_name_free(object->names[i]);
    if (free_value) {
        json_value_free(object->values[i]);
    }
    if (i != last_item_index) { /* Replace key value pair with one from the end */
        object->names[i] = object->names[last_item_index];
        object->values[i] = object->values[last_item_index];
    }
    object->count -= 1;
    return JSONSuccess;
}

static JSON_Status json_object_dotremove_internal(JSON_Object *object, const char *name, int free_value) {
    JSON_Value *temp_value = NULL;
    JSON_Object *temp_object = NULL;
    const char *dot_pos = strchr(name, '.');
    if (dot_pos == NULL) {
        return json_object_remove_internal(object, name, free_value);
    }
    temp_value = json_object_getn_value(object, name, dot_pos - name);
    if (json_value_get_type(temp_value) != JSONObject) {
        return JSONFailure;
    }
    temp_object = json_value_get_object(temp_value);
    return json_object_dotremove_internal(temp_object, dot_pos + 1, free_value);
}

static void json_object_free(JSON_Object *object) {
    size_t i;
    for (i = 0; i < object->count; i++) {
        json_name_free(object->names[i]);
        json_value_free(object->values[i]);
    }
    parson_free(object->names);
}

/* JSON Array */
static void json_array_init(JSON_Array *array, JSON_Value *wrapping_value) {
    array->wrapping_value = wrapping_value;
    array->items = (JSON_Value**)NULL;
    array->capacity = 0;
    array->count = 0;
}

static JSON_Status json_array_add(JSON_Array *array, JSON_Value *value) {
    if (array->count >= array->capacity) {
        size_t new_capacity = MAX(array->capacity * 2, STARTING_CAPACITY);
        if (json_array_resize(array, new_capacity) == JSONFailure) {
            return JSONFailure;
        }
    }
    value->parent = json_array_get_wrapping_value(array);
    array->items[array->count] = value;
    array->count++;
    return JSONSuccess;
}

static JSON_Status json_array_resize(JSON_Array *array, size_t new_capacity) {
    JSON_Value **new_items = NULL;
    if (new_capacity == 0) {
        return JSONFailure;
    }
    new_items = (JSON_Value**)parson_malloc(new_capacity * sizeof(JSON_Value*));
    if (new_items == NULL) {
        return JSONFailure;
    }
    if (array->items != NULL && array->count > 0) {
        memcpy(new_items, array->items, array->count * sizeof(JSON_Value*));
    }
    parson_free(array->items);
    array->items = new_items;
    array->capacity = new_capacity;
    return JSONSuccess;
}

static void json_array_free(JSON_Array *array) {
    size_t i;
    for (i = 0; i < array->count; i++) {
        json_value_free(array->items[i]);
    }
    parson_free(array->items);
}

/* JSON Value */
static JSON_Value * json_value_alloc(JSON_Value_Type type, size_t payload_size) {
    JSON_Value *new_value;
    if (payload_size > (size_t)-1 - sizeof(JSON_Value)) {
        return NULL;
    }
    new_value = (JSON_Value*)parson_malloc(sizeof(JSON_Value) + payload_size);
    if (!new_value) {
        return NULL;
    }
    new_value->parent = NULL;
    new_value->type = type;
    return new_value;
}

/* room for length bytes plus the terminator; the caller fills the characters */
static JSON_Value * json_value_init_string_alloc(size_t length) {
    JSON_Value *new_value;
    if (length == (size_t)-1) {
        return NULL;
    }
    new_value = json_value_alloc(JSONString, length + 1);
    if (!new_value) {
        return NULL;
    }
    new_value->value.string.chars = (char*)(new_value + 1);
    new_value->value.string.length = length;
    return new_value;
}

JSON_Value *json_value_init_string_buffer(size_t length, char **buffer) {
    JSON_Value *value;
    if (buffer == NULL) {
        return NULL;
    }
    *buffer = NULL;
    value = json_value_init_string_alloc(length);
    if (value != NULL) {
        *buffer = value->value.string.chars;
        (*buffer)[length] = '\0';
    }
    return value;
}

/* Parser */
static JSON_Status skip_quotes(const char **string) {
    if (**string != '\"') {
        return JSONFailure;
    }
    SKIP_CHAR(string);
    while (**string != '\"') {
        *string += strcspn(*string, "\"\\");
        if (**string == '\0') {
            return JSONFailure;
        } else if (**string == '\\') {
            SKIP_CHAR(string);
            if (**string == '\0') {
                return JSONFailure;
            }
            SKIP_CHAR(string);
        }
    }
    SKIP_CHAR(string);
    return JSONSuccess;
}

static int parse_utf16(const char **unprocessed, char **processed) {
    unsigned int cp, lead, trail;
    int parse_succeeded = 0;
    char *processed_ptr = *processed;
    const char *unprocessed_ptr = *unprocessed;
    unprocessed_ptr++; /* skips u */
    parse_succeeded = parse_utf16_hex(unprocessed_ptr, &cp);
    if (!parse_succeeded) {
        return JSONFailure;
    }
    if (cp < 0x80) {
        processed_ptr[0] = (char)cp; /* 0xxxxxxx */
    } else if (cp < 0x800) {
        processed_ptr[0] = ((cp >> 6) & 0x1F) | 0xC0; /* 110xxxxx */
        processed_ptr[1] = ((cp)      & 0x3F) | 0x80; /* 10xxxxxx */
        processed_ptr += 1;
    } else if (cp < 0xD800 || cp > 0xDFFF) {
        processed_ptr[0] = ((cp >> 12) & 0x0F) | 0xE0; /* 1110xxxx */
        processed_ptr[1] = ((cp >> 6)  & 0x3F) | 0x80; /* 10xxxxxx */
        processed_ptr[2] = ((cp)       & 0x3F) | 0x80; /* 10xxxxxx */
        processed_ptr += 2;
    } else if (cp >= 0xD800 && cp <= 0xDBFF) { /* lead surrogate (0xD800..0xDBFF) */
        lead = cp;
        unprocessed_ptr += 4; /* should always be within the buffer, otherwise previous sscanf would fail */
        if (*unprocessed_ptr++ != '\\' || *unprocessed_ptr++ != 'u') {
            return JSONFailure;
        }
        parse_succeeded = parse_utf16_hex(unprocessed_ptr, &trail);
        if (!parse_succeeded || trail < 0xDC00 || trail > 0xDFFF) { /* valid trail surrogate? (0xDC00..0xDFFF) */
            return JSONFailure;
        }
        cp = ((((lead - 0xD800) & 0x3FF) << 10) | ((trail - 0xDC00) & 0x3FF)) + 0x010000;
        processed_ptr[0] = (((cp >> 18) & 0x07) | 0xF0); /* 11110xxx */
        processed_ptr[1] = (((cp >> 12) & 0x3F) | 0x80); /* 10xxxxxx */
        processed_ptr[2] = (((cp >> 6)  & 0x3F) | 0x80); /* 10xxxxxx */
        processed_ptr[3] = (((cp)       & 0x3F) | 0x80); /* 10xxxxxx */
        processed_ptr += 3;
    } else { /* trail surrogate before lead surrogate */
        return JSONFailure;
    }
    unprocessed_ptr += 3;
    *processed = processed_ptr;
    *unprocessed = unprocessed_ptr;
    return JSONSuccess;
}


/* Copies and processes passed string up to supplied length into output (at least input_len + 1 bytes).
Example: "\u006Corem ipsum" -> lorem ipsum */
static JSON_Status process_string(const char *input, size_t input_len, char *output, size_t *output_len) {
    const char *input_ptr = input, *input_end = input + input_len, *run_start = NULL;
    char *output_ptr = output;
    unsigned long long w = 0;
    while (input_ptr < input_end) {
        run_start = input_ptr;
        while ((size_t)(input_end - input_ptr) >= 8) {
            memcpy(&w, input_ptr, 8);
            if (SWAR_HITS(w, SWAR_HAS_LESS_32(w) | SWAR_BYTE_EQ(w, '\\'))) {
                break;
            }
            input_ptr += 8;
        }
        while (input_ptr < input_end && (unsigned char)*input_ptr >= 0x20 && *input_ptr != '\\') {
            input_ptr++;
        }
        if (input_ptr > run_start) {
            memcpy(output_ptr, run_start, (size_t)(input_ptr - run_start));
            output_ptr += (size_t)(input_ptr - run_start);
        }
        if (input_ptr >= input_end) {
            break;
        }
        if (*input_ptr == '\\') {
            input_ptr++;
            switch (*input_ptr) {
                case '\"': *output_ptr = '\"'; break;
                case '\\': *output_ptr = '\\'; break;
                case '/':  *output_ptr = '/';  break;
                case 'b':  *output_ptr = '\b'; break;
                case 'f':  *output_ptr = '\f'; break;
                case 'n':  *output_ptr = '\n'; break;
                case 'r':  *output_ptr = '\r'; break;
                case 't':  *output_ptr = '\t'; break;
                case 'u':
                    if (parse_utf16(&input_ptr, &output_ptr) == JSONFailure) {
                        goto error;
                    }
                    break;
                default:
                    goto error;
            }
        } else {
            goto error; /* 0x00-0x19 are invalid characters for json string (http://www.ietf.org/rfc/rfc4627.txt) */
        }
        output_ptr++;
        input_ptr++;
    }
    *output_ptr = '\0';
    *output_len = (size_t)(output_ptr - output);
    return JSONSuccess;
error:
    return JSONFailure;
}

/* Returns the processed key between quotes as an owned name block and
   skips passed argument to a matching quote. */
static char * parse_object_key(const char **string, size_t *key_len) {
    const char *string_start = *string;
    size_t input_string_len = 0;
    char *key = NULL;
    if (skip_quotes(string) != JSONSuccess) {
        return NULL;
    }
    input_string_len = *string - string_start - 2; /* length without quotes */
    key = json_name_alloc(input_string_len);
    if (key == NULL) {
        return NULL;
    }
    if (process_string(string_start + 1, input_string_len, key, key_len) != JSONSuccess) {
        json_name_free(key);
        return NULL;
    }
    json_name_set_len(key, *key_len);
    return key;
}

static JSON_Value * parse_value(const char **string, size_t nesting) {
    if (nesting > MAX_NESTING) {
        return NULL;
    }
    SKIP_WHITESPACES(string);
    switch (**string) {
        case '{':
            return parse_object_value(string, nesting + 1);
        case '[':
            return parse_array_value(string, nesting + 1);
        case '\"':
            return parse_string_value(string);
        case 'f': case 't':
            return parse_boolean_value(string);
        case '-':
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
            return parse_number_value(string);
        case 'n':
            return parse_null_value(string);
        default:
            return NULL;
    }
}

static JSON_Value * parse_object_value(const char **string, size_t nesting) {
    JSON_Value *output_value = NULL, *new_value = NULL;
    JSON_Object *output_object = NULL;
    char *new_key = NULL;
    output_value = json_value_init_object();
    if (output_value == NULL) {
        return NULL;
    }
    if (**string != '{') {
        json_value_free(output_value);
        return NULL;
    }
    output_object = json_value_get_object(output_value);
    SKIP_CHAR(string);
    SKIP_WHITESPACES(string);
    if (**string == '}') { /* empty object */
        SKIP_CHAR(string);
        return output_value;
    }
    while (**string != '\0') {
        size_t key_len = 0;
        new_key = parse_object_key(string, &key_len);
        /* We do not support key names with embedded \0 chars */
        if (new_key == NULL || key_len != strlen(new_key)) {
            json_name_free(new_key);
            json_value_free(output_value);
            return NULL;
        }
        SKIP_WHITESPACES(string);
        if (**string != ':') {
            json_name_free(new_key);
            json_value_free(output_value);
            return NULL;
        }
        SKIP_CHAR(string);
        new_value = parse_value(string, nesting);
        if (new_value == NULL) {
            json_name_free(new_key);
            json_value_free(output_value);
            return NULL;
        }
        if (json_object_find(output_object, new_key, key_len) != JSON_NOT_FOUND ||
            json_object_add_owned(output_object, new_key, new_value) == JSONFailure) {
            json_name_free(new_key);
            json_value_free(new_value);
            json_value_free(output_value);
            return NULL;
        }
        SKIP_WHITESPACES(string);
        if (**string != ',') {
            break;
        }
        SKIP_CHAR(string);
        SKIP_WHITESPACES(string);
    }
    SKIP_WHITESPACES(string);
    if (**string != '}' || /* Trim object after parsing is over */
        json_object_resize(output_object, json_object_get_count(output_object)) == JSONFailure) {
            json_value_free(output_value);
            return NULL;
    }
    SKIP_CHAR(string);
    return output_value;
}

static JSON_Value * parse_array_value(const char **string, size_t nesting) {
    JSON_Value *output_value = NULL, *new_array_value = NULL;
    JSON_Array *output_array = NULL;
    output_value = json_value_init_array();
    if (output_value == NULL) {
        return NULL;
    }
    if (**string != '[') {
        json_value_free(output_value);
        return NULL;
    }
    output_array = json_value_get_array(output_value);
    SKIP_CHAR(string);
    SKIP_WHITESPACES(string);
    if (**string == ']') { /* empty array */
        SKIP_CHAR(string);
        return output_value;
    }
    while (**string != '\0') {
        new_array_value = parse_value(string, nesting);
        if (new_array_value == NULL) {
            json_value_free(output_value);
            return NULL;
        }
        if (json_array_add(output_array, new_array_value) == JSONFailure) {
            json_value_free(new_array_value);
            json_value_free(output_value);
            return NULL;
        }
        SKIP_WHITESPACES(string);
        if (**string != ',') {
            break;
        }
        SKIP_CHAR(string);
        SKIP_WHITESPACES(string);
    }
    SKIP_WHITESPACES(string);
    if (**string != ']' || /* Trim array after parsing is over */
        json_array_resize(output_array, json_array_get_count(output_array)) == JSONFailure) {
            json_value_free(output_value);
            return NULL;
    }
    SKIP_CHAR(string);
    return output_value;
}

static JSON_Value * parse_string_value(const char **string) {
    JSON_Value *value = NULL;
    const char *string_start = *string;
    size_t input_string_len = 0, new_string_len = 0;
    if (skip_quotes(string) != JSONSuccess) {
        return NULL;
    }
    input_string_len = *string - string_start - 2; /* length without quotes */
    value = json_value_init_string_alloc(input_string_len);
    if (value == NULL) {
        return NULL;
    }
    if (process_string(string_start + 1, input_string_len, value->value.string.chars, &new_string_len) != JSONSuccess) {
        json_value_free(value);
        return NULL;
    }
    value->value.string.length = new_string_len;
    return value;
}

static JSON_Value * parse_boolean_value(const char **string) {
    size_t true_token_size = SIZEOF_TOKEN("true");
    size_t false_token_size = SIZEOF_TOKEN("false");
    if (strncmp("true", *string, true_token_size) == 0) {
        *string += true_token_size;
        return json_value_init_boolean(1);
    } else if (strncmp("false", *string, false_token_size) == 0) {
        *string += false_token_size;
        return json_value_init_boolean(0);
    }
    return NULL;
}

static JSON_Value * parse_number_value(const char **string) {
    char *end;
    double number = 0;
    errno = 0;
    number = strtod_no_locale(*string, &end);/*UAPKI, original line: number = strtod(*string, &end);*/
    if (errno || !is_decimal(*string, end - *string)) {
        return NULL;
    }
    *string = end;
    return json_value_init_number(number);
}

static JSON_Value * parse_null_value(const char **string) {
    size_t token_size = SIZEOF_TOKEN("null");
    if (strncmp("null", *string, token_size) == 0) {
        *string += token_size;
        return json_value_init_null();
    }
    return NULL;
}

/* Serialization */
/* UAPKI-MOD: one writer for the three modes: count only (base == NULL), fixed buffer, growable buffer */
struct json_sink_t {
    char  *base;
    size_t pos;
    size_t cap;
    int    growable;
    JSON_Malloc_Function malloc_fun;
    JSON_Free_Function free_fun;
    char   num_buf[NUM_BUF_SIZE]; /* recursively allocating buffer on stack is a bad idea, so let's do it only once */
};

/* 0 = copy as is, 1 = two-char escape, 2 = \u00xx, 3 = '/' (escaped only when parson_escape_slashes) */
static const unsigned char serialize_escape_kind[256] = {
    2,2,2,2,2,2,2,2,1,1,1,2,1,1,2,2, 2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
    0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,3, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

static char serialize_escape_char(char c) {
    switch (c) {
        case '\b': return 'b';
        case '\f': return 'f';
        case '\n': return 'n';
        case '\r': return 'r';
        case '\t': return 't';
        default:   return c; /* '"', '\\', '/' */
    }
}

static int sink_grow(JSON_Sink *sink, size_t needed) {
    size_t new_cap = 0;
    char *new_base = NULL;
    if (!sink->growable) {
        return -1;
    }
    new_cap = sink->cap <= (size_t)-1 / 2 ? sink->cap * 2 : (size_t)-1;
    if (new_cap < needed) {
        new_cap = needed;
    }
    new_base = (char*)sink->malloc_fun(new_cap);
    if (new_base == NULL) {
        return -1;
    }
    memcpy(new_base, sink->base, sink->pos);
    sink->free_fun(sink->base);
    sink->base = new_base;
    sink->cap = new_cap;
    return 0;
}

#define SINK_RESERVE(n) do { if ((n) > (size_t)-1 - sink->pos) { return -1; } if (sink->base != NULL && sink->pos + (n) > sink->cap && sink_grow(sink, sink->pos + (n)) < 0) { return -1; } } while(0)
#define APPEND_CHAR(ch) do { SINK_RESERVE(1); if (sink->base != NULL) { sink->base[sink->pos] = (ch); } sink->pos++; } while(0)
#define APPEND_BYTES(ptr, n) do { SINK_RESERVE(n); if (sink->base != NULL) { memcpy(sink->base + sink->pos, (ptr), (n)); } sink->pos += (n); } while(0)
#define APPEND_LITERAL(lit) APPEND_BYTES((lit), sizeof(lit) - 1)

static int append_indent(JSON_Sink *sink, int level) {
    int i;
    for (i = 0; i < level; i++) {
        APPEND_LITERAL("    ");
    }
    return 0;
}

static int json_serialize_number(double num, JSON_Sink *sink) {
    char *p = sink->num_buf + NUM_BUF_SIZE;
    int written = -1;
    if (num > -9007199254740992.0 && num < 9007199254740992.0 && num == (double)(long long)num && (num != 0.0 || !signbit(num))) {
        long long i = (long long)num;
        unsigned long long u = (i < 0) ? (unsigned long long)(-i) : (unsigned long long)i;
        do {
            *--p = (char)('0' + (u % 10));
            u /= 10;
        } while (u);
        if (i < 0) {
            *--p = '-';
        }
        APPEND_BYTES(p, (size_t)(sink->num_buf + NUM_BUF_SIZE - p));
        return 0;
    }
    written = sprintf(sink->num_buf, FLOAT_FORMAT, num);
    if (written < 0) {
        return -1;
    }
    str_comma2point(sink->num_buf);/*UAPKI, remove locale dependency*/
    APPEND_BYTES(sink->num_buf, (size_t)written);
    return 0;
}

static size_t serialize_plain_run(const unsigned char *s, size_t len, int escape_slashes) {
    size_t i = 0;
    unsigned long long w = 0, special = 0;
    unsigned char kind = 0;
    while (i + 8 <= len) {
        memcpy(&w, s + i, 8);
        special = SWAR_HAS_LESS_32(w) | SWAR_BYTE_EQ(w, '\"') | SWAR_BYTE_EQ(w, '\\');
        if (escape_slashes) {
            special |= SWAR_BYTE_EQ(w, '/');
        }
        if (SWAR_HITS(w, special)) {
            break;
        }
        i += 8;
    }
    while (i < len) {
        kind = serialize_escape_kind[s[i]];
        if (kind != 0 && (kind != 3 || escape_slashes)) {
            break;
        }
        i++;
    }
    return i;
}

static int json_serialize_string(const char *string, size_t len, JSON_Sink *sink) {
    static const char hex_chars[] = "0123456789abcdef";
    const unsigned char *s = (const unsigned char*)string;
    const int escape_slashes = parson_escape_slashes;
    size_t i = 0, run_start = 0;
    unsigned char kind = 0;
    char escaped[6] = { '\\', 'u', '0', '0', '0', '0' };
    APPEND_CHAR('\"');
    while (i < len) {
        run_start = i;
        i += serialize_plain_run(s + i, len - i, escape_slashes);
        if (i > run_start) {
            APPEND_BYTES(s + run_start, i - run_start);
        }
        if (i >= len) {
            break;
        }
        kind = serialize_escape_kind[s[i]];
        if (kind == 2) {
            escaped[1] = 'u';
            escaped[4] = hex_chars[s[i] >> 4];
            escaped[5] = hex_chars[s[i] & 0x0F];
            APPEND_BYTES(escaped, 6);
        } else {
            escaped[1] = serialize_escape_char((char)s[i]);
            APPEND_BYTES(escaped, 2);
        }
        i++;
    }
    APPEND_CHAR('\"');
    return 0;
}

static int json_serialize_to_sink_r(const JSON_Value *value, JSON_Sink *sink, int level, int is_pretty)
{
    const char *key = NULL, *string = NULL;
    JSON_Value *temp_value = NULL;
    JSON_Array *array = NULL;
    JSON_Object *object = NULL;
    size_t i = 0, count = 0;

    switch (json_value_get_type(value)) {
        case JSONArray:
            array = json_value_get_array(value);
            count = json_array_get_count(array);
            APPEND_CHAR('[');
            if (count > 0 && is_pretty) {
                APPEND_CHAR('\n');
            }
            for (i = 0; i < count; i++) {
                if (is_pretty && append_indent(sink, level+1) < 0) {
                    return -1;
                }
                temp_value = array->items[i];
                if (json_serialize_to_sink_r(temp_value, sink, level+1, is_pretty) < 0) {
                    return -1;
                }
                if (i < (count - 1)) {
                    APPEND_CHAR(',');
                }
                if (is_pretty) {
                    APPEND_CHAR('\n');
                }
            }
            if (count > 0 && is_pretty && append_indent(sink, level) < 0) {
                return -1;
            }
            APPEND_CHAR(']');
            return 0;
        case JSONObject:
            object = json_value_get_object(value);
            count  = json_object_get_count(object);
            APPEND_CHAR('{');
            if (count > 0 && is_pretty) {
                APPEND_CHAR('\n');
            }
            for (i = 0; i < count; i++) {
                key = object->names[i];
                if (key == NULL) {
                    return -1;
                }
                if (is_pretty && append_indent(sink, level+1) < 0) {
                    return -1;
                }
                /* We do not support key names with embedded \0 chars */
                if (json_serialize_string(key, json_name_len(key), sink) < 0) {
                    return -1;
                }
                APPEND_CHAR(':');
                if (is_pretty) {
                    APPEND_CHAR(' ');
                }
                temp_value = object->values[i];
                if (json_serialize_to_sink_r(temp_value, sink, level+1, is_pretty) < 0) {
                    return -1;
                }
                if (i < (count - 1)) {
                    APPEND_CHAR(',');
                }
                if (is_pretty) {
                    APPEND_CHAR('\n');
                }
            }
            if (count > 0 && is_pretty && append_indent(sink, level) < 0) {
                return -1;
            }
            APPEND_CHAR('}');
            return 0;
        case JSONString:
            string = json_value_get_string(value);
            if (string == NULL) {
                return -1;
            }
            return json_serialize_string(string, json_value_get_string_len(value), sink);
        case JSONBoolean:
            if (json_value_get_boolean(value)) {
                APPEND_LITERAL("true");
            } else {
                APPEND_LITERAL("false");
            }
            return 0;
        case JSONNumber:
            return json_serialize_number(json_value_get_number(value), sink);
        case JSONNull:
            APPEND_LITERAL("null");
            return 0;
        case JSONError:
            return -1;
        default:
            return -1;
    }
}

/* Estimate compact output without scanning strings for escapes. */
static size_t json_serialization_estimate(const JSON_Value *value) {
    size_t i = 0, count = 0, total = 2;
    const JSON_Object *object = NULL;
    const JSON_Array *array = NULL;
    switch (json_value_get_type(value)) {
        case JSONArray:
            array = value->value.array;
            count = array->count;
            for (i = 0; i < count; i++) {
                total += json_serialization_estimate(array->items[i]) + 1;
            }
            return total;
        case JSONObject:
            object = value->value.object;
            count = object->count;
            for (i = 0; i < count; i++) {
                total += json_name_len(object->names[i]) + 4 + json_serialization_estimate(object->values[i]);
            }
            return total;
        case JSONString:
            return value->value.string.length + 2;
        case JSONNumber:
            return NUM_BUF_SIZE;
        default:
            return 5;
    }
}

static int json_serialize_to_buffer_r(const JSON_Value *value, char *buf, size_t buf_size, int is_pretty, size_t *written) {
    JSON_Sink sink;
    sink.base = buf;
    sink.pos = 0;
    sink.cap = buf_size;
    sink.growable = 0;
    if (json_serialize_to_sink_r(value, &sink, 0, is_pretty) < 0) {
        return -1;
    }
    *written = sink.pos;
    return 0;
}

static char * json_serialize_to_string_r(const JSON_Value *value, int is_pretty, JSON_Malloc_Function malloc_fun, JSON_Free_Function free_fun) {
    JSON_Sink sink;
    sink.pos = 0;
    sink.cap = json_serialization_estimate(value);
    sink.cap += sink.cap / 8 + 64;
    sink.growable = 1;
    sink.malloc_fun = malloc_fun;
    sink.free_fun = free_fun;
    sink.base = (char*)malloc_fun(sink.cap);
    if (sink.base == NULL) {
        return NULL;
    }
    if (json_serialize_to_sink_r(value, &sink, 0, is_pretty) < 0 || (sink.pos + 1 > sink.cap && sink_grow(&sink, sink.pos + 1) < 0)) {
        free_fun(sink.base);
        return NULL;
    }
    sink.base[sink.pos] = '\0';
    return sink.base;
}

#undef SINK_RESERVE
#undef APPEND_CHAR
#undef APPEND_BYTES
#undef APPEND_LITERAL

/* Parser API */
JSON_Value * json_parse_file(const char *filename) {
    char *file_contents = read_file(filename);
    JSON_Value *output_value = NULL;
    if (file_contents == NULL) {
        return NULL;
    }
    output_value = json_parse_string(file_contents);
    parson_free(file_contents);
    return output_value;
}

JSON_Value * json_parse_file_with_comments(const char *filename) {
    char *file_contents = read_file(filename);
    JSON_Value *output_value = NULL;
    if (file_contents == NULL) {
        return NULL;
    }
    output_value = json_parse_string_with_comments(file_contents);
    parson_free(file_contents);
    return output_value;
}

JSON_Value * json_parse_string(const char *string) {
    if (string == NULL) {
        return NULL;
    }
    if (string[0] == '\xEF' && string[1] == '\xBB' && string[2] == '\xBF') {
        string = string + 3; /* Support for UTF-8 BOM */
    }
    return parse_value((const char**)&string, 0);
}

JSON_Value * json_parse_string_with_comments(const char *string) {
    JSON_Value *result = NULL;
    char *string_mutable_copy = NULL, *string_mutable_copy_ptr = NULL;
    string_mutable_copy = parson_strdup(string);
    if (string_mutable_copy == NULL) {
        return NULL;
    }
    remove_comments(string_mutable_copy, "/*", "*/");
    remove_comments(string_mutable_copy, "//", "\n");
    string_mutable_copy_ptr = string_mutable_copy;
    result = parse_value((const char**)&string_mutable_copy_ptr, 0);
    parson_free(string_mutable_copy);
    return result;
}

/* JSON Object API */

JSON_Value * json_object_get_value(const JSON_Object *object, const char *name) {
    if (object == NULL || name == NULL) {
        return NULL;
    }
    return json_object_getn_value(object, name, strlen(name));
}

const char * json_object_get_string(const JSON_Object *object, const char *name) {
    return json_value_get_string(json_object_get_value(object, name));
}

size_t json_object_get_string_len(const JSON_Object *object, const char *name) {
    return json_value_get_string_len(json_object_get_value(object, name));
}

double json_object_get_number(const JSON_Object *object, const char *name) {
    return json_value_get_number(json_object_get_value(object, name));
}

JSON_Object * json_object_get_object(const JSON_Object *object, const char *name) {
    return json_value_get_object(json_object_get_value(object, name));
}

JSON_Array * json_object_get_array(const JSON_Object *object, const char *name) {
    return json_value_get_array(json_object_get_value(object, name));
}

int json_object_get_boolean(const JSON_Object *object, const char *name) {
    return json_value_get_boolean(json_object_get_value(object, name));
}

JSON_Value * json_object_dotget_value(const JSON_Object *object, const char *name) {
    const char *dot_position = strchr(name, '.');
    if (!dot_position) {
        return json_object_get_value(object, name);
    }
    object = json_value_get_object(json_object_getn_value(object, name, dot_position - name));
    return json_object_dotget_value(object, dot_position + 1);
}

const char * json_object_dotget_string(const JSON_Object *object, const char *name) {
    return json_value_get_string(json_object_dotget_value(object, name));
}

size_t json_object_dotget_string_len(const JSON_Object *object, const char *name) {
    return json_value_get_string_len(json_object_dotget_value(object, name));
}

double json_object_dotget_number(const JSON_Object *object, const char *name) {
    return json_value_get_number(json_object_dotget_value(object, name));
}

JSON_Object * json_object_dotget_object(const JSON_Object *object, const char *name) {
    return json_value_get_object(json_object_dotget_value(object, name));
}

JSON_Array * json_object_dotget_array(const JSON_Object *object, const char *name) {
    return json_value_get_array(json_object_dotget_value(object, name));
}

int json_object_dotget_boolean(const JSON_Object *object, const char *name) {
    return json_value_get_boolean(json_object_dotget_value(object, name));
}

size_t json_object_get_count(const JSON_Object *object) {
    return object ? object->count : 0;
}

const char * json_object_get_name(const JSON_Object *object, size_t index) {
    if (object == NULL || index >= json_object_get_count(object)) {
        return NULL;
    }
    return object->names[index];
}

JSON_Value * json_object_get_value_at(const JSON_Object *object, size_t index) {
    if (object == NULL || index >= json_object_get_count(object)) {
        return NULL;
    }
    return object->values[index];
}

JSON_Value *json_object_get_wrapping_value(const JSON_Object *object) {
    return object->wrapping_value;
}

int json_object_has_value (const JSON_Object *object, const char *name) {
    return json_object_get_value(object, name) != NULL;
}

int json_object_has_value_of_type(const JSON_Object *object, const char *name, JSON_Value_Type type) {
    JSON_Value *val = json_object_get_value(object, name);
    return val != NULL && json_value_get_type(val) == type;
}

int json_object_dothas_value (const JSON_Object *object, const char *name) {
    return json_object_dotget_value(object, name) != NULL;
}

int json_object_dothas_value_of_type(const JSON_Object *object, const char *name, JSON_Value_Type type) {
    JSON_Value *val = json_object_dotget_value(object, name);
    return val != NULL && json_value_get_type(val) == type;
}

/* JSON Array API */
JSON_Value * json_array_get_value(const JSON_Array *array, size_t index) {
    if (array == NULL || index >= json_array_get_count(array)) {
        return NULL;
    }
    return array->items[index];
}

const char * json_array_get_string(const JSON_Array *array, size_t index) {
    return json_value_get_string(json_array_get_value(array, index));
}

size_t json_array_get_string_len(const JSON_Array *array, size_t index) {
    return json_value_get_string_len(json_array_get_value(array, index));
}

double json_array_get_number(const JSON_Array *array, size_t index) {
    return json_value_get_number(json_array_get_value(array, index));
}

JSON_Object * json_array_get_object(const JSON_Array *array, size_t index) {
    return json_value_get_object(json_array_get_value(array, index));
}

JSON_Array * json_array_get_array(const JSON_Array *array, size_t index) {
    return json_value_get_array(json_array_get_value(array, index));
}

int json_array_get_boolean(const JSON_Array *array, size_t index) {
    return json_value_get_boolean(json_array_get_value(array, index));
}

size_t json_array_get_count(const JSON_Array *array) {
    return array ? array->count : 0;
}

JSON_Value * json_array_get_wrapping_value(const JSON_Array *array) {
    return array->wrapping_value;
}

/* JSON Value API */
JSON_Value_Type json_value_get_type(const JSON_Value *value) {
    return value ? value->type : JSONError;
}

JSON_Object * json_value_get_object(const JSON_Value *value) {
    return json_value_get_type(value) == JSONObject ? value->value.object : NULL;
}

JSON_Array * json_value_get_array(const JSON_Value *value) {
    return json_value_get_type(value) == JSONArray ? value->value.array : NULL;
}

static const JSON_String * json_value_get_string_desc(const JSON_Value *value) {
    return json_value_get_type(value) == JSONString ? &value->value.string : NULL;
}

const char * json_value_get_string(const JSON_Value *value) {
    const JSON_String *str = json_value_get_string_desc(value);
    return str ? str->chars : NULL;
}

size_t json_value_get_string_len(const JSON_Value *value) {
    const JSON_String *str = json_value_get_string_desc(value);
    return str ? str->length : 0;
}

double json_value_get_number(const JSON_Value *value) {
    return json_value_get_type(value) == JSONNumber ? value->value.number : 0;
}

int json_value_get_boolean(const JSON_Value *value) {
    return json_value_get_type(value) == JSONBoolean ? value->value.boolean : -1;
}

JSON_Value * json_value_get_parent (const JSON_Value *value) {
    return value ? value->parent : NULL;
}

void json_value_free(JSON_Value *value) {
    switch (json_value_get_type(value)) {
        case JSONObject:
            json_object_free(value->value.object);
            break;
        case JSONArray:
            json_array_free(value->value.array);
            break;
        default:
            break;
    }
    parson_free(value);
}

JSON_Value * json_value_init_object(void) {
    JSON_Value *new_value = json_value_alloc(JSONObject, sizeof(JSON_Object));
    if (!new_value) {
        return NULL;
    }
    new_value->value.object = (JSON_Object*)(new_value + 1);
    json_object_init(new_value->value.object, new_value);
    return new_value;
}

JSON_Value * json_value_init_array(void) {
    JSON_Value *new_value = json_value_alloc(JSONArray, sizeof(JSON_Array));
    if (!new_value) {
        return NULL;
    }
    new_value->value.array = (JSON_Array*)(new_value + 1);
    json_array_init(new_value->value.array, new_value);
    return new_value;
}

JSON_Value * json_value_init_string(const char *string) {
    if (string == NULL) {
        return NULL;
    }
    return json_value_init_string_with_len(string, strlen(string));
}

JSON_Value * json_value_init_string_with_len(const char *string, size_t length) {
    JSON_Value *value;
    if (string == NULL) {
        return NULL;
    }
    if (!is_valid_utf8(string, length)) {
        return NULL;
    }
    value = json_value_init_string_alloc(length);
    if (value == NULL) {
        return NULL;
    }
    memcpy(value->value.string.chars, string, length);
    value->value.string.chars[length] = '\0';
    return value;
}

JSON_Value * json_value_init_number(double number) {
    JSON_Value *new_value = NULL;
    if (IS_NUMBER_INVALID(number)) {
        return NULL;
    }
    new_value = json_value_alloc(JSONNumber, 0);
    if (new_value == NULL) {
        return NULL;
    }
    new_value->value.number = number;
    return new_value;
}

JSON_Value * json_value_init_boolean(int boolean) {
    JSON_Value *new_value = json_value_alloc(JSONBoolean, 0);
    if (!new_value) {
        return NULL;
    }
    new_value->value.boolean = boolean ? 1 : 0;
    return new_value;
}

JSON_Value * json_value_init_null(void) {
    return json_value_alloc(JSONNull, 0);
}

JSON_Value * json_value_deep_copy(const JSON_Value *value) {
    size_t i = 0;
    JSON_Value *return_value = NULL, *temp_value_copy = NULL, *temp_value = NULL;
    const JSON_String *temp_string = NULL;
    const char *temp_key = NULL;
    JSON_Array *temp_array = NULL, *temp_array_copy = NULL;
    JSON_Object *temp_object = NULL, *temp_object_copy = NULL;

    switch (json_value_get_type(value)) {
        case JSONArray:
            temp_array = json_value_get_array(value);
            return_value = json_value_init_array();
            if (return_value == NULL) {
                return NULL;
            }
            temp_array_copy = json_value_get_array(return_value);
            for (i = 0; i < json_array_get_count(temp_array); i++) {
                temp_value = json_array_get_value(temp_array, i);
                temp_value_copy = json_value_deep_copy(temp_value);
                if (temp_value_copy == NULL) {
                    json_value_free(return_value);
                    return NULL;
                }
                if (json_array_add(temp_array_copy, temp_value_copy) == JSONFailure) {
                    json_value_free(return_value);
                    json_value_free(temp_value_copy);
                    return NULL;
                }
            }
            return return_value;
        case JSONObject:
            temp_object = json_value_get_object(value);
            return_value = json_value_init_object();
            if (return_value == NULL) {
                return NULL;
            }
            temp_object_copy = json_value_get_object(return_value);
            for (i = 0; i < json_object_get_count(temp_object); i++) {
                temp_key = json_object_get_name(temp_object, i);
                temp_value = json_object_get_value(temp_object, temp_key);
                temp_value_copy = json_value_deep_copy(temp_value);
                if (temp_value_copy == NULL) {
                    json_value_free(return_value);
                    return NULL;
                }
                if (json_object_add(temp_object_copy, temp_key, temp_value_copy) == JSONFailure) {
                    json_value_free(return_value);
                    json_value_free(temp_value_copy);
                    return NULL;
                }
            }
            return return_value;
        case JSONBoolean:
            return json_value_init_boolean(json_value_get_boolean(value));
        case JSONNumber:
            return json_value_init_number(json_value_get_number(value));
        case JSONString:
            temp_string = json_value_get_string_desc(value);
            if (temp_string == NULL) {
                return NULL;
            }
            return_value = json_value_init_string_alloc(temp_string->length);
            if (return_value == NULL) {
                return NULL;
            }
            memcpy(return_value->value.string.chars, temp_string->chars, temp_string->length + 1);
            return return_value;
        case JSONNull:
            return json_value_init_null();
        case JSONError:
            return NULL;
        default:
            return NULL;
    }
}

size_t json_serialization_size(const JSON_Value *value) {
    size_t written = 0;
    if (json_serialize_to_buffer_r(value, NULL, 0, 0, &written) < 0) {
        return 0;
    }
    return written + 1;
}

JSON_Status json_serialize_to_buffer(const JSON_Value *value, char *buf, size_t buf_size_in_bytes) {
    size_t written = 0;
    size_t needed_size_in_bytes = json_serialization_size(value);
    if (buf == NULL || needed_size_in_bytes == 0 || buf_size_in_bytes < needed_size_in_bytes) {
        return JSONFailure;
    }
    if (json_serialize_to_buffer_r(value, buf, buf_size_in_bytes - 1, 0, &written) < 0) {
        return JSONFailure;
    }
    buf[written] = '\0';
    return JSONSuccess;
}

JSON_Status json_serialize_to_file(const JSON_Value *value, const char *filename) {
    JSON_Status return_code = JSONSuccess;
    FILE *fp = NULL;
    char *serialized_string = json_serialize_to_string(value);
    if (serialized_string == NULL) {
        return JSONFailure;
    }
    fp = fopen(filename, "w");
    if (fp == NULL) {
        json_free_serialized_string(serialized_string);
        return JSONFailure;
    }
    if (fputs(serialized_string, fp) == EOF) {
        return_code = JSONFailure;
    }
    if (fclose(fp) == EOF) {
        return_code = JSONFailure;
    }
    json_free_serialized_string(serialized_string);
    return return_code;
}

char * json_serialize_to_string(const JSON_Value *value) {
    return json_serialize_to_string_r(value, 0, parson_malloc, parson_free);
}

char * json_serialize_to_string_malloc(const JSON_Value *value) {
    return json_serialize_to_string_r(value, 0, malloc, free);
}

size_t json_serialization_size_pretty(const JSON_Value *value) {
    size_t written = 0;
    if (json_serialize_to_buffer_r(value, NULL, 0, 1, &written) < 0) {
        return 0;
    }
    return written + 1;
}

JSON_Status json_serialize_to_buffer_pretty(const JSON_Value *value, char *buf, size_t buf_size_in_bytes) {
    size_t written = 0;
    size_t needed_size_in_bytes = json_serialization_size_pretty(value);
    if (buf == NULL || needed_size_in_bytes == 0 || buf_size_in_bytes < needed_size_in_bytes) {
        return JSONFailure;
    }
    if (json_serialize_to_buffer_r(value, buf, buf_size_in_bytes - 1, 1, &written) < 0) {
        return JSONFailure;
    }
    buf[written] = '\0';
    return JSONSuccess;
}

JSON_Status json_serialize_to_file_pretty(const JSON_Value *value, const char *filename) {
    JSON_Status return_code = JSONSuccess;
    FILE *fp = NULL;
    char *serialized_string = json_serialize_to_string_pretty(value);
    if (serialized_string == NULL) {
        return JSONFailure;
    }
    fp = fopen(filename, "w");
    if (fp == NULL) {
        json_free_serialized_string(serialized_string);
        return JSONFailure;
    }
    if (fputs(serialized_string, fp) == EOF) {
        return_code = JSONFailure;
    }
    if (fclose(fp) == EOF) {
        return_code = JSONFailure;
    }
    json_free_serialized_string(serialized_string);
    return return_code;
}

char * json_serialize_to_string_pretty(const JSON_Value *value) {
    return json_serialize_to_string_r(value, 1, parson_malloc, parson_free);
}

void json_free_serialized_string(char *string) {
    parson_free(string);
}

JSON_Status json_array_remove(JSON_Array *array, size_t ix) {
    size_t to_move_bytes = 0;
    if (array == NULL || ix >= json_array_get_count(array)) {
        return JSONFailure;
    }
    json_value_free(json_array_get_value(array, ix));
    to_move_bytes = (json_array_get_count(array) - 1 - ix) * sizeof(JSON_Value*);
    memmove(array->items + ix, array->items + ix + 1, to_move_bytes);
    array->count -= 1;
    return JSONSuccess;
}

JSON_Status json_array_replace_value(JSON_Array *array, size_t ix, JSON_Value *value) {
    if (array == NULL || value == NULL || value->parent != NULL || ix >= json_array_get_count(array)) {
        return JSONFailure;
    }
    json_value_free(json_array_get_value(array, ix));
    value->parent = json_array_get_wrapping_value(array);
    array->items[ix] = value;
    return JSONSuccess;
}

JSON_Status json_array_replace_string(JSON_Array *array, size_t i, const char* string) {
    JSON_Value *value = json_value_init_string(string);
    if (value == NULL) {
        return JSONFailure;
    }
    if (json_array_replace_value(array, i, value) == JSONFailure) {
        json_value_free(value);
        return JSONFailure;
    }
    return JSONSuccess;
}

JSON_Status json_array_replace_string_with_len(JSON_Array *array, size_t i, const char *string, size_t len) {
    JSON_Value *value = json_value_init_string_with_len(string, len);
    if (value == NULL) {
        return JSONFailure;
    }
    if (json_array_replace_value(array, i, value) == JSONFailure) {
        json_value_free(value);
        return JSONFailure;
    }
    return JSONSuccess;
}

JSON_Status json_array_replace_number(JSON_Array *array, size_t i, double number) {
    JSON_Value *value = json_value_init_number(number);
    if (value == NULL) {
        return JSONFailure;
    }
    if (json_array_replace_value(array, i, value) == JSONFailure) {
        json_value_free(value);
        return JSONFailure;
    }
    return JSONSuccess;
}

JSON_Status json_array_replace_boolean(JSON_Array *array, size_t i, int boolean) {
    JSON_Value *value = json_value_init_boolean(boolean);
    if (value == NULL) {
        return JSONFailure;
    }
    if (json_array_replace_value(array, i, value) == JSONFailure) {
        json_value_free(value);
        return JSONFailure;
    }
    return JSONSuccess;
}

JSON_Status json_array_replace_null(JSON_Array *array, size_t i) {
    JSON_Value *value = json_value_init_null();
    if (value == NULL) {
        return JSONFailure;
    }
    if (json_array_replace_value(array, i, value) == JSONFailure) {
        json_value_free(value);
        return JSONFailure;
    }
    return JSONSuccess;
}

JSON_Status json_array_clear(JSON_Array *array) {
    size_t i = 0;
    if (array == NULL) {
        return JSONFailure;
    }
    for (i = 0; i < json_array_get_count(array); i++) {
        json_value_free(json_array_get_value(array, i));
    }
    array->count = 0;
    return JSONSuccess;
}

JSON_Status json_array_append_value(JSON_Array *array, JSON_Value *value) {
    if (array == NULL || value == NULL || value->parent != NULL) {
        return JSONFailure;
    }
    return json_array_add(array, value);
}

JSON_Status json_array_append_string(JSON_Array *array, const char *string) {
    JSON_Value *value = json_value_init_string(string);
    if (value == NULL) {
        return JSONFailure;
    }
    if (json_array_append_value(array, value) == JSONFailure) {
        json_value_free(value);
        return JSONFailure;
    }
    return JSONSuccess;
}

JSON_Status json_array_append_string_with_len(JSON_Array *array, const char *string, size_t len) {
    JSON_Value *value = json_value_init_string_with_len(string, len);
    if (value == NULL) {
        return JSONFailure;
    }
    if (json_array_append_value(array, value) == JSONFailure) {
        json_value_free(value);
        return JSONFailure;
    }
    return JSONSuccess;
}

JSON_Status json_array_append_number(JSON_Array *array, double number) {
    JSON_Value *value = json_value_init_number(number);
    if (value == NULL) {
        return JSONFailure;
    }
    if (json_array_append_value(array, value) == JSONFailure) {
        json_value_free(value);
        return JSONFailure;
    }
    return JSONSuccess;
}

JSON_Status json_array_append_boolean(JSON_Array *array, int boolean) {
    JSON_Value *value = json_value_init_boolean(boolean);
    if (value == NULL) {
        return JSONFailure;
    }
    if (json_array_append_value(array, value) == JSONFailure) {
        json_value_free(value);
        return JSONFailure;
    }
    return JSONSuccess;
}

JSON_Status json_array_append_null(JSON_Array *array) {
    JSON_Value *value = json_value_init_null();
    if (value == NULL) {
        return JSONFailure;
    }
    if (json_array_append_value(array, value) == JSONFailure) {
        json_value_free(value);
        return JSONFailure;
    }
    return JSONSuccess;
}

JSON_Status json_object_set_value(JSON_Object *object, const char *name, JSON_Value *value) {
    size_t i = 0, name_len = 0;
    char *new_name = NULL;
    if (object == NULL || name == NULL || value == NULL || value->parent != NULL) {
        return JSONFailure;
    }
    name_len = strlen(name);
    i = json_object_find(object, name, name_len);
    if (i != JSON_NOT_FOUND) { /* free and overwrite old value */
        json_value_free(object->values[i]);
        value->parent = json_object_get_wrapping_value(object);
        object->values[i] = value;
        return JSONSuccess;
    }
    /* add new key value pair */
    new_name = json_name_new(name, name_len);
    if (new_name == NULL) {
        return JSONFailure;
    }
    if (json_object_add_owned(object, new_name, value) == JSONFailure) {
        json_name_free(new_name);
        return JSONFailure;
    }
    return JSONSuccess;
}

JSON_Status json_object_set_string(JSON_Object *object, const char *name, const char *string) {
    JSON_Value *value = json_value_init_string(string);
    JSON_Status status = json_object_set_value(object, name, value);
    if (status == JSONFailure) {
        json_value_free(value);
    }
    return status;
}

JSON_Status json_object_set_string_with_len(JSON_Object *object, const char *name, const char *string, size_t len) {
    JSON_Value *value = json_value_init_string_with_len(string, len);
    JSON_Status status = json_object_set_value(object, name, value);
    if (status == JSONFailure) {
        json_value_free(value);
    }
    return status;
}

JSON_Status json_object_set_number(JSON_Object *object, const char *name, double number) {
    JSON_Value *value = json_value_init_number(number);
    JSON_Status status = json_object_set_value(object, name, value);
    if (status == JSONFailure) {
        json_value_free(value);
    }
    return status;
}

JSON_Status json_object_set_boolean(JSON_Object *object, const char *name, int boolean) {
    JSON_Value *value = json_value_init_boolean(boolean);
    JSON_Status status = json_object_set_value(object, name, value);
    if (status == JSONFailure) {
        json_value_free(value);
    }
    return status;
}

JSON_Status json_object_set_null(JSON_Object *object, const char *name) {
    JSON_Value *value = json_value_init_null();
    JSON_Status status = json_object_set_value(object, name, value);
    if (status == JSONFailure) {
        json_value_free(value);
    }
    return status;
}

JSON_Status json_object_dotset_value(JSON_Object *object, const char *name, JSON_Value *value) {
    const char *dot_pos = NULL;
    JSON_Value *temp_value = NULL, *new_value = NULL;
    JSON_Object *temp_object = NULL, *new_object = NULL;
    JSON_Status status = JSONFailure;
    size_t name_len = 0;
    if (object == NULL || name == NULL || value == NULL) {
        return JSONFailure;
    }
    dot_pos = strchr(name, '.');
    if (dot_pos == NULL) {
        return json_object_set_value(object, name, value);
    }
    name_len = dot_pos - name;
    temp_value = json_object_getn_value(object, name, name_len);
    if (temp_value) {
        /* Don't overwrite existing non-object (unlike json_object_set_value, but it shouldn't be changed at this point) */
        if (json_value_get_type(temp_value) != JSONObject) {
            return JSONFailure;
        }
        temp_object = json_value_get_object(temp_value);
        return json_object_dotset_value(temp_object, dot_pos + 1, value);
    }
    new_value = json_value_init_object();
    if (new_value == NULL) {
        return JSONFailure;
    }
    new_object = json_value_get_object(new_value);
    status = json_object_dotset_value(new_object, dot_pos + 1, value);
    if (status != JSONSuccess) {
        json_value_free(new_value);
        return JSONFailure;
    }
    status = json_object_addn(object, name, name_len, new_value);
    if (status != JSONSuccess) {
        json_object_dotremove_internal(new_object, dot_pos + 1, 0);
        json_value_free(new_value);
        return JSONFailure;
    }
    return JSONSuccess;
}

JSON_Status json_object_dotset_string(JSON_Object *object, const char *name, const char *string) {
    JSON_Value *value = json_value_init_string(string);
    if (value == NULL) {
        return JSONFailure;
    }
    if (json_object_dotset_value(object, name, value) == JSONFailure) {
        json_value_free(value);
        return JSONFailure;
    }
    return JSONSuccess;
}

JSON_Status json_object_dotset_string_with_len(JSON_Object *object, const char *name, const char *string, size_t len) {
    JSON_Value *value = json_value_init_string_with_len(string, len);
    if (value == NULL) {
        return JSONFailure;
    }
    if (json_object_dotset_value(object, name, value) == JSONFailure) {
        json_value_free(value);
        return JSONFailure;
    }
    return JSONSuccess;
}

JSON_Status json_object_dotset_number(JSON_Object *object, const char *name, double number) {
    JSON_Value *value = json_value_init_number(number);
    if (value == NULL) {
        return JSONFailure;
    }
    if (json_object_dotset_value(object, name, value) == JSONFailure) {
        json_value_free(value);
        return JSONFailure;
    }
    return JSONSuccess;
}

JSON_Status json_object_dotset_boolean(JSON_Object *object, const char *name, int boolean) {
    JSON_Value *value = json_value_init_boolean(boolean);
    if (value == NULL) {
        return JSONFailure;
    }
    if (json_object_dotset_value(object, name, value) == JSONFailure) {
        json_value_free(value);
        return JSONFailure;
    }
    return JSONSuccess;
}

JSON_Status json_object_dotset_null(JSON_Object *object, const char *name) {
    JSON_Value *value = json_value_init_null();
    if (value == NULL) {
        return JSONFailure;
    }
    if (json_object_dotset_value(object, name, value) == JSONFailure) {
        json_value_free(value);
        return JSONFailure;
    }
    return JSONSuccess;
}

JSON_Status json_object_remove(JSON_Object *object, const char *name) {
    return json_object_remove_internal(object, name, 1);
}

JSON_Status json_object_dotremove(JSON_Object *object, const char *name) {
    return json_object_dotremove_internal(object, name, 1);
}

JSON_Status json_object_clear(JSON_Object *object) {
    size_t i = 0;
    if (object == NULL) {
        return JSONFailure;
    }
    for (i = 0; i < json_object_get_count(object); i++) {
        json_name_free(object->names[i]);
        json_value_free(object->values[i]);
    }
    object->count = 0;
    return JSONSuccess;
}

JSON_Status json_object_copy_all_items (JSON_Object *joDest, const JSON_Object *joSrc) {
    JSON_Value* temp_value = NULL;
    JSON_Value* temp_value_copy = NULL;
    size_t i = 0;
    const char* key_name = NULL;
    for (i = 0; i < json_object_get_count(joSrc); i++) {
        key_name = json_object_get_name(joSrc, i);
        temp_value = json_object_get_value(joSrc, key_name);
        temp_value_copy = json_value_deep_copy(temp_value);
        if (temp_value_copy == NULL) return JSONFailure;

        if (json_object_add(joDest, key_name, temp_value_copy) == JSONFailure) {
            json_value_free(temp_value_copy);
            return JSONFailure;
        }
    }
    return JSONSuccess;
}

JSON_Status json_array_copy_all_items (JSON_Array *jaDest, const JSON_Array *jaSrc) {
    JSON_Value* temp_value = NULL;
    JSON_Value* temp_value_copy = NULL;
    size_t i = 0;
    for (i = 0; i < json_array_get_count(jaSrc); i++) {
        temp_value = json_array_get_value(jaSrc, i);
        temp_value_copy = json_value_deep_copy(temp_value);
        if (temp_value_copy == NULL) return JSONFailure;

        if (json_array_add(jaDest, temp_value_copy) == JSONFailure) {
            json_value_free(temp_value_copy);
            return JSONFailure;
        }
    }
    return JSONSuccess;
}

JSON_Status json_validate(const JSON_Value *schema, const JSON_Value *value) {
    JSON_Value *temp_schema_value = NULL, *temp_value = NULL;
    JSON_Array *schema_array = NULL, *value_array = NULL;
    JSON_Object *schema_object = NULL, *value_object = NULL;
    JSON_Value_Type schema_type = JSONError, value_type = JSONError;
    const char *key = NULL;
    size_t i = 0, count = 0;
    if (schema == NULL || value == NULL) {
        return JSONFailure;
    }
    schema_type = json_value_get_type(schema);
    value_type = json_value_get_type(value);
    if (schema_type != value_type && schema_type != JSONNull) { /* null represents all values */
        return JSONFailure;
    }
    switch (schema_type) {
        case JSONArray:
            schema_array = json_value_get_array(schema);
            value_array = json_value_get_array(value);
            count = json_array_get_count(schema_array);
            if (count == 0) {
                return JSONSuccess; /* Empty array allows all types */
            }
            /* Get first value from array, rest is ignored */
            temp_schema_value = json_array_get_value(schema_array, 0);
            for (i = 0; i < json_array_get_count(value_array); i++) {
                temp_value = json_array_get_value(value_array, i);
                if (json_validate(temp_schema_value, temp_value) == JSONFailure) {
                    return JSONFailure;
                }
            }
            return JSONSuccess;
        case JSONObject:
            schema_object = json_value_get_object(schema);
            value_object = json_value_get_object(value);
            count = json_object_get_count(schema_object);
            if (count == 0) {
                return JSONSuccess; /* Empty object allows all objects */
            } else if (json_object_get_count(value_object) < count) {
                return JSONFailure; /* Tested object mustn't have less name-value pairs than schema */
            }
            for (i = 0; i < count; i++) {
                key = json_object_get_name(schema_object, i);
                temp_schema_value = json_object_get_value(schema_object, key);
                temp_value = json_object_get_value(value_object, key);
                if (temp_value == NULL) {
                    return JSONFailure;
                }
                if (json_validate(temp_schema_value, temp_value) == JSONFailure) {
                    return JSONFailure;
                }
            }
            return JSONSuccess;
        case JSONString: case JSONNumber: case JSONBoolean: case JSONNull:
            return JSONSuccess; /* equality already tested before switch */
        case JSONError: default:
            return JSONFailure;
    }
}

int json_value_equals(const JSON_Value *a, const JSON_Value *b) {
    JSON_Object *a_object = NULL, *b_object = NULL;
    JSON_Array *a_array = NULL, *b_array = NULL;
    const JSON_String *a_string = NULL, *b_string = NULL;
    const char *key = NULL;
    size_t a_count = 0, b_count = 0, i = 0;
    JSON_Value_Type a_type, b_type;
    a_type = json_value_get_type(a);
    b_type = json_value_get_type(b);
    if (a_type != b_type) {
        return 0;
    }
    switch (a_type) {
        case JSONArray:
            a_array = json_value_get_array(a);
            b_array = json_value_get_array(b);
            a_count = json_array_get_count(a_array);
            b_count = json_array_get_count(b_array);
            if (a_count != b_count) {
                return 0;
            }
            for (i = 0; i < a_count; i++) {
                if (!json_value_equals(json_array_get_value(a_array, i),
                                       json_array_get_value(b_array, i))) {
                    return 0;
                }
            }
            return 1;
        case JSONObject:
            a_object = json_value_get_object(a);
            b_object = json_value_get_object(b);
            a_count = json_object_get_count(a_object);
            b_count = json_object_get_count(b_object);
            if (a_count != b_count) {
                return 0;
            }
            for (i = 0; i < a_count; i++) {
                key = json_object_get_name(a_object, i);
                if (!json_value_equals(json_object_get_value(a_object, key),
                                       json_object_get_value(b_object, key))) {
                    return 0;
                }
            }
            return 1;
        case JSONString:
            a_string = json_value_get_string_desc(a);
            b_string = json_value_get_string_desc(b);
            if (a_string == NULL || b_string == NULL) {
                return 0; /* shouldn't happen */
            }
            return a_string->length == b_string->length &&
                   memcmp(a_string->chars, b_string->chars, a_string->length) == 0;
        case JSONBoolean:
            return json_value_get_boolean(a) == json_value_get_boolean(b);
        case JSONNumber:
            return fabs(json_value_get_number(a) - json_value_get_number(b)) < 0.000001; /* EPSILON */
        case JSONError:
            return 1;
        case JSONNull:
            return 1;
        default:
            return 1;
    }
}

JSON_Value_Type json_type(const JSON_Value *value) {
    return json_value_get_type(value);
}

JSON_Object * json_object (const JSON_Value *value) {
    return json_value_get_object(value);
}

JSON_Array * json_array  (const JSON_Value *value) {
    return json_value_get_array(value);
}

const char * json_string (const JSON_Value *value) {
    return json_value_get_string(value);
}

size_t json_string_len(const JSON_Value *value) {
    return json_value_get_string_len(value);
}

double json_number (const JSON_Value *value) {
    return json_value_get_number(value);
}

int json_boolean(const JSON_Value *value) {
    return json_value_get_boolean(value);
}

void json_set_allocation_functions(JSON_Malloc_Function malloc_fun, JSON_Free_Function free_fun) {
    parson_malloc = malloc_fun;
    parson_free = free_fun;
}

void json_set_escape_slashes(int escape_slashes) {
    parson_escape_slashes = escape_slashes;
}
