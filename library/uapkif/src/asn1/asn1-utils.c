/*
 * Copyright 2021 The UAPKI Project Authors.
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

#include "asn1-utils.h"
#include "macros-internal.h"
#include <time.h>

#undef FILE_MARKER
#define FILE_MARKER "asn1/asn1-utils.c"

struct _callback_arg {
    uint8_t *buffer;
    size_t   offset;
    size_t   size;
};

static int der_encode_consume_bytes(const void *buffer, size_t size, void *key)
{
    struct _callback_arg *arg = (struct _callback_arg *)key;
    int ret = RET_OK;

    if ((arg->offset + size) >= arg->size) {
        size_t nsize = (arg->size ? arg->size << 2 : 16) + size;
        void *p = NULL;

        REALLOC_CHECKED(arg->buffer, nsize, p);

        arg->buffer = (uint8_t *)p;
        arg->size = nsize;
    }

    memcpy(arg->buffer + arg->offset, buffer, size);
    arg->offset += size;
    ASSERT(arg->offset < arg->size);

cleanup:

    return ret;
}

/**
 * Возвращает байтовое представление объекта в DER-кодировании.
 * Выделяемая память требует освобождения.
 *
 * @param desc       дескриптор объекта
 * @param object     указатель на объект
 * @param encode     указатель на выделяемую память, содержащую DER-представление.
 * @param encode_len актуальный размер данных
 *
 * @return код ошибки
 */
int asn_encode(asn_TYPE_descriptor_t *desc, const void *object,
        uint8_t **encode, size_t *encode_len)
{
    struct _callback_arg arg_cb;
    asn_enc_rval_t ret_old;
    int ret = RET_OK;

    CHECK_PARAM(desc != NULL);
    CHECK_PARAM(object != NULL);
    CHECK_PARAM(encode != NULL);
    CHECK_PARAM(encode_len != NULL);

    arg_cb.offset = arg_cb.size = 0;
    arg_cb.buffer = 0;

    ret_old = der_encode(desc, (void *)object, der_encode_consume_bytes, &arg_cb);

    if (ret_old.encoded == -1) {
        free(arg_cb.buffer);
        SET_ERROR(RET_ASN1_ERROR);
    }

    *encode = arg_cb.buffer;
    *encode_len = ret_old.encoded;
cleanup:

    return ret;
}

int asn_encode_ba(asn_TYPE_descriptor_t *desc, const void *object, ByteArray **encoded)
{
    uint8_t *encoded_bytes = NULL;
    size_t encoded_bytes_len = 0;
    int ret = RET_OK;

    CHECK_PARAM(desc);
    CHECK_PARAM(object);
    CHECK_PARAM(encoded);

    DO(asn_encode(desc, object, &encoded_bytes, &encoded_bytes_len));
    CHECK_NOT_NULL(*encoded = ba_alloc_from_uint8(encoded_bytes, encoded_bytes_len));

cleanup:
    free(encoded_bytes);
    return ret;
}
/**
 * Инициализирует asn1 структуру объекта из байтового представления.
 * Выделяемая память требует освобождения.
 *
 * @param desc        дескриптор объекта
 * @param object      указатель на объект
 * @param encode      указатель буфер содержащий BER-представление структуры.
 * @param encode_len  размер буфер
 *
 * @return код ошибки
 */
int asn_decode(asn_TYPE_descriptor_t *desc, void *object,
        const void *encode, size_t encode_len)
{
    asn_dec_rval_t ret_old;
    int ret = RET_OK;

    CHECK_PARAM(desc != NULL);
    CHECK_PARAM(object != NULL);
    CHECK_PARAM(encode != NULL);

    ret_old = ber_decode(NULL, desc, &object, encode, encode_len);
    ret =  (ret_old.code == RC_OK) ? RET_OK : RET_ASN1_DECODE_ERROR;
cleanup:
    return ret;
}

int asn_decode_ba(asn_TYPE_descriptor_t *desc, void *object, const ByteArray *encode)
{
    int ret = RET_OK;

    CHECK_PARAM(desc != NULL);
    CHECK_PARAM(object != NULL);
    CHECK_PARAM(encode != NULL);

    DO(asn_decode(desc, object, ba_get_buf_const(encode), ba_get_len(encode)));
cleanup:
    return ret;
}

void *asn_decode_with_alloc(asn_TYPE_descriptor_t *desc, const void *encode, size_t encode_len)
{
    void *object = NULL;
    asn_dec_rval_t ret_old;
    int ret = RET_OK;

    CHECK_PARAM(encode != NULL);
    CHECK_PARAM(desc != NULL);

    ret_old = ber_decode(NULL, desc, &object, encode, encode_len);
    ret = ret_old.code;

cleanup:

    if (ret != RET_OK) {
        ASN_FREE(desc, object);
        object = NULL;
    }
    return object;
}

void *asn_decode_ba_with_alloc(asn_TYPE_descriptor_t *desc, const ByteArray *encoded)
{
    int ret = RET_OK;
    void *value = NULL;

    CHECK_PARAM(desc != NULL);
    CHECK_PARAM(encoded != NULL);

    CHECK_NOT_NULL(value = asn_decode_with_alloc(desc, ba_get_buf_const(encoded), ba_get_len(encoded)));

cleanup:

    return value;
}

/**
 * Создает копию ASN.1 объекта заданного типа.
 * Если (*dst == NULL) выделяется память.
 * Выделяемая память требует освобождения.
 *
 * @param type тип объекта
 * @param src  источник
 * @param dst  приемник
 *
 * @return код ошибки
 */
int asn_copy(asn_TYPE_descriptor_t *type, const void *src, void *dst)
{
    uint8_t *encode = NULL;
    size_t encode_len = 0;
    int ret = RET_OK;

    CHECK_PARAM(type != NULL);
    CHECK_PARAM(src != NULL);
    CHECK_PARAM(dst != NULL);

    DO(asn_encode(type, src, &encode, &encode_len));
    DO(asn_decode(type, dst, encode, encode_len));
    CHECK_NOT_NULL(dst);

cleanup:

    free(encode);

    return ret;
}

/**
* Создает копию ASN.1 объекта заданного типа.
* Если (*dst == NULL) выделяется память.
* Выделяемая память требует освобождения.
*
* @param type тип объекта
* @param src  источник
* @param dst  приемник
*
* @return код ошибки
*/
void *asn_copy_with_alloc(asn_TYPE_descriptor_t *type, const void *src)
{
    uint8_t *encode = NULL;
    void *dst = NULL;
    size_t encode_len = 0;
    int ret = RET_OK;

    CHECK_PARAM(type != NULL);
    CHECK_PARAM(src != NULL);

    DO(asn_encode(type, src, &encode, &encode_len));
    dst = asn_decode_with_alloc(type, encode, encode_len);
    CHECK_NOT_NULL(dst);

cleanup:

    free(encode);

    return dst;
}

/**
 * Сравнивает две ASN.1 структуры.
 *
 * @param type тип объекта
 * @param a    сравниваемая структура
 * @param b    сравниваемая структура
 *
 * @return равны ли a и b
 */
bool asn_equals(asn_TYPE_descriptor_t *type, const void *a, const void *b)
{
    uint8_t *a_buffer = NULL;
    uint8_t *b_buffer = NULL;
    size_t a_size = 0;
    size_t b_size = 0;
    int ret = RET_OK;

    CHECK_PARAM(type);
    CHECK_PARAM(a);
    CHECK_PARAM(b);

    DO(asn_encode(type, a, &a_buffer, &a_size));
    DO(asn_encode(type, b, &b_buffer, &b_size));

    ret = (int)(a_size - b_size);
    if (ret) {
        goto cleanup;
    }

    ret = memcmp(a_buffer, b_buffer, a_size);

cleanup:

    free(a_buffer);
    free(b_buffer);

    return (ret == 0);
}

int asn_parse_args_oid(const char *text, long **arcs, size_t *size)
{
    long *arcs_oid = NULL;
    int ret = RET_OK;
    int contained;

    CHECK_PARAM(text != NULL);
    CHECK_PARAM(arcs != NULL);
    CHECK_PARAM(size != NULL);

    contained = OBJECT_IDENTIFIER_parse_arcs(text, -1, NULL, 0, NULL);
    if (contained == -1) {
        SET_ERROR(RET_ASN1_ERROR);
    }

    MALLOC_CHECKED(arcs_oid, contained * sizeof(long));

    contained = OBJECT_IDENTIFIER_parse_arcs(text, -1, arcs_oid, contained, NULL);
    if (contained == -1) {
        SET_ERROR(RET_ASN1_ERROR);
    }

    *arcs = arcs_oid;
    arcs_oid = NULL;
    *size = contained;

cleanup:

    free(arcs_oid);

    return ret;
}

int asn_create_oid_from_text(const char *text, OBJECT_IDENTIFIER_t **dst)
{
    long *arcs = NULL;
    size_t size;
    int ret = RET_OK;

    CHECK_PARAM(text != NULL);
    CHECK_PARAM(dst != NULL);

    DO(asn_parse_args_oid(text, &arcs, &size));
    DO(asn_create_oid(arcs, size, dst));

cleanup:

    free(arcs);

    return ret;
}

int asn_set_oid_from_text(const char* text, OBJECT_IDENTIFIER_t* dst)
{
    long* arcs = NULL;
    size_t size;
    int ret = RET_OK;

    CHECK_PARAM(text != NULL);
    CHECK_PARAM(dst != NULL);

    DO(asn_parse_args_oid(text, &arcs, &size));
    DO(asn_set_oid(arcs, size, dst));

cleanup:

    free(arcs);

    return ret;
}

int asn_oid_to_text(const OBJECT_IDENTIFIER_t* dst, char** text)
{
    int ret = RET_OK;
    unsigned long fixed_arcs[12];    // Try with fixed space first
    unsigned long* arcs = fixed_arcs;
    unsigned int arc_type_size = sizeof(fixed_arcs[0]);    // sizeof(long)
    unsigned int arc_slots = sizeof(fixed_arcs) / sizeof(fixed_arcs[0]); // 12
    unsigned int count, i;    // Real number of arcs.
    int n, l = 0;

    CHECK_PARAM(text != NULL);
    CHECK_PARAM(dst != NULL);

    *text = NULL;

    count = OBJECT_IDENTIFIER_get_arcs(dst, arcs, arc_type_size, arc_slots);
    // If necessary, reallocate arcs array and try again.
    if (count > arc_slots) {
        arc_slots = count;
        MALLOC_CHECKED(arcs, (size_t)arc_type_size * arc_slots);
        count = OBJECT_IDENTIFIER_get_arcs(dst, arcs, arc_type_size, arc_slots);
        ASSERT(count == arc_slots);
    }
       
    CALLOC_CHECKED(*text, (size_t)count * 11); /*10 digits + 1 point or zero teminator*/

    // Print the contents of the arcs array.
    if (count > 0) {
        for (i = 0; i < count - 1; i++) {
            n = snprintf((*text) + l, 12, "%lu.", arcs[i]);
            if ((n < 0) || (n >= 12)) {
                SET_ERROR(RET_INVALID_OID);
            }
            l += n;
        }

        n = snprintf((*text) + l, 11, "%lu", arcs[count - 1]);
        if ((n < 0) || (n >= 11)) {
            SET_ERROR(RET_INVALID_OID);
        }
    }
        
cleanup:

    if (arcs != fixed_arcs) {
        free(arcs);
    }

    if (ret != RET_OK) {
        free(*text);
        *text = NULL;
    }

    return ret;
}

int asn_create_oid(const long *src, const size_t size, OBJECT_IDENTIFIER_t **dst)
{
    int ret = RET_OK;

    CHECK_PARAM(dst != NULL);
    CHECK_PARAM(dst != NULL);

    if (!*dst) {
        ASN_ALLOC(*dst);
    }
    DO(OBJECT_IDENTIFIER_set_arcs(*dst, src, sizeof(long), (unsigned int)size));
cleanup:
    return ret;
}

int asn_set_oid(const long *src, const size_t size, OBJECT_IDENTIFIER_t *dst)
{
    int ret = RET_OK;

    CHECK_PARAM(src != NULL);
    CHECK_PARAM(dst != NULL);
    DO(OBJECT_IDENTIFIER_set_arcs(dst, src, sizeof(long), (unsigned int)size));

cleanup:
    return ret;
}

int asn_create_octstring(const void *src, const size_t len, OCTET_STRING_t **dst)
{
    int ret = RET_OK;

    CHECK_PARAM(src != NULL);
    CHECK_PARAM(dst != NULL);

    if (!*dst) {
        ASN_ALLOC(*dst);
    }
    DO(asn_bytes2OCTSTRING(*dst, src, len));
cleanup:
    return ret;
}

int asn_create_octstring_from_ba(const ByteArray *src, OCTET_STRING_t **dst)
{
    uint8_t *buf = NULL;
    size_t buf_len;
    int ret = RET_OK;

    CHECK_PARAM(src != NULL);
    CHECK_PARAM(dst != NULL);

    if (!*dst) {
        ASN_ALLOC(*dst);
    }

    DO(ba_to_uint8_with_alloc(src, &buf, &buf_len));
    DO(asn_bytes2OCTSTRING(*dst, buf, buf_len));

cleanup:

    free(buf);

    return ret;
}

int asn_set_any(const asn_TYPE_descriptor_t *src_type, const void *src, ANY_t *dst)
{
    int ret = RET_OK;
    ANY_t *dst_copy = NULL;

    CHECK_PARAM(src != NULL);
    CHECK_PARAM(dst != NULL);
    CHECK_PARAM(src_type != NULL);

    dst_copy = ANY_new_fromType((asn_TYPE_descriptor_t *)src_type, (void *)src);
    CHECK_NOT_NULL(dst_copy);

    DO(asn_copy(get_ANY_desc(), dst_copy, dst));

cleanup:

    ASN_FREE(get_ANY_desc(), dst_copy);

    return ret;
}

void *asn_any2type(const ANY_t *src, asn_TYPE_descriptor_t *dst_type)
{
    int ret = RET_OK;
    void *dst = NULL;

    CHECK_PARAM(src != NULL);
    CHECK_PARAM(dst_type != NULL);

    DO(ANY_to_type(src, dst_type, &dst));

cleanup:

    return dst;
}

int asn_create_any(const asn_TYPE_descriptor_t *src_type, const void *src, ANY_t **dst)
{
    int ret = RET_OK;

    CHECK_PARAM(src != NULL);
    CHECK_PARAM(dst != NULL);
    CHECK_PARAM(src_type != NULL);

    ASN_ALLOC(*dst);
    DO(asn_set_any(src_type, src, *dst));

cleanup:

    return ret;
}

int asn_create_integer(const void *src, const size_t len, INTEGER_t **dst)
{
    int ret = RET_OK;

    CHECK_PARAM(src != NULL);
    CHECK_PARAM(dst != NULL);

    if (!*dst) {
        ASN_ALLOC(*dst);
    }
    DO(asn_bytes2INTEGER(*dst, src, len));

cleanup:

    return ret;
}

int asn_create_integer_from_ba(const ByteArray *src, INTEGER_t **dst)
{
    int ret = RET_OK;

    CHECK_PARAM(src != NULL);
    CHECK_PARAM(dst != NULL);

    if (!*dst) {
        ASN_ALLOC(*dst);
    }

    DO(asn_ba2INTEGER(src, *dst));

cleanup:

    return ret;
}

int asn_create_bitstring(const void *src, const size_t len, BIT_STRING_t **dst)
{
    int ret = RET_OK;

    CHECK_PARAM(src != NULL);
    CHECK_PARAM(dst != NULL);

    if (!*dst) {
        ASN_ALLOC(*dst);
    }
    DO(asn_bytes2BITSTRING(src, *dst, len));

cleanup:

    return ret;
}

int asn_set_bitstring_from_ba(const ByteArray *src, BIT_STRING_t *dst)
{
    uint8_t *buf = NULL;
    size_t buf_len;
    int ret = RET_OK;

    CHECK_PARAM(src != NULL);
    CHECK_PARAM(dst != NULL);

    DO(ba_to_uint8_with_alloc(src, &buf, &buf_len));
    DO(asn_bytes2BITSTRING(ba_get_buf_const(src), dst, ba_get_len(src)));

cleanup:

    free(buf);

    return ret;
}

int asn_create_bitstring_from_ba(const ByteArray *src, BIT_STRING_t **dst)
{
    uint8_t *buf = NULL;
    size_t buf_len;
    int ret = RET_OK;

    CHECK_PARAM(src != NULL);
    CHECK_PARAM(dst != NULL);

    if (!*dst) {
        ASN_ALLOC(*dst);
    }

    DO(ba_to_uint8_with_alloc(src, &buf, &buf_len));
    DO(asn_bytes2BITSTRING(buf, *dst, buf_len));

cleanup:

    free(buf);

    return ret;
}

int asn_create_integer_from_long(long src, INTEGER_t **dst)
{
    int ret = RET_OK;

    CHECK_PARAM(dst != NULL);

    if (!*dst) {
        ASN_ALLOC(*dst);
    }
    DO(asn_long2INTEGER(*dst, src));
cleanup:
    return ret;
}

int asn_create_bitstring_from_octstring(const OCTET_STRING_t *src, BIT_STRING_t **dst)
{
    uint8_t *buf = NULL;
    size_t buf_len;
    int ret = RET_OK;
    BIT_STRING_t *bit_str = NULL;

    CHECK_PARAM(dst != NULL);
    CHECK_PARAM(src != NULL);

    if (!bit_str) {
        ASN_ALLOC(bit_str);
    }

    DO(asn_encode(get_OCTET_STRING_desc(), src, &buf, &buf_len));
    DO(asn_bytes2BITSTRING(buf, bit_str, buf_len));
    *dst = bit_str;
    bit_str = NULL;

cleanup:

    free(buf);
    ASN_FREE(get_OCTET_STRING_desc(), bit_str);

    return ret;
}

int asn_create_bitstring_from_integer(const INTEGER_t *src, BIT_STRING_t **dst)
{
    int ret = RET_OK;
    uint8_t *buf = NULL;
    size_t buf_len;

    CHECK_PARAM(dst != NULL);
    CHECK_PARAM(src != NULL);

    if (!*dst) {
        ASN_ALLOC(*dst);
    }

    DO(asn_encode(get_INTEGER_desc(), src, &buf, &buf_len));
    DO(asn_bytes2BITSTRING(buf, *dst, buf_len));

cleanup:

    free(buf);
    if (ret != RET_OK) {
        ASN_FREE(get_BIT_STRING_desc(), *dst);
        *dst = NULL;
    }

    return ret;
}

int asn_get_oid_arcs(const OBJECT_IDENTIFIER_t *oid, long **arcs, size_t *size)
{
    int arc_type_size = sizeof(long);
    unsigned int arc_slots = 1;
    int count;
    int ret = RET_OK;

    CHECK_PARAM(oid != NULL);
    CHECK_PARAM(arcs != NULL);
    CHECK_PARAM(size != NULL);

    CALLOC_CHECKED(*arcs, (size_t)arc_type_size * arc_slots);
    count = OBJECT_IDENTIFIER_get_arcs(oid, *arcs, arc_type_size, arc_slots);

    if (count > (int)arc_slots) {
        arc_slots = count;
        free(*arcs);
        *arcs = NULL;
        CALLOC_CHECKED(*arcs, (size_t)arc_type_size * arc_slots);
        count = OBJECT_IDENTIFIER_get_arcs(oid, *arcs, arc_type_size, arc_slots);

        if (count <= 0 || count != (int)arc_slots) {
            free(*arcs);
            *arcs = NULL;
            SET_ERROR(RET_ASN1_ERROR);
        }
    } else {
        if (count <= 0) {
            free(*arcs);
            *arcs = NULL;
            SET_ERROR(RET_ASN1_ERROR);
        }
    }

    *size = arc_slots;

cleanup:

    return ret;
}

/**
 * Проверяет вхождение заданного OID`а в другой (родительский) OID.
 *
 * @param oid         проверяемый OID
 * @param parent_arcs int-представление родительского OID`а
 * @param parent_size размер родительского OID`а
 *
 * @return true  - OID входит в родительский
 *         false - OID не входит в родительский
 */
bool asn_check_oid_parent(const OBJECT_IDENTIFIER_t *oid, const long *parent_arcs, size_t parent_size)
{
    long *arcs = NULL;
    size_t size;
    int ret = RET_OK;

    CHECK_PARAM(oid != NULL);
    CHECK_PARAM(parent_arcs != NULL);

    DO(asn_get_oid_arcs(oid, &arcs, &size));

    if (size < parent_size) {
        ret = -1;
        goto cleanup;
    }

    ret = memcmp((void *)arcs, (void *)parent_arcs, sizeof(long) * parent_size);

cleanup:

    free(arcs);

    return ret == 0;
}

/**
 * Сравнивает два OID.
 *
 * @param oid         OID
 * @param parent_arcs указатель на буфер для int`ов
 * @param parent_size указатель на размер буфера для int`ов
 *
 * @return равны ли oid и parent_arcs
 */
bool asn_check_oid_equal(const OBJECT_IDENTIFIER_t *oid, const long *parent_arcs, size_t parent_size)
{
    int ret = RET_OK;
    size_t size;
    long *arcs = NULL;

    CHECK_PARAM(oid != NULL);
    CHECK_PARAM(parent_arcs != NULL);

    DO(asn_get_oid_arcs(oid, &arcs, &size));

    ret = (int)(size - parent_size);
    if (ret) {
        goto cleanup;
    }

    ret = memcmp((void *)arcs, (void *)parent_arcs, sizeof(long) * parent_size);

cleanup:

    free(arcs);

    return ret == 0;
}

/**
 * Возврощает содержимое структуры OCTET STRING.
 * Выделяемая память требует освобождения.
 *
 * @param octet     указатель на объект
 * @param bytes     указатель буфер содержащий содержимое структуры.
 * @param bytes_len размер буфера
 *
 * @return код ошибки
 */
int asn_OCTSTRING2bytes(const OCTET_STRING_t *octet, unsigned char **bytes, size_t *bytes_len)
{
    int ret = RET_OK;

    CHECK_PARAM(octet != NULL);
    CHECK_PARAM(bytes != NULL);
    CHECK_PARAM(bytes_len != NULL);

    MALLOC_CHECKED(*bytes, octet->size);
    memcpy(*bytes, octet->buf, octet->size);
    *bytes_len = octet->size;

cleanup:

    return ret;
}

/**
 * Устанвливает содержимое структуры OCTET STRING.
 * Выделяемая память требует освобождения.
 *
 * @param octet     указатель на объект
 * @param bytes     указатель буфер с данными.
 * @param bytes_len размер буфера
 *
 * @return код ошибки
 */
int asn_bytes2OCTSTRING(OCTET_STRING_t *octet, const unsigned char *bytes, size_t bytes_len)
{
    int ret = RET_OK;

    CHECK_PARAM(octet != NULL);
    CHECK_PARAM(bytes != NULL);

    REALLOC_CHECKED(octet->buf, bytes_len, octet->buf);
    memcpy(octet->buf, bytes, bytes_len);
    octet->size = (int)bytes_len;

cleanup:

    return ret;
}

/**
 * Возврощает содержимое структуры INTEGER.
 * Выделяемая память требует освобождения.
 *
 * @param integer   указатель на объект
 * @param bytes     указатель буфер содержащий содержимое структуры.
 * @param bytes_len размер буфера
 *
 * @return код ошибки
 */
int asn_INTEGER2bytes(const INTEGER_t *integer, unsigned char **bytes, size_t *bytes_len)
{
    int ret = RET_OK;

    CHECK_PARAM(integer != NULL);
    CHECK_PARAM(bytes != NULL);
    CHECK_PARAM(bytes_len != NULL);

    MALLOC_CHECKED(*bytes , integer->size);
    memcpy(*bytes, integer->buf, integer->size);
    *bytes_len = integer->size;

cleanup:

    return ret;
}

/**
 * Устанвливает содержимое структуры INTEGER.
 * Выделяемая память требует освобождения.
 *
 * @param integer   указатель на объект
 * @param bytes     указатель буфер с данными.
 * @param bytes_len размер буфера
 *
 * @return код ошибки
 */
int asn_bytes2INTEGER(INTEGER_t *integer, const unsigned char *value, size_t len)
{
    uint8_t *buf, *bp;
    uint8_t *p;
    uint8_t *pstart;
    uint8_t *pend1;
    int ret = RET_OK;

    CHECK_PARAM(integer != NULL);
    CHECK_PARAM(value != NULL);

    MALLOC_CHECKED(buf, len);

    pstart = (uint8_t *)value;
    pend1 = pstart + len - 1;

    /*
     * If the contents octet consists of more than one octet,
     * then bits of the first octet and bit 8 of the second octet:
     * a) shall not all be ones; and
     * b) shall not all be zero.
     */
    for (p = pstart; p != pend1; p++) {
        switch (*p) {
        case 0x00:
            if ((*(p + 1) & 0x80) == 0) {
                continue;
            }

            break;

        case 0xff:
            if ((*(p + 1) & 0x80)) {
                continue;
            }

            break;
        }

        break;
    }

    /* Copy the integer body */
    for (pstart = p, bp = buf, pend1++; p != pend1; p++) {
        * bp++ = *p;
    }

    if (integer->buf) {
        free(integer->buf);
    }

    integer->buf = buf;
    integer->size = (int)(bp - buf);

cleanup:

    return ret;
}

/**
 * Устанвливает содержимое структуры INTEGER.
 * Выделяемая память требует освобождения.
 *
 * @param integer   указатель на объект
 * @param bytes     указатель буфер с данными.
 *
 * @return код ошибки
 */
int asn_ba2INTEGER(const ByteArray *value, INTEGER_t *integer)
{
    int ret = RET_OK;
    ByteArray *ba_tmp = NULL;
    size_t len, i = 0;
    const uint8_t *buf;

    CHECK_PARAM(value);
    CHECK_PARAM(integer);

    len = ba_get_len(value);
    buf = ba_get_buf_const(value);

    if ((len > 0) && (buf[0] > 127)) {
        uint8_t *tmp_buf;
        CHECK_NOT_NULL(ba_tmp = ba_alloc_by_len(len + 1));
        tmp_buf = ba_get_buf(ba_tmp);
        tmp_buf[0] = 0;
        memcpy(tmp_buf + 1, buf, len);
        DO(asn_bytes2INTEGER(integer, tmp_buf, len + 1));
    }
    else {
        if (len > 1) {
            for (; i < len - 1; i++) {
                if ((buf[i] != 0) || (buf[i + 1] > 127)) {
                    break;
                }
            }
        }

        DO(asn_bytes2INTEGER(integer, buf + i, len - i));
    }

cleanup:
    ba_free(ba_tmp);
    return ret;
}

/**
 * Возврощает содержимое структуры BITSTRING.
 * Выделяемая память требует освобождения.
 *
 * @param string    указатель на объект
 * @param bytes     указатель буфер содержащий содержимое структуры.
 * @param bytes_len размер буфера
 *
 * @return код ошибки
 */
int asn_BITSTRING2bytes(const BIT_STRING_t *string, unsigned char **bytes, size_t *bytes_len)
{
    int ret = RET_OK;

    CHECK_PARAM(string != NULL);
    CHECK_PARAM(bytes != NULL);
    CHECK_PARAM(bytes_len != NULL);

    MALLOC_CHECKED(*bytes, string->size);

    memcpy(*bytes, string->buf, string->size);

    *bytes_len = string->size;
cleanup:
    return ret;
}

int asn_BITSTRING2ba(const BIT_STRING_t *string, ByteArray **ba)
{
    int ret = RET_OK;

    CHECK_PARAM(string != NULL);
    CHECK_PARAM(ba != NULL);

    CHECK_NOT_NULL(*ba = ba_alloc_from_uint8(string->buf, string->size));

cleanup:
    return ret;
}

/**
 * Устанвливает содержимое структуры BITSTRING.
 * Выделяемая память требует освобождения.
 *
 * @param string    указатель на объект
 * @param bytes     указатель буфер с данными.
 * @param bytes_len размер буфера
 *
 * @return код ошибки
 */
int asn_bytes2BITSTRING(const unsigned char *bytes, BIT_STRING_t *string, size_t bytes_len)
{
    int ret = RET_OK;

    CHECK_PARAM(string != NULL);
    CHECK_PARAM(bytes != NULL);

    REALLOC_CHECKED(string->buf, bytes_len, string->buf);

    memcpy(string->buf, bytes, bytes_len);
    string->size = (int)bytes_len;

cleanup:
    return ret;
}

/**
 * Устанвливает содержимое структуры BITSTRING.
 * Выделяемая память требует освобождения.
 *
 * @param string    указатель на объект
 * @param bytes     указатель буфер с данными.
 * @param bytes_len размер буфера
 *
 * @return код ошибки
 */
int asn_BITSTRING_get_bit(const BIT_STRING_t *string, int bit_num, int *bit_value)
{
    int ret = RET_OK;

    CHECK_PARAM(string != NULL);
    CHECK_PARAM(bit_value != NULL);

    if (bit_num > string->size * 8 - string->bits_unused - 1) {
        *bit_value = 0;
        return RET_OK;
    }

    *bit_value = (string->buf[bit_num / 8] & (0x80 >> (bit_num % 8))) ? 1 : 0;
cleanup:
    return ret;
}

int asn_OCTSTRING2ba(const OCTET_STRING_t *os, ByteArray **ba)
{
    int ret = RET_OK;

    CHECK_PARAM(os != NULL);
    CHECK_PARAM(ba != NULL);

    CHECK_NOT_NULL(*ba = ba_alloc_from_uint8(os->buf, os->size));
cleanup:
    return ret;
}

int asn_INTEGER2ba(const INTEGER_t *in, ByteArray **ba)
{
    int ret = RET_OK;
    int i;

    CHECK_PARAM(in != NULL);
    CHECK_PARAM(ba != NULL);

    for (i = 0; (i < in->size) && (in->buf[i] == 0); i++);

    *ba = ba_alloc_from_uint8(in->buf + i, (size_t)in->size - i);

cleanup:

    return ret;
}

int asn_ba2BITSTRING(const ByteArray *ba, BIT_STRING_t *bit_string)
{
    const uint8_t *buf;
    int ret = RET_OK;
    size_t buf_len;

    CHECK_PARAM(bit_string != NULL);
    CHECK_PARAM(ba != NULL);

    buf = ba_get_buf_const(ba);
    buf_len = ba_get_len(ba);
    DO(asn_bytes2BITSTRING(buf, bit_string, buf_len));

cleanup:

    return ret;
}

int asn_ba2OCTSTRING(const ByteArray *ba, OCTET_STRING_t *octet)
{
    const uint8_t *buf;
    int ret = RET_OK;
    size_t buf_len;

    CHECK_PARAM(octet != NULL);
    CHECK_PARAM(ba != NULL);

    buf = ba_get_buf_const(ba);
    buf_len = ba_get_len(ba);
    DO(asn_bytes2OCTSTRING(octet, buf, buf_len));

cleanup:

    return ret;
}

/** Преобразует OCTERT_STRING в объект указанного типа. */
int asn_OCTSTRING_to_type(const OCTET_STRING_t *src, asn_TYPE_descriptor_t *type, void **dst)
{
    uint8_t *buffer = NULL;
    int ret = RET_OK;
    size_t len;

    CHECK_PARAM(src != NULL);
    CHECK_PARAM(type != NULL);
    CHECK_PARAM(dst != NULL);

    DO(asn_OCTSTRING2bytes(src, &buffer, &len));

    *dst = asn_decode_with_alloc(type, buffer, len);
    CHECK_NOT_NULL(*dst);

cleanup:

    free(buffer);
    return ret;
}

UTCTime_t *asn_create_curent_time(void)
{
    time_t cur_time = time(NULL);
    struct tm tm_cur_time = *localtime(&cur_time);

    return asn_time2UT(NULL, &tm_cur_time, true);
}

int asn_print(FILE *stream, asn_TYPE_descriptor_t *td, void *sptr)
{
    int ret = RET_OK;

    CHECK_PARAM(td);
    CHECK_PARAM(sptr);

    DO(xer_fprint(stream, td, sptr));

cleanup:

    return ret;
}

void asn_free(asn_TYPE_descriptor_t *td, void *ptr)
{
    if (td != NULL && ptr != NULL) {
        td->free_struct(td, ptr, 0);
    }
}


//  source from "asn_utils_x.h"
static int generalized_time_diff_init = 0;
static time_t generalized_time_diff = 0;

static void fix_generalized_time(void)
{
    uint8_t encoded[] = { 0x18, 0x0F, 0x32, 0x30, 0x31, 0x37, 0x30, 0x32, 0x30, 0x37, 0x30, 0x39, 0x32, 0x31, 0x35, 0x31, 0x5A };
    int frac_value;
    int frac_digits;
    GeneralizedTime_t* actual = NULL;
    time_t time_sec = 0;
    time_t time_sec_exp = 1486459311;
    int ret;

    CHECK_NOT_NULL(actual = asn_decode_with_alloc(get_GeneralizedTime_desc(), encoded, sizeof(encoded)));
    time_sec = asn_GT2time_frac(actual, &frac_value, &frac_digits, NULL, false);
    if (time_sec == -1) {
        //error
        goto cleanup;
    }

    generalized_time_diff = time_sec_exp - time_sec;

cleanup:

    ASN_FREE(get_GeneralizedTime_desc(), actual);

    return;
}

static time_t time_t_fix(time_t in)
{
    if (generalized_time_diff_init == 0) {
        fix_generalized_time();
        generalized_time_diff_init = 1;
    }

    return generalized_time_diff + in;
}

static uint64_t pow10_uint64(int frac_digits)
{
    uint64_t fbase;
    for (fbase = 1; frac_digits--;) {
            fbase *= 10;
    }
    return fbase;
}

uint64_t asn_GT2msec(const GeneralizedTime_t *st, struct tm *ret_tm, int as_gmt)
{
    int frac_value;
    int frac_digits;
    time_t time_sec;
    uint64_t time_msec;

    time_sec = time_t_fix(asn_GT2time_frac(st, &frac_value, &frac_digits, ret_tm, as_gmt));
    if (time_sec != -1) {
        time_msec = ((uint64_t)time_sec) * 1000 + (uint64_t)frac_value * pow10_uint64(3 - frac_digits);
    } else {
        time_msec = (uint64_t)-1;
    }

    return time_msec;
}

uint64_t asn_UT2msec(const UTCTime_t* st, struct tm* ret_tm, int as_gmt)
{
    time_t time_sec;
    uint64_t time_msec;

    (void)as_gmt;

    time_sec = time_t_fix(asn_UT2time(st, ret_tm, false));
    if (time_sec != -1) {
        time_msec = ((uint64_t)time_sec) * 1000;
    }
    else {
        time_msec = (uint64_t)-1;
    }
    return time_msec;
}


int asn_msec2GT(const uint64_t msec, GeneralizedTime_t **out)
{
    int ret = RET_OK;
    GeneralizedTime_t *generalTime = NULL;
    time_t utc_time = msec / 1000;

    CHECK_PARAM(out != NULL);

    const struct tm *st_tm = localtime(&utc_time);
    if (st_tm == NULL) {
        SET_ERROR(RET_ASN1_TIME_ERROR);
    }

    generalTime = asn_time2GT(NULL, st_tm, true);

    *out = generalTime;
    generalTime = NULL;

cleanup:

    asn_free(get_GeneralizedTime_desc(), generalTime);

    return ret;
}

int asn_msec2UT(const uint64_t msec, UTCTime_t **out)
{
    int ret = RET_OK;
    UTCTime_t *utc_time_asn = NULL;
    time_t utc_time = msec / 1000;

    CHECK_PARAM(out != NULL);

    const struct tm *st_tm = localtime(&utc_time);
    if (st_tm == NULL) {
        SET_ERROR(RET_ASN1_TIME_ERROR);
    }

    utc_time_asn = asn_time2UT(NULL, st_tm, true);

    *out = utc_time_asn;
    utc_time_asn = NULL;

cleanup:

    asn_free(get_UTCTime_desc(), utc_time_asn);

    return ret;
}

