/*
 * Copyright (c) 2023, The UAPKI Project Authors.
 * Copyright 2016 PrivatBank IT <acsk@privatbank.ua>
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

#ifndef SRC_ASN1_UTILS_H_
#define SRC_ASN1_UTILS_H_

#include <stdbool.h>
#include <stdint.h>

#include "byte-array.h"
#include "asn1-errors.h"
#include "asn1-module.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Виділяє пам'ять для asn-структури.
 */
#define ASN_ALLOC(obj) ((obj) = calloc(1, sizeof(*(obj))));                                    \
    if ((obj) == NULL) { ret = RET_MEMORY_ALLOC_ERROR;                                         \
                         ERROR_CREATE(ret);                                                    \
                         goto cleanup; }

#define    ASN_FREE(asn_DEF, ptr)                (asn_DEF)->free_struct(asn_DEF, ptr, 0)
#define    ASN_FREE_CONTENT_PTR(asn_DEF, ptr)    { if (ptr != NULL) {(asn_DEF)->free_struct(asn_DEF,ptr,1); memset(ptr, 0, sizeof *ptr);}}
#define    ASN_FREE_CONTENT_STATIC(asn_DEF, ptr) { (asn_DEF)->free_struct(asn_DEF,ptr,1); memset(ptr, 0, sizeof *ptr); }

/**
 * Повертає байтове подання об'єкта в DER-кодуванні.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param desc       дескриптор об'єкта
 * @param object     вказівник на об'єкт
 * @param encode     вказівник на виділену пам'ять, що містить DER-подання.
 * @param encode_len фактичний розмір даних
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_encode(asn_TYPE_descriptor_t *desc, const void *object,
        uint8_t **encode, size_t *encode_len);

UAPKIF_EXPORT int asn_encode_ba(asn_TYPE_descriptor_t *desc, const void *object, ByteArray **encoded);

/**
 * Ініціалізує asn-структуру об'єкта з байтового подання.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param desc        дескриптор об'єкта
 * @param object      вказівник на об'єкт
 * @param encode      вказівник на буфер, що містить BER-подання структури.
 * @param encode_len  розмір буфера
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_decode(asn_TYPE_descriptor_t *desc, void *object, const void *encode, size_t encode_len);

UAPKIF_EXPORT int asn_decode_ba(asn_TYPE_descriptor_t *desc, void *object,
        const ByteArray *encode);

UAPKIF_EXPORT void *asn_decode_with_alloc(asn_TYPE_descriptor_t *desc, const void *encode, size_t encode_len);

UAPKIF_EXPORT void *asn_decode_ba_with_alloc(asn_TYPE_descriptor_t *desc, const ByteArray *encoded);

/**
 * Створює копію ASN.1-об'єкта заданого типу.
 *
 * @param type тип об'єкта
 * @param src  джерело
 * @param dst  приймач
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_copy(asn_TYPE_descriptor_t *type, const void *src, void *dst);

/**
* Створює копію ASN.1-об'єкта заданого типу.
* Виділена пам'ять потребує вивільнення.
*
* @param type тип об'єкта
* @param src  джерело
*
* @return копія ASN.1-об'єкта заданого типу.
*/
UAPKIF_EXPORT void *asn_copy_with_alloc(asn_TYPE_descriptor_t *type, const void *src);

/**
 * Порівнює дві ASN.1-структури.
 *
 * @param type тип об'єкта
 * @param a    структура для порівняння
 * @param b    структура для порівняння
 *
 * @return чи рівні a і b
 */
UAPKIF_EXPORT bool asn_equals(asn_TYPE_descriptor_t *type, const void *a, const void *b);

UAPKIF_EXPORT int asn_parse_args_oid(const char *text, long **arcs, size_t *size);

/**
 * Повертає OID за текстовим поданням.
 * (*oid == NULL) - пам'ять під відповідь виділяється і потребує подальшого вивільнення.
 * (*oid != NULL) - якщо пам'ять під об'єкт, що повертається, вже виділена.
 *
 * @param text  рядок з OID
 * @param dst  OID
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_create_oid_from_text(const char *text, OBJECT_IDENTIFIER_t **dst);

/**
 * Встановлює OID за текстовим поданням.
 *
 * @param text  рядок з OID
 * @param dst  OID
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_set_oid_from_text(const char* text, OBJECT_IDENTIFIER_t * dst);

/**
 * Створює текстове подання OID.
 *
 * @param dst  OID
 * @param text  рядок з OID
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_oid_to_text(const OBJECT_IDENTIFIER_t* dst, char** text);

#define ASN_OID_TEXT_MAX 256

/* Returns the text length, or -1 to fall back to asn_oid_to_text. */
UAPKIF_EXPORT int asn_oid_to_text_buf(const OBJECT_IDENTIFIER_t* oid, char* buf, size_t size);

/**
 * Повертає OID за int-поданням.
 * (*oid == NULL) - пам'ять під відповідь виділяється і потребує подальшого вивільнення.
 * (*oid != NULL) - якщо пам'ять під об'єкт, що повертається, вже виділена.
 *
 * @param src  вказівник на буфер для int-ів
 * @param size розмір буфера для int-ів
 * @param dst  OID
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_create_oid(const long *src, const size_t size, OBJECT_IDENTIFIER_t **dst);

/**
 * Встановлює OID за int-поданням.
 *
 * @param src  вказівник на буфер для int-ів
 * @param size розмір буфера для int-ів
 * @param dst  OID
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_set_oid(const long *src, const size_t size, OBJECT_IDENTIFIER_t *dst);

/**
 * Створює OCTET_STRING_t з масиву байтів.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param src масив байтів
 * @param len розмір вхідного буфера
 * @param dst OCTET_STRING_t
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_create_octstring(const void *src, const size_t len, OCTET_STRING_t **dst);

/**
 * Створює OCTET_STRING_t з масиву байтів.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param src масив байтів
 * @param dst OCTET_STRING_t
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_create_octstring_from_ba(const ByteArray *src, OCTET_STRING_t **dst);

/**
 * Створює BIT_STRING_t з масиву байтів.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param src масив байтів
 * @param len розмір вхідного буфера
 * @param dst створюваний BIT_STRING_t
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_create_bitstring(const void *src, const size_t len, BIT_STRING_t **dst);

/**
 * Створює BIT_STRING_t з масиву байтів.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param src масив байтів
 * @param dst створюваний BIT_STRING_t
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_create_bitstring_from_ba(const ByteArray *src, BIT_STRING_t **dst);

UAPKIF_EXPORT int asn_set_bitstring_from_ba(const ByteArray *src, BIT_STRING_t *dst);
/**
 * Створює INTEGER_t з байтового подання цілого числа.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param src байтове подання цілого числа
 * @param len розмір вхідного буфера
 * @param dst створюваний INTEGER_t
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_create_integer(const void *src, const size_t len, INTEGER_t **dst);

UAPKIF_EXPORT int asn_create_integer_from_ba(const ByteArray *src, INTEGER_t **dst);

UAPKIF_EXPORT void *asn_any2type(const ANY_t *src, asn_TYPE_descriptor_t *dst_type);

/**
 * Створює ANY_t з довільного ASN.1-об'єкта.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param src_type тип вхідної структури
 * @param src ASN.1-об'єкт
 * @param dst створюваний ANY_t
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_create_any(const asn_TYPE_descriptor_t *src_type, const void *src, ANY_t **dst);

/**
 * Встановлює ANY_t з довільного ASN.1-об'єкта.
 *
 * @param src_type тип вхідної структури
 * @param src ASN.1-об'єкт
 * @param dst створюваний ANY_t
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_set_any(const asn_TYPE_descriptor_t *src_type, const void *src, ANY_t *dst);

/**
 * Створює INTEGER_t з long-подання цілого числа.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param src long-подання цілого числа
 * @param dst створюваний INTEGER_t
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_create_integer_from_long(long src, INTEGER_t **dst);

/**
 * Створює BIT_STRING_t, що містить заданий OCTET_STRING_t.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param src вхідні дані
 * @param dst створюваний BIT_STRING_t
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_create_bitstring_from_octstring(const OCTET_STRING_t *src, BIT_STRING_t **dst);

/**
 * Створює BIT_STRING_t, що містить заданий INTEGER_t.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param src вхідні дані
 * @param dst створюваний BIT_STRING_t
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_create_bitstring_from_integer(const INTEGER_t *src, BIT_STRING_t **dst);

/**
 * Повертає масив int-ів, що подають OID.
 *
 * @param oid  OID
 * @param arcs вказівник на буфер для int-ів
 * @param size вказівник на розмір буфера для int-ів
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_get_oid_arcs(const OBJECT_IDENTIFIER_t *oid, long **arcs, size_t *size);

/**
 * Перевіряє входження заданого OID в інший (батьківський) OID.
 *
 * @param oid         OID, що перевіряється
 * @param parent_arcs int-подання батьківського OID
 * @param parent_size розмір батьківського OID
 *
 * @return true  - OID входить до батьківського
 *         false - OID не входить до батьківського
 */
UAPKIF_EXPORT bool asn_check_oid_parent(const OBJECT_IDENTIFIER_t *oid, const long *parent_arcs, size_t parent_size);

/**
 * Порівнює два OID.
 *
 * @param oid         OID
 * @param parent_arcs вказівник на буфер для int-ів
 * @param parent_size вказівник на розмір буфера для int-ів
 *
 * @return чи рівні oid і parent_arcs
 */
UAPKIF_EXPORT bool asn_check_oid_equal(const OBJECT_IDENTIFIER_t *oid, const long *parent_arcs, size_t parent_size);

/**
 * Повертає вміст структури OCTET STRING.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param octet      вказівник на об'єкт
 * @param bytes      вказівник на буфер, що містить вміст структури.
 * @param bytes_len  розмір буфера
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_OCTSTRING2bytes(const OCTET_STRING_t *octet, unsigned char **bytes, size_t *bytes_len);

/**
 * Встановлює вміст структури OCTET STRING.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param octet      вказівник на об'єкт
 * @param bytes      вказівник на буфер з даними.
 * @param bytes_len  розмір буфера
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_bytes2OCTSTRING(OCTET_STRING_t *octet, const unsigned char *bytes, size_t bytes_len);

/**
 * Повертає вміст структури INTEGER.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param integer    вказівник на об'єкт
 * @param bytes      вказівник на буфер, що містить вміст структури.
 * @param bytes_len  розмір буфера
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_INTEGER2bytes(const INTEGER_t *integer, unsigned char **bytes, size_t *bytes_len);

/**
 * Встановлює вміст структури INTEGER.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param integer    вказівник на об'єкт
 * @param value      вказівник на буфер з даними.
 * @param len        розмір буфера
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_bytes2INTEGER(INTEGER_t *integer, const unsigned char *value, size_t len);

/**
 * Встановлює вміст структури INTEGER.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param value     масив байтів з даними.
 * @param integer   вказівник на об'єкт
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_ba2INTEGER(const ByteArray *value, INTEGER_t *integer);

/**
 * Повертає вміст структури BITSTRING.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param string    вказівник на об'єкт
 * @param bytes     вказівник на буфер, що містить вміст структури.
 * @param bytes_len розмір буфера
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_BITSTRING2bytes(const BIT_STRING_t *string, unsigned char **bytes, size_t *bytes_len);

/**
 * Встановлює вміст структури BITSTRING.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param bytes     вказівник на буфер з даними.
 * @param string    вказівник на об'єкт
 * @param bytes_len розмір буфера
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_bytes2BITSTRING(const unsigned char *bytes, BIT_STRING_t *string, size_t bytes_len);

/**
 * Повертає значення біта структури BITSTRING із заданим номером.
 * Біти нумеруються від старшого біта першого байта; для номера за межами рядка повертається 0.
 *
 * @param string    вказівник на об'єкт
 * @param bit_num   номер біта
 * @param bit_value значення біта (0 або 1)
 *
 * @return код помилки
 */
UAPKIF_EXPORT int asn_BITSTRING_get_bit(const BIT_STRING_t *string, int bit_num, int *bit_value);

UAPKIF_EXPORT int asn_OCTSTRING2ba(const OCTET_STRING_t *os, ByteArray **ba);
UAPKIF_EXPORT int asn_ba2OCTSTRING(const ByteArray *ba, OCTET_STRING_t *octet);
UAPKIF_EXPORT int asn_ba2BITSTRING(const ByteArray *ba, BIT_STRING_t *bit_string);
UAPKIF_EXPORT int asn_INTEGER2ba(const INTEGER_t *in, ByteArray **ba);

UAPKIF_EXPORT int asn_BITSTRING2ba(const BIT_STRING_t *string, ByteArray **ba);

/** Перетворює OCTET_STRING на об'єкт зазначеного типу. */
UAPKIF_EXPORT int asn_OCTSTRING_to_type(const OCTET_STRING_t *src, asn_TYPE_descriptor_t *type, void **dst);

UAPKIF_EXPORT int asn_print(FILE *stream, asn_TYPE_descriptor_t *td, void *sptr);
UAPKIF_EXPORT void asn_free(asn_TYPE_descriptor_t *td, void *ptr);

UAPKIF_EXPORT void uapkif_free(void* ptr);

//  From "asn_utils_x.h" and "[asn1]", redesigned
struct tm;    /* <time.h> */

UAPKIF_EXPORT bool asn_check_tm (struct tm* tmData);
UAPKIF_EXPORT uint64_t asn_tm2msec (struct tm* tmData, const int ms);
UAPKIF_EXPORT uint64_t asn_UT2time (const UTCTime_t* st, struct tm* tmData);
UAPKIF_EXPORT uint64_t asn_GT2time (const GeneralizedTime_t* st, struct tm* tmData);
UAPKIF_EXPORT bool asn_msecToTm (struct tm* tmData, const uint64_t msTime, const bool isLocal);
UAPKIF_EXPORT int asn_time2UT (UTCTime_t* st, const uint64_t msTime, const struct tm* tmData);
UAPKIF_EXPORT int asn_time2GT (GeneralizedTime_t* st, const uint64_t msTime, const struct tm* tmData);

#ifdef __cplusplus
}
#endif

#endif
