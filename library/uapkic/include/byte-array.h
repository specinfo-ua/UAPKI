/*
 * Copyright 2021 The UAPKI Project Authors.
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

#ifndef UAPKIC_BYTE_ARRAY_H
#define UAPKIC_BYTE_ARRAY_H

#include <stdint.h>
#include <stdio.h>
#include "uapkic-export.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Контекст масиву байтів.
 */
typedef struct ByteArray_st ByteArray;

/**
 * Створює контекст масиву байтів.
 *
 * @return контекст масиву байтів
 */
UAPKIC_EXPORT ByteArray* ba_alloc(void);

/**
 * Створює контекст масиву байтів.
 *
 * @param len розмір масиву байтів
 * @return контекст масиву байтів
 */
UAPKIC_EXPORT ByteArray* ba_alloc_by_len(size_t len);

/**
 * Створює контекст масиву байтів.
 *
 * @param buf масив байтів
 * @param buf_len розмір масиву байтів
 * @return контекст масиву байтів
 */
UAPKIC_EXPORT ByteArray* ba_alloc_from_uint8(const uint8_t* buf, size_t buf_len);

/**
 * Створює контекст масиву байтів.
 *
 * @param str дані в шістнадцятковому кодуванні
 * @return контекст масиву байтів
 */
UAPKIC_EXPORT ByteArray* ba_alloc_from_hex(const char* str);

/**
 * Створює контекст масиву байтів.
 *
 * @param str дані в кодуванні Base64
 * @return контекст масиву байтів
 */
UAPKIC_EXPORT ByteArray* ba_alloc_from_base64(const char* str);

/**
 * Створює контекст масиву байтів.
 *
 * @param str рядок
 * @return контекст масиву байтів
 */
UAPKIC_EXPORT ByteArray* ba_alloc_from_str(const char* str);

UAPKIC_EXPORT ByteArray* ba_copy_with_alloc(const ByteArray* in, size_t off, size_t len);

/**
 * Записує дані в наявний контекст масиву байтів.
 *
 * @param buf масив байтів
 * @param buf_len розмір масиву байтів
 * @param ba контекст масиву байтів
 * @return код помилки
 */
UAPKIC_EXPORT int ba_from_uint8(const uint8_t* buf, size_t buf_len, ByteArray* ba);

/**
 * Створює контекст масиву байтів.
 *
 * @param str дані в шістнадцятковому кодуванні
 * @param ba контекст масиву байтів
 * @return код помилки
 */
UAPKIC_EXPORT int ba_from_hex(const char* str, ByteArray* ba);

UAPKIC_EXPORT int ba_from_base64(const char* str, ByteArray* ba);

/**
 * Повертає дані, які зберігає контекст масиву байтів.
 * Не виділяє пам’ять.
 *
 * @param ba контекст масиву байтів
 * @param buf масив байтів
 * @param buf_len розмір масиву байтів
 * @return код помилки
 */
UAPKIC_EXPORT int ba_to_uint8(const ByteArray* ba, uint8_t* buf, size_t buf_len);

/**
 * Повертає дані, які зберігає контекст масиву байтів.
 * Виділяє пам’ять.
 *
 * @param ba контекст масиву байтів
 * @param buf масив байтів
 * @param buf_len розмір масиву байтів
 * @return код помилки
 */
UAPKIC_EXPORT int ba_to_uint8_with_alloc(const ByteArray* ba, uint8_t** buf, size_t* buf_len);

UAPKIC_EXPORT int ba_to_base64_with_alloc(const ByteArray* ba, char** str);

UAPKIC_EXPORT int ba_to_hex_with_alloc(const ByteArray* ba, char** str);

UAPKIC_EXPORT int ba_to_str_with_alloc(const ByteArray* ba, size_t off, size_t len, char** str);

UAPKIC_EXPORT int ba_to_base64(const ByteArray* ba, char* str, size_t* outlen);

UAPKIC_EXPORT int ba_to_hex(const ByteArray* ba, char* str, size_t* outlen);

/**
 * Повертає розмір даних, які зберігає контекст масиву байтів.
 *
 * @param ba контекст масиву байтів
 * @return розмір даних, які зберігає контекст масиву байтів.
 */
UAPKIC_EXPORT size_t ba_get_len(const ByteArray* ba);

/**
 * Повертає вказівник на дані, які зберігає контекст масиву байтів.
 *
 * @param ba контекст масиву байтів
 * @return вказівник на дані, які зберігає контекст масиву байтів
 */
UAPKIC_EXPORT const uint8_t* ba_get_buf_const(const ByteArray* ba);

/**
 * Повертає вказівник на дані, які зберігає контекст масиву байтів.
 *
 * @param ba контекст масиву байтів
 * @return вказівник на дані, які зберігає контекст масиву байтів
 */
UAPKIC_EXPORT uint8_t* ba_get_buf(ByteArray* ba);

/**
 * Зчитує елемент масиву байтів.
 *
 * @param ba контекст масиву байтів
 * @param index індекс елемента
 * @param value значення елемента
 * @return код помилки
 */
UAPKIC_EXPORT int ba_get_byte(const ByteArray* ba, size_t index, uint8_t* value);

/**
 * Змінює елемент масиву байтів.
 *
 * @param ba контекст масиву байтів
 * @param index індекс елемента
 * @param value нове значення елемента
 * @return код помилки
 */
UAPKIC_EXPORT int ba_set_byte(ByteArray* ba, size_t index, uint8_t value);

UAPKIC_EXPORT int ba_copy(const ByteArray* in, size_t in_off, size_t len, ByteArray* out, size_t out_off);

UAPKIC_EXPORT int ba_append(const ByteArray* in, size_t in_off, size_t len, ByteArray* out);

/**
 * Змінює розмір масиву байтів.
 *
 * @param ba контекст масиву байтів
 * @param len новий розмір масиву байтів
 * @return код помилки
 */
UAPKIC_EXPORT int ba_change_len(ByteArray* ba, size_t len);

UAPKIC_EXPORT int ba_trim_leading_zeros_le(ByteArray* ba);

/**
 * Розташовує вміст масиву байтів у зворотному порядку.
 *
 * @param a контекст масиву байтів
 * @return код помилки
 */
UAPKIC_EXPORT int ba_swap(const ByteArray* a);

/**
 * Додає до першого масиву байтів другий за модулем 2.
 * Перший масив не може бути більшим за другий.
 *
 * @param a контекст масиву байтів
 * @param b контекст масиву байтів
 * @return код помилки
 */
UAPKIC_EXPORT int ba_xor(const ByteArray* a, const ByteArray* b);

/**
 * Заповнює масив байтів.
 *
 * @param a контекст масиву байтів
 * @param value значення, яким треба заповнити масив
 * @return код помилки
 */
UAPKIC_EXPORT int ba_set(ByteArray* a, uint8_t value);

/**
 * Створює контекст масиву байтів шляхом зчеплення двох інших.
 *
 * @param a контекст масиву байтів
 * @param b контекст масиву байтів
 * @return контекст масиву байтів
 */
UAPKIC_EXPORT ByteArray* ba_join(const ByteArray* a, const ByteArray* b);

/**
 * Порівнює два контексти масивів байтів.
 *
 * @param a контекст масиву байтів
 * @param b контекст масиву байтів
 * @return 0, якщо масиви мають однаковий розмір і містять однакові дані, інакше -1 або 1.
 */
UAPKIC_EXPORT int ba_cmp(const ByteArray* a, const ByteArray* b);

/**
 * Звільняє контекст масиву байтів.
 *
 * @param ba контекст масиву байтів
 */
UAPKIC_EXPORT void ba_free(ByteArray* ba);

/**
 * Стирає дані й звільняє контекст масиву байтів.
 *
 * @param ba контекст масиву байтів
 */
UAPKIC_EXPORT void ba_free_private(ByteArray* ba);


#ifdef  __cplusplus
}
#endif

#endif
