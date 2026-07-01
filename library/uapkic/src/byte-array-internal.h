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

#ifndef UAPKIC_BYTE_ARRAY_INTERNAL_H
#define UAPKIC_BYTE_ARRAY_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "byte-array.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct ByteArray_st {
    uint8_t *buf;
    size_t len;
};

/**
 * Створює контекст масиву байтів.
 *
 * @param buf масив байтів у Big Endian
 * @param buf_len кількість елементів у buf
 * @return контекст масиву байтів
 */
ByteArray *ba_alloc_from_uint8_be(const uint8_t *buf, size_t buf_len);

/**
 * Створює контекст масиву байтів із масиву 32-розрядних цілих чисел.
 *
 * @param buf масив 32-розрядних цілих чисел
 * @param buf_len кількість елементів у buf
 * @return контекст масиву байтів
 */
ByteArray* ba_alloc_from_uint32(const uint32_t* buf, size_t buf_len);

/**
 * Створює контекст масиву байтів із масиву 64-розрядних цілих чисел.
 *
 * @param buf масив 64-розрядних цілих чисел
 * @param buf_len кількість елементів у buf
 * @return контекст масиву байтів
 */
ByteArray *ba_alloc_from_uint64(const uint64_t *buf, size_t buf_len);

/**
 * Повертає дані, котрі містить контекст масиву байтів, у вигляді масиву 64-розрядних цілих чисел.
 * Виділяє пам’ять.
 *
 * @param ba контекст масиву байтів
 * @param buf масив 64-розрядних цілих чисел
 * @param buf_len кількість елементів у buf
 * @return код помилки
 */
int ba_to_uint64_with_alloc(const ByteArray *ba, uint64_t **buf, size_t *buf_len);

/**
 * Повертає дані, котрі містить контекст масиву байтів, у вигляді масиву 32-розрядних цілих чисел.
 * Не виділяє пам’ять.
 *
 * @param ba контекст масиву байтів
 * @param buf масив 32-розрядних цілих чисел
 * @param buf_len кількість елементів у buf
 * @return код помилки
 */
int ba_to_uint32(const ByteArray *ba, uint32_t *buf, size_t buf_len);

/**
 * Повертає дані, котрі містить контекст масиву байтів, у вигляді масиву 64-розрядних цілих чисел.
 * Не виділяє пам’ять.
 *
 * @param ba контекст масиву байтів
 * @param buf масив 64-розрядних цілих чисел
 * @param buf_len кількість елементів у buf
 * @return код помилки
 */
int ba_to_uint64(const ByteArray* ba, uint64_t* buf, size_t buf_len);

int ba_from_uint32(const uint32_t *buf, size_t buf_len, ByteArray *ba);
int ba_from_uint64(const uint64_t *buf, size_t buf_len, ByteArray *ba);
int ba_trim_leading_zeros(ByteArray *ba);
int ba_truncate(ByteArray *a, size_t bit_len);
bool ba_is_zero(const ByteArray *a);

#ifdef  __cplusplus
}
#endif

#endif
