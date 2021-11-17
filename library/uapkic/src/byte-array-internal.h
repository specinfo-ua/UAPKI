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
 * Создаёт контекст массива байт.
 *
 * @param buf массив байт с инвертированным порядком байт
 * @param buf_len размер массива байт
 * @return контекст массива байт
 */
ByteArray *ba_alloc_from_uint8_be(const uint8_t *buf, size_t buf_len);

/**
 * Создаёт контекст массива байт по массиву 64-битных слов.
 *
 * @param buf массив 64 битных слов
 * @param buf_len количество слов в buf
 * @return контекст массива байт
 */
ByteArray *ba_alloc_from_uint64(const uint64_t *buf, size_t buf_len);

/**
 * Возвращает данные, которые хранит контекст массива байт, в формате массива 64-битных слов.
 * Выделяет память.
 *
 * @param ba контекст массива байт
 * @param buf массив 64-битных слов
 * @param buf_len количество слов buf
 * @return код ошибки
 */
int ba_to_uint64_with_alloc(const ByteArray *ba, uint64_t **buf, size_t *buf_len);

/**
 * Возвращает данные, которые хранит контекст массива байт, в формате массива 32-битных слов.
 * Не выделяет память.
 *
 * @param ba контекст массива байт
 * @param buf массив 32-битных слов
 * @param buf_len количество слов buf
 * @return код ошибки
 */
int ba_to_uint32(const ByteArray *ba, uint32_t *buf, size_t buf_len);
int ba_from_uint32(const uint32_t *buf, size_t buf_len, ByteArray *ba);
ByteArray *ba_alloc_from_uint32(const uint32_t *buf, size_t buf_len);
int ba_to_uint64(const ByteArray *ba, uint64_t *buf, size_t buf_len);
int ba_from_uint64(const uint64_t *buf, size_t buf_len, ByteArray *ba);
int ba_to_uint64(const ByteArray *ba, uint64_t *buf, size_t buf_len);
int ba_trim_leading_zeros(ByteArray *ba);
int ba_truncate(ByteArray *a, size_t bit_len);
bool ba_is_zero(const ByteArray *a);

#ifdef  __cplusplus
}
#endif

#endif
