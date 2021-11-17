/*
 * Copyright (c) 2021, The UAPKI Project Authors.
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

#ifndef JKS_BUFFER_H
#define JKS_BUFFER_H

#include "uapkic.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Структура для работы с байтовым представлением ключевого хранилища. */
typedef struct Buffer_st
{
    ByteArray *buffer;        /**< Буфер для данных.*/
    size_t     read_off;      /**< Положение индекса чтения буфера. */
    ByteArray *hash;          /**< Хеш.*/
} JksBufferCtx;

/**
 * Выделяет буфер для записи данных хранилища.
 *
 * @param size размер буфера в байтах
 *
 * @return контекст буфера
 */
JksBufferCtx* jks_buffer_alloc(void);

/**
 * Выделяет буфер для записи данных хранилища.
 *
 * @param size размер буфера в байтах
 *
 * @return контекст буфера
 */
JksBufferCtx* jks_buffer_alloc_ba(const ByteArray *data);

/**
 * Освобождает выделенный буфер для записи данных.
 *
 * @param ctx контекст буфера
 */
void jks_buffer_free(JksBufferCtx *ctx);

/**
 * Производит чтение целого числа из буфера.
 *
 * @param ctx   контекст буфера
 * @param value целое число (32 бита)
 *
 * @return код ошибки
 */
int jks_buffer_read_int(JksBufferCtx *ctx, uint32_t *value);

/**
 * Производит чтение длинного целого числа из буфера.
 *
 * @param ctx   контекст буфера
 * @param value считанное длинного целое число (64 бита)
 *
 * @return код ошибки
 */
int jks_buffer_read_long(JksBufferCtx *ctx, uint64_t *value);

/**
 * Производит чтение массива байтов из буфера.
 *
 * @param ctx  контекст буфера
 * @param data массив байтов
 *
 * @return код ошибки
 */
int jks_buffer_read_data(JksBufferCtx *ctx, ByteArray **data);

/**
 * Производит чтение массива char utf8 из буфера.
 * Выделяемая память требует освобождения.
 *
 * @param ctx    контекст буфера
 * @param string буфер для записи прочитанных данных
 *
 * @return код ошибки
 */
int jks_buffer_read_string(JksBufferCtx *ctx, char **string);

/**
 * Возвращает хеша из буфера.
 * Выделяемая память требует освобождения.
 *
 * @param ctx  контекст буфера
 * @param hash буфер для записи прочитанных данных
 *
 * @return код ошибки
 */
int jks_buffer_get_hash(const JksBufferCtx *ctx, ByteArray **hash);

/**
 * Возвращает тело буфера.
 * Выделяемая память требует освобождения.
 *
 * @param ctx  контекст буфера
 * @param hash буфер для записи прочитанных данных
 *
 * @return код ошибки
 */
int jks_buffer_get_body(const JksBufferCtx *ctx, ByteArray **body);

int jks_buffer_to_ba(const JksBufferCtx *ctx, ByteArray **ba);


#ifdef __cplusplus
}
#endif

#endif
