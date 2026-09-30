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

/** Структура для роботи з байтовим поданням сховища ключів. */
typedef struct Buffer_st
{
    ByteArray *buffer;        /**< Буфер для даних.*/
    size_t     read_off;      /**< Позиція індексу читання буфера. */
    ByteArray *hash;          /**< Геш.*/
} JksBufferCtx;

/**
 * Виділяє буфер для запису даних сховища.
 *
 * @return контекст буфера
 */
JksBufferCtx* jks_buffer_alloc(void);

/**
 * Створює буфер для читання даних сховища з масиву байтів.
 *
 * @param data дані сховища (останні 20 байтів — геш SHA-1)
 *
 * @return контекст буфера або NULL у разі помилки
 */
JksBufferCtx* jks_buffer_alloc_ba(const ByteArray *data);

/**
 * Звільняє виділений буфер для запису даних.
 *
 * @param ctx контекст буфера
 */
void jks_buffer_free(JksBufferCtx *ctx);

/**
 * Зчитує ціле число з буфера.
 *
 * @param ctx   контекст буфера
 * @param value ціле число (32 біти)
 *
 * @return код помилки
 */
int jks_buffer_read_int(JksBufferCtx *ctx, uint32_t *value);

/**
 * Зчитує довге ціле число з буфера.
 *
 * @param ctx   контекст буфера
 * @param value зчитане довге ціле число (64 біти)
 *
 * @return код помилки
 */
int jks_buffer_read_long(JksBufferCtx *ctx, uint64_t *value);

/**
 * Зчитує масив байтів з буфера.
 *
 * @param ctx  контекст буфера
 * @param data масив байтів
 *
 * @return код помилки
 */
int jks_buffer_read_data(JksBufferCtx *ctx, ByteArray **data);

/**
 * Зчитує масив char utf8 з буфера.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param ctx    контекст буфера
 * @param string буфер для запису прочитаних даних
 *
 * @return код помилки
 */
int jks_buffer_read_string(JksBufferCtx *ctx, char **string);

/**
 * Повертає геш з буфера.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param ctx  контекст буфера
 * @param hash буфер для запису прочитаних даних
 *
 * @return код помилки
 */
int jks_buffer_get_hash(const JksBufferCtx *ctx, ByteArray **hash);

/**
 * Повертає тіло буфера.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param ctx  контекст буфера
 * @param body тіло буфера
 *
 * @return код помилки
 */
int jks_buffer_get_body(const JksBufferCtx *ctx, ByteArray **body);

int jks_buffer_to_ba(const JksBufferCtx *ctx, ByteArray **ba);


#ifdef __cplusplus
}
#endif

#endif
