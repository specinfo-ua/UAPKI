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

#ifndef UAPKI_BA_UTILS_H
#define UAPKI_BA_UTILS_H


#include <stdbool.h>
#include "byte-array.h"


#ifdef  __cplusplus
extern "C" {
#endif


#define BA_FREE(...) ba_free_many(NARGS(__VA_ARGS__), __VA_ARGS__)


bool ba_is_equals(ByteArray *expected, ByteArray *actual);

void ba_free_many(int num, ...);

int ba_print(FILE *stream, const ByteArray *ba);

FILE* fopen_utf8(char const* utf8path, const int is_writemode);

/**
 * Створює контекст масиву байт з файлу.
 *
 * @param path шлях до файлу
 * @param out  контекст масиву байт
 * @return код помилки
 */
int ba_alloc_from_file(const char * utf8path, ByteArray ** out);

/**
 * Записує дані у файл, які зберігають контекст масиву байт.
 * Не виділяє пам'ять.
 *
 * @param ba   контекст масиву байт
 * @param path шлях до файлу
 * @return код помилки
 */
int ba_to_file(const ByteArray * ba, const char * utf8path);

//  Додаткова функція: видалення файлу
int delete_file(const char * utf8path);


#ifdef  __cplusplus
}
#endif

#endif
