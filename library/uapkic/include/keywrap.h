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

#ifndef UAPKIC_KEYWRAP_H
#define UAPKIC_KEYWRAP_H

#include "byte-array.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
* Зашифровує ключ за алгоритмом Dstu7624Wrap згідно ТЕХНІЧНИХ СПЕЦИФІКАЦІЙ до RFC 5652 затверждених наказом Адмiнiстрацiї Дерспецзв'язку 27.10.2020 року N 687
*
* @param kek        ключ шифрування ключа
* @param key        ключ що шифрується
* @param wraped_key зашифрований ключ
*
* @return код помилки
*/
UAPKIC_EXPORT int key_wrap_dstu7624(const ByteArray* kek, const ByteArray* key, ByteArray** wraped_key);

/**
* Розшифровує ключ за алгоритмом Dstu7624Wrap згідно ТЕХНІЧНИХ СПЕЦИФІКАЦІЙ до RFC 5652 затверждених наказом Адмiнiстрацiї Дерспецзв'язку 27.10.2020 року N 687
*
* @param kek        ключ шифрування ключа
* @param wraped_key зашифрований ключ
* @param key        розшифрований ключ
*
* @return код помилки
*/
UAPKIC_EXPORT int key_unwrap_dstu7624(const ByteArray* kek, const ByteArray* wraped_key, ByteArray** key);

/**
* Зашифровує ключ за алгоритмом GOST28147Wrap згідно наказу Адмiнiстрацiї Дерспецзв'язку від 14 січня 2013 р. N 108/22640
*
* @param sbox       ДКЕ
* @param kek        ключ шифрування ключа
* @param key        ключ що шифрується
* @param wraped_key зашифрований ключ
*
* @return код помилки
*/
UAPKIC_EXPORT int key_wrap_gost28147(const ByteArray* sbox, const ByteArray* kek, const ByteArray* key, ByteArray** wraped_key);

/**
* Розшифровує ключ за алгоритмом GOST28147Wrap згідно наказу Адмiнiстрацiї Дерспецзв'язку від 14 січня 2013 р. N 108/22640
*
* @param sbox       ДКЕ
* @param kek        ключ шифрування ключа
* @param wraped_key зашифрований ключ
* @param key        розшифрований ключ
*
* @return код помилки
*/
UAPKIC_EXPORT int key_unwrap_gost28147(const ByteArray* sbox, const ByteArray* kek, const ByteArray* wraped_key, ByteArray** key);

/**
 * Виконує самотестування реалізації алгоритмів keywrap.
 *
 * @return код помилки або RET_OK, якщо самотестування пройдено
 */
UAPKIC_EXPORT int key_wrap_self_test(void);

#ifdef  __cplusplus
}
#endif

#endif
