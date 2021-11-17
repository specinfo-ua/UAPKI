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

#ifndef UAPKIC_ENTROPY_H
#define UAPKIC_ENTROPY_H

#include "byte-array.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Заповнює масив випадковими байтами використовуючи системний ГПВЧ.
 *
 * @param buf масив для розміщення випадкових байт
 * @return код помилки
 */
UAPKIC_EXPORT int entropy_std(ByteArray *buf);

/**
 * Заповнює масив випадковими байтами на основі CPU execution time jitter.
 *
 * @param buf масив для розміщення випадкових байт
 * @return код помилки
 */
UAPKIC_EXPORT int entropy_jitter(ByteArray *buf);

/**
 * Виконує самотестування джерел ентропії.
 *
 * @param buf масив для розміщення випадкових байт
 * @return код помилки
 */
UAPKIC_EXPORT int entropy_self_test(void);

#ifdef  __cplusplus
}
#endif

#endif
