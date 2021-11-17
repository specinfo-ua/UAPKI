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

#ifndef UAPKI_CONTENT_INFO_H
#define UAPKI_CONTENT_INFO_H


#include "uapkif.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CONTENT_UNKNOWN     = 0,
    CONTENT_DATA        = 1,
    CONTENT_SIGNED      = 2,
    CONTENT_DIGESTED    = 3,
    CONTENT_ENCRYPTED   = 4,
    CONTENT_ENVELOPED   = 5,
} CinfoType;


/**
 * Повертає тип контейнера.
 *
 * @param cinfo контейнер даних
 * @param type тип контейнера
 *
 * @return код помилки
 */
int cinfo_get_type (const ContentInfo_t* cinfo, CinfoType* type);

/**
 * Повертає контейнер даних.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param cinfo контейнер даних
 * @param data створюваний об'єкт контейнера даних
 *
 * @return код помилки
 */
int cinfo_get_data (const ContentInfo_t* cinfo, ByteArray** data);

/**
 * Повертає контейнер шифрованих даних.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param cinfo контейнер даних
 * @param encr_data створюваний об'єкт контейнера шифрованих даних
 *
 * @return код помилки
 */
int cinfo_get_encrypted_data (const ContentInfo_t* cinfo, EncryptedData_t** encr_data);

/**
 * Повертає контейнер підписаних даних.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param cinfo контейнер даних
 * @param sdata створюваний об'єкт контейнера підписаних даних
 *
 * @return код помилки
 */
int cinfo_get_signed_data (const ContentInfo_t* cinfo, SignedData_t** sdata);

/**
 * Ініціалізує контейнер даних.
 *
 * @param cinfo контейнер даних
 * @param data дані
 *
 * @return код помилки
 */
int cinfo_init_by_data (ContentInfo_t* cinfo, const ByteArray *data);

/**
 * Ініціалізує контейнер контейнером шифрованих даних.
 *
 * @param cinfo контейнер даних
 * @param encr_data контейнер шифрованих даних
 *
 * @return код помилки
 */
int cinfo_init_by_encrypted_data (ContentInfo_t* cinfo, const EncryptedData_t* encr_data);


#ifdef __cplusplus
}
#endif

#endif
