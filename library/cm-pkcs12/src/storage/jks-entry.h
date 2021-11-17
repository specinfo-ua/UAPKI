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

#ifndef JKS_ENTRY_H
#define JKS_ENTRY_H


#include "jks-buffer.h"
#include "uapkic.h"
#include "uapkif.h"


#ifdef __cplusplus
extern "C" {
#endif


#define JKS_VERSION_1   0x01
#define JKS_VERSION_2   0x02


/*********************** Объекты хранилища. **********************************/

/** Типы объектов ключевого хранилища. */
typedef enum {
    SECRET_KEY_ENTRY,
    PRIVATE_KEY_ENTRY,
    CERTIFICATE_ENTRY,
    UNKNOWN_ENTRY
} EntryType;

/** Структура сертификата. */
typedef struct JksCertificate_st
{
    char          *type;       /**< тип сертификата */
    ByteArray     *encoded;    /**< сертификат */
} JksCertificate;

typedef struct JksCertificaties_st
{
    JksCertificate **list;     /**< Список объектов */
    uint32_t         count;    /**< количество объектов */
} JksCertificaties;

/** Структура объекта ключевого хранилища. */
typedef struct JksEntry_st
{
    EntryType  entry_type;                  /**< тип объекта */
    char      *alias;                       /**< уникальный идентификатор объекта (строка UTF-8) */
    uint64_t   date;                        /**< дата создания объекта */

    union {                                 /**< данные объекта */
        EncryptedPrivateKeyInfo_t *key;     /**< закрытый ключ */
        JksCertificate            *cert;    /**< сертификат */
    } entry;

    JksCertificaties *entry_exts;           /**< дополнительные данные, может быть NULL */
} JksEntry;

typedef struct JksEntries_st
{
    JksEntry **list;          /**< Список объектов */
    uint32_t   count;         /**< количество объектов */
} JksEntries;

/**
 * Освобождает память, занимаемую списком.
 *
 * @param entries удаляемый объект или NULL
 */
void jks_entry_free(JksEntry* entry);

/**
 * Создает пустой список объектов JksEntry.
 *
 * @param count количество элементов
 *
 * @return указатель на созданный объект или NULL в случае ошибки
 */
JksEntries* jks_entries_alloc(const uint32_t count);

/**
 * Освобождает память, занимаемую списком.
 *
 * @param entry удаляемый объект или NULL
 */
void jks_entries_free(JksEntries* entries);

/**
 * Создает пустой список сертфикатов.
 *
 * @param count количество элементов
 *
 * @return указатель на созданный объект или NULL в случае ошибки
 */
JksCertificaties* jks_entry_certs_alloc(const uint32_t count);

/**
 * Освобождает память, занимаемую списком.
 *
 * @param certs удаляемый объект или NULL
 */
void jks_entry_certs_free(JksCertificaties* certs);

/**
 * Чтение объекта из буфера.
 *
 * @param reader контекст буфера
 * @param entry  объект
 *
 * @return код ошибки
 */
int jks_entry_read(JksBufferCtx* buffer, const uint32_t jks_ver, JksEntry** entry);


#ifdef __cplusplus
}
#endif

#endif
