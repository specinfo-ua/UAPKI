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


/*********************** Об'єкти сховища. **********************************/

/** Типи об'єктів сховища ключів. */
typedef enum {
    SECRET_KEY_ENTRY,
    PRIVATE_KEY_ENTRY,
    CERTIFICATE_ENTRY,
    UNKNOWN_ENTRY
} EntryType;

/** Структура сертифіката. */
typedef struct JksCertificate_st
{
    char          *type;       /**< тип сертифіката */
    ByteArray     *encoded;    /**< сертифікат */
} JksCertificate;

typedef struct JksCertificaties_st
{
    JksCertificate **list;     /**< Список об'єктів */
    uint32_t         count;    /**< кількість об'єктів */
} JksCertificaties;

/** Структура об'єкта сховища ключів. */
typedef struct JksEntry_st
{
    EntryType  entry_type;                  /**< тип об'єкта */
    char      *alias;                       /**< унікальний ідентифікатор об'єкта (рядок UTF-8) */
    uint64_t   date;                        /**< дата створення об'єкта */

    union {                                 /**< дані об'єкта */
        EncryptedPrivateKeyInfo_t *key;     /**< особистий ключ */
        JksCertificate            *cert;    /**< сертифікат */
    } entry;

    JksCertificaties *entry_exts;           /**< додаткові дані, може бути NULL */
} JksEntry;

typedef struct JksEntries_st
{
    JksEntry **list;          /**< Список об'єктів */
    uint32_t   count;         /**< кількість об'єктів */
} JksEntries;

/**
 * Звільняє пам'ять, яку займає об'єкт.
 *
 * @param entry об'єкт, що видаляється, або NULL
 */
void jks_entry_free(JksEntry* entry);

/**
 * Створює порожній список об'єктів JksEntry.
 *
 * @param count кількість елементів
 *
 * @return вказівник на створений об'єкт або NULL у разі помилки
 */
JksEntries* jks_entries_alloc(const uint32_t count);

/**
 * Звільняє пам'ять, яку займає список.
 *
 * @param entries об'єкт, що видаляється, або NULL
 */
void jks_entries_free(JksEntries* entries);

/**
 * Створює порожній список сертифікатів.
 *
 * @param count кількість елементів
 *
 * @return вказівник на створений об'єкт або NULL у разі помилки
 */
JksCertificaties* jks_entry_certs_alloc(const uint32_t count);

/**
 * Звільняє пам'ять, яку займає список.
 *
 * @param certs об'єкт, що видаляється, або NULL
 */
void jks_entry_certs_free(JksCertificaties* certs);

/**
 * Читання об'єкта з буфера.
 *
 * @param buffer  контекст буфера
 * @param jks_ver версія формату JKS
 * @param entry   об'єкт
 *
 * @return код помилки
 */
int jks_entry_read(JksBufferCtx* buffer, const uint32_t jks_ver, JksEntry** entry);


#ifdef __cplusplus
}
#endif

#endif
