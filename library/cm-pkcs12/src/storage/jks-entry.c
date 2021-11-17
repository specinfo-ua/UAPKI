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

#include "jks-entry.h"
#include "macros-internal.h"
#include <time.h>

#undef FILE_MARKER
#define FILE_MARKER "jks-entry.c"


/**
 * Создает пустой список объектов JksCertificate.
 *
 * @return указатель на созданный объект или NULL в случае ошибки
 */
JksCertificaties* jks_entry_certs_alloc(const uint32_t count)
{
    int ret = RET_OK;
    JksCertificaties *certs = NULL;

    CALLOC_CHECKED(certs, sizeof(JksCertificaties));
    CALLOC_CHECKED(certs->list, sizeof(JksCertificate *) * count);

    certs->count = count;

    return certs;

cleanup:

    jks_entry_certs_free(certs);

    return NULL;
}

/**
 * Освобождает память, занимаемую сертификатом.
 *
 * @param cert удаляемый объект или NULL
 */
static void jks_entry_cert_free(JksCertificate *cert)
{
    if (cert) {
        ba_free(cert->encoded);
        free(cert->type);

        free(cert);
    }
}

/**
 * Освобождает память, занимаемую списком.
 *
 * @param certs удаляемый объект или NULL
 */
void jks_entry_certs_free(JksCertificaties* certs)
{
    if (certs) {
        size_t i;

        for (i = 0; i < certs->count; i++) {
            jks_entry_cert_free(certs->list[i]);
        }

        free(certs->list);
        free(certs);
    }
}

/**
 * Освобождает память, занимаемую списком.
 *
 * @param entries удаляемый объект или NULL
 */
void jks_entry_free(JksEntry *entry)
{
    if (entry) {
        free(entry->alias);

        switch (entry->entry_type) {
            case PRIVATE_KEY_ENTRY:
            asn_free(get_EncryptedPrivateKeyInfo_desc(), entry->entry.key);
            jks_entry_certs_free(entry->entry_exts);
            break;

        case CERTIFICATE_ENTRY:
            jks_entry_cert_free(entry->entry.cert);
            break;

        default:
            break;
        }

        free(entry);
    }
}

/**
 * Создает пустой список объектов entry.
 *
 * @return указатель на созданный объект или NULL в случае ошибки
 */
JksEntries* jks_entries_alloc(const uint32_t count)
{
    int ret = RET_OK;
    JksEntries *entries = NULL;

    CALLOC_CHECKED(entries, sizeof(JksEntries));

    if (count > 0) {
        CALLOC_CHECKED(entries->list, sizeof(JksEntry *) * count);
    }

    entries->count = count;

    return entries;

cleanup:

    jks_entries_free(entries);

    return NULL;
}

/**
 * Освобождает память, занимаемую списком.
 *
 * @param entries удаляемый объект или NULL
 */
void jks_entries_free(JksEntries *entries)
{
    if (entries) {
        size_t i;

        for (i = 0; i < entries->count; i++) {
            jks_entry_free(entries->list[i]);
        }

        free(entries->list);
        free(entries);
    }
}

/**
 * Чтение сертификата из буфера.
 *
 * @param buffer контекст буфера
 * @param cert   сертификат
 *
 * @return код ошибки
 */
static int jks_entry_cert_read(JksBufferCtx *buffer, const uint32_t jks_ver, JksCertificate **cert)
{
    int ret = RET_OK;
    JksCertificate *read_cert = NULL;

    CHECK_PARAM(buffer != NULL);
    CHECK_PARAM(cert != NULL);

    CALLOC_CHECKED(read_cert, sizeof(JksCertificate));

    if (jks_ver == JKS_VERSION_2) {
        //  Считывание типа сертификата
        DO(jks_buffer_read_string(buffer, &read_cert->type));
    } else {
        //  Устанавливаем тип по умолчанию
        CHECK_NOT_NULL(read_cert->type = strdup("X.509"));
    }

    //  Считывание сертификат
    DO(jks_buffer_read_data(buffer, &read_cert->encoded));

    *cert = read_cert;
    read_cert = NULL;

cleanup:

    jks_entry_cert_free(read_cert);

    return ret;
}

/**
 * Чтение объекта из буфера.
 *
 * @param reader контекст буфера
 * @param entry  объект
 *
 * @return код ошибки
 */
int jks_entry_read(JksBufferCtx *buffer, const uint32_t jks_ver, JksEntry **entry)
{
    int ret = RET_OK;
    ByteArray* encoded = NULL;
    JksEntry* read_entry = NULL;
    uint32_t cnt_certs = 0;

    CHECK_PARAM(buffer != NULL);
    CHECK_PARAM(entry != NULL);

    CALLOC_CHECKED(read_entry, sizeof(JksEntry));

    //  Считывание тэга
    DO(jks_buffer_read_int(buffer, (uint32_t *)&read_entry->entry_type));
    //  Считывание алиаса
    DO(jks_buffer_read_string(buffer, &read_entry->alias));
    //  Считывание даты создания
    DO(jks_buffer_read_long(buffer, &read_entry->date));

    switch (read_entry->entry_type) {
        case PRIVATE_KEY_ENTRY:
            cnt_certs = 0;
            //  Считываем закрытый ключ
            DO(jks_buffer_read_data(buffer, &encoded));
            CHECK_NOT_NULL(read_entry->entry.key = asn_decode_ba_with_alloc(get_EncryptedPrivateKeyInfo_desc(), encoded));
            //  Считываем цепочку сертификатов
            DO(jks_buffer_read_int(buffer, &cnt_certs));
            if (cnt_certs > 0) {
                CHECK_NOT_NULL(read_entry->entry_exts =  jks_entry_certs_alloc(cnt_certs));
                for (uint32_t i = 0; i < cnt_certs; i++) {
                    DO(jks_entry_cert_read(buffer, jks_ver, &read_entry->entry_exts->list[i]));
                }
            }
            break;
        case CERTIFICATE_ENTRY:
            //  Считываем сертификат
            DO(jks_entry_cert_read(buffer, jks_ver, &read_entry->entry.cert));
            break;
        default:
            break;
    }

    *entry = read_entry;
    read_entry = NULL;

cleanup:
    jks_entry_free(read_entry);
    ba_free(encoded);
    return ret;
}

