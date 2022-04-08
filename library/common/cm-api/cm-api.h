/*
 * Copyright (c) 2022, The UAPKI Project Authors.
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

#ifndef CM_API_H
#define CM_API_H


#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif


struct CM_SESSION_API_ST;
struct CM_KEY_API_ST;

typedef uint32_t CM_ERROR;
typedef uint8_t CM_UTF8_CHAR;
typedef CM_UTF8_CHAR* CM_JSON_PCHAR;
typedef uint32_t CM_KEY_FLAGS;

typedef enum CM_OPEN_MODE_ST {
    OPEN_MODE_RW        = 0,
    OPEN_MODE_RO        = 1,
    OPEN_MODE_CREATE    = 2
} CM_OPEN_MODE;

typedef struct CM_BYTEARRAY {
    uint8_t*    buf;
    size_t      len;
} CM_BYTEARRAY;

typedef CM_ERROR (*cm_provider_info_f) (CM_JSON_PCHAR* providerInfo);
typedef CM_ERROR (*cm_provider_init_f) (CM_JSON_PCHAR providerParams);
typedef CM_ERROR (*cm_provider_deinit_f) (void);
typedef CM_ERROR (*cm_provider_list_storages_f) (CM_JSON_PCHAR* listUris);
typedef CM_ERROR (*cm_provider_storage_info_f) (const char* uri, CM_JSON_PCHAR* storageInfo);
// uri(Uniform Resource Identificator): filename, token, url-path
typedef CM_ERROR (*cm_provider_open_f) (const char* uri, const uint32_t mode, const CM_JSON_PCHAR params, struct CM_SESSION_API_ST** session);
typedef CM_ERROR (*cm_provider_close_f) (struct CM_SESSION_API_ST* session);
typedef CM_ERROR (*cm_provider_format_f) (const char* uri, const char* soPassword, const char* newUserPassword);
typedef void (*cm_block_free_f) (void* ptr);
typedef void (*cm_bytearray_free_f) (CM_BYTEARRAY* ba);

typedef struct {
    uint32_t                    version;
    void*                       reserved;
    void*                       hlib;
    cm_provider_info_f          info;
    cm_provider_init_f          init;
    cm_provider_deinit_f        deinit;
    cm_provider_list_storages_f list_storages;
    cm_provider_storage_info_f  storage_info;
    cm_provider_open_f          open;
    cm_provider_close_f         close;
    cm_provider_format_f        format;
    cm_block_free_f             block_free;
    cm_bytearray_free_f         bytearray_free;
} CM_PROVIDER_API;

typedef CM_ERROR (*cm_session_info_f) (struct CM_SESSION_API_ST* session,
        CM_JSON_PCHAR* sessionInfo);
typedef CM_ERROR (*cm_session_mechanism_parameters_f) (struct CM_SESSION_API_ST* session,
        const CM_UTF8_CHAR* mechanismId, CM_JSON_PCHAR* parameterIds);
typedef CM_ERROR (*cm_session_login_f) (struct CM_SESSION_API_ST* session,
        const CM_UTF8_CHAR* password, const void* reserved);
typedef CM_ERROR (*cm_session_logout_f) (struct CM_SESSION_API_ST* session);
typedef CM_ERROR (*cm_session_list_keys_f) (struct CM_SESSION_API_ST* session,
        uint32_t* count, CM_BYTEARRAY*** baKeyIds, CM_JSON_PCHAR* keysInfo);
typedef CM_ERROR (*cm_session_create_key_f) (struct CM_SESSION_API_ST* session,
        const CM_JSON_PCHAR keyParam, const struct CM_KEY_API_ST** key);
typedef CM_ERROR (*cm_session_import_key_f) (struct CM_SESSION_API_ST* session,
        const CM_BYTEARRAY* baP8container, const CM_UTF8_CHAR* password, const CM_JSON_PCHAR keyParam, const struct CM_KEY_API_ST** key);
typedef CM_ERROR (*cm_session_delete_key_f) (struct CM_SESSION_API_ST* session,
        const CM_BYTEARRAY* baKeyId, const bool deleteRelatedObjects);
typedef CM_ERROR (*cm_session_select_key_f) (struct CM_SESSION_API_ST* session,
        const CM_BYTEARRAY* baKeyId, const struct CM_KEY_API_ST** key);
typedef CM_ERROR (*cm_session_get_selected_key_f) (struct CM_SESSION_API_ST* session,
        const struct CM_KEY_API_ST** key);
typedef CM_ERROR (*cm_session_get_certificates_f) (struct CM_SESSION_API_ST* session,
        uint32_t* count, CM_BYTEARRAY*** abaCertificates);
typedef CM_ERROR (*cm_session_add_certificate_f) (struct CM_SESSION_API_ST* session,
        const CM_BYTEARRAY* baCertEncoded);
typedef CM_ERROR (*cm_session_delete_certificate_f) (struct CM_SESSION_API_ST* session,
        const CM_BYTEARRAY* baKeyId);
typedef CM_ERROR (*cm_session_change_password_f) (struct CM_SESSION_API_ST* session,
        const CM_UTF8_CHAR* newPassword);
typedef CM_ERROR (*cm_session_random_bytes_f) (struct CM_SESSION_API_ST* session,
        struct CM_BYTEARRAY* baBuffer);

typedef struct CM_SESSION_API_ST {
    uint32_t                            version;
    void*                               reserved;
    const void* const                   ctx;
    cm_session_info_f                   info;
    cm_session_mechanism_parameters_f   mechanismParameters;
    cm_session_login_f                  login;
    cm_session_logout_f                 logout;
    cm_session_list_keys_f              listKeys;
    cm_session_select_key_f             selectKey;
    cm_session_create_key_f             createKey;
    cm_session_import_key_f             importKey;
    cm_session_delete_key_f             deleteKey;
    cm_session_get_selected_key_f       getSelectedKey;
    cm_session_get_certificates_f       getCertificates;
    cm_session_add_certificate_f        addCertificate;
    cm_session_delete_certificate_f     deleteCertificate;
    cm_session_change_password_f        changePassword;
    cm_session_random_bytes_f           randomBytes;
} CM_SESSION_API;

typedef CM_ERROR (*cm_key_get_info_f) (struct CM_SESSION_API_ST* session,
        CM_JSON_PCHAR* keyInfo, CM_BYTEARRAY** baKeyId);
typedef CM_ERROR (*cm_key_get_publickey_f) (struct CM_SESSION_API_ST* session,
        CM_BYTEARRAY** baAlgorithmIdentifier, CM_BYTEARRAY** baPublicKey);
typedef CM_ERROR (*cm_key_init_key_usage_f) (struct CM_SESSION_API_ST* session,
        void* reserved);
typedef CM_ERROR (*cm_key_set_otp_f) (struct CM_SESSION_API_ST* session,
        const CM_UTF8_CHAR* otp);
typedef CM_ERROR (*cm_key_sign_f) (struct CM_SESSION_API_ST* session,
        const CM_UTF8_CHAR* signAlgo, const CM_BYTEARRAY* baSignAlgoParams,
        const uint32_t count, const CM_BYTEARRAY** abaHashes, CM_BYTEARRAY*** abaSignatures);
typedef CM_ERROR (*cm_key_sign_init_f) (struct CM_SESSION_API_ST* session,
        const CM_UTF8_CHAR* signAlgo, const CM_BYTEARRAY* baSignAlgoParams);
typedef CM_ERROR (*cm_key_sign_update_f) (struct CM_SESSION_API_ST* session, const CM_BYTEARRAY* baData);
typedef CM_ERROR (*cm_key_sign_final_f) (struct CM_SESSION_API_ST* session, CM_BYTEARRAY** baSignature);
typedef CM_ERROR (*cm_key_get_certificates_f) (struct CM_SESSION_API_ST* session,
        uint32_t* count, CM_BYTEARRAY*** abaCertificates);
typedef CM_ERROR (*cm_key_add_certificate_f) (struct CM_SESSION_API_ST* session,
        const CM_BYTEARRAY* baCertEncoded);
typedef CM_ERROR (*cm_key_get_csr_f) (struct CM_SESSION_API_ST* session,
        const CM_UTF8_CHAR* signAlgo, const CM_BYTEARRAY* baSignAlgoParams,
        const CM_BYTEARRAY* baSubject, const CM_BYTEARRAY* baAttributes, CM_BYTEARRAY** baCsrEncoded);
typedef CM_ERROR (*cm_key_dh_f) (struct CM_SESSION_API_ST* session,
        const uint32_t count, const CM_BYTEARRAY** abaSPKIs, CM_BYTEARRAY*** abaSecrets);
typedef CM_ERROR (*cm_key_dh_wrap_key_f) (struct CM_SESSION_API_ST* session,
        const CM_UTF8_CHAR* kdfOid, const CM_UTF8_CHAR* wrapAlgOid,
        const uint32_t count, const CM_BYTEARRAY** abaSPKIs, const CM_BYTEARRAY** abaSessionKeys,
        CM_BYTEARRAY*** abaSalts, CM_BYTEARRAY*** abaWrappedKeys);
typedef CM_ERROR (*cm_key_dh_unwrap_key_f) (struct CM_SESSION_API_ST* session,
        const CM_UTF8_CHAR* kdfOid, const CM_UTF8_CHAR* wrapAlgOid,
        const uint32_t count, const CM_BYTEARRAY** abaPubkeys, const CM_BYTEARRAY** abaSalts, const CM_BYTEARRAY** abaWrappedKeys,
        CM_BYTEARRAY*** abaSessionKeys);
typedef CM_ERROR (*cm_key_decrypt_f) (struct CM_SESSION_API_ST* session,
        const CM_BYTEARRAY* baAlgorithmIdentifier, const CM_BYTEARRAY* baSource, CM_BYTEARRAY** baDest);
typedef CM_ERROR (*cm_key_encrypt_f) (struct CM_SESSION_API_ST* session,
        const CM_BYTEARRAY* baAlgorithmIdentifier, const CM_BYTEARRAY* baSource, CM_BYTEARRAY** baDest);
typedef CM_ERROR (*cm_key_set_info_f) (struct CM_SESSION_API_ST* session,
        const CM_UTF8_CHAR* label);
typedef CM_ERROR (*cm_key_export_f) (struct CM_SESSION_API_ST* session,
        const CM_UTF8_CHAR* password, CM_BYTEARRAY** baP8container);


typedef struct CM_KEY_API_ST {
    uint32_t                    version;
    void*                       reserved;
    cm_key_get_info_f           getInfo;
    cm_key_get_publickey_f      getPublicKey;
    cm_key_init_key_usage_f     initKeyUsage;
    cm_key_set_otp_f            setOtp;
    cm_key_sign_f               sign;
    cm_key_sign_init_f          signInit;
    cm_key_sign_update_f        signUpdate;
    cm_key_sign_final_f         signFinal;
    cm_key_get_certificates_f   getCertificates;
    cm_key_add_certificate_f    addCertificate;
    cm_key_get_csr_f            getCsr;
    cm_key_dh_f                 dh;
    cm_key_dh_wrap_key_f        dhWrapKey;
    cm_key_dh_unwrap_key_f      dhUnwrapKey;
    cm_key_decrypt_f            decrypt;
    cm_key_encrypt_f            encrypt;
    cm_key_set_info_f           setInfo;
    cm_key_export_f             exportKey;
} CM_KEY_API;


#ifdef __cplusplus
}
#endif

#endif
