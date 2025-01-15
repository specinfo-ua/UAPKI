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

#include "cm-api.h"
#include "cm-errors.h"
#include "cm-pkcs12.h"
#include "cm-pkcs12-ctx.h"
#include "oids.h"
#include "parson-helper.h"
#include "private-key.h"
#include "uapkif.h"
#include "uapki-ns.h"
#include "cm-pkcs12-debug.h"


#define DEBUG_OUTPUT(msg)
#ifndef DEBUG_OUTPUT
DEBUG_OUTPUT_FUNC
#define DEBUG_OUTPUT(msg) debug_output(DEBUG_OUTSTREAM_DEFAULT, msg);
#endif


using namespace std;
using namespace UapkiNS;


static CM_ERROR cm_session_info (
        CM_SESSION_API* session,
        CM_JSON_PCHAR* sessionInfo
)
{
    DEBUG_OUTPUT("cm_session_info()");
    if (!session) return RET_CM_NO_SESSION;
    if (!sessionInfo) return RET_CM_INVALID_PARAMETER;

    *sessionInfo = nullptr;
    SessionPkcs12Context* ss_ctx = (SessionPkcs12Context*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    return CmPkcs12::sessionInfoToJson(ss_ctx->fileStorage.filename(), (CM_JSON_PCHAR*)sessionInfo);
}   //  cm_session_info

static CM_ERROR cm_session_mechanism_parameters (
        CM_SESSION_API* session,
        const CM_UTF8_CHAR* mechanismId,
        CM_JSON_PCHAR* parameterIds
)
{
    DEBUG_OUTPUT("cm_session_mechanism_parameters()");
    if (!session) return RET_CM_NO_SESSION;
    if (!mechanismId || !parameterIds || (strlen((char*)mechanismId) == 0)) return RET_CM_INVALID_PARAMETER;

    return CmPkcs12::mechanismParamsToJson((const char*)mechanismId, parameterIds);
}   //  cm_session_mechanism_parameters

static CM_ERROR cm_session_login (
        CM_SESSION_API* session,
        const CM_UTF8_CHAR* password,
        const void* reserved
)
{
    DEBUG_OUTPUT("cm_session_login()");
    (void)reserved;
    if (!session) return RET_CM_NO_SESSION;
    if (!password || (strlen((const char*)password) == 0)) return RET_CM_INVALID_PARAMETER;

    SessionPkcs12Context* ss_ctx = (SessionPkcs12Context*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    session->logout(session);

    int ret = RET_OK;
    FileStorage& storage = ss_ctx->fileStorage;
    if (!storage.isCreate()) {
        ret = ss_ctx->fileStorage.decode((char*)password);
    }
    else {
        storage.setOpen((char*)password);
    }
    return ret;
}   //  cm_session_login

static CM_ERROR cm_session_logout (
        CM_SESSION_API* session
)
{
    DEBUG_OUTPUT("cm_session_logout()");
    if (!session) return RET_CM_NO_SESSION;

    SessionPkcs12Context* ss_ctx = (SessionPkcs12Context*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    ss_ctx->fileStorage.selectKey(nullptr);
    //TODO: fileStorage.reset()
    return RET_OK;
}   //  cm_session_logout

static CM_ERROR cm_session_list_keys (
        CM_SESSION_API* session,
        uint32_t* count,
        CM_BYTEARRAY*** abaKeyIds,
        CM_JSON_PCHAR* keysInfo
)
{
    DEBUG_OUTPUT("cm_session_list_keys()");
    if (!session) return RET_CM_NO_SESSION;
    if (!count || !abaKeyIds) return RET_CM_INVALID_PARAMETER;

    *count = 0;
    *abaKeyIds = nullptr;

    SessionPkcs12Context* ss_ctx = (SessionPkcs12Context*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    FileStorage& storage = ss_ctx->fileStorage;
    if (!storage.isOpen()) return RET_CM_NOT_AUTHORIZED;

    vector<StoreBag*> list_keys = storage.listBags(StoreBag::BAG_TYPE::KEY);
    DEBUG_OUTPUT(std::string("cm_session_list_keys(), count keys: ") + std::to_string(list_keys.size()));

    if (list_keys.empty()) return RET_OK;

    //  Set returned keysInfo(JSON), optional
    if (keysInfo) {
        ParsonHelper json;
        if (!json.create()) return RET_CM_GENERAL_ERROR;

        JSON_Array* ja_keys = json.setArray("keys");
        for (size_t i = 0; i < list_keys.size(); i++) {
            StoreKeyInfo info_key;
            if (!list_keys[i]->getKeyInfo(info_key)) return RET_CM_GENERAL_ERROR;

            json_array_append_value(ja_keys, json_value_init_object());
            CM_ERROR cm_err = CmPkcs12::keyInfoToJson(info_key, json_array_get_object(ja_keys, i));
            if (cm_err != RET_OK) return cm_err;
        }

        if (!json.serialize((char**)keysInfo)) return RET_CM_GENERAL_ERROR;
    }

    //  Set returned abaKeyIds(array)
    ByteArray** aba_keyids = (ByteArray**)calloc(list_keys.size(), sizeof(ByteArray*));
    if (!aba_keyids) return RET_CM_GENERAL_ERROR;

    for (size_t i = 0; i < list_keys.size(); i++) {
        aba_keyids[i] = ba_copy_with_alloc(list_keys[i]->keyId(), 0, 0);
        if (!aba_keyids[i]) {
            for (size_t j = 0; j < i; j++) {
                ba_free(aba_keyids[j]);
                aba_keyids[j] = nullptr;
            }
            free(aba_keyids);
            return RET_CM_GENERAL_ERROR;
        }
    }

    *abaKeyIds = (CM_BYTEARRAY**)aba_keyids;
    *count = (uint32_t)list_keys.size();
    return RET_OK;
}   //  cm_session_list_keys

static CM_ERROR cm_session_select_key (
        CM_SESSION_API* session,
        const CM_BYTEARRAY* baKeyId,
        const CM_KEY_API** key
)
{
    DEBUG_OUTPUT("cm_session_select_key()");
    if (!session) return RET_CM_NO_SESSION;
    if (!baKeyId || !key) return RET_CM_INVALID_PARAMETER;

    *key = nullptr;
    SessionPkcs12Context* ss_ctx = (SessionPkcs12Context*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    FileStorage& storage = ss_ctx->fileStorage;
    if (!storage.isOpen()) return RET_CM_NOT_AUTHORIZED;

    storage.selectKey(nullptr);
    vector<StoreBag*> list_keys = storage.listBags(StoreBag::BAG_TYPE::KEY);
    DEBUG_OUTPUT(std::string("cm_session_select_key(), count keys: ") + std::to_string(list_keys.size()));

    for (size_t i = 0; i < list_keys.size(); i++) {
        if (ba_cmp(list_keys[i]->keyId(), (ByteArray*)baKeyId) == 0) {
            storage.selectKey(list_keys[i]);
            break;
        }
    }

    if (!storage.selectedKey()) return RET_CM_KEY_NOT_FOUND;

    *key = (const CM_KEY_API*)&ss_ctx->keyApi;
    return RET_OK;
}   //  cm_session_select_key

static CM_ERROR cm_session_create_key (
        CM_SESSION_API* session,
        const CM_JSON_PCHAR keyParam,
        const CM_KEY_API** key
)
{
    DEBUG_OUTPUT("cm_session_create_key()");
    if (!session) return RET_CM_NO_SESSION;
    if (!keyParam || !key) return RET_CM_INVALID_PARAMETER;

    *key = nullptr;
    SessionPkcs12Context* ss_ctx = (SessionPkcs12Context*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    FileStorage& storage = ss_ctx->fileStorage;
    if (!storage.isOpen()) return RET_CM_NOT_AUTHORIZED;
    if (storage.isReadOnly()) return RET_CM_READONLY_SESSION;

    ParsonHelper json;
    if (!json.parse((const char*)keyParam)) return RET_CM_INVALID_JSON;

    const char* algo = json.getString("mechanismId");
    const char* param = json.getString("parameterId");
    if (!algo || (strlen(algo) == 0)) return RET_CM_INVALID_PARAMETER;

    SmartBA sba_privkey;
    int ret = private_key_generate(algo, param, &sba_privkey);
    if (ret != RET_OK) return ret;

    StoreBag* store_bag = new StoreBag();
    if (!store_bag) return RET_CM_GENERAL_ERROR;

    store_bag->setBagId(OID_PKCS12_P8_SHROUDED_KEY_BAG);
    store_bag->setData(StoreBag::BAG_TYPE::KEY, sba_privkey.pop());

    param = json.getString("label");
    if (param && (strlen(param) > 0)) {
        store_bag->setFriendlyName(param);
    }
    param = json.getString("application");
    if (param && (strlen(param) > 0)) {
        store_bag->setLocalKeyID(param);
    }
    store_bag->scanStdAttrs();

    const FileStorageParam& storage_param = storage.storageParam();
    store_bag->setPbes2Param(storage_param.bagKdf, storage_param.bagCipher);
    ret = store_bag->encodeBag(storage.password(), storage_param.iterations);
    if (ret != RET_OK) {
        delete store_bag;
        return ret;
    }

    storage.addBag(store_bag);
    storage.selectKey(store_bag);
    *key = (const CM_KEY_API*)&ss_ctx->keyApi;

    ret = storage.store();
    return ret;
}   //  cm_session_create_key

static CM_ERROR cm_session_delete_key (
        CM_SESSION_API* session,
        const CM_BYTEARRAY* baKeyId,
        const bool deleteRelatedObjects
)
{
    DEBUG_OUTPUT("cm_session_delete_key()");
    if (!session) return RET_CM_NO_SESSION;
    if (!baKeyId) return RET_CM_INVALID_PARAMETER;

    SessionPkcs12Context* ss_ctx = (SessionPkcs12Context*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    FileStorage& storage = ss_ctx->fileStorage;
    if (!storage.isOpen()) return RET_CM_NOT_AUTHORIZED;
    if (storage.isReadOnly()) return RET_CM_READONLY_SESSION;

    StoreBag* bag_to_del = nullptr;
    vector<StoreBag*> list_keys = storage.listBags(StoreBag::BAG_TYPE::KEY);
    DEBUG_OUTPUT(std::string("cm_session_delete_key(), count keys: ") + std::to_string(list_keys.size()));

    for (size_t i = 0; i < list_keys.size(); i++) {
        if (ba_cmp(list_keys[i]->keyId(), (ByteArray*)baKeyId) == 0) {
            bag_to_del = list_keys[i];
            break;
        }
    }

    if (!bag_to_del) return RET_CM_KEY_NOT_FOUND;

    if (storage.selectedKey() == bag_to_del) {
        storage.selectKey(nullptr);
    }
    storage.deleteBag(bag_to_del);

    if (deleteRelatedObjects) {
        vector<StoreBag*> list_certs = storage.listBags(StoreBag::BAG_TYPE::CERT);
        DEBUG_OUTPUT(std::string("cm_session_delete_key(), count certs: ") + std::to_string(list_certs.size()));

        for (size_t i = 0; i < list_certs.size(); i++) {
            SmartBA sba_keyid;
            int ret = keyid_by_cert(list_certs[i]->bagValue(), &sba_keyid);
            if ((ret == RET_OK) && (ba_cmp(sba_keyid.get(), (ByteArray*)baKeyId) == 0)) {
                storage.deleteBag(list_certs[i]);
            }
        }
    }

    const int ret = storage.store();
    return ret;
}   //  cm_session_delete_key

static CM_ERROR cm_session_get_selected_key (
        CM_SESSION_API* session,
        const CM_KEY_API** key
)
{
    DEBUG_OUTPUT("cm_session_get_selected_key()");
    if (!session) return RET_CM_NO_SESSION;
    if (!key) return RET_CM_INVALID_PARAMETER;

    *key = nullptr;
    SessionPkcs12Context* ss_ctx = (SessionPkcs12Context*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    FileStorage& storage = ss_ctx->fileStorage;
    if (!storage.isOpen()) return RET_CM_NOT_AUTHORIZED;
    if (!storage.selectedKey()) return RET_CM_KEY_NOT_SELECTED;

    *key = (const CM_KEY_API*)&ss_ctx->keyApi;
    return RET_OK;
}   //  cm_session_get_selected_key

static CM_ERROR cm_session_get_certificates (
        CM_SESSION_API* session,
        uint32_t* count,
        CM_BYTEARRAY*** abaCertificates
)
{
    DEBUG_OUTPUT("cm_session_get_certificates()");
    if (!session) return RET_CM_NO_SESSION;
    if (!count || !abaCertificates) return RET_CM_INVALID_PARAMETER;

    *count = 0;
    *abaCertificates = nullptr;
    SessionPkcs12Context* ss_ctx = (SessionPkcs12Context*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    FileStorage& storage = ss_ctx->fileStorage;
    if (!storage.isOpen()) return RET_CM_NOT_AUTHORIZED;

    vector<StoreBag*> list_certs = storage.listBags(StoreBag::BAG_TYPE::CERT);
    DEBUG_OUTPUT(std::string("cm_session_get_certificates(), count certs: ") + std::to_string(list_certs.size()));

    ByteArray** aba_certs = (ByteArray**)calloc(list_certs.size(), sizeof(ByteArray*));
    if (!aba_certs) return RET_CM_GENERAL_ERROR;

    for (size_t i = 0; i < list_certs.size(); i++) {
        aba_certs[i] = ba_copy_with_alloc(list_certs[i]->bagValue(), 0, 0);
        if (!aba_certs[i]) {
            for (size_t j = 0; j < i; j++) {
                ba_free(aba_certs[j]);
                aba_certs[j] = nullptr;
            }
            free(aba_certs);
            return RET_CM_GENERAL_ERROR;
        }
    }
    *abaCertificates = (CM_BYTEARRAY**)aba_certs;
    *count = (uint32_t)list_certs.size();
    return RET_OK;
}   //  cm_session_get_certificates

static CM_ERROR cm_session_add_certificate (
        CM_SESSION_API* session,
        const CM_BYTEARRAY* baCertEncoded
)
{
    DEBUG_OUTPUT("cm_session_add_certificate()");
    if (!session) return RET_CM_NO_SESSION;
    if (!baCertEncoded) return RET_CM_INVALID_PARAMETER;

    SessionPkcs12Context* ss_ctx = (SessionPkcs12Context*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    FileStorage& storage = ss_ctx->fileStorage;
    if (!storage.isOpen()) return RET_CM_NOT_AUTHORIZED;
    if (storage.isReadOnly()) return RET_CM_READONLY_SESSION;

    //  Check struct cert - calculate keyId
    SmartBA sba_keyid;
    int ret = keyid_by_cert((ByteArray*)baCertEncoded, &sba_keyid);
    if (ret != RET_OK) return RET_CM_INVALID_CERTIFICATE;

    vector<StoreBag*> list_certs = storage.listBags(StoreBag::BAG_TYPE::CERT);
    DEBUG_OUTPUT(std::string("cm_session_add_certificate(), count certs: ") + std::to_string(list_certs.size()));

    for (size_t i = 0; i < list_certs.size(); i++) {
        SmartBA sba_keyid2;
        int ret = keyid_by_cert(list_certs[i]->bagValue(), &sba_keyid2);
        if ((ret == RET_OK) && (ba_cmp(sba_keyid.get(), sba_keyid2.get()) == 0)) {
            return RET_OK;
        }
    }

    //  Make copy for store
    SmartBA sba_cert;
    if (!sba_cert.set(ba_copy_with_alloc((const ByteArray*)baCertEncoded, 0, 0))) {
        return RET_CM_GENERAL_ERROR;
    }

    StoreBag* store_bag = new StoreBag();
    if (!store_bag) return RET_CM_GENERAL_ERROR;

    store_bag->setBagId(OID_PKCS12_CERT_BAG);
    store_bag->setData(StoreBag::BAG_TYPE::CERT, sba_cert.pop());

    ret = store_bag->encodeBag();
    if (ret != RET_OK) {
        delete store_bag;
        return ret;
    }

    storage.addBag(store_bag);

    ret = storage.store();
    return ret;
}   //  cm_session_add_certificate

static CM_ERROR cm_session_delete_certificate (
        CM_SESSION_API* session,
        const CM_BYTEARRAY* baKeyId
)
{
    DEBUG_OUTPUT("cm_session_delete_certificate()");
    if (!session) return RET_CM_NO_SESSION;
    if (!baKeyId) return RET_CM_INVALID_PARAMETER;

    SessionPkcs12Context* ss_ctx = (SessionPkcs12Context*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    FileStorage& storage = ss_ctx->fileStorage;
    if (!storage.isOpen()) return RET_CM_NOT_AUTHORIZED;
    if (storage.isReadOnly()) return RET_CM_READONLY_SESSION;

    bool flag_found = false;
    vector<StoreBag*> list_certs = storage.listBags(StoreBag::BAG_TYPE::CERT);
    DEBUG_OUTPUT(std::string("cm_session_delete_certificate(), count certs: ") + std::to_string(list_certs.size()));

    for (size_t i = 0; i < list_certs.size(); i++) {
        SmartBA sba_keyid;
        int ret = keyid_by_cert(list_certs[i]->bagValue(), &sba_keyid);
        if ((ret == RET_OK) && (ba_cmp(sba_keyid.get(), (ByteArray*)baKeyId) == 0)) {
            storage.deleteBag(list_certs[i]);
            flag_found = true;
        }
    }
    if (!flag_found) return RET_CM_CERTIFICATE_NOT_FOUND;

    const int ret = storage.store();
    return ret;
}   //  cm_session_delete_certificate

static CM_ERROR cm_session_change_password (
        CM_SESSION_API* session,
        const CM_UTF8_CHAR* newPassword
)
{
    DEBUG_OUTPUT("cm_session_change_password()");
    if (!session) return RET_CM_NO_SESSION;
    if (!newPassword || (strlen((const char*) newPassword) == 0)) return RET_CM_INVALID_PARAMETER;

    SessionPkcs12Context* ss_ctx = (SessionPkcs12Context*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    FileStorage& storage = ss_ctx->fileStorage;
    if (!storage.isOpen()) return RET_CM_NOT_AUTHORIZED;
    if (storage.isReadOnly()) return RET_CM_READONLY_SESSION;

    const int ret = storage.changePassword((const char*) newPassword);
    return ret;
}   //  cm_session_change_password


void CmPkcs12::assignSessionFunc (
        CM_SESSION_API& session
)
{
    session.version             = CmPkcs12::CM_SESSION_API_V1;
    session.info                = cm_session_info;
    session.mechanismParameters = cm_session_mechanism_parameters;
    session.login               = cm_session_login;
    session.logout              = cm_session_logout;
    session.listKeys            = cm_session_list_keys;
    session.selectKey           = cm_session_select_key;
    session.createKey           = cm_session_create_key;
    session.importKey           = nullptr;
    session.deleteKey           = cm_session_delete_key;
    session.getSelectedKey      = cm_session_get_selected_key;
    session.getCertificates     = cm_session_get_certificates;
    session.addCertificate      = cm_session_add_certificate;
    session.deleteCertificate   = cm_session_delete_certificate;
    session.changePassword      = cm_session_change_password;
    session.randomBytes         = nullptr;
}   //  CmPkcs12::assignSessionFunc
