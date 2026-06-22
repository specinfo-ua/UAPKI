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

#define FILE_MARKER "cm-cryptoki/cm-cryptoki-session.cpp"

#include <string.h>
#include "cm-cryptoki.h"
#include "cryptoki-const.h"
#include "dstu-ns.h"
#include "macros-internal.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include "uapkif.h"
#include "uapki-ns-util.h"

#include "cm-cryptoki-debug.h"


#define DEBUG_OUTPUT(msg)
#ifndef DEBUG_OUTPUT
DEBUG_OUTPUT_FUNC
#define DEBUG_OUTPUT(msg) debug_output(DEBUG_OUTSTREAM_DEFAULT, msg);
#endif


using namespace std;
using namespace UapkiNS;


static const char* APPLICATION_CERT_MARK_STR = "UAPKI-CERTIFICATE";
static const size_t MAXLEN_ID       = 32;
static const size_t MAXLEN_LABEL    = 32;


static CM_ERROR data_from_cert (
        const uint8_t* bufEncoded,
        const size_t lenEncoded,
        ByteArray** baSubject,
        ByteArray** baPublicKey,
        ByteArray** baSubjectKeyId
)
{
    int ret = RET_OK;
    SmartBA sba_encoded;
    Certificate_t* cert = (Certificate_t*)asn_decode_with_alloc(get_Certificate_desc(), bufEncoded, lenEncoded);
    if (!cert) return RET_CM_INVALID_CERTIFICATE;

    if (baSubject) {
        DO(asn_encode_ba(get_Name_desc(), &cert->tbsCertificate.subject, baSubject));
    }

    if (baPublicKey) {
        DO(asn_BITSTRING2ba(&cert->tbsCertificate.subjectPublicKeyInfo.subjectPublicKey, baPublicKey));
    }

    if (baSubjectKeyId) {
        DO(Util::extnValueFromExtensions(cert->tbsCertificate.extensions, OID_X509v3_SubjectKeyIdentifier, nullptr, &sba_encoded));
        DO(Util::decodeOctetString(sba_encoded.get(), baSubjectKeyId));
    }

cleanup:
    asn_free(get_Certificate_desc(), cert);
    return ret;
}   //  data_from_cert

static CryptokiStorage::GenerateKeyFlags parse_genkey_flags (
        JSON_Object* joFlags
)
{
    CryptokiStorage::GenerateKeyFlags rv_flags;
    rv_flags.keyAgreement = ParsonHelper::jsonObjectGetBoolean(joFlags, "keyAgreement", false);
    return rv_flags;
}   //  parse_genkey_flags


static CM_ERROR cm_session_info (
        CM_SESSION_API* session,
        CM_JSON_PCHAR* sessionInfo
)
{
    DEBUG_OUTPUT("cm_session_info()");
    if (!session) return RET_CM_NO_SESSION;
    if (!sessionInfo) return RET_CM_INVALID_PARAMETER;

    *sessionInfo = nullptr;
    CmCryptoki::SessionContext* ss_ctx = (CmCryptoki::SessionContext*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    CryptokiStorage& storage = ss_ctx->getStorage();
    if (!storage.isOpened()) return RET_CM_STORAGE_NOT_OPEN;

    return CmCryptoki::sessionInfoToJson(
        storage,
        (CM_JSON_PCHAR*)sessionInfo
    );
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

    CmCryptoki::SessionContext* ss_ctx = (CmCryptoki::SessionContext*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    CryptokiStorage& storage = ss_ctx->getStorage();
    if (!storage.isOpened()) return RET_CM_STORAGE_NOT_OPEN;

    return CmCryptoki::mechanismParamsToJson(
        storage,
        (const char*)mechanismId,
        parameterIds
    );
}   //  cm_session_mechanism_parameters

static CM_ERROR cm_session_login (
        CM_SESSION_API* session,
        const CM_UTF8_CHAR* password,
        const CM_JSON_PCHAR loginParams
)
{
    DEBUG_OUTPUT("cm_session_login()");
    (void)loginParams;
    if (!session) return RET_CM_NO_SESSION;
    if (!password || (strlen((const char*)password) == 0)) return RET_CM_INVALID_PARAMETER;

    CmCryptoki::SessionContext* ss_ctx = (CmCryptoki::SessionContext*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    CryptokiStorage& storage = ss_ctx->getStorage();
    const CM_ERROR cm_err = storage.login(CKU_USER, (CK_CHAR_PTR)password);
    return cm_err;
}   //  cm_session_login

static CM_ERROR cm_session_logout (
        CM_SESSION_API* session
)
{
    DEBUG_OUTPUT("cm_session_logout()");
    if (!session) return RET_CM_NO_SESSION;

    CmCryptoki::SessionContext* ss_ctx = (CmCryptoki::SessionContext*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    CryptokiStorage& storage = ss_ctx->getStorage();
    if (!storage.isOpened()) return RET_CM_STORAGE_NOT_OPEN;

    const CM_ERROR cm_err = storage.logout();
    return cm_err;
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

    CmCryptoki::SessionContext* ss_ctx = (CmCryptoki::SessionContext*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    CryptokiStorage& storage = ss_ctx->getStorage();
    if (!storage.isOpened()) return RET_CM_STORAGE_NOT_OPEN;
    if (!storage.isAuthorized()) return RET_CM_NOT_AUTHORIZED;

    vector<CryptokiStorage::KeyInfo> list_keyinfos;
    CM_ERROR cm_err = storage.findKeyPairs(list_keyinfos);
    DEBUG_OUTPUT(string("cm_session_list_keys(), count keys: ") + to_string(list_keyinfos.size()));
    if (cm_err != RET_OK) return cm_err;

    size_t idx = 0;
    //  Set returned keysInfo(JSON), optional
    if (keysInfo) {
        ParsonHelper json;
        if (!json.create()) return RET_CM_GENERAL_ERROR;

        JSON_Array* ja_keyinfos = json.setArray("keys");
        for (const auto& it : list_keyinfos) {
            json_array_append_value(ja_keyinfos, json_value_init_object());
            cm_err = CmCryptoki::keyInfoToJson(it, json_array_get_object(ja_keyinfos, idx++));
            if (cm_err != RET_OK) return cm_err;
        }

        if (!json.serialize((char**)keysInfo)) return RET_CM_GENERAL_ERROR;
    }

    //  Set returned abaKeyIds(array)
    ByteArray** aba_keyids = (ByteArray**)calloc(list_keyinfos.size(), sizeof(ByteArray*));
    if (!aba_keyids) return RET_CM_GENERAL_ERROR;

    idx = 0;
    for (auto& it : list_keyinfos) {
        aba_keyids[idx] = ba_alloc_from_uint8((const uint8_t*)it.keyId.data(), it.keyId.size());
        if (!aba_keyids[idx]) {
            for (size_t j = 0; j < idx; j++) {
                ba_free(aba_keyids[j]);
                aba_keyids[j] = nullptr;
            }
            ::free(aba_keyids);
            return RET_CM_GENERAL_ERROR;
        }
        idx++;
    }

    *abaKeyIds = (CM_BYTEARRAY**)aba_keyids;
    *count = (uint32_t)list_keyinfos.size();
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
    if (!baKeyId || !baKeyId->buf || (baKeyId->len == 0) || !key) return RET_CM_INVALID_PARAMETER;

    *key = nullptr;
    CmCryptoki::SessionContext* ss_ctx = (CmCryptoki::SessionContext*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    CryptokiStorage& storage = ss_ctx->getStorage();
    if (!storage.isOpened()) return RET_CM_STORAGE_NOT_OPEN;
    if (!storage.isAuthorized()) return RET_CM_NOT_AUTHORIZED;

    storage.selectKey();

    vector<CryptokiStorage::KeyInfo> list_keyinfos;
    CM_ERROR cm_err = storage.findKeyPairs(list_keyinfos);
    DEBUG_OUTPUT(string("cm_session_select_key(), count keys: ") + to_string(list_keyinfos.size()));
    if (cm_err != RET_OK) return cm_err;

    for (auto& it : list_keyinfos) {
        if (it.equalKeyId(baKeyId->buf, baKeyId->len)) {
            storage.selectKey(it);
            break;
        }
    }

    if (!storage.selectedKey().isPresent()) return RET_CM_KEY_NOT_FOUND;

    *key = ss_ctx->getKeyApi();
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
    CmCryptoki::SessionContext* ss_ctx = (CmCryptoki::SessionContext*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    CryptokiStorage& storage = ss_ctx->getStorage();
    if (!storage.isOpened()) return RET_CM_STORAGE_NOT_OPEN;
    if (storage.isReadOnly()) return RET_CM_READONLY_SESSION;
    if (!storage.isAuthorized()) return RET_CM_NOT_AUTHORIZED;

    ParsonHelper json;
    if (!json.parse((const char*)keyParam)) return RET_CM_INVALID_JSON;

    CryptokiStorage::KeyInfo new_keyinfo;
    if (!json.getString("mechanismId", new_keyinfo.mechanismId)) return RET_CM_INVALID_PARAMETER;
    json.getString("parameterId", new_keyinfo.parameterId);
    json.getString("label", new_keyinfo.label);

    CryptokiStorage::GenerateKeyFlags flags = parse_genkey_flags(json.getObject("flags"));
    CM_ERROR cm_err = storage.buildGenKeyPairParams(new_keyinfo);
    if (cm_err != RET_OK) return cm_err;

    storage.selectKey();
    cm_err = storage.generateKeyPair(flags, new_keyinfo);
    if (cm_err != RET_OK) return cm_err;

    cm_err = storage.getKeyInfo(new_keyinfo.hPrivateKey, new_keyinfo);
    if (cm_err != RET_OK) return cm_err;

    storage.selectKey(new_keyinfo);
    *key = ss_ctx->getKeyApi();
    return RET_OK;
}   //  cm_session_create_key

static CM_ERROR cm_session_delete_key (
        CM_SESSION_API* session,
        const CM_BYTEARRAY* baKeyId,
        const bool deleteRelatedObjects
)
{
    //  Note: now work for keypairs only, later will be for all (asym and sym) private-keys
    DEBUG_OUTPUT("cm_session_delete_key()");
    (void)deleteRelatedObjects;
    if (!session) return RET_CM_NO_SESSION;
    if (!baKeyId) return RET_CM_INVALID_PARAMETER;

    CmCryptoki::SessionContext* ss_ctx = (CmCryptoki::SessionContext*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    CryptokiStorage& storage = ss_ctx->getStorage();
    if (!storage.isOpened()) return RET_CM_STORAGE_NOT_OPEN;
    if (storage.isReadOnly()) return RET_CM_READONLY_SESSION;
    if (!storage.isAuthorized()) return RET_CM_NOT_AUTHORIZED;

    CryptokiStorage::KeyInfo* del_keyinfo = nullptr;
    vector<CryptokiStorage::KeyInfo> list_keyinfos;
    CM_ERROR cm_err = storage.findKeyPairs(list_keyinfos);
    DEBUG_OUTPUT(string("cm_session_delete_key(), count keys: ") + to_string(list_keyinfos.size()));
    if (cm_err != RET_OK) return cm_err;

    for (auto& it : list_keyinfos) {
        if (CryptokiStorage::cmpBuffers(it.keyId, baKeyId->buf, baKeyId->len)) {
            del_keyinfo = &it;
            break;
        }
    }
    if (!del_keyinfo) return RET_CM_KEY_NOT_FOUND;

    cm_err = storage.deleteKey(*del_keyinfo);
    return cm_err;
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
    CmCryptoki::SessionContext* ss_ctx = (CmCryptoki::SessionContext*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    CryptokiStorage& storage = ss_ctx->getStorage();
    if (!storage.isOpened()) return RET_CM_STORAGE_NOT_OPEN;
    if (!storage.isAuthorized()) return RET_CM_NOT_AUTHORIZED;
    if (!storage.selectedKey().isPresent()) return RET_CM_KEY_NOT_FOUND;

    *key = ss_ctx->getKeyApi();
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
    CmCryptoki::SessionContext* ss_ctx = (CmCryptoki::SessionContext*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    CryptokiStorage& storage = ss_ctx->getStorage();
    if (!storage.isOpened()) return RET_CM_STORAGE_NOT_OPEN;

    vector<CK_OBJECT_HANDLE> list_certobjects;
    CM_ERROR cm_err = storage.findCerts(
        false,
        string(APPLICATION_CERT_MARK_STR),
        list_certobjects
    );
    DEBUG_OUTPUT(string("cm_session_get_certificates(), count certs: ") + to_string(list_certobjects.size()));
    if (cm_err != RET_OK) return cm_err;

    CM_BYTEARRAY** aba_certs = (CM_BYTEARRAY**)calloc(list_certobjects.size(), sizeof(CM_BYTEARRAY*));
    if (!aba_certs) return RET_CM_GENERAL_ERROR;

    for (size_t i = 0; i < list_certobjects.size(); i++) {
        cm_err = storage.readFile(list_certobjects[i], &aba_certs[i]);
        if (cm_err != RET_OK) {
            for (size_t j = 0; j < i; j++) {
                ba_free((ByteArray*)aba_certs[j]);
                aba_certs[j] = nullptr;
            }
            ::free(aba_certs);
            return RET_CM_TOKEN_ERROR;
        }
    }

    *abaCertificates = aba_certs;
    *count = (uint32_t)list_certobjects.size();
    return RET_OK;
}   //  cm_session_get_certificates

static CM_ERROR cm_session_add_certificate (
        CM_SESSION_API* session,
        const CM_BYTEARRAY* baCertEncoded
)
{
    DEBUG_OUTPUT("cm_session_add_certificate()");
    if (!session) return RET_CM_NO_SESSION;
    if (!baCertEncoded || !baCertEncoded->buf || (baCertEncoded->len == 0)) return RET_CM_INVALID_PARAMETER;

    SmartBA sba_publickey, sba_subject, sba_subjectkeyid;
    CM_ERROR cm_err = data_from_cert(
        baCertEncoded->buf,
        baCertEncoded->len,
        &sba_subject,
        &sba_publickey,
        &sba_subjectkeyid
    );
    if (cm_err != RET_OK) return cm_err;

    Cryptoki::Buffer buf_cert;
    if (!CryptokiStorage::bufferFromBa((const ByteArray*)baCertEncoded, buf_cert)) return RET_CM_GENERAL_ERROR;

    CmCryptoki::SessionContext* ss_ctx = (CmCryptoki::SessionContext*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    CryptokiStorage& storage = ss_ctx->getStorage();
    if (!storage.isOpened()) return RET_CM_STORAGE_NOT_OPEN;
    if (storage.isReadOnly()) return RET_CM_READONLY_SESSION;
    if (!storage.isAuthorized()) return RET_CM_NOT_AUTHORIZED;

    vector<CK_OBJECT_HANDLE> list_certobjects;
    cm_err = storage.findCerts(
        false,
        string(APPLICATION_CERT_MARK_STR),
        list_certobjects
    );
    DEBUG_OUTPUT(string("cm_session_add_certificate(), count certs: ") + to_string(list_certobjects.size()));
    if (cm_err != RET_OK) return cm_err;

    for (const auto& it : list_certobjects) {
        Cryptoki::Buffer buf_encoded;
        cm_err = storage.readFile(it, buf_encoded);
        if (cm_err != RET_OK) return cm_err;

        if (CryptokiStorage::cmpBuffers(buf_encoded, buf_cert)) {
            DEBUG_OUTPUT(string("cm_session_add_certificate() - certificate found in storage"));
            return RET_OK;
        }
    }

    const CryptokiStorage::KeyInfo* found_keyinfo = nullptr;
    vector<CryptokiStorage::KeyInfo> list_keyinfos;
    cm_err = storage.findKeyPairs(list_keyinfos);
    DEBUG_OUTPUT(string("cm_session_add_certificate(), count keys: ") + to_string(list_keyinfos.size()));
    if (cm_err != RET_OK) return cm_err;

    for (const auto& it : list_keyinfos) {
        if (it.equalPublicKey(sba_publickey.buf(), sba_publickey.size())) {
            found_keyinfo = &it;
            DEBUG_OUTPUT(string("cm_session_add_certificate() - key found in storage"));
            break;
        }
    }

    const CK_CERTIFICATE_CATEGORY cert_cat = (found_keyinfo) ? CK_CERTIFICATE_CATEGORY_TOKEN_USER : CK_CERTIFICATE_CATEGORY_OTHER_ENTITY;
    const CK_ATTRIBUTE attr_certcat = { Cryptoki::CKA::CERTIFICATE_CATEGORY, (CK_VOID_PTR)&cert_cat, (CK_ULONG)sizeof(CK_CERTIFICATE_CATEGORY) };
    const CK_ATTRIBUTE attr_subject = { Cryptoki::CKA::SUBJECT, (CK_VOID_PTR)sba_subject.buf(), (CK_ULONG)sba_subject.size() };
    CK_OBJECT_HANDLE h_addedfile;
    Cryptoki::Buffer buf_id;
    string s_label;

    if (found_keyinfo) {
        buf_id = found_keyinfo->id;
        s_label = found_keyinfo->label;
    }
    else {
        if (!CryptokiStorage::bufferFromBa((const ByteArray*)sba_subjectkeyid.get(), buf_id)) return RET_CM_GENERAL_ERROR;
        if (buf_id.size() > MAXLEN_ID) buf_id.resize(MAXLEN_ID);
        s_label = CmCryptoki::bufferToHex((const ByteArray*)sba_subjectkeyid.get(), false);
        if (s_label.length() > MAXLEN_LABEL) s_label.resize(MAXLEN_LABEL);
    }

    vector<CK_ATTRIBUTE> template_add;
    template_add.push_back(attr_certcat);
    template_add.push_back(attr_subject);
    cm_err = storage.addCert(
        true,
        false,
        buf_cert,
        buf_id,
        s_label,
        template_add,
        h_addedfile
    );

    return cm_err;
}   //  cm_session_add_certificate

static CM_ERROR cm_session_delete_certificate (
        CM_SESSION_API* session,
        const CM_BYTEARRAY* baKeyId
)
{
    DEBUG_OUTPUT("cm_session_delete_certificate()");
    if (!session) return RET_CM_NO_SESSION;
    if (!baKeyId || !baKeyId->buf || (baKeyId->len == 0)) return RET_CM_INVALID_PARAMETER;

    CmCryptoki::SessionContext* ss_ctx = (CmCryptoki::SessionContext*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    CryptokiStorage& storage = ss_ctx->getStorage();
    if (!storage.isOpened()) return RET_CM_STORAGE_NOT_OPEN;
    if (storage.isReadOnly()) return RET_CM_READONLY_SESSION;
    if (!storage.isAuthorized()) return RET_CM_NOT_AUTHORIZED;

    vector<CK_OBJECT_HANDLE> list_certobjects;
    CM_ERROR cm_err = storage.findCerts(
        false,
        string(APPLICATION_CERT_MARK_STR),
        list_certobjects
    );
    DEBUG_OUTPUT(string("cm_session_delete_certificate(), count certs: ") + to_string(list_certobjects.size()));
    if (cm_err != RET_OK) return cm_err;

    for (const auto& it : list_certobjects) {
        Cryptoki::Buffer buf_encoded;
        cm_err = storage.readFile(it, buf_encoded);
        if (cm_err != RET_OK) return cm_err;

        SmartBA sba_subjectkeyid;
        cm_err = data_from_cert(
            buf_encoded.data(),
            buf_encoded.size(),
            nullptr,
            nullptr,
            &sba_subjectkeyid
        );
        if (cm_err != RET_OK) return cm_err;

        if ((baKeyId->len == sba_subjectkeyid.size()) && (memcmp(baKeyId->buf, sba_subjectkeyid.buf(), sba_subjectkeyid.size()) == 0)) {
            cm_err = storage.deleteFile(it);
            return cm_err;
        }
    }

    return RET_CM_CERTIFICATE_NOT_FOUND;
}   //  cm_session_delete_certificate

static CM_ERROR cm_session_change_password (
        CM_SESSION_API* session,
        const CM_UTF8_CHAR* newPassword
)
{
    DEBUG_OUTPUT("cm_session_change_password()");
    if (!session) return RET_CM_NO_SESSION;
    if (!newPassword) return RET_CM_INVALID_PARAMETER;

    CmCryptoki::SessionContext* ss_ctx = (CmCryptoki::SessionContext*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    CryptokiStorage& storage = ss_ctx->getStorage();
    if (!storage.isOpened()) return RET_CM_STORAGE_NOT_OPEN;
    if (storage.isReadOnly()) return RET_CM_READONLY_SESSION;
    if (!storage.isAuthorized()) return RET_CM_NOT_AUTHORIZED;

    const CM_ERROR cm_err = storage.changePassword((const char*)newPassword);
    return cm_err;
}   //  cm_session_change_password

static CM_ERROR cm_session_random_bytes (
        CM_SESSION_API* session,
        CM_BYTEARRAY* baBuffer
)
{
    DEBUG_OUTPUT("cm_session_random_bytes()");
    if (!session) return RET_CM_NO_SESSION;

    CmCryptoki::SessionContext* ss_ctx = (CmCryptoki::SessionContext*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    CryptokiStorage& storage = ss_ctx->getStorage();
    if (!storage.isOpened()) return RET_CM_STORAGE_NOT_OPEN;

    const CM_ERROR cm_err = storage.randomBytes(baBuffer);
    return cm_err;
}   //  cm_session_random_bytes


void CmCryptoki::SessionContext::assignSessionApi (
        CM_SESSION_API& session
)
{
    session.version = CmCryptoki::CM_SESSION_API_V1;
    session.reserved = 0;
    *((void**)&session.ctx) = this;
    session.info = cm_session_info;
    session.mechanismParameters = cm_session_mechanism_parameters;
    session.login = (cm_session_login_f)cm_session_login;
    session.logout = cm_session_logout;
    session.listKeys = cm_session_list_keys;
    session.selectKey = cm_session_select_key;
    session.createKey = cm_session_create_key;
    session.importKey = nullptr;
    session.deleteKey = cm_session_delete_key;
    session.getSelectedKey = cm_session_get_selected_key;
    session.getCertificates = cm_session_get_certificates;
    session.addCertificate = cm_session_add_certificate;
    session.deleteCertificate = cm_session_delete_certificate;
    session.changePassword = cm_session_change_password;
    session.randomBytes = cm_session_random_bytes;
}
