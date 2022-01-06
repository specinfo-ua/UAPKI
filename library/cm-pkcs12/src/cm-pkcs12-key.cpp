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
#include "key-wrap.h"
#include "parson-helper.h"
#include "private-key.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
    #define DEBUG_OUTCON(expression) expression
#endif


static CM_ERROR cm_key_get_info (CM_SESSION_API* session,
        CM_JSON_PCHAR* keyInfo, CM_BYTEARRAY** baKeyId)
{
    DEBUG_OUTCON(puts("cm_key_get_info()"));
    if (!session) return RET_CM_NO_SESSION;
    if (!keyInfo && !baKeyId) return RET_CM_INVALID_PARAMETER;

    SessionPkcs12Context *ss_ctx = (SessionPkcs12Context*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    FileStorage& storage = ss_ctx->fileStorage;
    if (!storage.isOpen()) return RET_CM_NOT_AUTHORIZED;

    StoreBag* selected_key = storage.selectedKey();
    if (!selected_key) return RET_CM_KEY_NOT_SELECTED;

    //  Set returned info in keyInfo
    if (keyInfo) {
        StoreKeyInfo key_info;
        if (!selected_key->getKeyInfo(key_info)) return RET_CM_GENERAL_ERROR;

        ParsonHelper json;
        if (!json.create()) return RET_CM_GENERAL_ERROR;

        const CM_ERROR cm_err = CmPkcs12::keyInfoToJson(key_info, json.rootObject());
        if (cm_err != RET_OK) return cm_err;

        if (!json.serialize((char**)keyInfo)) return RET_CM_GENERAL_ERROR;
    }

    //  Set returned info in keyInfo
    if (baKeyId) {
        *baKeyId = (CM_BYTEARRAY*)ba_copy_with_alloc(selected_key->keyId(), 0, 0);
    }

    return RET_OK;
}   //  cm_key_get_info

static CM_ERROR cm_key_get_public_key (CM_SESSION_API* session,
        CM_BYTEARRAY** baAlgorithmIdentifier, CM_BYTEARRAY** baPublicKey)
{
    DEBUG_OUTCON(puts("cm_key_get_public_key()"));
    if (!session) return RET_CM_NO_SESSION;
    if (!baAlgorithmIdentifier && !baPublicKey) return RET_CM_INVALID_PARAMETER;

    SessionPkcs12Context *ss_ctx = (SessionPkcs12Context*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    FileStorage& storage = ss_ctx->fileStorage;
    if (!storage.isOpen()) return RET_CM_NOT_AUTHORIZED;

    StoreBag* selected_key = storage.selectedKey();
    if (!selected_key) return RET_CM_KEY_NOT_SELECTED;

    const int ret = spki_by_privkeyinfo(selected_key->bagValue(), (ByteArray**)baAlgorithmIdentifier, (ByteArray**)baPublicKey);
    return ret;
}   //  cm_key_get_public_key

static CM_ERROR cm_key_sign (CM_SESSION_API* session,
        const CM_UTF8_CHAR* signAlgo, const CM_BYTEARRAY* baSignAlgoParams,
        const uint32_t count, const CM_BYTEARRAY** abaHashes, CM_BYTEARRAY*** abaSignatures)
{
    DEBUG_OUTCON(puts("cm_key_sign()"));
    if (!session) return RET_CM_NO_SESSION;
    if ((count == 0) || !abaHashes || !abaSignatures) return RET_CM_INVALID_PARAMETER;

    SessionPkcs12Context *ss_ctx = (SessionPkcs12Context*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    FileStorage& storage = ss_ctx->fileStorage;
    if (!storage.isOpen()) return RET_CM_NOT_AUTHORIZED;

    StoreBag* selected_key = storage.selectedKey();
    if (!selected_key) return RET_CM_KEY_NOT_SELECTED;

    const int ret = private_key_sign(selected_key->bagValue(), (const ByteArray**) abaHashes, count,
        (const char*) signAlgo, (const ByteArray*) baSignAlgoParams, (ByteArray***) abaSignatures);
    return ret;
}   //  cm_key_sign

static CM_ERROR cm_key_sign_init (CM_SESSION_API* session,
    const CM_UTF8_CHAR* signAlgo, const CM_BYTEARRAY* baSignAlgoParams)
{
    DEBUG_OUTCON(puts("cm_key_sign_init()"));
    if (!session) return RET_CM_NO_SESSION;
    if (!signAlgo) return RET_CM_INVALID_PARAMETER;

    SessionPkcs12Context* ss_ctx = (SessionPkcs12Context*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    FileStorage& storage = ss_ctx->fileStorage;
    if (!storage.isOpen()) return RET_CM_NOT_AUTHORIZED;

    StoreBag* selected_key = storage.selectedKey();
    if (!selected_key) return RET_CM_KEY_NOT_SELECTED;

    ss_ctx->resetSignLong();

    HashAlg hash_algo = HASH_ALG_UNDEFINED;
    const int ret = private_key_sign_check(selected_key->bagValue(), (const char*) signAlgo, (const ByteArray*) baSignAlgoParams, &hash_algo);
    if (ret != RET_OK) return ret;

    ss_ctx->ctxHash = hash_alloc(hash_algo);
    if (!ss_ctx->ctxHash) return RET_UNSUPPORTED;

    ss_ctx->hashAlgo = hash_algo;
    ss_ctx->aidSignAlgo.algorithm = string((const char*)signAlgo);
    ss_ctx->aidSignAlgo.baParameters = ba_copy_with_alloc((const ByteArray*) baSignAlgoParams, 0, 0);
    ss_ctx->activeBag = selected_key;
    return RET_OK;
}   //  cm_key_sign_init

static CM_ERROR cm_key_sign_update (CM_SESSION_API* session, const CM_BYTEARRAY* baData)
{
    DEBUG_OUTCON(puts("cm_key_sign_update()"));
    if (!session) return RET_CM_NO_SESSION;
    if (!baData) return RET_CM_INVALID_PARAMETER;

    SessionPkcs12Context* ss_ctx = (SessionPkcs12Context*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    FileStorage& storage = ss_ctx->fileStorage;
    if (!storage.isOpen()) return RET_CM_NOT_AUTHORIZED;

    StoreBag* selected_key = storage.selectedKey();
    if (!selected_key || !ss_ctx->activeBag || !ss_ctx->ctxHash) return RET_CM_KEY_NOT_SELECTED;

    const int ret = hash_update(ss_ctx->ctxHash, (const ByteArray*)baData);
    return ret;
}   //  cm_key_sign_update

static CM_ERROR cm_key_sign_final (CM_SESSION_API* session, CM_BYTEARRAY** baSignature)
{
    DEBUG_OUTCON(puts("cm_key_sign_final()"));
    if (!session) return RET_CM_NO_SESSION;
    if (!baSignature) return RET_CM_INVALID_PARAMETER;

    SessionPkcs12Context* ss_ctx = (SessionPkcs12Context*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    FileStorage& storage = ss_ctx->fileStorage;
    if (!storage.isOpen()) return RET_CM_NOT_AUTHORIZED;

    StoreBag* selected_key = storage.selectedKey();
    if (!selected_key || !ss_ctx->activeBag || !ss_ctx->ctxHash) return RET_CM_KEY_NOT_SELECTED;

    ByteArray* ba_hash = nullptr;
    int ret = hash_final(ss_ctx->ctxHash, &ba_hash);
    if (ret == RET_OK) {
        DEBUG_OUTCON(printf("cm_key_sign_final(), ba_hash: "); ba_print(stdout, ba_hash));
        ret = private_key_sign_single(
            ss_ctx->activeBag->bagValue(),
            (const char*)ss_ctx->aidSignAlgo.algorithm.c_str(),
            ss_ctx->aidSignAlgo.baParameters,
            ba_hash,
            (ByteArray**) baSignature
        );
        ba_free(ba_hash);
    }
    ss_ctx->resetSignLong();
    return ret;
}   //  cm_key_sign_final

static CM_ERROR cm_key_dh_wrap_key (CM_SESSION_API* session,
    const CM_UTF8_CHAR* kdfOid, const CM_UTF8_CHAR* wrapAlgOid,
    const uint32_t count, const CM_BYTEARRAY** abaPubkeys, const CM_BYTEARRAY** abaSessionKeys,
    CM_BYTEARRAY*** abaSalts, CM_BYTEARRAY*** abaWrappedKeys)
{
    DEBUG_OUTCON(puts("cm_key_dh_wrap_key()"));
    if (!session) return RET_CM_NO_SESSION;
    if (!kdfOid || !wrapAlgOid || (count == 0) || !abaPubkeys || !abaSessionKeys || !abaSalts || !abaWrappedKeys) return RET_CM_INVALID_PARAMETER;

    SessionPkcs12Context *ss_ctx = (SessionPkcs12Context*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    FileStorage& storage = ss_ctx->fileStorage;
    if (!storage.isOpen()) return RET_CM_NOT_AUTHORIZED;

    StoreBag* selected_key = storage.selectedKey();
    if (!selected_key) return RET_CM_KEY_NOT_SELECTED;

    const int ret = key_wrap(selected_key->bagValue(), true,
        (const char*)kdfOid, (const char*)wrapAlgOid,
        count, (const ByteArray**)abaPubkeys, (const ByteArray**)abaSessionKeys,
        (ByteArray***)abaSalts, (ByteArray***)abaWrappedKeys);
    return ret;
}   //  cm_key_dh_wrap_key

static CM_ERROR cm_key_dh_unwrap_key (CM_SESSION_API* session,
    const CM_UTF8_CHAR* kdfOid, const CM_UTF8_CHAR* wrapAlgOid,
    const uint32_t count, const CM_BYTEARRAY** abaPubkeys, const CM_BYTEARRAY** abaSalts, const CM_BYTEARRAY** abaWrappedKeys,
    CM_BYTEARRAY*** abaSessionKeys)
{
    DEBUG_OUTCON(puts("cm_key_dh_unwrap_key()"));
    if (!session) return RET_CM_NO_SESSION;
    if (!kdfOid || !wrapAlgOid || (count == 0) || !abaPubkeys || !abaWrappedKeys || !abaSessionKeys) return RET_CM_INVALID_PARAMETER;

    SessionPkcs12Context *ss_ctx = (SessionPkcs12Context*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    FileStorage& storage = ss_ctx->fileStorage;
    if (!storage.isOpen()) return RET_CM_NOT_AUTHORIZED;

    StoreBag* selected_key = storage.selectedKey();
    if (!selected_key) return RET_CM_KEY_NOT_SELECTED;

    const int ret = key_unwrap(selected_key->bagValue(),
        (const char*)kdfOid, (const char*)wrapAlgOid,
        count, (const ByteArray**)abaPubkeys, (const ByteArray**)abaSalts, (const ByteArray**)abaWrappedKeys,
        (ByteArray***)abaSessionKeys);
    return ret;
}   //  cm_key_dh_unwrap_key


void CmPkcs12::assignKeyFunc (CM_KEY_API& key)
{
    DEBUG_OUTCON(puts("CmPkcs12::assignKeyFunc()"));
    key.getInfo         = cm_key_get_info;
    key.getPublicKey    = cm_key_get_public_key;
    key.initKeyUsage    = nullptr;
    key.setOtp          = nullptr;
    key.sign            = cm_key_sign;
    key.signInit        = cm_key_sign_init;
    key.signUpdate      = cm_key_sign_update;
    key.signFinal       = cm_key_sign_final;
    key.getCertificates = nullptr;
    key.addCertificate  = nullptr;
    key.getCsr          = nullptr;
    key.dh              = nullptr;
    key.dhWrapKey       = cm_key_dh_wrap_key;
    key.dhUnwrapKey     = cm_key_dh_unwrap_key;
    key.decrypt         = nullptr;
    key.encrypt         = nullptr;
    key.setInfo         = nullptr;
    key.exportKey       = nullptr;
}
