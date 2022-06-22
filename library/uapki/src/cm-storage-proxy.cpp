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

#include "cm-storage-proxy.h"
#include "oid-utils.h"
#include "uapki-errors.h"
#include <stdio.h>


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


CmStorageProxy::CmStorageProxy (void)
    : m_IsInitialized(false)
    , m_IsAuthorizedSession(false)
    , m_Session(nullptr)
    , m_SelectedKey(nullptr)
{
    DEBUG_OUTCON(puts("CmStorageProxy::CmStorageProxy()"));
}

CmStorageProxy::~CmStorageProxy (void)
{
    DEBUG_OUTCON(puts("CmStorageProxy::~CmStorageProxy()"));
    if (isOpenedStorage()) {
        storageClose();
    }
    if (isInitialized()) {
        providerDeinit();
    }
}

bool CmStorageProxy::load (const string& libName, const string& dir)
{
    return m_CmLoader.load(libName, dir);
}

void CmStorageProxy::cmFree (void* block)
{
    m_CmLoader.blockFree(block);
}

void CmStorageProxy::cmbaFree (CM_BYTEARRAY* ba)
{
    m_CmLoader.baFree(ba);
}

void CmStorageProxy::arrayCmbaFree (const uint32_t count, CM_BYTEARRAY** arrayBa)
{
    if ((count > 0) && arrayBa) {
        for (uint32_t i = 0; i < count; i++) {
            cmbaFree(arrayBa[i]);
            arrayBa[i] = nullptr;
        }
        cmFree(arrayBa);
    }
}

int CmStorageProxy::providerInfo (string& providerInfo)
{
    providerInfo.clear();

    char* s_providerinfo = nullptr;
    const int ret = m_CmLoader.info((CM_JSON_PCHAR*)&s_providerinfo);
    if (ret != RET_OK) return ret;

    if (s_providerinfo) {
        providerInfo = string(s_providerinfo);
        m_CmLoader.blockFree(s_providerinfo);
    }
    return RET_OK;
}

int CmStorageProxy::providerInit (const string& providerParams)
{
    const int ret = m_CmLoader.init(!providerParams.empty() ? (const CM_JSON_PCHAR)providerParams.c_str() : nullptr);
    m_IsInitialized = (ret == RET_OK);
    DEBUG_OUTCON(printf("CmStorageProxy::providerInit, provider is-initialized=%d\n", (int)m_IsInitialized));
    return ret;
}

int CmStorageProxy::providerDeinit (void)
{
    int ret = RET_OK;
    if (isInitialized()) {
        ret = m_CmLoader.deinit();
        m_IsInitialized = false;
        DEBUG_OUTCON(puts("CmStorageProxy::providerDeinit, provider is deinitialized"));
    }
    return ret;
}

int CmStorageProxy::storageList (string& storageList)
{
    CM_JSON_PCHAR json_listuris = nullptr;
    const int ret = m_CmLoader.listStorages(&json_listuris);
    if ((ret == RET_OK) && json_listuris) {
        storageList = string((char*)json_listuris);
        cmFree(json_listuris);
    }
    return ret;
}

int CmStorageProxy::storageInfo (const string& storageId, string& storageInfo)
{
    CM_JSON_PCHAR json_storageinfo = nullptr;
    const int ret = m_CmLoader.storageInfo(storageId.c_str(), &json_storageinfo);
    if ((ret == RET_OK) && json_storageinfo) {
        storageInfo = string((char*)json_storageinfo);
        cmFree(json_storageinfo);
    }
    return ret;
}

int CmStorageProxy::storageOpen (const string& storageId, const CM_OPEN_MODE openMode, const string& openParams)
{
    const int ret = m_CmLoader.open(
        storageId.c_str(),
        openMode,
        !openParams.empty() ? (const CM_JSON_PCHAR)openParams.c_str() : nullptr,
        &m_Session
    );
    m_IsAuthorizedSession = (ret == RET_OK);
    return ret;
}

int CmStorageProxy::storageClose (void)
{
    int ret = RET_OK;
    if (isAuthorizedSession()) {
        ret = sessionLogout();
    }
    if (isOpenedStorage()) {
        ret = m_CmLoader.close(m_Session);
        m_Session = nullptr;
        DEBUG_OUTCON(puts("CmStorageProxy::storageClose, storage is cloded"));
    }
    return ret;
}

int CmStorageProxy::storageFormat (const string& storageId, const char* soPassword, const char* userPassword)
{
    const int ret = m_CmLoader.format(storageId.c_str(), soPassword, userPassword);
    return ret;
}

int CmStorageProxy::sessionInfo (string& sessionInfo)
{
    CM_JSON_PCHAR json_sesinfo = nullptr;
    const int ret = (int)m_Session->info(m_Session, &json_sesinfo);
    if ((ret == RET_OK) && json_sesinfo) {
        sessionInfo = string((char*)json_sesinfo);
        cmFree(json_sesinfo);
    }
    return ret;
}

int CmStorageProxy::sessionMechanismParameters (const string& mechanismId, string& parameterIds)
{
    CM_JSON_PCHAR json_paramids = nullptr;
    const int ret = (int)m_Session->mechanismParameters(m_Session, (CM_UTF8_CHAR*)mechanismId.c_str(), &json_paramids);
    if ((ret == RET_OK) && json_paramids) {
        parameterIds = string((char*)json_paramids);
        cmFree(json_paramids);
    }
    return ret;
}

int CmStorageProxy::sessionLogin (const char* password, const void* reserved)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;

    const int ret = (int)m_Session->login(m_Session, (const CM_UTF8_CHAR*)password, reserved);
    DEBUG_OUTCON(printf("CmStorageProxy::sessionLogin, ret: %d\n", ret));
    return ret;
}

int CmStorageProxy::sessionLogout (void)
{
    int ret = RET_OK;
    if (isAuthorizedSession()) {
        ret = (int)m_Session->logout(m_Session);
        m_IsAuthorizedSession = false;
        DEBUG_OUTCON(puts("CmStorageProxy::storageClose, authorized session is reset"));
    }
    return ret;
}

int CmStorageProxy::sessionCreateKey (const string& keyParam)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_Session->createKey) return RET_UAPKI_NOT_SUPPORTED;

    const int ret = (int)m_Session->createKey(m_Session, (CM_JSON_PCHAR)keyParam.c_str(), &m_SelectedKey);
    return ret;
}

int CmStorageProxy::sessionDeleteKey (const ByteArray* baKeyId, const bool deleteRelatedObjects)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_Session->deleteKey) return RET_UAPKI_NOT_SUPPORTED;

    const int ret = (int)m_Session->deleteKey(m_Session, (CM_BYTEARRAY*)baKeyId, deleteRelatedObjects);
    return ret;
}

int CmStorageProxy::sessionImportKey (const ByteArray* baP8container, const char* password, const string& keyParam)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_Session->importKey) return RET_UAPKI_NOT_SUPPORTED;
    if (!baP8container) return RET_UAPKI_INVALID_PARAMETER;

    const int ret = (int)m_Session->importKey(
        m_Session,
        (const CM_BYTEARRAY*) baP8container,
        (const CM_UTF8_CHAR*) password,
        (CM_JSON_PCHAR)keyParam.c_str(),
        &m_SelectedKey
    );
    return ret;
}

int CmStorageProxy::sessionListKeys (vector<ByteArray*>& vbaKeyIds)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_Session->listKeys) return RET_UAPKI_NOT_SUPPORTED;

    uint32_t cnt_keys = 0;
    CM_BYTEARRAY** cmba_keyids = nullptr;
    const int ret = (int)m_Session->listKeys(m_Session, &cnt_keys, &cmba_keyids, nullptr);
    if (ret != RET_OK) return ret;

    vbaKeyIds.resize(cnt_keys);
    for (uint32_t i = 0; i < cnt_keys; i++) {
        vbaKeyIds[i] = ba_copy_with_alloc((const ByteArray*)cmba_keyids[i], 0, 0);
    }
    arrayCmbaFree(cnt_keys, cmba_keyids);
    return ret;
}

int CmStorageProxy::sessionListKeys (vector<ByteArray*>& vbaKeyIds, string& infoKeys)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_Session->listKeys) return RET_UAPKI_NOT_SUPPORTED;

    uint32_t cnt_keys = 0;
    CM_BYTEARRAY** cmba_keyids = nullptr;
    CM_JSON_PCHAR json_keysinfo = nullptr;
    const int ret = (int)m_Session->listKeys(m_Session, &cnt_keys, &cmba_keyids, &json_keysinfo);
    if (ret != RET_OK) return ret;

    vbaKeyIds.resize(cnt_keys);
    for (uint32_t i = 0; i < cnt_keys; i++) {
        vbaKeyIds[i] = ba_copy_with_alloc((const ByteArray*)cmba_keyids[i], 0, 0);
    }
    arrayCmbaFree(cnt_keys, cmba_keyids);

    if (json_keysinfo) {
        infoKeys = string((char*)json_keysinfo);
        cmFree(json_keysinfo);
    }
    return ret;
}

int CmStorageProxy::sessionSelectKey (const ByteArray* baKeyId)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_Session->selectKey) return RET_UAPKI_NOT_SUPPORTED;

    const int ret = (int)m_Session->selectKey(m_Session, (const CM_BYTEARRAY*)baKeyId, &m_SelectedKey);
    return ret;
}

int CmStorageProxy::sessionAddCertificate (const ByteArray* baCert)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_Session->addCertificate) return RET_UAPKI_NOT_SUPPORTED;
    if (!baCert) return RET_UAPKI_INVALID_PARAMETER;

    const int ret = (int)m_Session->addCertificate(m_Session, (const CM_BYTEARRAY*)baCert);
    return ret;
}

int CmStorageProxy::sessionDeleteCertificate (const ByteArray* baKeyId)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_Session->deleteCertificate) return RET_UAPKI_NOT_SUPPORTED;

    const int ret = (int)m_Session->deleteCertificate(m_Session, (const CM_BYTEARRAY*)baKeyId);
    return ret;
}

int CmStorageProxy::sessionGetCertificates (vector<ByteArray*>& vbaCerts)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_Session->getCertificates) return RET_UAPKI_NOT_SUPPORTED;

    uint32_t cnt_certs = 0;
    CM_BYTEARRAY** cmba_certs = nullptr;
    const int ret = (int)m_Session->getCertificates(m_Session, &cnt_certs, &cmba_certs);
    if (ret != RET_OK) return ret;

    vbaCerts.resize(cnt_certs);
    for (uint32_t i = 0; i < cnt_certs; i++) {
        vbaCerts[i] = ba_copy_with_alloc((const ByteArray*)cmba_certs[i], 0, 0);
    }
    arrayCmbaFree(cnt_certs, cmba_certs);
    return ret;
}

int CmStorageProxy::sessionChangePassword (const char* newPassword)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_Session->changePassword) return RET_UAPKI_NOT_SUPPORTED;

    const int ret = (int)m_Session->changePassword(m_Session, (const CM_UTF8_CHAR*)newPassword);
    return ret;
}

int CmStorageProxy::sessionRandomBytes (ByteArray* baBuffer)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_Session->randomBytes) return RET_UAPKI_NOT_SUPPORTED;
    if (!baBuffer) return RET_UAPKI_INVALID_PARAMETER;

    const int ret = (int)m_Session->randomBytes(m_Session, (CM_BYTEARRAY*)baBuffer);
    return ret;
}

int CmStorageProxy::keyGetInfo (string& keyInfo, ByteArray** baKeyId)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_SelectedKey) return RET_UAPKI_KEY_NOT_SELECTED;
    if (!m_SelectedKey->getInfo) return RET_UAPKI_NOT_SUPPORTED;

    CM_JSON_PCHAR json_keyinfo = nullptr;
    CM_BYTEARRAY* cmba_keyid = nullptr;
    const int ret = (int)m_SelectedKey->getInfo(m_Session, &json_keyinfo, (baKeyId) ? &cmba_keyid : nullptr);
    if (ret == RET_OK) {
        if (json_keyinfo) {
            keyInfo = string((char*)json_keyinfo);
        }
        if (baKeyId && cmba_keyid) {
            *baKeyId = ba_copy_with_alloc((const ByteArray*)cmba_keyid, 0, 0);
        }
    }
    cmFree(json_keyinfo);
    cmbaFree(cmba_keyid);
    return ret;
}

int CmStorageProxy::keyGetInfo (ByteArray** baKeyId)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_SelectedKey) return RET_UAPKI_KEY_NOT_SELECTED;
    if (!m_SelectedKey->getInfo) return RET_UAPKI_NOT_SUPPORTED;
    if (!baKeyId) return RET_UAPKI_INVALID_PARAMETER;

    CM_BYTEARRAY* cmba_keyid = nullptr;
    const int ret = (int)m_SelectedKey->getInfo(m_Session, nullptr, &cmba_keyid);
    if (ret == RET_OK) {
        *baKeyId = ba_copy_with_alloc((const ByteArray*)cmba_keyid, 0, 0);
    }
    cmbaFree(cmba_keyid);
    return ret;
}

int CmStorageProxy::keyGetInfo (string& keyInfo)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_SelectedKey) return RET_UAPKI_KEY_NOT_SELECTED;
    if (!m_SelectedKey->getInfo) return RET_UAPKI_NOT_SUPPORTED;

    CM_JSON_PCHAR json_keyinfo = nullptr;
    const int ret = (int)m_SelectedKey->getInfo(m_Session, &json_keyinfo, nullptr);
    if (ret == RET_OK) {
        if (json_keyinfo) {
            keyInfo = string((char*)json_keyinfo);
        }
    }
    cmFree(json_keyinfo);
    return ret;
}

int CmStorageProxy::keyGetPublicKey (ByteArray** baAlgoId, ByteArray** baPublicKey)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_SelectedKey) return RET_UAPKI_KEY_NOT_SELECTED;
    if (!m_SelectedKey->getPublicKey) return RET_UAPKI_NOT_SUPPORTED;

    CM_BYTEARRAY* cmba_algo = nullptr;
    CM_BYTEARRAY* cmba_publickey = nullptr;
    const int ret = (int)m_SelectedKey->getPublicKey(m_Session, &cmba_algo, &cmba_publickey);
    if (ret == RET_OK) {
        if (baAlgoId) {
            *baAlgoId = ba_copy_with_alloc((const ByteArray*)cmba_algo, 0, 0);
        }
        if (baPublicKey) {
            *baPublicKey = ba_copy_with_alloc((const ByteArray*)cmba_publickey, 0, 0);
        }
    }
    cmbaFree(cmba_algo);
    cmbaFree(cmba_publickey);
    return ret;
}

int CmStorageProxy::keyInitUsage (void* param)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_SelectedKey) return RET_UAPKI_KEY_NOT_SELECTED;
    if (!m_SelectedKey->initKeyUsage) return RET_UAPKI_NOT_SUPPORTED;

    const int ret = (int)m_SelectedKey->initKeyUsage(m_Session, param);
    return ret;
}

int CmStorageProxy::keySetOtp (const char* otp)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_SelectedKey) return RET_UAPKI_KEY_NOT_SELECTED;
    if (!m_SelectedKey->setOtp) return RET_UAPKI_NOT_SUPPORTED;

    const int ret = (int)m_SelectedKey->setOtp(m_Session, (const CM_UTF8_CHAR*)otp);
    return ret;
}

int CmStorageProxy::keySign (const string& signAlgo, const ByteArray* baSignAlgoParams,
                    const vector<ByteArray*>& vbaHashes, vector<ByteArray*>& vbaSignatures)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_SelectedKey) return RET_UAPKI_KEY_NOT_SELECTED;
    if (!m_SelectedKey->sign) return RET_UAPKI_NOT_SUPPORTED;
    if (vbaHashes.empty()) return RET_UAPKI_INVALID_PARAMETER;

    CM_BYTEARRAY** cmba_signatures = nullptr;
    const int ret = (int)m_SelectedKey->sign(
        m_Session,
        (const CM_UTF8_CHAR*)signAlgo.c_str(),
        (const CM_BYTEARRAY*)baSignAlgoParams,
        (uint32_t)vbaHashes.size(),
        (const CM_BYTEARRAY**)vbaHashes.data(),
        &cmba_signatures
    );
    if (ret == RET_OK) {
        vbaSignatures.resize(vbaHashes.size());
        for (size_t i = 0; i < vbaSignatures.size(); i++) {
            vbaSignatures[i] = ba_copy_with_alloc((const ByteArray*)cmba_signatures[i], 0, 0);
        }
        arrayCmbaFree((uint32_t)vbaSignatures.size(), cmba_signatures);
    }
    return ret;
}

int CmStorageProxy::keySignInit (const string& signAlgo, const ByteArray* baSignAlgoParams)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_SelectedKey) return RET_UAPKI_KEY_NOT_SELECTED;
    if (!m_SelectedKey->signInit) return RET_UAPKI_NOT_SUPPORTED;

    const int ret = (int)m_SelectedKey->signInit(m_Session, (const CM_UTF8_CHAR*)signAlgo.c_str(), (const CM_BYTEARRAY*)baSignAlgoParams);
    return ret;
}

int CmStorageProxy::keySignUpdate (const ByteArray* baData)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_SelectedKey) return RET_UAPKI_KEY_NOT_SELECTED;
    if (!m_SelectedKey->signUpdate) return RET_UAPKI_NOT_SUPPORTED;

    const int ret = (int)m_SelectedKey->signUpdate(m_Session, (const CM_BYTEARRAY*)baData);
    return ret;
}

int CmStorageProxy::keySignFinal (ByteArray** baSignature)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_SelectedKey) return RET_UAPKI_KEY_NOT_SELECTED;
    if (!m_SelectedKey->signFinal) return RET_UAPKI_NOT_SUPPORTED;
    if (!baSignature) return RET_UAPKI_INVALID_PARAMETER;

    CM_BYTEARRAY* cmba_signature = nullptr;
    const int ret = (int)m_SelectedKey->signFinal(m_Session, &cmba_signature);
    if (ret == RET_OK) {
        *baSignature = ba_copy_with_alloc((const ByteArray*)cmba_signature, 0, 0);
    }
    cmbaFree(cmba_signature);
    return ret;
}

int CmStorageProxy::keySignData (const string& signAlgo, const ByteArray* baSignAlgoParams,
                    const ByteArray* baData, ByteArray** baSignature)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_SelectedKey) return RET_UAPKI_KEY_NOT_SELECTED;
    if (!m_SelectedKey->sign) return RET_UAPKI_NOT_SUPPORTED;
    if (!baData || !baSignature) return RET_UAPKI_INVALID_PARAMETER;

    const SignAlg sign_alg = signature_from_oid(signAlgo.c_str());
    if (sign_alg == SIGN_UNDEFINED) return RET_UAPKI_UNSUPPORTED_ALG;

    HashAlg hash_alg = HASH_ALG_UNDEFINED;
    if (sign_alg != SIGN_RSA_PSS) {
        hash_alg = hash_from_oid(signAlgo.c_str());
    }
    else {
        //TODO: later impl SIGN_RSA_PSS, see pkcs12 - DO(hash_from_rsa_pss(baSignAlgoParams, &hash_alg));
    }
    if (hash_alg == HASH_ALG_UNDEFINED) return RET_UAPKI_UNSUPPORTED_ALG;

    ByteArray* ba_hash = nullptr;
    int ret = ::hash(hash_alg, (const ByteArray*)baData, &ba_hash);
    if (ret != RET_OK) return ret;

    CM_BYTEARRAY** cmba_signatures = nullptr;
    vector<ByteArray*> aba_hashes;
    aba_hashes.push_back(ba_hash);

    ret = (int)m_SelectedKey->sign(
        m_Session,
        (const CM_UTF8_CHAR*)signAlgo.c_str(),
        (const CM_BYTEARRAY*)baSignAlgoParams,
        1,
        (const CM_BYTEARRAY**)aba_hashes.data(),
        &cmba_signatures
    );
    ba_free(ba_hash);
    if (ret == RET_OK) {
        *baSignature = ba_copy_with_alloc((const ByteArray*)cmba_signatures[0], 0, 0);
        arrayCmbaFree(1, cmba_signatures);
    }
    return ret;
}

int CmStorageProxy::keyAddCertificate (const ByteArray* baCert)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_SelectedKey) return RET_UAPKI_KEY_NOT_SELECTED;
    if (!m_SelectedKey->addCertificate) return RET_UAPKI_NOT_SUPPORTED;
    if (!baCert) return RET_UAPKI_INVALID_PARAMETER;

    const int ret = (int)m_SelectedKey->addCertificate(m_Session, (const CM_BYTEARRAY*)baCert);
    return ret;
}

int CmStorageProxy::keyGetCertificates (vector<ByteArray*>& vbaCerts)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_SelectedKey) return RET_UAPKI_KEY_NOT_SELECTED;
    if (!m_SelectedKey->getCertificates) return RET_UAPKI_NOT_SUPPORTED;

    uint32_t cnt_certs = 0;
    CM_BYTEARRAY** cmba_certs = nullptr;
    const int ret = (int)m_SelectedKey->getCertificates(m_Session, &cnt_certs, &cmba_certs);
    if (ret != RET_OK) return ret;

    vbaCerts.resize(cnt_certs);
    for (uint32_t i = 0; i < cnt_certs; i++) {
        vbaCerts[i] = ba_copy_with_alloc((const ByteArray*)cmba_certs[i], 0, 0);
    }
    arrayCmbaFree(cnt_certs, cmba_certs);
    return ret;
}

int CmStorageProxy::keyGetCsr (const string& signAlgo, const ByteArray* baSignAlgoParams,
                    const ByteArray* baSubject, const ByteArray* baAttributes, ByteArray** baCsr)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_SelectedKey) return RET_UAPKI_KEY_NOT_SELECTED;
    if (!m_SelectedKey->getCsr) return RET_UAPKI_NOT_SUPPORTED;
    if (!baCsr) return RET_UAPKI_INVALID_PARAMETER;

    const int ret = (int)m_SelectedKey->getCsr(m_Session,
        (const CM_UTF8_CHAR*)signAlgo.c_str(),
        (const CM_BYTEARRAY*)baSignAlgoParams,
        (const CM_BYTEARRAY*)baSubject,
        (const CM_BYTEARRAY*)baAttributes,
        (CM_BYTEARRAY**)baCsr
    );
    return ret;
}

int CmStorageProxy::keyDhWrapKey (const string& kdfOid, const string& wrapAlgOid,
                    const ByteArray* baSPKI, const ByteArray* baSessionKey,
                    ByteArray** baSalt, ByteArray** baWrappedKey)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_SelectedKey) return RET_UAPKI_KEY_NOT_SELECTED;
    if (!m_SelectedKey->dhWrapKey) return RET_UAPKI_NOT_SUPPORTED;
    if (kdfOid.empty() || wrapAlgOid.empty()
        || !baSPKI || !baSessionKey || !baWrappedKey) return RET_UAPKI_INVALID_PARAMETER;

    vector<const ByteArray*> aba_spkis, aba_sessionkeys;
    aba_spkis.push_back(baSPKI);
    aba_sessionkeys.push_back(baSessionKey);

    CM_BYTEARRAY** cmba_salts = nullptr;
    CM_BYTEARRAY** cmba_wrappedkeys = nullptr;
    int ret = m_SelectedKey->dhWrapKey(m_Session,
        (const CM_UTF8_CHAR*)kdfOid.c_str(),
        (const CM_UTF8_CHAR*)wrapAlgOid.c_str(),
        1,
        (const CM_BYTEARRAY**)aba_spkis.data(),
        (const CM_BYTEARRAY**)aba_sessionkeys.data(),
        (baSalt) ? &cmba_salts : nullptr,
        &cmba_wrappedkeys
    );
    if (ret == RET_OK) {
        ByteArray* ba_salt = nullptr;
        ByteArray* ba_wrappedkey = nullptr;
        if (cmba_salts) {
            ba_salt = ba_copy_with_alloc((const ByteArray*)cmba_salts[0], 0, 0);
            arrayCmbaFree(1, cmba_salts);
        }
        ba_wrappedkey = ba_copy_with_alloc((const ByteArray*)cmba_wrappedkeys[0], 0, 0);
        arrayCmbaFree(1, cmba_wrappedkeys);

        if ((baSalt && !ba_salt) || !ba_wrappedkey) {
            ret = RET_UAPKI_GENERAL_ERROR;
        }
        else {
            if (baSalt) {
                *baSalt = ba_salt;
            }
            ba_salt = nullptr;
            *baWrappedKey = ba_wrappedkey;
            ba_wrappedkey = nullptr;
        }
        ba_free(ba_salt);
        ba_free(ba_wrappedkey);
    }
    return ret;
}

int CmStorageProxy::keyDhWrapKey (const string& kdfOid, const string& wrapAlgOid,
                    const vector<ByteArray*>& vbaSPKIs, const vector<ByteArray*>& vbaSessionKeys,
                    vector<ByteArray*>* vbaSalts, vector<ByteArray*>& vbaWrappedKeys)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_SelectedKey) return RET_UAPKI_KEY_NOT_SELECTED;
    if (!m_SelectedKey->dhWrapKey) return RET_UAPKI_NOT_SUPPORTED;
    if (kdfOid.empty() || wrapAlgOid.empty() || vbaSPKIs.empty()
        || (vbaSPKIs.size() != vbaSessionKeys.size())) return RET_UAPKI_INVALID_PARAMETER;

    const uint32_t cnt_keys = (uint32_t)vbaSPKIs.size();
    CM_BYTEARRAY** cmba_salts = nullptr;
    CM_BYTEARRAY** cmba_wrappedkeys = nullptr;
    int ret = m_SelectedKey->dhWrapKey(m_Session,
        (const CM_UTF8_CHAR*)kdfOid.c_str(),
        (const CM_UTF8_CHAR*)wrapAlgOid.c_str(),
        cnt_keys,
        (const CM_BYTEARRAY**)vbaSPKIs.data(),
        (const CM_BYTEARRAY**)vbaSessionKeys.data(),
        (vbaSalts) ? &cmba_salts : nullptr,
        &cmba_wrappedkeys
    );
    if (ret != RET_OK) return ret;

    if (vbaSalts && cmba_salts) {
        vector<ByteArray*>& vba_salts = *vbaSalts;
        vba_salts.resize(cnt_keys);
        for (uint32_t i = 0; i < cnt_keys; i++) {
            vba_salts[i] = ba_copy_with_alloc((const ByteArray*)cmba_salts[i], 0, 0);
            if (!vba_salts[i]) {
                ret = RET_UAPKI_GENERAL_ERROR;
                break;
            }
        }
    }
    if (ret == RET_OK) {
        vbaWrappedKeys.resize(cnt_keys);
        for (uint32_t i = 0; i < cnt_keys; i++) {
            vbaWrappedKeys[i] = ba_copy_with_alloc((const ByteArray*)cmba_wrappedkeys[i], 0, 0);
            if (!vbaWrappedKeys[i]) {
                ret = RET_UAPKI_GENERAL_ERROR;
                break;
            }
        }
    }
    arrayCmbaFree(cnt_keys, cmba_salts);
    arrayCmbaFree(cnt_keys, cmba_wrappedkeys);
    if (ret != RET_OK) {
        if (vbaSalts) {
            vector<ByteArray*>& vba_salts = *vbaSalts;
            for (size_t i = 0; i < vba_salts.size(); i++) {
                ba_free(vba_salts[i]);
                vba_salts[i] = nullptr;
            }
            vba_salts.clear();
        }
        for (size_t i = 0; i < vbaWrappedKeys.size(); i++) {
            ba_free(vbaWrappedKeys[i]);
            vbaWrappedKeys[i] = nullptr;
        }
        vbaWrappedKeys.clear();
    }

    return ret;
}

int CmStorageProxy::keyDhUnwrapKey (const string& kdfOid, const string& wrapAlgOid,
                    const ByteArray* baSPKI, const ByteArray* baSalt,
                    const ByteArray* baWrappedKey, ByteArray** baSessionKey)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_SelectedKey) return RET_UAPKI_KEY_NOT_SELECTED;
    if (!m_SelectedKey->dhUnwrapKey) return RET_UAPKI_NOT_SUPPORTED;
    if (kdfOid.empty() || wrapAlgOid.empty()
        || !baSPKI || !baWrappedKey || !baSessionKey) return RET_UAPKI_INVALID_PARAMETER;

    vector<const ByteArray*> aba_spkis, aba_salts, aba_wrappedkeys;
    aba_spkis.push_back(baSPKI);
    if (baSalt) {
        aba_salts.push_back(baSalt);
    }
    aba_wrappedkeys.push_back(baWrappedKey);
    CM_BYTEARRAY** cmba_seskeys = nullptr;
    const int ret =  m_SelectedKey->dhUnwrapKey(m_Session,
        (const CM_UTF8_CHAR*)kdfOid.c_str(),
        (const CM_UTF8_CHAR*)wrapAlgOid.c_str(),
        1,
        (const CM_BYTEARRAY**)aba_spkis.data(),
        (baSalt) ? ((const CM_BYTEARRAY**)aba_salts.data()) : nullptr,
        (const CM_BYTEARRAY**)aba_wrappedkeys.data(),
        &cmba_seskeys
    );
    if (ret == RET_OK) {
        *baSessionKey = ba_copy_with_alloc((const ByteArray*)cmba_seskeys[0], 0, 0);
        arrayCmbaFree(1, cmba_seskeys);
    }
    return ret;
}

int CmStorageProxy::keyDhUnwrapKey (const string& kdfOid, const string& wrapAlgOid,
                    const vector<ByteArray*>& vbaSPKIs, const vector<ByteArray*>& vbaSalts,
                    const vector<ByteArray*>& vbaWrappedKeys, vector<ByteArray*>& vbaSessionKeys)
{
    if (!isOpenedStorage()) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!m_SelectedKey) return RET_UAPKI_KEY_NOT_SELECTED;
    if (!m_SelectedKey->dhUnwrapKey) return RET_UAPKI_NOT_SUPPORTED;
    if (kdfOid.empty() || wrapAlgOid.empty() || vbaSPKIs.empty()
        || (vbaSPKIs.size() != vbaWrappedKeys.size())) return RET_UAPKI_INVALID_PARAMETER;
    if (!vbaSalts.empty() && (vbaSPKIs.size() != vbaSalts.size())) return RET_UAPKI_INVALID_PARAMETER;

    const uint32_t cnt_keys = (uint32_t)vbaSPKIs.size();
    CM_BYTEARRAY** cmba_seskeys = nullptr;
    const int ret = m_SelectedKey->dhUnwrapKey(m_Session,
        (const CM_UTF8_CHAR*)kdfOid.c_str(),
        (const CM_UTF8_CHAR*)wrapAlgOid.c_str(),
        cnt_keys,
        (const CM_BYTEARRAY**)vbaSPKIs.data(),
        (!vbaSalts.empty()) ? ((const CM_BYTEARRAY**)vbaSalts.data()) : nullptr,
        (const CM_BYTEARRAY**)vbaWrappedKeys.data(),
        &cmba_seskeys
    );
    if (ret != RET_OK) return ret;

    vbaSessionKeys.resize(cnt_keys);
    for (uint32_t i = 0; i < cnt_keys; i++) {
        vbaSessionKeys[i] = ba_copy_with_alloc((const ByteArray*)cmba_seskeys[i], 0, 0);
    }
    arrayCmbaFree(cnt_keys, cmba_seskeys);
    return ret;
}
