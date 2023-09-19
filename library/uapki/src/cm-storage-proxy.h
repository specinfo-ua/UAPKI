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

#ifndef CM_STORAGE_PROXY_H
#define CM_STORAGE_PROXY_H


#include "byte-array.h"
#include "cm-api.h"
#include "cm-loader.h"
#include <atomic>
#include <mutex>
#include <string>
#include <vector>


class CmStorageProxy {
    CmLoader    m_CmLoader;
    std::atomic_bool
                m_IsInitialized;
    std::atomic_bool
                m_IsAuthorizedSession;
    std::mutex  m_Mutex;
    CM_SESSION_API*
                m_Session;
    const CM_KEY_API* 
                m_SelectedKey;

public:
    CmStorageProxy (void);
    ~CmStorageProxy (void);

    bool load (
        const std::string& libName,
        const std::string& dir = std::string()
    );
    void cmFree (
        void* block
    );
    void cmbaFree (
        CM_BYTEARRAY* ba
    );
    void arrayCmbaFree (
        const uint32_t count,
        CM_BYTEARRAY** arrayBa
    );

    int providerInfo (
        std::string& providerInfo
    );
    int providerInit (
        const std::string& providerParams
    );
    int providerDeinit (void);

    int storageList (
        std::string& storageList
    );
    int storageInfo (
        const std::string& storageId,
        std::string& storageInfo
    );
    int storageOpen (
        const std::string& storageId,
        const CM_OPEN_MODE openMode,
        const std::string& openParams
    );
    int storageClose (void);
    int storageFormat (
        const std::string& storageId,
        const char* soPassword,
        const char* userPassword
    );

    int sessionInfo (
        std::string& sessionInfo
    );
    int sessionMechanismParameters (
        const std::string& mechanismId,
        std::string& parameterIds
    );
    int sessionLogin (
        const char* password,
        const void* reserved
    );
    int sessionLogout (void);

    int sessionCreateKey (
        const std::string& keyParam
    );
    int sessionDeleteKey (
        const ByteArray* baKeyId,
        const bool deleteRelatedObjects = false
    );
    int sessionImportKey (
        const ByteArray* baP8container,
        const char* password,
        const std::string& keyParam
    );
    int sessionListKeys (
        std::vector<ByteArray*>& vbaKeyIds
    );
    int sessionListKeys (
        std::vector<ByteArray*>& vbaKeyIds,
        std::string& infoKeys
    );
    int sessionSelectKey (
        const ByteArray* baKeyId
    );
    int sessionAddCertificate (
        const ByteArray* baCert
    );
    int sessionDeleteCertificate (
        const ByteArray* baKeyId
    );
    int sessionGetCertificates (
        std::vector<ByteArray*>& vbaCerts
    );
    int sessionChangePassword (
        const char* newPassword
    );
    int sessionRandomBytes (
        ByteArray* baBuffer
    );

    int keyGetInfo (
        std::string& keyInfo,
        ByteArray** baKeyId
    );
    int keyGetInfo (
        ByteArray** baKeyId
    );
    int keyGetInfo (
        std::string& keyInfo
    );
    int keyGetPublicKey (
        ByteArray** baAlgoId,
        ByteArray** baPublicKey
    );
    int keyInitUsage (
        void* param
    );
    int keySetOtp (
        const char* otp
    );
    int keySign (
        const std::string& signAlgo,
        const ByteArray* baSignAlgoParams,
        const std::vector<ByteArray*>& vbaHashes,
        std::vector<ByteArray*>& vbaSignatures
    );
    int keySignInit (
        const std::string& signAlgo,
        const ByteArray* baSignAlgoParams
    );
    int keySignUpdate (
        const ByteArray* baData
    );
    int keySignFinal (
        ByteArray** baSignature
    );
    int keySignData (
        const std::string& signAlgo,
        const ByteArray* baSignAlgoParams,
        const ByteArray* baData,
        ByteArray** baSignature
    );
    int keyAddCertificate (
        const ByteArray* baCert
    );
    int keyGetCertificates (
        std::vector<ByteArray*>& vbaCerts
    );
    int keyGetCsr (
        const std::string& signAlgo,
        const ByteArray* baSignAlgoParams,
        const ByteArray* baSubject,
        const ByteArray* baAttributes,
        ByteArray** baCsr
    );

    int keyDhWrapKey (
        const std::string& kdfOid,
        const std::string& wrapAlgOid,
        const ByteArray* baSPKI,
        const ByteArray* baSessionKey,
        ByteArray** baSalt,
        ByteArray** baWrappedKey
    );
    int keyDhWrapKey (
        const std::string& kdfOid,
        const std::string& wrapAlgOid,
        const std::vector<ByteArray*>& vbaSPKIs,
        const std::vector<ByteArray*>& vbaSessionKeys,
        std::vector<ByteArray*>* vbaSalts,
        std::vector<ByteArray*>& vbaWrappedKeys
    );
    int keyDhUnwrapKey (
        const std::string& kdfOid,
        const std::string& wrapAlgOid,
        const ByteArray* baSPKI,
        const ByteArray* baSalt,
        const ByteArray* baWrappedKey,
        ByteArray** baSessionKey
    );
    int keyDhUnwrapKey (
        const std::string& kdfOid,
        const std::string& wrapAlgOid,
        const std::vector<ByteArray*>& vbaSPKIs,
        const std::vector<ByteArray*>& vbaSalts,
        const std::vector<ByteArray*>& vbaWrappedKeys,
        std::vector<ByteArray*>& vbaSessionKeys
    );

    CM_SESSION_API* getCmSessionApi (void) const {
        return m_Session;
    }
    const CM_KEY_API* getSelectedKey (void) const {
        return m_SelectedKey;
    }
    bool isAuthorizedSession (void) const {
        return m_IsAuthorizedSession;
    }
    bool isInitialized (void) const {
        return m_IsInitialized;
    }
    bool isOpenedStorage (void) const {
        return (m_Session != nullptr);
    }
    bool keyIsSelected (void) const {
        return (m_SelectedKey);
    }

};  //  end class CmStorageProxy


#endif
