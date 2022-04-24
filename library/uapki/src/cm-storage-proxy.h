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

#ifndef CM_STORAGE_PROXY_H
#define CM_STORAGE_PROXY_H


#include <string>
#include <vector>
#include "byte-array.h"
#include "cm-api.h"
#include "cm-loader.h"


using namespace std;


class CmStorageProxy {
    CmLoader    m_CmLoader;
    bool        m_IsInitialized;
    bool        m_IsAuthorizedSession;
    CM_SESSION_API*
                m_Session;
    const CM_KEY_API* 
                m_SelectedKey;

public:
    CmStorageProxy (void);
    ~CmStorageProxy (void);

    bool load (const string& libName, const string& dir = string());
    void cmFree (void* block);
    void cmbaFree (CM_BYTEARRAY* ba);
    void arrayCmbaFree (const uint32_t count, CM_BYTEARRAY** arrayBa);

    int providerInfo (string& providerInfo);
    int providerInit (const string& providerParams);
    int providerDeinit (void);

    int storageList (string& storageList);
    int storageInfo (const string& storageId, string& storageInfo);
    int storageOpen (const string& storageId, const CM_OPEN_MODE openMode, const string& openParams);
    int storageClose (void);
    int storageFormat (const string& storageId, const char* soPassword, const char* userPassword);

    int sessionInfo (string& sessionInfo);
    int sessionMechanismParameters (const string& mechanismId, string& parameterIds);
    int sessionLogin (const char* password, const void* reserved);
    int sessionLogout (void);

    int sessionCreateKey (const string& keyParam);
    int sessionDeleteKey (const ByteArray* baKeyId, const bool deleteRelatedObjects = false);
    int sessionImportKey (const ByteArray* baP8container, const char* password, const string& keyParam);
    int sessionListKeys (vector<ByteArray*>& vbaKeyIds);
    int sessionListKeys (vector<ByteArray*>& vbaKeyIds, string& infoKeys);
    int sessionSelectKey (const ByteArray* baKeyId);
    int sessionAddCertificate (const ByteArray* baCert);
    int sessionDeleteCertificate (const ByteArray* baKeyId);
    int sessionGetCertificates (vector<ByteArray*>& vbaCerts);
    int sessionChangePassword (const char* newPassword);
    int sessionRandomBytes (ByteArray* baBuffer);

    int keyGetInfo (string& keyInfo, ByteArray** baKeyId);
    int keyGetInfo (ByteArray** baKeyId);
    int keyGetInfo (string& keyInfo);
    int keyGetPublicKey (ByteArray** baAlgoId, ByteArray** baPublicKey);
    int keyInitUsage (void* param);
    int keySetOtp (const char* otp);
    int keySign (const string& signAlgo, const ByteArray* baSignAlgoParams,
            const vector<ByteArray*>& vbaHashes, vector<ByteArray*>& vbaSignatures);
    int keySignInit (const string& signAlgo, const ByteArray* baSignAlgoParams);
    int keySignUpdate (const ByteArray* baData);
    int keySignFinal (ByteArray** baSignature);
    int keySignData (const string& signAlgo, const ByteArray* baSignAlgoParams,
            const ByteArray* baData, ByteArray** baSignature);
    int keyAddCertificate (const ByteArray* baCert);
    int keyGetCertificates (vector<ByteArray*>& vbaCerts);
    int keyGetCsr (const string& signAlgo, const ByteArray* baSignAlgoParams,
            const ByteArray* baSubject, const ByteArray* baAttributes, ByteArray** baCsr);

    int keyDhWrapKey (const string& kdfOid, const string& wrapAlgOid,
            const ByteArray* baSPKI, const ByteArray* baSessionKey,
            ByteArray** baSalt, ByteArray** baWrappedKey);
    int keyDhWrapKey (const string& kdfOid, const string& wrapAlgOid,
            const vector<ByteArray*>& vbaSPKIs, const vector<ByteArray*>& vbaSessionKeys,
            vector<ByteArray*>* vbaSalts, vector<ByteArray*>& vbaWrappedKeys);
    int keyDhUnwrapKey (const string& kdfOid, const string& wrapAlgOid,
            const ByteArray* baSPKI, const ByteArray* baSalt,
            const ByteArray* baWrappedKey, ByteArray** baSessionKey);
    int keyDhUnwrapKey (const string& kdfOid, const string& wrapAlgOid,
            const vector<ByteArray*>& vbaSPKIs, const vector<ByteArray*>& vbaSalts,
            const vector<ByteArray*>& vbaWrappedKeys, vector<ByteArray*>& vbaSessionKeys);

    CM_SESSION_API* getCmSessionApi (void) const { return m_Session; }
    const CM_KEY_API* getSelectedKey (void) const { return m_SelectedKey; }
    bool isAuthorizedSession (void) const { return m_IsAuthorizedSession; }
    bool isInitialized (void) const { return m_IsInitialized; }
    bool isOpenedStorage (void) const { return (m_Session != nullptr); }
    bool keyIsSelected (void) const { return (m_SelectedKey); }

};  //  end class CmStorageProxy


#endif
