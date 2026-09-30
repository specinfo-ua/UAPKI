/*
 * Copyright (c) 2026, The UAPKI Project Authors.
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

#ifndef UAPKI_SESSION_H
#define UAPKI_SESSION_H


#include "cer-store.h"
#include "cm-providers.h"
#include "cm-storage-proxy.h"
#include "crl-store.h"
#include "library-config.h"
#include "parson.h"
#include <condition_variable>
#include <memory>
#include <mutex>
#include <vector>


namespace UapkiNS {


//  Serial methods change the session state and run exclusively;
//  thread methods run concurrently with each other.
class ApiGate {
    std::mutex  m_Mutex;
    std::condition_variable
                m_Cond;
    unsigned    m_CountThreadMethods;
    unsigned    m_CountWaitingSerial;
    bool        m_SerialIsRunning;

public:
    ApiGate (void);

    void enterSerial (void);
    void leaveSerial (void);
    void enterThread (void);
    void leaveThread (void);

    class SerialLock {
        ApiGate&    m_Gate;
    public:
        explicit SerialLock (ApiGate& gate) : m_Gate(gate) { m_Gate.enterSerial(); }
        ~SerialLock (void) { m_Gate.leaveSerial(); }
    };  //  end class SerialLock

    class ThreadLock {
        ApiGate&    m_Gate;
    public:
        explicit ThreadLock (ApiGate& gate) : m_Gate(gate) { m_Gate.enterThread(); }
        ~ThreadLock (void) { m_Gate.leaveThread(); }
    };  //  end class ThreadLock

};  //  end class ApiGate


class Session {
    ApiGate     m_ApiGate;
    std::unique_ptr<LibraryConfig>
                m_Config;
    std::unique_ptr<Cert::CerStore>
                m_CerStore;
    std::unique_ptr<Crl::CrlStore>
                m_CrlStore;
    std::vector<std::shared_ptr<CmProvider>>
                m_Providers;
    std::unique_ptr<CmStorageProxy>
                m_Storage;
    bool        m_HttpInitialized;
    bool        m_CryptoLibraryAcquired;    //  the session is counted in the users of the crypto library

public:
    Session (void);
    ~Session (void);

    static Session& global (void);

    ApiGate& apiGate (void) {
        return m_ApiGate;
    }
    LibraryConfig* config (void) {
        return m_Config.get();
    }
    Cert::CerStore* cerStore (void) {
        return m_CerStore.get();
    }
    Crl::CrlStore* crlStore (void) {
        return m_CrlStore.get();
    }

    int initCryptoLibrary (
        uint32_t* selfTestStatus
    );
    void releaseCryptoLibrary (void);
    int initHttp (void);
    void deinit (void);
    void releaseConfig (void);
    void releaseProviders (void);
    void releaseStores (void);
    void releaseHttp (void);

    int loadProvider (
        const std::string& dir,
        const std::string& libName,
        const std::string& jsonParams
    );
    size_t countProviders (void) const {
        return m_Providers.size();
    }
    int providerInfo (
        const size_t index,
        JSON_Object* joResult
    );
    std::shared_ptr<CmProvider> providerById (
        const std::string& providerId
    );
    int listStorages (
        const std::string& providerId,
        JSON_Object* joResult
    );
    int storageInfo (
        const std::string& providerId,
        const std::string& storageId,
        JSON_Object* joResult
    );
    int storageOpen (
        const std::string& providerId,
        const std::string& storageId,
        JSON_Object* joParams
    );
    int storageClose (void);
    CmStorageProxy* openedStorage (void) {
        return m_Storage.get();
    }

};  //  end class Session


//  One request of a session, optionally with a shared memory (another Session that only holds caches):
//  certificates are looked up in the session first and then in the shared memory, CRLs come from the
//  shared memory only, and a session that was not initialized borrows the shared memory's configuration.
//  The stores are resolved when a method asks for them, i.e. after the gates are held.
class Context {
    Session&    m_Session;
    std::shared_ptr<Session>
                m_Shared;
    const bool  m_IsSharedMemory;
    std::unique_ptr<Cert::CerStore>
                m_CerView;

public:
    Context (
        Session& session,
        std::shared_ptr<Session> shared = std::shared_ptr<Session>(),
        const bool isSharedMemory = false
    );

    Session& session (void) {
        return m_Session;
    }
    Session* shared (void) {
        return m_Shared.get();
    }
    bool isSharedMemory (void) const {
        return m_IsSharedMemory;
    }
    LibraryConfig* config (void);
    Cert::CerStore* cerStore (void);
    Crl::CrlStore* crlStore (void);

    size_t countProviders (void) const {
        return m_Session.countProviders();
    }
    int providerInfo (
        const size_t index,
        JSON_Object* joResult
    ) {
        return m_Session.providerInfo(index, joResult);
    }
    int listStorages (
        const std::string& providerId,
        JSON_Object* joResult
    ) {
        return m_Session.listStorages(providerId, joResult);
    }
    int storageInfo (
        const std::string& providerId,
        const std::string& storageId,
        JSON_Object* joResult
    ) {
        return m_Session.storageInfo(providerId, storageId, joResult);
    }
    int storageOpen (
        const std::string& providerId,
        const std::string& storageId,
        JSON_Object* joParams
    ) {
        return m_Session.storageOpen(providerId, storageId, joParams);
    }
    int storageClose (void) {
        return m_Session.storageClose();
    }
    CmStorageProxy* openedStorage (void) {
        return m_Session.openedStorage();
    }

};  //  end class Context


}   //  end namespace UapkiNS


#endif
