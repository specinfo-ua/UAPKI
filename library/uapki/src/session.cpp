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

#define FILE_MARKER "uapki/session.cpp"

#include "session.h"
#include "http-helper.h"
#include "parson-helper.h"
#include "uapki-errors.h"
#include "uapkic.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


namespace UapkiNS {


ApiGate::ApiGate (void)
    : m_CountThreadMethods(0)
    , m_CountWaitingSerial(0)
    , m_SerialIsRunning(false)
{
}

void ApiGate::enterSerial (void)
{
    unique_lock<mutex> lock(m_Mutex);
    m_CountWaitingSerial++;
    m_Cond.wait(lock, [this] { return !m_SerialIsRunning && (m_CountThreadMethods == 0); });
    m_CountWaitingSerial--;
    m_SerialIsRunning = true;
}

void ApiGate::leaveSerial (void)
{
    {
        lock_guard<mutex> lock(m_Mutex);
        m_SerialIsRunning = false;
    }
    m_Cond.notify_all();
}

void ApiGate::enterThread (void)
{
    unique_lock<mutex> lock(m_Mutex);
    m_Cond.wait(lock, [this] { return !m_SerialIsRunning && (m_CountWaitingSerial == 0); });
    m_CountThreadMethods++;
}

void ApiGate::leaveThread (void)
{
    bool wake_serial;
    {
        lock_guard<mutex> lock(m_Mutex);
        m_CountThreadMethods--;
        wake_serial = (m_CountThreadMethods == 0 && m_CountWaitingSerial > 0);
    }
    if (wake_serial) m_Cond.notify_all();
}


Session::Session (void)
    : m_Config(new LibraryConfig())
    , m_CerStore(new Cert::CerStore())
    , m_CrlStore(new Crl::CrlStore())
    , m_HttpInitialized(false)
    , m_CryptoLibraryAcquired(false)
{
    DEBUG_OUTCON(puts("Session::Session()"));
}

Session::~Session (void)
{
    DEBUG_OUTCON(puts("Session::~Session()"));
    deinit();
}

Session& Session::global (void)
{
    static Session* session = new Session();
    return *session;
}

//  Sessions (including the global one) that initialized the crypto library: when the last one
//  is deinitialized, the global state of uapkic (DRBG, EC cache, error stacks) is released.
//  The application guarantees that nothing else uses the library at that moment.
static mutex crypto_library_mutex;
static size_t crypto_library_sessions = 0;

int Session::initCryptoLibrary (
        uint32_t* selfTestStatus
)
{
    //  uapkic_init() initializes DRBG once; the self-test runs on every call with selfTestStatus
    //  (INIT without skipSelfTest), it does not touch the global DRBG state
    lock_guard<mutex> lock(crypto_library_mutex);
    const int ret = uapkic_init(nullptr, selfTestStatus);
    if ((ret == RET_OK) && !m_CryptoLibraryAcquired) {
        m_CryptoLibraryAcquired = true;
        crypto_library_sessions++;
    }
    return ret;
}

void Session::releaseCryptoLibrary (void)
{
    lock_guard<mutex> lock(crypto_library_mutex);
    if (!m_CryptoLibraryAcquired) return;

    m_CryptoLibraryAcquired = false;
    if (--crypto_library_sessions == 0) {
        uapkic_deinit();
    }
}

int Session::initHttp (void)
{
    if (m_HttpInitialized) return RET_OK;

    const HttpHelper::Params& http_params = m_Config->getHttp();
    const int ret = (this == &global())
        ? HttpHelper::init(http_params.offline, http_params.proxyUrl.c_str(), http_params.proxyCredentials.c_str())
        : HttpHelper::init();
    m_HttpInitialized = (ret == RET_OK);
    return ret;
}

void Session::deinit (void)
{
    releaseConfig();
    releaseProviders();
    releaseStores();
    releaseHttp();
    releaseCryptoLibrary();
}

void Session::releaseConfig (void)
{
    m_Config.reset(new LibraryConfig());
}

void Session::releaseProviders (void)
{
    m_Storage.reset();
    m_Providers.clear();
}

void Session::releaseStores (void)
{
    m_CerStore.reset(new Cert::CerStore());
    m_CrlStore.reset(new Crl::CrlStore());
}

void Session::releaseHttp (void)
{
    if (m_HttpInitialized) {
        HttpHelper::deinit();
        m_HttpInitialized = false;
    }
}

int Session::loadProvider (
        const string& dir,
        const string& libName,
        const string& jsonParams
)
{
    shared_ptr<CmProvider> provider;
    const int ret = CmProviderRegistry::instance().acquire(dir, libName, jsonParams, provider);
    DEBUG_OUTCON(printf("Session::loadProvider(dir: '%s', libName: '%s'), ret: %d\n", dir.c_str(), libName.c_str(), ret));
    if (ret != RET_OK) return ret;

    for (const auto& it : m_Providers) {
        if (it == provider) return RET_OK;
    }
    m_Providers.push_back(provider);
    return RET_OK;
}

int Session::providerInfo (
        const size_t index,
        JSON_Object* joResult
)
{
    if (index >= m_Providers.size()) return RET_INVALID_PARAM;

    return m_Providers[index]->getInfo(joResult);
}

shared_ptr<CmProvider> Session::providerById (
        const string& providerId
)
{
    for (const auto& it : m_Providers) {
        if (providerId == it->getId()) {
            return it;
        }
    }
    return shared_ptr<CmProvider>();
}

int Session::listStorages (
        const string& providerId,
        JSON_Object* joResult
)
{
    shared_ptr<CmProvider> provider = providerById(providerId);
    if (!provider) return RET_UAPKI_UNKNOWN_PROVIDER;

    return provider->listStorages(joResult);
}

int Session::storageInfo (
        const string& providerId,
        const string& storageId,
        JSON_Object* joResult
)
{
    shared_ptr<CmProvider> provider = providerById(providerId);
    if (!provider) return RET_UAPKI_UNKNOWN_PROVIDER;

    return provider->storageInfo(storageId, joResult);
}

int Session::storageOpen (
        const string& providerId,
        const string& storageId,
        JSON_Object* joParams
)
{
    const string s_mode = ParsonHelper::jsonObjectGetString(joParams, "mode");
    const string s_password = ParsonHelper::jsonObjectGetString(joParams, "password");
    const char* s_username = json_object_get_string(joParams, "username");
    if (s_password.empty()) return RET_UAPKI_INVALID_PARAMETER;

    CM_OPEN_MODE mode = OPEN_MODE_RW;
    if ((s_mode == "RW") || s_mode.empty()) mode = OPEN_MODE_RW;
    else if (s_mode == "RO") mode = OPEN_MODE_RO;
    else if (s_mode == "CREATE") mode = OPEN_MODE_CREATE;
    else return RET_UAPKI_INVALID_PARAMETER;

    shared_ptr<CmProvider> provider = providerById(providerId);
    if (!provider) return RET_UAPKI_UNKNOWN_PROVIDER;

    if (m_Storage) return RET_UAPKI_STORAGE_ALREADY_OPENED;

    string s_openparams;
    if (ParsonHelper::jsonObjectHasValue(joParams, "openParams", JSONObject)) {
        ParsonHelper json;
        json_object_copy_all_items(json.create(), json_object_get_object(joParams, "openParams"));
        json.serialize(s_openparams);
    }

    unique_ptr<CmStorageProxy> storage(new CmStorageProxy(provider));
    int ret = storage->storageOpen(storageId, mode, s_openparams);
    if (ret != RET_OK) return ret;

    ret = storage->sessionLogin(s_password.c_str(), s_username);
    if (ret == RET_OK) {
        m_Storage = std::move(storage);
    }
    else {
        (void)storage->storageClose();
    }
    return ret;
}

int Session::storageClose (void)
{
    if (!m_Storage) return RET_UAPKI_STORAGE_NOT_OPEN;

    const int ret = m_Storage->storageClose();
    m_Storage.reset();
    return ret;
}



Context::Context (
        Session& session,
        shared_ptr<Session> shared,
        const bool isSharedMemory
)
    : m_Session(session)
    , m_Shared(std::move(shared))
    , m_IsSharedMemory(isSharedMemory)
{
}

LibraryConfig* Context::config (void)
{
    if (m_Shared && !m_Session.config()->isInitialized()) {
        return m_Shared->config();
    }
    return m_Session.config();
}

Cert::CerStore* Context::cerStore (void)
{
    if (!m_Shared) return m_Session.cerStore();

    if (!m_CerView) {
        m_CerView.reset(new Cert::CerStore(m_Session.cerStore(), m_Shared->cerStore()));
    }
    return m_CerView.get();
}

Crl::CrlStore* Context::crlStore (void)
{
    return (m_Shared) ? m_Shared->crlStore() : m_Session.crlStore();
}


}   //  end namespace UapkiNS
