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

#define FILE_MARKER "uapki/cm-providers.cpp"

#include "cm-providers.h"
#include "macros-internal.h"
#include "parson-ba-utils.h"
#include "parson-helper.h"
#include "session.h"
#include "uapki-errors.h"
#include <vector>
#include <algorithm>
#include <cctype>


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


namespace UapkiNS {


static JSON_Status json_object_copy_boolean (
        JSON_Object* joDest,
        JSON_Object* joSource,
        const char* key
)
{
    const bool b_value = ParsonHelper::jsonObjectGetBoolean(joSource, key, false);
    return ParsonHelper::jsonObjectSetBoolean(joDest, key, b_value);
}   //  json_object_copy_boolean

static JSON_Status json_object_copy_number (
    JSON_Object* joDest,
    JSON_Object* joSource,
    const char* key
)
{
    const int32_t int_value = ParsonHelper::jsonObjectGetInt32(joSource, key, 0);
    return ParsonHelper::jsonObjectSetInt32(joDest, key, int_value);
}   //  json_object_copy_number

static JSON_Status json_object_copy_string (
        JSON_Object* joDest,
        JSON_Object* joSource,
        const char* key
)
{
    const string s = ParsonHelper::jsonObjectGetString(joSource, key);
    return json_object_set_string(joDest, key, s.c_str());
}   //  json_object_copy_string

static int json_object_copy_storageinfo (
        JSON_Object* joDestStorageInfo,
        JSON_Object* joSrcStorageInfo
)
{
    int ret = RET_OK;

    DO_JSON(json_object_copy_string(joDestStorageInfo,  joSrcStorageInfo, "id"));
    DO_JSON(json_object_copy_string(joDestStorageInfo,  joSrcStorageInfo, "description"));
    DO_JSON(json_object_copy_string(joDestStorageInfo,  joSrcStorageInfo, "manufacturer"));
    DO_JSON(json_object_copy_string(joDestStorageInfo,  joSrcStorageInfo, "model"));
    DO_JSON(json_object_copy_string(joDestStorageInfo,  joSrcStorageInfo, "serial"));
    DO_JSON(json_object_copy_string(joDestStorageInfo,  joSrcStorageInfo, "label"));

    DO_JSON(json_object_copy_boolean(joDestStorageInfo, joSrcStorageInfo, "passwordCountLow"));
    DO_JSON(json_object_copy_boolean(joDestStorageInfo, joSrcStorageInfo, "passwordFinalTry"));
    DO_JSON(json_object_copy_boolean(joDestStorageInfo, joSrcStorageInfo, "passwordLocked"));
    DO_JSON(json_object_copy_boolean(joDestStorageInfo, joSrcStorageInfo, "passwordToBeChanged"));
    DO_JSON(json_object_copy_number(joDestStorageInfo,  joSrcStorageInfo, "passwordAttemptsLeft"));
    DO_JSON(json_object_copy_number(joDestStorageInfo,  joSrcStorageInfo, "passwordMinLen"));
    DO_JSON(json_object_copy_number(joDestStorageInfo,  joSrcStorageInfo, "passwordMaxLen"));

    DO_JSON(json_object_copy_string(joDestStorageInfo, joSrcStorageInfo, "flags"));
    DO_JSON(json_object_copy_number(joDestStorageInfo, joSrcStorageInfo, "maxSessionCount"));
    DO_JSON(json_object_copy_number(joDestStorageInfo, joSrcStorageInfo, "sessionCount"));
    DO_JSON(json_object_copy_number(joDestStorageInfo, joSrcStorageInfo, "maxRwSessionCount"));
    DO_JSON(json_object_copy_number(joDestStorageInfo, joSrcStorageInfo, "rwSessionCount"));
    DO_JSON(json_object_copy_number(joDestStorageInfo, joSrcStorageInfo, "totalPublicMemory"));
    DO_JSON(json_object_copy_number(joDestStorageInfo, joSrcStorageInfo, "freePublicMemory"));
    DO_JSON(json_object_copy_number(joDestStorageInfo, joSrcStorageInfo, "totalPrivateMemory"));
    DO_JSON(json_object_copy_number(joDestStorageInfo, joSrcStorageInfo, "freePrivateMemory"));
    DO_JSON(json_object_copy_string(joDestStorageInfo, joSrcStorageInfo, "hardwareVersion"));
    DO_JSON(json_object_copy_string(joDestStorageInfo, joSrcStorageInfo, "firmwareVersion"));
    DO_JSON(json_object_copy_string(joDestStorageInfo, joSrcStorageInfo, "utcTime"));

cleanup:
    return ret;
}   //  json_object_copy_storageinfo


CmProvider::CmProvider (void)
    : m_IsInitialized(false)
    , m_IsRegistered(false)
{
    DEBUG_OUTCON(puts("CmProvider::CmProvider()"));
}

CmProvider::~CmProvider (void)
{
    DEBUG_OUTCON(puts("CmProvider::~CmProvider()"));
    if (m_IsInitialized) {
        (void)m_CmLoader.deinit();
        m_IsInitialized = false;
    }
}

int CmProvider::loadLibrary (
        const string& dir,
        const string& libName
)
{
    DEBUG_OUTCON(printf("CmProvider::loadLibrary(dir: '%s', libName: '%s')\n", dir.c_str(), libName.c_str()));
    return m_CmLoader.load(libName, dir) ? RET_OK : RET_CM_LIBRARY_NOT_LOADED;
}

int CmProvider::loadStatic (
        const CM_STATIC_PROVIDER_FUNCS& funcs
)
{
    DEBUG_OUTCON(puts("CmProvider::loadStatic()"));
    return m_CmLoader.loadStatic(funcs) ? RET_OK : RET_CM_LIBRARY_NOT_LOADED;
}

int CmProvider::init (
        const string& jsonParams
)
{
    DEBUG_OUTCON(printf("CmProvider::init(params: '%s')\n", jsonParams.c_str()));
    int ret = RET_OK;
    char* s_providerinfo = nullptr;
    ParsonHelper json;

    DO(m_CmLoader.init(!jsonParams.empty() ? (CM_JSON_PCHAR)jsonParams.c_str() : nullptr));
    m_IsInitialized = true;

    DO(m_CmLoader.info((CM_JSON_PCHAR*)&s_providerinfo));
    if (s_providerinfo) {
        m_Info = string(s_providerinfo);
        m_CmLoader.blockFree(s_providerinfo);
    }

    if (!json.parse(m_Info.c_str())) {
        SET_ERROR(RET_UAPKI_INVALID_JSON_FORMAT);
    }

    json.getString("id", m_Id);
    if (m_Id.empty()) {
        SET_ERROR(RET_UAPKI_INVALID_JSON_FORMAT);
    }

cleanup:
    return ret;
}

int CmProvider::getInfo (
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    ParsonHelper json;

    if (!json.parse(m_Info.c_str())) {
        SET_ERROR(RET_UAPKI_INVALID_JSON_FORMAT);
    }

    DO_JSON(json_object_set_string(joResult, "id",           json.getString("id")));
    DO_JSON(json_object_set_string(joResult, "apiVersion",   json.getString("apiVersion")));
    DO_JSON(json_object_set_string(joResult, "libVersion",   json.getString("libVersion")));
    DO_JSON(json_object_set_string(joResult, "description",  json.getString("description")));
    DO_JSON(json_object_set_string(joResult, "manufacturer", json.getString("manufacturer")));
    DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "supportListStorages",
                                                             json.getBoolean("supportListStorages", false)));
    if (json.hasValue("flags", JSONNumber)) {
        const int flags = json.getInt("flags");
        if (flags >= 0) ParsonHelper::jsonObjectSetUint32(joResult, "flags", (uint32_t)flags);
    }

cleanup:
    return ret;
}

int CmProvider::listStorages (
        string& outList
)
{
    lock_guard<mutex> lock(m_Mutex);

    CM_JSON_PCHAR json_listuris = nullptr;
    const int ret = m_CmLoader.listStorages(&json_listuris);
    if ((ret == RET_OK) && json_listuris) {
        outList = string((char*)json_listuris);
        blockFree(json_listuris);
    }
    return ret;
}

int CmProvider::listStorages (
        JSON_Object* joResult
)
{
    string s_storlist;
    int ret = listStorages(s_storlist);
    if (ret != RET_OK) return ret;

    ParsonHelper json;
    JSON_Object* jo_resp = json.parse(s_storlist.c_str());
    if (!jo_resp) return RET_UAPKI_INVALID_JSON_FORMAT;

    JSON_Array* ja_dststoreinfos = nullptr;
    JSON_Array* ja_srcstoreinfos = json.getArray("storages");
    const size_t cnt_storages = json_array_get_count(ja_srcstoreinfos);

    DO_JSON(json_object_set_value(joResult, "storages", json_value_init_array()));
    ja_dststoreinfos = json_object_get_array(joResult, "storages");
    for (size_t i = 0; i < cnt_storages; i++) {
        DO_JSON(json_array_append_value(ja_dststoreinfos, json_value_init_object()));
        JSON_Object* jo_dstkeyinfo = json_array_get_object(ja_dststoreinfos, i);
        JSON_Object* jo_srckeyinfo = json_array_get_object(ja_srcstoreinfos, i);
        DO(json_object_copy_storageinfo(jo_dstkeyinfo, jo_srckeyinfo));
    }

cleanup:
    return ret;
}

int CmProvider::storageInfo (
        const string& storageId,
        string& outInfo
)
{
    lock_guard<mutex> lock(m_Mutex);

    CM_JSON_PCHAR json_storageinfo = nullptr;
    const int ret = m_CmLoader.storageInfo(storageId.c_str(), &json_storageinfo);
    if ((ret == RET_OK) && json_storageinfo) {
        outInfo = string((char*)json_storageinfo);
        blockFree(json_storageinfo);
    }
    return ret;
}

int CmProvider::storageInfo (
        const string& storageId,
        JSON_Object* joResult
)
{
    string s_storinfo;
    const int ret = storageInfo(storageId, s_storinfo);
    if (ret != RET_OK) return ret;

    ParsonHelper json;
    JSON_Object* jo_resp = json.parse(s_storinfo.c_str());
    if (!jo_resp) return RET_UAPKI_INVALID_JSON_FORMAT;

    return json_object_copy_storageinfo(joResult, jo_resp);
}

int CmProvider::storageOpen (
        const string& storageId,
        const CM_OPEN_MODE openMode,
        const string& openParams,
        CM_SESSION_API** session
)
{
    lock_guard<mutex> lock(m_Mutex);

    return m_CmLoader.open(
        storageId.c_str(),
        openMode,
        !openParams.empty() ? (CM_JSON_PCHAR)openParams.c_str() : nullptr,
        session
    );
}

int CmProvider::storageClose (
        CM_SESSION_API* session
)
{
    lock_guard<mutex> lock(m_Mutex);

    return m_CmLoader.close(session);
}

int CmProvider::storageFormat (
        const string& storageId,
        const char* soPassword,
        const char* userPassword
)
{
    lock_guard<mutex> lock(m_Mutex);

    return m_CmLoader.format(storageId.c_str(), soPassword, userPassword);
}

void CmProvider::blockFree (
        void* block
)
{
    m_CmLoader.blockFree(block);
}

void CmProvider::baFree (
        CM_BYTEARRAY* ba
)
{
    m_CmLoader.baFree(ba);
}


CmProviderRegistry& CmProviderRegistry::instance (void)
{
    static CmProviderRegistry* registry = new CmProviderRegistry();
    return *registry;
}

int CmProviderRegistry::registerStatic (
        const string& libName,
        const CM_STATIC_PROVIDER_FUNCS& funcs,
        const string& jsonParams
)
{
    if (libName.empty()) return RET_UAPKI_INVALID_PARAMETER;

    lock_guard<mutex> lock(m_Mutex);

    if (m_StaticProviders.find(libName) != m_StaticProviders.end()) {
        return RET_CM_ALREADY_INITIALIZED;
    }

    shared_ptr<CmProvider> provider(new CmProvider());
    int ret = provider->loadStatic(funcs);
    if (ret != RET_OK) return ret;

    ret = provider->init(jsonParams);
    DEBUG_OUTCON(printf("CmProviderRegistry::registerStatic(libName: '%s'), init ret: %d\n", libName.c_str(), ret));
    if (ret != RET_OK) return ret;

    m_StaticProviders[libName] = std::move(provider);
    return RET_OK;
}

int CmProviderRegistry::acquire (
        const string& dir,
        const string& libName,
        const string& jsonParams,
        shared_ptr<CmProvider>& provider
)
{
    unique_lock<mutex> lock(m_Mutex);

    {
        auto it_static = m_StaticProviders.find(libName);
        if (it_static != m_StaticProviders.end()) {
            provider = it_static->second;
            return RET_OK;
        }
        //  Configs written for the old static loader name the provider by its id ("PKCS12")
        for (const auto& it : m_StaticProviders) {
            const string& id = it.second->getId();
            if ((id.size() == libName.size()) && std::equal(id.begin(), id.end(), libName.begin(),
                    [] (char a, char b) { return std::tolower((unsigned char)a) == std::tolower((unsigned char)b); })) {
                provider = it.second;
                return RET_OK;
            }
        }
    }

    const string key = dir + '|' + libName;
    for (;;) {
        auto it = m_Providers.find(key);
        if (it != m_Providers.end()) {
            provider = it->second.provider.lock();
            if (provider) return RET_OK;

            //  The last owner is releasing this provider right now, wait until it is unloaded
            m_Cond.wait(lock);
            continue;
        }

        unique_ptr<CmProvider> loaded(new CmProvider());
        int ret = loaded->loadLibrary(dir, libName);
        if (ret != RET_OK) return ret;

        //  The same library named through another directory spelling is the same process-wide provider
        const Entry* same = nullptr;
        for (const auto& it_same : m_Providers) {
            if (it_same.second.handle == loaded->getHandle()) {
                same = &it_same.second;
                break;
            }
        }
        if (same) {
            provider = same->provider.lock();
            if (!provider) {
                loaded.reset();
                m_Cond.wait(lock);
                continue;
            }
            provider->m_RegistryKeys.push_back(key);
            m_Providers[key] = { provider, provider->getHandle() };
            return RET_OK;
        }

        ret = loaded->init(jsonParams);
        if (ret != RET_OK) return ret;

        //  The deleter unloads the provider under the registry lock; it goes through the registry only once
        //  the provider is registered, so a failure while registering can not re-enter the held lock
        loaded->m_RegistryKeys.push_back(key);
        CmProviderRegistry* registry = this;
        provider = shared_ptr<CmProvider>(
            loaded.release(),
            [registry] (CmProvider* p) { if (p->m_IsRegistered) registry->release(p); else delete p; }
        );
        m_Providers[key] = { provider, provider->getHandle() };
        provider->m_IsRegistered = true;
        return RET_OK;
    }
}

void CmProviderRegistry::release (
        CmProvider* provider
)
{
    lock_guard<mutex> lock(m_Mutex);

    for (const auto& key : provider->m_RegistryKeys) {
        auto it = m_Providers.find(key);
        if ((it != m_Providers.end()) && it->second.provider.expired()) {
            m_Providers.erase(it);
        }
    }
    delete provider;
    m_Cond.notify_all();
}


}   //  end namespace UapkiNS


int CmProviders::loadProvider (const string& dir, const string& libName, const string& jsonParams)
{
    return UapkiNS::Session::global().loadProvider(dir, libName, jsonParams);
}

void CmProviders::deinit (void)
{
    UapkiNS::Session::global().releaseProviders();
}

size_t CmProviders::count (void)
{
    return UapkiNS::Session::global().countProviders();
}

int CmProviders::getInfo (const size_t index, JSON_Object* joResult)
{
    return UapkiNS::Session::global().providerInfo(index, joResult);
}

int CmProviders::listStorages (const string& providerId, JSON_Object* joResult)
{
    return UapkiNS::Session::global().listStorages(providerId, joResult);
}

int CmProviders::storageInfo (const string& providerId, const string& storageId, JSON_Object* joResult)
{
    return UapkiNS::Session::global().storageInfo(providerId, storageId, joResult);
}

int CmProviders::storageOpen (const string& providerId, const string& storageId, JSON_Object* joParams)
{
    return UapkiNS::Session::global().storageOpen(providerId, storageId, joParams);
}

int CmProviders::storageClose (void)
{
    return UapkiNS::Session::global().storageClose();
}

CmStorageProxy* CmProviders::openedStorage (void)
{
    return UapkiNS::Session::global().openedStorage();
}
