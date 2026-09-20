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

#ifndef UAPKI_CM_PROVIDERS_H
#define UAPKI_CM_PROVIDERS_H

#include "cm-api.h"
#include "cm-loader.h"
#include "cm-storage-proxy.h"
#include "parson.h"
#include "uapkic.h"
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>


namespace UapkiNS {


//  One loaded CM-provider library. A provider library keeps its own process-wide
//  state and may be initialized only once, so the instance is shared by all
//  sessions that requested it and the library is deinitialized/unloaded when the
//  last session releases it.
class CmProvider {
    friend class CmProviderRegistry;

    CmLoader    m_CmLoader;
    std::mutex  m_Mutex;
    std::string m_Id;
    std::string m_Info;
    bool        m_IsInitialized;
    bool        m_IsRegistered;
    std::vector<std::string>
                m_RegistryKeys;

    CmProvider (void);

    int loadLibrary (
        const std::string& dir,
        const std::string& libName
    );
    int loadStatic (
        const CM_STATIC_PROVIDER_FUNCS& funcs
    );
    int init (
        const std::string& jsonParams
    );
    HANDLE_DLIB getHandle (void) const {
        return m_CmLoader.getHandle();
    }

public:
    ~CmProvider (void);

    const std::string& getId (void) const {
        return m_Id;
    }
    bool isStatic (void) const {
        return m_CmLoader.isStatic();
    }
    const std::string& getInfo (void) const {
        return m_Info;
    }
    int getInfo (
        JSON_Object* joResult
    );

    int listStorages (
        std::string& outList
    );
    int listStorages (
        JSON_Object* joResult
    );
    int storageInfo (
        const std::string& storageId,
        std::string& outInfo
    );
    int storageInfo (
        const std::string& storageId,
        JSON_Object* joResult
    );
    int storageOpen (
        const std::string& storageId,
        const CM_OPEN_MODE openMode,
        const std::string& openParams,
        CM_SESSION_API** session
    );
    int storageClose (
        CM_SESSION_API* session
    );
    int storageFormat (
        const std::string& storageId,
        const char* soPassword,
        const char* userPassword
    );

    void blockFree (
        void* block
    );
    void baFree (
        CM_BYTEARRAY* ba
    );

};  //  end class CmProvider


class CmProviderRegistry {
    struct Entry {
        std::weak_ptr<CmProvider>
                    provider;
        HANDLE_DLIB handle;
    };

    std::mutex  m_Mutex;
    std::condition_variable
                m_Cond;
    std::map<std::string, Entry>
                m_Providers;
    //  Providers linked into the executable, keyed by libName; initialized once and owned
    //  by the registry for the lifetime of the process
    std::map<std::string, std::shared_ptr<CmProvider>>
                m_StaticProviders;

    CmProviderRegistry (void) {}

    void release (
        CmProvider* provider
    );

public:
    static CmProviderRegistry& instance (void);

    int registerStatic (
        const std::string& libName,
        const CM_STATIC_PROVIDER_FUNCS& funcs,
        const std::string& jsonParams
    );

    int acquire (
        const std::string& dir,
        const std::string& libName,
        const std::string& jsonParams,
        std::shared_ptr<CmProvider>& provider
    );

};  //  end class CmProviderRegistry


}   //  end namespace UapkiNS


//  Operates on the global session (the one behind process()).
class CmProviders {
public:
    static int loadProvider (const std::string& dir, const std::string& libName, const std::string& jsonParams);
    static void deinit (void);

    static size_t count (void);
    static int getInfo (const size_t index, JSON_Object* joResult);
    static int listStorages (const std::string& providerId, JSON_Object* joResult);
    static int storageInfo (const std::string& providerId, const std::string& storageId, JSON_Object* joResult);
    static int storageOpen (const std::string& providerId, const std::string& storageId, JSON_Object* joParams);
    static int storageClose (void);

    static CmStorageProxy* openedStorage (void);

};  //  end class CmProviders


#endif
