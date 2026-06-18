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

#ifndef CM_CRYPTOKI_H
#define CM_CRYPTOKI_H


#include "cryptoki-storage.h"
#include "cryptoki-helper.h"
#include "hash.h"
#include "parson.h"
#include "uapki-ns.h"


enum class CryptokiProviderId : uint32_t {
    UNDEFINED = 0,
    SIS_P11,
    AVEST_KEY,
    AVTOR_STOKEN33X,
    IIT_ALMAZ1C,
    IIT_GRYADA,
    SOFTHSM2,
    UNKNOWN = 100
};  //  end enum class CryptokiProviderId


class CmCryptoki
{
    struct ProviderParams {
        bool        ekuDevice;
        bool        pkAttestate;
        bool        subjectKeyId;
    };  //  end struct ProviderParams

    struct CryptokiProvider {
        CryptokiProviderId
                    id;
        std::string libName;
        ProviderParams
                    params;
        Cryptoki::Helper
                    helper;

        CryptokiProvider (void)
            : id(CryptokiProviderId::UNDEFINED)
            , params(ProviderParams{false, false, false})
        {}
    };  //  end struct CryptokiProvider

    struct DetectedStorage {
        CryptokiProvider*
                    pCkProvider;
        std::string storageId;
        CK_SLOT_ID  slotId;
        Cryptoki::TokenInfo
                    tokenInfo;

        DetectedStorage (
            CryptokiProvider* iCkProvider = nullptr,
            const std::string& iStorageId = std::string{},
            const CK_SLOT_ID iSlotId = (CK_SLOT_ID) - 1,
            const Cryptoki::TokenInfo& iTokenInfo = Cryptoki::TokenInfo{}
        )
            : pCkProvider(iCkProvider)
            , storageId(iStorageId)
            , slotId(iSlotId)
            , tokenInfo(iTokenInfo)
        {}

    };  //  end struct DetectedStorage

    std::vector<CryptokiProvider>
                m_CryptokiProviders;
    std::vector<DetectedStorage>
                m_DetectedStorages;

public:
    class SessionContext {
        CryptokiStorage
                    m_Storage;
        CryptokiProviderId
                    m_ProviderId;
        ProviderParams
                    m_ProviderParams;
        CM_KEY_API  m_KeyApi;
        //  data for sign-init/update/final
        HashCtx*    m_CtxHash;
        HashAlg     m_HashAlgo;
        UapkiNS::AlgorithmIdentifier
                    m_SignAlgo;

    public:
        SessionContext (
            CryptokiProvider& refCkProvider
        );
        ~SessionContext (void);

        const CM_KEY_API* getKeyApi (void) const {
            return &m_KeyApi;
        }
        const CryptokiProviderId getProviderId (void) const {
            return m_ProviderId;
        }
        const ProviderParams getProviderParams (void) const {
            return m_ProviderParams;
        }
        CryptokiStorage& getStorage (void) {
            return m_Storage;
        }

        void assignSessionApi (
            CM_SESSION_API& session
        );
        void resetLongSign (void);
        // TODO: impl getter and setter for LongSign

    private:
        void assignKeyApi (void);

    };  //  end class SessionContext

public:
    CmCryptoki (void);
    ~CmCryptoki (void);

    CM_ERROR init (
        JSON_Object* joParams
    );

private:
    size_t detectStorages (void);
    DetectedStorage* foundStorage (
        const std::string& storageId
    );

public:
    CM_ERROR listStorages (
        CM_JSON_PCHAR* jsonList
    );
    CM_ERROR storageInfo (
        const char* storageId,
        CM_JSON_PCHAR* jsonInfo
    );
    CM_ERROR open (
        const char* storageId,
        uint32_t openMode,
        const CM_JSON_PCHAR openParams,
        CM_SESSION_API** session
    );
    CM_ERROR close (
        CM_SESSION_API* session
    );

public:
    static std::string bufferToHex (
        const ByteArray* ba,
        const bool lowerCase
    );
    static std::string bufferToHex (
        const Cryptoki::Buffer& buf,
        const bool lowerCase
    );

    static CryptokiProviderId cryptokiProviderIdByModel(
        const Cryptoki::TokenInfo& tokenInfo
    );

    static CM_ERROR getKeyAttestate (
        CryptokiStorage& storage,
        const CryptokiStorage::KeyInfo& keyInfo,
        Cryptoki::Buffer& buf
    );

    static CM_ERROR deviceInfoToJson (
        const Cryptoki::TokenInfo& tokenInfo,
        JSON_Object* joResult,
        const bool isBasic
    );
    static CM_ERROR keyInfoToJson (
        const CryptokiStorage::KeyInfo& keyInfo,
        JSON_Object* joResult
    );
    static CM_ERROR listMechanismsToJson (
        const CryptokiStorage& storage,
        JSON_Array* jaMechanisms
    );
    static CM_ERROR mechanismParamsToJson (
        const CryptokiStorage& storage,
        const char* mechanismId,
        CM_JSON_PCHAR* jsonResult
    );
    static CM_ERROR providerInfoToJson (
        CM_JSON_PCHAR* jsonResult
    );
    static CM_ERROR sessionInfoToJson (
        const CryptokiStorage& storage,
        CM_JSON_PCHAR* jsonResult
    );

public:
    static const uint32_t CM_SESSION_API_V1 = 1;

};  //  end class CmCryptoki


#endif
