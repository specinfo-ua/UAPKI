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

#define FILE_MARKER "cm-cryptoki/cm-cryptoki.cpp"

#include <stdlib.h>
#include <string>
#include <vector>
#include "ba-utils.h"
#include "cryptoki-const-ukr.h"
#include "cryptoki-storage.h"
#include "cm-cryptoki.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include "uapki-ns-util.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


struct CryptokiProviderInfo {
    CryptokiProviderId  id;
    const char*         libName;
};  //  end enum class CryptokiProviderInfo


static const char* HEX_LOWER_SYMBOLS = "0123456789abcdef";
static const char* HEX_UPPER_SYMBOLS = "0123456789ABCDEF";


CmCryptoki::SessionContext::SessionContext (
        CryptokiProvider& refCkProvider
)
    : m_Storage(refCkProvider.helper)
    , m_ProviderId(refCkProvider.id)
    , m_ProviderParams(refCkProvider.params)
    , m_CtxHash(nullptr)
    , m_HashAlgo(HASH_ALG_UNDEFINED)
{
    DEBUG_OUTCON(puts("CmCryptoki::SessionContext::SessionContext()"));
    memset(&m_KeyApi, 0, sizeof(CM_KEY_API));
    assignKeyApi();
}

CmCryptoki::SessionContext::~SessionContext (void)
{
    DEBUG_OUTCON(puts("CmCryptoki::SessionContext::~SessionContext()"));
    resetLongSign();
    memset(&m_KeyApi, 0, sizeof(CM_KEY_API));
}

void CmCryptoki::SessionContext::resetLongSign (void)
{
    if (m_CtxHash) {
        hash_free(m_CtxHash);
        m_CtxHash = nullptr;
    }
    m_HashAlgo = HASH_ALG_UNDEFINED;
    m_SignAlgo.clear();
}


CmCryptoki::CmCryptoki (void)
{
    DEBUG_OUTCON(puts("CmCryptoki::CmCryptoki()"));
}

CmCryptoki::~CmCryptoki (void)
{
    DEBUG_OUTCON(puts("CmCryptoki::~CmCryptoki()"));
}

CM_ERROR CmCryptoki::init (
        JSON_Object* joParams
)
{
    bool subject_keyid = false;
    if (joParams) {
        subject_keyid = ParsonHelper::jsonObjectGetBoolean(joParams, "subjectKeyId");
        JSON_Array* ja_modules = json_object_get_array(joParams, "modules");
        const size_t cnt_modules = json_array_get_count(ja_modules);
        if (cnt_modules > 0) {
            m_CryptokiProviders.resize(cnt_modules);
            for (size_t i = 0; i < cnt_modules; i++) {
                CryptokiProvider& cryptoki_provider = m_CryptokiProviders[i];
                JSON_Object* const jo_module = json_array_get_object(ja_modules, i);
                cryptoki_provider.libName = ParsonHelper::jsonObjectGetString(jo_module, "name");
                if (cryptoki_provider.libName.empty()) continue;

                cryptoki_provider.params.ekuDevice = ParsonHelper::jsonObjectGetBoolean(jo_module, "ekuDevice", false);
                cryptoki_provider.params.pkAttestate = ParsonHelper::jsonObjectGetBoolean(jo_module, "pka", false);
                cryptoki_provider.params.subjectKeyId = subject_keyid;
            }
        }
    }

    for (auto& it : m_CryptokiProviders) {
        if (it.helper.load(it.libName)) {
            (void)(it.helper.initialize(nullptr));
        }
    }

    return RET_OK;
}

size_t CmCryptoki::detectStorages (void)
{
    m_DetectedStorages.clear();

    size_t cnt_initprovs = 0;
    for (size_t i = 0; i < m_CryptokiProviders.size(); i++) {
        CryptokiProvider& cr_prov = m_CryptokiProviders[i];
        if (!cr_prov.helper.isInitialized()) continue;

        cnt_initprovs++;
        vector<CK_SLOT_ID> list_slotids;
        if (cr_prov.helper.getSlotList(true, list_slotids) != CKR_OK) continue;

        for (const auto it_slotid : list_slotids) {
            Cryptoki::TokenInfo token_info;
            if ((cr_prov.helper.getTokenInfo(it_slotid, token_info) != CKR_OK) || token_info.serialNumber.empty()) {
                continue;
            }

            if (cr_prov.id == CryptokiProviderId::UNDEFINED) {
                cr_prov.id = cryptokiProviderIdByModel(token_info);
                if (cr_prov.id == CryptokiProviderId::UNDEFINED) {
                    cr_prov.id = CryptokiProviderId(size_t(CryptokiProviderId::UNKNOWN) + i);
                }
            }

            m_DetectedStorages.push_back(DetectedStorage(&cr_prov, token_info.serialNumber, it_slotid, token_info));
        }
    }

    return cnt_initprovs;
}

CmCryptoki::DetectedStorage* CmCryptoki::foundStorage (
        const std::string& storageId
)
{
    for (size_t i = 0; i < m_DetectedStorages.size(); i++) {
        DetectedStorage* detected_storage = &m_DetectedStorages[i];
        if (detected_storage->pCkProvider && (detected_storage->storageId == storageId)) {
            return detected_storage;
        }
    }

    return nullptr;
}

CM_ERROR CmCryptoki::listStorages (
        CM_JSON_PCHAR* jsonList
)
{
    DEBUG_OUTCON(puts("CmCryptoki::listStorages()"));
    m_DetectedStorages.clear();
    if (!jsonList) return RET_CM_INVALID_PARAMETER;

    if (detectStorages() == 0) return RET_CM_LIBRARY_NOT_LOADED;

    ParsonHelper json;
    if (!json.create()) return RET_CM_GENERAL_ERROR;

    JSON_Array* ja_results = json.setArray("storages");
    for (const auto& it : m_DetectedStorages) {
        const size_t idx_last = json_array_get_count(ja_results);
        json_array_append_value(ja_results, json_value_init_object());
        if (deviceInfoToJson(it.tokenInfo, json_array_get_object(ja_results, idx_last), false) != CKR_OK) {
            json_array_remove(ja_results, idx_last);
            continue;
        }
    }

    return (json.serialize((char**)jsonList)) ? RET_OK : RET_CM_JSON_FAILURE;
}

CM_ERROR CmCryptoki::storageInfo (
        const char* storageId,
        CM_JSON_PCHAR* jsonInfo
)
{
    DEBUG_OUTCON(puts("CmCryptoki::storageInfo()"));
    if (!storageId) return RET_CM_INVALID_PARAMETER;

    const string s_storageid = string(storageId);
    Cryptoki::TokenInfo token_info;
    DetectedStorage* p_detectedstorage = foundStorage(s_storageid);
    if (p_detectedstorage) {
        const CK_RV ck_rv = p_detectedstorage->pCkProvider->helper.getTokenInfo(p_detectedstorage->slotId, token_info);
        if (ck_rv != CKR_OK) return CryptokiStorage::toCmError(ck_rv);

        if (token_info.serialNumber != s_storageid) return RET_CM_STORAGE_NOT_FOUND;
        p_detectedstorage->tokenInfo = token_info;
    }
    else {
        (void)detectStorages();
        p_detectedstorage = foundStorage(s_storageid);
        if (!p_detectedstorage) return RET_CM_STORAGE_NOT_FOUND;
        //  after detectStorages() we have actual slotId and tokenInfo
        token_info = p_detectedstorage->tokenInfo;
    }

    ParsonHelper json;
    CM_ERROR cm_err = deviceInfoToJson(token_info, json.create(), false);
    if (cm_err != RET_OK) return cm_err;

    cm_err = (json.serialize((char**)jsonInfo)) ? RET_OK : RET_CM_JSON_FAILURE;
    return cm_err;
}

CM_ERROR CmCryptoki::open (
        const char* storageId,
        uint32_t openMode,
        const CM_JSON_PCHAR openParams,
        CM_SESSION_API** session
)
{
    (void)openParams;
    DEBUG_OUTCON(puts("CmCryptoki::open()"));
    if (!storageId || !session) return RET_CM_INVALID_PARAMETER;

    bool is_readonly = false;
    switch (openMode) {
    case OPEN_MODE_RO:
        is_readonly = true;
        break;
    case OPEN_MODE_RW:
    case OPEN_MODE_CREATE:
        break;
    default:
        return RET_CM_INVALID_PARAMETER;
    }

    const string s_storageid = string(storageId);
    Cryptoki::TokenInfo token_info;
    DetectedStorage* p_detectedstorage = foundStorage(s_storageid);
    if (p_detectedstorage) {
        const CK_RV ck_rv = p_detectedstorage->pCkProvider->helper.getTokenInfo(p_detectedstorage->slotId, token_info);
        if (ck_rv != CKR_OK) return CryptokiStorage::toCmError(ck_rv);

        if (token_info.serialNumber != s_storageid) return RET_CM_STORAGE_NOT_FOUND;
        p_detectedstorage->tokenInfo = token_info;
    }
    else {
        (void)detectStorages();
        p_detectedstorage = foundStorage(s_storageid);
        if (!p_detectedstorage) return RET_CM_STORAGE_NOT_FOUND;
        //  after detectStorages() we have actual slotId and tokenInfo
        token_info = p_detectedstorage->tokenInfo;
    }

    SessionContext* ss_ctx = new SessionContext(*p_detectedstorage->pCkProvider);
    if (!ss_ctx) return RET_CM_GENERAL_ERROR;

    CryptokiStorage& storage = ss_ctx->getStorage();
    CM_ERROR cm_err = storage.open(p_detectedstorage->slotId, is_readonly, s_storageid);
    if (cm_err != RET_OK) {
        delete ss_ctx;
        return RET_CM_STORAGE_NOT_OPEN;
    }

    CM_SESSION_API* new_ss = (CM_SESSION_API*)calloc(1, sizeof(CM_SESSION_API));
    if (!new_ss) {
        delete ss_ctx;
        return RET_CM_GENERAL_ERROR;
    }

    ss_ctx->assignSessionApi(*new_ss);
    *session = new_ss;
    return RET_OK;
}

CM_ERROR CmCryptoki::close (
        CM_SESSION_API* session
)
{
    DEBUG_OUTCON(puts("CmCryptoki::close()"));
    if (session && session->ctx) {
        delete (SessionContext*)session->ctx;
        ::free(session);
    }
    return RET_OK;
}

string CmCryptoki::bufferToHex (
        const ByteArray* ba,
        const bool lowerCase
)
{
    const char* hex_symbols = (lowerCase) ? HEX_LOWER_SYMBOLS : HEX_UPPER_SYMBOLS;
    const uint8_t* buf = ba_get_buf_const(ba);
    const size_t len = ba_get_len(ba);

    string rv_hex;
    rv_hex.resize(2 * len);
    for (size_t i = 0, j = 0; i < len; i++) {
        rv_hex[j++] = hex_symbols[buf[i] >> 4];
        rv_hex[j++] = hex_symbols[buf[i] & 0x0F];
    }

    return rv_hex;
}

string CmCryptoki::bufferToHex (
        const Cryptoki::Buffer& buf,
        const bool lowerCase
)
{
    const char* hex_symbols = (lowerCase) ? HEX_LOWER_SYMBOLS : HEX_UPPER_SYMBOLS;

    string rv_hex;
    rv_hex.resize(2 * buf.size());
    for (size_t i = 0, j = 0; i < buf.size(); i++) {
        rv_hex[j++] = hex_symbols[buf[i] >> 4];
        rv_hex[j++] = hex_symbols[buf[i] & 0x0F];
    }

    return rv_hex;
}

CryptokiProviderId CmCryptoki::cryptokiProviderIdByModel (
        const Cryptoki::TokenInfo& tokenInfo
)
{
    CryptokiProviderId rv_cpid = CryptokiProviderId::UNDEFINED;
    if (
        (tokenInfo.manufacturerId == string("SPECINFOSYSTEMS LLC")) ||
        (tokenInfo.model == string("DIAMOND 1000")) ||
        (tokenInfo.model == string("DIAMOND 2000")) ||
        (tokenInfo.model == string("DIAMOND 3000")) ||
        (tokenInfo.model == string("DIAMOND 4000")) ||
        (tokenInfo.model == string("OLYMP HSM")) ||
        (tokenInfo.model == string("OLYMP mini HSM"))
    ) {
        rv_cpid = CryptokiProviderId::SIS_P11;
    } else if (
        (tokenInfo.manufacturerId == string("AvestUA")) ||
        (tokenInfo.model == string("AvestKey"))
    ) {
        rv_cpid = CryptokiProviderId::AVEST_KEY;
    } else if (
        (tokenInfo.manufacturerId == string("AVTOR LLC")) ||
        (tokenInfo.model == string("CC-337 RSA DSTU")) ||
        (tokenInfo.model == string("ST-338"))
    ) {
        rv_cpid = CryptokiProviderId::AVTOR_STOKEN33X;
    } else if ((tokenInfo.model == string("E.key_Almaz-1C"))) {
        rv_cpid = CryptokiProviderId::IIT_ALMAZ1C;
    } else if ((tokenInfo.model == string("NCM_Gryada301"))) {
        rv_cpid = CryptokiProviderId::IIT_GRYADA;
    }
    else if (
        (tokenInfo.manufacturerId == string("SoftHSM project")) ||
        (tokenInfo.model == string("SoftHSM v2"))
    ) {
        rv_cpid = CryptokiProviderId::SOFTHSM2;
    }

    return rv_cpid;
}


CM_ERROR CmCryptoki::getKeyAttestate (
        CryptokiStorage& storage,
        const CryptokiStorage::KeyInfo& keyInfo,
        Cryptoki::Buffer& buf
)
{
    const CK_RV ck_err = storage.getSession().getAttributeBuffer(
        keyInfo.hPrivateKey,
        Cryptoki::CKA::UKR::KEY_ATTESTATE,
        buf
    );

    return CryptokiStorage::toCmError(ck_err);
}
