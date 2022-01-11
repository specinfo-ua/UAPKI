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

#include "api-json-internal.h"
#include "cm-loader.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include <string>
#include <vector>


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


typedef struct CM_PROVIDER_ST {
    const string    id;
    CmLoader* const provider;
    CM_PROVIDER_ST (const string& iId, CmLoader* const iProvider) : id(iId), provider(iProvider) {}
} CM_PROVIDER;

typedef struct CM_ACTIVITY_ST {
    const CM_PROVIDER*  provider;
    CM_SESSION_API*     session;
    const CM_KEY_API*   key;
    cm_block_free_f     block_free;
    cm_bytearray_free_f ba_free;
    CM_ACTIVITY_ST (void)
        : provider(nullptr), session(nullptr), key(nullptr), block_free(nullptr), ba_free(nullptr) {}
} CM_ACTIVITY;

static struct {
    CM_ACTIVITY         activity;
    vector<CM_PROVIDER> providers;
    bool keyIsSelected (void) const {
        return (activity.key != nullptr);
    }
    bool sessionIsOpen (void) const {
        return (activity.session != nullptr);
    }
    void setSession (CM_PROVIDER* activeProvider = nullptr, CM_SESSION_API* activeSession = nullptr) {
        activity.provider = activeProvider;
        activity.session = activeSession;
        if (activeProvider) {
            const CM_PROVIDER_API* cm_api = activeProvider->provider->getApi();
            activity.block_free = cm_api->block_free;
            activity.ba_free = cm_api->bytearray_free;
        }
        else {
            activity.block_free = nullptr;
            activity.ba_free = nullptr;
        }
    }
} lib_cmproviders;


static int get_providerid_from_info (CmLoader& provider, string& id)
{
    int ret = RET_OK;
    CM_JSON_PCHAR json_resp = nullptr;
    ParsonHelper json;

    DO(provider.info(&json_resp));
    if (!json.parse((const char*)json_resp)) {
        SET_ERROR(RET_UAPKI_INVALID_JSON_FORMAT)
    }

    json.getString("id", id);

cleanup:
    provider.blockFree(json_resp);
    return ret;
}   //  get_providerid_from_info


int CmProviders::loadProvider (const string& dir, const string& libName, const char* jsonParams)
{
    int ret = RET_OK;
    CmLoader* cmloader = new CmLoader();
    if (!cmloader) return RET_UAPKI_GENERAL_ERROR;

    DEBUG_OUTCON(printf("CmProviders::loadProvider(name: '%s', dir: '%s')\n", libName.c_str(), dir.c_str()));
    if (cmloader->load(libName, dir)) {
        string s_id;
        const CM_ERROR cm_err = cmloader->init((CM_JSON_PCHAR)jsonParams);
        DEBUG_OUTCON(printf("cmloader->init(), cm_err: %d\n", cm_err));
        if ((cm_err == RET_OK) && (get_providerid_from_info(*cmloader, s_id) == RET_OK) && !s_id.empty()) {
            lib_cmproviders.providers.push_back(CM_PROVIDER(s_id, cmloader));
            cmloader = nullptr;
        }
    }

    delete cmloader;
    return ret;
}

void CmProviders::deinit (void)
{
    for (auto& it : lib_cmproviders.providers) {
        it.provider->unload();
    }
    lib_cmproviders.providers.clear();
}

size_t CmProviders::count (void)
{
    return lib_cmproviders.providers.size();
}

int CmProviders::getInfo (const size_t index, JSON_Object* joResult)
{
    if (index >= CmProviders::count()) return RET_INVALID_PARAM;

    int ret = RET_OK;
    CmLoader* provider = lib_cmproviders.providers[index].provider;
    CM_JSON_PCHAR json_resp = nullptr;
    ParsonHelper json;

    DO(provider->info(&json_resp));
    CHECK_NOT_NULL(json.parse((const char*)json_resp));

    DO_JSON(json_object_set_string(joResult, "id",           json.getString("id")));
    DO_JSON(json_object_set_string(joResult, "apiVersion",   json.getString("apiVersion")));
    DO_JSON(json_object_set_string(joResult, "libVersion",   json.getString("libVersion")));
    DO_JSON(json_object_set_string(joResult, "description",  json.getString("description")));
    DO_JSON(json_object_set_string(joResult, "manufacturer", json.getString("manufacturer")));
    DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "supportListStorages",
                                                             json.getBoolean("supportListStorages", false)));
    if (json.hasValue("flags", JSONNumber)) {
        const int flags = json.getInt("flags");
        if ((flags >= 0) && (flags <= 0xFFFFFFFF)) ParsonHelper::jsonObjectSetUint32(joResult, "flags", (uint32_t)flags);
    }

cleanup:
    provider->blockFree(json_resp);
    return ret;
}

struct CM_PROVIDER_ST* CmProviders::getProviderById (const char* id)
{
    const string s_id = string(id);
    for (size_t i = 0; i < lib_cmproviders.providers.size(); i++) {
        CM_PROVIDER* provider = &lib_cmproviders.providers[i];
        if (s_id == provider->id) {
            return provider;
        }
    }
    return nullptr;
}

int CmProviders::listStorages (const char* providerId, JSON_Object* joResult)
{
    CM_PROVIDER* cm_provider = CmProviders::getProviderById(providerId);
    if (!cm_provider) return RET_UAPKI_UNKNOWN_PROVIDER;

    const CM_PROVIDER_API* cm_provapi = cm_provider->provider->getApi();
    if (!cm_provapi) return RET_UAPKI_GENERAL_ERROR;

    CM_ERROR ret = RET_CM_UNSUPPORTED_API;
    if (cm_provapi->list_storages) {
        CM_JSON_PCHAR json_storages = nullptr;
        ret = cm_provapi->list_storages(&json_storages);
        if (ret == RET_OK) {
            JSON_Value* jv_resp = json_parse_string((const char*)json_storages);
            if (jv_resp) {
                JSON_Object* jo_resp = json_value_get_object(jv_resp);
                json_object_copy_all_items(joResult, jo_resp);
                json_value_free(jv_resp);
            }
            cm_provapi->block_free(json_storages);
        }
    }

    return ret;
}

int CmProviders::storageInfo (const char* providerId, const char* storageId, JSON_Object* joResult)
{
    CM_PROVIDER* cm_provider = CmProviders::getProviderById(providerId);
    if (!cm_provider) return RET_UAPKI_UNKNOWN_PROVIDER;

    const CM_PROVIDER_API* cm_provapi = cm_provider->provider->getApi();
    if (!cm_provapi) return RET_UAPKI_GENERAL_ERROR;

    CM_ERROR ret = RET_CM_UNSUPPORTED_API;
    if (cm_provapi->storage_info) {
        CM_JSON_PCHAR json_resp = nullptr;
        CM_ERROR ret = cm_provapi->storage_info(storageId, &json_resp);
        if (ret == RET_OK) {
            JSON_Value* jv_resp = json_parse_string((const char*)json_resp);
            if (jv_resp) {
                JSON_Object* jo_resp = json_value_get_object(jv_resp);
                json_object_copy_all_items(joResult, jo_resp);
                json_value_free(jv_resp);
            }
            cm_provapi->block_free(json_resp);
        }
    }

    return ret;
}

int CmProviders::storageOpen (const char* providerId, const char* storageId, JSON_Object* joParams)
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

    CM_PROVIDER* cm_provider = CmProviders::getProviderById(providerId);
    if (!cm_provider) return RET_UAPKI_UNKNOWN_PROVIDER;

    const CM_PROVIDER_API* cm_provapi = cm_provider->provider->getApi();
    if (!cm_provapi) return RET_UAPKI_GENERAL_ERROR;

    char* s_openparam = nullptr;
    if (ParsonHelper::jsonObjectHasValue(joParams, "openParams", JSONObject)) {
        ParsonHelper json;
        json_object_copy_all_items(json.create(), json_object_get_object(joParams, "openParams"));
        json.serialize(&s_openparam);
    }

    CM_SESSION_API* session = nullptr;
    CM_ERROR ret = cm_provapi->open(storageId, mode, (const CM_JSON_PCHAR)s_openparam, &session);
    ::free((void*)s_openparam);
    if (ret == RET_OK) {
        ret = session->login(session, (const CM_UTF8_CHAR*)s_password.c_str(), s_username);
        if (ret == RET_OK) {
            lib_cmproviders.setSession(cm_provider, session);
        }
        else {
            cm_provapi->close(session);
        }
    }
    return ret;
}

int CmProviders::storageClose (void)
{
    int ret = RET_OK;
    if (lib_cmproviders.sessionIsOpen()) {
        ret = lib_cmproviders.activity.provider->provider->close(lib_cmproviders.activity.session);
        lib_cmproviders.setSession(nullptr, nullptr);
    }
    else {
        ret = RET_UAPKI_NO_STORAGE;
    }
    return ret;
}

void CmProviders::free (void* block)
{
    if (lib_cmproviders.activity.block_free && block) {
        lib_cmproviders.activity.block_free(block);
    }
}

void CmProviders::baFree (CM_BYTEARRAY* ba)
{
    if (lib_cmproviders.activity.ba_free && ba) {
        lib_cmproviders.activity.ba_free(ba);
    }
}

void CmProviders::arrayBaFree (const uint32_t count, CM_BYTEARRAY** arrayBa)
{
    if (lib_cmproviders.activity.ba_free && (count > 0) && arrayBa) {
        for (uint32_t i = 0; i < count; i++) {
            lib_cmproviders.activity.ba_free(arrayBa[i]);
            arrayBa[i] = nullptr;
        }
        if (lib_cmproviders.activity.block_free) {
            lib_cmproviders.activity.block_free(arrayBa);
        }
    }
}

int CmProviders::sessionInfo (JSON_Object* joResult)
{
    if (!lib_cmproviders.sessionIsOpen()) return RET_UAPKI_NO_STORAGE;

    CM_JSON_PCHAR json_resp = nullptr;
    vector<string> mechanisms;
    CM_SESSION_API* ss = lib_cmproviders.activity.session;
    CM_ERROR ret = ss->info(ss, &json_resp);
    if (ret == RET_OK) {
        ParsonHelper json;
        JSON_Object* jo_resp = json.parse((const char*)json_resp);
        JSON_Array* ja_mechanisms = json.getArray("mechanisms");
        for (size_t i = 0; i < json_array_get_count(ja_mechanisms); i++) {
            mechanisms.push_back(string(json_array_get_string(ja_mechanisms, i)));
        }

        json_object_remove(jo_resp, "mechanisms");
        json_object_copy_all_items(joResult, jo_resp);
        json.cleanup();
        lib_cmproviders.activity.block_free(json_resp);
        json_resp = nullptr;

        json_object_set_value(joResult, "mechanisms", json_value_init_array());
        ja_mechanisms = json_object_get_array(joResult, "mechanisms");

        size_t idx_mechanism = 0;
        for (auto& it : mechanisms) {
            const CM_ERROR cm_err = ss->mechanismParameters(ss, (CM_JSON_PCHAR)it.c_str(), (CM_JSON_PCHAR*)&json_resp);
            if (cm_err == RET_OK) {
                jo_resp = json.parse((const char*)json_resp);
                if (jo_resp) {
                    json_array_append_value(ja_mechanisms, json_value_init_object());
                    JSON_Object* jo_mech = json_array_get_object(ja_mechanisms, idx_mechanism);
                    if (jo_mech) {
                        json_object_set_string(jo_mech, "id", it.c_str());
                        json_object_copy_all_items(jo_mech, jo_resp);
                        idx_mechanism++;
                    }
                }
                json.cleanup();
                lib_cmproviders.activity.block_free(json_resp);
                json_resp = nullptr;
            }
        }
    }

    return ret;
}

int CmProviders::sessionListKeys (JSON_Object* joResult)
{
    if (!lib_cmproviders.sessionIsOpen()) return RET_UAPKI_NO_STORAGE;

    uint32_t cnt_keys = 0;
    CM_BYTEARRAY** list_keyids = nullptr;
    CM_JSON_PCHAR json_resp = nullptr;
    CM_SESSION_API* ss = lib_cmproviders.activity.session;
    const CM_ERROR ret = ss->listKeys(ss, &cnt_keys, &list_keyids, &json_resp);
    if (ret == RET_OK) {
        ParsonHelper json;
        JSON_Object* jo_resp = json.parse((const char*)json_resp);
        json_object_copy_all_items(joResult, jo_resp);
        CmProviders::arrayBaFree(cnt_keys, list_keyids);
        CmProviders::free(json_resp);
    }
    return ret;
}

int CmProviders::sessionGetCertificates (uint32_t* countCerts, CM_BYTEARRAY*** baCerts)
{
    *countCerts = 0;
    *baCerts = nullptr;
    if (!lib_cmproviders.sessionIsOpen()) return RET_UAPKI_NO_STORAGE;

    CM_ERROR ret = RET_OK;
    CM_SESSION_API* ss = lib_cmproviders.activity.session;
    if (ss->getCertificates) {
        ret = ss->getCertificates(ss, countCerts, baCerts);
    }
    return ret;
}

int CmProviders::sessionCreateKey (JSON_Object* joParameters, CM_BYTEARRAY** baKeyId)
{
    lib_cmproviders.activity.key = nullptr;
    if (!lib_cmproviders.sessionIsOpen()) return RET_UAPKI_NO_STORAGE;

    char* s_keyparam = nullptr;
    ParsonHelper json;
    json_object_copy_all_items(json.create(), joParameters);
    json.serialize(&s_keyparam);
    if (!s_keyparam) return RET_UAPKI_GENERAL_ERROR;

    const CM_KEY_API* key = nullptr;
    CM_SESSION_API* ss = lib_cmproviders.activity.session;
    CM_ERROR ret = ss->createKey(ss, (CM_JSON_PCHAR)s_keyparam, &key);
    free(s_keyparam);

    if (ret == RET_OK) {
        lib_cmproviders.activity.key = key;
        ret = key->getInfo(ss, nullptr, baKeyId);
    }
    return ret;
}

int CmProviders::sessionDeleteKey (CM_BYTEARRAY* baKeyId)
{
    lib_cmproviders.activity.key = nullptr;
    if (!lib_cmproviders.sessionIsOpen()) return RET_UAPKI_NO_STORAGE;

    CM_SESSION_API* ss = lib_cmproviders.activity.session;
    const CM_ERROR ret = ss->deleteKey(ss, baKeyId, false);
    return ret;
}

int CmProviders::sessionSelectKey (CM_BYTEARRAY* baKeyId)
{
    lib_cmproviders.activity.key = nullptr;
    if (!lib_cmproviders.sessionIsOpen()) return RET_UAPKI_NO_STORAGE;

    const CM_KEY_API* cm_key = nullptr;
    CM_SESSION_API* ss = lib_cmproviders.activity.session;
    const CM_ERROR ret = ss->selectKey(ss, baKeyId, &cm_key);
    if (ret == RET_OK) {
        lib_cmproviders.activity.key = cm_key;
    }
    return ret;
}

int CmProviders::sessionChangePassword (const CM_UTF8_CHAR* newPassword)
{
    if (!lib_cmproviders.sessionIsOpen()) return RET_UAPKI_NO_STORAGE;

    CM_SESSION_API* ss = lib_cmproviders.activity.session;
    const CM_ERROR ret = (ss->changePassword)
        ? ss->changePassword(ss, newPassword) : RET_UAPKI_NOT_SUPPORTED;
    return ret;
}

int CmProviders::keyIsSelected (void)
{
    if (!lib_cmproviders.sessionIsOpen()) return RET_UAPKI_NO_STORAGE;

    return (lib_cmproviders.keyIsSelected()) ? RET_OK : RET_UAPKI_KEY_NOT_SELECTED;
}

int CmProviders::keyGetInfo (CM_JSON_PCHAR* keyInfo, CM_BYTEARRAY** keyId)
{
    int ret = keyIsSelected();
    if (ret != RET_OK) return ret;

    CM_SESSION_API* ss = lib_cmproviders.activity.session;
    const CM_KEY_API* key = lib_cmproviders.activity.key;
    ret = (key->getInfo)
        ? key->getInfo(ss, keyInfo, keyId) : RET_UAPKI_NOT_SUPPORTED;
    return ret;
}

int CmProviders::keyGetPublickey (CM_BYTEARRAY** baAlgorithmIdentifier, CM_BYTEARRAY** baPublicKey)
{
    int ret = keyIsSelected();
    if (ret != RET_OK) return ret;

    CM_SESSION_API* ss = lib_cmproviders.activity.session;
    const CM_KEY_API* key = lib_cmproviders.activity.key;
    ret = (key->getPublicKey)
        ? key->getPublicKey(ss, baAlgorithmIdentifier, baPublicKey) : RET_UAPKI_NOT_SUPPORTED;
    return ret;
}

int CmProviders::keyInitUsage (JSON_Object* joParameters)
{
    int ret = CmProviders::keyIsSelected();
    if (ret != RET_OK) return ret;

    CM_SESSION_API* ss = lib_cmproviders.activity.session;
    const CM_KEY_API* key = lib_cmproviders.activity.key;

    //  Note: initKeyUsage() - this device-specific function
    if (key->initKeyUsage) {
        char* s_initkeyusage = nullptr;
        if (joParameters) {
            ParsonHelper json;
            json_object_copy_all_items(json.create(), joParameters);
            json.serialize(&s_initkeyusage);
        }
        ret = key->initKeyUsage(ss, (void*)s_initkeyusage);
        free((void*)s_initkeyusage);
    }
    return ret;
}

int CmProviders::keySetOtp (const CM_UTF8_CHAR* otp)
{
    int ret = CmProviders::keyIsSelected();
    if (ret != RET_OK) return ret;

    CM_SESSION_API* ss = lib_cmproviders.activity.session;
    const CM_KEY_API* key = lib_cmproviders.activity.key;
    ret = (key->setOtp)
        ? key->setOtp(ss, otp) : RET_UAPKI_NOT_SUPPORTED;
    return ret;
}

int CmProviders::keySign (const CM_UTF8_CHAR* signAlgo, const CM_BYTEARRAY* baSignAlgoParams,
    const uint32_t count, const CM_BYTEARRAY** baHashes, CM_BYTEARRAY*** baSignatures)
{
    int ret = CmProviders::keyIsSelected();
    if (ret != RET_OK) return ret;

    CM_SESSION_API* ss = lib_cmproviders.activity.session;
    const CM_KEY_API* key = lib_cmproviders.activity.key;
    ret = (key->sign)
        ? key->sign(ss, signAlgo, baSignAlgoParams, count, baHashes, baSignatures) : RET_UAPKI_NOT_SUPPORTED;
    return ret;
}

int CmProviders::keySignInit (const CM_UTF8_CHAR* signAlgo, const CM_BYTEARRAY* baSignAlgoParams)
{
    int ret = CmProviders::keyIsSelected();
    if (ret != RET_OK) return ret;

    CM_SESSION_API* ss = lib_cmproviders.activity.session;
    const CM_KEY_API* key = lib_cmproviders.activity.key;
    ret = (key->signInit)
        ? key->signInit(ss, signAlgo, baSignAlgoParams) : RET_UAPKI_NOT_SUPPORTED;
    return ret;
}

int CmProviders::keySignUpdate (const CM_BYTEARRAY* baData)
{
    int ret = CmProviders::keyIsSelected();
    if (ret != RET_OK) return ret;

    CM_SESSION_API* ss = lib_cmproviders.activity.session;
    const CM_KEY_API* key = lib_cmproviders.activity.key;
    ret = (key->signUpdate)
        ? key->signUpdate(ss, baData) : RET_UAPKI_NOT_SUPPORTED;
    return ret;
}

int CmProviders::keySignFinal (CM_BYTEARRAY** baSignature)
{
    int ret = CmProviders::keyIsSelected();
    if (ret != RET_OK) return ret;

    CM_SESSION_API* ss = lib_cmproviders.activity.session;
    const CM_KEY_API* key = lib_cmproviders.activity.key;
    ret = (key->signFinal)
        ? key->signFinal(ss, baSignature) : RET_UAPKI_NOT_SUPPORTED;
    return ret;
}

int CmProviders::keySignData (const CM_UTF8_CHAR* signAlgo, const CM_BYTEARRAY* baSignAlgoParams,
    const CM_BYTEARRAY* baData, CM_BYTEARRAY** baSignature)
{
    int ret = CmProviders::keyIsSelected();
    if (ret != RET_OK) return ret;

    CM_SESSION_API* ss = lib_cmproviders.activity.session;
    const CM_KEY_API* key = lib_cmproviders.activity.key;
    if (!key->sign) return RET_UAPKI_NOT_SUPPORTED;

    const SignAlg sign_alg = signature_from_oid((const char*)signAlgo);
    if (sign_alg == SIGN_UNDEFINED) return RET_UAPKI_UNSUPPORTED_ALG;

    HashAlg hash_alg = HASH_ALG_UNDEFINED;
    if (sign_alg != SIGN_RSA_PSS) {
        hash_alg = hash_from_oid((const char*)signAlgo);
    }
    else {
        //TODO: later impl SIGN_RSA_PSS, see pkcs12 - DO(hash_from_rsa_pss(baSignAlgoParams, &hash_alg));
    }
    if (hash_alg == HASH_ALG_UNDEFINED) return RET_UAPKI_UNSUPPORTED_ALG;

    ByteArray* ba_hash = nullptr;
    ret = ::hash(hash_alg, (const ByteArray*)baData, &ba_hash);
    if (ret != RET_OK) return ret;

    CM_BYTEARRAY** cmba_signatures = nullptr;
    vector<ByteArray*> ba_hashes;
    ba_hashes.push_back(ba_hash);
    ret = key->sign(ss, signAlgo, baSignAlgoParams, 1, (const CM_BYTEARRAY**)ba_hashes.data(), &cmba_signatures);
    ba_free(ba_hash);
    if (ret == RET_OK) {
        *baSignature = cmba_signatures[0];   //  Note: called routine must be use CmProviders::baFree() for free baSignature
        free(cmba_signatures);
    }
    return ret;
}

int CmProviders::keyGetCertificates (uint32_t* countCerts, CM_BYTEARRAY*** baCerts)
{
    *countCerts = 0;
    *baCerts = nullptr;
    int ret = CmProviders::keyIsSelected();
    if (ret != RET_OK) return ret;

    CM_SESSION_API* ss = lib_cmproviders.activity.session;
    const CM_KEY_API* key = lib_cmproviders.activity.key;
    ret = (key->getCertificates)
        ? key->getCertificates(ss, countCerts, baCerts) : RET_UAPKI_NOT_SUPPORTED;
    return ret;
}

int CmProviders::keyAddCertificate (const CM_BYTEARRAY* baCert)
{
    int ret = CmProviders::keyIsSelected();
    if (ret != RET_OK) return ret;

    CM_SESSION_API* ss = lib_cmproviders.activity.session;
    const CM_KEY_API* key = lib_cmproviders.activity.key;
    ret = (key->addCertificate)
        ? key->addCertificate(ss, baCert) : RET_UAPKI_NOT_SUPPORTED;
    return ret;
}

int CmProviders::keyGetCsr (const CM_UTF8_CHAR* signAlgo, const CM_BYTEARRAY* baSignAlgoParams,
    const CM_BYTEARRAY* baSubject, const CM_BYTEARRAY* baAttributes, CM_BYTEARRAY** baCsr)
{
    int ret = CmProviders::keyIsSelected();
    if (ret != RET_OK) return ret;

    CM_SESSION_API* ss = lib_cmproviders.activity.session;
    const CM_KEY_API* key = lib_cmproviders.activity.key;
    ret = (key->getCsr)
        ? key->getCsr(ss, signAlgo, baSignAlgoParams, baSubject, baAttributes, baCsr) : RET_UAPKI_NOT_SUPPORTED;
    return ret;
}
