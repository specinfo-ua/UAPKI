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
#include "asn1-ba-utils.h"
#include "global-objects.h"
#include "http-helper.h"
#include "parson-helper.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


static int load_config (ParsonHelper& json, const char* configFile, JSON_Object** joResult)
{
    int ret = RET_OK;
    ByteArray* ba_json = nullptr;
    size_t len = 0;

    if (!configFile) return RET_OK;

    DO(ba_alloc_from_file(configFile, &ba_json));

    len = ba_get_len(ba_json);
    DO(ba_change_len(ba_json, len + 1));
    DO(ba_set_byte(ba_json, len, 0));

    if (json.parse((const char*)ba_get_buf_const(ba_json), true) == NULL) {
        SET_ERROR(RET_UAPKI_INVALID_JSON_FORMAT);
    }

cleanup:
    ba_free(ba_json);
    return ret;
}   //  load_config

static int setup_cm_providers (JSON_Object* joParams)
{
    const string s_dir = ParsonHelper::jsonObjectGetString(joParams, "dir");
    JSON_Array* ja_providers = json_object_get_array(joParams, "allowedProviders");
    size_t len = json_array_get_count(ja_providers);

    for (size_t i = 0; i < len; i++) {
        JSON_Object* jo_provider = json_array_get_object(ja_providers, i);
        if (!jo_provider) return RET_UAPKI_INVALID_JSON_FORMAT;

        string s_config;
        const string s_lib = ParsonHelper::jsonObjectGetString(jo_provider, "lib");
        JSON_Object* jo_config = json_object_get_object(jo_provider, "config");
        if (jo_config) {
            ParsonHelper json;
            json_object_copy_all_items(json.create(), jo_config);
            json.serialize(s_config);
        }

        const int ret = CmProviders::loadProvider(s_dir, s_lib, !s_config.empty() ? s_config.c_str() : nullptr);
        if (ret != RET_OK) return ret;
    }

    return RET_OK;
}

static int setup_cert_cache (JSON_Object* joParams)
{
    int ret = RET_OK;
    CerStore* cer_store = get_cerstore();
    ByteArray* ba_encoded = nullptr;
    JSON_Array* ja_trustedcerts = json_object_get_array(joParams, "trustedCerts");
    const char* s_path = nullptr;

    if (ja_trustedcerts) {
        const size_t cnt_certs = json_array_get_count(ja_trustedcerts);
        for (size_t i = 0; i < cnt_certs; i++) {
            bool is_unique;
            const char* s_b64 = json_array_get_string(ja_trustedcerts, i);
            if (s_b64) {
                ba_encoded = ba_alloc_from_base64(s_b64);
            }
            if (!ba_encoded) {
                SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
            }
            DO(cer_store->addCert(ba_encoded, false, false, true, is_unique, NULL));
            ba_encoded = nullptr;
        }
    }

    s_path = json_object_get_string(joParams, "path");
    if (s_path) {
        DO(cer_store->load(s_path));
    }

cleanup:
    ba_free(ba_encoded);
    return ret;
}   //  setup_cert_cache

static int setup_crl_cache (JSON_Object* joParams)
{
    int ret = RET_OK;
    CrlStore* crl_store = get_crlstore();
    const char* s_path = json_object_get_string(joParams, "path");

    if (s_path) {
        DO(crl_store->load(s_path));
    }

cleanup:
    return ret;
}   //  setup_crl_cache

static int setup_tsp (JSON_Object* joParams, LibraryConfig& libConfig)
{
    int ret = RET_OK;
    ByteArray* ba_encoded = nullptr;
    LibraryConfig::TspParams params;

    params.url = ParsonHelper::jsonObjectGetString(joParams, "url");

    params.policyId = ParsonHelper::jsonObjectGetString(joParams, "policyId");
    if (!params.policyId.empty()) {
        if (ba_encode_oid(params.policyId.c_str(), &ba_encoded) != RET_OK) {
            params.policyId.clear();
        }
    }

    libConfig.setTsp(params);

    ba_free(ba_encoded);
    return ret;
}   //  setup_tsp


int uapki_init (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    ParsonHelper json;
    LibraryConfig* lib_config = nullptr;
    CerStore* lib_cerstore = nullptr;
    CrlStore* lib_crlstore = nullptr;
    JSON_Object* jo_params = joParams;
    JSON_Object* jo_subresult = nullptr;
    size_t count;
    bool offline;

    lib_config = get_config();
    if (lib_config) {
        if (lib_config->isInitialized()) return RET_UAPKI_ALREADY_INITIALIZED;
        DO(load_config(json, json_object_get_string(joParams, "configFile"), &jo_params));
    }
    else {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    lib_cerstore = get_cerstore();
    if (!lib_cerstore) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    lib_crlstore = get_crlstore();
    if (!lib_crlstore) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    //  Setup subsystems
    DO(setup_cm_providers(json_object_get_object(jo_params, "cmProviders")));

    DO(setup_cert_cache(json_object_get_object(jo_params, "certCache")));

    DO(setup_crl_cache(json_object_get_object(jo_params, "crlCache")));

    offline = ParsonHelper::jsonObjectGetBoolean(jo_params, "offline", false);
    lib_config->setOffline(offline);

    DO(setup_tsp(json_object_get_object(jo_params, "tsp"), *lib_config));

    HttpHelper::init(offline);

    lib_config->setInitialized(true);

    //  Out info subsystems
    DO_JSON(json_object_set_value(joResult, "certCache", json_value_init_object()));
    jo_subresult = json_object_get_object(joResult, "certCache");
    if (lib_cerstore->getCount(count) == RET_OK) {
        DO_JSON(ParsonHelper::jsonObjectSetUint32(jo_subresult, "countCerts", (uint32_t)count));
    }
    if (lib_cerstore->getCountTrusted(count) == RET_OK) {
        DO_JSON(ParsonHelper::jsonObjectSetUint32(jo_subresult, "countTrustedCerts", (uint32_t)count));
    }

    DO_JSON(json_object_set_value(joResult, "crlCache", json_value_init_object()));
    jo_subresult = json_object_get_object(joResult, "crlCache");
    if (lib_crlstore->getCount(count) == RET_OK) {
        DO_JSON(ParsonHelper::jsonObjectSetUint32(jo_subresult, "countCrls", (uint32_t)count));
    }

    DO_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "countCmProviders", (uint32_t)CmProviders::count()));

    ParsonHelper::jsonObjectSetBoolean(joResult, "offline", offline);

    DO_JSON(json_object_set_value(joResult, "tsp", json_value_init_object()));
    jo_subresult = json_object_get_object(joResult, "tsp");
    DO_JSON(json_object_set_string(jo_subresult, "url", lib_config->getTsp().url.c_str()));
    DO_JSON(json_object_set_string(jo_subresult, "policyId", lib_config->getTsp().policyId.c_str()));

cleanup:
    if (ret != RET_OK) {
        release_config();
        CmProviders::deinit();
        release_stores();
        HttpHelper::deinit();
    }

    return ret;
}
