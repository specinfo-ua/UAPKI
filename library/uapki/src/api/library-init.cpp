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

#define FILE_MARKER "uapki/api/library-init.cpp"

#include "api-json-internal.h"
#include "global-objects.h"
#include "http-helper.h"
#include "ocsp-helper.h"
#include "parson-helper.h"
#include "tsp-helper.h"
#include "uapki-ns-util.h"


using namespace std;
using namespace UapkiNS;


static int load_config (ParsonHelper& json, const string& configFile)
{
    int ret = RET_OK;
    UapkiNS::SmartBA sba_json;
    size_t len = 0;

    DO(ba_alloc_from_file(configFile.c_str(), &sba_json));

    len = sba_json.size();
    DO(ba_change_len(sba_json.get(), len + 1));
    DO(ba_set_byte(sba_json.get(), len, 0));

    if (!json.parse((const char*)sba_json.buf(), true)) {
        SET_ERROR(RET_UAPKI_INVALID_JSON_FORMAT);
    }

cleanup:
    return ret;
}   //  load_config

static int setup_cm_providers (JSON_Object* joParams)
{
    const string s_dir = ParsonHelper::jsonObjectGetString(joParams, "dir");
    JSON_Array* ja_providers = json_object_get_array(joParams, "allowedProviders");
    const size_t cnt_providers = json_array_get_count(ja_providers);

    for (size_t i = 0; i < cnt_providers; i++) {
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

        (void)CmProviders::loadProvider(s_dir, s_lib, s_config);
    }

    return RET_OK;
}   //  setup_cm_providers

static int setup_cert_cache (JSON_Object* joParams)
{
    int ret = RET_OK;
    Cert::CerStore& cer_store = *get_cerstore();

    cer_store.setParams(ParsonHelper::jsonObjectGetString(joParams, "path"));

    JSON_Array* ja_trustedcerts = json_object_get_array(joParams, "trustedCerts");
    const size_t cnt_certs = json_array_get_count(ja_trustedcerts);
    if (cnt_certs > 0) {
        VectorBA vba_encodedcerts;
        vector<Cert::CerStore::AddedCerItem> added_ceritems;

        vba_encodedcerts.resize(cnt_certs);
        for (size_t i = 0; i < cnt_certs; i++) {
            const char* s_b64 = json_array_get_string(ja_trustedcerts, i);
            if (s_b64) {
                vba_encodedcerts[i] = ba_alloc_from_base64(s_b64);
            }
            if (!vba_encodedcerts[i]) {
                SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
            }
        }

        DO(cer_store.addCerts(
            Cert::TRUSTED,
            Cert::NOT_PERMANENT,
            vba_encodedcerts,
            added_ceritems
        ));

        for (const auto& it : added_ceritems) {
            if (it.errorCode != RET_OK) {
                SET_ERROR(it.errorCode);
            }
        }
    }

    DO(cer_store.load());

cleanup:
    return ret;
}   //  setup_cert_cache

static int setup_crl_cache (JSON_Object* joParams)
{
    int ret = RET_OK;
    Crl::CrlStore& crl_store = *get_crlstore();

    crl_store.setParams(
        ParsonHelper::jsonObjectGetString(joParams, "path"),
        ParsonHelper::jsonObjectGetBoolean(joParams, "useDeltaCrl", true)
    );
    DO(crl_store.load());

cleanup:
    return ret;
}   //  setup_crl_cache

static int setup_ocsp (LibraryConfig& libConfig, JSON_Object* joParams)
{
    LibraryConfig::OcspParams ocsp_params;

    //  =nonceLen=
    ocsp_params.nonceLen = ParsonHelper::jsonObjectGetUint32(joParams, "nonceLen", LibraryConfig::OcspParams::NONCE_LEN_DEFAULT);
    if ((ocsp_params.nonceLen < UapkiNS::Ocsp::NONCE_MINLEN) || (ocsp_params.nonceLen > UapkiNS::Ocsp::NONCE_MAXLEN)) {
        ocsp_params.nonceLen = 0;
    }

    libConfig.setOcsp(ocsp_params);
    return RET_OK;
}   //  setup_ocsp

static int setup_tsp (LibraryConfig& libConfig, JSON_Object* joParams)
{
    LibraryConfig::TspParams tsp_params;

    //  =certReq=
    tsp_params.certReq = ParsonHelper::jsonObjectGetBoolean(joParams, "certReq", false);

    //  =forced=
    tsp_params.forced = ParsonHelper::jsonObjectGetBoolean(joParams, "forced", false);

    //  =nonceLen=
    tsp_params.nonceLen = ParsonHelper::jsonObjectGetUint32(joParams, "nonceLen", LibraryConfig::TspParams::NONCE_LEN_DEFAULT);
    if ((tsp_params.nonceLen < UapkiNS::Tsp::NONCE_MINLEN) || (tsp_params.nonceLen > UapkiNS::Tsp::NONCE_MAXLEN)) {
        tsp_params.nonceLen = 0;
    }

    //  =policyId=
    tsp_params.policyId = ParsonHelper::jsonObjectGetString(joParams, "policyId");
    if (!tsp_params.policyId.empty()) {
        UapkiNS::SmartBA sba_encoded;
        if (UapkiNS::Util::encodeOid(tsp_params.policyId.c_str(), &sba_encoded) != RET_OK) {
            tsp_params.policyId.clear();
        }
    }

    //  =url=
    if (ParsonHelper::jsonObjectHasValue(joParams, "url", JSONString)) {
        const string s_uri = ParsonHelper::jsonObjectGetString(joParams, "url");
        tsp_params.uris.push_back(s_uri);
    }
    else if (ParsonHelper::jsonObjectHasValue(joParams, "url", JSONArray)) {
        JSON_Array* ja_uris = json_object_get_array(joParams, "url");
        const size_t cnt = json_array_get_count(ja_uris);
        for (size_t i = 0; i < cnt; i++) {
            const string s_uri = ParsonHelper::jsonArrayGetString(ja_uris, i);
            tsp_params.uris.push_back(s_uri);
        }
    }

    libConfig.setTsp(tsp_params);
    return RET_OK;
}   //  setup_tsp


int uapki_init (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    ParsonHelper json;
    LibraryConfig* lib_config = get_config();
    Cert::CerStore* lib_cerstore = get_cerstore();
    Crl::CrlStore* lib_crlstore = get_crlstore();
    const string fn_config = ParsonHelper::jsonObjectGetString(joParams, "configFile");
    JSON_Object* jo_refparams = joParams;
    JSON_Object* jo_category = nullptr;
    size_t cnt_certs, cnt_crls, cnt_trustedcerts;
    bool offline;

    if (!lib_config || !lib_cerstore || !lib_crlstore) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    if (lib_config->isInitialized()) return RET_UAPKI_ALREADY_INITIALIZED;

    if (!fn_config.empty()) {
        DO(load_config(json, fn_config));
        jo_refparams = json.rootObject();
    }

    //  Setup subsystems
    DO(setup_cm_providers(json_object_get_object(jo_refparams, "cmProviders")));

    DO(setup_cert_cache(json_object_get_object(jo_refparams, "certCache")));

    DO(setup_crl_cache(json_object_get_object(jo_refparams, "crlCache")));

    DO(setup_ocsp(*lib_config, json_object_get_object(jo_refparams, "ocsp")));

    offline = ParsonHelper::jsonObjectGetBoolean(jo_refparams, "offline", false);
    lib_config->setOffline(offline);

    DO(setup_tsp(*lib_config, json_object_get_object(jo_refparams, "tsp")));

    {   //  Setup CURL
        JSON_Object* jo_proxy = json_object_get_object(jo_refparams, "proxy");
        HttpHelper::init(
            offline,
            json_object_get_string(jo_proxy, "url"),
            json_object_get_string(jo_proxy, "credentials")
        );
    }

    lib_config->setValidationByCrl(ParsonHelper::jsonObjectGetBoolean(jo_refparams, "validationByCrl", false));

    lib_config->setInitialized(true);

    //  Out info subsystems
    DO_JSON(json_object_set_value(joResult, "certCache", json_value_init_object()));
    jo_category = json_object_get_object(joResult, "certCache");
    (void)lib_cerstore->getCount(cnt_certs, cnt_trustedcerts);
    DO_JSON(ParsonHelper::jsonObjectSetUint32(jo_category, "countCerts", (uint32_t)cnt_certs));
    DO_JSON(ParsonHelper::jsonObjectSetUint32(jo_category, "countTrustedCerts", (uint32_t)cnt_trustedcerts));

    DO_JSON(json_object_set_value(joResult, "crlCache", json_value_init_object()));
    jo_category = json_object_get_object(joResult, "crlCache");
    (void)lib_crlstore->getCount(cnt_crls);
    DO_JSON(ParsonHelper::jsonObjectSetUint32(jo_category, "countCrls", (uint32_t)cnt_crls));
    DO_JSON(ParsonHelper::jsonObjectSetBoolean(jo_category, "useDeltaCrl", lib_crlstore->useDeltaCrl()));

    DO_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "countCmProviders", (uint32_t)CmProviders::count()));

    DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "offline", offline));

    DO_JSON(json_object_set_value(joResult, "ocsp", json_value_init_object()));
    jo_category = json_object_get_object(joResult, "ocsp");
    if (jo_category) {
        const LibraryConfig::OcspParams& ocsp_params = lib_config->getOcsp();
        DO_JSON(ParsonHelper::jsonObjectSetUint32(jo_category, "nonceLen", (uint32_t)ocsp_params.nonceLen));
    }

    DO_JSON(json_object_set_value(joResult, "proxy", json_value_init_object()));
    jo_category = json_object_get_object(joResult, "proxy");
    if (jo_category) {
        DO_JSON(json_object_set_string(jo_category, "url", HttpHelper::getProxyUrl().c_str()));
    }

    DO_JSON(json_object_set_value(joResult, "tsp", json_value_init_object()));
    jo_category = json_object_get_object(joResult, "tsp");
    if (jo_category) {
        const LibraryConfig::TspParams& tsp_params = lib_config->getTsp();
        const string s_url = UapkiNS::Util::joinStrings(tsp_params.uris);

        DO_JSON(ParsonHelper::jsonObjectSetBoolean(jo_category, "certReq", tsp_params.certReq));
        DO_JSON(ParsonHelper::jsonObjectSetBoolean(jo_category, "forced", tsp_params.forced));
        DO_JSON(ParsonHelper::jsonObjectSetUint32(jo_category, "nonceLen", (uint32_t)tsp_params.nonceLen));
        DO_JSON(json_object_set_string(jo_category, "policyId", tsp_params.policyId.c_str()));
        DO_JSON(json_object_set_string(jo_category, "url", s_url.c_str()));
    }

    DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "validationByCrl", lib_config->getValidationByCrl()));

cleanup:
    if (ret != RET_OK) {
        release_config();
        CmProviders::deinit();
        release_stores();
        HttpHelper::deinit();
    }

    return ret;
}
