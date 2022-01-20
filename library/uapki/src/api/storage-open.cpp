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

#include "api-json-internal.h"
#include "cm-providers.h"
#include "global-objects.h"
#include "parson-helper.h"
#include "uapki-ns.h"

#undef FILE_MARKER
#define FILE_MARKER "api/storage-open.cpp"

// "method": "OPEN"
// "parameters": {"provider":"PKCS12", "storage":"test.p12", "password":"testpassword", "mode":"RO/RW/CREATE"}
// out: {"mechanisms":[{"id":"ECDSA", "description":"ECDSA", "parameters":[{"id":"P256", "description":"NIST P256 curve"},{...}],{...}]}, "user_presense":false}

static int session_info (CmStorageProxy& storage, JSON_Object* joResult)
{
    string s_sesinfo;
    int ret = storage.sessionInfo(s_sesinfo);
    if (ret != RET_OK) return ret;

    ParsonHelper json;
    JSON_Object* jo_resp = json.parse(s_sesinfo.c_str());
    if (!jo_resp) return RET_UAPKI_INVALID_JSON_FORMAT;

    size_t idx_mechanism = 0;
    vector<string> mechanisms;
    JSON_Array* ja_mechanisms = json.getArray("mechanisms");
    for (size_t i = 0; i < json_array_get_count(ja_mechanisms); i++) {
        const string s_mechid = ParsonHelper::jsonArrayGetString(ja_mechanisms, i);
        mechanisms.push_back(s_mechid);
    }

    DO_JSON(json_object_remove(jo_resp, "mechanisms"));
    DO_JSON(json_object_copy_all_items(joResult, jo_resp));
    json.cleanup();

    DO_JSON(json_object_set_value(joResult, "mechanisms", json_value_init_array()));
    ja_mechanisms = json_object_get_array(joResult, "mechanisms");

    for (auto& it : mechanisms) {
        string s_paramids;
        DO(storage.sessionMechanismParameters(it, s_paramids));

        jo_resp = json.parse(s_paramids.c_str());
        if (jo_resp) {
            DO_JSON(json_array_append_value(ja_mechanisms, json_value_init_object()));
            JSON_Object* jo_mech = json_array_get_object(ja_mechanisms, idx_mechanism);
            DO_JSON(json_object_set_string(jo_mech, "id", it.c_str()));
            DO_JSON(json_object_copy_all_items(jo_mech, jo_resp));
            idx_mechanism++;
        }
        json.cleanup();
    }

cleanup:
    return ret;
}

static int add_certs_from_storage_to_cache (CmStorageProxy& storage, CerStore& cerStore)
{
    UapkiNS::VectorBA vba_certs;
    int ret = storage.sessionGetCertificates(vba_certs);
    if (ret != RET_OK) {
        return (ret == RET_UAPKI_NOT_SUPPORTED) ? RET_OK : ret;
    }

    for (size_t i = 0; i < vba_certs.size(); i++) {
        bool is_unique;
        DO(cerStore.addCert(vba_certs[i], false, false, false, is_unique, nullptr));
        vba_certs[i] = nullptr;
    }

cleanup:
    return ret;
}


int uapki_storage_open (JSON_Object* joParams, JSON_Object* joResult)
{
    const char* s_providerid = json_object_get_string(joParams, "provider");
    const char* s_storageid = json_object_get_string(joParams, "storage");
    if (!s_providerid || !s_storageid) return RET_UAPKI_INVALID_PARAMETER;

    int ret = CmProviders::storageOpen(s_providerid, s_storageid, joParams);
    if (ret != RET_OK) return ret;

    CmStorageProxy* storage = CmProviders::openedStorage();
    CerStore* cer_store = get_cerstore();
    if (!storage || !cer_store) return RET_UAPKI_GENERAL_ERROR;

    ret = session_info(*storage, joResult);
    if (ret != RET_OK) {
        CmProviders::storageClose();
        return ret;
    }

    ret = add_certs_from_storage_to_cache(*storage, *cer_store);

    return ret;
}
