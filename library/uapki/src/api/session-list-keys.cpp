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

#define FILE_MARKER "uapki/api/session-list-keys.cpp"

#include "api-json-internal.h"
#include "cm-providers.h"
#include "parson-helper.h"
#include "uapki-ns.h"


using namespace std;


static JSON_Status json_object_copy_string (
        JSON_Object* joDest,
        JSON_Object* joSource,
        const char* key
)
{
    const string s = ParsonHelper::jsonObjectGetString(joSource, key);
    return json_object_set_string(joDest, key, s.c_str());
}   //  json_object_copy_string


int uapki_session_list_keys (JSON_Object* joParams, JSON_Object* joResult)
{
    (void)joParams;
    CmStorageProxy* storage = CmProviders::openedStorage();
    if (!storage) return RET_UAPKI_STORAGE_NOT_OPEN;

    UapkiNS::VectorBA vba_keyids;
    string s_infokeys;
    int ret = storage->sessionListKeys(vba_keyids, s_infokeys);
    if (ret != RET_OK) return ret;

    ParsonHelper json;
    JSON_Object* jo_resp = nullptr;
    if (!s_infokeys.empty()) {
        jo_resp = json.parse(s_infokeys.c_str());
        if (!jo_resp) return RET_UAPKI_INVALID_JSON_FORMAT;
    }

    JSON_Array* ja_dstkeyinfos = nullptr;
    JSON_Array* ja_srckeyinfos = json.getArray("keys");
    const size_t cnt_keys = json_array_get_count(ja_srckeyinfos);

    DO_JSON(json_object_set_value(joResult, "keys", json_value_init_array()));
    ja_dstkeyinfos = json_object_get_array(joResult, "keys");
    for (size_t i = 0; i < cnt_keys; i++) {
        DO_JSON(json_array_append_value(ja_dstkeyinfos, json_value_init_object()));
        JSON_Object* jo_dstkeyinfo = json_array_get_object(ja_dstkeyinfos, i);
        JSON_Object* jo_srckeyinfo = json_array_get_object(ja_srckeyinfos, i);

        DO_JSON(json_object_copy_string(jo_dstkeyinfo, jo_srckeyinfo, "id"));
        DO_JSON(json_object_copy_string(jo_dstkeyinfo, jo_srckeyinfo, "mechanismId"));
        DO_JSON(json_object_copy_string(jo_dstkeyinfo, jo_srckeyinfo, "parameterId"));
        DO_JSON(json_object_copy_string(jo_dstkeyinfo, jo_srckeyinfo, "label"));
        DO_JSON(json_object_copy_string(jo_dstkeyinfo, jo_srckeyinfo, "application"));
        DO_JSON(json_object_set_value(jo_dstkeyinfo, "signAlgo", json_value_init_array()));
        DO_JSON(json_array_copy_all_items(json_object_get_array(jo_dstkeyinfo, "signAlgo"), json_object_get_array(jo_srckeyinfo, "signAlgo")));
    }

cleanup:
    return ret;
}
