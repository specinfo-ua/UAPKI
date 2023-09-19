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

#define FILE_MARKER "uapki/api/session-select-key.cpp"

#include "api-json-internal.h"
#include "cm-providers.h"
#include "global-objects.h"
#include "parson-helper.h"
#include "uapki-ns.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;
using namespace UapkiNS;


int uapki_session_select_key (JSON_Object* joParams, JSON_Object* joResult)
{
    Cert::CerStore* cer_store = get_cerstore();
    if (!cer_store) return RET_UAPKI_GENERAL_ERROR;

    CmStorageProxy* storage = CmProviders::openedStorage();
    if (!storage) return RET_UAPKI_STORAGE_NOT_OPEN;

    SmartBA sba_keyid;
    if (!sba_keyid.set(json_object_get_hex(joParams, "id"))) return RET_UAPKI_INVALID_PARAMETER;

    int ret = storage->sessionSelectKey(*sba_keyid);
    if (ret != RET_OK) return ret;

    string s_keyinfo;
    ret = storage->keyGetInfo(s_keyinfo);
    if (ret != RET_OK) return ret;

    ParsonHelper json;
    if (!json.parse(s_keyinfo.c_str())) return RET_UAPKI_INVALID_JSON_FORMAT;

    string s_label, s_application;
    VectorBA vba_encodedcerts;
    vector<Cert::CerStore::AddedCerItem> added_ceritems;
    Cert::CerItem* cer_selectedkey = nullptr;

    (void)json.getString("label", s_label);
    (void)json.getString("application", s_application);

    DO_JSON(json_object_set_string(joResult, "id", json.getString("id")));
    DO_JSON(json_object_set_string(joResult, "mechanismId", json.getString("mechanismId")));
    DO_JSON(json_object_set_string(joResult, "parameterId", json.getString("parameterId")));
    DO_JSON(json_object_set_value(joResult, "signAlgo", json_value_init_array()));
    DO_JSON(json_array_copy_all_items(json_object_get_array(joResult, "signAlgo"), json.getArray("signAlgo")));
    DO_JSON(json_object_set_string(joResult, "label", s_label.c_str()));
    DO_JSON(json_object_set_string(joResult, "application", s_application.c_str()));

    //  Add certs to cert-store (if present)
    ret = storage->keyGetCertificates(vba_encodedcerts);
    DEBUG_OUTCON(printf("Get certs(%zu) from key, ret: %d\n", vba_encodedcerts.size(), ret));
    if ((ret == RET_OK) && !vba_encodedcerts.empty()) {
        DO(cer_store->addCerts(
            Cert::NOT_TRUSTED,
            Cert::NOT_PERMANENT,
            vba_encodedcerts,
            added_ceritems
        ));
    }

    // Get cert from cert-store
    ret = cer_store->getCertByKeyId(*sba_keyid, &cer_selectedkey);
    if (ret == RET_OK) {
        DO_JSON(json_object_set_base64(joResult, "certId", cer_selectedkey->getCertId()));
        DO_JSON(json_object_set_base64(joResult, "certificate", cer_selectedkey->getEncoded()));
    }
    else if (ret == RET_UAPKI_CERT_NOT_FOUND) {
        ret = RET_OK;
    }

cleanup:
    return ret;
}
