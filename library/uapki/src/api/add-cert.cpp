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

#define FILE_MARKER "uapki/api/add-cert.cpp"

#include "api-json-internal.h"
#include "global-objects.h"
#include "parson-ba-utils.h"
#include "parson-helper.h"
#include "signeddata-helper.h"
#include "uapki-errors.h"
#include "uapki-ns.h"


using namespace std;
using namespace UapkiNS;


static int add_certs_to_store (
        Cert::CerStore& cerStore,
        const bool trusted,
        const bool permanent,
        const VectorBA& vbaEncodedCerts,
        JSON_Array* jaResults
)
{
    int ret = RET_OK;
    vector<Cert::CerStore::AddedCerItem> added_ceritems;
    size_t idx = 0;

    DO(cerStore.addCerts(
        trusted,
        permanent,
        vbaEncodedCerts,
        added_ceritems
    ));

    for (const auto& it : added_ceritems) {
        DO_JSON(json_array_append_value(jaResults, json_value_init_object()));
        JSON_Object* jo_added = json_array_get_object(jaResults, idx++);
        DO(ParsonHelper::jsonObjectSetInt32(jo_added, "errorCode", it.errorCode));
        if (it.errorCode == RET_OK) {
            DO(json_object_set_base64(jo_added, "certId", it.cerItem->getCertId()));
            DO(ParsonHelper::jsonObjectSetBoolean(jo_added, "isUnique", it.isUnique));
        }
    }

cleanup:
    return ret;
}   //  add_cert_to_store

static int parse_add_certs (
        JSON_Object* joParams,
        VectorBA& vbaEncodedCerts
)
{
    int ret = RET_OK;
    SmartBA sba_encoded;
    JSON_Array* ja_certs = json_object_get_array(joParams, "certificates");

    if (ja_certs) {
        const size_t cnt_certs = json_array_get_count(ja_certs);
        for (size_t i = 0; i < cnt_certs; i++) {
            if (!sba_encoded.set(json_array_get_base64(ja_certs, i))) {
                SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
            }
            vbaEncodedCerts.push_back(sba_encoded.pop());
        }
    }
    else {
        Pkcs7::SignedDataParser sdata_parser;
        if (!sba_encoded.set(json_object_get_base64(joParams, "bundle"))) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }

        DO(sdata_parser.parse(sba_encoded.get()));

        for (auto& it : sdata_parser.getCerts()) {
            vbaEncodedCerts.push_back(it);
            it = nullptr;
        }
    }

cleanup:
    return ret;
}   //  parse_add_certs


int uapki_add_cert (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    LibraryConfig* lib_config = get_config();
    Cert::CerStore* cer_store = get_cerstore();
    const bool present_certs = ParsonHelper::jsonObjectHasValue(joParams, "certificates", JSONArray);
    const bool present_bundle = ParsonHelper::jsonObjectHasValue(joParams, "bundle", JSONString);
    const bool permanent = ParsonHelper::jsonObjectGetBoolean(joParams, "permanent", false);
    const bool to_storage = ParsonHelper::jsonObjectGetBoolean(joParams, "storage", false);
    VectorBA vba_encodedcerts;
    JSON_Array* ja_results = nullptr;

    if (!lib_config || !cer_store) return RET_UAPKI_GENERAL_ERROR;
    if (!lib_config->isInitialized()) return RET_UAPKI_NOT_INITIALIZED;

    if (
        (present_certs && present_bundle) ||
        (!present_certs && !present_bundle)
    ) {
        return RET_UAPKI_INVALID_PARAMETER;
    }

    DO(parse_add_certs(joParams, vba_encodedcerts));
    if (vba_encodedcerts.empty()) return RET_UAPKI_INVALID_PARAMETER;

    DO_JSON(json_object_set_value(joResult, "added", json_value_init_array()));
    ja_results = json_object_get_array(joResult, "added");

    if (!to_storage) {
        DO(add_certs_to_store(
            *cer_store,
            Cert::NOT_TRUSTED,
            permanent,
            vba_encodedcerts,
            ja_results
        ));
    }
    else {
        CmStorageProxy* storage = CmProviders::openedStorage();
        if (!storage) return RET_UAPKI_STORAGE_NOT_OPEN;

        for (const auto& it : vba_encodedcerts) {
            ret = storage->sessionAddCertificate(it);
            if (ret == RET_UAPKI_NOT_SUPPORTED) {
                DO(storage->keyAddCertificate(it));
            }
        }

        DO(add_certs_to_store(
            *cer_store,
            Cert::NOT_TRUSTED,
            permanent,
            vba_encodedcerts,
            ja_results
        ));
    }

cleanup:
    return ret;
}
