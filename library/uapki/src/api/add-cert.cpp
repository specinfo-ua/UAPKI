/*
 * Copyright (c) 2023, The UAPKI Project Authors.
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
#include "global-objects.h"
#include "parson-ba-utils.h"
#include "parson-helper.h"
#include "signeddata-helper.h"
#include "uapki-errors.h"
#include "uapki-ns.h"


#undef FILE_MARKER
#define FILE_MARKER "api/add-cert.cpp"


static int add_cert_to_store (
        CerStore& cerStore,
        const ByteArray* baEncoded,
        bool isPermanent,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    CerStore::Item* cer_item = nullptr;
    bool is_unique;

    DO(cerStore.addCert(baEncoded, true, isPermanent, false, is_unique, &cer_item));

    DO(json_object_set_base64(joResult, "certId", cer_item->baCertId));
    DO(ParsonHelper::jsonObjectSetBoolean(joResult, "isUnique", is_unique));

cleanup:
    return ret;
}   //  add_cert_to_store

static int parse_added_certs (
        JSON_Object* joParams,
        UapkiNS::VectorBA& vbaCerts
)
{
    int ret = RET_OK;
    UapkiNS::SmartBA sba_encoded;
    JSON_Array* ja_certs = json_object_get_array(joParams, "certificates");

    if (ja_certs) {
        const size_t cnt_certs = json_array_get_count(ja_certs);
        for (size_t i = 0; i < cnt_certs; i++) {
            if (!sba_encoded.set(json_array_get_base64(ja_certs, i))) {
                SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
            }
            vbaCerts.push_back(sba_encoded.pop());
        }
    }
    else {
        UapkiNS::Pkcs7::SignedDataParser sdata_parser;
        if (!sba_encoded.set(json_object_get_base64(joParams, "bundle"))) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }

        DO(sdata_parser.parse(sba_encoded.get()));

        for (auto& it : sdata_parser.getCerts()) {
            vbaCerts.push_back(it);
            it = nullptr;
        }
    }

cleanup:
    return ret;
}   //  parse_added_certs


int uapki_add_cert (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    UapkiNS::VectorBA vba_certs;
    JSON_Array* ja_results = nullptr;
    size_t idx = 0;
    const bool present_certs = ParsonHelper::jsonObjectHasValue(joParams, "certificates", JSONArray);
    const bool present_bundle = ParsonHelper::jsonObjectHasValue(joParams, "bundle", JSONString);
    const bool permanent = ParsonHelper::jsonObjectGetBoolean(joParams, "permanent", false);
    const bool to_storage = ParsonHelper::jsonObjectGetBoolean(joParams, "storage", false);

    LibraryConfig* lib_config = get_config();
    if (!lib_config) return RET_UAPKI_GENERAL_ERROR;
    if (!lib_config->isInitialized()) return RET_UAPKI_NOT_INITIALIZED;

    CerStore* cer_store = get_cerstore();
    if (!cer_store) return RET_UAPKI_GENERAL_ERROR;

    if (
        (present_certs && present_bundle) ||
        (!present_certs && !present_bundle)
    ) {
        return RET_UAPKI_INVALID_PARAMETER;
    }

    DO(parse_added_certs(joParams, vba_certs));
    if (vba_certs.empty()) return RET_UAPKI_INVALID_PARAMETER;

    DO_JSON(json_object_set_value(joResult, "added", json_value_init_array()));
    ja_results = json_object_get_array(joResult, "added");

    if (!to_storage) {
        for (const auto& it : vba_certs) {
            DO_JSON(json_array_append_value(ja_results, json_value_init_object()));
            DO(add_cert_to_store(*cer_store, it, permanent, json_array_get_object(ja_results, idx++)));
        }
    }
    else {
        CmStorageProxy* storage = CmProviders::openedStorage();
        if (!storage) return RET_UAPKI_STORAGE_NOT_OPEN;

        for (const auto& it : vba_certs) {
            DO_JSON(json_array_append_value(ja_results, json_value_init_object()));
            ret = storage->sessionAddCertificate(it);
            if (ret == RET_UAPKI_NOT_SUPPORTED) {
                DO(storage->keyAddCertificate(it));
            }
            DO(add_cert_to_store(*cer_store, it, permanent, json_array_get_object(ja_results, idx++)));
        }
    }

cleanup:
    return ret;
}
