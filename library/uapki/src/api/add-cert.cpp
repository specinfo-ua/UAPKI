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
#include "content-info.h"
#include "global-objects.h"
#include "parson-ba-utils.h"
#include "parson-helper.h"
#include "uapki-errors.h"


#undef FILE_MARKER
#define FILE_MARKER "api/add-cert.cpp"


static int add_cert_to_store (CerStore& cerStore, const ByteArray* baEncoded, bool isPermanent, JSON_Object* joResult)
{
    int ret = RET_OK;
    const CerStore::Item* cer_item = nullptr;
    bool is_unique;

    DO(cerStore.addCert(baEncoded, false, isPermanent, false, is_unique, &cer_item));

    DO(json_object_set_base64(joResult, "certId", cer_item->baCertId));
    DO(ParsonHelper::jsonObjectSetBoolean(joResult, "isUnique", is_unique));

cleanup:
    return ret;
}

static int decode_bundle_and_store (CerStore& cerStore, const ByteArray* baEncoded, JSON_Array* jaResults, bool isPermanent)
{
    int ret = RET_OK;
    ContentInfo_t* cinfo = nullptr;
    SignedData_t* sdata = nullptr;
    ByteArray* ba_encoded = nullptr;
    long version = 0;

    CHECK_NOT_NULL(cinfo = (ContentInfo_t*)asn_decode_ba_with_alloc(get_ContentInfo_desc(), baEncoded));
    DO(cinfo_get_signed_data(cinfo, &sdata));

    DO(asn_INTEGER2long(&sdata->version, &version));
    if ((version < 1) || (version > 5) || (version == 2)) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT_VERSION);
    }

    if ((sdata->digestAlgorithms.list.count != 0)
     || !sdata->certificates || (sdata->certificates->list.count == 0)
     || sdata->encapContentInfo.eContent
     || (sdata->signerInfos.list.count != 0)) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

    for (int i = 0; i < sdata->certificates->list.count; i++) {
        DO(asn_encode_ba(get_CertificateChoices_desc(), sdata->certificates->list.array[i], &ba_encoded));
        DO_JSON(json_array_append_value(jaResults, json_value_init_object()));
        DO(add_cert_to_store(cerStore, ba_encoded, isPermanent, json_array_get_object(jaResults, i)));
        ba_encoded = nullptr;
    }

cleanup:
    asn_free(get_ContentInfo_desc(), cinfo);
    asn_free(get_SignedData_desc(), sdata);
    ba_free(ba_encoded);
    return ret;
}


int uapki_add_cert (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    CerStore* cer_store = nullptr;
    ByteArray* ba_encoded = nullptr;
    JSON_Array* ja_incerts = nullptr;
    JSON_Array* ja_results = nullptr;
    bool permanent;

    cer_store = get_cerstore();
    if (!cer_store) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    DO_JSON(json_object_set_value(joResult, "added", json_value_init_array()));
    ja_results = json_object_get_array(joResult, "added");

    permanent = ParsonHelper::jsonObjectGetBoolean(joParams, "permanent", false);

    ja_incerts = json_object_get_array(joParams, "certificates");
    if (ja_incerts) {
        const size_t cnt_certs = json_array_get_count(ja_incerts);
        for (size_t i = 0; i < cnt_certs; i++) {
            ba_encoded = json_array_get_base64(ja_incerts, i);
            if (!ba_encoded) {
                SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
            }

            DO_JSON(json_array_append_value(ja_results, json_value_init_object()));
            DO(add_cert_to_store(*cer_store, ba_encoded, permanent, json_array_get_object(ja_results, i)));
            ba_encoded = nullptr;
        }
    }
    else {
        ba_encoded = json_object_get_base64(joParams, "bundle");
        if (!ba_encoded) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }

        DO(decode_bundle_and_store(*cer_store, ba_encoded, ja_results, permanent));
    }

cleanup:
    ba_free(ba_encoded);
    return ret;
}
