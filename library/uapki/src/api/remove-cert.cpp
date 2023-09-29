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

#define FILE_MARKER "uapki/api/remove-cert.cpp"

#include "api-json-internal.h"
#include "global-objects.h"
#include "parson-ba-utils.h"
#include "parson-helper.h"
#include "uapki-errors.h"
#include "uapki-ns.h"


using namespace std;
using namespace UapkiNS;


int uapki_remove_cert (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    LibraryConfig* lib_config = get_config();
    Cert::CerStore* cer_store = get_cerstore();
    const bool permanent = ParsonHelper::jsonObjectGetBoolean(joParams, "permanent", false);
    const bool from_storage = ParsonHelper::jsonObjectGetBoolean(joParams, "storage", false);
    SmartBA sba_certid, sba_encoded, sba_keyid;
    Cert::CerItem* cer_item = nullptr;

    if (!lib_config || !cer_store) return RET_UAPKI_GENERAL_ERROR;
    if (!lib_config->isInitialized()) return RET_UAPKI_NOT_INITIALIZED;

    if (!from_storage) {
        if (sba_certid.set(json_object_get_base64(joParams, "certId"))) {
            DO(cer_store->getCertByCertId(sba_certid.get(), &cer_item));
            DO(cer_store->removeCert(cer_item, permanent));
        }
        else if (sba_encoded.set(json_object_get_base64(joParams, "bytes"))) {
            DO(cer_store->getCertByEncoded(sba_encoded.get(), &cer_item));
            DO(cer_store->removeCert(cer_item, permanent));
        }
        else {
            DO(cer_store->removeMarkedCerts());
        }
    }
    else {
        const bool present_bytes = ParsonHelper::jsonObjectHasValue(joParams, "bytes", JSONString);
        const bool present_certid = ParsonHelper::jsonObjectHasValue(joParams, "certId", JSONString);
        if (
            (present_bytes && present_certid) ||
            (!present_bytes && !present_certid)
        ) {
            return RET_UAPKI_INVALID_PARAMETER;
        }

        CmStorageProxy* storage = CmProviders::openedStorage();
        if (!storage) return RET_UAPKI_STORAGE_NOT_OPEN;

        if (sba_encoded.set(json_object_get_base64(joParams, "bytes"))) {
            DO(Cert::parseCert(sba_encoded.get(), &cer_item));
            (void)sba_keyid.set(ba_copy_with_alloc(cer_item->getKeyId(), 0, 0));
            delete cer_item;
        }
        else if (sba_certid.set(json_object_get_base64(joParams, "certId"))) {
            DO(cer_store->getCertByCertId(sba_certid.get(), &cer_item));
            (void)sba_keyid.set(ba_copy_with_alloc(cer_item->getKeyId(), 0, 0));
        }

        if (sba_keyid.empty()) {
            SET_ERROR(RET_UAPKI_GENERAL_ERROR);
        }

        DO(storage->sessionDeleteCertificate(sba_keyid.get()));
    }

cleanup:
    return ret;
}
