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
#include "store-util.h"
#include "uapki-errors.h"
#include "uapki-ns.h"


#undef FILE_MARKER
#define FILE_MARKER "api/cert-info.cpp"


int uapki_cert_info (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    UapkiNS::SmartBA sba_certid, sba_encoded;

    if (sba_encoded.set(json_object_get_base64(joParams, "bytes"))) {
        CerStore::Item* cer_item = nullptr;
        DO(CerStore::parseCert(sba_encoded.get(), &cer_item));
        sba_encoded.set(nullptr);

        DO(CerStoreUtil::detailInfoToJson(joResult, cer_item));
        delete cer_item;
    }
    else {
        if (sba_certid.set(json_object_get_base64(joParams, "certId"))) {
            CerStore* cer_store = get_cerstore();
            if (cer_store) {
                CerStore::Item* cer_item = nullptr;
                DO(cer_store->getCertByCertId(sba_certid.get(), &cer_item));
                DO(CerStoreUtil::detailInfoToJson(joResult, cer_item));
            }
            else {
                SET_ERROR(RET_UAPKI_GENERAL_ERROR);
            }
        }
        else {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
    }

cleanup:
    return ret;
}
