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

#define FILE_MARKER "uapki/api/crl-info.cpp"

#include "api-json-internal.h"
#include "global-objects.h"
#include "parson-helper.h"
#include "store-json.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"


using namespace std;
using namespace UapkiNS;


static int crl_info_to_json (
        JSON_Object* joResult,
        Crl::CrlItem* crlItem,
        const bool showRevokedCerts
)
{
    int ret = Crl::infoToJson(joResult, crlItem);
    if ((ret == RET_OK) && showRevokedCerts && (crlItem->getCountRevokedCerts() > 0)) {
        (void)json_object_set_value(joResult, "revokedCerts", json_value_init_array());
        ret = Crl::revokedCertsToJson(json_object_get_array(joResult, "revokedCerts"), crlItem);
    }
    return ret;
}   //  crl_info_to_json


int uapki_crl_info (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    const bool show_revcerts = ParsonHelper::jsonObjectGetBoolean(joParams, "showRevokedCerts", true);
    SmartBA sba_encoded;

    if (sba_encoded.set(json_object_get_base64(joParams, "bytes"))) {
        Crl::CrlItem* crl_item = nullptr;
        DO(Crl::parseCrl(sba_encoded.get(), &crl_item));
        sba_encoded.set(nullptr);

        ret = crl_info_to_json(joResult, crl_item, show_revcerts);

        delete crl_item;
    }
    else {
        SmartBA sba_crlid;
        if (!sba_crlid.set(json_object_get_base64(joParams, "crlId"))) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }

        Crl::CrlStore* crl_store = get_crlstore();
        if (!crl_store) {
            SET_ERROR(RET_UAPKI_GENERAL_ERROR);
        }

        Crl::CrlItem* crl_item = nullptr;
        DO(crl_store->getCrlByCrlId(sba_crlid.get(), &crl_item));

        ret = crl_info_to_json(joResult, crl_item, show_revcerts);
    }

cleanup:
    return ret;
}
