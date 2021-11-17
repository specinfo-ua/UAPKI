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
#include "global-objects.h"
#include "parson-helper.h"
#include "store-utils.h"
#include "uapki-errors.h"
#include "time-utils.h"


#undef FILE_MARKER
#define FILE_MARKER "api/crl-info.cpp"


int uapki_crl_info (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    ByteArray* ba_crlid = nullptr;
    ByteArray* ba_encoded = nullptr;

    ba_encoded = json_object_get_base64(joParams, "bytes");
    if (ba_encoded) {
        CrlStore::Item* crl_item = nullptr;
        DO(CrlStore::parseCrl(ba_encoded, &crl_item));
        ba_encoded = nullptr;

        DO(CrlStoreUtils::infoToJson(joResult, crl_item));
        if (crl_item->countRevokedCerts() > 0) {
            DO_JSON(json_object_set_value(joResult, "revokedCerts", json_value_init_array()));
            DO(CrlStoreUtils::revokedCertsToJson(json_object_get_array(joResult, "revokedCerts"), crl_item));
        }
        delete crl_item;
    }
    else {
        ba_crlid = json_object_get_base64(joParams, "crlId");
        if (ba_crlid) {
            CrlStore* crl_store = get_crlstore();
            if (crl_store) {
                const CrlStore::Item* crl_item = nullptr;
                DO(crl_store->getCrlByCrlId(ba_crlid, &crl_item));

                DO(CrlStoreUtils::infoToJson(joResult, crl_item));
                if (crl_item->countRevokedCerts() > 0) {
                    DO_JSON(json_object_set_value(joResult, "revokedCerts", json_value_init_array()));
                    DO(CrlStoreUtils::revokedCertsToJson(json_object_get_array(joResult, "revokedCerts"), crl_item));
                }
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
    ba_free(ba_crlid);
    ba_free(ba_encoded);
    return ret;
}
