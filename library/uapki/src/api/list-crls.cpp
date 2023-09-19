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

#define FILE_MARKER "uapki/api/list-crls.cpp"

#include "api-json-internal.h"
#include "global-objects.h"
#include "parson-ba-utils.h"
#include "parson-helper.h"
#include "store-json.h"
#include "uapki-errors.h"
#include "uapki-ns.h"


using namespace std;
using namespace UapkiNS;


int uapki_list_crls (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    LibraryConfig* lib_config = get_config();
    Crl::CrlStore* crl_store = get_crlstore();
    const bool show_crlinfos = ParsonHelper::jsonObjectGetBoolean(joParams, "showCrlInfos", false);
    Pagination pagination;

    if (!lib_config || !crl_store) return RET_UAPKI_GENERAL_ERROR;
    if (!lib_config->isInitialized()) return RET_UAPKI_NOT_INITIALIZED;

    if (!pagination.parseParams(joParams)) return RET_UAPKI_INVALID_PARAMETER;

    (void)json_object_set_value(joResult, "crlIds", json_value_init_array());
    JSON_Array* ja_crlids = json_object_get_array(joResult, "crlIds");
    JSON_Array* ja_crlinfos = nullptr;
    if (show_crlinfos) {
        (void)json_object_set_value(joResult, "crlInfos", json_value_init_array());
        ja_crlinfos = json_object_get_array(joResult, "crlInfos");
    }

    const vector<Crl::CrlItem*> crl_items = crl_store->getCrlItems();
    pagination.count = crl_items.size();
    pagination.calcParams();
    for (size_t idx = pagination.offset; idx < pagination.offsetLast; idx++) {
        Crl::CrlItem* crl_item = crl_items[idx];
        DO(json_array_append_base64(ja_crlids, crl_item->getCrlId()));
        if (show_crlinfos) {
            DO_JSON(json_array_append_value(ja_crlinfos, json_value_init_object()));
            JSON_Object* jo_crlinfo = json_array_get_object(ja_crlinfos, idx);
            DO(json_object_set_base64(jo_crlinfo, "crlId", crl_item->getCrlId()));
            DO(Crl::infoToJson(jo_crlinfo, crl_item));
            if (crl_item->getActuality() == Crl::CrlItem::Actuality::OBSOLETE) {
                DO_JSON(ParsonHelper::jsonObjectSetBoolean(jo_crlinfo, "isObsolete", true));
            }
        }
    }

    DO(pagination.setResult(joResult));

cleanup:
    return ret;
}
