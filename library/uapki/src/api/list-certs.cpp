/*
 * Copyright (c) 2022, The UAPKI Project Authors.
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
#include "uapki-errors.h"
#include "store-utils.h"
#include "time-utils.h"


#undef FILE_MARKER
#define FILE_MARKER "api/list-certs.cpp"


int uapki_list_certs (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    CerStore* cer_store = nullptr;
    JSON_Array* ja_results = nullptr;
    size_t cnt_certs, offset, offset_last, page_size;

    cer_store = get_cerstore();
    if (!cer_store) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    offset = ParsonHelper::jsonObjectGetUint32(joParams, "offset", 0);
    page_size = ParsonHelper::jsonObjectGetUint32(joParams, "pageSize", 0);

    DO_JSON(json_object_set_value(joResult, "certIds", json_value_init_array()));
    ja_results = json_object_get_array(joResult, "certIds");

    //  NOTE: now simple solution.. for-each; without lock/unlock store..
    cer_store->getCount(cnt_certs);//Note: may returned RET_UAPKI_NOT_SUPPORTED
    page_size = (page_size == 0) ? (cnt_certs - offset) : page_size;
    offset_last = offset + page_size;
    offset_last = (offset_last < cnt_certs) ? offset_last : cnt_certs;
    for (size_t idx = offset, j = 0; idx < offset_last; idx++) {
        CerStore::Item* cer_item = nullptr;
        DO(cer_store->getCertByIndex(idx, &cer_item));
        DO_JSON(json_array_append_base64(ja_results, cer_item->baCertId));
    }

    DO_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "count", (uint32_t)cnt_certs));
    DO_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "offset", (uint32_t)offset));
    DO_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "pageSize", (uint32_t)page_size));

cleanup:
    return ret;
}
