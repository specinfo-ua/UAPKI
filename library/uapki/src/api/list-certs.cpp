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
#include "uapki-errors.h"
#include "uapki-ns.h"


#undef FILE_MARKER
#define FILE_MARKER "api/list-certs.cpp"


struct Pagination {
    size_t count;
    size_t offset;
    size_t offsetLast;
    size_t pageSize;

    Pagination (void)
        : count(0)
        , offset(0)
        , offsetLast(0)
        , pageSize(0)
    {}

    void calcParams (void)
    {
        offset = (offset < count) ? offset : count;
        pageSize = (pageSize == 0) ? (count - offset) : pageSize;
        if (pageSize == 0) pageSize = 1;
        offsetLast = offset + pageSize;
        offsetLast = (offsetLast < count) ? offsetLast : count;
    }

    bool parseParams (
        JSON_Object* joParams
    )
    {
        const int32_t int_offset = ParsonHelper::jsonObjectGetInt32(joParams, "offset", 0);
        if (int_offset < 0) return false;
        offset = (size_t)int_offset;

        const int32_t int_pagesize = ParsonHelper::jsonObjectGetInt32(joParams, "pageSize", 0);
        if (int_pagesize < 0) return false;
        pageSize = (size_t)int_pagesize;

        return true;
    }

    int setResult (JSON_Object* joResult)
    {
        int ret = RET_OK;

        DO_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "count", (uint32_t)count));
        DO_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "offset", (uint32_t)offset));
        DO_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "pageSize", (uint32_t)pageSize));

    cleanup:
        return ret;
    }

};  //  end struct Pagination


int uapki_list_certs (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    CerStore* cer_store = nullptr;
    CerStore::Item* cer_item = nullptr;
    JSON_Array* ja_results = nullptr;
    Pagination pa;
    const bool from_storage = ParsonHelper::jsonObjectGetBoolean(joParams, "storage", false);

    LibraryConfig* lib_config = get_config();
    if (!lib_config) return RET_UAPKI_GENERAL_ERROR;
    if (!lib_config->isInitialized()) return RET_UAPKI_NOT_INITIALIZED;

    cer_store = get_cerstore();
    if (!cer_store) return RET_UAPKI_GENERAL_ERROR;

    if (!pa.parseParams(joParams)) return RET_UAPKI_INVALID_PARAMETER;

    DO_JSON(json_object_set_value(joResult, "certIds", json_value_init_array()));
    ja_results = json_object_get_array(joResult, "certIds");

    if (!from_storage) {
        DO(cer_store->getCount(pa.count));
        pa.calcParams();
        for (size_t idx = pa.offset; idx < pa.offsetLast; idx++) {
            cer_item = nullptr;
            DO(cer_store->getCertByIndex(idx, &cer_item));
            DO_JSON(json_array_append_base64(ja_results, cer_item->baCertId));
        }
    }
    else {
        UapkiNS::VectorBA vba_certs;
        vector<const ByteArray*> list_refcertids;

        CmStorageProxy* storage = CmProviders::openedStorage();
        if (!storage) return RET_UAPKI_STORAGE_NOT_OPEN;

        ret = storage->sessionGetCertificates(vba_certs);
        if (ret == RET_UAPKI_NOT_SUPPORTED) {
            DO(storage->keyGetCertificates(vba_certs));
        }

        for (const auto& it : vba_certs) {
            cer_item = nullptr;
            ret = cer_store->getCertByEncoded(it, &cer_item);
            if (ret == RET_OK) {
                list_refcertids.push_back(cer_item->baCertId);
                pa.count++;
            }
        }

        pa.calcParams();
        for (size_t idx = pa.offset; idx < pa.offsetLast; idx++) {
            DO_JSON(json_array_append_base64(ja_results, list_refcertids[idx]));
        }
    }

    DO(pa.setResult(joResult));

cleanup:
    return ret;
}
