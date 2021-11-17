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

#undef FILE_MARKER
#define FILE_MARKER "api/session_select_key.cpp"

#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


int uapki_session_select_key (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    CerStore* cer_store = nullptr;
    ParsonHelper json;
    ByteArray* ba_keyid = NULL;
    CM_BYTEARRAY** cmba_certs = NULL;
    CM_JSON_PCHAR cmjs_keyinfo = NULL;
    const CerStore::Item* cer_selectedkey = NULL;
    uint32_t cnt_certs = 0;

    cer_store = get_cerstore();
    if (!cer_store) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    ba_keyid = json_object_get_hex(joParams, "id");
    if (ba_keyid == NULL) return RET_UAPKI_INVALID_PARAMETER;

    DO(CmProviders::sessionSelectKey((CM_BYTEARRAY*)ba_keyid));

    DO(CmProviders::keyGetInfo(&cmjs_keyinfo, NULL));

    if (!json.parse((const char*)cmjs_keyinfo)) {
        SET_ERROR(RET_UAPKI_INVALID_JSON_FORMAT);
    }

    DO_JSON(json_object_set_value(joResult, "signAlgo", json_value_init_array()));
    DO_JSON(json_array_copy_all_items(json_object_get_array(joResult, "signAlgo"), json.getArray("signAlgo")));

    //  Add certs to cert-store (if present)
    ret = CmProviders::keyGetCertificates(&cnt_certs, &cmba_certs);
    if ((ret == RET_OK) && (cnt_certs > 0)) {
        for (uint32_t i = 0; i < cnt_certs; i++) {
            DEBUG_OUTCON(printf("cert[%d]: ", i); ba_print(stdout, (const ByteArray*)cmba_certs[i]));
            bool is_unique;
            DO(cer_store->addCert((const ByteArray*)cmba_certs[i], true, false, false, is_unique, nullptr));
        }
    }

    // Get cert from cert-store
    ret = cer_store->getCertByKeyId(ba_keyid, &cer_selectedkey);
    if (ret == RET_OK) {
        DO_JSON(json_object_set_base64(joResult, "certId", cer_selectedkey->baCertId));
        DO_JSON(json_object_set_base64(joResult, "certificate", cer_selectedkey->baEncoded));
    }
    else if (ret == RET_UAPKI_CERT_NOT_FOUND) {
        ret = RET_OK;
    }

cleanup:
    CmProviders::arrayBaFree(cnt_certs, cmba_certs);
    CmProviders::free(cmjs_keyinfo);
    ba_free(ba_keyid);
    return ret;
}
