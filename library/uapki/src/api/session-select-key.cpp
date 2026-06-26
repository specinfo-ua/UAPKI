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

#define FILE_MARKER "uapki/api/session-select-key.cpp"

#include "api-json-internal.h"
#include "cm-providers.h"
#include "global-objects.h"
#include "oids.h"
#include "parson-helper.h"
#include "uapki-ns.h"
#include "uapki-ns-util.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;
using namespace UapkiNS;

static int keyid2_from_publickey (
        const char* b64PublicKey,
        ByteArray** baKeyId2
)
{
    SmartBA sba_pubkey, sba_encappubkey;
    if (!sba_pubkey.set(ba_alloc_from_base64(b64PublicKey))) return RET_INVALID_BASE64_STRING;
    if (Util::encodeOctetString(sba_pubkey.get(), &sba_encappubkey) != RET_OK) return RET_UAPKI_GENERAL_ERROR;
    return ::hash(HASH_ALG_DSTU7564_256, sba_encappubkey.get(), baKeyId2);
}   //  keyid2_from_publickey


int uapki_session_select_key (JSON_Object* joParams, JSON_Object* joResult)
{
    Cert::CerStore* cer_store = get_cerstore();
    if (!cer_store) return RET_UAPKI_GENERAL_ERROR;

    CmStorageProxy* storage = CmProviders::openedStorage();
    if (!storage) return RET_UAPKI_STORAGE_NOT_OPEN;

    const bool present_certid = ParsonHelper::jsonObjectHasValue(joParams, "certId", JSONString);
    const bool present_keyid = ParsonHelper::jsonObjectHasValue(joParams, "id", JSONString);
    SmartBA sba_certid, sba_keyid, sba_keyid2;
    int ret = RET_OK;

    if (!present_certid && present_keyid) {
        if (!sba_keyid.set(json_object_get_hex(joParams, "id"))) return RET_UAPKI_INVALID_PARAMETER;
    } else if (present_certid && !present_keyid) {
        if (!sba_certid.set(json_object_get_base64(joParams, "certId"))) return RET_UAPKI_INVALID_PARAMETER;
    } else return RET_UAPKI_INVALID_PARAMETER;

    if (sba_keyid.empty()) {
        Cert::CerItem* cer_item = nullptr;
        ret = cer_store->getCertByCertId(sba_certid.get(), &cer_item);
        if (ret != RET_OK) return ret;

        if (!sba_keyid.set(ba_copy_with_alloc(cer_item->getKeyId(), 0, 0))) {
            return RET_UAPKI_GENERAL_ERROR;
        }
    }

    ret = storage->sessionSelectKey(sba_keyid.get());
    if (ret != RET_OK) return ret;

    string s_keyinfo;
    ParsonHelper json;
    string s_label, s_application;
    const char* s_keyalgo = nullptr;
    const char* s_pubkey = nullptr;
    bool need_deselectkey = true;

    DO(storage->keyGetInfo(s_keyinfo));
    if (!json.parse(s_keyinfo.c_str())) {
        SET_ERROR(RET_UAPKI_INVALID_JSON_FORMAT);
    }

    s_keyalgo = json.getString("mechanismId");
    s_pubkey = json.getString("publicKey");
    (void)json.getString("label", s_label);
    (void)json.getString("application", s_application);
    DO_JSON(json_object_set_string(joResult, "id", json.getString("id")));
    DO_JSON(json_object_set_string(joResult, "mechanismId", s_keyalgo));
    DO_JSON(json_object_set_string(joResult, "parameterId", json.getString("parameterId")));
    DO_JSON(json_object_set_value(joResult, "signAlgo", json_value_init_array()));
    DO_JSON(json_array_copy_all_items(json_object_get_array(joResult, "signAlgo"), json.getArray("signAlgo")));
    DO_JSON(json_object_set_string(joResult, "label", s_label.c_str()));
    DO_JSON(json_object_set_string(joResult, "application", s_application.c_str()));
    if (oid_is_equal(s_keyalgo, OID_DSTU4145_PARAM_PB_LE) && s_pubkey) {
        DO(keyid2_from_publickey(s_pubkey, &sba_keyid2));
        DO_JSON(json_object_set_hex(joResult, "keyId2", sba_keyid2.get()));
    }
    DO(storage->setSelectedKeyId(sba_keyid.get(), sba_keyid2.get()));
    need_deselectkey = false;

    {
        VectorBA vba_encodedcerts;
        vector<Cert::CerStore::AddedCerItem> added_ceritems;
        Cert::CerItem* cer_selectedkey = nullptr;

        //  Add certs to cert-store (if present)
        ret = storage->keyGetCertificates(vba_encodedcerts);
        DEBUG_OUTCON(printf("Get certs(%zu) from key, ret: %d\n", vba_encodedcerts.size(), ret));
        if ((ret == RET_OK) && !vba_encodedcerts.empty()) {
            DO(cer_store->addCerts(
                Cert::NOT_TRUSTED,
                Cert::NOT_PERMANENT,
                vba_encodedcerts,
                added_ceritems
            ));
        }

        //  Get cert from cert-store
        if (!sba_certid.empty()) {
            ret = cer_store->getCertByCertId(sba_certid.get(), &cer_selectedkey);
        }
        else {
            ret = cer_store->getCertByKeyId(sba_keyid.get(), &cer_selectedkey);
        }
        if (ret == RET_OK) {
            DO(storage->setPairedCertId(cer_selectedkey->getCertId()));

            DO_JSON(json_object_set_base64(joResult, "certId", cer_selectedkey->getCertId()));
            DO_JSON(json_object_set_base64(joResult, "certificate", cer_selectedkey->getEncoded()));
        }
        else if (ret == RET_UAPKI_CERT_NOT_FOUND) {
            ret = RET_OK;
        }
    }

cleanup:
    if (need_deselectkey) {
        storage->deselectKey();
    }
    return ret;
}
