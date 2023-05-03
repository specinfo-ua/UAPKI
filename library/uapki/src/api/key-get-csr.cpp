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
#include "certreq-builder.h"
#include "cm-providers.h"
#include "global-objects.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include "uapkif.h"
#include "uapki-ns.h"

#undef FILE_MARKER
#define FILE_MARKER "api/key-get-csr.c"


static int build_csr (CmStorageProxy& storage, const UapkiNS::AlgorithmIdentifier& aidSignAlgo,
                    const ByteArray* baSubject, const ByteArray* baAttributes, ByteArray** baCsr)
{
    int ret = RET_OK;
    UapkiNS::CertReqBuilder certreq_builder;
    UapkiNS::SmartBA sba_keyalgo, sba_pubkey, sba_signvalue;
    //vector<UapkiNS::Extension> extns;

    DO(certreq_builder.init(1));

    DO(storage.keyGetPublicKey(&sba_keyalgo, &sba_pubkey));
    DO(certreq_builder.setSubjectPublicKeyInfo(sba_keyalgo.get(), sba_pubkey.get()));

    //DO(certreq_builder.addExtensions(extns));

    DO(certreq_builder.encodeTbs());
    DO(storage.keySignData(aidSignAlgo.algorithm, aidSignAlgo.baParameters, certreq_builder.getTbsEncoded(), &sba_signvalue));

    DO(certreq_builder.encodeCertRequest(aidSignAlgo, sba_signvalue.get()));
    *baCsr = certreq_builder.getCsrEncoded(true);

cleanup:
    return ret;
}

static int get_default_signalgo (CmStorageProxy& storage, string& signAlgo)
{
    string s_keyinfo;
    int ret = storage.keyGetInfo(s_keyinfo);
    if (ret != RET_OK) return ret;

    ParsonHelper json;
    if (!json.parse(s_keyinfo.c_str())) return RET_UAPKI_INVALID_JSON_FORMAT;

    JSON_Array* ja_signalgo = json.getArray("signAlgo");
    if (json_array_get_count(ja_signalgo) > 0) {
        signAlgo = ParsonHelper::jsonArrayGetString(ja_signalgo, 0);
    }

    ret = (!signAlgo.empty()) ? RET_OK : RET_UAPKI_INVALID_JSON_FORMAT;
    return ret;
}

int uapki_key_get_csr (JSON_Object* jo_parameters, JSON_Object* jo_result)
{
    UapkiNS::AlgorithmIdentifier aid_signalgo;
    UapkiNS::SmartBA sba_attrs, sba_csr, sba_subject;
    UapkiNS::CertReqBuilder certreq_builder;

    CmStorageProxy* storage = CmProviders::openedStorage();
    if (!storage) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!storage->keyIsSelected()) return RET_UAPKI_KEY_NOT_SELECTED;

    if (jo_parameters) {
        aid_signalgo.algorithm = ParsonHelper::jsonObjectGetString(jo_parameters, "signAlgo");
        aid_signalgo.baParameters = json_object_get_base64(jo_parameters, "signAlgoParams");
        sba_subject.set(json_object_get_base64(jo_parameters, "subject"));
        sba_attrs.set(json_object_get_base64(jo_parameters, "attributes"));
    }

    int ret = RET_OK;
    if (!aid_signalgo.isPresent()) {
        DO(get_default_signalgo(*storage, aid_signalgo.algorithm));
    }

    ret = storage->keyGetCsr(aid_signalgo.algorithm, aid_signalgo.baParameters, sba_subject.get(), sba_attrs.get(), &sba_csr);
    switch (ret) {
    case RET_OK:
        break;
    case RET_UAPKI_NOT_SUPPORTED:
        DO(build_csr(*storage, aid_signalgo, sba_subject.get(), sba_attrs.get(), &sba_csr));
        break;
    default:
        SET_ERROR(ret);
    }

    DO_JSON(json_object_set_base64(jo_result, "bytes", sba_csr.get()));

cleanup:
    return ret;
}
