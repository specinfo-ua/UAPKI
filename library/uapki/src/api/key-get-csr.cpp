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
#include "asn1-ba-utils.h"
#include "certreq-builder.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include "uapkif.h"

#undef FILE_MARKER
#define FILE_MARKER "api/key-get-csr.c"


static int build_csr (const UapkiNS::AlgorithmIdentifier& aidSignAlgo,
                    const ByteArray* baSubject, const ByteArray* baAttributes, ByteArray** baCsr)
{
    int ret = RET_OK;
    UapkiNS::CertReqBuilder certreq_builder;
    UapkiNS::SmartBA sba_keyalgo, sba_pubkey, sba_signvalue;
    //vector<UapkiNS::Extension> extns;

    DO(certreq_builder.init(1));

    DO(CmProviders::keyGetPublickey((CM_BYTEARRAY**)&sba_keyalgo, (CM_BYTEARRAY**)&sba_pubkey));//TODO: need use next-gen CmProvider (coming soon)
    DO(certreq_builder.setSubjectPublicKeyInfo(sba_keyalgo.get(), sba_pubkey.get()));

    //DO(certreq_builder.addExtensions(extns));

    DO(certreq_builder.encodeTbs());
    DO(CmProviders::keySignData(
        (const CM_UTF8_CHAR*)aidSignAlgo.algorithm.c_str(),
        (const CM_BYTEARRAY*)aidSignAlgo.baParameters,
        (const CM_BYTEARRAY*)certreq_builder.getTbsEncoded(),
        (CM_BYTEARRAY**)&sba_signvalue
    ));//TODO: need use next-gen CmProvider (coming soon)

    DO(certreq_builder.encodeCertRequest(aidSignAlgo, sba_signvalue.get()));
    *baCsr = certreq_builder.getCsrEncoded(true);

cleanup:
    return ret;
}

static int get_default_signalgo (string& signAlgo)
{
    CM_JSON_PCHAR s_keyinfo = NULL;
    int ret = CmProviders::keyGetInfo(&s_keyinfo, nullptr);
    if (ret != RET_OK) return ret;

    ParsonHelper json;
    if (json.parse((const char*)s_keyinfo)) {
        JSON_Array* ja_signalgo = json.getArray("signAlgo");
        if (json_array_get_count(ja_signalgo) > 0) {
            signAlgo = ParsonHelper::jsonArrayGetString(ja_signalgo, 0);
        }
    }

    CmProviders::free(s_keyinfo);
    ret = (!signAlgo.empty()) ? RET_OK : RET_CM_INVALID_JSON;
    return ret;
}

int uapki_key_get_csr (JSON_Object* jo_parameters, JSON_Object* jo_result)
{
    int ret = RET_OK;
    CM_BYTEARRAY* cmba_csr = NULL;//TODO: deprecated, waiting next-gen CmProvider (coming soon)
    UapkiNS::AlgorithmIdentifier aid_signalgo;
    UapkiNS::SmartBA sba_attrs, sba_csr, sba_subject;
    UapkiNS::CertReqBuilder certreq_builder;

    if (jo_parameters) {
        aid_signalgo.algorithm = ParsonHelper::jsonObjectGetString(jo_parameters, "signAlgo");
        aid_signalgo.baParameters = json_object_get_base64(jo_parameters, "signAlgoParams");
        sba_subject.set(json_object_get_base64(jo_parameters, "subject"));
        sba_attrs.set(json_object_get_base64(jo_parameters, "attributes"));
    }

    if (!aid_signalgo.isPresent()) {
        DO(get_default_signalgo(aid_signalgo.algorithm));
    }

    ret = CmProviders::keyGetCsr(
        (const CM_UTF8_CHAR*)aid_signalgo.algorithm.c_str(),
        (CM_BYTEARRAY*)aid_signalgo.baParameters,
        (CM_BYTEARRAY*)sba_subject.get(),
        (CM_BYTEARRAY*)sba_attrs.get(),
        &cmba_csr
    );
    switch (ret) {
    case RET_OK:
        break;
    case RET_UAPKI_NOT_SUPPORTED:
        DO(build_csr(aid_signalgo, sba_subject.get(), sba_attrs.get(), &sba_csr));
        break;
    default:
        SET_ERROR(ret);
    }

    DO_JSON(json_object_set_base64(jo_result, "bytes", (cmba_csr != NULL) ? (ByteArray*)cmba_csr : sba_csr.get()));

cleanup:
    CmProviders::baFree(cmba_csr);
    return ret;
}
