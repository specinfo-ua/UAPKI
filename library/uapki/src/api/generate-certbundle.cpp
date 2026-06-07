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

#define FILE_MARKER "uapki/api/generate-certbundle.cpp"


#include "api-json-internal.h"
#include "parson-helper.h"
#include "signeddata-helper.h"
#include "uapki-errors.h"
#include "uapki-ns.h"


using namespace std;
using namespace UapkiNS;


int uapki_generate_certbundle (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    Pkcs7::SignedDataBuilder sdata_builder;
    JSON_Array* ja_certs = json_object_get_array(joParams, "certificates");
    JSON_Array* ja_crls = json_object_get_array(joParams, "crls");
    const size_t cnt_certs = json_array_get_count(ja_certs);
    const size_t cnt_crls = json_array_get_count(ja_crls);
    if ((cnt_certs == 0) && (cnt_crls == 0)) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    DO(sdata_builder.init());

    //  =version=
    DO(sdata_builder.setVersion(1));

    //  =digestAlgorithms=
    //  Cert-bundle must be not contain

    //  =encapContentInfo=
    //  Parameter eContentType must be set PKCS7-DATA and parameter eContent is empty
    DO(sdata_builder.setEncapContentInfo(OID_PKCS7_DATA, nullptr));

    //  =certificates=, optional
    for (size_t i = 0; i < cnt_certs; i++) {
        SmartBA sba_cert;
        if (!sba_cert.set(json_array_get_base64(ja_certs, i))) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
        DO(sdata_builder.addCertificate(sba_cert.get()));
    }

    //  =crls=, optional
    for (size_t i = 0; i < cnt_crls; i++) {
        SmartBA sba_crl;
        if (!sba_crl.set(json_array_get_base64(ja_crls, i))) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
        DO(sdata_builder.addCrl(sba_crl.get()));
    }

    //  Encode SignedData
    DO(sdata_builder.encode());
    DO(json_object_set_base64(joResult, "bytes", sdata_builder.getEncoded()));

cleanup:
    return ret;
}
