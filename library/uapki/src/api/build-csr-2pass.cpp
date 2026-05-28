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

#define FILE_MARKER "uapki/api/build-csr-2pass.cpp"

#include "api-json-internal.h"
#include "certreq-builder.h"
#include "extnreq-helper.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include "uapkif.h"
#include "uapki-ns.h"
#include "uapki-ns-util.h"


using namespace std;
using namespace UapkiNS;


static int step1_encodetbs (
        JSON_Object* joStep1Params,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    CertReqBuilder certreq_builder;
    ExtnRequestHelper extnreq_helper;
    UapkiNS::AlgorithmIdentifier aid_keyalgo;
    JSON_Object* jo_spki = json_object_get_object(joStep1Params, "subjectPublicKeyInfo");
    SmartBA sba_digest, sba_keyalgo, sba_pubkey, sba_spki, sba_subject;
    HashAlg hash_alg = HashAlg::HASH_ALG_UNDEFINED;

    if (ParsonHelper::jsonObjectHasValue(joStep1Params, "subject", JSONString)) {
        if (!sba_subject.set(json_object_get_base64(joStep1Params, "subject"))) return RET_UAPKI_INVALID_PARAMETER;
    }
    if (
        ParsonHelper::jsonObjectHasValue(jo_spki, "bytes", JSONString) &&
        !ParsonHelper::jsonObjectHasValue(jo_spki, "algorithm")
    ) {
        if (!sba_spki.set(json_object_get_base64(jo_spki, "bytes"))) return RET_UAPKI_INVALID_PARAMETER;
    }
    else if (
        !ParsonHelper::jsonObjectHasValue(jo_spki, "bytes") &&
        ParsonHelper::jsonObjectHasValue(jo_spki, "algorithm", JSONString)
    ) {
        aid_keyalgo.algorithm = ParsonHelper::jsonObjectGetString(jo_spki, "algorithm");
        aid_keyalgo.baParameters = json_object_get_base64(jo_spki, "parameters");
        sba_pubkey.set(json_object_get_base64(jo_spki, "publicKey"));
        if (!aid_keyalgo.isPresent() || sba_pubkey.empty()) return RET_UAPKI_INVALID_PARAMETER;
    }
    else return RET_UAPKI_INVALID_PARAMETER;
    if (ParsonHelper::jsonObjectHasValue(joStep1Params, "extensionRequest", JSONObject)) {
        JSON_Object* jo_extnreq = json_object_get_object(joStep1Params, "extensionRequest");
        JSON_Array* ja_extns = json_object_get_array(jo_extnreq, "extensions");

        if (ParsonHelper::jsonObjectHasValue(jo_extnreq, "extendedKeyUsage", JSONArray)) {
            JSON_Array* ja_extkeyusage = json_object_get_array(jo_extnreq, "extendedKeyUsage");
            const size_t cnt_ekus = json_array_get_count(ja_extkeyusage);
            if (cnt_ekus > 0) {
                vector<string> ekus;
                for (size_t i = 0; i < cnt_ekus; i++) {
                    const string s_oid = ParsonHelper::jsonArrayGetString(ja_extkeyusage, i);
                    if (!s_oid.empty() && oid_is_valid(s_oid.c_str())) {
                        ekus.push_back(s_oid);
                    }
                }
                extnreq_helper.setKeyPurposeIds(ekus);
                DO(extnreq_helper.encodeExtKeyUsage(nullptr, false));
            }
        }
        if (ParsonHelper::jsonObjectHasValue(jo_extnreq, "subjectKeyIdentifier", JSONString)) {
            SmartBA sba_keyid;
            if (!sba_keyid.set(json_object_get_hex(jo_extnreq, "subjectKeyIdentifier"))) return RET_UAPKI_INVALID_PARAMETER;
            DO(extnreq_helper.encodeSubjectKeyId(sba_keyid.get(), false));
        }
        if (ParsonHelper::jsonObjectHasValue(jo_extnreq, "pkaBytes", JSONString)) {
            SmartBA sba_pkattestate;
            if (!sba_pkattestate.set(json_object_get_base64(jo_extnreq, "pkaBytes"))) return RET_UAPKI_INVALID_PARAMETER;
            DO(extnreq_helper.encodePkAttestate(sba_pkattestate.get(), false));
        }
        if (json_array_get_count(ja_extns) > 0) {
            VectorBA vba_customextns;
            vba_customextns.resize(json_array_get_count(ja_extns));
            for (size_t i = 0; i < vba_customextns.size(); i++) {
                SmartBA sba_extnvalue;
                JSON_Object* jo_extn = json_array_get_object(ja_extns, i);
                const string s_extnid = ParsonHelper::jsonObjectGetString(jo_extn, "extnId");
                const bool critical = ParsonHelper::jsonObjectGetBoolean(jo_extn, "critical", false);
                sba_extnvalue.set(json_object_get_base64(jo_extn, "extnValue"));
                if (s_extnid.empty() || !oid_is_valid(s_extnid.c_str()) || sba_extnvalue.empty()) {
                    return RET_UAPKI_INVALID_PARAMETER;
                }
                DO(Util::encodeExtension(
                    s_extnid,
                    critical,
                    sba_extnvalue.get(),
                    &vba_customextns[i]
                ));
            }
            extnreq_helper.pushCustomExtns(vba_customextns);
        }
    }
    if (ParsonHelper::jsonObjectHasValue(joStep1Params, "digestAlgo", JSONString)) {
        const string s_digestalgo = ParsonHelper::jsonObjectGetString(joStep1Params, "digestAlgo");
        hash_alg = hash_from_oid(s_digestalgo.c_str());
        if (hash_alg == HashAlg::HASH_ALG_UNDEFINED) {
            SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
        }
    }

    DO(certreq_builder.init(1));
    if (!sba_subject.empty()) {
        DO(certreq_builder.setSubject(sba_subject.get()));
    }
    if (!sba_spki.empty()) {
        DO(certreq_builder.setSubjectPublicKeyInfo(sba_spki.get()));
    }
    else {
        DO(certreq_builder.setSubjectPublicKeyInfo(aid_keyalgo, sba_pubkey.get()));
    }
    if (extnreq_helper.build() > 0) {
        DO(certreq_builder.addExtensions(extnreq_helper.getEncodedExtns()));
    }

    DO(certreq_builder.encodeTbs());

    DO_JSON(json_object_set_base64(joResult, "bytes", certreq_builder.getTbsEncoded()));

    if (hash_alg != HashAlg::HASH_ALG_UNDEFINED) {
        DO(::hash(hash_alg, certreq_builder.getTbsEncoded(), &sba_digest));
        DO_JSON(json_object_set_base64(joResult, "digestBytes", sba_digest.get()));
    }

cleanup:
    return ret;
}   //  step1_encodetbs

static int step2_encodecsr (
        JSON_Object* joStep2Params,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    CertReqBuilder certreq_builder;
    UapkiNS::AlgorithmIdentifier aid_signalgo;
    SmartBA sba_encodedtbs, sba_signvalue;

    sba_encodedtbs.set(json_object_get_base64(joStep2Params, "bytes"));
    aid_signalgo.algorithm = ParsonHelper::jsonObjectGetString(joStep2Params, "signAlgo");
    aid_signalgo.baParameters = json_object_get_base64(joStep2Params, "signAlgoParams");
    sba_signvalue.set(json_object_get_base64(joStep2Params, "signBytes"));
    if (sba_encodedtbs.empty() || !aid_signalgo.isPresent() || sba_signvalue.empty()) return RET_UAPKI_INVALID_PARAMETER;

    DO(certreq_builder.init(sba_encodedtbs.get()));
    DO(certreq_builder.encodeTbs());
    DO(certreq_builder.encodeCertRequest(aid_signalgo, sba_signvalue.get()));

    DO_JSON(json_object_set_base64(joResult, "bytes", certreq_builder.getCsrEncoded()));

cleanup:
    return ret;
}   //  step2_encodecsr

int uapki_build_csr_2pass (
        JSON_Object* joParams,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    int cnt_steps = 0;

    if (ParsonHelper::jsonObjectHasValue(joParams, "step1", JSONObject)) {
        DO_JSON(json_object_set_value(joResult, "step1", json_value_init_object()));
        DO(step1_encodetbs(
            json_object_get_object(joParams, "step1"),
            json_object_get_object(joResult, "step1")
        ));
        cnt_steps++;
    }
    if (ParsonHelper::jsonObjectHasValue(joParams, "step2", JSONObject)) {
        DO_JSON(json_object_set_value(joResult, "step2", json_value_init_object()));
        DO(step2_encodecsr(
            json_object_get_object(joParams, "step2"),
            json_object_get_object(joResult, "step2"))
        );
        cnt_steps++;
    }

    if (cnt_steps == 0) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

cleanup:
    return ret;
}
