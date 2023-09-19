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

#define FILE_MARKER "uapki/api/cert-status-by-ocsp.cpp"

#include "api-json-internal.h"
#include "cert-validator.h"
#include "global-objects.h"
#include "oid-utils.h"
#include "parson-ba-utils.h"
#include "parson-helper.h"
#include "store-json.h"
#include "time-util.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"


using namespace std;
using namespace UapkiNS;


int uapki_cert_status_by_ocsp (JSON_Object* joParams, JSON_Object* joResult)
{
    CertValidator::CertValidator cert_validator;
    if (!cert_validator.init(get_config(), get_cerstore(), get_crlstore())) return RET_UAPKI_GENERAL_ERROR;
    if (!cert_validator.getLibConfig()->isInitialized()) return RET_UAPKI_NOT_INITIALIZED;

    int ret = RET_OK;
    Ocsp::OcspHelper ocsp_helper;
    Cert::CerStore& cer_store = *cert_validator.getCerStore();
    Cert::CerItem* cer_issuer = nullptr;
    SmartBA sba_issuercertid, sba_serialnumber, sba_issuerbytes, sba_resp;

    const string s_url = ParsonHelper::jsonObjectGetString(joParams, "url");
    const uint32_t nonce_len = ParsonHelper::jsonObjectGetUint32(joParams, "nonceLen", 0);
    sba_issuercertid.set(json_object_get_base64(joParams, "issuerCertId"));
    sba_serialnumber.set(json_object_get_hex(joParams, "serialNumber"));

    if (sba_serialnumber.empty()) return RET_UAPKI_INVALID_PARAMETER;

    DO(ocsp_helper.init());
    if (!sba_issuercertid.empty()) {
        //  Note: if cert not found the just return RET_UAPKI_CERT_NOT_FOUND without 'expectedCerts'
        DO(cer_store.getCertByCertId(sba_issuercertid.get(), &cer_issuer));
        DO(ocsp_helper.addIssuerAndSN(cer_issuer, sba_serialnumber.get()));
    }
    else {
        UapkiNS::AlgorithmIdentifier aid_hashalgo;
        SmartBA sba_issuernamehash, sba_issuerkeyhash;

        aid_hashalgo.algorithm = ParsonHelper::jsonObjectGetString(joParams, "hashAlgo");
        sba_issuerbytes.set(json_object_get_base64(joParams, "issuerBytes"));
        sba_issuernamehash.set(json_object_get_hex(joParams, "issuerNameHash"));
        sba_issuerkeyhash.set(json_object_get_hex(joParams, "issuerKeyHash"));

        if (
            !aid_hashalgo.isPresent() ||
            sba_issuerkeyhash.empty()
        ) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
        else if (sba_issuernamehash.empty()) {
            const HashAlg hash_alg = hash_from_oid(aid_hashalgo.algorithm.c_str());
            if (hash_alg == HASH_ALG_UNDEFINED) {
                SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
            }
            DO(::hash(hash_alg, sba_issuerbytes.get(), &sba_issuernamehash));
        }

        DO(ocsp_helper.addCertId(
            aid_hashalgo,
            sba_issuernamehash.get(),
            sba_issuerkeyhash.get(),
            sba_serialnumber.get())
        );
    }

    if ((nonce_len >= Ocsp::NONCE_MINLEN) && (nonce_len <= Ocsp::NONCE_MAXLEN)) {
        DO(ocsp_helper.genNonce(nonce_len));
    }

    DO(ocsp_helper.encodeRequest());

    DO(json_object_set_base64(joResult, "requestBytes", ocsp_helper.getRequestEncoded()));

    if (!s_url.empty()) {
        if (HttpHelper::isOfflineMode()) {
            SET_ERROR(RET_UAPKI_OFFLINE_MODE);
        }

        lock_guard<mutex> lock(HttpHelper::lockUri(s_url));

        DO(HttpHelper::post(
            s_url,
            HttpHelper::CONTENT_TYPE_OCSP_REQUEST,
            ocsp_helper.getRequestEncoded(),
            &sba_resp
        ));

        if (sba_resp.empty()) {
            SET_ERROR(RET_UAPKI_OCSP_RESPONSE_INVALID);
        }
        DO(json_object_set_base64(joResult, "bytes", sba_resp.get()));

        ret = ocsp_helper.parseResponse(sba_resp.get());
        DO_JSON(json_object_set_string(joResult, "responseStatus", Ocsp::responseStatusToStr(ocsp_helper.getResponseStatus())));

        if ((ret == RET_OK) && (ocsp_helper.getResponseStatus() == Ocsp::ResponseStatus::SUCCESSFUL)) {
            Ocsp::OcspHelper::SingleResponseInfo singleresp_info;
            DO(cert_validator.processResponseData(
                ocsp_helper,
                singleresp_info,
                joResult
            ));

            if (cer_issuer || !sba_issuerbytes.empty()) {
                Cert::CerItem* cer_subject = nullptr;
                if (cer_issuer) {
                    ret = cer_store.getCertByIssuerAndSN(cer_issuer->getSubject(), sba_serialnumber.get(), &cer_subject);
                }
                else {
                    ret = cer_store.getCertByIssuerAndSN(sba_issuerbytes.get(), sba_serialnumber.get(), &cer_subject);
                }
                if ((ret == RET_OK) && cer_subject) {
                    lock_guard<mutex> lock(cer_subject->getMutex());
                    DO(cer_subject->getCertStatusByOcsp().set(
                        singleresp_info.certStatus,
                        singleresp_info.msThisUpdate + Ocsp::OFFSET_EXPIRE_DEFAULT,
                        sba_resp.get()
                    ));
                }
                ret = RET_OK;   //  getCertByIssuerAndSN() may return RET_UAPKI_CERT_NOT_FOUND
            }
        }
    }

cleanup:
    return ret;
}
