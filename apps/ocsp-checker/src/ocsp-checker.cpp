/*
 * Copyright (c) 2026, The UAPKI Project Authors.
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

#include <stdio.h>
#include <string.h>
#include "ba-utils.h"
#include "extension-helper.h"
#include "http-helper.h"
#include "macros-internal.h"
#include "ocsp-helper.h"
#include "ocsp-checker-options.h"
#include "oid-utils.h"
#include "response-signature.h"
#include "time-util.h"
#include "uapkic.h"
#include "uapkif.h"
#include "uapki-errors.h"
#include "uapki-ns.h"
#include "uapki-ns-util.h"
#include "app-common.h"


using namespace std;
using namespace UapkiNS;
using namespace AppCommon;


static const uint8_t ASN1_NULL_ENCODED[2] = { 0x05, 0x00 };

static const char* HELP_STRINGS =
    "Usage: ocsp-checker --cert <FILE_CER> [options...]\n"
    "  --cert <FILE_CER>           File of certificate\n"
    "  --header <HEADER>           Default: Content-Type:application/ocsp-request\n"
    "  --nonce-hex <NONCE_HEX>     Optional\n"
    "  --nonce-len <NONCE_LEN>     Optional\n"
    "  --responder-cert <FILE>     Certificate of OCSP-responder (PEM or DER), if the response does not contain it. Optional\n"
    "  --save-pem <FILE_PEM>       Save certificates from response in PEM format to file. Optional\n"
    "  --save-request <FILE_ORQ>   Save OCSP-request to file. Optional\n"
    "  --save-response <FILE_ORS>  Save OCSP-response to file. Optional\n";

static const char* STAGE_STRINGS[8] = {
    "\r[1] Parsing certificate...              ",   //  STAGE[0]
    "\r[2] Certificate is parsed.              ",   //  STAGE[1]
    "\r[3] OCSP-request is generated.          ",   //  STAGE[2]
    "\r[4] OCSP-response received.             ",   //  STAGE[3]
    "\r[5] OCSP-response is successed parsed.  ",   //  STAGE[4]
    "\r[6] Response-status is SUCCESSFUL.      ",   //  STAGE[5]
    "\r[7] Nonce is equal OCSP-request.        ",   //  STAGE[6]
    "\r[8] Signature is VALID.                 "    //  STAGE[7]
};

static const char* STAGE7_NOT_VALID =
    "\r[8] Signature is NOT VALID.             ";   //  for STAGE[7]


struct CertInfo {
    HashAlg     algoKeyId = HASH_ALG_UNDEFINED;
    SmartBA     authorityKeyId;
    UapkiNS::AlgorithmIdentifier
                keyAlgo;
    SmartBA     issuerEncoded;
    std::vector<std::string>
                ocsp;
    SmartBA     serialNumber;
    UapkiNS::AlgorithmIdentifier
                signAlgo;
    SmartBA     subjectKeyId;
};  //  end struct CertInfo


static const char* certstatus_to_str (
        const UapkiNS::CertStatus status
)
{
    static const char* CERT_STATUS_STRINGS[4] = {
        "UNDEFINED", "GOOD", "REVOKED", "UNKNOWN"
    };

    int32_t idx = (int32_t)status + 1;
    return CERT_STATUS_STRINGS[(idx < 4) ? idx : 0];
}   //  certstatus_to_str

static const char* crlreason_to_str (
        const UapkiNS::CrlReason reason
)
{
    static const char* CRL_REASON_STRINGS[12] = {
        "UNDEFINED", "UNSPECIFIED", "KEY_COMPROMISE", "CA_COMPROMISE", "AFFILIATION_CHANGED",
        "SUPERSEDED", "CESSATION_OF_OPERATION", "CERTIFICATE_HOLD", "", "REMOVE_FROM_CRL",
        "PRIVILEGE_WITHDRAWN", "AA_COMPROMISE"
    };

    int32_t idx = (int32_t)reason + 1;
    return CRL_REASON_STRINGS[(idx < 12) ? idx : 0];
}   //  crlreason_to_str

static bool is_dstu_family (const char* algo)
{
    return (
        algo &&
        (oid_is_parent(OID_DSTU4145_WITH_DSTU7564, algo) || oid_is_parent(OID_DSTU4145_WITH_GOST3411, algo))
    );
}   //  is_dstu_family

static int parse_cert (
        const string& certFile,
        CertInfo& certInfo
)
{
    int ret = RET_OK;
    SmartBA sba_cert;
    Certificate_t* cert = nullptr;
    Extensions_t* extns = nullptr;
    TBSCertificate_t* tbs = nullptr;

    DO(ba_alloc_from_file(certFile.c_str(), &sba_cert));
    if (sba_cert.empty()) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

    cert = (Certificate_t*)asn_decode_ba_with_alloc(get_Certificate_desc(), sba_cert.get());
    tbs = (cert) ? &cert->tbsCertificate : nullptr;
    extns = (tbs) ? tbs->extensions : nullptr;
    if (!extns || (extns->list.count == 0)) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

    DO(asn_INTEGER2ba(&tbs->serialNumber, &certInfo.serialNumber));
    DO(asn_encode_ba(get_Name_desc(), &tbs->issuer, &certInfo.issuerEncoded));
    DO(Util::algorithmIdentifierFromAsn1(tbs->subjectPublicKeyInfo.algorithm, certInfo.keyAlgo));
    certInfo.algoKeyId = (is_dstu_family(certInfo.keyAlgo.algorithm.c_str())) ? HASH_ALG_GOST34311 : HASH_ALG_SHA1;
    DO(ExtensionHelper::getAuthorityKeyId(extns, &certInfo.authorityKeyId));
    DO(ExtensionHelper::getOcspUris(extns, certInfo.ocsp));
    DO(ExtensionHelper::getSubjectKeyId(extns, &certInfo.subjectKeyId));
    DO(Util::algorithmIdentifierFromAsn1(cert->signatureAlgorithm, certInfo.signAlgo));

cleanup:
    asn_free(get_Certificate_desc(), cert);
    return ret;
}   //  parse_cert

//  Сертифіката видавця немає: issuerKeyHash береться з authorityKeyIdentifier
static int add_certid (
        Ocsp::OcspHelper& ocspHelper,
        const CertInfo& certInfo
)
{
    int ret = RET_OK;
    UapkiNS::AlgorithmIdentifier aid_hashalgo;
    SmartBA sba_issuernamehash;

    aid_hashalgo.algorithm = string(hash_to_oid(certInfo.algoKeyId));
    if (ba_get_len(certInfo.signAlgo.baParameters) == 2) {
        const uint8_t* buf = ba_get_buf_const(certInfo.signAlgo.baParameters);
        if ((buf[0] == 0x05) && (buf[1] == 0x00)) {
            CHECK_NOT_NULL(aid_hashalgo.baParameters = ba_alloc_from_uint8(ASN1_NULL_ENCODED, sizeof(ASN1_NULL_ENCODED)));
        }
    }
    DO(::hash(certInfo.algoKeyId, certInfo.issuerEncoded.get(), &sba_issuernamehash));

    DO(ocspHelper.addCertId(
        aid_hashalgo,
        sba_issuernamehash.get(),
        certInfo.authorityKeyId.get(),
        certInfo.serialNumber.get()
    ));

cleanup:
    return ret;
}   //  add_certid

static void print_certinfo (
        const CertInfo& cerItem,
        WorkFlowInfo& wfi
)
{
    wfi.cert += string("Certificate information:") + LF;
    wfi.cert += TAB + string("Serial number, HEX:   ") + baToHex(cerItem.serialNumber.get()) + LF;
    wfi.cert += TAB + string("Key algo, OID:        ") + cerItem.keyAlgo.algorithm + LF;
    wfi.cert += TAB + string("Key param, HEX:       ");
    wfi.cert += ((cerItem.keyAlgo.baParameters) ? baToHex(cerItem.keyAlgo.baParameters) : string("NOT PRESENT")) + LF;
    wfi.cert += TAB + string("Authority keyid, HEX: ") + baToHex(cerItem.authorityKeyId.get()) + LF;
    wfi.cert += TAB + string("Subject keyid, HEX:   ") + baToHex(cerItem.subjectKeyId.get()) + LF;
    const size_t cnt_uris = cerItem.ocsp.size();
    if (cnt_uris == 1) {
        wfi.cert += TAB + string("ocsp, URL:            ") + cerItem.ocsp[0] + LF;
    }
    else if (cnt_uris > 1) {
        for (size_t i = 0; i < cnt_uris; i++) {
            wfi.cert += TAB + string("ocsp[") + to_string(i) + string("], URL:         ") + cerItem.ocsp[i] + LF;
        }
    }
    wfi.cert += TAB + string("Signature algo, OID:  ") + cerItem.signAlgo.algorithm + LF;
    wfi.cert += TAB + string("Signature param, HEX: ");
    wfi.cert += ((cerItem.signAlgo.baParameters) ? baToHex(cerItem.signAlgo.baParameters) : string("NOT PRESENT")) + LF;
}   //  print_certinfo

static int check_nonce (
        Ocsp::OcspHelper& ocspHelper,
        WorkFlowInfo& wfi
)
{
    const char* s_nonce = nullptr;
    const int ret = ocspHelper.checkNonce();
    switch (ret) {
    case RET_OK:
        s_nonce = STAGE_STRINGS[6];
        wfi.detail += TAB + string("Check nonce:          EQUAL") + LF;
        break;
    case RET_UAPKI_EXTENSION_NOT_PRESENT:
        s_nonce = "\r[7] Nonce is NOT PRESENT, but MUST BE.  ";
        wfi.detail += TAB + string("Check nonce:          NOT PRESENT, but MUST BE") + LF;
        break;
    case RET_UAPKI_OCSP_RESPONSE_INVALID_NONCE:
        s_nonce = "\r[7] Nonce is INVALID.                   ";
        wfi.detail += TAB + string("Check nonce:          INVALID") + LF;
        break;
    default:
        s_nonce = "\r[7] Check nonce is FAILED.              ";
        wfi.detail += TAB + string("Check nonce:          FAILED") + LF;
        break;
    }
    printf(s_nonce);
    return ret;
}   //  check_nonce

static int verify_signature (
        Ocsp::OcspHelper& ocspHelper,
        const VectorBA& responseCerts,
        const string& responderCertFile,
        WorkFlowInfo& wfi
)
{
    Ocsp::ResponderIdType responder_idtype = Ocsp::ResponderIdType::UNDEFINED;
    ResponseSignature::SignerId signer_id;
    string s_signalgo;

    int ret = ocspHelper.getResponderId(responder_idtype, &signer_id.value);
    if (ret != RET_OK) return ret;
    signer_id.type = (responder_idtype == Ocsp::ResponderIdType::BY_NAME)
        ? ResponseSignature::SignerIdType::NAME : ResponseSignature::SignerIdType::KEY_ID;

    ret = ocspHelper.getSignatureAlgorithm(s_signalgo);
    if (ret != RET_OK) return ret;

    ret = ResponseSignature::verify(
        responseCerts,
        responderCertFile,
        signer_id,
        s_signalgo,
        [&](const ByteArray* baSpki) {
            SignatureVerifyStatus status_sign = SignatureVerifyStatus::UNDEFINED;
            return ocspHelper.verifyTbsResponseData(baSpki, status_sign);
        },
        wfi.signature
    );
    printf((ret == RET_OK) ? STAGE_STRINGS[7] : STAGE7_NOT_VALID);
    return ret;
}   //  verify_signature

static int process_basicocspresp (
        Ocsp::OcspHelper& ocspHelper,
        const OcspCheckerOptions& options,
        WorkFlowInfo& wfi
)
{
    VectorBA vba_encodedcerts;
    int ret = ocspHelper.getCerts(vba_encodedcerts);
    if (ret != RET_OK) return ret;

    if (!options.savePem.empty()) {
        (void)saveCertsToPem(vba_encodedcerts, options.savePem, wfi);
    }

    wfi.detail += TAB + string("Count certificates:   ") + to_string(vba_encodedcerts.size()) + LF;
    wfi.detail += TAB + string("Produced at:          ") + TimeUtil::mtimeToFtime(ocspHelper.getProducedAt()) + LF;

    ret = ocspHelper.scanSingleResponses();
    if (ret != RET_OK) return ret;

    const Ocsp::OcspHelper::SingleResponseInfo& single_respinfo = ocspHelper.getSingleResponseInfo(0);
    wfi.detail += TAB + string("Certificate status:   ") + certstatus_to_str(single_respinfo.certStatus) + LF;
    wfi.detail += TAB + string("This update:          ") + TimeUtil::mtimeToFtime(single_respinfo.msThisUpdate) + LF;
    wfi.detail += TAB + string("Next update:          ");
    wfi.detail += ((single_respinfo.msNextUpdate > 0) ? TimeUtil::mtimeToFtime(single_respinfo.msNextUpdate) : string("NOT PRESENT")) + LF;

    if (single_respinfo.certStatus == UapkiNS::CertStatus::REVOKED) {
        wfi.detail += TAB + string("Revocation reason:    ") + crlreason_to_str(single_respinfo.revocationReason) + LF;
        wfi.detail += TAB + string("Revocation time:      ") + TimeUtil::mtimeToFtime(single_respinfo.msRevocationTime) + LF;
    }

    ret = check_nonce(ocspHelper, wfi);
    if (ret != RET_OK) return ret;

    ret = verify_signature(ocspHelper, vba_encodedcerts, options.responderCert, wfi);
    if (ret != RET_OK) return ret;

    string s_certstatus = string("\r[9] Certificate status: ") + certstatus_to_str(single_respinfo.certStatus);
    s_certstatus.append(41 - s_certstatus.length(), ' ');
    printf(s_certstatus.c_str());
    return ret;
}   //  process_basicocspresp


int main (int argc, char* argv[])
{
    OcspCheckerOptions options;
    const int ret_opt = checkParsedOptions(options.parse(argc, argv), options.helper, argc);
    if (ret_opt != RET_OK) return ret_opt;

    if (options.outVersion) {
        puts("ocsp-checker version: " APP_VERSION);
    }
    if (options.outHelp) {
        puts(HELP_STRINGS);
        return 0;
    }

    if (options.header.empty()) {
        options.header = string(HttpHelper::CONTENT_TYPE_OCSP_REQUEST);
    }
    if (options.certFile.empty()) {
        return showOptionError(-1, string("required option '--cert' is missed"));
    }

    CertInfo cer_item;
    HttpSession http;
    SmartBA sba_resp;
    WorkFlowInfo wfi;

    printf(STAGE_STRINGS[0]);
    wfi.ret = parse_cert(options.certFile, cer_item);
    if (wfi.ret != RET_OK) return wfi.ret;

    printf(STAGE_STRINGS[1]);
    print_certinfo(cer_item, wfi);
    if (cer_item.ocsp.empty()) {
        wfi.ret = RET_UAPKI_OCSP_URL_NOT_PRESENT;
        return wfi.ret;
    }

    wfi.ret = http.init();
    if (wfi.ret != RET_OK) return wfi.ret;

    Ocsp::OcspHelper ocsp_helper;
    wfi.ret = ocsp_helper.init();
    if (wfi.ret != RET_OK) return wfi.ret;

    wfi.ret = add_certid(ocsp_helper, cer_item);
    if (wfi.ret != RET_OK) return wfi.ret;
    if (!options.nonceHex.empty()) {
        SmartBA sba_nonce;
        if (!sba_nonce.set(ba_alloc_from_hex(options.nonceHex.c_str()))) {
            return showOptionError(-1, string("invalid parameter '--nonce-hex'=" + options.nonceHex));
        }
        wfi.ret = ocsp_helper.setNonce(sba_nonce.get());
    }
    else if (!options.nonceLen.empty()) {
        int nonce_len = stol(options.nonceLen.c_str());
        if ((nonce_len < Ocsp::NONCE_MINLEN) || (nonce_len > Ocsp::NONCE_MAXLEN)) {
            return showOptionError(-1, string("invalid parameter '--nonce-len'=" + options.nonceLen));
        }
        wfi.ret = ocsp_helper.genNonce((size_t)nonce_len);
    }
    if (wfi.ret != RET_OK) return wfi.ret;

    wfi.ret = ocsp_helper.encodeRequest();
    if (wfi.ret != RET_OK) return wfi.ret;

    printf(STAGE_STRINGS[2]);
    wfi.http += string("OCSP-request is generated, bytes: ") + to_string(ba_get_len(ocsp_helper.getRequestEncoded())) + LF;
    if (!options.saveRequest.empty()) {
        (void)saveToFile(ocsp_helper.getRequestEncoded(), options.saveRequest, "OCSP-request", wfi);
    }

    wfi.ret = postRequest(cer_item.ocsp[0], options.header, ocsp_helper.getRequestEncoded(), "OCSP-response", &sba_resp, wfi);
    if (wfi.ret != RET_OK) return wfi.ret;

    printf(STAGE_STRINGS[3]);
    if (!options.saveResponse.empty()) {
        (void)saveToFile(sba_resp.get(), options.saveResponse, "OCSP-response", wfi);
    }

    wfi.ret = ocsp_helper.parseResponse(sba_resp.get());
    wfi.detail += string("Parsed OCSP-response: ") + errcodeToStr(wfi.ret) + LF;
    if (wfi.ret != RET_OK) return wfi.ret;

    printf(STAGE_STRINGS[4]);
    wfi.detail += TAB + string("Response status:      ") + Ocsp::responseStatusToStr(ocsp_helper.getResponseStatus()) + LF;
    if (ocsp_helper.getResponseStatus() != Ocsp::ResponseStatus::SUCCESSFUL) {
        wfi.ret = RET_UAPKI_OCSP_RESPONSE_NOT_SUCCESSFUL;
        return wfi.ret;
    }

    printf(STAGE_STRINGS[5]);
    wfi.ret = process_basicocspresp(ocsp_helper, options, wfi);
    return wfi.ret;
}
