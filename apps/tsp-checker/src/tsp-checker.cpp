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
#include "http-helper.h"
#include "oid-helper.h"
#include "oid-utils.h"
#include "response-signature.h"
#include "time-util.h"
#include "tsp-helper.h"
#include "tsp-checker-options.h"
#include "uapkic.h"
#include "uapki-errors.h"
#include "uapki-ns.h"
#include "app-common.h"


using namespace std;
using namespace UapkiNS;
using namespace AppCommon;


static const uint8_t ASN1_NULL_ENCODED[2] = { 0x05, 0x00 };

static const char* HELP_STRINGS =
    "Usage: tsp-checker --url <URL> [options...]\n"
    "  --url <URL>                 URL of TSP-service\n"
    "  --header <HEADER>           Default: Content-Type:application/timestamp-query\n"
    "  --digest-algo <ALGO_OID>    Default: 1.2.804.2.1.1.1.1.2.1\n"
    "  --digest-param-null         Optional\n"
    "  --digest <DIGEST>           Optional\n"
    "  --req-policy <POLICY_OID>   Optional\n"
    "  --nonce-hex <NONCE_HEX>     Optional\n"
    "  --nonce-len <NONCE_LEN>     Optional\n"
    "  --cert-req                  Optional\n"
    "  --responder-cert <FILE>     Certificate of TSA (PEM or DER), if the response does not contain it. Optional\n"
    "  --save-pem <FILE_PEM>       Save certificates from response in PEM format to file. Optional\n"
    "  --save-request <FILE_TSQ>   Save TSQ-request to file. Optional\n"
    "  --save-response <FILE_TSR>  Save TSQ-response to file. Optional\n"
    "\n"
    "Aliases of digest algorithm (for --digest-algo):\n"
    "  gost-34311, sha1, sha224, sha256, sha384, sha512, sha3-224, sha3-256, sha3-384, sha3-512\n";

static const char* STAGE_STRINGS[6] = {
    "\r[1] TSP-request is generated.           ",   //  STAGE[0]
    "\r[2] TSP-response received.              ",   //  STAGE[1]
    "\r[3] TSP-response is successed parsed.   ",   //  STAGE[2]
    "\r[4] TSP-response is GRANTED.            ",   //  STAGE[3]
    "\r[5] TstInfo is equal TSP-request.       ",   //  STAGE[4]
    "\r[6] Signature is VALID.                 "    //  STAGE[5]
};

static const char* STAGE4_NOT_EQUAL =
    "\r[5] TstInfo is NOT equal TSP-request    ";   //  for STAGE[4]
static const char* STAGE5_NOT_VALID =
    "\r[6] Signature is NOT VALID.             ";   //  for STAGE[5]

static const char* TSP_STATUS_STRINGS[6] = {
    "GRANTED",
    "GRANTED_WITHMODS",
    "REJECTION",
    "WAITING",
    "REVOCATION_WARNING",
    "REVOCATION_NOTIFICATION"
};


static void init_hash_alias (
        AliasToOid& hashAlias
)
{
    hashAlias.add("GOST-34311", OID_GOST34311);
    hashAlias.add("SHA1",       OID_SHA1);
    hashAlias.add("SHA224",     OID_SHA224);
    hashAlias.add("SHA256",     OID_SHA256);
    hashAlias.add("SHA384",     OID_SHA384);
    hashAlias.add("SHA512",     OID_SHA512);
    hashAlias.add("SHA3-224",   OID_SHA3_224);
    hashAlias.add("SHA3-256",   OID_SHA3_256);
    hashAlias.add("SHA3-384",   OID_SHA3_384);
    hashAlias.add("SHA3-512",   OID_SHA3_512);
}

static int process_tstoken (
        Tsp::TspHelper& tspHelper,
        const TspCheckerOptions& options,
        WorkFlowInfo& wfi
)
{
    Pkcs7::SignedDataParser sdata_parser;
    Pkcs7::SignedDataParser::SignerInfo signer_info;
    Tsp::TsTokenParser tstoken_parser;

    int ret = sdata_parser.parse(tspHelper.getTsToken());
    if (ret != RET_OK) return ret;
    if (
        (!sdata_parser.getEncapContentInfo().baEncapContent) ||
        (sdata_parser.getCountSignerInfos() == 0)
    ) {
        return RET_UAPKI_INVALID_STRUCT;
    }

    if (!options.savePem.empty()) {
        (void)saveCertsToPem(sdata_parser.getCerts(), options.savePem, wfi);
    }

    ret = sdata_parser.parseSignerInfo(0, signer_info);
    if (ret != RET_OK) return ret;

    ret = tstoken_parser.parse(tspHelper.getTsToken());
    if (ret != RET_OK) return ret;

    wfi.detail += TAB + string("Count certs:        ") + to_string(sdata_parser.getCerts().size()) + LF;
    wfi.detail += TAB + string("TSA PolicyId, OID:  ") + tstoken_parser.getPolicyId() + LF;
    wfi.detail += TAB + string("Digest Algo, OID:   ") + tstoken_parser.getHashAlgo() + LF;
    wfi.detail += TAB + string("Digest, HEX:        ") + baToHex(tstoken_parser.getHashedMessage()) + LF;
    wfi.detail += TAB + string("Serial Number, HEX: ") + baToHex(tstoken_parser.getSerialNumber()) + LF;
    wfi.detail += TAB + string("Gen Time:           ") + TimeUtil::mtimeToFtime(tstoken_parser.getGenTime()) + LF;
    wfi.detail += TAB + string("Accuracy:           ") + string(tstoken_parser.accuracyIsPresent() ? "PRESENT" : "NOT PRESENT") + LF;
    wfi.detail += TAB + string("Ordering:           ") + string(tstoken_parser.getOrdering() ? "TRUE" : "FALSE") + LF;  //  current ASN1-struct without Ordering
    wfi.detail += TAB + string("Nonce, HEX:         ") + (tstoken_parser.getNonce() ? baToHex(tstoken_parser.getNonce()) : string("NOT PRESENT")) + LF;

    ret = tspHelper.tstInfoIsEqualRequest();
    printf((ret == RET_OK) ? STAGE_STRINGS[4] : STAGE4_NOT_EQUAL);
    wfi.detail += TAB + string((ret == RET_OK) ? "TstInfo is equal TSP-request" : "TstInfo is NOT equal TSP-request") + LF;
    if (ret != RET_OK) return ret;

    ResponseSignature::SignerId signer_id;
    ret = ResponseSignature::signerIdFromSid(signer_info.getSidEncoded(), signer_id);
    if (ret != RET_OK) return ret;

    const ByteArray* ba_tstinfo = sdata_parser.getEncapContentInfo().baEncapContent;
    ret = ResponseSignature::verify(
        sdata_parser.getCerts(),
        options.responderCert,
        signer_id,
        signer_info.getSignatureAlgorithm().algorithm,
        [&](const ByteArray* baSpki) {
            return ResponseSignature::verifySignerInfo(signer_info, ba_tstinfo, baSpki);
        },
        wfi.signature
    );
    printf((ret == RET_OK) ? STAGE_STRINGS[5] : STAGE5_NOT_VALID);
    return ret;
}   //  process_tstoken


int main (int argc, char* argv[])
{
    AliasToOid hash_alias;
    TspCheckerOptions options;
    const int ret_opt = checkParsedOptions(options.parse(argc, argv), options.helper, argc);
    if (ret_opt != RET_OK) return ret_opt;

    if (options.outVersion) {
        puts("tsp-checker version: " APP_VERSION);
    }
    if (options.outHelp) {
        puts(HELP_STRINGS);
        return 0;
    }

    init_hash_alias(hash_alias);
    if (options.url.empty()) {
        return showOptionError(-1, string("required option '--url' is missed"));
    }
    if (options.header.empty()) {
        options.header = string(HttpHelper::CONTENT_TYPE_TSP_REQUEST);
    }
    if (options.hashAlgo.empty()) {
        options.hashAlgo = string(OID_GOST34311);
    }
    options.hashAlgo = hash_alias.toOid(options.hashAlgo);
    bool is_valid = oid_is_valid(options.hashAlgo.c_str());
    if (!is_valid) {
        return showOptionError(-1, string("option --digest-algo have invalid value ") + options.hashAlgo);
    }

    const HashAlg hash_algo = hash_from_oid(options.hashAlgo.c_str());
    const size_t hash_size = hash_get_size(hash_algo);
    SmartBA sba_hash, sba_resp;
    if (!options.hashedMessage.empty()) {
        if (hash_size > 0) {
            if (2 * hash_size != options.hashedMessage.size()) {
                return showOptionError(-1, string("option --digest have invalid length"));
            }
        }
        if (!sba_hash.set(ba_alloc_from_hex(options.hashedMessage.c_str()))) {
            return showOptionError(-2, string("option --digest have invalid value ") + options.hashedMessage);
        }
    }
    else {
        if (hash_size > 0) {
            if (
                !sba_hash.set(ba_alloc_by_len(hash_size)) ||
                (drbg_random(sba_hash.get()) != 0)
            ) {
                return showOptionError(-2, string("internal error"));
            }
        }
        else {
            return showOptionError(-2, string("option --digest-algo have unknown digest algorithm ") + options.hashAlgo);
        }
    }

    if (!options.reqPolicy.empty()) {
        is_valid = oid_is_valid(options.reqPolicy.c_str());
        if (!is_valid) {
            return showOptionError(-1, string("option --req-policy have invalid value ") + options.reqPolicy);
        }
    }

    UapkiNS::AlgorithmIdentifier aid_hash;
    aid_hash.algorithm = options.hashAlgo;
    if (options.hashParamNull) {
        aid_hash.baParameters = ba_alloc_from_uint8(ASN1_NULL_ENCODED, sizeof(ASN1_NULL_ENCODED));
        if (!aid_hash.baParameters) {
            return showOptionError(-2, string("internal error"));
        }
    }

    HttpSession http;
    WorkFlowInfo wfi;

    wfi.ret = http.init();
    if (wfi.ret != RET_OK) return wfi.ret;

    Tsp::TspHelper tsp_helper;
    wfi.ret = tsp_helper.init();
    if (wfi.ret != RET_OK) return wfi.ret;

    wfi.ret = tsp_helper.setMessageImprint(aid_hash, sba_hash.get());
    if (wfi.ret != RET_OK) return wfi.ret;

    if (!options.nonceHex.empty()) {
        SmartBA sba_nonce;
        if (!sba_nonce.set(ba_alloc_from_hex(options.nonceHex.c_str()))) {
            return showOptionError(-1, string("invalid parameter '--nonce-hex'=" + options.nonceHex));
        }
        wfi.ret = tsp_helper.setNonce(sba_nonce.get());
    }
    else if (!options.nonceLen.empty()) {
        int nonce_len = stol(options.nonceLen.c_str());
        if ((nonce_len < Tsp::NONCE_MINLEN) || (nonce_len > Tsp::NONCE_MAXLEN)) {
            return showOptionError(-1, string("invalid parameter '--nonce-len'=" + options.nonceLen));
        }
        wfi.ret = tsp_helper.genNonce((size_t)nonce_len);
    }
    if (wfi.ret != RET_OK) return wfi.ret;
    wfi.ret = tsp_helper.setCertReq(options.certReq);
    if (wfi.ret != RET_OK) return wfi.ret;
    if (!options.reqPolicy.empty()) {
        wfi.ret = tsp_helper.setReqPolicy(options.reqPolicy);
        if (wfi.ret != RET_OK) return wfi.ret;
    }

    wfi.ret = tsp_helper.encodeRequest();
    if (wfi.ret != RET_OK) return wfi.ret;

    printf(STAGE_STRINGS[0]);
    wfi.http += string("TSP-request is generated, bytes: ") + to_string(ba_get_len(tsp_helper.getRequestEncoded())) + LF;
    if (!options.saveRequest.empty()) {
        (void)saveToFile(tsp_helper.getRequestEncoded(), options.saveRequest, "TSP-request", wfi);
    }

    wfi.ret = postRequest(options.url, options.header, tsp_helper.getRequestEncoded(), "TSP-response", &sba_resp, wfi);
    if (wfi.ret != RET_OK) return wfi.ret;

    printf(STAGE_STRINGS[1]);
    if (!options.saveResponse.empty()) {
        (void)saveToFile(sba_resp.get(), options.saveResponse, "TSP-response", wfi);
    }

    wfi.ret = tsp_helper.parseResponse(sba_resp.get());
    wfi.detail += string("Parsed TSP-response: ") + errcodeToStr(wfi.ret) + LF;
    if (wfi.ret != RET_OK) return wfi.ret;

    printf(STAGE_STRINGS[2]);
    const Tsp::PkiStatus tsp_status = tsp_helper.getStatus();
    if ((tsp_status >= Tsp::PkiStatus::GRANTED) && (tsp_status <= Tsp::PkiStatus::REVOCATION_NOTIFICATION)) {
        wfi.detail += TAB + string("TSP-status:         ") + string(TSP_STATUS_STRINGS[(int)tsp_status]) + LF;
    }
    else {
        wfi.detail += TAB + string("TSP-status:         ") + to_string((int)tsp_status) + LF;
    }
    if ((tsp_status != Tsp::PkiStatus::GRANTED) && (tsp_status != Tsp::PkiStatus::GRANTED_WITHMODS)) {
        wfi.ret = RET_UAPKI_TSP_RESPONSE_NOT_GRANTED;
        return wfi.ret;
    }

    printf(STAGE_STRINGS[3]);
    wfi.ret = process_tstoken(tsp_helper, options, wfi);
    return wfi.ret;
}
