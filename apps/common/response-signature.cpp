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

#include "response-signature.h"
#include "extension-helper.h"
#include "macros-internal.h"
#include "oid-utils.h"
#include "pem-helper.h"
#include "uapkic.h"
#include "uapkif.h"
#include "uapki-errors.h"
#include "uapki-ns-verify.h"
#include "app-common.h"


using namespace std;
using namespace UapkiNS;
using namespace AppCommon;


namespace ResponseSignature {

static bool ba_equals (
        const ByteArray* ba1,
        const ByteArray* ba2
)
{
    return (ba1 && ba2 && (ba_cmp(ba1, ba2) == 0));
}

static bool is_keyid_of_cert (
        const TBSCertificate_t& tbs,
        const ByteArray* baKeyId
)
{
    SmartBA sba_keyid;
    if (
        tbs.extensions &&
        (ExtensionHelper::getSubjectKeyId(tbs.extensions, &sba_keyid) == RET_OK) &&
        ba_equals(sba_keyid.get(), baKeyId)
    ) {
        return true;
    }

    //  Без розширення: геш значення відкритого ключа (SHA-1 за RFC 5280 або ГОСТ 34.311 для ДСТУ 4145)
    const BIT_STRING_t& pubkey = tbs.subjectPublicKeyInfo.subjectPublicKey;
    SmartBA sba_pubkey;
    if (!sba_pubkey.set(ba_alloc_from_uint8(pubkey.buf, (size_t)pubkey.size))) return false;
    for (const HashAlg hash_alg : { HASH_ALG_SHA1, HASH_ALG_GOST34311 }) {
        SmartBA sba_hash;
        if (
            (::hash(hash_alg, sba_pubkey.get(), &sba_hash) == RET_OK) &&
            ba_equals(sba_hash.get(), baKeyId)
        ) {
            return true;
        }
    }
    return false;
}

static int is_issuer_and_sn_of_cert (
        const TBSCertificate_t& tbs,
        const ByteArray* baIssuerAndSN,
        bool& isEqual
)
{
    int ret = RET_OK;
    IssuerAndSerialNumber_t* issuer_and_sn = nullptr;
    SmartBA sba_issuer1, sba_issuer2, sba_serial1, sba_serial2;

    isEqual = false;
    CHECK_NOT_NULL(issuer_and_sn = (IssuerAndSerialNumber_t*)asn_decode_ba_with_alloc(get_IssuerAndSerialNumber_desc(), baIssuerAndSN));
    DO(asn_encode_ba(get_Name_desc(), &issuer_and_sn->issuer, &sba_issuer1));
    DO(asn_encode_ba(get_Name_desc(), &tbs.issuer, &sba_issuer2));
    DO(asn_INTEGER2ba(&issuer_and_sn->serialNumber, &sba_serial1));
    DO(asn_INTEGER2ba(&tbs.serialNumber, &sba_serial2));
    isEqual = ba_equals(sba_issuer1.get(), sba_issuer2.get()) && ba_equals(sba_serial1.get(), sba_serial2.get());

cleanup:
    asn_free(get_IssuerAndSerialNumber_desc(), issuer_and_sn);
    return ret;
}

//  Якщо сертифікат належить підписувачу — повертає його SPKI і серійний номер
static int match_cert (
        const ByteArray* baCert,
        const SignerId& signerId,
        ByteArray** baSpki,
        ByteArray** baSerialNumber
)
{
    int ret = RET_OK;
    Certificate_t* cert = nullptr;
    bool is_equal = false;

    CHECK_NOT_NULL(cert = (Certificate_t*)asn_decode_ba_with_alloc(get_Certificate_desc(), baCert));
    {
        const TBSCertificate_t& tbs = cert->tbsCertificate;
        switch (signerId.type) {
        case SignerIdType::ISSUER_AND_SN:
            DO(is_issuer_and_sn_of_cert(tbs, signerId.value.get(), is_equal));
            break;
        case SignerIdType::KEY_ID:
            is_equal = is_keyid_of_cert(tbs, signerId.value.get());
            break;
        case SignerIdType::NAME: {
            SmartBA sba_subject;
            DO(asn_encode_ba(get_Name_desc(), &tbs.subject, &sba_subject));
            is_equal = ba_equals(sba_subject.get(), signerId.value.get());
            break;
        }
        default:
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }

        if (!is_equal) {
            SET_ERROR(RET_UAPKI_CERT_NOT_FOUND);
        }
        DO(asn_encode_ba(get_SubjectPublicKeyInfo_desc(), &tbs.subjectPublicKeyInfo, baSpki));
        DO(asn_INTEGER2ba(&tbs.serialNumber, baSerialNumber));
    }

cleanup:
    asn_free(get_Certificate_desc(), cert);
    return ret;
}

static int find_signer (
        const VectorBA& certs,
        const SignerId& signerId,
        ByteArray** baSpki,
        ByteArray** baSerialNumber
)
{
    for (const auto& it : certs) {
        const int ret = match_cert(it, signerId, baSpki, baSerialNumber);
        if (ret != RET_UAPKI_CERT_NOT_FOUND) return ret;
    }
    return RET_UAPKI_CERT_NOT_FOUND;
}

static string signer_id_to_str (
        const SignerId& signerId
)
{
    switch (signerId.type) {
    case SignerIdType::ISSUER_AND_SN: return string("issuer and serial number");
    case SignerIdType::KEY_ID: return string("key id, HEX: ") + baToHex(signerId.value.get());
    case SignerIdType::NAME: return string("name");
    default: return string("undefined");
    }
}

int signerIdFromSid (
        const ByteArray* baSidEncoded,
        SignerId& signerId
)
{
    int ret = RET_OK;
    SignerIdentifier_t* sid = nullptr;

    CHECK_NOT_NULL(sid = (SignerIdentifier_t*)asn_decode_ba_with_alloc(get_SignerIdentifier_desc(), baSidEncoded));
    switch (sid->present) {
    case SignerIdentifier_PR_issuerAndSerialNumber:
        DO(asn_encode_ba(get_IssuerAndSerialNumber_desc(), &sid->choice.issuerAndSerialNumber, &signerId.value));
        signerId.type = SignerIdType::ISSUER_AND_SN;
        break;
    case SignerIdentifier_PR_subjectKeyIdentifier:
        DO(asn_OCTSTRING2ba(&sid->choice.subjectKeyIdentifier, &signerId.value));
        signerId.type = SignerIdType::KEY_ID;
        break;
    default:
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

cleanup:
    asn_free(get_SignerIdentifier_desc(), sid);
    return ret;
}

int verify (
        const VectorBA& responseCerts,
        const string& responderCertFile,
        const SignerId& signerId,
        const string& signAlgo,
        const VerifyFunc& verifyFunc,
        string& report
)
{
    SmartBA sba_spki, sba_serial;
    string s_source = "response";

    report += string("Signature verification:") + LF;
    report += TAB + string("Signature algo, OID:  ") + signAlgo + LF;
    report += TAB + string("Signer id:            ") + signer_id_to_str(signerId) + LF;

    int ret = find_signer(responseCerts, signerId, &sba_spki, &sba_serial);
    if ((ret == RET_UAPKI_CERT_NOT_FOUND) && !responderCertFile.empty()) {
        VectorBA vba_filecerts;
        ret = PemHelper::loadCerts(responderCertFile, vba_filecerts);
        if (ret != RET_OK) {
            report += TAB + string("Can not load certificate from file: ") + responderCertFile + LF;
            return ret;
        }
        ret = find_signer(vba_filecerts, signerId, &sba_spki, &sba_serial);
        s_source = string("file ") + responderCertFile;
    }
    if (ret == RET_UAPKI_CERT_NOT_FOUND) {
        report += TAB + string("Signer certificate:   NOT FOUND");
        report += string(responderCertFile.empty() ? ", specify --responder-cert <FILE>" : "") + LF;
        return ret;
    }
    if (ret != RET_OK) return ret;

    report += TAB + string("Signer certificate:   from ") + s_source + LF;
    report += TAB + string("Serial number, HEX:   ") + baToHex(sba_serial.get()) + LF;

    ret = verifyFunc(sba_spki.get());
    string s_status;
    switch (ret) {
    case RET_OK:
        s_status = "VALID";
        break;
    case RET_VERIFY_FAILED:
        s_status = "INVALID";
        break;
    case RET_UAPKI_INVALID_DIGEST:
        s_status = "INVALID (message digest mismatch)";
        break;
    default:
        s_status = string("FAILED (") + errcodeToStr(ret) + ")";
    }
    report += TAB + string("Signature:            ") + s_status + LF;
    return ret;
}

//  CMS допускає rsaEncryption як алгоритм підпису, тоді геш задає digestAlgorithm (RFC 3370)
static const char* signature_algo_of_signerinfo (
        const Pkcs7::SignedDataParser::SignerInfo& signerInfo
)
{
    static const char* RSA_BY_DIGEST[][2] = {
        { OID_SHA1,     OID_RSA_WITH_SHA1 },
        { OID_SHA224,   OID_RSA_WITH_SHA224 },
        { OID_SHA256,   OID_RSA_WITH_SHA256 },
        { OID_SHA384,   OID_RSA_WITH_SHA384 },
        { OID_SHA512,   OID_RSA_WITH_SHA512 },
        { OID_SHA3_224, OID_RSA_WITH_SHA3_224 },
        { OID_SHA3_256, OID_RSA_WITH_SHA3_256 },
        { OID_SHA3_384, OID_RSA_WITH_SHA3_384 },
        { OID_SHA3_512, OID_RSA_WITH_SHA3_512 }
    };

    const string& s_signalgo = signerInfo.getSignatureAlgorithm().algorithm;
    if (s_signalgo != string(OID_RSA)) return s_signalgo.c_str();

    const string& s_digestalgo = signerInfo.getDigestAlgorithm().algorithm;
    for (const auto& it : RSA_BY_DIGEST) {
        if (s_digestalgo == it[0]) return it[1];
    }
    return nullptr;
}

int verifySignerInfo (
        const Pkcs7::SignedDataParser::SignerInfo& signerInfo,
        const ByteArray* baEncapContent,
        const ByteArray* baSpki
)
{
    const HashAlg hash_alg = hash_from_oid(signerInfo.getDigestAlgorithm().algorithm.c_str());
    if (hash_alg == HASH_ALG_UNDEFINED) return RET_UAPKI_UNSUPPORTED_ALG;
    if (!baEncapContent || !signerInfo.getMessageDigest()) return RET_UAPKI_INVALID_STRUCT;

    SmartBA sba_hash;
    int ret = ::hash(hash_alg, baEncapContent, &sba_hash);
    if (ret != RET_OK) return ret;
    if (!ba_equals(sba_hash.get(), signerInfo.getMessageDigest())) return RET_UAPKI_INVALID_DIGEST;

    const char* s_signalgo = signature_algo_of_signerinfo(signerInfo);
    if (!s_signalgo) return RET_UAPKI_UNSUPPORTED_ALG;

    return Verify::verifySignature(
        s_signalgo,
        signerInfo.getSignedAttrsEncoded(),
        false,
        baSpki,
        signerInfo.getSignature()
    );
}

}   //  end namespace ResponseSignature
