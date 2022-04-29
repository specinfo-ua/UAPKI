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

#include "store-utils.h"
#include "asn1-ba-utils.h"
#include "attribute-utils.h"
#include "extension-helper.h"
#include "extension-utils.h"
#include "macros-internal.h"
#include "oid-utils.h"
#include "parson-ba-utils.h"
#include "parson-helper.h"
#include "uapki-errors.h"
#include "uapki-ns.h"
#include "time-utils.h"
#include "verify-utils.h"
#include <string>


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;
using namespace ExtensionHelper;


int CerStoreUtils::detailInfoToJson (JSON_Object* joResult, const CerStore::Item* cerStoreItem)
{
    int ret = RET_OK;
    const TBSCertificate_t& tbs_cert = cerStoreItem->cert->tbsCertificate;
    long version = 0;
    bool self_signed = false;

    if (tbs_cert.version != nullptr) {
        DO(asn_INTEGER2long(tbs_cert.version, &version));
    }

    DO_JSON(ParsonHelper::jsonObjectSetInt32(joResult, "version", (int32_t)version + 1));
    DO(json_object_set_hex(joResult, "serialNumber", cerStoreItem->baSerialNumber));
    DO_JSON(json_object_set_value(joResult, "issuer", json_value_init_object()));
    DO_JSON(json_object_set_value(joResult, "validity", json_value_init_object()));
    DO_JSON(json_object_set_value(joResult, "subject", json_value_init_object()));
    DO_JSON(json_object_set_value(joResult, "subjectPublicKeyInfo", json_value_init_object()));
    DO_JSON(json_object_set_value(joResult, "extensions", json_value_init_array()));
    DO_JSON(json_object_set_value(joResult, "signatureInfo", json_value_init_object()));

    DO(CerStoreUtils::nameToJson(json_object_get_object(joResult, "issuer"), tbs_cert.issuer));
    DO(validityToJson(joResult, cerStoreItem));
    DO(CerStoreUtils::nameToJson(json_object_get_object(joResult, "subject"), tbs_cert.subject));
    DO(CerStoreUtils::spkiToJson(json_object_get_object(joResult, "subjectPublicKeyInfo"), cerStoreItem, true));
    DO(CerStoreUtils::extensionsToJson(json_object_get_array(joResult, "extensions"), cerStoreItem, self_signed));
    DO(CerStoreUtils::signatureInfoToJson(json_object_get_object(joResult, "signatureInfo"), cerStoreItem));
    DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "selfSigned", self_signed));

cleanup:
    return ret;
}

static int extns_encoded_to_json (const Extensions_t* extns, JSON_Object* joResult)
{
    int ret = RET_OK;
    ByteArray* ba_value = nullptr;
    JSON_Array* ja_extns = nullptr;
    char* s_extnid = nullptr;

    DO_JSON(json_object_set_value(joResult, "encoded", json_value_init_array()));
    ja_extns = json_object_get_array(joResult, "encoded");
    for (int i = 0; i < extns->list.count; i++) {
        DO_JSON(json_array_append_value(ja_extns, json_value_init_object()));
        JSON_Object* jo_extn = json_array_get_object(ja_extns, i);
        const Extension_t* extn = extns->list.array[i];

        DO(asn_oid_to_text(&extn->extnID, &s_extnid));
        DO_JSON(json_object_set_string(jo_extn, "extnId", s_extnid));

        if (extn->critical) {
            DO_JSON(ParsonHelper::jsonObjectSetBoolean(jo_extn, "critical", true));
        }

        DO(asn_OCTSTRING2ba(&extn->extnValue, &ba_value));
        DO(json_object_set_base64(jo_extn, "extnValue", ba_value));

        ::free(s_extnid);
        s_extnid = nullptr;
        ba_free(ba_value);
        ba_value = nullptr;
    }

cleanup:
    ba_free(ba_value);
    ::free(s_extnid);
    return ret;
}

static JSON_Object* extn_json_add_decoded (JSON_Object* joResult, const char* extnIdName)
{
    json_object_set_value(joResult, "decoded", json_value_init_object());
    JSON_Object* jo_decoded = json_object_get_object(joResult, "decoded");
    if (!jo_decoded) return nullptr;

    int ret = RET_OK;
    DO_JSON(json_object_set_string(jo_decoded, "id", extnIdName));
    DO_JSON(json_object_set_value(jo_decoded, "value", json_value_init_object()));

cleanup:
    return json_object_get_object(jo_decoded, "value");
}

int CerStoreUtils::extensionsToJson (JSON_Array* jaResult, const CerStore::Item* cerStoreItem, bool& selfSigned)
{
    int ret = RET_OK;
    const Extensions_t* extns = cerStoreItem->cert->tbsCertificate.extensions;
    ByteArray* ba_authoritykeyid = nullptr;
    ByteArray* ba_subjectkeyid = nullptr;
    ByteArray* ba_value = nullptr;
    JSON_Array* ja_extns = nullptr;
    char* s_extnid = nullptr;

    for (int i = 0; i < extns->list.count; i++) {
        DO_JSON(json_array_append_value(jaResult, json_value_init_object()));
        JSON_Object* jo_extn = json_array_get_object(jaResult, i);
        const Extension_t* extn = extns->list.array[i];

        DO(asn_oid_to_text(&extn->extnID, &s_extnid));
        DO_JSON(json_object_set_string(jo_extn, "extnId", s_extnid));

        if (extn->critical) {
            DO_JSON(ParsonHelper::jsonObjectSetBoolean(jo_extn, "critical", true));
        }

        DO(asn_OCTSTRING2ba(&extn->extnValue, &ba_value));
        DO(json_object_set_base64(jo_extn, "extnValue", ba_value));

        //  Decode specific extensions
        if (oid_is_equal(s_extnid, OID_X509v3_KeyUsage)) {
            DO(DecodeToJsonObject::keyUsage(ba_value, extn_json_add_decoded(jo_extn, "keyUsage")));
        }
        else if (oid_is_equal(s_extnid, OID_X509v3_SubjectKeyIdentifier)) {
            DO(DecodeToJsonObject::subjectKeyIdentifier(ba_value, extn_json_add_decoded(jo_extn, "subjectKeyIdentifier"), &ba_subjectkeyid));
        }
        else if (oid_is_equal(s_extnid, OID_X509v3_AuthorityKeyIdentifier)) {
            DO(DecodeToJsonObject::authorityKeyIdentifier(ba_value, extn_json_add_decoded(jo_extn, "authorityKeyIdentifier"), &ba_authoritykeyid));
        }
        else if (oid_is_equal(s_extnid, OID_X509v3_BasicConstraints)) {
            DO(DecodeToJsonObject::basicConstraints(ba_value, extn_json_add_decoded(jo_extn, "basicConstraints")));
        }
        else if (oid_is_equal(s_extnid, OID_X509v3_CRLDistributionPoints)) {
            DO(DecodeToJsonObject::distributionPoints(ba_value, extn_json_add_decoded(jo_extn, "cRLDistributionPoints")));
        }
        else if (oid_is_equal(s_extnid, OID_X509v3_CertificatePolicies)) {
            DO(DecodeToJsonObject::certificatePolicies(ba_value, extn_json_add_decoded(jo_extn, "certificatePolicies")));
        }
        else if (oid_is_equal(s_extnid, OID_X509v3_ExtendedKeyUsage)) {
            DO(DecodeToJsonObject::extendedKeyUsage(ba_value, extn_json_add_decoded(jo_extn, "extKeyUsage")));
        }
        else if (oid_is_equal(s_extnid, OID_X509v3_FreshestCRL)) {
            DO(DecodeToJsonObject::distributionPoints(ba_value, extn_json_add_decoded(jo_extn, "freshestCRL")));
        }
        else if (oid_is_equal(s_extnid, OID_X509v3_SubjectDirectoryAttributes)) {
            DO(DecodeToJsonObject::subjectDirectoryAttributes(ba_value, extn_json_add_decoded(jo_extn, "subjectDirectoryAttributes")));
        }
        else if (oid_is_equal(s_extnid, OID_PKIX_AuthorityInfoAccess)) {
            DO(DecodeToJsonObject::accessDescriptions(ba_value, extn_json_add_decoded(jo_extn, "authorityInfoAccess")));
        }
        else if (oid_is_equal(s_extnid, OID_PKIX_QcStatements)) {
            DO(DecodeToJsonObject::qcStatements(ba_value, extn_json_add_decoded(jo_extn, "qcStatements")));
        }
        else if (oid_is_equal(s_extnid, OID_PKIX_SubjectInfoAccess)) {
            DO(DecodeToJsonObject::accessDescriptions(ba_value, extn_json_add_decoded(jo_extn, "subjectInfoAccess")));
        }
        else if (oid_is_equal(s_extnid, OID_X509v3_SubjectAlternativeName)) {
            DO(DecodeToJsonObject::alternativeName(ba_value, extn_json_add_decoded(jo_extn, "subjectAltName")));
        }
        else if (oid_is_equal(s_extnid, OID_X509v3_IssuerAlternativeName)) {
            DO(DecodeToJsonObject::alternativeName(ba_value, extn_json_add_decoded(jo_extn, "issuerAltName")));
        }

        ::free(s_extnid);
        s_extnid = nullptr;
        ba_free(ba_value);
        ba_value = nullptr;
    }

    //  Check selfSigned
    selfSigned = (ba_subjectkeyid) && (ba_authoritykeyid) && (ba_cmp(ba_subjectkeyid, ba_authoritykeyid) == 0);

cleanup:
    ba_free(ba_authoritykeyid);
    ba_free(ba_subjectkeyid);
    ba_free(ba_value);
    ::free(s_extnid);
    return ret;
}


int CerStoreUtils::nameToJson (JSON_Object* joResult, const Name_t& name)
{
    if (name.present != Name_PR_rdnSequence) return RET_UAPKI_INVALID_STRUCT;

    int ret = RET_OK;
    char* s_oid = nullptr;
    char* s_value = nullptr;

    for (size_t i = 0; i < name.choice.rdnSequence.list.count; i++) {
        const RelativeDistinguishedName_t* rdname_src = name.choice.rdnSequence.list.array[i];
        for (size_t j = 0; j < rdname_src->list.count; j++) {
            const AttributeTypeAndValue_t* attr = rdname_src->list.array[j];
            DO(asn_oid_to_text(&attr->type, &s_oid));
            DO(asn_decode_anystring(attr->value.buf, (const size_t)attr->value.size, &s_value));
            DO_JSON(json_object_set_string(joResult, oid_to_rdname(s_oid), s_value));
            ::free(s_oid);
            ::free(s_value);
            s_oid = s_value = nullptr;
        }
    }

cleanup:
    ::free(s_oid);
    ::free(s_value);
    return ret;
}

int CerStoreUtils::signatureInfoToJson (JSON_Object* joResult, const CerStore::Item* cerStoreItem)
{
    if ((joResult == nullptr) || (cerStoreItem == nullptr)) return RET_UAPKI_GENERAL_ERROR;

    int ret = RET_OK;
    const ByteArray* ref_ba;
    const ANY_t* any_params = cerStoreItem->cert->signatureAlgorithm.parameters;
    ByteArray* ba_encapsignvalue = nullptr;
    ByteArray* ba_encoded = nullptr;
    char* s_signalgo = nullptr;

    //  Set algorithm
    DO(asn_oid_to_text(&cerStoreItem->cert->signatureAlgorithm.algorithm, &s_signalgo));
    DO_JSON(json_object_set_string(joResult, "algorithm", s_signalgo));

    //  Set parameters
    if (any_params != nullptr) {
        ba_encoded = ba_alloc_from_uint8(any_params->buf, any_params->size);
        if (ba_encoded == nullptr) {
            SET_ERROR(RET_MEMORY_ALLOC_ERROR);
        }
        DO(json_object_set_base64(joResult, "parameters", ba_encoded));
        ba_free(ba_encoded);
        ba_encoded = nullptr;
    }

    //  Set signature
    DO(asn_BITSTRING2ba(&cerStoreItem->cert->signature, &ba_encoded));
    if (oid_is_parent(OID_DSTU4145_WITH_DSTU7564, s_signalgo)
        || oid_is_parent(OID_DSTU4145_WITH_GOST3411, s_signalgo)) {
        DO(ba_decode_octetstring(ba_encoded, &ba_encapsignvalue));
        ref_ba = ba_encapsignvalue;
    }
    else {
        ref_ba = ba_encoded;
    }
    DO(json_object_set_base64(joResult, "signature", ref_ba));

cleanup:
    ba_free(ba_encapsignvalue);
    ba_free(ba_encoded);
    ::free(s_signalgo);
    return ret;
}

int CerStoreUtils::spkiToJson (JSON_Object* joResult, const CerStore::Item* cerStoreItem, const bool encoded)
{
    if ((joResult == nullptr) || (cerStoreItem == nullptr)) return RET_UAPKI_GENERAL_ERROR;

    int ret = RET_OK;
    const ByteArray* ref_ba;
    const SubjectPublicKeyInfo_t& spki = cerStoreItem->cert->tbsCertificate.subjectPublicKeyInfo;
    const ANY_t* any_params = spki.algorithm.parameters;
    ByteArray* ba_encappubkey = nullptr;
    ByteArray* ba_encoded = nullptr;

    if (encoded) {
        DO(json_object_set_base64(joResult, "bytes", cerStoreItem->baSPKI));
    }

    //  Set algorithm
    DO_JSON(json_object_set_string(joResult, "algorithm", cerStoreItem->keyAlgo));

    //  Set parameters
    if (any_params != nullptr) {
        ba_encoded = ba_alloc_from_uint8(any_params->buf, any_params->size);
        if (ba_encoded == nullptr) {
            SET_ERROR(RET_MEMORY_ALLOC_ERROR);
        }
        DO(json_object_set_base64(joResult, "parameters", ba_encoded));
        ba_free(ba_encoded);
        ba_encoded = nullptr;
    }

    //  Set publicKey
    DO(asn_BITSTRING2ba(&spki.subjectPublicKey, &ba_encoded));
    if (oid_is_parent(OID_DSTU4145_WITH_DSTU7564, cerStoreItem->keyAlgo)
        || oid_is_parent(OID_DSTU4145_WITH_GOST3411, cerStoreItem->keyAlgo)) {
        DO(ba_encode_octetstring(ba_encoded, &ba_encappubkey));
        ref_ba = ba_encappubkey;
    }
    else {
        ref_ba = ba_encoded;
    }
    DO(json_object_set_base64(joResult, "publicKey", ref_ba));

cleanup:
    ba_free(ba_encappubkey);
    ba_free(ba_encoded);
    return ret;
}

int CerStoreUtils::validityToJson (JSON_Object* joResult, const CerStore::Item* cerStoreItem)
{
    if ((joResult == nullptr) || (cerStoreItem == nullptr)) return RET_UAPKI_GENERAL_ERROR;

    int ret = RET_OK;
    string s_time;

    s_time = TimeUtils::mstimeToFormat(cerStoreItem->notBefore);
    DO_JSON(json_object_dotset_string(joResult, "validity.notBefore", s_time.c_str()));

    s_time = TimeUtils::mstimeToFormat(cerStoreItem->notAfter);
    DO_JSON(json_object_dotset_string(joResult, "validity.notAfter", s_time.c_str()));

cleanup:
    return ret;
}

int CerStoreUtils::verify (const CerStore::Item* cerSubject, const CerStore::Item* cerIssuer)
{
    int ret = RET_OK;
    X509Tbs_t* x509_cert = nullptr;
    ByteArray* ba_signvalue = nullptr;
    ByteArray* ba_tbs = nullptr;
    char* s_signalgo = nullptr;

    CHECK_PARAM(cerSubject != nullptr);
    CHECK_PARAM(cerIssuer != nullptr);

    CHECK_NOT_NULL(x509_cert = (X509Tbs_t*)asn_decode_ba_with_alloc(get_X509Tbs_desc(), cerSubject->baEncoded));
    CHECK_NOT_NULL(ba_tbs = ba_alloc_from_uint8(x509_cert->tbsData.buf, x509_cert->tbsData.size));

    DO(asn_oid_to_text(&cerSubject->cert->signatureAlgorithm.algorithm, &s_signalgo));
    if (cerSubject->algoKeyId == HASH_ALG_GOST34311) {
        DO(asn_decodevalue_bitstring_encap_octet(&cerSubject->cert->signature, &ba_signvalue));
    }
    else {
        DO(asn_BITSTRING2ba(&cerSubject->cert->signature, &ba_signvalue));
    }

    ret = verify_signature(s_signalgo, ba_tbs, false, cerIssuer->baSPKI, ba_signvalue);

cleanup:
    asn_free(get_X509Tbs_desc(), x509_cert);
    ba_free(ba_signvalue);
    ba_free(ba_tbs);
    ::free(s_signalgo);
    return ret;
}


int CrlStoreUtils::infoToJson (JSON_Object* joResult, const CrlStore::Item* crlStoreItem)
{
    int ret = RET_OK;
    uint32_t cnt_revcerts = 0;
    string s_time;

    if ((joResult == nullptr) || (crlStoreItem == nullptr)) return RET_UAPKI_GENERAL_ERROR;

    DO_JSON(json_object_set_value(joResult, "issuer", json_value_init_object()));
    DO(CerStoreUtils::nameToJson(json_object_get_object(joResult, "issuer"), crlStoreItem->crl->tbsCertList.issuer));

    s_time = TimeUtils::mstimeToFormat(crlStoreItem->thisUpdate);
    DO_JSON(json_object_set_string(joResult, "thisUpdate", s_time.c_str()));

    s_time = TimeUtils::mstimeToFormat(crlStoreItem->nextUpdate);
    DO_JSON(json_object_set_string(joResult, "nextUpdate", s_time.c_str()));


    DO_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "countRevokedCerts", (uint32_t)crlStoreItem->countRevokedCerts()));

    if (crlStoreItem->baAuthorityKeyId) {
        DO_JSON(json_object_set_hex(joResult, "authorityKeyId", crlStoreItem->baAuthorityKeyId));
    }

    DO_JSON(json_object_set_hex(joResult, "crlNumber", crlStoreItem->baCrlNumber));

    if (crlStoreItem->baDeltaCrl) {
        DO_JSON(json_object_set_hex(joResult, "deltaCrlIndicator", crlStoreItem->baDeltaCrl));
    }

cleanup:
    return ret;
}

int CrlStoreUtils::revokedCertsToJson (JSON_Array* jaResult, const CrlStore::Item* crlStoreItem)
{
    int ret = RET_OK;
    const RevokedCertificates_t* revoked_certs = nullptr;
    ByteArray* ba_sn = nullptr;
    size_t cnt_crls;
    uint64_t ms_time = 0;
    string s_time;

    if ((jaResult == nullptr) || (crlStoreItem == nullptr)) return RET_UAPKI_GENERAL_ERROR;

    revoked_certs = crlStoreItem->crl->tbsCertList.revokedCertificates;
    if (!revoked_certs) return ret;

    DEBUG_OUTCON(printf("CrlStoreUtils::revokedCertsToJson() count: %d\n", revoked_certs->list.count));
    cnt_crls = (size_t)revoked_certs->list.count;
    for (size_t i = 0; i < cnt_crls; i++) {
        JSON_Object* jo_result = nullptr;
        const RevokedCertificate_t* revoked_cert = revoked_certs->list.array[i];

        DO_JSON(json_array_append_value(jaResult, json_value_init_object()));
        jo_result = json_array_get_object(jaResult, i);

        DO(asn_INTEGER2ba(&revoked_cert->userCertificate, &ba_sn));
        DO(json_object_set_hex(jo_result, "userCertificate", ba_sn));
        ba_free(ba_sn);
        ba_sn = nullptr;

        DO(asn_decodevalue_pkixtime(&revoked_cert->revocationDate, &ms_time));
        s_time = TimeUtils::mstimeToFormat(ms_time);
        DO_JSON(json_object_set_string(jo_result, "revocationDate", s_time.c_str()));

        if (revoked_cert->crlEntryExtensions) {
            uint32_t u32_crlreason = 0;
            ret = extns_get_crl_reason(revoked_cert->crlEntryExtensions, &u32_crlreason);
            if (ret == RET_OK) {
                DO_JSON(json_object_set_string(jo_result, "crlReason", CrlStore::crlReasonToStr((UapkiNS::CrlReason)u32_crlreason)));
            }
            ret = extns_get_crl_invalidity_date(revoked_cert->crlEntryExtensions, &ms_time);
            if (ret == RET_OK) {
                s_time = TimeUtils::mstimeToFormat(ms_time);
                DO_JSON(json_object_set_string(jo_result, "invalidityDate", s_time.c_str()));
            }
        }
    }

cleanup:
    ba_free(ba_sn);
    return ret;
}

