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

#define FILE_MARKER "uapki/store-json.cpp"

#include "store-json.h"
#include "extension-helper.h"
#include "extension-helper-json.h"
#include "dstu-ns.h"
#include "macros-internal.h"
#include "oid-utils.h"
#include "parson-ba-utils.h"
#include "parson-helper.h"
#include "time-util.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"
#include "uapki-ns-verify.h"
#include <map>


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


namespace UapkiNS {


static int extns_encoded_to_json (
        const Extensions_t* extns,
        JSON_Object* joResult
)
{
    int ret = RET_OK;

    (void)json_object_set_value(joResult, "encoded", json_value_init_array());
    JSON_Array* ja_extns = json_object_get_array(joResult, "encoded");
    for (int i = 0; i < extns->list.count; i++) {
        DO_JSON(json_array_append_value(ja_extns, json_value_init_object()));
        JSON_Object* jo_extn = json_array_get_object(ja_extns, i);
        const Extension_t* extn = extns->list.array[i];
        SmartBA sba_value;
        string s_extnid;

        DO(Util::oidFromAsn1(&extn->extnID, s_extnid));
        DO_JSON(json_object_set_string(jo_extn, "extnId", s_extnid.c_str()));

        if (extn->critical) {
            DO_JSON(ParsonHelper::jsonObjectSetBoolean(jo_extn, "critical", true));
        }

        DO(asn_OCTSTRING2ba(&extn->extnValue, &sba_value));
        DO(json_object_set_base64(jo_extn, "extnValue", sba_value.get()));
    }

cleanup:
    return ret;
}   //  extns_encoded_to_json

static JSON_Object* extn_json_add_decoded (
        JSON_Object* joResult,
        const char* extnIdName
)
{
    json_object_set_value(joResult, "decoded", json_value_init_object());
    JSON_Object* jo_decoded = json_object_get_object(joResult, "decoded");
    if (!jo_decoded) return nullptr;

    int ret = RET_OK;
    DO_JSON(json_object_set_string(jo_decoded, "id", extnIdName));
    DO_JSON(json_object_set_value(jo_decoded, "value", json_value_init_object()));

cleanup:
    return json_object_get_object(jo_decoded, "value");
}   //  extn_json_add_decoded


Pagination::Pagination (void)
    : count(0)
    , offset(0)
    , offsetLast(0)
    , pageSize(0)
{}

void Pagination::calcParams (void)
{
    offset = (offset < count) ? offset : count;
    pageSize = (pageSize == 0) ? (count - offset) : pageSize;
    if (pageSize == 0) pageSize = 1;
    offsetLast = offset + pageSize;
    offsetLast = (offsetLast < count) ? offsetLast : count;
}

bool Pagination::parseParams (
        JSON_Object* joParams
)
{
    const int32_t int_offset = ParsonHelper::jsonObjectGetInt32(joParams, "offset", 0);
    if (int_offset < 0) return false;
    offset = (size_t)int_offset;

    const int32_t int_pagesize = ParsonHelper::jsonObjectGetInt32(joParams, "pageSize", 0);
    if (int_pagesize < 0) return false;
    pageSize = (size_t)int_pagesize;

    return true;
}

int Pagination::setResult (
        JSON_Object* joResult
)
{
    int ret = RET_OK;

    DO_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "count", (uint32_t)count));
    DO_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "offset", (uint32_t)offset));
    DO_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "pageSize", (uint32_t)pageSize));

cleanup:
    return ret;
}


int nameToJson (
        JSON_Object* joResult,
        const ByteArray* baEncoded
)
{
    int ret = RET_OK;
    Name_t* name = nullptr;

    CHECK_NOT_NULL(name = (Name_t*)asn_decode_ba_with_alloc(get_Name_desc(), baEncoded));

    DO(nameToJson(joResult, *name));

cleanup:
    asn_free(get_Name_desc(), name);
    return ret;
}

int nameToJson (
        JSON_Object* joResult,
        const Name_t& name
)
{
    if (name.present != Name_PR_rdnSequence) return RET_UAPKI_INVALID_STRUCT;

    int ret = RET_OK;
    map<string, string> map_name;
    for (int i = 0; i < name.choice.rdnSequence.list.count; i++) {
        const RelativeDistinguishedName_t* rdname_src = name.choice.rdnSequence.list.array[i];
        for (int j = 0; j < rdname_src->list.count; j++) {
            const AttributeTypeAndValue_t* attr = rdname_src->list.array[j];
            string s_oid, s_value;

            DO(Util::oidFromAsn1((OBJECT_IDENTIFIER_t*)&attr->type, s_oid));
            DO(Util::decodeAnyString(attr->value.buf, (const size_t)attr->value.size, s_value));
            s_oid = string(oid_to_rdname(s_oid.c_str()));
            auto it = map_name.find(s_oid);
            if (it == map_name.end()) {
                map_name.insert(pair<string, string>(s_oid, s_value));
            }
            else {
                it->second += string(";") + s_value;
            }
        }
    }

    for (const auto& it : map_name) {
        DO_JSON(json_object_set_string(joResult, it.first.c_str(), it.second.c_str()));
    }

cleanup:
    return ret;
}

int rdnameFromName (
        const Name_t& name,
        const char* type,
        string& value
)
{
    if (name.present != Name_PR_rdnSequence) return RET_UAPKI_INVALID_STRUCT;
    if (!type) return RET_UAPKI_INVALID_PARAMETER;

    for (int i = 0; i < name.choice.rdnSequence.list.count; i++) {
        const RelativeDistinguishedName_t* rdname_src = name.choice.rdnSequence.list.array[i];
        for (int j = 0; j < rdname_src->list.count; j++) {
            const AttributeTypeAndValue_t* attr = rdname_src->list.array[j];
            if (OID_is_equal_oid(&attr->type, type)) {
                const int ret = Util::decodeAnyString(attr->value.buf, (const size_t)attr->value.size, value);
                if (ret != RET_OK) return ret;
                break;
            }
        }
    }

    return RET_OK;
}


namespace Cert {

int detailInfoToJson (
        JSON_Object* joResult,
        const CerItem* cerItem
)
{
    int ret = RET_OK;
    const TBSCertificate_t& tbs_cert = cerItem->getCert()->tbsCertificate;
    long version = 0;
    bool self_signed = false;

    if (tbs_cert.version != nullptr) {
        DO(asn_INTEGER2long(tbs_cert.version, &version));
    }

    DO_JSON(ParsonHelper::jsonObjectSetInt32(joResult, "version", (int32_t)version + 1));
    DO(json_object_set_hex(joResult, "serialNumber", cerItem->getSerialNumber()));
    DO_JSON(json_object_set_value(joResult, "issuer", json_value_init_object()));
    DO_JSON(json_object_set_value(joResult, "validity", json_value_init_object()));
    DO_JSON(json_object_set_value(joResult, "subject", json_value_init_object()));
    DO_JSON(json_object_set_value(joResult, "subjectPublicKeyInfo", json_value_init_object()));
    DO_JSON(json_object_set_value(joResult, "extensions", json_value_init_array()));
    DO_JSON(json_object_set_value(joResult, "signatureInfo", json_value_init_object()));

    DO(nameToJson(json_object_get_object(joResult, "issuer"), tbs_cert.issuer));
    DO(validityToJson(joResult, cerItem));
    DO(nameToJson(json_object_get_object(joResult, "subject"), tbs_cert.subject));
    DO(spkiToJson(json_object_get_object(joResult, "subjectPublicKeyInfo"), cerItem, true));
    DO(extensionsToJson(json_object_get_array(joResult, "extensions"), cerItem, self_signed));
    DO(signatureInfoToJson(json_object_get_object(joResult, "signatureInfo"), cerItem));
    DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "selfSigned", self_signed));

cleanup:
    return ret;
}

int extensionsToJson (
        JSON_Array* jaResult,
        const CerItem* cerItem,
        bool& selfSigned
)
{
    int ret = RET_OK;
    const Extensions_t* extns = cerItem->getCert()->tbsCertificate.extensions;
    SmartBA sba_authoritykeyid, sba_subjectkeyid;
    JSON_Array* ja_extns = nullptr;

    if (!extns) return RET_UAPKI_INVALID_STRUCT;

    for (int i = 0; i < extns->list.count; i++) {
        DO_JSON(json_array_append_value(jaResult, json_value_init_object()));
        JSON_Object* jo_extn = json_array_get_object(jaResult, i);
        const Extension_t* extn = extns->list.array[i];
        SmartBA sba_value;
        string s_extnid;

        DO(Util::oidFromAsn1(&extn->extnID, s_extnid));
        DO_JSON(json_object_set_string(jo_extn, "extnId", s_extnid.c_str()));

        if (extn->critical) {
            DO_JSON(ParsonHelper::jsonObjectSetBoolean(jo_extn, "critical", true));
        }

        DO(asn_OCTSTRING2ba(&extn->extnValue, &sba_value));
        DO(json_object_set_base64(jo_extn, "extnValue", sba_value.get()));

        //  Decode specific extensions
        if (oid_is_equal(s_extnid.c_str(), OID_X509v3_KeyUsage)) {
            DO(ExtensionHelper::DecodeToJsonObject::keyUsage(sba_value.get(), extn_json_add_decoded(jo_extn, "keyUsage")));
        }
        else if (oid_is_equal(s_extnid.c_str(), OID_X509v3_SubjectKeyIdentifier)) {
            DO(ExtensionHelper::DecodeToJsonObject::subjectKeyId(sba_value.get(), extn_json_add_decoded(jo_extn, "subjectKeyIdentifier"), &sba_subjectkeyid));
        }
        else if (oid_is_equal(s_extnid.c_str(), OID_X509v3_AuthorityKeyIdentifier)) {
            DO(ExtensionHelper::DecodeToJsonObject::authorityKeyId(sba_value.get(), extn_json_add_decoded(jo_extn, "authorityKeyIdentifier"), &sba_authoritykeyid));
        }
        else if (oid_is_equal(s_extnid.c_str(), OID_X509v3_BasicConstraints)) {
            DO(ExtensionHelper::DecodeToJsonObject::basicConstraints(sba_value.get(), extn_json_add_decoded(jo_extn, "basicConstraints")));
        }
        else if (oid_is_equal(s_extnid.c_str(), OID_X509v3_CRLDistributionPoints)) {
            DO(ExtensionHelper::DecodeToJsonObject::distributionPoints(sba_value.get(), extn_json_add_decoded(jo_extn, "cRLDistributionPoints")));
        }
        else if (oid_is_equal(s_extnid.c_str(), OID_X509v3_CertificatePolicies)) {
            DO(ExtensionHelper::DecodeToJsonObject::certificatePolicies(sba_value.get(), extn_json_add_decoded(jo_extn, "certificatePolicies")));
        }
        else if (oid_is_equal(s_extnid.c_str(), OID_X509v3_ExtendedKeyUsage)) {
            DO(ExtensionHelper::DecodeToJsonObject::extendedKeyUsage(sba_value.get(), extn_json_add_decoded(jo_extn, "extKeyUsage")));
        }
        else if (oid_is_equal(s_extnid.c_str(), OID_X509v3_FreshestCRL)) {
            DO(ExtensionHelper::DecodeToJsonObject::distributionPoints(sba_value.get(), extn_json_add_decoded(jo_extn, "freshestCRL")));
        }
        else if (oid_is_equal(s_extnid.c_str(), OID_X509v3_SubjectDirectoryAttributes)) {
            DO(ExtensionHelper::DecodeToJsonObject::subjectDirectoryAttributes(sba_value.get(), extn_json_add_decoded(jo_extn, "subjectDirectoryAttributes")));
        }
        else if (oid_is_equal(s_extnid.c_str(), OID_PKIX_AuthorityInfoAccess)) {
            DO(ExtensionHelper::DecodeToJsonObject::accessDescriptions(sba_value.get(), extn_json_add_decoded(jo_extn, "authorityInfoAccess")));
        }
        else if (oid_is_equal(s_extnid.c_str(), OID_PKIX_QcStatements)) {
            DO(ExtensionHelper::DecodeToJsonObject::qcStatements(sba_value.get(), extn_json_add_decoded(jo_extn, "qcStatements")));
        }
        else if (oid_is_equal(s_extnid.c_str(), OID_PKIX_SubjectInfoAccess)) {
            DO(ExtensionHelper::DecodeToJsonObject::accessDescriptions(sba_value.get(), extn_json_add_decoded(jo_extn, "subjectInfoAccess")));
        }
        else if (oid_is_equal(s_extnid.c_str(), OID_X509v3_SubjectAlternativeName)) {
            DO(ExtensionHelper::DecodeToJsonObject::alternativeName(sba_value.get(), extn_json_add_decoded(jo_extn, "subjectAltName")));
        }
        else if (oid_is_equal(s_extnid.c_str(), OID_X509v3_IssuerAlternativeName)) {
            DO(ExtensionHelper::DecodeToJsonObject::alternativeName(sba_value.get(), extn_json_add_decoded(jo_extn, "issuerAltName")));
        }
    }

    //  Check selfSigned
    selfSigned = (!sba_subjectkeyid.empty() && !sba_authoritykeyid.empty() && (ba_cmp(sba_subjectkeyid.get(), sba_authoritykeyid.get()) == 0));

cleanup:
    return ret;
}

int ocspIdentifierToJson (
        JSON_Object* joResult,
        const ByteArray* baEncoded
)
{
    int ret = RET_OK;
    OcspIdentifier_t* ocsp_identifier = nullptr;
    SmartBA sba_keyid;
    uint64_t ms_producedat = 0;

    CHECK_NOT_NULL(ocsp_identifier = (OcspIdentifier_t*)asn_decode_ba_with_alloc(get_OcspIdentifier_desc(), baEncoded));

    //  =ocspResponderID=
    switch (ocsp_identifier->ocspResponderID.present) {
    case ResponderID_PR_byName:
        DO_JSON(json_object_set_value(joResult, "responderId", json_value_init_object()));
        DO(nameToJson(json_object_get_object(joResult, "responderId"), ocsp_identifier->ocspResponderID.choice.byName));
        break;
    case ResponderID_PR_byKey:
        DO(asn_OCTSTRING2ba(&ocsp_identifier->ocspResponderID.choice.byKey, &sba_keyid));
        DO(json_object_set_hex(joResult, "responderId", sba_keyid.get()));
        break;
    default:
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }
    //  =producedAt=
    DO(Util::genTimeFromAsn1(&ocsp_identifier->producedAt, ms_producedat));
    DO_JSON(json_object_set_string(joResult, "producedAt", TimeUtil::mtimeToFtime(ms_producedat).c_str()));

cleanup:
    asn_free(get_OcspIdentifier_desc(), ocsp_identifier);
    return ret;
}

int signatureInfoToJson (
        JSON_Object* joResult,
        const CerItem* cerItem
)
{
    if (!joResult || !cerItem) return RET_UAPKI_GENERAL_ERROR;

    int ret = RET_OK;
    const Certificate_t& cert = *cerItem->getCert();
    UapkiNS::AlgorithmIdentifier aid_sign;
    SmartBA sba_signvalue;

    DO(Util::algorithmIdentifierFromAsn1(cert.signatureAlgorithm, aid_sign));
    if (DstuNS::isDstu4145family(aid_sign.algorithm)) {
        DO(Util::bitStringEncapOctetFromAsn1(&cert.signature, &sba_signvalue));
    }
    else {
        DO(asn_BITSTRING2ba(&cert.signature, &sba_signvalue));
    }

    DO_JSON(json_object_set_string(joResult, "algorithm", aid_sign.algorithm.c_str()));
    if (aid_sign.baParameters) {
        DO(json_object_set_base64(joResult, "parameters", aid_sign.baParameters));
    }
    DO(json_object_set_base64(joResult, "signature", sba_signvalue.get()));

cleanup:
    return ret;
}

int spkiToJson (
        JSON_Object* joResult,
        const CerItem* cerItem,
        const bool encoded
)
{
    if (!joResult || !cerItem) return RET_UAPKI_GENERAL_ERROR;

    int ret = RET_OK;
    const SubjectPublicKeyInfo_t& spki = cerItem->getCert()->tbsCertificate.subjectPublicKeyInfo;
    UapkiNS::AlgorithmIdentifier aid_key;
    SmartBA sba_publickey;

    DO(Util::algorithmIdentifierFromAsn1(spki.algorithm, aid_key));
    if (DstuNS::isDstu4145family(aid_key.algorithm)) {
        DO(Util::bitStringEncapOctetFromAsn1(&spki.subjectPublicKey, &sba_publickey));
    }
    else {
        DO(asn_BITSTRING2ba(&spki.subjectPublicKey, &sba_publickey));
    }

    if (encoded) {
        DO(json_object_set_base64(joResult, "bytes", cerItem->getSpki()));
    }
    DO_JSON(json_object_set_string(joResult, "algorithm", aid_key.algorithm.c_str()));
    if (aid_key.baParameters) {
        DO(json_object_set_base64(joResult, "parameters", aid_key.baParameters));
    }
    DO(json_object_set_base64(joResult, "publicKey", sba_publickey.get()));

cleanup:
    return ret;
}

int validityToJson (
        JSON_Object* joResult,
        const CerItem* cerItem
)
{
    if (!joResult || !cerItem) return RET_UAPKI_GENERAL_ERROR;

    int ret = RET_OK;
    string s_time;

    s_time = TimeUtil::mtimeToFtime(cerItem->getNotBefore());
    DO_JSON(json_object_dotset_string(joResult, "validity.notBefore", s_time.c_str()));

    s_time = TimeUtil::mtimeToFtime(cerItem->getNotAfter());
    DO_JSON(json_object_dotset_string(joResult, "validity.notAfter", s_time.c_str()));

cleanup:
    return ret;
}


}   //  end namespace Cert


namespace Crl {


int crlIdentifierToJson (
        JSON_Object* joResult,
        const ByteArray* baEncoded
)
{
    int ret = RET_OK;
    CrlIdentifier_t* crl_identifier = nullptr;
    uint64_t ms_issuedtime = 0;

    CHECK_NOT_NULL(crl_identifier = (CrlIdentifier_t*)asn_decode_ba_with_alloc(get_CrlIdentifier_desc(), baEncoded));

    //  =crlIssuer=
    DO_JSON(json_object_set_value(joResult, "crlIssuer", json_value_init_object()));
    DO(nameToJson(json_object_get_object(joResult, "crlIssuer"), crl_identifier->crlissuer));
    //  =crlIssuedTime=
    DO(Util::utcTimeFromAsn1(&crl_identifier->crlIssuedTime, ms_issuedtime));
    DO_JSON(json_object_set_string(joResult, "crlIssuedTime", TimeUtil::mtimeToFtime(ms_issuedtime).c_str()));
    //  =crlNumber= (optional)
    if (crl_identifier->crlNumber) {
        SmartBA sba_number;
        DO(asn_INTEGER2ba(crl_identifier->crlNumber, &sba_number));
        DO(json_object_set_hex(joResult, "crlNumber", sba_number.get()));
    }

cleanup:
    asn_free(get_CrlIdentifier_desc(), crl_identifier);
    return ret;
}

int infoToJson (
        JSON_Object* joResult,
        const CrlItem* crlItem
)
{
    int ret = RET_OK;
    uint32_t cnt_revcerts = 0;
    string s_time;

    if (!joResult || !crlItem) return RET_UAPKI_GENERAL_ERROR;

    DO_JSON(json_object_set_value(joResult, "issuer", json_value_init_object()));
    DO(nameToJson(json_object_get_object(joResult, "issuer"), crlItem->getTbsCrl()->issuer));

    s_time = TimeUtil::mtimeToFtime(crlItem->getThisUpdate());
    DO_JSON(json_object_set_string(joResult, "thisUpdate", s_time.c_str()));

    s_time = TimeUtil::mtimeToFtime(crlItem->getNextUpdate());
    DO_JSON(json_object_set_string(joResult, "nextUpdate", s_time.c_str()));

    DO_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "countRevokedCerts", (uint32_t)crlItem->getCountRevokedCerts()));

    if (crlItem->getAuthorityKeyId()) {
        DO(json_object_set_hex(joResult, "authorityKeyId", crlItem->getAuthorityKeyId()));
    }

    DO(json_object_set_hex(joResult, "crlNumber", crlItem->getCrlNumber()));

    if (crlItem->getDeltaCrl()) {
        DO(json_object_set_hex(joResult, "deltaCrlIndicator", crlItem->getDeltaCrl()));
    }

    if (!crlItem->getUris().fullCrl.empty()) {
        DO_JSON(json_object_set_value(joResult, "distributionPoints", json_value_init_array()));
        JSON_Array* ja_distribpoints = json_object_get_array(joResult, "distributionPoints");
        for (const auto& it : crlItem->getUris().fullCrl) {
            DO_JSON(json_array_append_string(ja_distribpoints, it.c_str()));
        }
    }

    if (!crlItem->getUris().deltaCrl.empty()) {
        DO_JSON(json_object_set_value(joResult, "freshestCRL", json_value_init_array()));
        JSON_Array* ja_distribpoints = json_object_get_array(joResult, "freshestCRL");
        for (const auto& it : crlItem->getUris().deltaCrl) {
            DO_JSON(json_array_append_string(ja_distribpoints, it.c_str()));
        }
    }

cleanup:
    return ret;
}

int revokedCertsToJson (
        JSON_Array* jaResult,
        const CrlItem* crlItem
)
{
    if (!jaResult || !crlItem) return RET_UAPKI_GENERAL_ERROR;

    const size_t cnt_revokedcerts = crlItem->getCountRevokedCerts();
    if (cnt_revokedcerts == 0) return RET_OK;

    int ret = RET_OK;
    DEBUG_OUTCON(printf("CrlStoreUtil::revokedCertsToJson() count: %zu\n", cnt_revokedcerts));
    for (size_t i = 0; i < cnt_revokedcerts; i++) {
        JSON_Object* jo_result = nullptr;
        SmartBA sba_certsn;
        uint64_t revocation_date, invalidity_date;
        UapkiNS::CrlReason crl_reason;
        string s_time;

        DO(crlItem->parsedRevokedCert(
            i,
            &sba_certsn,
            revocation_date,
            crl_reason,
            invalidity_date
        ));

        DO_JSON(json_array_append_value(jaResult, json_value_init_object()));
        jo_result = json_array_get_object(jaResult, i);

        DO(json_object_set_hex(jo_result, "userCertificate", sba_certsn.get()));

        s_time = TimeUtil::mtimeToFtime(revocation_date);
        DO_JSON(json_object_set_string(jo_result, "revocationDate", s_time.c_str()));
        if (crl_reason > UapkiNS::CrlReason::UNDEFINED) {
            DO_JSON(json_object_set_string(jo_result, "crlReason", crlReasonToStr(crl_reason)));
        }
        if (invalidity_date > 0) {
            s_time = TimeUtil::mtimeToFtime(invalidity_date);
            DO_JSON(json_object_set_string(jo_result, "invalidityDate", s_time.c_str()));
        }
    }

cleanup:
    return ret;
}


}   //  end namespace Crl

}   //  end namespace UapkiNS
