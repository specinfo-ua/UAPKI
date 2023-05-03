/*
 * Copyright (c) 2023, The UAPKI Project Authors.
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

#include "extension-helper-json.h"
#include "extension-helper.h"
#include "macros-internal.h"
#include "oid-utils.h"
#include "parson-ba-utils.h"
#include "parson-helper.h"
#include "uapkif.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"


using namespace std;


namespace UapkiNS {


static const char* KEY_USAGE_NAMES[9] = {   //  KeyUsage ::= BIT STRING -- rfc5280, $4.2.1.3
    "digitalSignature",  // (0),
    "contentCommitment", // (1), -- old name: "nonRepudiation" - recent editions of X.509 have renamed this bit to contentCommitment 
    "keyEncipherment",   // (2),
    "dataEncipherment",  // (3),
    "keyAgreement",      // (4),
    "keyCertSign",       // (5),
    "crlSign",           // (6),
    "encipherOnly",      // (7),
    "decipherOnly"       // (8)
};


int ExtensionHelper::DecodeToJsonObject::accessDescriptions (const ByteArray* baEncoded, JSON_Object* joResult)
{
    int ret = RET_OK;
    SubjectInfoAccess_t* subject_infoaccess = nullptr;
    ByteArray* ba_accesslocation = nullptr;
    JSON_Array* ja_accessdescrs = nullptr;
    char* s_accessmethod = nullptr;
    char* s_uri = nullptr;

    CHECK_NOT_NULL(subject_infoaccess = (SubjectInfoAccess_t*)asn_decode_ba_with_alloc(get_SubjectInfoAccess_desc(), baEncoded));

    DO_JSON(json_object_set_value(joResult, "accessDescriptions", json_value_init_array()));
    ja_accessdescrs = json_object_get_array(joResult, "accessDescriptions");

    for (int i = 0; i < subject_infoaccess->list.count; i++) {
        DO_JSON(json_array_append_value(ja_accessdescrs, json_value_init_object()));
        JSON_Object* jo_accessdescr = json_array_get_object(ja_accessdescrs, i);
        const AccessDescription_t* access_descr = subject_infoaccess->list.array[i];

        DO(asn_oid_to_text(&access_descr->accessMethod, &s_accessmethod));

        if (oid_is_equal(s_accessmethod, OID_PKIX_OCSP)
            && (access_descr->accessLocation.present == GeneralName_PR_uniformResourceIdentifier)) {
            DO(UapkiNS::Util::pbufToStr(access_descr->accessLocation.choice.uniformResourceIdentifier.buf,
                    access_descr->accessLocation.choice.uniformResourceIdentifier.size, &s_uri));
            DO(json_object_set_string(jo_accessdescr, "ocsp", s_uri));
        }
        else if (oid_is_equal(s_accessmethod, OID_PKIX_CaIssuers)
            && (access_descr->accessLocation.present == GeneralName_PR_uniformResourceIdentifier)) {
            DO(UapkiNS::Util::pbufToStr(access_descr->accessLocation.choice.uniformResourceIdentifier.buf,
                access_descr->accessLocation.choice.uniformResourceIdentifier.size, &s_uri));
            DO(json_object_set_string(jo_accessdescr, "caIssuers", s_uri));
        }
        else if (oid_is_equal(s_accessmethod, OID_PKIX_TimeStamping)
            && (access_descr->accessLocation.present == GeneralName_PR_uniformResourceIdentifier)) {
            DO(UapkiNS::Util::pbufToStr(access_descr->accessLocation.choice.uniformResourceIdentifier.buf,
                access_descr->accessLocation.choice.uniformResourceIdentifier.size, &s_uri));
            DO(json_object_set_string(jo_accessdescr, "timeStamping", s_uri));
        }
        else {
            DO(asn_encode_ba(get_GeneralName_desc(), &access_descr->accessLocation, &ba_accesslocation));
            DO_JSON(json_object_set_string(jo_accessdescr, "accessMethod", s_accessmethod));
            DO(json_object_set_base64(jo_accessdescr, "accessLocation", ba_accesslocation));
        }

        ::free(s_accessmethod);
        s_accessmethod = nullptr;
        ::free(s_uri);
        s_uri = nullptr;
        ba_free(ba_accesslocation);
        ba_accesslocation = nullptr;
    }

cleanup:
    asn_free(get_SubjectInfoAccess_desc(), subject_infoaccess);
    ba_free(ba_accesslocation);
    ::free(s_accessmethod);
    ::free(s_uri);
    return ret;
}

static int decode_other_name_to_json (const OtherName_t* otherName, JSON_Object* joResult)
{
    int ret = RET_OK;
    ByteArray* ba_value = nullptr;
    char* s_typeid = nullptr;

    DO(asn_oid_to_text(&otherName->type_id, &s_typeid));
    DO_JSON(json_object_set_string(joResult, "typeId", s_typeid));

    CHECK_NOT_NULL(ba_value = ba_alloc_from_uint8(otherName->value.buf, otherName->value.size));
    DO(json_object_set_base64(joResult, "value", ba_value));

cleanup:
    ba_free(ba_value);
    ::free(s_typeid);
    return ret;
}

static int decode_general_name_to_json (const GeneralName_t* generalName, JSON_Object* joResult)
{
    int ret = RET_OK;
    ByteArray* ba_value = nullptr;
    char* s_value = nullptr;
    string s_name;

    switch (generalName->present) {
    case GeneralName_PR_otherName:
        DO_JSON(json_object_set_value(joResult, "otherName", json_value_init_object()));
        DO(decode_other_name_to_json(&generalName->choice.otherName, json_object_get_object(joResult, "otherName")));
        break;
    case GeneralName_PR_rfc822Name:
        DO(UapkiNS::Util::pbufToStr(generalName->choice.rfc822Name.buf, generalName->choice.rfc822Name.size, &s_value));
        DO_JSON(json_object_set_string(joResult, "email", s_value));
        break;
    case GeneralName_PR_dNSName:
        DO(UapkiNS::Util::pbufToStr(generalName->choice.dNSName.buf, generalName->choice.dNSName.size, &s_value));
        DO_JSON(json_object_set_string(joResult, "dns", s_value));
        break;
    case GeneralName_PR_uniformResourceIdentifier:
        DO(UapkiNS::Util::pbufToStr(generalName->choice.uniformResourceIdentifier.buf, generalName->choice.uniformResourceIdentifier.size, &s_value));
        DO_JSON(json_object_set_string(joResult, "uri", s_value));
        break;
    default:
        // GeneralName_PR_x400Address, GeneralName_PR_directoryName, GeneralName_PR_ediPartyName, GeneralName_PR_iPAddress, GeneralName_PR_registeredID
        CHECK_NOT_NULL(ba_value = ba_alloc_from_uint8(generalName->choice.iPAddress.buf, generalName->choice.iPAddress.size));
        s_name = "[" + to_string((int)generalName->present - (int)GeneralName_PR_otherName) + "]";
        DO_JSON(json_object_set_base64(joResult, s_name.c_str(), ba_value));
        break;
    }

cleanup:
    ba_free(ba_value);
    ::free(s_value);
    return ret;
}

int ExtensionHelper::DecodeToJsonObject::alternativeName (const ByteArray* baEncoded, JSON_Object* joResult)
{
    int ret = RET_OK;
    //  typedef GeneralNames_t IssuerAltName_t;
    //  typedef GeneralNames_t SubjectAltName_t;
    GeneralNames_t* general_names = nullptr;
    JSON_Array* ja_generalnames = nullptr;

    CHECK_NOT_NULL(general_names = (GeneralNames_t*)asn_decode_ba_with_alloc(get_GeneralNames_desc(), baEncoded));

    DO_JSON(json_object_set_value(joResult, "generalNames", json_value_init_array()));
    ja_generalnames = json_object_get_array(joResult, "generalNames");

    for (int i = 0; i < general_names->list.count; i++) {
        DO_JSON(json_array_append_value(ja_generalnames, json_value_init_object()));
        DO(decode_general_name_to_json(general_names->list.array[i], json_array_get_object(ja_generalnames, i)));
    }

cleanup:
    asn_free(get_GeneralNames_desc(), general_names);
    return ret;
}

int ExtensionHelper::DecodeToJsonObject::authorityKeyId (const ByteArray* baEncoded, JSON_Object* joResult, ByteArray** baKeyId)
{
    int ret = RET_OK;
    AuthorityKeyIdentifier_t* authority_keyid = nullptr;
    ByteArray* ba_authoritycertsn = nullptr;

    CHECK_PARAM(baKeyId != nullptr);

    CHECK_NOT_NULL(authority_keyid = (AuthorityKeyIdentifier_t*)asn_decode_ba_with_alloc(get_AuthorityKeyIdentifier_desc(), baEncoded));
    if (authority_keyid->keyIdentifier) {
        DO(asn_OCTSTRING2ba(authority_keyid->keyIdentifier, baKeyId));
        DO(json_object_set_hex(joResult, "keyIdentifier", *baKeyId));
    }

    //TODO: need impl 'authorityCertIssuer'(OPTIONAL)

    if (authority_keyid->authorityCertSerialNumber) {//TODO: need check
        DO(asn_INTEGER2ba(authority_keyid->authorityCertSerialNumber, &ba_authoritycertsn));
        DO(json_object_set_hex(joResult, "authorityCertSerialNumber", ba_authoritycertsn));
    }

cleanup:
    asn_free(get_AuthorityKeyIdentifier_desc(), authority_keyid);
    ba_free(ba_authoritycertsn);
    return ret;
}

int ExtensionHelper::DecodeToJsonObject::basicConstraints (const ByteArray* baEncoded, JSON_Object* joResult)
{
    int ret = RET_OK;
    BasicConstraints_t* basic_constraints = nullptr;

    CHECK_NOT_NULL(basic_constraints = (BasicConstraints_t*)asn_decode_ba_with_alloc(get_BasicConstraints_desc(), baEncoded));

    if (basic_constraints->cA) {
        const bool cA = (basic_constraints->cA != 0);
        DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "cA", cA));
    }

    if (basic_constraints->pathLenConstraint) {
        long pathlen_constraint = 0;
        DO(asn_INTEGER2long(basic_constraints->pathLenConstraint, &pathlen_constraint));
        DO_JSON(ParsonHelper::jsonObjectSetInt32(joResult, "pathLenConstraint", pathlen_constraint));
    }

cleanup:
    asn_free(get_BasicConstraints_desc(), basic_constraints);
    return ret;
}

int ExtensionHelper::DecodeToJsonObject::certificatePolicies (const ByteArray* baEncoded, JSON_Object* joResult)
{
    int ret = RET_OK;
    CertificatePolicies_t* cert_policies = nullptr;
    ByteArray* ba_encodedqualifier = nullptr;
    JSON_Array* ja_policyinfos = nullptr;
    JSON_Array* ja_policyquals = nullptr;
    char* s_policyid = nullptr;
    char* s_policyqualid = nullptr;
    char* s_qualifier = nullptr;

    CHECK_NOT_NULL(cert_policies = (CertificatePolicies_t*)asn_decode_ba_with_alloc(get_CertificatePolicies_desc(), baEncoded));

    DO_JSON(json_object_set_value(joResult, "certificatePolicies", json_value_init_array()));
    ja_policyinfos = json_object_get_array(joResult, "certificatePolicies");

    for (int i = 0; i < cert_policies->list.count; i++) {
        DO_JSON(json_array_append_value(ja_policyinfos, json_value_init_object()));
        JSON_Object* jo_policyinfo = json_array_get_object(ja_policyinfos, i);
        const PolicyInformation_t* policy_info = cert_policies->list.array[i];

        DO(asn_oid_to_text(&policy_info->policyIdentifier, &s_policyid));
        DO_JSON(json_object_set_string(jo_policyinfo, "policyIdentifier", s_policyid));
        ::free(s_policyid);
        s_policyid = nullptr;

        if (policy_info->policyQualifiers) {
            DO_JSON(json_object_set_value(jo_policyinfo, "policyQualifiers", json_value_init_array()));
            ja_policyquals = json_object_get_array(jo_policyinfo, "policyQualifiers");

            for (int j = 0; j < policy_info->policyQualifiers->list.count; j++) {
                DO_JSON(json_array_append_value(ja_policyquals, json_value_init_object()));
                JSON_Object* jo_pqinfo = json_array_get_object(ja_policyquals, j);
                const PolicyQualifierInfo_t* pq_info = policy_info->policyQualifiers->list.array[j];

                DO(asn_oid_to_text(&pq_info->policyQualifierId, &s_policyqualid));
                DO_JSON(json_object_set_string(jo_pqinfo, "policyQualifierId", s_policyqualid));

                CHECK_NOT_NULL(ba_encodedqualifier = ba_alloc_from_uint8(pq_info->qualifier.buf, pq_info->qualifier.size));
                DO(json_object_set_base64(jo_pqinfo, "qualifier", ba_encodedqualifier));
                if (oid_is_equal(s_policyqualid, OID_PKIX_PqiCps)) {
                    DO(UapkiNS::Util::decodeAnyString(ba_encodedqualifier, &s_qualifier));
                    DO_JSON(json_object_set_string(jo_pqinfo, "cps", s_qualifier));
                }
                else {
                    //TODO: OID_PKIX_PqiUnotice("1.3.6.1.5.5.7.2.2"), OID_PKIX_PqiTextNotice("1.3.6.1.5.5.7.2.3"), and ?
                }

                ::free(s_policyqualid);
                s_policyqualid = nullptr;
                ba_free(ba_encodedqualifier);
                ba_encodedqualifier = nullptr;
                ::free(s_qualifier);
                s_qualifier = nullptr;
            }
        }
    }

cleanup:
    asn_free(get_CertificatePolicies_desc(), cert_policies);
    ba_free(ba_encodedqualifier);
    ::free(s_policyid);
    ::free(s_policyqualid);
    ::free(s_qualifier);
    return ret;
}

int ExtensionHelper::DecodeToJsonObject::distributionPoints (const ByteArray* baEncoded, JSON_Object* joResult)
{
    int ret = RET_OK;
    vector<string> uris;
    JSON_Array* ja_distribpoints = nullptr;

    DO(decodeDistributionPoints(baEncoded, uris));

    DO_JSON(json_object_set_value(joResult, "distributionPoints", json_value_init_array()));
    ja_distribpoints = json_object_get_array(joResult, "distributionPoints");

    for (auto& it : uris) {
        DO_JSON(json_array_append_string(ja_distribpoints, it.c_str()));
    }

cleanup:
    return ret;
}

int ExtensionHelper::DecodeToJsonObject::extendedKeyUsage (const ByteArray* baEncoded, JSON_Object* joResult)
{
    int ret = RET_OK;
    ExtendedKeyUsage_t* ext_keyusage = nullptr;
    JSON_Array* ja_keypurposeids = nullptr;
    char* s_keypurposeid = nullptr;

    CHECK_NOT_NULL(ext_keyusage = (ExtendedKeyUsage_t*)asn_decode_ba_with_alloc(get_ExtendedKeyUsage_desc(), baEncoded));

    DO_JSON(json_object_set_value(joResult, "keyPurposeId", json_value_init_array()));
    ja_keypurposeids = json_object_get_array(joResult, "keyPurposeId");

    for (int i = 0; i < ext_keyusage->list.count; i++) {
        const KeyPurposeId_t* key_purposeid = ext_keyusage->list.array[i];
        DO(asn_oid_to_text(key_purposeid, &s_keypurposeid));
        DO_JSON(json_array_append_string(ja_keypurposeids, s_keypurposeid));
        ::free(s_keypurposeid);
        s_keypurposeid = nullptr;
    }

cleanup:
    asn_free(get_ExtendedKeyUsage_desc(), ext_keyusage);
    ::free(s_keypurposeid);
    return ret;
}

int ExtensionHelper::DecodeToJsonObject::keyUsage (const ByteArray* baEncoded, JSON_Object* joResult)
{
    int ret = RET_OK;
    KeyUsage_t* key_usage = nullptr;

    CHECK_NOT_NULL(key_usage = (KeyUsage_t*)asn_decode_ba_with_alloc(get_KeyUsage_desc(), baEncoded));

    if (key_usage->size > 0) {
        for (int bit_num = 0; bit_num < 9; bit_num++) {
            int bit_flag = 0;
            DO(asn_BITSTRING_get_bit(key_usage, bit_num, &bit_flag));
            if (bit_flag) {
                DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, KEY_USAGE_NAMES[bit_num], true));
            }
        }
    }

cleanup:
    asn_free(get_KeyUsage_desc(), key_usage);
    return ret;
}

int ExtensionHelper::DecodeToJsonObject::qcStatements (const ByteArray* baEncoded, JSON_Object* joResult)
{
    int ret = RET_OK;
    QCStatements_t* qc_statements = nullptr;
    ByteArray* ba_statementinfo = nullptr;
    JSON_Array* ja_qcstatements = nullptr;
    char* s_statementid = nullptr;

    CHECK_NOT_NULL(qc_statements = (QCStatements_t*)asn_decode_ba_with_alloc(get_QCStatements_desc(), baEncoded));

    DO_JSON(json_object_set_value(joResult, "qcStatements", json_value_init_array()));
    ja_qcstatements = json_object_get_array(joResult, "qcStatements");

    for (int i = 0; i < qc_statements->list.count; i++) {
        DO_JSON(json_array_append_value(ja_qcstatements, json_value_init_object()));
        JSON_Object* jo_qcstatement = json_array_get_object(ja_qcstatements, i);
        const QCStatement_t* qc_statement = qc_statements->list.array[i];

        DO(asn_oid_to_text(&qc_statement->statementId, &s_statementid));
        DO_JSON(json_object_set_string(jo_qcstatement, "statementId", s_statementid));
        if (qc_statement->statementInfo) {
            CHECK_NOT_NULL(ba_statementinfo = ba_alloc_from_uint8(qc_statement->statementInfo->buf, qc_statement->statementInfo->size));
            DO(json_object_set_base64(jo_qcstatement, "statementInfo", ba_statementinfo));
        }

        ::free(s_statementid);
        s_statementid = nullptr;
        ba_free(ba_statementinfo);
        ba_statementinfo = nullptr;
    }

cleanup:
    asn_free(get_QCStatements_desc(), qc_statements);
    ba_free(ba_statementinfo);
    ::free(s_statementid);
    return ret;
}

int ExtensionHelper::DecodeToJsonObject::subjectDirectoryAttributes (const ByteArray* baEncoded, JSON_Object* joResult)
{
    int ret = RET_OK;
    SubjectDirectoryAttributes_t* subject_dirattrs = nullptr;
    ByteArray* ba_encoded = nullptr;
    char* str = nullptr;

    CHECK_NOT_NULL(subject_dirattrs = (SubjectDirectoryAttributes_t*)asn_decode_ba_with_alloc(get_SubjectDirectoryAttributes_desc(), baEncoded));

    ret = UapkiNS::Util::attrValueFromAttributes((const Attributes_t*)subject_dirattrs, OID_PDS_UKRAINE_DRFO, &ba_encoded);
    if (ret == RET_OK) {
        DO(UapkiNS::Util::decodeAnyString(ba_encoded, &str));
        ba_free(ba_encoded);
        ba_encoded = nullptr;
        if (str != nullptr) {
            DO_JSON(json_object_dotset_string(joResult, "DRFO", str));
            ::free(str);
            str = nullptr;
        }
    }

    ret = UapkiNS::Util::attrValueFromAttributes((const Attributes_t*)subject_dirattrs, OID_PDS_UKRAINE_EDRPOU, &ba_encoded);
    if (ret == RET_OK) {
        DO(UapkiNS::Util::decodeAnyString(ba_encoded, &str));
        ba_free(ba_encoded);
        ba_encoded = nullptr;
        if (str != nullptr) {
            DO_JSON(json_object_dotset_string(joResult, "EDRPOU", str));
            ::free(str);
            str = nullptr;
        }
    }

    ret = UapkiNS::Util::attrValueFromAttributes((const Attributes_t*)subject_dirattrs, OID_PDS_UKRAINE_EDDR, &ba_encoded);
    if (ret == RET_OK) {
        DO(UapkiNS::Util::decodeAnyString(ba_encoded, &str));
        ba_free(ba_encoded);
        ba_encoded = nullptr;
        if (str != nullptr) {
            DO_JSON(json_object_dotset_string(joResult, "EDDR", str));
            ::free(str);
            str = nullptr;
        }
    }

    ret = RET_OK;

cleanup:
    asn_free(get_SubjectDirectoryAttributes_desc(), subject_dirattrs);
    ba_free(ba_encoded);
    return ret;
}

int ExtensionHelper::DecodeToJsonObject::subjectKeyId (const ByteArray* baEncoded, JSON_Object* joResult, ByteArray** baKeyId)
{
    int ret = RET_OK;
    SubjectKeyIdentifier_t* subject_keyid = nullptr;

    CHECK_PARAM(baKeyId != nullptr);

    CHECK_NOT_NULL(subject_keyid = (SubjectKeyIdentifier_t*)asn_decode_ba_with_alloc(get_SubjectKeyIdentifier_desc(), baEncoded));
    DO(asn_OCTSTRING2ba(subject_keyid, baKeyId));

    DO(json_object_set_hex(joResult, "keyIdentifier", *baKeyId));

cleanup:
    asn_free(get_SubjectKeyIdentifier_desc(), subject_keyid);
    return ret;
}


}   //  end namespace UapkiNS
