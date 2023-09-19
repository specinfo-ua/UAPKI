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

#define FILE_MARKER "common/pkix/extension-helper-json.cpp"

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



static int decode_other_name_to_json (
        const OtherName_t* otherName,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    string s_typeid;
    SmartBA sba_value;

    DO(Util::oidFromAsn1(&otherName->type_id, s_typeid));
    DO_JSON(json_object_set_string(joResult, "typeId", s_typeid.c_str()));

    if (!sba_value.set(ba_alloc_from_uint8(otherName->value.buf, otherName->value.size))) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }
    DO(json_object_set_base64(joResult, "value", sba_value.get()));

cleanup:
    return ret;
}   //  decode_other_name_to_json

static int decode_general_name_to_json (
        const GeneralName_t* generalName,
        JSON_Object* joResult
)
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
        DO(Util::pbufToStr(generalName->choice.rfc822Name.buf, generalName->choice.rfc822Name.size, &s_value));
        DO_JSON(json_object_set_string(joResult, "email", s_value));
        break;
    case GeneralName_PR_dNSName:
        DO(Util::pbufToStr(generalName->choice.dNSName.buf, generalName->choice.dNSName.size, &s_value));
        DO_JSON(json_object_set_string(joResult, "dns", s_value));
        break;
    case GeneralName_PR_uniformResourceIdentifier:
        DO(Util::pbufToStr(generalName->choice.uniformResourceIdentifier.buf, generalName->choice.uniformResourceIdentifier.size, &s_value));
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
}   //  decode_general_name_to_json

static const char* friendlyname_from_oid (
        const string& type
)
{
    const char* rv_s = nullptr;
    if (type == string(OID_PDS_UKRAINE_DRFO)) {
        rv_s = "PDS_UKRAINE_DRFO";
    }
    else if (type == string(OID_PDS_UKRAINE_EDRPOU)) {
        rv_s = "PDS_UKRAINE_EDRPOU";
    }
    else if (type == string(OID_PDS_UKRAINE_NBU)) {
        rv_s = "PDS_UKRAINE_NBU";
    }
    else if (type == string(OID_PDS_UKRAINE_SPMF)) {
        rv_s = "PDS_UKRAINE_SPMF";
    }
    else if (type == string(OID_PDS_UKRAINE_ORG)) {
        rv_s = "PDS_UKRAINE_ORG";
    }
    else if (type == string(OID_PDS_UKRAINE_UNIT)) {
        rv_s = "PDS_UKRAINE_UNIT";
    }
    else if (type == string(OID_PDS_UKRAINE_USER)) {
        rv_s = "PDS_UKRAINE_USER";
    }
    else if (type == string(OID_PDS_UKRAINE_EDDR)) {
        rv_s = "PDS_UKRAINE_EDDR";
    }
    return rv_s;
}   //  friendlyname_from_oid



int ExtensionHelper::DecodeToJsonObject::accessDescriptions (
        const ByteArray* baEncoded,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    SubjectInfoAccess_t* subject_infoaccess = nullptr;
    JSON_Array* ja_accessdescrs = nullptr;
    char* s_uri = nullptr;

    CHECK_NOT_NULL(subject_infoaccess = (SubjectInfoAccess_t*)asn_decode_ba_with_alloc(get_SubjectInfoAccess_desc(), baEncoded));

    DO_JSON(json_object_set_value(joResult, "accessDescriptions", json_value_init_array()));
    ja_accessdescrs = json_object_get_array(joResult, "accessDescriptions");

    for (int i = 0; i < subject_infoaccess->list.count; i++) {
        DO_JSON(json_array_append_value(ja_accessdescrs, json_value_init_object()));
        JSON_Object* jo_accessdescr = json_array_get_object(ja_accessdescrs, i);
        const AccessDescription_t* access_descr = subject_infoaccess->list.array[i];
        string s_accessmethod;

        DO(Util::oidFromAsn1(&access_descr->accessMethod, s_accessmethod));

        if (
            oid_is_equal(s_accessmethod.c_str(), OID_PKIX_OCSP) &&
            (access_descr->accessLocation.present == GeneralName_PR_uniformResourceIdentifier)
        ) {
            DO(Util::pbufToStr(access_descr->accessLocation.choice.uniformResourceIdentifier.buf,
                    access_descr->accessLocation.choice.uniformResourceIdentifier.size, &s_uri));
            DO(json_object_set_string(jo_accessdescr, "ocsp", s_uri));
        }
        else if (oid_is_equal(s_accessmethod.c_str(), OID_PKIX_CaIssuers)
            && (access_descr->accessLocation.present == GeneralName_PR_uniformResourceIdentifier)) {
            DO(Util::pbufToStr(access_descr->accessLocation.choice.uniformResourceIdentifier.buf,
                access_descr->accessLocation.choice.uniformResourceIdentifier.size, &s_uri));
            DO(json_object_set_string(jo_accessdescr, "caIssuers", s_uri));
        }
        else if (oid_is_equal(s_accessmethod.c_str(), OID_PKIX_TimeStamping)
            && (access_descr->accessLocation.present == GeneralName_PR_uniformResourceIdentifier)) {
            DO(Util::pbufToStr(access_descr->accessLocation.choice.uniformResourceIdentifier.buf,
                access_descr->accessLocation.choice.uniformResourceIdentifier.size, &s_uri));
            DO(json_object_set_string(jo_accessdescr, "timeStamping", s_uri));
        }
        else {
            SmartBA sba_accesslocation;
            DO(asn_encode_ba(get_GeneralName_desc(), &access_descr->accessLocation, &sba_accesslocation));
            DO_JSON(json_object_set_string(jo_accessdescr, "accessMethod", s_accessmethod.c_str()));
            DO(json_object_set_base64(jo_accessdescr, "accessLocation", sba_accesslocation.get()));
        }

        ::free(s_uri);
        s_uri = nullptr;
    }

cleanup:
    asn_free(get_SubjectInfoAccess_desc(), subject_infoaccess);
    ::free(s_uri);
    return ret;
}

int ExtensionHelper::DecodeToJsonObject::alternativeName (
        const ByteArray* baEncoded,
        JSON_Object* joResult
)
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

int ExtensionHelper::DecodeToJsonObject::authorityKeyId (
        const ByteArray* baEncoded,
        JSON_Object* joResult,
        ByteArray** baKeyId
)
{
    int ret = RET_OK;
    AuthorityKeyIdentifier_t* authority_keyid = nullptr;
    SmartBA sba_authoritycertsn;

    CHECK_PARAM(baKeyId != nullptr);

    CHECK_NOT_NULL(authority_keyid = (AuthorityKeyIdentifier_t*)asn_decode_ba_with_alloc(get_AuthorityKeyIdentifier_desc(), baEncoded));
    if (authority_keyid->keyIdentifier) {
        DO(asn_OCTSTRING2ba(authority_keyid->keyIdentifier, baKeyId));
        DO(json_object_set_hex(joResult, "keyIdentifier", *baKeyId));
    }

    //TODO: need impl 'authorityCertIssuer'(OPTIONAL)

    if (authority_keyid->authorityCertSerialNumber) {//TODO: need check
        DO(asn_INTEGER2ba(authority_keyid->authorityCertSerialNumber, &sba_authoritycertsn));
        DO(json_object_set_hex(joResult, "authorityCertSerialNumber", sba_authoritycertsn.get()));
    }

cleanup:
    asn_free(get_AuthorityKeyIdentifier_desc(), authority_keyid);
    return ret;
}

int ExtensionHelper::DecodeToJsonObject::basicConstraints (
        const ByteArray* baEncoded,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    BasicConstraints_t* basic_constraints = nullptr;

    CHECK_NOT_NULL(basic_constraints = (BasicConstraints_t*)asn_decode_ba_with_alloc(get_BasicConstraints_desc(), baEncoded));

    if (basic_constraints->cA) {
        const bool is_ca = (basic_constraints->cA != 0);
        DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "cA", is_ca));
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

int ExtensionHelper::DecodeToJsonObject::certificatePolicies (
        const ByteArray* baEncoded,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    CertificatePolicies_t* cert_policies = nullptr;
    JSON_Array* ja_policyinfos = nullptr;
    JSON_Array* ja_policyquals = nullptr;

    CHECK_NOT_NULL(cert_policies = (CertificatePolicies_t*)asn_decode_ba_with_alloc(get_CertificatePolicies_desc(), baEncoded));

    DO_JSON(json_object_set_value(joResult, "certificatePolicies", json_value_init_array()));
    ja_policyinfos = json_object_get_array(joResult, "certificatePolicies");

    for (int i = 0; i < cert_policies->list.count; i++) {
        DO_JSON(json_array_append_value(ja_policyinfos, json_value_init_object()));
        JSON_Object* jo_policyinfo = json_array_get_object(ja_policyinfos, i);
        const PolicyInformation_t* policy_info = cert_policies->list.array[i];
        string s_policyid, s_policyqualid, s_qualifier;
        SmartBA sba_encodedqualifier;

        DO(Util::oidFromAsn1(&policy_info->policyIdentifier, s_policyid));
        DO_JSON(json_object_set_string(jo_policyinfo, "policyIdentifier", s_policyid.c_str()));

        if (policy_info->policyQualifiers) {
            DO_JSON(json_object_set_value(jo_policyinfo, "policyQualifiers", json_value_init_array()));
            ja_policyquals = json_object_get_array(jo_policyinfo, "policyQualifiers");

            for (int j = 0; j < policy_info->policyQualifiers->list.count; j++) {
                DO_JSON(json_array_append_value(ja_policyquals, json_value_init_object()));
                JSON_Object* jo_pqinfo = json_array_get_object(ja_policyquals, j);
                const PolicyQualifierInfo_t* pq_info = policy_info->policyQualifiers->list.array[j];

                DO(Util::oidFromAsn1(&pq_info->policyQualifierId, s_policyqualid));
                DO_JSON(json_object_set_string(jo_pqinfo, "policyQualifierId", s_policyqualid.c_str()));

                if (!sba_encodedqualifier.set(ba_alloc_from_uint8(pq_info->qualifier.buf, pq_info->qualifier.size))) {
                    SET_ERROR(RET_UAPKI_GENERAL_ERROR);
                }

                DO(json_object_set_base64(jo_pqinfo, "qualifier", sba_encodedqualifier.get()));
                if (oid_is_equal(s_policyqualid.c_str(), OID_PKIX_PqiCps)) {
                    DO(Util::decodeAnyString(sba_encodedqualifier.get(), s_qualifier));
                    DO_JSON(json_object_set_string(jo_pqinfo, "cps", s_qualifier.c_str()));
                }
                else {
                    //TODO: OID_PKIX_PqiUnotice("1.3.6.1.5.5.7.2.2"), OID_PKIX_PqiTextNotice("1.3.6.1.5.5.7.2.3")
                }
            }
        }
    }

cleanup:
    asn_free(get_CertificatePolicies_desc(), cert_policies);
    return ret;
}

int ExtensionHelper::DecodeToJsonObject::distributionPoints (
        const ByteArray* baEncoded,
        JSON_Object* joResult
)
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

int ExtensionHelper::DecodeToJsonObject::extendedKeyUsage (
        const ByteArray* baEncoded,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    ExtendedKeyUsage_t* ext_keyusage = nullptr;
    JSON_Array* ja_keypurposeids = nullptr;

    CHECK_NOT_NULL(ext_keyusage = (ExtendedKeyUsage_t*)asn_decode_ba_with_alloc(get_ExtendedKeyUsage_desc(), baEncoded));

    DO_JSON(json_object_set_value(joResult, "keyPurposeId", json_value_init_array()));
    ja_keypurposeids = json_object_get_array(joResult, "keyPurposeId");

    for (int i = 0; i < ext_keyusage->list.count; i++) {
        const KeyPurposeId_t* key_purposeid = ext_keyusage->list.array[i];
        string s_keypurposeid;

        DO(Util::oidFromAsn1(key_purposeid, s_keypurposeid));
        DO_JSON(json_array_append_string(ja_keypurposeids, s_keypurposeid.c_str()));
    }

cleanup:
    asn_free(get_ExtendedKeyUsage_desc(), ext_keyusage);
    return ret;
}

int ExtensionHelper::DecodeToJsonObject::keyUsage (
        const ByteArray* baEncoded,
        JSON_Object* joResult
)
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

int ExtensionHelper::DecodeToJsonObject::qcStatements (
        const ByteArray* baEncoded,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    QCStatements_t* qc_statements = nullptr;
    JSON_Array* ja_qcstatements = nullptr;

    CHECK_NOT_NULL(qc_statements = (QCStatements_t*)asn_decode_ba_with_alloc(get_QCStatements_desc(), baEncoded));

    DO_JSON(json_object_set_value(joResult, "qcStatements", json_value_init_array()));
    ja_qcstatements = json_object_get_array(joResult, "qcStatements");

    for (int i = 0; i < qc_statements->list.count; i++) {
        DO_JSON(json_array_append_value(ja_qcstatements, json_value_init_object()));
        JSON_Object* jo_qcstatement = json_array_get_object(ja_qcstatements, i);
        const QCStatement_t* qc_statement = qc_statements->list.array[i];
        string s_statementid;
        SmartBA sba_statementinfo;

        DO(Util::oidFromAsn1(&qc_statement->statementId, s_statementid));
        DO_JSON(json_object_set_string(jo_qcstatement, "statementId", s_statementid.c_str()));
        if (qc_statement->statementInfo) {
            if (!sba_statementinfo.set(ba_alloc_from_uint8(qc_statement->statementInfo->buf, qc_statement->statementInfo->size))) {
                SET_ERROR(RET_UAPKI_GENERAL_ERROR);
            }
            DO(json_object_set_base64(jo_qcstatement, "statementInfo", sba_statementinfo.get()));
        }
    }

cleanup:
    asn_free(get_QCStatements_desc(), qc_statements);
    return ret;
}

int ExtensionHelper::DecodeToJsonObject::subjectDirectoryAttributes (
        const ByteArray* baEncoded,
        JSON_Object* joResult
)
{
    int ret = RET_OK;
    SubjectDirectoryAttributes_t* subject_dirattrs = nullptr;
    JSON_Array* ja_attrs = nullptr;

    CHECK_NOT_NULL(subject_dirattrs = (SubjectDirectoryAttributes_t*)asn_decode_ba_with_alloc(get_SubjectDirectoryAttributes_desc(), baEncoded));

    DO_JSON(json_object_set_value(joResult, "attributes", json_value_init_array()));
    ja_attrs = json_object_get_array(joResult, "attributes");

    for (int i = 0; i < subject_dirattrs->list.count; i++) {
        const Attribute_t* attr = subject_dirattrs->list.array[i];
        string s_type, s_value;
        SmartBA sba_encoded;
        const char* s_friendlyname = nullptr;

        DO_JSON(json_array_append_value(ja_attrs, json_value_init_object()));
        JSON_Object* jo_attr = json_array_get_object(ja_attrs, i);

        DO(Util::oidFromAsn1(&attr->type, s_type));
        DO_JSON(json_object_set_string(jo_attr, "type", s_type.c_str()));
        if (attr->value.list.count > 0) {
            const AttributeValue_t* attr_value = attr->value.list.array[0];
            if (!sba_encoded.set(ba_alloc_from_uint8(attr_value->buf, attr_value->size))) {
                SET_ERROR(RET_UAPKI_GENERAL_ERROR);
            }
            DO(json_object_set_base64(jo_attr, "bytes", sba_encoded.get()));
        }
        s_friendlyname = friendlyname_from_oid(s_type);
        if (s_friendlyname) {
            DO_JSON(json_object_set_string(jo_attr, "friendlyName", s_friendlyname));
        }

        if (s_type == string(OID_PDS_UKRAINE_DRFO)) {
            DO(Util::decodeAnyString(sba_encoded.get(), s_value));
            DO_JSON(json_object_set_string(jo_attr, "value", s_value.c_str()));
            DO_JSON(json_object_set_string(joResult, "DRFO", s_value.c_str()));
        }
        else if (s_type == string(OID_PDS_UKRAINE_EDRPOU)) {
            DO(Util::decodeAnyString(sba_encoded.get(), s_value));
            DO_JSON(json_object_set_string(jo_attr, "value", s_value.c_str()));
            DO_JSON(json_object_set_string(joResult, "EDRPOU", s_value.c_str()));
        }
        else if (s_type == string(OID_PDS_UKRAINE_EDDR)) {
            DO(Util::decodeAnyString(sba_encoded.get(), s_value));
            DO_JSON(json_object_set_string(jo_attr, "value", s_value.c_str()));
            DO_JSON(json_object_set_string(joResult, "EDDR", s_value.c_str()));
        }
        else if (
            (s_type == string(OID_PDS_UKRAINE_NBU)) ||
            (s_type == string(OID_PDS_UKRAINE_SPMF)) ||
            (s_type == string(OID_PDS_UKRAINE_ORG)) ||
            (s_type == string(OID_PDS_UKRAINE_UNIT)) ||
            (s_type == string(OID_PDS_UKRAINE_USER))
        ) {
            DO(Util::decodeAnyString(sba_encoded.get(), s_value));
            DO_JSON(json_object_set_string(jo_attr, "value", s_value.c_str()));
        }
    }

cleanup:
    asn_free(get_SubjectDirectoryAttributes_desc(), subject_dirattrs);
    return ret;
}

int ExtensionHelper::DecodeToJsonObject::subjectKeyId (
        const ByteArray* baEncoded,
        JSON_Object* joResult,
        ByteArray** baKeyId
)
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
