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

#define FILE_MARKER "uapki/api/verify-csr.cpp"

#include "api-json-internal.h"
#include "dstu-ns.h"
#include "extension-helper.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include "uapkif.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"
#include "uapki-ns-verify.h"


using namespace std;
using namespace UapkiNS;


static const char* OID_EXTN_PKA = "1.3.6.1.4.1.54069.3.1.1.1";


static int parse_extn_extended_keyusage (const Extensions_t* extns, JSON_Object* joResult)
{
    int ret = RET_OK;
    ExtendedKeyUsage_t* ext_keyusage = nullptr;
    SmartBA sba_encoded;
    JSON_Array* ja_keypurposeids = nullptr;

    ret = Util::extnValueFromExtensions(extns, OID_X509v3_ExtendedKeyUsage, nullptr, &sba_encoded);
    if (ret == RET_OK) {
        CHECK_NOT_NULL(ext_keyusage = (ExtendedKeyUsage_t*)asn_decode_ba_with_alloc(get_ExtendedKeyUsage_desc(), sba_encoded.get()));

        DO_JSON(json_object_set_value(joResult, "extendedKeyUsage", json_value_init_array()));
        ja_keypurposeids = json_object_get_array(joResult, "extendedKeyUsage");

        for (int i = 0; i < ext_keyusage->list.count; i++) {
            const KeyPurposeId_t* key_purposeid = ext_keyusage->list.array[i];
            string s_purposeid;

            DO(Util::oidFromAsn1(key_purposeid, s_purposeid));
            DO_JSON(json_array_append_string(ja_keypurposeids, s_purposeid.c_str()));
        }
    }

cleanup:
    asn_free(get_ExtendedKeyUsage_desc(), ext_keyusage);
    return ret;
}

static int parse_extn_pka (const Extensions_t* extns, JSON_Object* joResult)
{
    int ret = RET_OK;
    SmartBA sba_extnvalue;

    ret = Util::extnValueFromExtensions(extns, OID_EXTN_PKA, nullptr, &sba_extnvalue);
    if (ret == RET_OK) {
        DO(json_object_set_base64(joResult, "pkaBytes", sba_extnvalue.get()));
    }

cleanup:
    return ret;
}

static int parse_attr_extensionrequest (const ByteArray* baEncoded, JSON_Object* joResult)
{
    int ret = RET_OK;
    Extensions_t* extns = nullptr;
    JSON_Array* ja_extns = nullptr;
    SmartBA sba_value;

    CHECK_NOT_NULL(extns = (Extensions_t*)asn_decode_ba_with_alloc(get_Extensions_desc(), baEncoded));

    DO_JSON(json_object_set_value(joResult, "extensions", json_value_init_array()));
    ja_extns = json_object_get_array(joResult, "extensions");
    for (int i = 0; i < extns->list.count; i++) {
        DO_JSON(json_array_append_value(ja_extns, json_value_init_object()));
        JSON_Object* jo_extn = json_array_get_object(ja_extns, i);
        const Extension_t* extn = extns->list.array[i];
        string s_extnid;

        DO(Util::oidFromAsn1(&extn->extnID, s_extnid));
        DO_JSON(json_object_set_string(jo_extn, "extnId", s_extnid.c_str()));

        if (extn->critical) {
            DO_JSON(ParsonHelper::jsonObjectSetBoolean(jo_extn, "critical", true));
        }

        DO(asn_OCTSTRING2ba(&extn->extnValue, &sba_value));
        DO(json_object_set_base64(jo_extn, "extnValue", sba_value.get()));
        sba_value.clear();
    }

    if (extns) {
        ret = ExtensionHelper::getSubjectKeyId(extns, &sba_value);
        if (ret == RET_OK) {
            DO(json_object_set_hex(joResult, "subjectKeyIdentifier", sba_value.get()));
        }
        ret = RET_OK; // ignore errors

        (void)parse_extn_extended_keyusage(extns, joResult); // ignore errors
        (void)parse_extn_pka(extns, joResult); // ignore errors
    }


cleanup:
    asn_free(get_Extensions_desc(), extns);
    return ret;
}

static int parse_attributes (const Attributes_t& attrs, JSON_Object* joResult)
{
    int ret = RET_OK;
    JSON_Array* ja_attrs = json_object_get_array(joResult, "attributes");

    for (int i = 0; i < attrs.list.count; i++) {
        DO_JSON(json_array_append_value(ja_attrs, json_value_init_object()));
        JSON_Object* jo_attr = json_array_get_object(ja_attrs, i);
        const Attribute_t* attr = attrs.list.array[i];
        string s_type;
        SmartBA sba_attrvalue;


        DO(Util::oidFromAsn1(&attr->type, s_type));
        DO_JSON(json_object_set_string(jo_attr, "type", s_type.c_str()));

        if (attr->value.list.count > 0) {
            sba_attrvalue.set(ba_alloc_from_uint8(attr->value.list.array[0]->buf, attr->value.list.array[0]->size));
            DO(json_object_set_base64(jo_attr, "bytes", sba_attrvalue.get()));
            if (oid_is_equal(s_type.c_str(), OID_PKCS9_EXTENSION_REQUEST)) {
                DO_JSON(json_object_set_value(joResult, "extensionRequest", json_value_init_object()));
                DO(parse_attr_extensionrequest(sba_attrvalue.get(), json_object_get_object(joResult, "extensionRequest")));
            }
        }
    }

cleanup:
    return ret;
}

static int parse_spki (const SubjectPublicKeyInfo_t* spki, ByteArray** baSpkiEncoded, JSON_Object* joResult)
{
    int ret = RET_OK;
    SmartBA sba_keyid, sba_keyparams, sba_publickey;
    JSON_Object* jo_spki = nullptr;
    HashAlg hash_algo = HASH_ALG_SHA1;
    bool is_dstu4145;
    string s_keyalgo;

    DO_JSON(json_object_set_value(joResult, "subjectPublicKeyInfo", json_value_init_object()));
    jo_spki = json_object_get_object(joResult, "subjectPublicKeyInfo");

    DO(Util::oidFromAsn1(&spki->algorithm.algorithm, s_keyalgo));
    DO_JSON(json_object_set_string(jo_spki, "algorithm", s_keyalgo.c_str()));

    if (spki->algorithm.parameters) {
        if (!sba_keyparams.set(ba_alloc_from_uint8(spki->algorithm.parameters->buf, spki->algorithm.parameters->size))) {
            SET_ERROR(RET_UAPKI_GENERAL_ERROR);
        }
        DO(json_object_set_base64(jo_spki, "parameters", sba_keyparams.get()));
    }

    is_dstu4145 = DstuNS::isDstu4145family(s_keyalgo);
    if (is_dstu4145) {
        DO(Util::bitStringEncapOctetFromAsn1(&spki->subjectPublicKey, &sba_publickey));
        hash_algo = HASH_ALG_GOST34311;
    }
    else {
        DO(asn_BITSTRING2ba(&spki->subjectPublicKey, &sba_publickey));
    }
    DO(json_object_set_base64(jo_spki, "publicKey", sba_publickey.get()));

    if (is_dstu4145) {
        sba_publickey.clear();
        DO(asn_BITSTRING2ba(&spki->subjectPublicKey, &sba_publickey));
    }
    DO(::hash(hash_algo, sba_publickey.get(), &sba_keyid));
    DO(json_object_set_hex(joResult, "keyId", sba_keyid.get()));

    if (is_dstu4145) {
        sba_keyid.clear();
        DO(::hash(HASH_ALG_DSTU7564_256, sba_publickey.get(), &sba_keyid));
        DO(json_object_set_hex(joResult, "keyId2", sba_keyid.get()));
    }

    DO(asn_encode_ba(get_SubjectPublicKeyInfo_desc(), spki, baSpkiEncoded));
    DO(json_object_set_base64(jo_spki, "bytes", *baSpkiEncoded));

cleanup:
    return ret;
}

static int parse_rdname (const Name_t& name, JSON_Object* joResult)
{
    int ret = RET_OK;

    if (name.present != Name_PR_rdnSequence) return RET_UAPKI_INVALID_STRUCT;

    for (int i = 0; i < name.choice.rdnSequence.list.count; i++) {
        const RelativeDistinguishedName_t* rdname_src = name.choice.rdnSequence.list.array[i];
        for (int j = 0; j < rdname_src->list.count; j++) {
            const AttributeTypeAndValue_t* attr = rdname_src->list.array[j];
            string s_oid, s_value;

            DO(Util::oidFromAsn1(&attr->type, s_oid));
            DO(Util::decodeAnyString(attr->value.buf, (const size_t)attr->value.size, s_value));
            DO_JSON(json_object_set_string(joResult, oid_to_rdname(s_oid.c_str()), s_value.c_str()));
        }
    }

cleanup:
    return ret;
}

static int parse_csr_info (const ByteArray* baEncoded, ByteArray** baSpkiEncoded, JSON_Object* joResult)
{
    int ret = RET_OK;
    CertificationRequestInfo_t* csr_info = nullptr;
    long version = 0;

    CHECK_NOT_NULL(csr_info = (CertificationRequestInfo_t*)asn_decode_ba_with_alloc(get_CertificationRequestInfo_desc(), baEncoded));

    DO(asn_INTEGER2long(&csr_info->version, &version));
    DO(ParsonHelper::jsonObjectSetInt32(joResult, "version", version));

    if (csr_info->subject.choice.rdnSequence.list.count > 0) {
        DO_JSON(json_object_set_value(joResult, "subject", json_value_init_object()));
        DO(parse_rdname(csr_info->subject, json_object_get_object(joResult, "subject")));
    }

    DO(parse_spki(&csr_info->subjectPKInfo, baSpkiEncoded, joResult));

    if (csr_info->attributes.list.count > 0) {
        DO_JSON(json_object_set_value(joResult, "attributes", json_value_init_array()));
        DO(parse_attributes(csr_info->attributes, joResult));
    }

cleanup:
    asn_free(get_CertificationRequestInfo_desc(), csr_info);
    return ret;
}

static int parse_csr (const ByteArray* baEncoded, ByteArray** baTbsEncoded, ByteArray** baSignValue, JSON_Object* joResult)
{
    int ret = RET_OK;
    X509Tbs_t* csr = nullptr;
    SmartBA sba_signparam, sba_signvalue, sba_tbs;
    JSON_Object* jo_signinfo = nullptr;
    string s_signalgo;

    DO_JSON(json_object_set_value(joResult, "signatureInfo", json_value_init_object()));
    jo_signinfo = json_object_get_object(joResult, "signatureInfo");

    CHECK_NOT_NULL(csr = (X509Tbs_t*)asn_decode_ba_with_alloc(get_X509Tbs_desc(), baEncoded));
    if (!sba_tbs.set(ba_alloc_from_uint8(csr->tbsData.buf, csr->tbsData.size))) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    DO(Util::oidFromAsn1(&csr->signAlgo.algorithm, s_signalgo));
    DO_JSON(json_object_set_string(jo_signinfo, "algorithm", s_signalgo.c_str()));

    if (csr->signAlgo.parameters) {
        if (!sba_signparam.set(ba_alloc_from_uint8(csr->signAlgo.parameters->buf, csr->signAlgo.parameters->size))) {
            SET_ERROR(RET_UAPKI_GENERAL_ERROR);
        }
        DO(json_object_set_base64(jo_signinfo, "parameters", sba_signparam.get()));
    }

    if (DstuNS::isDstu4145family(s_signalgo)) {
        DO(Util::bitStringEncapOctetFromAsn1(&csr->signValue, &sba_signvalue));
    }
    else {
        DO(asn_BITSTRING2ba(&csr->signValue, &sba_signvalue));
    }
    DO(json_object_set_base64(jo_signinfo, "signature", sba_signvalue.get()));

    *baTbsEncoded = sba_tbs.pop();
    *baSignValue = sba_signvalue.pop();

cleanup:
    asn_free(get_X509Tbs_desc(), csr);
    return ret;
}

int uapki_verify_csr (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    SmartBA sba_encoded, sba_signvalue, sba_spki, sba_tbs;
    const char* s_signalgo = nullptr;
    const char* s_statussign = "FAILED";

    if (!sba_encoded.set(json_object_get_base64(joParams, "bytes"))) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    DO(parse_csr(sba_encoded.get(), &sba_tbs, &sba_signvalue, joResult));
    DO(parse_csr_info(sba_tbs.get(), &sba_spki, joResult));

    s_signalgo = json_object_dotget_string(joResult, "signatureInfo.algorithm");
    ret = Verify::verifySignature(s_signalgo, sba_tbs.get(), false, sba_spki.get(), sba_signvalue.get());
    if (ret == RET_OK) s_statussign = "VALID";
    else if (ret == RET_VERIFY_FAILED) s_statussign = "INVALID";
    DO_JSON(json_object_set_string(joResult, "statusSignature", s_statussign));

cleanup:
    return ret;
}
