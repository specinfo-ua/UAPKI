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

#include "api-json-internal.h"
#include "asn1-ba-utils.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include "uapkif.h"

#undef FILE_MARKER
#define FILE_MARKER "api/key-get-csr.c"


static int encode_csr_info (const ByteArray* baAidKey, const ByteArray* baPubkey,
        const ByteArray* baSubject, const ByteArray* baAttributes, ByteArray** baCsrInfo)
{
    int ret = RET_OK;
    const ByteArray* ref_ba;
    INTEGER_t* version = NULL;
    Name_t* subject = NULL;
    RDNSequence_t* rdn_sequence = NULL;
    CertificationRequestInfo_t* csr_info = NULL;
    ByteArray* ba_pubkey = NULL;
    char* s_keyalgo = NULL;

    CHECK_PARAM(baAidKey != NULL);
    CHECK_PARAM(baPubkey != NULL);
    CHECK_PARAM(baCsrInfo != NULL);

    ASN_ALLOC_TYPE(csr_info, CertificationRequestInfo_t);
    ASN_ALLOC_TYPE(rdn_sequence, RDNSequence_t);

    // Set version
    DO(asn_create_integer_from_long(0, &version));
    DO(asn_copy(get_INTEGER_desc(), version, &csr_info->version));

    // Set subject
    csr_info->subject.present = Name_PR_rdnSequence;
    DO(asn_copy(get_RDNSequence_desc(), rdn_sequence, &csr_info->subject.choice.rdnSequence));
    //TODO: if present baSubject

    // Set subjectPKInfo
    DO(asn_decode_ba(get_AlgorithmIdentifier_desc(), &csr_info->subjectPKInfo.algorithm, baAidKey));
    DO(asn_oid_to_text(&csr_info->subjectPKInfo.algorithm.algorithm, &s_keyalgo));
    if (oid_is_parent(OID_DSTU4145_WITH_DSTU7564, s_keyalgo)
     || oid_is_parent(OID_DSTU4145_WITH_GOST3411, s_keyalgo)) {
        DO(ba_encode_octetstring(baPubkey, &ba_pubkey));
        ref_ba = ba_pubkey;
    }
    else {
        ref_ba = baPubkey;
    }

    DO(asn_ba2BITSTRING(ref_ba, &csr_info->subjectPKInfo.subjectPublicKey));

    //  Set attributes
    //TODO: if present baAttributes csr_info->attributes

    DO(asn_encode_ba(get_CertificationRequestInfo_desc(), csr_info, baCsrInfo));

cleanup:
    asn_free(get_CertificationRequestInfo_desc(), csr_info);
    asn_free(get_RDNSequence_desc(), rdn_sequence);
    asn_free(get_Name_desc(), subject);
    asn_free(get_INTEGER_desc(), version);
    ba_free(ba_pubkey);
    free(s_keyalgo);
    return ret;
}

static int encode_csr (const ByteArray* baCsrInfo, const char* signAlgo, const ByteArray* baSignAlgoParams,
        const ByteArray* baSignature, ByteArray** baCsr)
{
    int ret = RET_OK;
    const ByteArray* ref_ba;
    X509Tbs_t* x509_csr = NULL;
    ByteArray* ba_signvalue = NULL;

    CHECK_PARAM(baCsrInfo != NULL);
    CHECK_PARAM(signAlgo != NULL);
    CHECK_PARAM(baSignature != NULL);
    CHECK_PARAM(baCsr != NULL);

    ASN_ALLOC_TYPE(x509_csr, X509Tbs_t);

    //  Set certificationRequestInfo
    DO(asn_ba2OCTSTRING(baCsrInfo, (OCTET_STRING_t*)&x509_csr->tbsData));

    //  Set signatureAlgorithm
    DO(asn_set_oid_from_text(signAlgo, &x509_csr->signAlgo.algorithm));
    if (baSignAlgoParams) {
        CHECK_NOT_NULL(x509_csr->signAlgo.parameters = (ANY_t*)asn_decode_ba_with_alloc(get_ANY_desc(), baSignAlgoParams));
    }

    //  Set signature
    if (oid_is_parent(OID_DSTU4145_WITH_DSTU7564, signAlgo)
     || oid_is_parent(OID_DSTU4145_WITH_GOST3411, signAlgo)) {
        DO(ba_encode_octetstring(baSignature, &ba_signvalue));
        ref_ba = ba_signvalue;
    }
    else {
        ref_ba = baSignature;
    }
    DO(asn_ba2BITSTRING(ref_ba, &x509_csr->signValue));

    DO(asn_encode_ba(get_X509Tbs_desc(), x509_csr, baCsr));

cleanup:
    asn_free(get_X509Tbs_desc(), x509_csr);
    ba_free(ba_signvalue);
    return ret;
}

static int build_csr (const char* signAlgo, const ByteArray* baSignAlgoParams,
        const ByteArray* baSubject, const ByteArray* baAttributes, ByteArray** baCsr)
{
    int ret = RET_OK;
    CM_BYTEARRAY* cmba_pubkey = NULL;
    CM_BYTEARRAY* cmba_signature = NULL;
    ByteArray* ba_aidkey = NULL;
    ByteArray* ba_encoded = NULL;

    DO(CmProviders::keyGetPublickey((CM_BYTEARRAY**)&ba_aidkey, &cmba_pubkey));
    DO(encode_csr_info(ba_aidkey, (ByteArray*)cmba_pubkey, baSubject, baAttributes, &ba_encoded));
    DO(CmProviders::keySignData((const CM_UTF8_CHAR*)signAlgo, (const CM_BYTEARRAY*)baSignAlgoParams, (const CM_BYTEARRAY*)ba_encoded, &cmba_signature));
    DO(encode_csr(ba_encoded, signAlgo, baSignAlgoParams, (ByteArray*)cmba_signature, baCsr));

cleanup:
    CmProviders::baFree(cmba_pubkey);
    CmProviders::baFree(cmba_signature);
    ba_free(ba_aidkey);
    ba_free(ba_encoded);
    return ret;
}

static int get_default_signalgo (string& signAlgo)
{
    CM_JSON_PCHAR s_keyinfo = NULL;
    int ret = CmProviders::keyGetInfo(&s_keyinfo, nullptr);
    if (ret != RET_OK) return ret;

    ParsonHelper json;
    if (json.parse((const char*)s_keyinfo)) {
        JSON_Array* ja_signalgo = json.getArray("signAlgo");
        if (json_array_get_count(ja_signalgo) > 0) {
            signAlgo = ParsonHelper::jsonArrayGetString(ja_signalgo, 0);
        }
    }

    CmProviders::free(s_keyinfo);
    ret = (!signAlgo.empty()) ? RET_OK : RET_CM_INVALID_JSON;
    return ret;
}

int uapki_key_get_csr (JSON_Object* jo_parameters, JSON_Object* jo_result)
{
    int ret = RET_OK;
    CM_BYTEARRAY* cmba_csr = NULL;
    ByteArray* ba_csr = NULL;
    ByteArray* ba_subject = NULL;
    ByteArray* ba_attributes = NULL;
    ByteArray* ba_signalgoparams = NULL;
    string s_signalgo;

    if (jo_parameters) {
        s_signalgo = ParsonHelper::jsonObjectGetString(jo_parameters, "signAlgo");
        ba_signalgoparams = json_object_get_base64(jo_parameters, "signAlgoParams");
        ba_subject = json_object_get_base64(jo_parameters, "subject");
        ba_attributes = json_object_get_base64(jo_parameters, "attributes");
    }

    if (s_signalgo.empty()) {
        DO(get_default_signalgo(s_signalgo));
    }

    ret = CmProviders::keyGetCsr(
        (const CM_UTF8_CHAR*)s_signalgo.c_str(),
        (CM_BYTEARRAY*)ba_signalgoparams,
        (CM_BYTEARRAY*)ba_subject,
        (CM_BYTEARRAY*)ba_attributes,
        &cmba_csr
    );
    switch (ret) {
    case RET_OK:
        break;
    case RET_UAPKI_NOT_SUPPORTED:
        DO(build_csr(s_signalgo.c_str(), ba_signalgoparams, ba_subject, ba_attributes, &ba_csr));
        break;
    default:
        SET_ERROR(ret);
    }

    DO_JSON(json_object_set_base64(jo_result, "bytes", (cmba_csr != NULL) ? (ByteArray*)cmba_csr : ba_csr));

cleanup:
    CmProviders::baFree(cmba_csr);
    ba_free(ba_csr);
    ba_free(ba_subject);
    ba_free(ba_attributes);
    ba_free(ba_signalgoparams);
    return ret;
}
