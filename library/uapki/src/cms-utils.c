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

#include "cms-utils.h"
#include "asn1-ba-utils.h"
#include "attribute-utils.h"
#include "macros-internal.h"
#include "oid-utils.h"
#include <time.h>


static int sdata_certificate_set (SignedData_t* sdata, const ByteArray* baCert)
{
    int ret = RET_OK;
    OCTET_STRING_t* os_set = NULL;
    ByteArray* ba_encoded = NULL;

    ASN_ALLOC(os_set);
    DO(asn_ba2OCTSTRING(baCert, os_set));
    DO(asn_encode_ba(get_OCTET_STRING_desc(), os_set, &ba_encoded));
    DO(ba_set_byte(ba_encoded, 0, 0x31));
    CHECK_NOT_NULL(sdata->certificates = asn_decode_ba_with_alloc(get_CertificateSet_desc(), ba_encoded));

cleanup:
    asn_free(get_OCTET_STRING_desc(), os_set);
    ba_free(ba_encoded);
    return ret;
}

int create_std_signed_attrs (const char* contentType, const ByteArray* baMessageDigest, const uint64_t signingTime,
        Attributes_t** signedAttrs)
{
    int ret = RET_OK;
    Attributes_t* sattrs = NULL;
    ByteArray* ba_encoded = NULL;

    CHECK_PARAM(contentType != NULL);
    CHECK_PARAM(baMessageDigest != NULL);
    CHECK_PARAM(signedAttrs != NULL);

    ASN_ALLOC(sattrs);

    //  Set contentType
    DO(ba_encode_oid(OID_PKCS7_DATA, &ba_encoded));
    DO(attrs_add_attribute(sattrs, OID_PKCS9_CONTENT_TYPE, ba_encoded));
    ba_free(ba_encoded);
    ba_encoded = NULL;

    //  Set messageDigest
    DO(ba_encode_octetstring(baMessageDigest, &ba_encoded));
    DO(attrs_add_attribute(sattrs, OID_PKCS9_MESSAGE_DIGEST, ba_encoded));
    ba_free(ba_encoded);
    ba_encoded = NULL;

    //  Set signingTime
    if (signingTime > 0) {
        DO(ba_encode_pkixtime(PKIXTime_PR_NOTHING, signingTime, &ba_encoded));
        DO(attrs_add_attribute(sattrs, OID_PKCS9_SIGNING_TIME, ba_encoded));
    }

    *signedAttrs = sattrs;
    sattrs = NULL;

cleanup:
    asn_free(get_Attributes_desc(), sattrs);
    ba_free(ba_encoded);
    return ret;
}

int create_signer_info (uint32_t version, const ByteArray* baSID, const char* digestAlgo, const ByteArray* baSignedAttrs,
        const SignatureParams* signatureParams, const ByteArray* baUnsignedAttrs, SignerInfo_t** signerInfo)
{
    int ret = RET_OK;
    SignerInfo_t* sinfo = NULL;

    CHECK_PARAM(baSID != NULL);
    CHECK_PARAM(digestAlgo != NULL);
    CHECK_PARAM(baSignedAttrs != NULL);
    CHECK_PARAM(signatureParams != NULL);
    CHECK_PARAM(signatureParams->algo != NULL);
    CHECK_PARAM(signatureParams->value != NULL);
    CHECK_PARAM(signerInfo != NULL);

    ASN_ALLOC(sinfo);

    //  Set version
    DO(asn_ulong2INTEGER(&sinfo->version, (unsigned long)version));

    //  Set sid
    DO(asn_decode_ba(get_SignerIdentifier_desc(), &sinfo->sid, baSID));

    //  Set digestAlgorithm
    DO(asn_set_oid_from_text(digestAlgo, &sinfo->digestAlgorithm.algorithm));

    //  Set signedAttrs
    CHECK_NOT_NULL(sinfo->signedAttrs = asn_decode_ba_with_alloc(get_SignedAttributes_desc(), baSignedAttrs));

    //  Set signatureAlgorithm
    DO(asn_set_oid_from_text(signatureParams->algo, &sinfo->signatureAlgorithm.algorithm));
    if (signatureParams->algoParams != NULL) {
        CHECK_NOT_NULL(sinfo->signatureAlgorithm.parameters = asn_decode_ba_with_alloc(get_ANY_desc(), signatureParams->algoParams));
    }

    //  Set signature
    DO(asn_ba2OCTSTRING(signatureParams->value, &sinfo->signature));

    //  Set unsignedAttrs
    if (baUnsignedAttrs) {
        CHECK_NOT_NULL(sinfo->unsignedAttrs = asn_decode_ba_with_alloc(get_UnsignedAttributes_desc(), baUnsignedAttrs));
    }

    *signerInfo = sinfo;
    sinfo = NULL;

cleanup:
    asn_free(get_SignerInfo_desc(), sinfo);
    return ret;
}

int create_signed_data (uint32_t version, const ByteArray* baContent, const ByteArray* baCert, const SignerInfo_t* signerInfo,
        SignedData_t** signedData)
{
    int ret = RET_OK;
    SignedData_t* sdata = NULL;
    DigestAlgorithmIdentifier_t* dgst_algo = NULL;
    EncapsulatedContentInfo_t* encap_cinfo = NULL;
    char* s_dgstalgo = NULL;

    CHECK_PARAM(signedData != NULL);

    ASN_ALLOC(sdata);

    //  Set version
    DO(asn_ulong2INTEGER(&sdata->version, version));

    //  Set digestAlgorithms - one from signerInfo
    if (signerInfo) {
        DO(asn_oid_to_text(&signerInfo->digestAlgorithm.algorithm, &s_dgstalgo));

        ASN_ALLOC(dgst_algo);
        DO(asn_set_oid_from_text(s_dgstalgo, &dgst_algo->algorithm));
        DO(ASN_SET_ADD(&sdata->digestAlgorithms.list, dgst_algo));
        dgst_algo = NULL;
    }

    //  Set encapsulatedContentInfo
    ASN_ALLOC(encap_cinfo);
    DO(asn_set_oid_from_text(OID_PKCS7_DATA, &encap_cinfo->eContentType));
    if (baContent) {
        ASN_ALLOC(encap_cinfo->eContent);
        DO(asn_ba2OCTSTRING(baContent, encap_cinfo->eContent));
    }
    DO(asn_copy(get_EncapsulatedContentInfo_desc(), encap_cinfo, &sdata->encapContentInfo));

    //  Set certificates
    if (baCert) {
        DO(sdata_certificate_set(sdata, baCert));
    }

    //  Set signerInfos
    if (signerInfo) {
        DO(ASN_SET_ADD(&sdata->signerInfos.list, (SignerInfo_t*)signerInfo));
    }

    *signedData = sdata;
    sdata = NULL;

cleanup:
    asn_free(get_SignedData_desc(), sdata);
    asn_free(get_DigestAlgorithmIdentifier_desc(), dgst_algo);
    asn_free(get_EncapsulatedContentInfo_desc(), encap_cinfo);
    return ret;
}

int encode_signed_data (const SignedData_t* sdata, ByteArray** baEncoded)
{
    int ret = RET_OK;
    ContentInfo_t* cinfo = NULL;

    CHECK_PARAM(sdata != NULL);
    CHECK_PARAM(baEncoded != NULL);

    ASN_ALLOC(cinfo);
    DO(asn_set_oid_from_text(OID_PKCS7_SIGNED_DATA, &cinfo->contentType));
    DO(asn_set_any(get_SignedData_desc(), (void *)sdata, &cinfo->content));
    DO(asn_encode_ba(get_ContentInfo_desc(), cinfo, baEncoded));

cleanup:
    asn_free(get_ContentInfo_desc(), cinfo);
    return ret;
}

static int create_ess_certid_v2 (const HashAlg hashAlgo, const ByteArray* baCert, ESSCertIDv2_t** essCertId)
{
    int ret = RET_OK;
    Certificate_t* cert = NULL;
    GeneralName_t* general_name = NULL;
    GeneralNames_t* general_names = NULL;
    IssuerSerial_t* issuer_serial = NULL;
    ESSCertIDv2_t* ess_certid = NULL;
    ByteArray* ba_hash = NULL;

    CHECK_NOT_NULL(cert = asn_decode_ba_with_alloc(get_Certificate_desc(), baCert));
    CHECK_NOT_NULL(essCertId);

    ASN_ALLOC(general_name);
    general_name->present = GeneralName_PR_directoryName;
    DO(asn_copy(get_Name_desc(), &cert->tbsCertificate.issuer, &general_name->choice.directoryName));

    ASN_ALLOC(general_names);
    DO(ASN_SET_ADD(&general_names->list, (void *)general_name));
    general_name = NULL;

    ASN_ALLOC(issuer_serial);
    DO(asn_copy(get_GeneralNames_desc(), general_names, &issuer_serial->issuer));
    DO(asn_copy(get_CertificateSerialNumber_desc(), &cert->tbsCertificate.serialNumber, &issuer_serial->serialNumber));

    DO(hash(hashAlgo, baCert, &ba_hash));

    ASN_ALLOC(ess_certid);
    if (hashAlgo != HASH_ALG_SHA256) {
        ASN_ALLOC(ess_certid->hashAlgorithm);
        DO(asn_set_oid_from_text(hash_to_oid(hashAlgo), &ess_certid->hashAlgorithm->algorithm));
    }
    DO(asn_ba2OCTSTRING(ba_hash, &ess_certid->certHash));
    CHECK_NOT_NULL(ess_certid->issuerSerial = asn_copy_with_alloc(get_IssuerSerial_desc(), issuer_serial));
    
    *essCertId = ess_certid;
    ess_certid = NULL;

cleanup:
    asn_free(get_Certificate_desc(), cert);
    asn_free(get_GeneralName_desc(), general_name);
    asn_free(get_GeneralNames_desc(), general_names);
    asn_free(get_IssuerSerial_desc(), issuer_serial);
    asn_free(get_ESSCertIDv2_desc(), ess_certid);
    ba_free(ba_hash);
    return ret;
}

int gen_attrvalue_ess_certid_v2 (const HashAlg hashAlgo, const ByteArray* baCert, ByteArray** baEncoded)
{
    int ret = RET_OK;
    ESSCertIDv2_t* ess_certid = NULL;
    SigningCertificateV2_t* signing_cert_v2 = NULL;

    CHECK_PARAM(baCert != NULL);
    CHECK_PARAM(baEncoded != NULL);

    DO(create_ess_certid_v2(hashAlgo, baCert, &ess_certid));

    ASN_ALLOC(signing_cert_v2);
    DO(ASN_SEQUENCE_ADD(&signing_cert_v2->certs.list, (ESSCertIDv2_t*)ess_certid));
    ess_certid = NULL;

    DO(asn_encode_ba(get_SigningCertificateV2_desc(), signing_cert_v2, baEncoded));

cleanup:
    asn_free(get_ESSCertIDv2_desc(), ess_certid);
    asn_free(get_SigningCertificateV2_desc(), signing_cert_v2);
    return ret;
}

int keyid_to_sid_subjectkeyid (const ByteArray* baKeyId, ByteArray** baSubjectKeyId)
{
    int ret = RET_OK;
    //  Note:   SignerIdentifierIm_t - is SignerIdentifier IMPLICIT (use tag 0x80),
    //          SignerIdentifierEx_t - is SignerIdentifier EXPLICIT (use tag 0xA0),
    //          Here we need use implicit case SignerIdentifier
    SignerIdentifierIm_t* sid_im = NULL;

    CHECK_PARAM(baKeyId != NULL);
    CHECK_PARAM(baSubjectKeyId != NULL);

    ASN_ALLOC(sid_im);
    sid_im->present = SignerIdentifierIm_PR_subjectKeyIdentifier;
    DO(asn_ba2OCTSTRING(baKeyId, &sid_im->choice.subjectKeyIdentifier));

    DO(asn_encode_ba(get_SignerIdentifierIm_desc(), sid_im, baSubjectKeyId));

cleanup:
    asn_free(get_SignerIdentifierIm_desc(), sid_im);
    return ret;
}
