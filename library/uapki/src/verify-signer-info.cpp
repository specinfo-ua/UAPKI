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

#include "verify-signer-info.h"
#include "asn1-ba-utils.h"
#include "attribute-utils.h"
#include "global-objects.h"
#include "macros-internal.h"
#include "oid-utils.h"
#include "tsp-utils.h"
#include "uapki-errors.h"
#include "uapkic-errors.h"
#include "verify-utils.h"


AttrTimeStamp_ST::AttrTimeStamp_ST (void)
    : policy(nullptr), hashAlgo(nullptr), baHashedMessage(nullptr), msGenTime(0)
    , statusDigest(SIGNATURE_VERIFY::STATUS::UNDEFINED)
    , statusSign(SIGNATURE_VERIFY::STATUS::UNDEFINED)
{
}

AttrTimeStamp_ST::~AttrTimeStamp_ST (void)
{
    ::free((char*)policy);
    policy = nullptr;
    ::free((char*)hashAlgo);
    hashAlgo = nullptr;
    ba_free(baHashedMessage);
    baHashedMessage = nullptr;
}

int AttrTimeStamp_ST::checkEqual (const ByteArray* baData)
{
    int ret = RET_OK;
    ByteArray* ba_hash = nullptr;

    statusDigest = SIGNATURE_VERIFY::STATUS::FAILED;
    DO(::hash(hash_from_oid(hashAlgo), baData, &ba_hash));
    statusDigest = (ba_cmp(baHashedMessage, ba_hash) == 0) ? SIGNATURE_VERIFY::STATUS::VALID : SIGNATURE_VERIFY::STATUS::INVALID;

cleanup:
    ba_free(ba_hash);
    return ret;
}


VerifyInfo_ST::VerifyInfo_ST (void)
    : cerStoreItem(nullptr)
    , statusSignature(SIGNATURE_VERIFY::STATUS::UNDEFINED)
    , statusMessageDigest(SIGNATURE_VERIFY::STATUS::UNDEFINED)
    , statusEssCert(SIGNATURE_VERIFY::STATUS::UNDEFINED)
    , signingTime(0)
    , contentTS(nullptr)
    , signatureTS(nullptr)
{
}

VerifyInfo_ST::~VerifyInfo_ST (void)
{
    cerStoreItem = nullptr;
    signedAttrs.clear();
    unsignedAttrs.clear();
    delete contentTS;
    contentTS = nullptr;
    delete signatureTS;
    signatureTS = nullptr;
}


static int parse_attributes (const Attributes_t* srcAttrs, vector<AttrItem>& dstAttrs)
{
    int ret = RET_OK;

    if (srcAttrs && (srcAttrs->list.count > 0)) {
        dstAttrs.resize(srcAttrs->list.count);

        for (size_t i = 0; i < srcAttrs->list.count; i++) {
            const Attribute_t* src_attr = srcAttrs->list.array[i];
            AttrItem& dst_attr = dstAttrs[i];

            DO(asn_oid_to_text(&src_attr->type, (char**)&dst_attr.attrType));
            if (src_attr->value.list.count > 0) {
                const AttributeValue_t* attr_value = src_attr->value.list.array[0];
                dst_attr.baAttrValue = ba_alloc_from_uint8(attr_value->buf, attr_value->size);
            }
            else {
                dst_attr.baAttrValue = ba_alloc();
            }
            if (dst_attr.baAttrValue == nullptr) {
                SET_ERROR(RET_MEMORY_ALLOC_ERROR);
            }
        }
    }

cleanup:
    if (ret != RET_OK) {
        dstAttrs.clear();
    }
    return ret;
}

static int check_signing_certificate_v2 (const ByteArray* baEncoded, VerifyInfo* verifyInfo)
{
    int ret = RET_OK;
    SigningCertificateV2_t* signing_cert = nullptr;
    const ESSCertIDv2_t* ess_certid = nullptr;
    ByteArray* ba_calchash = nullptr;
    ByteArray* ba_certhash = nullptr;
    HashAlg hash_algo = HASH_ALG_SHA256;

    CHECK_NOT_NULL(signing_cert = (SigningCertificateV2_t*)asn_decode_ba_with_alloc(get_SigningCertificateV2_desc(), baEncoded));
    if (signing_cert->certs.list.count == 0) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

    //  Simple case - present one cert
    ess_certid = signing_cert->certs.list.array[0];
    if (ess_certid->hashAlgorithm != nullptr) {
        hash_algo = hash_from_OID(&ess_certid->hashAlgorithm->algorithm);
        if (hash_algo == HASH_ALG_UNDEFINED) {
            SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
        }
    }
    DO(asn_OCTSTRING2ba(&ess_certid->certHash, &ba_certhash));

    DO(::hash(hash_algo, verifyInfo->cerStoreItem->baEncoded, &ba_calchash));
    verifyInfo->statusEssCert = (ba_cmp(ba_calchash, ba_certhash) == 0) ? SIGNATURE_VERIFY::STATUS::VALID : SIGNATURE_VERIFY::STATUS::INVALID;

cleanup:
    asn_free(get_SigningCertificateV2_desc(), signing_cert);
    ba_free(ba_calchash);
    ba_free(ba_certhash);
    return ret;
}

static int process_signed_attributes (VerifyInfo* verifyInfo)
{
    int ret = RET_OK;
    AttrTimeStamp* attr_ts = nullptr;

    verifyInfo->statusEssCert = SIGNATURE_VERIFY::STATUS::NOT_PRESENT;

    for (size_t i = 0; i < verifyInfo->signedAttrs.size(); i++) {
        const AttrItem& attr_item = verifyInfo->signedAttrs[i];
        if (oid_is_equal(attr_item.attrType, OID_PKCS9_SIGNING_TIME)) {
            DO(ba_decode_pkixtime(attr_item.baAttrValue, &verifyInfo->signingTime));
        }
        else if (oid_is_equal(attr_item.attrType, OID_PKCS9_SIGNING_CERTIFICATE_V2)) {
            DO(check_signing_certificate_v2(attr_item.baAttrValue, verifyInfo));
        }
        else if (oid_is_equal(attr_item.attrType, OID_PKCS9_CONTENT_TIMESTAMP)) {
            CHECK_NOT_NULL(attr_ts = new AttrTimeStamp());
            DO(tsp_response_parse_tstoken_basic(attr_item.baAttrValue, (char**)&attr_ts->policy, (char**)&attr_ts->hashAlgo, &attr_ts->baHashedMessage, &attr_ts->msGenTime));
            verifyInfo->contentTS = attr_ts;
            attr_ts = nullptr;
        }
    }

cleanup:
    delete attr_ts;
    return ret;
}

static int process_unsigned_attributes (VerifyInfo* verifyInfo)
{
    int ret = RET_OK;
    AttrTimeStamp* attr_ts = nullptr;

    for (size_t i = 0; i < verifyInfo->unsignedAttrs.size(); i++) {
        const AttrItem& attr_item = verifyInfo->unsignedAttrs[i];
        if (oid_is_equal(attr_item.attrType, OID_PKCS9_TIMESTAMP_TOKEN)) {
            CHECK_NOT_NULL(attr_ts = new AttrTimeStamp());
            DO(tsp_response_parse_tstoken_basic(attr_item.baAttrValue, (char**)&attr_ts->policy, (char**)&attr_ts->hashAlgo, &attr_ts->baHashedMessage, &attr_ts->msGenTime));
            verifyInfo->signatureTS = attr_ts;
            attr_ts = nullptr;
        }
    }

cleanup:
    delete attr_ts;
    return ret;
}


int verify_signer_info (const SignerInfo_t* signerInfo, const vector<char*>& dgstAlgos,
                const ByteArray* baContent, const bool isDigest, VerifyInfo* verifyInfo)
{
    int ret = RET_OK;
    CerStore* cer_store = get_cerstore();
    long version = 0;
    ByteArray* ba_dgst = nullptr;
    ByteArray* ba_msgdigest = nullptr;
    ByteArray* ba_sattrs = nullptr;
    ByteArray* ba_sid = nullptr;
    ByteArray* ba_signvalue = nullptr;
    char* content_type = nullptr;
    char* dgst_algo = nullptr;
    char* sign_algo = nullptr;
    bool is_match = false;

    CHECK_PARAM(signerInfo != nullptr);
    if (baContent == nullptr) {
        SET_ERROR(RET_UAPKI_CONTENT_NOT_PRESENT);
    }
    CHECK_PARAM(verifyInfo != nullptr);

    //  version
    DO(asn_INTEGER2long(&signerInfo->version, &version));
    if ((version != 1) && (version != 3)) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT_VERSION);
    }

    //  sid
    if (version == 1) {
        //  it's issuerAndSerialNumber
        ba_sid = ba_alloc_from_uint8(signerInfo->sid.buf, (size_t)signerInfo->sid.size);
        DO(cer_store->getCertBySID(ba_sid, &verifyInfo->cerStoreItem));
    }
    else {
        //  it's subjectKeyIdentifier
        if ((signerInfo->sid.size < 18) || (signerInfo->sid.size > 66)) {
            SET_ERROR(RET_UAPKI_INVALID_KEY_ID);
        }
        CHECK_NOT_NULL(ba_sid = ba_alloc_from_uint8(signerInfo->sid.buf + 2, (size_t)signerInfo->sid.size - 2));
        DO(cer_store->getCertByKeyId(ba_sid, &verifyInfo->cerStoreItem));
    }

    //  digestAlgorithm
    DO(asn_oid_to_text(&signerInfo->digestAlgorithm.algorithm, &dgst_algo));

    //  signedAttrs
    DO(parse_attributes(signerInfo->signedAttrs, verifyInfo->signedAttrs));
    DO(asn_encode_ba(get_Attributes_desc(), signerInfo->signedAttrs, &ba_sattrs));

    //  signatureAlgorithm
    DO(asn_oid_to_text(&signerInfo->signatureAlgorithm.algorithm, &sign_algo));

    //  signature
    DO(asn_OCTSTRING2ba(&signerInfo->signature, &ba_signvalue));

    //  unsignedAttrs
    DO(parse_attributes(signerInfo->unsignedAttrs, verifyInfo->unsignedAttrs));

    //  Check digestAlgorithm
    for (size_t i = 0; i < dgstAlgos.size(); i++) {
        is_match = (strcmp(dgst_algo, dgstAlgos[i]) == 0);
        if (is_match) break;
    }
    if (!is_match) {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }

    //  Check minimal request attributes: 'contentType' and 'messageDigest'
    for (size_t i = 0; i < verifyInfo->signedAttrs.size(); i++) {
        const AttrItem& attr_item = verifyInfo->signedAttrs[i];
        if (oid_is_equal(attr_item.attrType, OID_PKCS9_CONTENT_TYPE)) {
            DO(ba_decode_oid(attr_item.baAttrValue, &content_type));
        }
        else if (oid_is_equal(attr_item.attrType, OID_PKCS9_MESSAGE_DIGEST)) {
            DO(ba_decode_octetstring(attr_item.baAttrValue, &ba_msgdigest));
        }
    }
    if ((content_type == nullptr) || !oid_is_equal(content_type, OID_PKCS7_DATA) || (ba_get_len(ba_msgdigest) == 0)) {
        SET_ERROR(RET_UAPKI_INVALID_ATTRIBUTE);
    }

    //  Verify signed attributes
    ret = verify_signature(sign_algo, ba_sattrs, false, verifyInfo->cerStoreItem->baSPKI, ba_signvalue);
    switch (ret) {
    case RET_OK:
        verifyInfo->statusSignature = SIGNATURE_VERIFY::STATUS::VALID;
        break;
    case RET_VERIFY_FAILED:
        verifyInfo->statusSignature = SIGNATURE_VERIFY::STATUS::INVALID;
        break;
    default:
        verifyInfo->statusSignature = SIGNATURE_VERIFY::STATUS::FAILED;
    }

    //  Validity messageDigest
    if (!isDigest) {
        DO(::hash(hash_from_oid(dgst_algo), baContent, &ba_dgst));
        verifyInfo->statusMessageDigest = (ba_cmp(ba_dgst, ba_msgdigest) == 0) ? SIGNATURE_VERIFY::STATUS::VALID : SIGNATURE_VERIFY::STATUS::INVALID;
    }
    else {
        verifyInfo->statusMessageDigest = (ba_cmp(baContent, ba_msgdigest) == 0) ? SIGNATURE_VERIFY::STATUS::VALID : SIGNATURE_VERIFY::STATUS::INVALID;
    }

    //  Process all attributes
    DO(process_signed_attributes(verifyInfo));
    DO(process_unsigned_attributes(verifyInfo));

    //  Validity contentTS (signed attribute)
    if (verifyInfo->contentTS) {
        verifyInfo->contentTS->checkEqual(baContent);
    }

    //  Validity signatureTS (unsigned attribute)
    if (verifyInfo->signatureTS) {
        verifyInfo->signatureTS->checkEqual(ba_signvalue);
    }

cleanup:
    ba_free(ba_dgst);
    ba_free(ba_msgdigest);
    ba_free(ba_sattrs);
    ba_free(ba_sid);
    ba_free(ba_signvalue);
    free(content_type);
    free(dgst_algo);
    free(sign_algo);
    return ret;
}

