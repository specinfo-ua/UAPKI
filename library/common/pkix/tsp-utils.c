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

#include "tsp-utils.h"
#include "asn1-ba-utils.h"
#include "content-info.h"
#include "macros-internal.h"
#include "oids.h"
#include "oid-utils.h"
#include "uapki-errors.h"


#undef FILE_MARKER
#define FILE_MARKER "common/tsp_utils.c"


int tsp_request_encode (const MessageImprintParams* msgImprint, const TspRequestParams* tsrParam, ByteArray** baEncodedTsq)
{
    int ret = RET_OK;
    TimeStampReq_t* tsp_request = NULL;
    NULL_t* null_params = NULL;
    BOOLEAN_t cr = true;

    CHECK_PARAM(msgImprint != NULL);
    CHECK_PARAM(tsrParam != NULL);
    CHECK_PARAM(baEncodedTsq != NULL);

    ASN_ALLOC(tsp_request);
    DO(asn_ulong2INTEGER(&tsp_request->version, 1));
    DO(asn_set_oid_from_text(msgImprint->hashAlgo, &tsp_request->messageImprint.hashAlgorithm.algorithm));
    if (msgImprint->hashAlgoParam_isNULL) {
        ASN_ALLOC(null_params);
        DO(asn_create_any(get_NULL_desc(), null_params, &tsp_request->messageImprint.hashAlgorithm.parameters));
    }
    DO(asn_ba2OCTSTRING(msgImprint->hashedMessage, &tsp_request->messageImprint.hashedMessage));

    if (tsrParam->reqPolicy || (ba_get_len(tsrParam->nonce) > 0) || tsrParam->certReq) {
        if (tsrParam->reqPolicy) {
            ASN_ALLOC(tsp_request->reqPolicy);
            DO(asn_set_oid_from_text(tsrParam->reqPolicy, tsp_request->reqPolicy));
        }
        if (ba_get_len(tsrParam->nonce) > 0) {
            ASN_ALLOC(tsp_request->nonce);
            DO(asn_ba2INTEGER(tsrParam->nonce, tsp_request->nonce));
        }
        if (tsrParam->certReq) {
            CHECK_NOT_NULL(tsp_request->certReq = (BOOLEAN_t*)asn_copy_with_alloc(get_BOOLEAN_desc(), &cr));
        }
    }

    DO(asn_encode_ba(get_TimeStampReq_desc(), tsp_request, baEncodedTsq));

cleanup:
    asn_free(get_TimeStampReq_desc(), tsp_request);
    asn_free(get_NULL_desc(), null_params);
    return ret;
}

int tsp_response_parse (const ByteArray* baEncodedTsr, uint32_t* status, ByteArray** baTsToken, ByteArray** baTstInfo)
{
    int ret = RET_OK;
    TimeStampResp_t* tsp_response = NULL;
    SignedData_t* signed_data = NULL;
    EncapsulatedContentInfo_t* encap_coninfo = NULL;
    unsigned long pkistatus_status = 0;

    CHECK_PARAM(baEncodedTsr != NULL);
    CHECK_PARAM(status != NULL);
    CHECK_PARAM(baTstInfo != NULL);
    CHECK_PARAM(baTsToken != NULL);

    CHECK_NOT_NULL(tsp_response = asn_decode_ba_with_alloc(get_TimeStampResp_desc(), baEncodedTsr));

    DO(asn_INTEGER2ulong(&tsp_response->status.status, &pkistatus_status));
    *status = (uint32_t)pkistatus_status;

    if (((pkistatus_status == PKIStatus_granted) || (pkistatus_status == PKIStatus_grantedWithMods)) && (tsp_response->timeStampToken != NULL)) {
        DO(asn_encode_ba(get_ContentInfo_desc(), tsp_response->timeStampToken, baTsToken));

        DO(cinfo_get_signed_data(tsp_response->timeStampToken, &signed_data));
        encap_coninfo = &signed_data->encapContentInfo;
        if (!OID_is_equal_oid(&encap_coninfo->eContentType, OID_PKCS9_TST_INFO)) {
            SET_ERROR(RET_UAPKI_INVALID_CONTENT_INFO);
        }
        CHECK_NOT_NULL(*baTstInfo = ba_alloc_from_uint8(encap_coninfo->eContent->buf, encap_coninfo->eContent->size));
    }

cleanup:
    asn_free(get_TimeStampResp_desc(), tsp_response);
    asn_free(get_SignedData_desc(), signed_data);
    return ret;
}

int tsp_response_parse_statusinfo (const ByteArray* baEncodedTsr, uint32_t* status, char** statusString, uint32_t* failInfo)
{
    int ret = RET_OK;
    TimeStampResp_t* tsp_response = NULL;
    unsigned long pkistatus_status = 0;
    UTF8String_t* utf8_str = NULL;

    CHECK_PARAM(baEncodedTsr != NULL);
    CHECK_PARAM(status != NULL);
    CHECK_PARAM(statusString != NULL);
    CHECK_PARAM(failInfo != NULL);

    CHECK_NOT_NULL(tsp_response = asn_decode_ba_with_alloc(get_TimeStampResp_desc(), baEncodedTsr));

    DO(asn_INTEGER2ulong(&tsp_response->status.status, &pkistatus_status));
    *status = (uint32_t)pkistatus_status;

    if ((tsp_response->status.statusString != NULL) && (tsp_response->status.statusString->list.count > 0)) {
        //  Get first utf8-string only
        utf8_str = tsp_response->status.statusString->list.array[0];
        DO(uint8_to_str_with_alloc(utf8_str->buf, (size_t)utf8_str->size, statusString));
    }

    if (tsp_response->status.failInfo != NULL) {
        DO(asn_decodevalue_bitstring_to_uint32(tsp_response->status.failInfo, failInfo));
    }

cleanup:
    asn_free(get_TimeStampResp_desc(), tsp_response);
    return ret;
}

int tsp_response_parse_tstoken_basic (const ByteArray* baTsToken, char** policy, char** hashAlgo, ByteArray** baHashedMessage, uint64_t* msGenTime)
{
    int ret = RET_OK;
    ContentInfo_t* cinfo = NULL;
    SignedData_t* signed_data = NULL;
    EncapsulatedContentInfo_t* encap_coninfo = NULL;
    TSTInfo_t* tst_info = NULL;
    CinfoType cinfo_type = CONTENT_UNKNOWN;
    ByteArray* ba_hashedmessage = NULL;
    char* s_hashalgo = NULL;
    char* s_policy = NULL;

    CHECK_PARAM(baTsToken != NULL);
    CHECK_PARAM(policy != NULL);
    CHECK_PARAM(hashAlgo != NULL);
    CHECK_PARAM(baHashedMessage != NULL);
    CHECK_PARAM(msGenTime != NULL);

    CHECK_NOT_NULL(cinfo = asn_decode_ba_with_alloc(get_ContentInfo_desc(), baTsToken));
    DO(cinfo_get_type(cinfo, &cinfo_type));
    if (cinfo_type != CONTENT_SIGNED) {
        SET_ERROR(RET_UAPKI_INVALID_CONTENT_INFO);
    }

    DO(cinfo_get_signed_data(cinfo, &signed_data));
    encap_coninfo = &signed_data->encapContentInfo;
    if (!OID_is_equal_oid(&encap_coninfo->eContentType, OID_PKCS9_TST_INFO)) {
        SET_ERROR(RET_UAPKI_INVALID_CONTENT_INFO);
    }

    CHECK_NOT_NULL(tst_info = asn_decode_with_alloc(get_TSTInfo_desc(), encap_coninfo->eContent->buf, encap_coninfo->eContent->size));
    DO(asn_oid_to_text(&tst_info->policy, &s_policy));
    DO(asn_oid_to_text(&tst_info->messageImprint.hashAlgorithm.algorithm, &s_hashalgo));
    DO(asn_OCTSTRING2ba(&tst_info->messageImprint.hashedMessage, &ba_hashedmessage));
    DO(asn_decodevalue_gentime(&tst_info->genTime, msGenTime));

    *policy = s_policy;
    s_policy = NULL;
    *hashAlgo = s_hashalgo;
    s_hashalgo = NULL;
    *baHashedMessage = ba_hashedmessage;
    ba_hashedmessage = NULL;

cleanup:
    asn_free(get_ContentInfo_desc(), cinfo);
    asn_free(get_SignedData_desc(), signed_data);
    asn_free(get_TSTInfo_desc(), tst_info);
    ba_free(ba_hashedmessage);
    free(s_hashalgo);
    free(s_policy);
    return ret;
}

//  Test-cases for tstinfo_is_equal_tsr(), in hex-string:
//  1) "3030302E02010230250C237265717565737420636F6E7461696E7320756E6B6E6F776E20616C676F726974686D2E03020780"
//  2) "3032303002010230270C255375706572666C756F7573206D6573736167652064696765737420706172616D657465722E03020780"
int tsp_tstinfo_is_equal_request (const ByteArray* baEncodedTsq, const ByteArray* baTstInfo)
{
    int ret = RET_OK;
    TimeStampReq_t* tsp_request = NULL;
    TSTInfo_t* tst_info = NULL;
    OBJECT_IDENTIFIER_t* oid_hashalgo1 = NULL;
    OBJECT_IDENTIFIER_t* oid_hashalgo2 = NULL;
    OCTET_STRING_t* os_hashedmsg1 = NULL;
    OCTET_STRING_t* os_hashedmsg2 = NULL;
    INTEGER_t* int_nonce1 = NULL;
    INTEGER_t* int_nonce2 = NULL;

    CHECK_PARAM(baEncodedTsq != NULL);
    CHECK_PARAM(baTstInfo != NULL);

    CHECK_NOT_NULL(tsp_request = asn_decode_ba_with_alloc(get_TimeStampReq_desc(), baEncodedTsq));
    CHECK_NOT_NULL(tst_info = asn_decode_ba_with_alloc(get_TSTInfo_desc(), baTstInfo));

    //  Check hashAlgorithm
    oid_hashalgo1 = &tsp_request->messageImprint.hashAlgorithm.algorithm;
    oid_hashalgo2 = &tst_info->messageImprint.hashAlgorithm.algorithm;
    if ((oid_hashalgo1->size != oid_hashalgo2->size) || (memcmp(oid_hashalgo1->buf, oid_hashalgo2->buf, oid_hashalgo2->size) != 0)) {
        SET_ERROR(RET_UAPKI_TSP_RESPONSE_NOT_EQUAL_REQUEST);
    }

    //  Check hashedMessage
    os_hashedmsg1 = &tsp_request->messageImprint.hashedMessage;
    os_hashedmsg2 = &tst_info->messageImprint.hashedMessage;
    if ((os_hashedmsg1->size != os_hashedmsg2->size) || (memcmp(os_hashedmsg1->buf, os_hashedmsg2->buf, os_hashedmsg2->size) != 0)) {
        SET_ERROR(RET_UAPKI_TSP_RESPONSE_NOT_EQUAL_REQUEST);
    }

    //  Check nonce if present
    int_nonce1 = tsp_request->nonce;
    if (int_nonce1 != NULL) {
        int_nonce2 = tst_info->nonce;
        if ((int_nonce1->size != int_nonce2->size) || (memcmp(int_nonce1->buf, int_nonce2->buf, int_nonce2->size) != 0)) {
            SET_ERROR(RET_UAPKI_TSP_RESPONSE_NOT_EQUAL_REQUEST);
        }
    }

cleanup:
    asn_free(get_TimeStampReq_desc(), tsp_request);
    asn_free(get_TSTInfo_desc(), tst_info);
    return ret;
}
