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

#include "ocsp-utils.h"
#include "asn1-ba-utils.h"
#include "content-info.h"
#include "extension-utils.h"
#include "macros-internal.h"
#include "oids.h"
#include "oid-utils.h"
#include "uapki-errors.h"


#undef FILE_MARKER
#define FILE_MARKER "common/ocsp_utils.c"


OCSPRequest_t* ocsp_request_alloc (void)
{
    int ret = RET_OK;
    OCSPRequest_t* rv_ocspreq = NULL;

    ASN_ALLOC(rv_ocspreq);

cleanup:
    return rv_ocspreq;
}

void ocsp_request_free (OCSPRequest_t* ocspRequest)
{
    asn_free(get_OCSPRequest_desc(), ocspRequest);
}

int ocsp_request_add_certid (OCSPRequest_t* ocspRequest, const OCSPCertID* certID)
{
    int ret = RET_OK;
    Request_t* request = NULL;
    NULL_t* null_params = NULL;

    CHECK_PARAM(ocspRequest != NULL);
    CHECK_PARAM(certID != NULL);
    CHECK_PARAM(certID->hashAlgo != NULL);
    CHECK_PARAM(certID->issuerNameHash != NULL);
    CHECK_PARAM(certID->issuerKeyHash != NULL);
    CHECK_PARAM(certID->serialNumber != NULL);

    ASN_ALLOC(request);

    DO(asn_set_oid_from_text(certID->hashAlgo, &request->reqCert.hashAlgorithm.algorithm));
    if (certID->hashAlgoParam_isNULL) {
        ASN_ALLOC(null_params);
        DO(asn_create_any(get_NULL_desc(), null_params, &request->reqCert.hashAlgorithm.parameters));
    }
    DO(asn_ba2OCTSTRING(certID->issuerNameHash, &request->reqCert.issuerNameHash));
    DO(asn_ba2OCTSTRING(certID->issuerKeyHash, &request->reqCert.issuerKeyHash));
    DO(asn_ba2INTEGER(certID->serialNumber, &request->reqCert.serialNumber));

    DO(ASN_SEQUENCE_ADD(&ocspRequest->tbsRequest.requestList.list, request));
    request = NULL;

cleanup:
    asn_free(get_Request_desc(), request);
    asn_free(get_NULL_desc(), null_params);
    return ret;
}

int ocsp_request_encode_tbsrequest (OCSPRequest_t* ocspRequest, ByteArray** baEncodedTbs)
{
    int ret = RET_OK;

    CHECK_PARAM(ocspRequest != NULL);
    CHECK_PARAM(baEncodedTbs != NULL);

    DO(asn_encode_ba(get_TBSRequest_desc(), &ocspRequest->tbsRequest, baEncodedTbs));

cleanup:
    return ret;
}

int ocsp_request_set_nonce (OCSPRequest_t* ocspRequest, const ByteArray* baNonce)
{
    int ret = RET_OK;

    CHECK_PARAM(ocspRequest != NULL);
    CHECK_PARAM(baNonce != NULL);

    if (ocspRequest->tbsRequest.requestExtensions == NULL) {
        ASN_ALLOC(ocspRequest->tbsRequest.requestExtensions);
    }
    DO(extns_add_ocsp_nonce(ocspRequest->tbsRequest.requestExtensions, baNonce));

cleanup:
    return ret;
}

int ocsp_request_set_signature (OCSPRequest_t* ocspRequest, const SignatureParams* signatureParams, const ByteArray* baCert)
{
    int ret = RET_OK;
    Certificate_t* cert = NULL;
    Signature_t* sign = NULL;

    CHECK_PARAM(ocspRequest != NULL);
    CHECK_PARAM(signatureParams != NULL);
    CHECK_PARAM(signatureParams->algo != NULL);
    CHECK_PARAM(signatureParams->value != NULL);

    ASN_ALLOC(sign);

    DO(asn_set_oid_from_text(signatureParams->algo, &sign->signatureAlgorithm.algorithm));
    if (signatureParams->algoParams != NULL) {
        CHECK_NOT_NULL(sign->signatureAlgorithm.parameters = asn_decode_ba_with_alloc(get_ANY_desc(), signatureParams->algoParams));
    }

    DO(asn_ba2BITSTRING(signatureParams->value, &sign->signature));
    if (baCert) {
        CHECK_NOT_NULL(cert = asn_decode_ba_with_alloc(get_Certificate_desc(), baCert));

        ASN_ALLOC(sign->certs);
        DO(ASN_SEQUENCE_ADD(&sign->certs->list, cert));
        cert = NULL;
    }

    ocspRequest->optionalSignature = sign;
    sign = NULL;

cleanup:
    asn_free(get_Certificate_desc(), cert);
    asn_free(get_Signature_desc(), sign);
    return ret;
}

int ocsp_request_signature_add_cert (OCSPRequest_t* ocspRequest, const ByteArray* baCert)
{
    int ret = RET_OK;
    Certificate_t* cert = NULL;
    Signature_t* sign = NULL;

    CHECK_PARAM(ocspRequest != NULL);
    CHECK_PARAM(ocspRequest->optionalSignature != NULL);
    CHECK_PARAM(baCert != NULL);

    CHECK_NOT_NULL(cert = asn_decode_ba_with_alloc(get_Certificate_desc(), baCert));

    sign = ocspRequest->optionalSignature;
    if (sign->certs == NULL) {
        ASN_ALLOC(sign->certs);
    }
    DO(ASN_SEQUENCE_ADD(&sign->certs->list, cert));
    cert = NULL;

cleanup:
    asn_free(get_Certificate_desc(), cert);
    return ret;
}

int ocsp_response_parse (const ByteArray* baEncodedOrs, uint32_t* status, BasicOCSPResponse_t** basicOcspResp, ByteArray** baResponseData)
{
    int ret = RET_OK;
    BasicOCSPResponse_t* basicocsp_resp = NULL;
    OCSPResponse_t* ocsp_resp = NULL;
    ResponseBytes_t* resp_bytes = NULL;

    CHECK_PARAM(baEncodedOrs != NULL);
    CHECK_PARAM(status != NULL);
    CHECK_PARAM(basicOcspResp != NULL);
    CHECK_PARAM(baResponseData != NULL);

    CHECK_NOT_NULL(ocsp_resp = asn_decode_ba_with_alloc(get_OCSPResponse_desc(), baEncodedOrs));

    DO(asn_decodevalue_enumerated(&ocsp_resp->responseStatus, status));
    if (*status != OCSPResponseStatus_successful) goto cleanup;

    resp_bytes = ocsp_resp->responseBytes;
    if ((resp_bytes == NULL) || (!OID_is_equal_oid(&resp_bytes->responseType, OID_PKIX_OcspBasic))) {
        SET_ERROR(RET_UAPKI_OCSP_RESPONSE_INVALID_CONTENT);
    }

    CHECK_NOT_NULL(basicocsp_resp = asn_decode_with_alloc(get_BasicOCSPResponse_desc(), resp_bytes->response.buf, resp_bytes->response.size));

    DO(asn_encode_ba(get_ResponseData_desc(), &basicocsp_resp->tbsResponseData, baResponseData));

    *basicOcspResp = basicocsp_resp;
    basicocsp_resp = NULL;

cleanup:
    asn_free(get_BasicOCSPResponse_desc(), basicocsp_resp);
    asn_free(get_OCSPResponse_desc(), ocsp_resp);
    return ret;
}

