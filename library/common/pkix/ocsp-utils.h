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

#ifndef UAPKI_OCSP_UTILS_H
#define UAPKI_OCSP_UTILS_H


#include "uapkic.h"
#include "uapkif.h"
#include "common.h"


#ifdef __cplusplus
extern "C" {
#endif


typedef struct OCSPCertID_ST {
    const char* hashAlgo;
    bool        hashAlgoParam_isNULL;
    ByteArray*  issuerNameHash;
    ByteArray*  issuerKeyHash;
    ByteArray*  serialNumber;
} OCSPCertID;


OCSPRequest_t* ocsp_request_alloc (void);
void ocsp_request_free (OCSPRequest_t* ocspRequest);

int ocsp_request_add_certid (OCSPRequest_t* ocspRequest, const OCSPCertID* certID);
int ocsp_request_encode_tbsrequest (OCSPRequest_t* ocspRequest, ByteArray** baEncodedTbs);
int ocsp_request_set_nonce (OCSPRequest_t* ocspRequest, const ByteArray* baNonce);
int ocsp_request_set_signature (OCSPRequest_t* ocspRequest, const SignatureParams* signatureParams, const ByteArray* baCert);
int ocsp_request_signature_add_cert (OCSPRequest_t* ocspRequest, const ByteArray* baCert);

int ocsp_response_parse (const ByteArray* baEncodedOrs, uint32_t* status, BasicOCSPResponse_t** basicOcspResp, ByteArray** baResponseData);

#ifdef __cplusplus
}
#endif


#endif
