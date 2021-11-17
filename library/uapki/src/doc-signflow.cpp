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
#include "attribute-utils.h"
#include "cer-store.h"
#include "cms-utils.h"
#include "doc-signflow.h"
#include "oid-utils.h"
#include "time-utils.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


int SigningDoc::init (const SignParams* iSignParams, const char* iId, ByteArray* iData)
{
    signParams = iSignParams;
    id = iId;
    baData = iData;

    return (!signParams && !id || (ba_get_len(baData) > 0)) ? RET_OK : RET_UAPKI_INVALID_PARAMETER;
}

int SigningDoc::buildSignedAttributes (void)
{
    int ret = RET_OK;
    Attributes_t* signed_attrs = nullptr;
    uint64_t signing_time = 0;

    if (signParams->includeTime) {
        signing_time = TimeUtils::nowMsTime();
    }

    DO(create_std_signed_attrs(OID_PKCS7_DATA, baMessageDigest, signing_time, &signed_attrs));

    for (auto& it : signedAttrs) {
        DO(attrs_add_attribute(signed_attrs, it->type, it->baValue));
    }

    DO(asn_encode_ba(get_Attributes_desc(), signed_attrs, &baSignedAttrs));

cleanup:
    asn_free(get_Attributes_desc(), signed_attrs);
    return ret;
}

int SigningDoc::buildSignedData (void)
{
    int ret = RET_OK;
    SignerInfo_t* signer_info = nullptr;
    SignedData_t* sdata = nullptr;
    ByteArray* ba_sid = nullptr;
    SignatureParams signatureParams;
    uint32_t version = 0;

    if (!signParams->sidUseKeyId) {
        DO(signParams->cerStoreItem->getIssuerAndSN(&ba_sid));
        version = 1;
    }
    else {
        DEBUG_OUTCON(printf("signParams->baKeyId, hex:"); ba_print(stdout, signParams->baKeyId));
        DO(keyid_to_sid_subjectkeyid(signParams->baKeyId, &ba_sid));
        version = 3;
    }
    DEBUG_OUTCON(printf("SigningDoc::buildSignedData(), ba_sid, hex:"); ba_print(stdout, ba_sid));

    signatureParams.algo = signParams->signAlgo.c_str();
    signatureParams.algoParams = nullptr;
    signatureParams.value = baSignature;
    DO(create_signer_info(
        version,
        ba_sid,
        signParams->digestAlgo.c_str(),
        baSignedAttrs,
        &signatureParams,
        baUnsignedAttrs,
        &signer_info
    ));

    DO(create_signed_data(
        version,
        (signParams->detachedData) ? nullptr : baData,
        (signParams->includeCert) ? signParams->cerStoreItem->baEncoded : nullptr,
        signer_info,
        &sdata
    ));
    signer_info = nullptr;

    DO(encode_signed_data(sdata, &baEncoded));

cleanup:
    asn_free(get_SignerInfo_desc(), signer_info);
    asn_free(get_SignedData_desc(), sdata);
    ba_free(ba_sid);
    return ret;
}

int SigningDoc::buildUnsignedAttributes (void)
{
    int ret = RET_OK;
    Attributes_t* unsigned_attrs = nullptr;

    if (!unsignedAttrs.empty()) {
        unsigned_attrs = (Attributes_t*) calloc(1, sizeof(Attributes_t));
        if (!unsigned_attrs) {
            SET_ERROR(RET_MEMORY_ALLOC_ERROR);
        }

        for (auto& it : unsignedAttrs) {
            DO(attrs_add_attribute(unsigned_attrs, it->type, it->baValue));
        }

        DO(asn_encode_ba(get_Attributes_desc(), unsigned_attrs, &baUnsignedAttrs));
    }

cleanup:
    asn_free(get_Attributes_desc(), unsigned_attrs);
    return ret;
}

int SigningDoc::digestMessage (void)
{
    int ret = RET_OK;

    if (!isDigest) {
        DO(::hash(signParams->digestHashAlgo, baData, &baMessageDigest));
    }
    else {
        const size_t hashsize_expected = hash_get_size(signParams->digestHashAlgo);
        if (hashsize_expected == ba_get_len(baData)) {
            baMessageDigest = baData;
            baData = nullptr;
        }
        else {
            ret = RET_UAPKI_INVALID_PARAMETER;
        }
    }

cleanup:
    return ret;
}

int SigningDoc::digestSignature (ByteArray** baHash)
{
    int ret = RET_OK;

    CHECK_PARAM(baHash != nullptr);

    DO(::hash(signParams->digestHashAlgo, baSignature, baHash));

cleanup:
    return ret;
}

int SigningDoc::digestSignedAttributes (void)
{
    int ret = RET_OK;

    DO(::hash(signParams->signHashAlgo, baSignedAttrs, &baHashSignedAttrs));

cleanup:
    return ret;
}
