/*
 * Copyright (c) 2022, The UAPKI Project Authors.
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
#include "envelopeddata-helper.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include "uapki-ns.h"

#undef FILE_MARKER
#define FILE_MARKER "api/decrypt.cpp"

//#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


int uapki_decrypt (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    UapkiNS::Pkcs7::EnvelopedDataParser envdata_parser;
    UapkiNS::SmartBA sba_data;

    if (!sba_data.set(json_object_get_base64(joParams, "bytes"))) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    DO(envdata_parser.parse(sba_data.get()));

    DEBUG_OUTCON(printf("version: %u\n", envdata_parser.getVersion()));
    DEBUG_OUTCON(printf("originatorInfo.certs: %zu\n", envdata_parser.getOriginatorCerts().size()));
    DEBUG_OUTCON(printf("originatorInfo.crls: %zu\n", envdata_parser.getOriginatorCrls().size()));
    DEBUG_OUTCON(printf("recipientInfos, count: %zu\n", envdata_parser.getRecipientInfoTypes().size()));
    DEBUG_OUTCON(printf("encryptedContentInfo.contentType: '%s'\n",
        envdata_parser.getEncryptedContentInfo().contentType.c_str()));
    DEBUG_OUTCON(printf("encryptedContentInfo.contentEncryptionAlgo.algorithm: '%s'\n",
        envdata_parser.getEncryptedContentInfo().contentEncryptionAlgo.algorithm.c_str()));
    DEBUG_OUTCON(printf("encryptedContentInfo.contentEncryptionAlgo.baParameters, hex: ");
        ba_print(stdout, envdata_parser.getEncryptedContentInfo().contentEncryptionAlgo.baParameters));
    DEBUG_OUTCON(printf("encryptedContentInfo.encryptedContent, size: %zu\n",
        ba_get_len(envdata_parser.getEncryptedContentInfo().baEncryptedContent)));

    //  Simple case: now support one KeyAgreeRecipientInfo
    if (envdata_parser.getRecipientInfoTypes()[0] == RecipientInfo_PR_kari) {
        UapkiNS::Pkcs7::EnvelopedDataParser::KeyAgreeRecipientInfo kari;
        DO(envdata_parser.parseKeyAgreeRecipientInfo(0, kari));
        DEBUG_OUTCON(printf("kari.version: %u\n", kari.getVersion()));
        DEBUG_OUTCON(printf("kari.originatorType: %u\n", kari.getOriginatorType()));
        DEBUG_OUTCON(printf("kari.originator(encoded), hex: ");ba_print(stdout, kari.getOriginator()));
        DEBUG_OUTCON(printf("kari.ukm, hex: ");ba_print(stdout, kari.getUkm()));
        DEBUG_OUTCON(printf("kari.keyEncryptionAlgorithm.algorithm: '%s'\n",
            kari.getKeyEncryptionAlgorithm().algorithm.c_str()));
        DEBUG_OUTCON(printf("kari.keyEncryptionAlgorithm.baParameters, hex: ");
            ba_print(stdout, kari.getKeyEncryptionAlgorithm().baParameters));
        DEBUG_OUTCON(printf("recipientEncryptedKeys, count: %zu\n", kari.getRecipientEncryptedKeys().size()));
    }

cleanup:
    return ret;
}
