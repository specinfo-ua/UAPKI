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
#include "cm-providers.h"
#include "envelopeddata-helper.h"
#include "global-objects.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include "uapki-ns.h"

#undef FILE_MARKER
#define FILE_MARKER "api/decrypt.cpp"

#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


static int parse_gost28147params_wo_dke (const ByteArray* baEncoded, ByteArray** baIv)
{
    int ret = RET_OK;
    GOST28147Params_t* params = nullptr;

    CHECK_NOT_NULL(params = (GOST28147Params_t*)asn_decode_ba_with_alloc(get_GOST28147Params_desc(), baEncoded));

    //  =iv=
    DO(asn_OCTSTRING2ba(&params->iv, baIv));

    //  =dke=
    //DO(asn_OCTSTRING2ba(&params->dke, baDke));

cleanup:
    asn_free(get_GOST28147Params_desc(), params);
    return ret;
}

static int add_certs_to_store (CerStore& cerStore, const vector<ByteArray*>& vbaCerts)
{
    int ret = RET_OK;

    DEBUG_OUTCON({ size_t cnt_certs; cerStore.getCount(cnt_certs); printf("add_certs_to_store(), certs (before): %d\n", (int)cnt_certs); });
    for (auto& it : vbaCerts) {
        bool is_unique;
        const CerStore::Item* cer_item = nullptr;
        DO(cerStore.addCert(it, true, false, false, is_unique, &cer_item));
        //TODO: out certId
    }
    DEBUG_OUTCON({ size_t cnt_certs; cerStore.getCount(cnt_certs); printf("add_certs_to_store(), certs (after): %d\n", (int)cnt_certs); });

cleanup:
    return ret;
}


int uapki_decrypt (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    CerStore* cer_store = nullptr;
    const CerStore::Item* csi_originator = nullptr;
    UapkiNS::Pkcs7::EnvelopedDataParser envdata_parser;
    UapkiNS::SmartBA sba_data, sba_decrypted, sba_sessionkey, sba_spki;
    size_t idx_recip = 0;

    cer_store = get_cerstore();
    if (!cer_store) return RET_UAPKI_GENERAL_ERROR;

    CmStorageProxy* storage = CmProviders::openedStorage();
    if (!storage) return RET_UAPKI_STORAGE_NOT_OPEN;
    if (!storage->keyIsSelected()) return RET_UAPKI_KEY_NOT_SELECTED;

    if (!sba_data.set(json_object_get_base64(joParams, "bytes"))) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    DO(envdata_parser.parse(sba_data.get()));

    DO(add_certs_to_store(*cer_store, envdata_parser.getOriginatorCerts()));

    if (envdata_parser.getRecipientInfoTypes()[idx_recip] == RecipientInfo_PR_kari) {
        UapkiNS::Pkcs7::EnvelopedDataParser::KeyAgreeRecipientInfo kar_info;
        DO(envdata_parser.parseKeyAgreeRecipientInfo(idx_recip, kar_info));

        DEBUG_OUTCON(printf("kar_info.originatorType: %u\n", kar_info.getOriginatorType()));
        DEBUG_OUTCON(printf("kar_info.originator(encoded), hex: "); ba_print(stdout, kar_info.getOriginator()));
        switch (kar_info.getOriginatorType()) {
        case OriginatorIdentifierOrKey_PR_issuerAndSerialNumber:
            DO(cer_store->getCertBySID(kar_info.getOriginator(), &csi_originator));
            break;
        case OriginatorIdentifierOrKey_PR_subjectKeyIdentifier:
            DO(cer_store->getCertByKeyId(kar_info.getOriginator(), &csi_originator));//not tested
            break;
        case OriginatorIdentifierOrKey_PR_originatorKey:
            return RET_UAPKI_NOT_SUPPORTED;//TODO: need impl
        default:
            return RET_UAPKI_INVALID_PARAMETER;
        }

        DEBUG_OUTCON(printf("kar_info.keyEncryptionAlgorithm.algorithm: '%s'\n",
            kar_info.getKeyEncryptionAlgorithm().algorithm.c_str()));
        const string s_kdf = kar_info.getKeyEncryptionAlgorithm().algorithm;
        if (s_kdf != OID_COFACTOR_DH_GOST34311_KDF) return RET_UAPKI_NOT_SUPPORTED;//now only COFACTOR_DH_GOST34311_KDF ("1.2.804.2.1.1.1.1.3.4")

        DEBUG_OUTCON(printf("kar_info.keyEncryptionAlgorithm.baParameters, hex: ");
            ba_print(stdout, kar_info.getKeyEncryptionAlgorithm().baParameters));
        const string s_wrapalg = string(OID_GOST28147_WRAP);// "1.2.804.2.1.1.1.1.1.1.5";

        //DEBUG_OUTCON(printf("kar_info.recipientEncryptedKeys, count: %zu\n", kar_info.getRecipientEncryptedKeys().size()));
        const vector<UapkiNS::Pkcs7::EnvelopedDataParser::RecipientEncryptedKey>& recip_ekeys = kar_info.getRecipientEncryptedKeys();
        UapkiNS::Pkcs7::EnvelopedDataParser::KeyAgreeRecipientIdentifier kar_id;
        DO(kar_id.parse(recip_ekeys[0].baRid));
        DEBUG_OUTCON(printf("kar_id.type: %u\n", kar_id.getType()));
        UapkiNS::SmartBA sba_recip;
        switch (kar_id.getType()) {
        case KeyAgreeRecipientIdentifier_PR_issuerAndSerialNumber:
            DO(kar_id.toIssuerAndSN(&sba_recip));
            DEBUG_OUTCON(printf("toIssuerAndSN, hex: "); ba_print(stdout, sba_recip.get()));
            break;
        case KeyAgreeRecipientIdentifier_PR_rKeyId:
            DO(kar_id.toRecipientKeyId(&sba_recip));
            DEBUG_OUTCON(printf("toRecipientKeyId, hex: "); ba_print(stdout, sba_recip.get()));
            break;
        default:
            break;
        }

        ret = storage->keyDhUnwrapKey(s_kdf, s_wrapalg,
            csi_originator->baSPKI, kar_info.getUkm(), recip_ekeys[0].baEncryptedKey,
            &sba_sessionkey);
        DEBUG_OUTCON(printf("unwrap key, ret: %d\n", ret); printf("vba_SessionKeys, hex: "); ba_print(stdout, sba_sessionkey.get()));
    }

    {   //TODO
        const string s_cryptalgo = envdata_parser.getEncryptedContentInfo().contentEncryptionAlgo.algorithm;
        if (s_cryptalgo != OID_GOST28147_CFB) return RET_UAPKI_NOT_SUPPORTED;//now only GOST28147_CFB ("1.2.804.2.1.1.1.1.1.1.3")
        //baParameters, hex: 300F060B2A862402010101010101050500 //1.2.804.2.1.1.1.1.1.1.5 Gost28147wrap

        UapkiNS::SmartBA sba_iv;
        Gost28147Ctx* ctx = NULL;

        DO(parse_gost28147params_wo_dke(envdata_parser.getEncryptedContentInfo().contentEncryptionAlgo.baParameters, &sba_iv));

        ctx = gost28147_alloc(GOST28147_SBOX_ID_1);
        DO(gost28147_init_cfb(ctx, sba_sessionkey.get(), sba_iv.get()));
        DO(gost28147_decrypt(ctx, envdata_parser.getEncryptedContentInfo().baEncryptedContent, &sba_decrypted));
        gost28147_free(ctx);

        //DEBUG_OUTCON(printf("sba_decrypted, hex: "); ba_print(stdout, sba_decrypted.get()));
    }

    {   //  Set result
        DO_JSON(json_object_set_value(joResult, "content", json_value_init_object()));
        JSON_Object* jo_content = json_object_get_object(joResult, "content");
        DO_JSON(json_object_set_string(jo_content, "type", envdata_parser.getEncryptedContentInfo().contentType.c_str()));
        DO(json_object_set_base64(jo_content, "bytes", sba_decrypted.get()));

        if (csi_originator) {
            DO(json_object_set_base64(joResult, "originatorCertId", csi_originator->baCertId));
        }

        if (!envdata_parser.getUnprotectedAttrs().empty()) {
            DEBUG_OUTCON(printf("unprotectedAttrs, count: %zu\n", envdata_parser.getUnprotectedAttrs().size()));
            //TODO: set array of UnprotectedAttrs
        }
    }

cleanup:
    return ret;
}
