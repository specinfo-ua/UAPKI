/*
 * Copyright (c) 2023, The UAPKI Project Authors.
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
#include "cipher-helper.h"
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


static int add_certs_to_store (
        CerStore& cerStore,
        const vector<ByteArray*>& vbaCerts
)
{
    int ret = RET_OK;

    DEBUG_OUTCON({ size_t cnt_certs; cerStore.getCount(cnt_certs); printf("add_certs_to_store(), certs (before): %d\n", (int)cnt_certs); });
    for (auto& it : vbaCerts) {
        bool is_unique;
        CerStore::Item* cer_item = nullptr;
        DO(cerStore.addCert(it, true, false, false, is_unique, &cer_item));
        //TODO: out certId
    }
    DEBUG_OUTCON({ size_t cnt_certs; cerStore.getCount(cnt_certs); printf("add_certs_to_store(), certs (after): %d\n", (int)cnt_certs); });

cleanup:
    return ret;
}

static int decrypt_content (const UapkiNS::Pkcs7::EncryptedContentInfo& eContentInfo,
                    const ByteArray* baSecretKey, ByteArray** baDecryptedContent)
{
    int ret = RET_OK;
    const UapkiNS::AlgorithmIdentifier& algo = eContentInfo.contentEncryptionAlgo;

    if (algo.algorithm == string(OID_DSTU7624_256_CFB)) {
        DO(UapkiNS::Cipher::Dstu7624::cryptData(
            algo,
            baSecretKey,
            UapkiNS::Cipher::Direction::DECRYPT,
            eContentInfo.baEncryptedContent,
            baDecryptedContent
        ));
    }
    else if (algo.algorithm == string(OID_GOST28147_CFB)) {
        DO(UapkiNS::Cipher::Gost28147::cryptData(
            algo,
            baSecretKey,
            UapkiNS::Cipher::Direction::DECRYPT,
            eContentInfo.baEncryptedContent,
            baDecryptedContent
        ));
    }

cleanup:
    return ret;
}

static int parse_keyencryption_algo (const UapkiNS::AlgorithmIdentifier& aidKeyEncryptionAlgo, string& oidDhKdf, string& oidWrapAlgo)
{
    int ret = RET_OK;
    AlgorithmIdentifier_t* aid = nullptr;
    char* s_wrapalgo = nullptr;

    DEBUG_OUTCON(printf("parse_keyencryption_algo(), algorithm: '%s'\n", aidKeyEncryptionAlgo.algorithm.c_str()));
    DEBUG_OUTCON(printf("parse_keyencryption_algo(), baParameters, hex: "); ba_print(stdout, aidKeyEncryptionAlgo.baParameters));

    oidDhKdf = aidKeyEncryptionAlgo.algorithm;
    if ((oidDhKdf == string(OID_COFACTOR_DH_DSTU7564_KDF)) || (oidDhKdf == string(OID_STD_DH_DSTU7564_KDF)) ||
        (oidDhKdf == string(OID_COFACTOR_DH_GOST34311_KDF)) || (oidDhKdf == string(OID_STD_DH_GOST34311_KDF))) {
        if (!aidKeyEncryptionAlgo.baParameters) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }

        CHECK_NOT_NULL(aid = (AlgorithmIdentifier_t*)asn_decode_ba_with_alloc(get_AlgorithmIdentifier_desc(), aidKeyEncryptionAlgo.baParameters));
        DO(asn_oid_to_text(&aid->algorithm, &s_wrapalgo));
        oidWrapAlgo = string(s_wrapalgo);
        if ((oidWrapAlgo == string(OID_DSTU7624_WRAP)) || (oidWrapAlgo == string(OID_GOST28147_WRAP))) {
            if (!aid->parameters || (aid->parameters->size != 2) || (aid->parameters->buf[0] != 0x05)) {
                SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
            }
        }
        else {
            SET_ERROR(RET_UAPKI_NOT_SUPPORTED);
        }
    }
    else {
        SET_ERROR(RET_UAPKI_NOT_SUPPORTED);
    }

cleanup:
    asn_free(get_AlgorithmIdentifier_desc(), aid);
    ::free(s_wrapalgo);
    return ret;
}

static int result_set_list_unprattrs (JSON_Object* joResult, const char* key, const vector<UapkiNS::Attribute>& attrs)
{
    int ret = RET_OK;
    json_object_set_value(joResult, key, json_value_init_array());
    JSON_Array* ja_attrs = json_object_get_array(joResult, key);
    for (size_t i = 0; i < attrs.size(); i++) {
        const UapkiNS::Attribute& attr = attrs[i];
        json_array_append_value(ja_attrs, json_value_init_object());
        JSON_Object* jo_attr = json_array_get_object(ja_attrs, i);
        DO_JSON(json_object_set_string(jo_attr, "type", attr.type.c_str()));
        DO_JSON(json_object_set_base64(jo_attr, "bytes", attr.baValues));
    }

cleanup:
    return ret;
}


int uapki_decrypt (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    CerStore* cer_store = nullptr;
    CerStore::Item* csi_originator = nullptr;
    UapkiNS::Pkcs7::EnvelopedDataParser envdata_parser;
    UapkiNS::SmartBA sba_data, sba_decrypted, sba_sessionkey;
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
        string s_kdfalgo, s_keywrapalgo;
        UapkiNS::Pkcs7::EnvelopedDataParser::KeyAgreeRecipientInfo kar_info;
        DO(envdata_parser.parseKeyAgreeRecipientInfo(idx_recip, kar_info));

        DEBUG_OUTCON(printf("kar_info.originatorType: %u\n", kar_info.getOriginatorType()));
        DEBUG_OUTCON(printf("kar_info.originator(encoded), hex: "); ba_print(stdout, kar_info.getOriginator()));
        switch (kar_info.getOriginatorType()) {
        case OriginatorIdentifierOrKey_PR_issuerAndSerialNumber:
            DO(cer_store->getCertBySID(kar_info.getOriginator(), &csi_originator));
            break;
        case OriginatorIdentifierOrKey_PR_subjectKeyIdentifier:
            DO(cer_store->getCertByKeyId(kar_info.getOriginator(), &csi_originator));
            break;
        case OriginatorIdentifierOrKey_PR_originatorKey:
            //Nothing: use kar_info.getOriginator() later - in keyDhUnwrapKey()
            break;
        default:
            return RET_UAPKI_INVALID_PARAMETER;
        }

        DO(parse_keyencryption_algo(kar_info.getKeyEncryptionAlgorithm(), s_kdfalgo, s_keywrapalgo));

        //DEBUG_OUTCON(printf("kar_info.recipientEncryptedKeys, count: %zu\n", kar_info.getRecipientEncryptedKeys().size()));
        const vector<UapkiNS::Pkcs7::RecipientEncryptedKey>& recip_ekeys = kar_info.getRecipientEncryptedKeys();
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

        ret = storage->keyDhUnwrapKey(
            s_kdfalgo,
            s_keywrapalgo,
            (csi_originator) ? csi_originator->baSPKI : kar_info.getOriginator(),
            kar_info.getUkm(),
            recip_ekeys[0].baEncryptedKey,
            &sba_sessionkey
        );
        DEBUG_OUTCON(printf("unwrap key, ret: %d\n", ret); printf("vba_SessionKeys, hex: "); ba_print(stdout, sba_sessionkey.get()));
    }

    DO(decrypt_content(envdata_parser.getEncryptedContentInfo(), sba_sessionkey.get(), &sba_decrypted));

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
            DO(result_set_list_unprattrs(joResult, "unprotectedAttrs", envdata_parser.getUnprotectedAttrs()));
        }
    }

cleanup:
    return ret;
}
