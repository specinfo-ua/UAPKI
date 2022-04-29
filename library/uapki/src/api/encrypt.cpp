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
#include "cipher-helper.h"
#include "dstu-ns.h"
#include "envelopeddata-helper.h"
#include "global-objects.h"
#include "key-wrap.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include "private-key.h"
#include "uapki-ns.h"

#undef FILE_MARKER
#define FILE_MARKER "api/encrypt.cpp"

#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif

//#define DEBUG_USE_FIXED_RND


using namespace  std;


struct EncryptContent {
    UapkiNS::AlgorithmIdentifier
                algo;
    UapkiNS::SmartBA
                data;
    UapkiNS::SmartBA
                secretkey;
    UapkiNS::SmartBA
                encrypted;
    string      type;
};


static const char* OID_KDF_ALGO_DEFAULT = OID_COFACTOR_DH_DSTU7564_KDF;
static const char* SHEX_KDFPARAM_DSTU7624WRAP   = "300F060B2A8624020101010101030B0500";
static const char* SHEX_KDFPARAM_GOST28147WRAP  = "300F060B2A862402010101010101050500";


static int add_originator_certs (CerStore& cerStore, UapkiNS::Pkcs7::EnvelopedDataBuilder& envDataBuilder, JSON_Array* jaCerts)
{
    if (!jaCerts) return RET_OK;

    int ret = RET_OK;
    const size_t cnt_certs = json_array_get_count(jaCerts);
    for (size_t i = 0; i < cnt_certs; i++) {
        UapkiNS::SmartBA sba_certid;
        if (!sba_certid.set(json_array_get_base64(jaCerts, i))) return RET_UAPKI_INVALID_PARAMETER;

        CerStore::Item* cer_item = nullptr;
        DO(cerStore.getCertByCertId(sba_certid.get(), &cer_item));
        DO(envDataBuilder.addOriginatorCert(cer_item->baEncoded));
    }

cleanup:
    return ret;
}

static int generate_ephemeral_privkey (const CerStore::Item& csiRecipient, ByteArray** baPrivateKeyInfo, ByteArray** baSpki)
{
    int ret = RET_OK;

    if (DstuNS::isDstu4145family(csiRecipient.keyAlgo)) {
        UapkiNS::SmartBA sba_params;
        string s_params;
        const ANY_t* algo_params = csiRecipient.cert->tbsCertificate.subjectPublicKeyInfo.algorithm.parameters;
        if (!algo_params) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }

        if (!sba_params.set(ba_alloc_from_uint8(algo_params->buf, algo_params->size))) {
            SET_ERROR(RET_UAPKI_GENERAL_ERROR);
        }
        DO(DstuNS::Dstu4145::decodeParams(sba_params.get(), s_params));

        DO(private_key_generate(csiRecipient.keyAlgo, s_params.c_str(), baPrivateKeyInfo));
        DEBUG_OUTCON(printf("generate_ephemeral_privkey(), encoded-pkinfo hex: "); ba_print(stdout, *baPrivateKeyInfo));

        DO(private_key_get_spki(*baPrivateKeyInfo, baSpki));
    }
    else {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }

cleanup:
    return ret;
}

static int wrap_sessionkey (const ByteArray* baPrivateKeyInfo, const string& oidDhKdf, const string& oidWrapAlgo,
                    const ByteArray* baSpki, const ByteArray* baSessionKey, ByteArray** baSalt, ByteArray** baWrappedKey)
{
    int ret = RET_OK;
    vector<const ByteArray*> vba_spkis, vba_skeys;
    ByteArray** aba_salts = nullptr;
    ByteArray** aba_wrappedkeys = nullptr;

    vba_spkis.push_back(baSpki);
    vba_skeys.push_back(baSessionKey);

    DO(key_wrap(baPrivateKeyInfo,
        (baSalt),   //  isStaticKey
        oidDhKdf.c_str(),
        oidWrapAlgo.c_str(),
        1,
        (const ByteArray**)vba_spkis.data(),
        (const ByteArray**)vba_skeys.data(),
        &aba_salts,
        &aba_wrappedkeys
    ));

    if (baSalt) {
        *baSalt = aba_salts[0];
        aba_salts[0] = nullptr;
    }
    *baWrappedKey = aba_wrappedkeys[0];
    aba_wrappedkeys[0] = nullptr;

cleanup:
    ::free(aba_salts);
    ::free(aba_wrappedkeys);
    return ret;
}

static int parse_keyencryption_algo (JSON_Object* joRecipientInfo, UapkiNS::AlgorithmIdentifier& aidKeyEncryptionAlgo, string& oidWrapAlgo)
{
    int ret = RET_OK;
    string s_kdfalgo;

    s_kdfalgo = ParsonHelper::jsonObjectGetString(joRecipientInfo, "kdfAlgo", OID_KDF_ALGO_DEFAULT);
    oidWrapAlgo = ParsonHelper::jsonObjectGetString(joRecipientInfo, "keyWrapAlgo");

    if ((s_kdfalgo == string(OID_COFACTOR_DH_DSTU7564_KDF)) || (s_kdfalgo == string(OID_STD_DH_DSTU7564_KDF))) {
        if (oidWrapAlgo.empty()) {
            oidWrapAlgo = string(OID_DSTU7624_WRAP);
        }
        if (oidWrapAlgo == string(OID_DSTU7624_WRAP)) {
            CHECK_NOT_NULL(aidKeyEncryptionAlgo.baParameters = ba_alloc_from_hex(SHEX_KDFPARAM_DSTU7624WRAP));
        }
        else {
            SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
        }
    }
    else if ((s_kdfalgo == string(OID_COFACTOR_DH_GOST34311_KDF)) || (s_kdfalgo == string(OID_STD_DH_GOST34311_KDF))) {
        if (oidWrapAlgo.empty()) {
            oidWrapAlgo = string(OID_GOST28147_WRAP);
        }
        if (oidWrapAlgo == string(OID_GOST28147_WRAP)) {
            CHECK_NOT_NULL(aidKeyEncryptionAlgo.baParameters = ba_alloc_from_hex(SHEX_KDFPARAM_GOST28147WRAP));
        }
        else {
            SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
        }
    }
    else {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }

    aidKeyEncryptionAlgo.algorithm = s_kdfalgo;

cleanup:
    return ret;
}

static int setup_kari (const CerStore::Item& csiRecipient, UapkiNS::Pkcs7::EnvelopedDataBuilder::KeyAgreeRecipientInfo* kari,
                    EncryptContent& encryptContent, JSON_Object* joRecipientInfo)
{
    if (!kari) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    UapkiNS::AlgorithmIdentifier aid_keyencryption;
    UapkiNS::SmartBA sba_ephemkey, sba_ephemspki, sba_recipissasn,sba_wrappedkey;
    string s_keywrapalgo;

    {   //  Check key usage: must be keyAgreement
        bool ku_keyagreement = false;
        DO(csiRecipient.keyUsageByBit(KeyUsage_keyAgreement, ku_keyagreement));
        if (!ku_keyagreement) {
            SET_ERROR(RET_UAPKI_INVALID_KEY_USAGE);
        }
    }

    DO(parse_keyencryption_algo(joRecipientInfo, aid_keyencryption, s_keywrapalgo));

    DO(generate_ephemeral_privkey(csiRecipient, &sba_ephemkey, &sba_ephemspki));
    DO(wrap_sessionkey(sba_ephemkey.get(),
        aid_keyencryption.algorithm,
        s_keywrapalgo,
        csiRecipient.baSPKI,
        encryptContent.secretkey.get(),
        nullptr,
        &sba_wrappedkey
    ));

    DO(csiRecipient.getIssuerAndSN(&sba_recipissasn));

    DO(kari->setVersion());
    DO(kari->setOriginatorByPublicKey(sba_ephemspki.get()));
    //  Salt/UserKeyingMaterial not used
    DO(kari->setKeyEncryptionAlgorithm(aid_keyencryption));
    DO(kari->addRecipientEncryptedKeyByIssuerAndSN(sba_recipissasn.get(), sba_wrappedkey.get()));

cleanup:
    return ret;
}

static int add_recipient_infos (CerStore& cerStore, UapkiNS::Pkcs7::EnvelopedDataBuilder& envDataBuilder,
                    EncryptContent& encryptContent, JSON_Array* jaRecipientInfos)
{
    const size_t cnt_recips = json_array_get_count(jaRecipientInfos);
    if (cnt_recips == 0) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    for (size_t i = 0; i < cnt_recips; i++) {
        UapkiNS::SmartBA sba_certid;
        CerStore::Item* csi_recipient = nullptr;
        JSON_Object* jo_recipinfo = json_array_get_object(jaRecipientInfos, i);

        //  Now supported only KeyAgree, other - later
        DO(envDataBuilder.addRecipientInfo(RecipientInfo_PR_kari));
        if (!sba_certid.set(json_object_get_base64(jo_recipinfo, "certId"))) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
        DO(cerStore.getCertByCertId(sba_certid.get(), &csi_recipient));
        DO(setup_kari(*csi_recipient, envDataBuilder.getKeyAgreeRecipientInfo(i), encryptContent, jo_recipinfo));
    }

cleanup:
    return ret;
}

static int add_unprotected_attrs (UapkiNS::Pkcs7::EnvelopedDataBuilder& envDataBuilder, JSON_Array* jaAttrs)
{
    if (!jaAttrs) return RET_OK;

    int ret = RET_OK;
    const size_t cnt_attrs = json_array_get_count(jaAttrs);
    for (size_t i = 0; i < cnt_attrs; i++) {
        UapkiNS::Attribute attr;
        JSON_Object* jo_attr = json_array_get_object(jaAttrs, i);
        attr.type = ParsonHelper::jsonObjectGetString(jo_attr, "type");
        attr.baValues = json_object_get_base64(jo_attr, "bytes");
        if (!attr.isPresent() || !attr.baValues) return RET_UAPKI_INVALID_PARAMETER;

        DO(envDataBuilder.addUnprotectedAttr(attr));
    }

cleanup:
    return ret;
}

static int encrypt_content (EncryptContent& content)
{
    int ret = RET_OK;

    if (content.algo.algorithm == string(OID_DSTU7624_256_CFB)) {
        DO(UapkiNS::Cipher::Dstu7624::cryptData(
            content.algo,
            content.secretkey.get(),
            UapkiNS::Cipher::Direction::ENCRYPT,
            content.data.get(),
            &content.encrypted
        ));
    }
    else if (content.algo.algorithm == string(OID_GOST28147_CFB)) {
        DO(UapkiNS::Cipher::Gost28147::cryptData(
            content.algo,
            content.secretkey.get(),
            UapkiNS::Cipher::Direction::ENCRYPT,
            content.data.get(),
            &content.encrypted
        ));
    }

cleanup:
    return ret;
}

static int generate_secretkey (EncryptContent& content)
{
    int ret = RET_OK;
    UapkiNS::SmartBA sba_dke, sba_iv;

    if (content.algo.algorithm == string(OID_DSTU7624_256_CFB)) {
        ba_free(content.algo.baParameters);
        content.algo.baParameters = nullptr;
        DO(UapkiNS::Cipher::Dstu7624::generateIV(&sba_iv));
#ifdef DEBUG_USE_FIXED_RND
        sba_iv.clear(); sba_iv.set(ba_alloc_from_hex("119070DE12D7C6AB303132333435363738394142434445464748494A4B4C4D4E"));
#endif
        DO(UapkiNS::Cipher::Dstu7624::encodeParams(sba_iv.get(), &content.algo.baParameters));
        DO(UapkiNS::Cipher::Dstu7624::generateKey(32, &content.secretkey));
#ifdef DEBUG_USE_FIXED_RND
content.secretkey.clear(); content.secretkey.set(ba_alloc_from_hex("9040E744B76191597150D29E212B92937E1A6CA2CDA925DACF3B2C7FBB8E4FFC"));
#endif
    }
    else if (content.algo.algorithm == string(OID_GOST28147_CFB)) {
        sba_dke.set(content.algo.baParameters);
        content.algo.baParameters = nullptr;
        DO(UapkiNS::Cipher::Gost28147::generateIV(&sba_iv));
#ifdef DEBUG_USE_FIXED_RND
sba_iv.clear(); sba_iv.set(ba_alloc_from_hex("119070DE12D7C6AB"));
sba_dke.clear(); //UapkiNS::Cipher::Gost28147::getDKE(GOST28147_SBOX_DEFAULT, &sba_dke);
#endif
        DO(UapkiNS::Cipher::Gost28147::encodeParams(sba_iv.get(), sba_dke.get(), &content.algo.baParameters));
        DO(UapkiNS::Cipher::Gost28147::generateKey(&content.secretkey));
#ifdef DEBUG_USE_FIXED_RND
content.secretkey.clear(); content.secretkey.set(ba_alloc_from_hex("9040E744B76191597150D29E212B92937E1A6CA2CDA925DACF3B2C7FBB8E4FFC"));
#endif
    }
    else {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }

cleanup:
    return ret;
}

static int parse_content (JSON_Object* joContent, EncryptContent& encryptContent)
{
    if (!encryptContent.data.set(json_object_get_base64(joContent, "bytes"))) return RET_UAPKI_INVALID_PARAMETER;

    encryptContent.algo.algorithm = ParsonHelper::jsonObjectGetString(joContent, "encryptionAlgo", string(OID_DSTU7624_256_CFB));
    //TODO: encryptContent.algo.baParameters (optional) - later
    encryptContent.type = ParsonHelper::jsonObjectGetString(joContent, "type", string(OID_PKCS7_DATA));

    return RET_OK;
}


int uapki_encrypt (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    CerStore* cer_store = nullptr;
    UapkiNS::Pkcs7::EnvelopedDataBuilder envdata_builder;
    EncryptContent econtent;
    vector<UapkiNS::Attribute> unpr_attrs;
    const uint32_t version = 2u;

    cer_store = get_cerstore();
    if (!cer_store) return RET_UAPKI_GENERAL_ERROR;

    DO(envdata_builder.init(version));

    DO(parse_content(json_object_get_object(joParams, "content"), econtent));
 
    DO(generate_secretkey(econtent));

    DO(add_originator_certs(*cer_store, envdata_builder, json_object_get_array(joParams, "originatorCertIds")));

    DO(add_recipient_infos(*cer_store, envdata_builder, econtent, json_object_get_array(joParams, "recipientInfos")));

    DO(add_unprotected_attrs(envdata_builder, json_object_get_array(joParams, "unprotectedAttrs")));

    DO(encrypt_content(econtent));
    DO(envdata_builder.setEncryptedContentInfo(econtent.type, econtent.algo, econtent.encrypted.get()));

    DO(envdata_builder.encode());
    DEBUG_OUTCON(printf("p7e(encoded), hex: "); ba_print(stdout, envdata_builder.getEncoded()));

    DO_JSON(json_object_set_base64(joResult, "bytes", envdata_builder.getEncoded()));

cleanup:
    return ret;
}
