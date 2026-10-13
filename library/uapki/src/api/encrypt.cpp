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

#define FILE_MARKER "uapki/api/encrypt.cpp"

#include "api-json-internal.h"
#include "cipher-helper.h"
#include "dstu-ns.h"
#include "envelopeddata-helper.h"
#include "iso15946.h"
#include "key-trans.h"
#include "key-wrap.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include "private-key.h"
#include "uapki-ns.h"
#include "uapki-ns-util.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;
using namespace UapkiNS;


struct EncryptContent {
    UapkiNS::AlgorithmIdentifier
            algoId;
    SmartBA data;
    SmartBA secretKey;
    SmartBA encrypted;
    string  type;
};  //  end struct EncryptContent


static const char* OID_KDF_ALGO_DEFAULT = OID_COFACTOR_DH_DSTU7564_KDF;
static const char* SHEX_KDFPARAM_DSTU7624WRAP   = "300F060B2A8624020101010101030B0500";
static const char* SHEX_KDFPARAM_GOST28147WRAP  = "300F060B2A862402010101010101050500";


static int add_originator_certs (
        Cert::CerStore& cerStore,
        Pkcs7::EnvelopedDataBuilder& envDataBuilder,
        JSON_Array* jaCerts
)
{
    if (!jaCerts) return RET_OK;

    int ret = RET_OK;
    const size_t cnt_certs = json_array_get_count(jaCerts);
    for (size_t i = 0; i < cnt_certs; i++) {
        SmartBA sba_certid;
        if (!sba_certid.set(json_array_get_base64(jaCerts, i))) return RET_UAPKI_INVALID_PARAMETER;

        Cert::CerItem* cer_item = nullptr;
        DO(cerStore.getCertByCertId(sba_certid.get(), &cer_item));
        DO(envDataBuilder.addOriginatorCert(cer_item->getEncoded()));
    }

cleanup:
    return ret;
}   //  add_originator_certs

static int generate_ephemeral_privkey (
        const Cert::CerItem& cerRecipient,
        ByteArray** baPrivateKeyInfo,
        ByteArray** baSpki
)
{
    int ret = RET_OK;

    if (DstuNS::isDstu4145family(cerRecipient.getKeyAlgo())) {
        SmartBA sba_params;
        string s_params;
        const ANY_t* algo_params = cerRecipient.getCert()->tbsCertificate.subjectPublicKeyInfo.algorithm.parameters;
        if (!algo_params) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }

        if (!sba_params.set(ba_alloc_from_uint8(algo_params->buf, algo_params->size))) {
            SET_ERROR(RET_UAPKI_GENERAL_ERROR);
        }
        DO(DstuNS::Dstu4145::decodeParams(sba_params.get(), s_params));

        DO(private_key_generate(cerRecipient.getKeyAlgo().c_str(), s_params.c_str(), baPrivateKeyInfo));
        DEBUG_OUTCON(printf("generate_ephemeral_privkey(), encoded-pkinfo hex: "); ba_print(stdout, *baPrivateKeyInfo));

        DO(private_key_get_spki(*baPrivateKeyInfo, baSpki));
    }
    else if (cerRecipient.getKeyAlgo() == string(OID_EC_KEY)) {
        //  The ephemeral key on the curve of the recipient (RFC 5753, 3.1.1)
        char* s_algo = nullptr;
        char* s_curve = nullptr;
        ret = spki_get_algo_param(cerRecipient.getSpki(), &s_algo, &s_curve);
        if ((ret == RET_OK) && s_curve) {
            ret = private_key_generate(OID_EC_KEY, s_curve, baPrivateKeyInfo);
        }
        else if (ret == RET_OK) {
            ret = RET_UAPKI_UNSUPPORTED_ALG;
        }
        ::free(s_algo);
        ::free(s_curve);
        DO(ret);

        DO(private_key_get_spki(*baPrivateKeyInfo, baSpki));
    }
    else {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }

cleanup:
    return ret;
}   //  generate_ephemeral_privkey

static int wrap_sessionkey (
        const ByteArray* baPrivateKeyInfo,
        const string& oidDhKdf,
        const string& oidWrapAlgo,
        const ByteArray* baSpki,
        const ByteArray* baSessionKey,
        ByteArray** baSalt,
        ByteArray** baWrappedKey
)
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
    if (aba_salts) {
        ba_free(aba_salts[0]);
        ::free(aba_salts);
    }
    if (aba_wrappedkeys) {
        ba_free(aba_wrappedkeys[0]);
        ::free(aba_wrappedkeys);
    }
    return ret;
}   //  wrap_sessionkey

static int parse_keyencryption_algo (
        const Cert::CerItem& cerRecipient,
        JSON_Object* joRecipientInfo,
        UapkiNS::AlgorithmIdentifier& aidKeyEncryptionAlgo,
        string& oidWrapAlgo
)
{
    int ret = RET_OK;
    string s_kdfalgo;
    const bool is_ec = (cerRecipient.getKeyAlgo() == string(OID_EC_KEY));

    s_kdfalgo = ParsonHelper::jsonObjectGetString(joRecipientInfo, "kdfAlgo", is_ec ? OID_DHSINGLEPASS_STD_DH_SHA256_KDF : OID_KDF_ALGO_DEFAULT);
    oidWrapAlgo = ParsonHelper::jsonObjectGetString(joRecipientInfo, "keyWrapAlgo");

    if (is_ec) {
        //  ECDH with the ANSI X9.63 KDF and AES Key Wrap (RFC 5753): the parameters of the scheme are
        //  the key wrap algorithm, its own parameters are absent
        const HashAlg hash_kdf = iso15946_hash_from_oid_dhkdf(s_kdfalgo.c_str(), nullptr);
        if (oidWrapAlgo.empty()) {
            oidWrapAlgo = string(OID_AES256_WRAP);
        }
        if (
            (hash_kdf == HASH_ALG_UNDEFINED) || (hash_kdf == HASH_ALG_DSTU7564_256) || (hash_kdf == HASH_ALG_GOST34311) ||
            ((oidWrapAlgo != string(OID_AES128_WRAP)) && (oidWrapAlgo != string(OID_AES192_WRAP)) && (oidWrapAlgo != string(OID_AES256_WRAP)))
        ) {
            SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
        }
        DO(Util::encodeAlgorithmIdentifier(oidWrapAlgo, nullptr, &aidKeyEncryptionAlgo.baParameters));
    }
    else if ((s_kdfalgo == string(OID_COFACTOR_DH_DSTU7564_KDF)) || (s_kdfalgo == string(OID_STD_DH_DSTU7564_KDF))) {
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
}   //  parse_keyencryption_algo

static int setup_kari (
        const Cert::CerItem& cerRecipient,
        Pkcs7::EnvelopedDataBuilder::KeyAgreeRecipientInfo* kari,
        EncryptContent& encryptContent,
        JSON_Object* joRecipientInfo
)
{
    if (!kari) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    UapkiNS::AlgorithmIdentifier aid_keyencryption;
    SmartBA sba_ephemkey, sba_ephemspki, sba_recipissasn,sba_wrappedkey;
    string s_keywrapalgo;

    if (!cerRecipient.keyUsageByBit(KeyUsage_keyAgreement)) {
        SET_ERROR(RET_UAPKI_INVALID_KEY_USAGE);
    }

    DO(parse_keyencryption_algo(cerRecipient, joRecipientInfo, aid_keyencryption, s_keywrapalgo));

    DO(generate_ephemeral_privkey(cerRecipient, &sba_ephemkey, &sba_ephemspki));
    DO(wrap_sessionkey(sba_ephemkey.get(),
        aid_keyencryption.algorithm,
        s_keywrapalgo,
        cerRecipient.getSpki(),
        encryptContent.secretKey.get(),
        nullptr,
        &sba_wrappedkey
    ));

    DO(cerRecipient.getIssuerAndSN(&sba_recipissasn));

    DO(kari->setVersion());
    DO(kari->setOriginatorByPublicKey(sba_ephemspki.get()));
    //  Salt/UserKeyingMaterial not used
    DO(kari->setKeyEncryptionAlgorithm(aid_keyencryption));
    DO(kari->addRecipientEncryptedKeyByIssuerAndSN(sba_recipissasn.get(), sba_wrappedkey.get()));

cleanup:
    return ret;
}   //  setup_kari

static int setup_ktri (
        const Cert::CerItem& cerRecipient,
        Pkcs7::EnvelopedDataBuilder& envDataBuilder,
        EncryptContent& encryptContent,
        JSON_Object* joRecipientInfo
)
{
    int ret = RET_OK;
    UapkiNS::AlgorithmIdentifier aid_keyencryption;
    SmartBA sba_encryptedkey, sba_recipissasn;

    if (!cerRecipient.keyUsageByBit(KeyUsage_keyEncipherment)) {
        SET_ERROR(RET_UAPKI_INVALID_KEY_USAGE);
    }

    //  RSAES-OAEP (RFC 3560) by default, or RSAES-PKCS1-v1_5 - rsaEncryption with the NULL parameters (RFC 3370, 4.2.1)
    aid_keyencryption.algorithm = ParsonHelper::jsonObjectGetString(joRecipientInfo, "keyEncryptionAlgo", OID_RSAES_OAEP);
    if (aid_keyencryption.algorithm == string(OID_RSAES_OAEP)) {
        const string s_digestalgo = ParsonHelper::jsonObjectGetString(joRecipientInfo, "digestAlgo");
        const HashAlg hash_algo = s_digestalgo.empty() ? HASH_ALG_SHA256 : hash_from_oid(s_digestalgo.c_str());
        if (hash_algo == HASH_ALG_UNDEFINED) {
            SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
        }
        DO(key_trans_encode_oaep_params(hash_algo, &aid_keyencryption.baParameters));
    }
    else if (aid_keyencryption.algorithm == string(OID_RSA)) {
        CHECK_NOT_NULL(aid_keyencryption.baParameters = ba_alloc_from_hex("0500"));
    }
    else {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }

    DO(key_trans_encrypt(
        cerRecipient.getSpki(),
        aid_keyencryption.algorithm.c_str(),
        aid_keyencryption.baParameters,
        encryptContent.secretKey.get(),
        &sba_encryptedkey
    ));

    DO(cerRecipient.getIssuerAndSN(&sba_recipissasn));
    DO(envDataBuilder.addKeyTransRecipientInfo(sba_recipissasn.get(), aid_keyencryption, sba_encryptedkey.get()));

cleanup:
    return ret;
}   //  setup_ktri

static int add_recipient_infos (
        Cert::CerStore& cerStore,
        Pkcs7::EnvelopedDataBuilder& envDataBuilder,
        EncryptContent& encryptContent,
        JSON_Array* jaRecipientInfos,
        bool& allKeyTrans
)
{
    const size_t cnt_recips = json_array_get_count(jaRecipientInfos);
    if (cnt_recips == 0) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    for (size_t i = 0; i < cnt_recips; i++) {
        SmartBA sba_certid;
        Cert::CerItem* cer_recipient = nullptr;
        JSON_Object* jo_recipinfo = json_array_get_object(jaRecipientInfos, i);

        if (!sba_certid.set(json_object_get_base64(jo_recipinfo, "certId"))) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
        DO(cerStore.getCertByCertId(sba_certid.get(), &cer_recipient));
        if (cer_recipient->getKeyAlgo() == string(OID_RSA)) {
            //  Key transport: the key is encrypted for the RSA key of the recipient
            DO(setup_ktri(*cer_recipient, envDataBuilder, encryptContent, jo_recipinfo));
        }
        else {
            //  Key agreement: an ephemeral key, a KDF and a key wrap
            DO(envDataBuilder.addRecipientInfo(RecipientInfo_PR_kari));
            DO(setup_kari(*cer_recipient, envDataBuilder.getKeyAgreeRecipientInfo(i), encryptContent, jo_recipinfo));
            allKeyTrans = false;
        }
    }

cleanup:
    return ret;
}   //  add_recipient_infos

static int add_unprotected_attrs (
        Pkcs7::EnvelopedDataBuilder& envDataBuilder,
        JSON_Array* jaAttrs
)
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
}   //  add_unprotected_attrs

static int encrypt_content (
        EncryptContent& content
)
{
    int ret = RET_OK;

    if (!content.data.empty()) {
        if (content.algoId.algorithm == string(OID_DSTU7624_256_CFB)) {
            DO(Cipher::Dstu7624::cryptData(
                content.algoId,
                content.secretKey.get(),
                Cipher::Direction::ENCRYPT,
                content.data.get(),
                &content.encrypted
            ));
        }
        else if (content.algoId.algorithm == string(OID_GOST28147_CFB)) {
            DO(Cipher::Gost28147::cryptData(
                content.algoId,
                content.secretKey.get(),
                Cipher::Direction::ENCRYPT,
                content.data.get(),
                &content.encrypted
            ));
        }
        else if (Cipher::Aes::keySize(content.algoId.algorithm) > 0) {
            DO(Cipher::Aes::cryptData(
                content.algoId,
                content.secretKey.get(),
                Cipher::Direction::ENCRYPT,
                content.data.get(),
                &content.encrypted
            ));
        }
    }

cleanup:
    return ret;
}   //  encrypt_content

static int generate_secretkey (
        EncryptContent& content
)
{
    int ret = RET_OK;
    SmartBA sba_dke, sba_iv;

    if (content.algoId.algorithm == string(OID_DSTU7624_256_CFB)) {
        if (!content.algoId.baParameters) {
            DO(Cipher::Dstu7624::generateIV(&sba_iv));
            DO(Cipher::Dstu7624::encodeParams(sba_iv.get(), &content.algoId.baParameters));
        }
        else {
            // Check decoding Dstu7624-params
            DO(Cipher::Dstu7624::decodeParams(content.algoId.baParameters, &sba_iv));
        }
        if (content.secretKey.empty()) {
            DO(Cipher::Dstu7624::generateKey(32, &content.secretKey));
        }
    }
    else if (content.algoId.algorithm == string(OID_GOST28147_CFB)) {
        if (!content.algoId.baParameters) {
            DO(Cipher::Gost28147::generateIV(&sba_iv));
            DO(Cipher::Gost28147::encodeParams(sba_iv.get(), sba_dke.get(), &content.algoId.baParameters));
        }
        else {
            // Check decoding Gost28147-params
            DO(Cipher::Gost28147::decodeParams(content.algoId.baParameters, &sba_iv, &sba_dke, true));
        }
        if (content.secretKey.empty()) {
            DO(Cipher::Gost28147::generateKey(&content.secretKey));
        }
    }
    else if (Cipher::Aes::keySize(content.algoId.algorithm) > 0) {
        if (!content.algoId.baParameters) {
            DO(Cipher::Aes::generateIV(&sba_iv));
            DO(Cipher::Aes::encodeParams(sba_iv.get(), &content.algoId.baParameters));
        }
        else {
            // Check decoding AES-IV
            DO(Cipher::Aes::decodeParams(content.algoId.baParameters, &sba_iv));
        }
        if (content.secretKey.empty()) {
            DO(Cipher::Aes::generateKey(Cipher::Aes::keySize(content.algoId.algorithm), &content.secretKey));
        }
        else if (content.secretKey.size() != Cipher::Aes::keySize(content.algoId.algorithm)) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
    }
    else if (content.data.empty() && !content.algoId.algorithm.empty()  && !content.secretKey.empty()) {
        // No action: uses external encryption data
    }
    else {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }

cleanup:
    return ret;
}   //  generate_secretkey

static int parse_content (
        JSON_Object* joContent,
        EncryptContent& content
)
{
    // content is optional (possible use an external encryption)
    if (ParsonHelper::jsonObjectHasValue(joContent, "bytes", JSONString)) {
        if (!content.data.set(json_object_get_base64(joContent, "bytes"))) return RET_UAPKI_INVALID_PARAMETER;
    }

    // secretKey is optional (possible use an exists value)
    if (ParsonHelper::jsonObjectHasValue(joContent, "dataEncryptionKey", JSONString)) {
        if (!content.secretKey.set(json_object_get_base64(joContent, "dataEncryptionKey"))) return RET_UAPKI_INVALID_PARAMETER;
    }

    //  The default depends on the key of the first recipient, see default_encryption_algo()
    content.algoId.algorithm = ParsonHelper::jsonObjectGetString(joContent, "encryptionAlgo");
    if (ParsonHelper::jsonObjectHasValue(joContent, "encryptionAlgoParams", JSONString)) {
        content.algoId.baParameters = json_object_get_base64(joContent, "encryptionAlgoParams");
        if (!content.algoId.baParameters) return RET_UAPKI_INVALID_PARAMETER;
    }

    content.type = ParsonHelper::jsonObjectGetString(joContent, "type", string(OID_PKCS7_DATA));

    if (content.data.empty() && content.secretKey.empty()) return RET_UAPKI_INVALID_PARAMETER;

    return RET_OK;
}   //  parse_content


//  The content encryption algorithm by default: DSTU 7624 for a recipient with a DSTU 4145 key, AES-256-CBC for RSA and ECDSA
static int default_encryption_algo (
        Cert::CerStore& cerStore,
        JSON_Array* jaRecipientInfos,
        EncryptContent& content
)
{
    if (!content.algoId.algorithm.empty()) return RET_OK;

    SmartBA sba_certid;
    Cert::CerItem* cer_recipient = nullptr;
    if (!sba_certid.set(json_object_get_base64(json_array_get_object(jaRecipientInfos, 0), "certId"))) return RET_UAPKI_INVALID_PARAMETER;

    const int ret = cerStore.getCertByCertId(sba_certid.get(), &cer_recipient);
    if (ret != RET_OK) return ret;

    content.algoId.algorithm = DstuNS::isDstu4145family(cer_recipient->getKeyAlgo()) ? string(OID_DSTU7624_256_CFB) : string(OID_AES256_CBC_PAD);
    return RET_OK;
}   //  default_encryption_algo


int uapki_encrypt (Context& context, JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    Cert::CerStore* cer_store = nullptr;
    Pkcs7::EnvelopedDataBuilder envdata_builder;
    EncryptContent econtent;
    vector<UapkiNS::Attribute> unpr_attrs;
    const uint32_t version = 2u;
    bool all_keytrans = true;

    cer_store = context.cerStore();
    if (!cer_store) return RET_UAPKI_GENERAL_ERROR;

    DO(envdata_builder.init(version));

    DO(parse_content(json_object_get_object(joParams, "content"), econtent));
    DO(default_encryption_algo(*cer_store, json_object_get_array(joParams, "recipientInfos"), econtent));
 
    DO(generate_secretkey(econtent));

    DO(add_originator_certs(*cer_store, envdata_builder, json_object_get_array(joParams, "originatorCertIds")));

    DO(add_recipient_infos(*cer_store, envdata_builder, econtent, json_object_get_array(joParams, "recipientInfos"), all_keytrans));

    DO(add_unprotected_attrs(envdata_builder, json_object_get_array(joParams, "unprotectedAttrs")));

    //  The version is 0 if there is neither originatorInfo nor unprotectedAttrs and every RecipientInfo
    //  has the version 0 (RFC 5652, 6.1)
    if (
        all_keytrans &&
        (json_array_get_count(json_object_get_array(joParams, "originatorCertIds")) == 0) &&
        (json_array_get_count(json_object_get_array(joParams, "unprotectedAttrs")) == 0)
    ) {
        DO(envdata_builder.setVersion(0));
    }

    DO(encrypt_content(econtent));
    DO(envdata_builder.setEncryptedContentInfo(econtent.type, econtent.algoId, econtent.encrypted.get()));

    DO(envdata_builder.encode());
    DEBUG_OUTCON(printf("p7e(encoded), hex: "); ba_print(stdout, envdata_builder.getEncoded()));

    DO_JSON(json_object_set_base64(joResult, "bytes", envdata_builder.getEncoded()));

cleanup:
    return ret;
}
