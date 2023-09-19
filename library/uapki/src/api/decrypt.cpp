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

#define FILE_MARKER "uapki/api/decrypt.cpp"

#include "api-json-internal.h"
#include "cert-validator.h"
#include "cipher-helper.h"
#include "cm-providers.h"
#include "envelopeddata-helper.h"
#include "global-objects.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include "store-json.h"
#include "uapki-ns-util.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;
using namespace UapkiNS;


class ExpectedCerts {
    vector<CertValidator::ExpectedCertItem*>
            m_ExpectedCertItems;
    bool    m_IsExpectedOriginatorCert;
    bool    m_IsExpectedRecipientCert;

public:
    ExpectedCerts (void)
        : m_IsExpectedOriginatorCert(false)
        , m_IsExpectedRecipientCert(false)
    {}
    ~ExpectedCerts (void) {
        for (auto& it : m_ExpectedCertItems) {
            delete it;
        }
    }

    bool isExpectedOriginatorCert (void) const {
        return m_IsExpectedOriginatorCert;
    }
    bool isExpectedRecipientCert (void) const {
        return m_IsExpectedRecipientCert;
    }
    bool isPresent (void) const {
        return (!m_ExpectedCertItems.empty());
    }

    int add (
        const CertValidator::CertEntity certEntity,
        const ByteArray* baKeyIdOrSN,
        const ByteArray* baName
    ) {
        m_IsExpectedOriginatorCert |= (certEntity == CertValidator::CertEntity::ORIGINATOR);
        m_IsExpectedRecipientCert |= (certEntity == CertValidator::CertEntity::RECIPIENT);
        const bool is_keyid = (!baName);
        for (const auto& it : m_ExpectedCertItems) {
            if (is_keyid) {
                if (ba_cmp(baKeyIdOrSN, it->getKeyId()) == 0) return RET_OK;
            }
            else {
                if (
                    (ba_cmp(baName, it->getName()) == 0) &&
                    (ba_cmp(baKeyIdOrSN, it->getSerialNumber()) == 0)
                ) return RET_OK;
            }
        }

        CertValidator::ExpectedCertItem* expcert_item = new CertValidator::ExpectedCertItem(certEntity);
        if (!expcert_item) return RET_UAPKI_GENERAL_ERROR;

        m_ExpectedCertItems.push_back(expcert_item);
        return expcert_item->setSignerIdentifier(baKeyIdOrSN, baName);
    }

    int toJson (
        JSON_Object* joResult,
        const char* keyName
    )
    {
        if (m_ExpectedCertItems.empty()) return RET_OK;

        int ret = RET_OK;
        JSON_Array* ja_items = nullptr;
        size_t idx = 0;

        DO_JSON(json_object_set_value(joResult, keyName, json_value_init_array()));
        ja_items = json_object_get_array(joResult, keyName);
        for (const auto& it : m_ExpectedCertItems) {
            DO_JSON(json_array_append_value(ja_items, json_value_init_object()));
            DO(itemToJson(json_array_get_object(ja_items, idx++), *it));
        }
    cleanup:
        return ret;
    }

private:
    static int itemToJson (
        JSON_Object* joResult,
        const CertValidator::ExpectedCertItem& expectedCertItem
    )
    {
        int ret = RET_OK;

        DO_JSON(json_object_set_string(joResult, "entity", CertValidator::certEntityToStr(expectedCertItem.getCertEntity())));
        if (expectedCertItem.getIdType() == CertValidator::ExpectedCertItem::IdType::CER_IDTYPE) {
            if (!expectedCertItem.getKeyId()) {
                DO_JSON(json_object_set_value(joResult, "issuer", json_value_init_object()));
                DO(nameToJson(json_object_get_object(joResult, "issuer"), expectedCertItem.getName()));
                DO(json_object_set_hex(joResult, "serialNumber", expectedCertItem.getSerialNumber()));
                DO(json_object_set_base64(joResult, "issuerBytes", expectedCertItem.getName()));
            }
            else {
                DO(json_object_set_hex(joResult, "keyId", expectedCertItem.getKeyId()));
            }
        }

    cleanup:
        return ret;
    }
};  //  end class ExpectedCerts


static int decrypt_content (
        const Pkcs7::EncryptedContentInfo& eContentInfo,
        const ByteArray* baSecretKey,
        ByteArray** baDecryptedContent
)
{
    int ret = RET_OK;
    const UapkiNS::AlgorithmIdentifier& algo = eContentInfo.contentEncryptionAlgo;

    if (algo.algorithm == string(OID_DSTU7624_256_CFB)) {
        DO(Cipher::Dstu7624::cryptData(
            algo,
            baSecretKey,
            Cipher::Direction::DECRYPT,
            eContentInfo.baEncryptedContent,
            baDecryptedContent
        ));
    }
    else if (algo.algorithm == string(OID_GOST28147_CFB)) {
        DO(Cipher::Gost28147::cryptData(
            algo,
            baSecretKey,
            Cipher::Direction::DECRYPT,
            eContentInfo.baEncryptedContent,
            baDecryptedContent
        ));
    }

cleanup:
    return ret;
}   //  decrypt_content

static int get_originator_spki (
        Cert::CerStore& cerStore,
        const Pkcs7::EnvelopedDataParser::KeyAgreeRecipientInfo& karInfo,
        ExpectedCerts& expectedCerts,
        const ByteArray** baOriginatorSpki,
        Cert::CerItem** cerOriginator
)
{
    int ret = RET_OK;
    SmartBA sba_issuer, sba_serialnumber;

    DEBUG_OUTCON(printf("kar_info.originatorType: %u\n", karInfo.getOriginatorType()));
    DEBUG_OUTCON(printf("kar_info.originator(encoded), hex: "); ba_print(stdout, karInfo.getOriginator()));
    switch (karInfo.getOriginatorType()) {
    case OriginatorIdentifierOrKey_PR_issuerAndSerialNumber:
        ret = Cert::parseIssuerAndSN(karInfo.getOriginator(), &sba_issuer, &sba_serialnumber);
        if (ret != RET_OK) return ret;
        ret = cerStore.getCertByIssuerAndSN(sba_issuer.get(), sba_serialnumber.get(), cerOriginator);
        if (ret == RET_OK) {
            *baOriginatorSpki = (*cerOriginator)->getSpki();
        }
        else if (ret == RET_UAPKI_CERT_NOT_FOUND) {
            ret = expectedCerts.add(CertValidator::CertEntity::ORIGINATOR, sba_serialnumber.get(), sba_issuer.get());
        }
        break;
    case OriginatorIdentifierOrKey_PR_subjectKeyIdentifier:
        ret = cerStore.getCertByKeyId(karInfo.getOriginator(), cerOriginator);
        if (ret == RET_OK) {
            *baOriginatorSpki = (*cerOriginator)->getSpki();
        }
        else if (ret == RET_UAPKI_CERT_NOT_FOUND) {
            ret = expectedCerts.add(CertValidator::CertEntity::ORIGINATOR, karInfo.getOriginator(), nullptr);
        }
        break;
    case OriginatorIdentifierOrKey_PR_originatorKey:
        *baOriginatorSpki = karInfo.getOriginator();
        break;
    default:
        ret = RET_UAPKI_INVALID_PARAMETER;
    }

    return ret;
}   //  get_originator_spki

static int get_recipekeyid (
        Cert::CerStore& cerStore,
        const Pkcs7::EnvelopedDataParser::KeyAgreeRecipientIdentifier& karId,
        ExpectedCerts& expectedCerts,
        ByteArray** baRecipEKeyId,
        Cert::CerItem** cerRecipient
)
{
    int ret = RET_OK;
    SmartBA sba_issuer, sba_serialnumber;

    DEBUG_OUTCON(printf("karId.type: %u\n", karId.getType()));
    switch (karId.getType()) {
    case KeyAgreeRecipientIdentifier_PR_issuerAndSerialNumber:
        ret = karId.toIssuerAndSN(&sba_issuer, &sba_serialnumber);
        if (ret != RET_OK) return ret;
        ret = cerStore.getCertByIssuerAndSN(sba_issuer.get(), sba_serialnumber.get(), cerRecipient);
        if (ret == RET_OK) {
            *baRecipEKeyId = ba_copy_with_alloc((*cerRecipient)->getKeyId(), 0, 0);
            ret = (*baRecipEKeyId) ? RET_OK : RET_UAPKI_GENERAL_ERROR;
        }
        else if (ret == RET_UAPKI_CERT_NOT_FOUND) {
            ret = expectedCerts.add(CertValidator::CertEntity::RECIPIENT, sba_serialnumber.get(), sba_issuer.get());
        }

        break;
    case KeyAgreeRecipientIdentifier_PR_rKeyId:
        ret = karId.toRecipientKeyId(baRecipEKeyId);
        break;
    default:
        ret = RET_UAPKI_INVALID_PARAMETER;
        break;
    }

    return ret;
}   //  get_recipekeyid

static int parse_keyencryption_algo (
        const UapkiNS::AlgorithmIdentifier& aidKeyEncryptionAlgo,
        string& oidDhKdf,
        string& oidWrapAlgo
)
{
    int ret = RET_OK;
    AlgorithmIdentifier_t* aid = nullptr;

    DEBUG_OUTCON(printf("parse_keyencryption_algo(), algorithm: '%s'\n", aidKeyEncryptionAlgo.algorithm.c_str()));
    DEBUG_OUTCON(printf("parse_keyencryption_algo(), baParameters, hex: "); ba_print(stdout, aidKeyEncryptionAlgo.baParameters));

    oidDhKdf = aidKeyEncryptionAlgo.algorithm;
    if (
        (oidDhKdf == string(OID_COFACTOR_DH_DSTU7564_KDF)) ||
        (oidDhKdf == string(OID_STD_DH_DSTU7564_KDF)) ||
        (oidDhKdf == string(OID_COFACTOR_DH_GOST34311_KDF)) ||
        (oidDhKdf == string(OID_STD_DH_GOST34311_KDF))
    ) {
        if (!aidKeyEncryptionAlgo.baParameters) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }

        CHECK_NOT_NULL(aid = (AlgorithmIdentifier_t*)asn_decode_ba_with_alloc(get_AlgorithmIdentifier_desc(), aidKeyEncryptionAlgo.baParameters));
        DO(Util::oidFromAsn1(&aid->algorithm, oidWrapAlgo));
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
    return ret;
}   //  parse_keyencryption_algo

static int result_recipientkey_to_json (
        JSON_Object* joResult,
        const Pkcs7::EnvelopedDataParser::KeyAgreeRecipientIdentifier& karId,
        const Cert::CerItem* cerRecipient
)
{
    int ret = RET_OK;
    SmartBA sba_issuer, sba_keyid, sba_serialnumber;

    DEBUG_OUTCON(printf("karId.type: %u\n", karId.getType()));
    switch (karId.getType()) {
    case KeyAgreeRecipientIdentifier_PR_issuerAndSerialNumber:
        DO(karId.toIssuerAndSN(&sba_issuer, &sba_serialnumber));
        DO_JSON(json_object_set_value(joResult, "issuer", json_value_init_object()));
        DO(nameToJson(json_object_get_object(joResult, "issuer"), sba_issuer.get()));
        DO(json_object_set_hex(joResult, "serialNumber", sba_serialnumber.get()));
        DO(json_object_set_base64(joResult, "issuerBytes", sba_issuer.get()));
        if (cerRecipient) {
            DO(json_object_set_base64(joResult, "certId", cerRecipient->getCertId()));
            DO(json_object_set_hex(joResult, "keyId", cerRecipient->getKeyId()));
        }
        break;
    case KeyAgreeRecipientIdentifier_PR_rKeyId:
        DO(karId.toRecipientKeyId(&sba_keyid));
        DO(json_object_set_hex(joResult, "keyId", sba_keyid.get()));
        break;
    default:
        break;
    }

cleanup:
    return ret;
}   //  result_recipientkey_to_json

static int result_set_list_unprattrs (
        JSON_Object* joResult,
        const char* key,
        const vector<UapkiNS::Attribute>& attrs
)
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
}   //  result_set_list_unprattrs


int uapki_decrypt (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    Cert::CerStore* cer_store = get_cerstore();
    CmStorageProxy* storage = nullptr;
    Pkcs7::EnvelopedDataParser envdata_parser;
    ExpectedCerts expected_certs;
    SmartBA sba_data, sba_decrypted, sba_keyid, sba_sessionkey;
    vector<RecipientInfo_PR> recipinfo_types;
    JSON_Array* ja_recipkeys = nullptr;
    JSON_Object* jo_content = nullptr;
    size_t idx_recipkey = 0;

    if (!cer_store) return RET_UAPKI_GENERAL_ERROR;

    const bool no_decrypt = ParsonHelper::jsonObjectGetBoolean(joParams, "noDecrypt", false);
    if (!sba_data.set(json_object_get_base64(joParams, "bytes"))) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    if (!no_decrypt) {
        storage = CmProviders::openedStorage();
        if (!storage) return RET_UAPKI_STORAGE_NOT_OPEN;
        if (!storage->keyIsSelected()) return RET_UAPKI_KEY_NOT_SELECTED;
        DO(storage->keyGetInfo(&sba_keyid));
    }
    else {
        storage = CmProviders::openedStorage();
        if (storage && storage->keyIsSelected()) {
            DO(storage->keyGetInfo(&sba_keyid));
        }
    }

    DO(envdata_parser.parse(sba_data.get()));

    DO_JSON(json_object_set_value(joResult, "content", json_value_init_object()));
    jo_content = json_object_get_object(joResult, "content");
    DO_JSON(json_object_set_string(jo_content, "type", envdata_parser.getEncryptedContentInfo().contentType.c_str()));
    DO_JSON(json_object_set_value(joResult, "recipientKeys", json_value_init_array()));
    ja_recipkeys = json_object_get_array(joResult, "recipientKeys");
    if (!envdata_parser.getUnprotectedAttrs().empty()) {
        DEBUG_OUTCON(printf("unprotectedAttrs, count: %zu\n", envdata_parser.getUnprotectedAttrs().size()));
        DO(result_set_list_unprattrs(joResult, "unprotectedAttrs", envdata_parser.getUnprotectedAttrs()));
    }

    {   //  Get originator certs
        vector<Cert::CerStore::AddedCerItem> added_ceritems;
        JSON_Array* ja_certs = nullptr;

        DO(cer_store->addCerts(
            Cert::NOT_TRUSTED,
            Cert::NOT_PERMANENT,
            envdata_parser.getOriginatorCerts(),
            added_ceritems
        ));

        DO_JSON(json_object_set_value(joResult, "originatorCertIds", json_value_init_array()));
        ja_certs = json_object_get_array(joResult, "originatorCertIds");
        for (auto& it : added_ceritems) {
            if (it.cerItem) {
                DO(json_array_append_base64(ja_certs, it.cerItem->getCertId()));
            }
        }
    }

    recipinfo_types = envdata_parser.getRecipientInfoTypes();
    for (size_t idx_recip = 0; idx_recip < recipinfo_types.size(); idx_recip++) {
        if (envdata_parser.getRecipientInfoTypes()[idx_recip] == RecipientInfo_PR_kari) {
            Pkcs7::EnvelopedDataParser::KeyAgreeRecipientInfo kar_info;
            Cert::CerItem* cer_originator = nullptr;
            const ByteArray* rba_originatorspki = nullptr;
            string s_kdfalgo, s_keywrapalgo;

            DO(envdata_parser.parseKeyAgreeRecipientInfo(idx_recip, kar_info));

            DO(get_originator_spki(
                *cer_store,
                kar_info,
                expected_certs,
                &rba_originatorspki,
                &cer_originator
            ));
            if (cer_originator) {
                DO(json_object_set_base64(joResult, "originatorCertId", cer_originator->getCertId()));
            }

            DO(parse_keyencryption_algo(kar_info.getKeyEncryptionAlgorithm(), s_kdfalgo, s_keywrapalgo));

            const vector<Pkcs7::RecipientEncryptedKey>& recip_ekeys = kar_info.getRecipientEncryptedKeys();
            DEBUG_OUTCON(printf("kar_info.getRecipientEncryptedKeys(), count: %zu\n", recip_ekeys.size()));
            for (const auto& it : recip_ekeys) {
                Pkcs7::EnvelopedDataParser::KeyAgreeRecipientIdentifier kar_id;
                Cert::CerItem* cer_recipient = nullptr;
                SmartBA sba_recipekeyid;

                DO(kar_id.parse(it.baRid));

                DO(get_recipekeyid(
                    *cer_store,
                    kar_id,
                    expected_certs,
                    &sba_recipekeyid,
                    &cer_recipient
                ));

                DO_JSON(json_array_append_value(ja_recipkeys, json_value_init_object()));
                DO(result_recipientkey_to_json(
                    json_array_get_object(ja_recipkeys, idx_recipkey++),
                    kar_id,
                    cer_recipient
                ));

                if (
                    !sba_keyid.empty() &&
                    (ba_cmp(sba_keyid.get(), sba_recipekeyid.get()) == 0)
                ) {
                    if (!no_decrypt) {
                        if (sba_decrypted.empty() && rba_originatorspki) {
                            DO(storage->keyDhUnwrapKey(
                                s_kdfalgo,
                                s_keywrapalgo,
                                rba_originatorspki,
                                kar_info.getUkm(),
                                it.baEncryptedKey,
                                &sba_sessionkey
                            ));
                            DEBUG_OUTCON(printf("storage->keyDhUnwrapKey(), vba_SessionKeys, hex: "); ba_print(stdout, sba_sessionkey.get()));

                            DO(decrypt_content(envdata_parser.getEncryptedContentInfo(), sba_sessionkey.get(), &sba_decrypted));
                            DO(json_object_set_base64(jo_content, "bytes", sba_decrypted.get()));
                        }
                    }
                    DO(json_object_set_hex(joResult, "recipientKeyId", sba_recipekeyid.get()));
                }
            }
        }
    }

    DO(expected_certs.toJson(joResult, "expectedCerts"));

    if (!no_decrypt) {
        if (sba_decrypted.empty()) {
            ret = expected_certs.isPresent() ? RET_UAPKI_CERT_NOT_FOUND : RET_UAPKI_OTHER_RECIPIENT;
        }
    }

cleanup:
    return ret;
}
