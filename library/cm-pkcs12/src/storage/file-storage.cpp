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

#define FILE_MARKER "cm-pkcs12/storage/file-storage.cpp"

#include <stdlib.h>
#include "file-storage.h"
#include "cm-errors.h"
#include "ba-utils.h"
#include "content-info.h"
#include "jks-buffer.h"
#include "jks-entry.h"
#include "jks-utils.h"
#include "iconv-utils.h"
#include "macros-internal.h"
#include "oids.h"
#include "oid-utils.h"
#include "pkcs5.h"
#include "pkcs12-utils.h"
#include "store-bag.h"
#include "uapki-ns-util.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
    #define DEBUG_OUTCON(expression) expression
#endif


using namespace std;
using namespace UapkiNS;


static const char* DEFAULT_BAG_CIPHER   = OID_AES256_CBC_PAD;
static const char* DEFAULT_BAG_KDF      = OID_HMAC_SHA512;
static const char* DEFAULT_MAC_ALGO     = OID_SHA512;
static const size_t DEFAULT_ITERATIONS  = 10000;


FileStorageParam::FileStorageParam (void)
{
    setDefault();
}

void FileStorageParam::setDefault (const FileStorageParam* defValues)
{
    if (defValues) {
        bagCipher = defValues->bagCipher;
        bagKdf = defValues->bagKdf;
        iterations = defValues->iterations;
        macAlgo = defValues->macAlgo;
    }
    else {
        bagCipher = DEFAULT_BAG_CIPHER;
        bagKdf = DEFAULT_BAG_KDF;
        iterations = DEFAULT_ITERATIONS;
        macAlgo = DEFAULT_MAC_ALGO;
    }
}


FileStorage::FileStorage (void)
    : m_Buffer(nullptr)
    , m_IsCreate(false)
    , m_IsOpen(false)
    , m_ReadOnly(false)
    , m_SelectedKey(nullptr)
{
    DEBUG_OUTCON(puts("FileStorage::FileStorage()"));
}

FileStorage::~FileStorage (void)
{
    DEBUG_OUTCON(puts("FileStorage::~FileStorage()"));
    reset();
}

void FileStorage::addBag (
        const StoreBag* bag
)
{
    m_SafeBags.push_back((StoreBag*)bag);
}

int FileStorage::changePassword (
        const char* password
)
{
    int ret = RET_OK;
    for (auto & it : m_SafeBags) {
        if (oid_is_equal(OID_PKCS12_P8_SHROUDED_KEY_BAG, it->bagId())) {
            ret = it->encodeBag(password, m_StorageParam.iterations);
            if (ret != RET_OK) return ret;
        }
    }

    ret = store(password);
    return ret;
}

void FileStorage::create (
        const string& fileName
)
{
    DEBUG_OUTCON(printf("FileStorage::create(fileName: '%s')\n", fileName.c_str()));
    reset();

    m_IsCreate = true;
    m_Filename = fileName;
    m_ReadOnly = false;
}

int FileStorage::decode (
        const char* password
)
{
    DEBUG_OUTCON(printf("FileStorage::decode(password = '%s')\n", password));
    int ret = decodePkcs12(password);
    DEBUG_OUTCON(printf("FileStorage::decodePkcs12(), ret: %d\n", ret));
    if (ret == RET_OK) {
        //nothing
    }
    else if (ret == RET_CM_UNSUPPORTED_MAC) {
        return ret;
    }
    else if (ret == RET_CM_INVALID_MAC) {
        char* pass_cp1251 = utf8_to_cp1251(password);
        ret = decodePkcs12(pass_cp1251);
        if (ret == RET_OK) {
            setOpen(pass_cp1251);
        }
        free(pass_cp1251);
        return ret;
    }
    else {
        ret = decodeJks(password);
        DEBUG_OUTCON(printf("FileStorage::decodeJks(), ret: %d\n", ret));
        if (ret != RET_OK) {
            ret = decodeIit(password);
            DEBUG_OUTCON(printf("FileStorage::decodeIit(), ret: %d\n", ret));
        }
        if (ret != RET_OK) {
            ret = decodePkcs8e(password);
            DEBUG_OUTCON(printf("FileStorage::decodePkcs8(), ret: %d\n", ret));
        }
    }

    if (ret == RET_OK) {
        setOpen(password);
    }
    return ret;
}

void FileStorage::deleteBag (
        const StoreBag* bag
)
{
    for (size_t i = 0; i < m_SafeBags.size(); i++) {
        if (m_SafeBags[i] == bag) {
            m_SafeBags[i] = nullptr;
            m_SafeBags.erase(m_SafeBags.begin() + i);
            delete bag;
            return;
        }
    }
}

vector<StoreBag*> FileStorage::listBags (
        const StoreBag::BAG_TYPE bagType
)
{
    vector<StoreBag*> rv_bags;
    for (auto & it : m_SafeBags) {
        if (it->bagType() == bagType) {
            rv_bags.push_back(it);
        }
    }
    return rv_bags;
}

void FileStorage::loadFromBuffer (
        ByteArray* baEncoded,
        const bool readOnly
)
{
    DEBUG_OUTCON(printf("FileStorage::loadFromBuffer(buf-size: %d, readOnly: %d)\n", (int)ba_get_len(baEncoded), readOnly));
    reset();

    m_Buffer = baEncoded;
    m_ReadOnly = readOnly;
}

int FileStorage::loadFromFile (
        const string& fileName,
        const bool readOnly
)
{
    DEBUG_OUTCON(printf("FileStorage::loadFromFile(fileName: '%s', readOnly: %d)\n", fileName.c_str(), readOnly));
    reset();

    const int ret = ba_alloc_from_file(fileName.c_str(), &m_Buffer);
    if (ret == RET_OK) {
        m_Filename = fileName;
        m_ReadOnly = readOnly;
    }
    return ret;
}

void FileStorage::reset (void)
{
    ba_free(m_Buffer);
    m_Buffer = nullptr;
    m_Filename.clear();
    m_IsCreate = false;
    m_IsOpen = false;
    for (auto & it : m_Password) {
        it = 0;
    }
    m_Password.clear();
    m_ReadOnly = false;
    for (auto & it : m_SafeBags) {
        delete it;
    }
    m_SafeBags.clear();
    m_SelectedKey = nullptr;
}

void FileStorage::selectKey (
        const StoreBag* storeBagKey
)
{
    m_SelectedKey = (StoreBag*)storeBagKey;
}

int FileStorage::store (
        const char* password
)
{
    DEBUG_OUTCON(puts("FileStorage::store()"));
    ba_free(m_Buffer);
    m_Buffer = nullptr;

    if (m_SafeBags.empty()) {
        DEBUG_OUTCON(puts("FileStorage::store(), empty SafeBags - remove file"));
        return saveBuffer();
    }

    if (password) {
        m_Password = string(password);
    }

    int ret = RET_OK;
    SmartBA sba_encoded;
    DO(encodeAuthenticatedSafe(m_Password.c_str(), &sba_encoded));
    DEBUG_OUTCON(printf("FileStorage::store(), ba_encoded: '\n"); ba_print(stdout, sba_encoded.get()));
    DO(encodePfx(m_Password.c_str(), sba_encoded.get()));
    DO(saveBuffer());

cleanup:
    return ret;
}

int FileStorage::decodeIit (
        const char* password
)
{
    DEBUG_OUTCON(printf("FileStorage::decodeIit(password = '%s')\n", password));
    int ret = RET_OK;
    ByteArray* ba_privkeys[2] = { nullptr, nullptr };
    StoreBag* store_bag = nullptr;

    DO(pkcs8_decrypt(m_Buffer, password, &ba_privkeys[0], nullptr, nullptr));
    DO(pkcs12_iit_read_kep_key(ba_privkeys[0], &ba_privkeys[1]));

    for (size_t i = 0; i < 2; i++) {
        if (!ba_privkeys[i])
            continue;

        DEBUG_OUTCON(printf("pkcs8_decrypt(iit), ba_privkey[%d]: ", (int)i); ba_print(stdout, ba_privkeys[i]));

        CHECK_NOT_NULL(store_bag = new StoreBag());
        store_bag->setBagId(string(OID_PKCS12_P8_SHROUDED_KEY_BAG));
        store_bag->setData(StoreBag::BAG_TYPE::KEY, ba_privkeys[i]);

        ba_privkeys[i] = nullptr;
        addBag(store_bag);
        store_bag = nullptr;
    }

    m_ReadOnly = true;

cleanup:
    if (store_bag) delete store_bag;
    ba_free(ba_privkeys[0]);
    ba_free(ba_privkeys[1]);
    return ret;
}

int FileStorage::decodeJks (
        const char* password
)
{
    DEBUG_OUTCON(printf("FileStorage::decodeJks(password = '%s')\n", password));
    int ret = RET_OK;
    StoreBag* store_bag = nullptr;
    JksBufferCtx* jks_buffer = nullptr;
    JksEntry* jks_entry = nullptr;
    ByteArray* ba_privkeys[2] = { nullptr, nullptr };
    ByteArray* ba_data = nullptr;
    SmartBA sba_hashact, sba_hashexp;
    uint32_t jks_version = 0, cnt_entries = 0;

    CHECK_NOT_NULL(jks_buffer = jks_buffer_alloc_ba(m_Buffer));
    DO(jks_read_header(jks_buffer, &jks_version, &cnt_entries));
    if (cnt_entries == 0) {
        SET_ERROR(RET_CM_BAG_NOT_FOUND);
    }

    for (uint32_t i = 0; i < cnt_entries; i++) {
        DO(jks_entry_read(jks_buffer, jks_version, &jks_entry));

        if (jks_entry->entry_type == PRIVATE_KEY_ENTRY) {
            // Private key for signing
            CHECK_NOT_NULL(store_bag = new StoreBag());
            DO(jks_decrypt_key(jks_entry->entry.key, password, &ba_privkeys[0]));
            store_bag->setData(StoreBag::BAG_TYPE::KEY, ba_privkeys[0]);
            if (jks_entry->alias) {
                store_bag->setFriendlyName(jks_entry->alias);
                store_bag->scanStdAttrs();
            }
            addBag(store_bag);
            store_bag = nullptr;
            // Private key for decryption
            if (pkcs12_iit_read_kep_key(ba_privkeys[0], &ba_privkeys[1]) == RET_OK) {
                ba_privkeys[0] = nullptr;
                CHECK_NOT_NULL(store_bag = new StoreBag());
                store_bag->setData(StoreBag::BAG_TYPE::KEY, ba_privkeys[1]);
                if (jks_entry->alias) {
                    store_bag->setFriendlyName(jks_entry->alias);
                    store_bag->scanStdAttrs();
                }
                addBag(store_bag);
                store_bag = nullptr;
            }
            ba_privkeys[0] = nullptr;
            ba_privkeys[1] = nullptr;

            //  Add cert-bags
            if (jks_entry->entry_exts) {
                for (uint32_t i = 0; i < jks_entry->entry_exts->count; i++) {
                    JksCertificate* jks_cert = jks_entry->entry_exts->list[i];
                    if (jks_cert && (strcmp(jks_cert->type, "X.509") == 0) && (ba_get_len(jks_cert->encoded) > 0)) {
                        CHECK_NOT_NULL(ba_data = ba_copy_with_alloc(jks_cert->encoded, 0, 0));
                        CHECK_NOT_NULL(store_bag = new StoreBag());
                        store_bag->setData(StoreBag::BAG_TYPE::CERT, ba_data);
                        ba_data = nullptr;
                        addBag(store_bag);
                        store_bag = nullptr;
                    }
                }
            }
        }

        jks_entry_free(jks_entry);
        jks_entry = nullptr;
    }

    DO(jks_buffer_get_hash(jks_buffer, &sba_hashexp));
    DO(jks_buffer_get_body(jks_buffer, &ba_data));
    DO(jks_hash_store(password, ba_data, &sba_hashact));

    if (ba_cmp(sba_hashexp.get(), sba_hashact.get())) {
        SET_ERROR(RET_CM_INVALID_PASSWORD);
    }

cleanup:
    if (store_bag) delete store_bag;
    jks_buffer_free(jks_buffer);
    jks_entry_free(jks_entry);
    ba_free(ba_data);
    ba_free(ba_privkeys[0]);
    ba_free(ba_privkeys[1]);
    return ret;
}
int FileStorage::decodePkcs12 (
        const char* password
)
{
    DEBUG_OUTCON(printf("FileStorage::decodePkcs12(password = '%s')\n", password));
    int ret = RET_OK;
    SmartBA sba_authsafe, sba_mac_actual, sba_mac_calc;

    PFX_t* pfx = (PFX_t*)asn_decode_ba_with_alloc(get_PFX_desc(), m_Buffer);
    if (!pfx) {
        SET_ERROR(RET_CM_INVALID_PARAMETER);
    }

    if (pfx->macData == nullptr) {
        SET_ERROR(RET_CM_WITHOUT_MAC);
    }

    DO(pkcs12_get_data_and_calc_mac(pfx, password, &m_StorageParam.macAlgo, &m_StorageParam.iterations, &sba_authsafe, &sba_mac_calc));
    DO(asn_OCTSTRING2ba(&pfx->macData->mac.digest, &sba_mac_actual));
    DEBUG_OUTCON(printf("FileStorage::decodePkcs12(),\n ba_calc_mac: "); ba_print(stdout, sba_mac_calc.get()));
    DEBUG_OUTCON(printf(" ba_actual_mac: ");ba_print(stdout, sba_mac_actual.get()));
    if (ba_cmp(sba_mac_calc.get(), sba_mac_actual.get())) {
        SET_ERROR(RET_CM_INVALID_MAC);
    }

    DO(readContents(sba_authsafe.get(), password));

cleanup:
    asn_free(get_PFX_desc(), pfx);
    return ret;
}

int FileStorage::decodePkcs8e (
        const char* password
)
{
    DEBUG_OUTCON(printf("FileStorage::decodePkcs8(password = '%s')\n", password));
    int ret = RET_OK;
    ByteArray* ba_privkey = nullptr;
    StoreBag* store_bag = nullptr;

    DO(pkcs8_decrypt(m_Buffer, password, &ba_privkey, nullptr, nullptr));
    DEBUG_OUTCON(printf("pkcs8_decrypt(), ba_privkey: ");ba_print(stdout, ba_privkey));

    CHECK_NOT_NULL(store_bag = new StoreBag());
    store_bag->setBagId(string(OID_PKCS12_P8_SHROUDED_KEY_BAG));
    store_bag->setData(StoreBag::BAG_TYPE::KEY, ba_privkey);
    ba_privkey = nullptr;
    addBag(store_bag);
    store_bag = nullptr;

    m_ReadOnly = true;

cleanup:
    if (store_bag) delete store_bag;
    ba_free(ba_privkey);
    return ret;
}

int FileStorage::readContents (
        const ByteArray* baAuthsafe,
        const char* password
)
{
    int ret = RET_OK;
    AuthenticatedSafe_t* authenticated_safe = nullptr;

    CHECK_NOT_NULL(authenticated_safe = (AuthenticatedSafe_t*)asn_decode_ba_with_alloc(get_AuthenticatedSafe_desc(), baAuthsafe));
    for (int i = 0; i < authenticated_safe->list.count; i++) {
        const ContentInfo_t* content = authenticated_safe->list.array[i];
        CinfoType type = CONTENT_UNKNOWN;
        SmartBA sba_data;

        DO(cinfo_get_type(content, &type));
        if (type == CONTENT_DATA) {
            DO(cinfo_get_data(content, &sba_data));
            DO(readSafeContents(sba_data.get(), password));
        } else if (type == CONTENT_ENCRYPTED) {
            DO(pkcs12_read_encrypted_content(content, password, &sba_data));
            DO(readSafeContents(sba_data.get(), password));
        } else {
            SET_ERROR(RET_CM_UNSUPPORTED_CONTENT_INFO);
        }
    }

cleanup:
    asn_free(get_AuthenticatedSafe_desc(), authenticated_safe);
    return ret;
}

static int readBagAttributes (
        const struct Attributes* bagAttributes,
        vector<StoreAttr*>& attrs
) {
    if (!bagAttributes) return RET_OK;

    int ret = RET_OK;
    char* oid = nullptr;
    StoreAttr* store_attr = nullptr;
    for (int i = 0; i < bagAttributes->list.count; i++) {
        const Attribute_t* attr = bagAttributes->list.array[i];
        CHECK_NOT_NULL(attr);
        DO(asn_oid_to_text(&attr->type, &oid));
        if (oid) {
            store_attr = new StoreAttr(oid);
            free(oid);
            oid = nullptr;
        }
        else {
            SET_ERROR(RET_CM_INVALID_SAFE_BAG);
        }

        if (attr->value.list.count > 0) {
            DO(asn_encode_ba(get_ANY_desc(), attr->value.list.array[0], &store_attr->data));
        }
        attrs.push_back(store_attr);
        store_attr = nullptr;
    }

cleanup:
    free(oid);
    delete store_attr;
    if (ret != RET_OK) {
        for (size_t i = 0; i < attrs.size(); i++) {
            delete attrs[i];
        }
        attrs.clear();
    }
    return ret;
}

int FileStorage::readSafeContents (
        const ByteArray* baSafeContents,
        const char* password
)
{
    int ret = RET_OK;
    SafeContents_t* safe_contents = nullptr;
    StoreBag* store_bag = nullptr;
    ByteArray* ba_data = nullptr;
    string s_oidbag;
    char* oid = nullptr;
    char* oid_cipher = nullptr;

    DEBUG_OUTCON(printf("FileStorage::readSafeContents(), baSafeContents: "); ba_print(stdout, baSafeContents));
    CHECK_NOT_NULL(safe_contents = (SafeContents_t*)asn_decode_ba_with_alloc(get_SafeContents_desc(), baSafeContents));
    DEBUG_OUTCON(printf("count safe_contents: %d\n", safe_contents->list.count));
    for (int i = 0; i < safe_contents->list.count; i++) {
        CHECK_NOT_NULL(store_bag = new StoreBag());

        const SafeBag_t* safe_bag = safe_contents->list.array[i];
        DO(Util::oidFromAsn1(&safe_bag->bagId, s_oidbag));
        DEBUG_OUTCON(printf("FileStorage::readSafeContents(), SafeBag.oid: %s\n", s_oidbag.c_str()));
        if (!s_oidbag.empty()) {
            store_bag->setBagId(s_oidbag);
        }
        else {
            SET_ERROR(RET_CM_INVALID_SAFE_BAG);
        }

        if (oid_is_equal(OID_PKCS12_P8_SHROUDED_KEY_BAG, store_bag->bagId())) {
            DO(pkcs12_read_shrouded_key_bag(&safe_bag->bagValue, password, &ba_data, &oid, &oid_cipher));
            store_bag->setData(StoreBag::BAG_TYPE::KEY, ba_data);
            if (oid) {
                //  PBES2
                store_bag->setPbes2Param(
                    checkHashOid(oid, m_StorageParam.bagKdf),
                    checkCipherOid(oid_cipher, m_StorageParam.bagCipher)
                );
            }
            else {
                //  PBE
                store_bag->setPbes2Param(
                    m_StorageParam.bagKdf,
                    oid_is_equal(OID_PBE_WITH_SHA1_TDES_CBC, oid_cipher)
                        ? OID_DES_EDE3_CBC : checkCipherOid(oid_cipher, m_StorageParam.bagCipher)
                );
            }
            free(oid);
            oid = nullptr;
            free(oid_cipher);
            oid_cipher = nullptr;
        }
        else if (oid_is_equal(OID_PKCS12_CERT_BAG, store_bag->bagId())) {
            bool is_sdsicert;
            DO(pkcs12_read_cert_bag(&safe_bag->bagValue, &ba_data, &is_sdsicert));
            if (is_sdsicert) {
                DO(asn_encode_ba(get_ANY_desc(), &safe_bag->bagValue, &ba_data));
            }
            store_bag->setData(!is_sdsicert ? StoreBag::BAG_TYPE::CERT : StoreBag::BAG_TYPE::DATA, ba_data);
        }
        else if (oid_is_parent(OID_PKCS12_BAGTYPES, store_bag->bagId())) {
            DO(asn_encode_ba(get_ANY_desc(), &safe_bag->bagValue, &ba_data));
            store_bag->setData(StoreBag::BAG_TYPE::DATA, ba_data);
        }
        else {
            SET_ERROR(RET_CM_INVALID_SAFE_BAG);
        }
        ba_data = nullptr;

        DO(readBagAttributes(safe_bag->bagAttributes, store_bag->bagAttributes()));
        DEBUG_OUTCON(printf("bagType: %d  bagId: '%s'\n", store_bag->bagType(), store_bag->bagId()); ba_print(stdout, store_bag->bagValue()));

        DO(asn_encode_ba(get_SafeBag_desc(), safe_bag, &ba_data));
        store_bag->setEncodedBag(ba_data);
        ba_data = nullptr;

        store_bag->scanStdAttrs();
        addBag(store_bag);
        store_bag = nullptr;
    }

cleanup:
    if (store_bag) delete store_bag;
    free(oid);
    ba_free(ba_data);
    asn_free(get_SafeContents_desc(), safe_contents);
    return ret;
}

void FileStorage::setOpen (
        const char* password
)
{
    m_Password = string(password);
    m_IsOpen = true;
}

int FileStorage::encodeAuthenticatedSafe (
        const char* password,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    AuthenticatedSafe_t* authenticated_safe = (AuthenticatedSafe_t*)calloc(1, sizeof(AuthenticatedSafe_t));
    if (!authenticated_safe) return RET_CM_GENERAL_ERROR;

    SmartBA sba_data, sba_encrypted;
    vector<const ByteArray*> bags_to_encrypt;
    for (size_t i = 0; i < m_SafeBags.size(); i++) {
        StoreBag* p_safebag = m_SafeBags[i];
        DEBUG_OUTCON(printf("p_safebag->bagId(): %s\n", p_safebag->bagId()));
        if (oid_is_equal(OID_PKCS12_P8_SHROUDED_KEY_BAG, p_safebag->bagId())) {
            DEBUG_OUTCON(printf("SafeBags[%d]->encodedBag(): '\n", (int)i); ba_print(stdout, p_safebag->encodedBag()));
            DO(pkcs12_add_p7data_single_safecontent(authenticated_safe, p_safebag->encodedBag()));
        }
        else {
            bags_to_encrypt.push_back(p_safebag->encodedBag());
        }
    }

    if (!bags_to_encrypt.empty()) {
        DO(pkcs12_write_safecontents(bags_to_encrypt.data(), bags_to_encrypt.size(), &sba_data));
        DEBUG_OUTCON(printf("pkcs12_write_safecontents(), ba_data: '\n"); ba_print(stdout, sba_data.get()));
        DO(pkcs8_pbes2_encrypt(sba_data.get(), password, m_StorageParam.iterations,
                m_StorageParam.bagKdf, m_StorageParam.bagCipher, &sba_encrypted));
        DEBUG_OUTCON(printf("pkcs8_pbes2_encrypt(), ba_encrypted: '\n"); ba_print(stdout, sba_encrypted.get()));
        DO(pkcs12_add_p7encrypteddata(authenticated_safe, sba_encrypted.get()));
    }

    DO(asn_encode_ba(get_AuthenticatedSafe_desc(), authenticated_safe, baEncoded));

cleanup:
    asn_free(get_AuthenticatedSafe_desc(), authenticated_safe);
    return ret;
}

int FileStorage::encodePfx (
        const char* password,
        const ByteArray* baEncoded
)
{
    int ret = RET_OK;
    MacData_t* mac_data = nullptr;

    DO(pkcs12_gen_macdata(password, m_StorageParam.macAlgo, m_StorageParam.iterations, baEncoded, &mac_data));
    DO(pkcs12_write_pfx(baEncoded, mac_data, &m_Buffer));

    DEBUG_OUTCON(printf("FileStorage::encodePfx(), this.m_Buffer: "); ba_print(stdout, m_Buffer));

cleanup:
    asn_free(get_MacData_desc(), mac_data);
    return ret;
}

int FileStorage::saveBuffer (void)
{
    int ret = RET_OK;
    if (!m_Filename.empty()) {
        if (ba_get_len(m_Buffer) > 0) {
            ret = ba_to_file(m_Buffer, m_Filename.c_str());
        }
        else {
            ret = delete_file(m_Filename.c_str());
        }
    }
    return ret;
}

const char* FileStorage::checkCipherOid (
        const char* oid,
        const char* oidDefault
)
{
    static const int N = 6;
    static const char* SUPPORTED_CIPHERS[N] = {
        OID_GOST28147_ECB, OID_GOST28147_CFB,
        OID_AES128_CBC_PAD, OID_AES192_CBC_PAD, OID_AES256_CBC_PAD,
        OID_DES_EDE3_CBC
    };

    if (oid != NULL) {
        for (size_t i = 0; i < N; i++) {
            if (oid_is_equal(SUPPORTED_CIPHERS[i], oid)) return SUPPORTED_CIPHERS[i];
        }
    }
    return oidDefault;
}

const char* FileStorage::checkHashOid (
        const char* oid,
        const char* oidDefault
)
{
    static const int N = 22;
    static const char* SUPPORTED_HASHES[N] = {
        OID_GOST34311, OID_HMAC_GOST34311,
        OID_DSTU7564_256, OID_DSTU7564_384, OID_DSTU7564_512,
        OID_DSTU7564_256_MAC, OID_DSTU7564_384_MAC, OID_DSTU7564_512_MAC,
        OID_SHA1, OID_SHA256, OID_SHA384, OID_SHA512,
        OID_HMAC_SHA1, OID_HMAC_SHA256, OID_HMAC_SHA384, OID_HMAC_SHA512,
        OID_SHA3_256, OID_SHA3_384, OID_SHA3_512,
        OID_HMAC_SHA3_256, OID_HMAC_SHA3_384, OID_HMAC_SHA3_512
    };

    if (oid != NULL) {
        for (size_t i = 0; i < N; i++) {
            if (oid_is_equal(SUPPORTED_HASHES[i], oid)) return SUPPORTED_HASHES[i];
        }
    }
    return oidDefault;
}
