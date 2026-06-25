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

#define FILE_MARKER "cm-pkcs12/storage/store-bag.cpp"

#include "store-bag.h"
#include "cm-errors.h"
#include "iconv-utils.h"
#include "macros-internal.h"
#include "oids.h"
#include "oid-utils.h"
#include "pkcs5.h"
#include "pkcs12-utils.h"
#include "private-key.h"
#include "uapki-ns-util.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
    #define DEBUG_OUTCON(expression) expression
#endif


using namespace std;
using namespace UapkiNS;


static int set_bag_attributes (const vector<StoreAttr*>& storeAttrs, Attributes** bagAttributes)
{
    if (storeAttrs.empty()) return RET_OK;

    int ret = RET_OK;
    ANY_t* any = nullptr;
    Attribute_t* attr = nullptr;
    Attributes* dst_attrs = (Attributes*)calloc(1, sizeof(Attributes));
    if (!dst_attrs) {
        SET_ERROR(RET_CM_GENERAL_ERROR);
    }

    for (size_t i = 0; i < storeAttrs.size(); i++) {
        const StoreAttr* src_attr = storeAttrs[i];
        attr = (Attribute_t*)calloc(1, sizeof(Attribute_t));
        if (!attr) {
            SET_ERROR(RET_CM_GENERAL_ERROR);
        }

        DO(asn_set_oid_from_text(src_attr->oid.c_str(), &attr->type));
        CHECK_NOT_NULL(any = (ANY_t*)asn_decode_ba_with_alloc(get_ANY_desc(), src_attr->data));

        DO(ASN_SET_ADD(&attr->value.list, any));
        any = nullptr;
        DO(ASN_SET_ADD(&dst_attrs->list, attr));
        attr = nullptr;
    }

    *bagAttributes = dst_attrs;
    dst_attrs = nullptr;

cleanup:
    asn_free(get_ANY_desc(), any);
    asn_free(get_Attribute_desc(), attr);
    asn_free(get_Attributes_desc(), dst_attrs);
    return ret;
}



StoreBag::StoreBag (void)
    : m_BagType(BAG_TYPE::UNDEFINED)
    , m_PtrFriendlyName(nullptr)
    , m_PtrLocalKeyId(nullptr)
{
    m_Pbes2param.kdf = nullptr;
    m_Pbes2param.cipher = nullptr;
}

StoreBag::~StoreBag (void)
{
    m_BagType = BAG_TYPE::UNDEFINED;
    m_BagId.clear();
    for (auto& it : m_BagAttributes) {
        delete it;
    }
    m_BagAttributes.clear();
    setEncodedBag(nullptr);
    m_KeyId.clear();
    m_KeyId2.clear();
    m_PtrFriendlyName = nullptr;
    m_PtrLocalKeyId = nullptr;
}

int StoreBag::encodeBag (
        const char* password,
        const size_t iterations
)
{
    m_EncodedBag.clear();
    SafeBag_t* safe_bag = (SafeBag_t*)calloc(1, sizeof(SafeBag_t));
    if (!safe_bag) return RET_CM_GENERAL_ERROR;

    int ret = RET_OK;
    ByteArray* ba_data = nullptr;

    DO(asn_set_oid_from_text(bagId(), &safe_bag->bagId));

    DEBUG_OUTCON( printf("bagValue:"); ba_print(stdout, bagValue()); )
    if (oid_is_equal(OID_PKCS12_P8_SHROUDED_KEY_BAG, bagId())) {
        DO(pkcs8_pbes2_encrypt(bagValue(), password, iterations, m_Pbes2param.kdf, m_Pbes2param.cipher, &ba_data));
        DEBUG_OUTCON( printf("PKCS12_P8_SHROUDED_KEY_BAG, ba_data:"); ba_print(stdout, ba_data); )
        DO(asn_decode_ba(get_ANY_desc(), &safe_bag->bagValue, ba_data));
        ba_free(ba_data);
        ba_data = nullptr;
    }
    else if (oid_is_equal(OID_PKCS12_CERT_BAG, bagId())) {
        DO(pkcs12_write_cert_bag(bagValue(), &ba_data));
        DEBUG_OUTCON( printf("PKCS12_CERT_BAG, ba_data:"); ba_print(stdout, ba_data); )
        DO(asn_decode_ba(get_ANY_desc(), &safe_bag->bagValue, ba_data));
        ba_free(ba_data);
        ba_data = nullptr;
    }
    else {
        DO(asn_decode_ba(get_ANY_desc(), &safe_bag->bagValue, bagValue()));
    }

    DO(set_bag_attributes(m_BagAttributes, &safe_bag->bagAttributes));

    DO(asn_encode_ba(get_SafeBag_desc(), safe_bag, &ba_data));
    m_EncodedBag.set(ba_data);
    ba_data = nullptr;
    DEBUG_OUTCON( printf("EncodedBag: "); ba_print(stdout, m_EncodedBag.get()); )

cleanup:
    ba_free(ba_data);
    asn_free(get_SafeBag_desc(), safe_bag);
    return ret;
}

bool StoreBag::equalKeyId (
        const ByteArray* baKeyId
) const
{
    return (
        ((ba_get_len(keyId2()) > 0) && (ba_cmp(keyId2(), baKeyId) == 0)) ||
        (ba_cmp(keyId(), baKeyId) == 0)
    );
}

StoreAttr* StoreBag::findBagAttr (
        const char* oid
)
{
    for (size_t i = 0; i < m_BagAttributes.size(); i++) {
        if (oid_is_equal(m_BagAttributes[i]->oid.c_str(), oid)) {
            return m_BagAttributes[i];
        }
    }
    return nullptr;
}

bool StoreBag::getKeyInfo (
        StoreKeyInfo& keyInfo
)
{
    char* s_param = nullptr;
    if (bagValue() == nullptr) return false;

    if ((ba_to_hex_with_alloc(keyId(), &s_param) == RET_OK) && s_param) {
        keyInfo.id = string(s_param);
        free(s_param);
        s_param = nullptr;
    }

    keyInfo.mechanismId = mechanismId();
    keyInfo.parameterId = parameterId();

    SmartBA sba_pubkey, sba_spki;
    if ((private_key_get_spki(bagValue(), &sba_spki) == RET_OK) &&
        (spki_get_pubkey(sba_spki.get(), &sba_pubkey) == RET_OK)) {
        if ((ba_to_base64_with_alloc(sba_pubkey.get(), &s_param) == RET_OK) && s_param) {
            keyInfo.publicKey = string(s_param);
            free(s_param);
            s_param = nullptr;
        }
    }

    const ByteArray* ba_attrvalue = friendlyName();
    if (ba_attrvalue) {
        (void)Util::decodeBmpString(ba_attrvalue, keyInfo.label);
    }

    ba_attrvalue = localKeyId();
    if (ba_attrvalue) {
        SmartBA sba_data;
        if (Util::decodeOctetString(ba_attrvalue, &sba_data) == RET_OK) {
            if ((ba_to_hex_with_alloc(sba_data.get(), &s_param) == RET_OK) && s_param) {
                keyInfo.application = string(s_param);
                free(s_param);
                s_param = nullptr;
            }
        }
    }

    free(s_param);
    return true;
}

void StoreBag::scanStdAttrs (void)
{
    StoreAttr* store_attr = findBagAttr(OID_PKCS9_FRIENDLY_NAME);
    m_PtrFriendlyName = (store_attr) ? store_attr->data : nullptr;
    store_attr = findBagAttr(OID_PKCS9_LOCAL_KEYID);
    m_PtrLocalKeyId = (store_attr) ? store_attr->data : nullptr;
}

StoreAttr* StoreBag::setBagAttr (
        const char* oid
)
{
    StoreAttr* rv_storeattr = findBagAttr(oid);
    if (!rv_storeattr) {
        rv_storeattr = new StoreAttr(oid);
        if (!rv_storeattr) {
            return nullptr;
        }
        m_BagAttributes.push_back(rv_storeattr);
    }
    else {
        ba_free(rv_storeattr->data);
        rv_storeattr->data = nullptr;
    }
    return rv_storeattr;
}

bool StoreBag::setBagId (
        const string& aBagId
)
{
    m_BagId = aBagId;
    return (!m_BagId.empty());
}

void StoreBag::setData (
        const BAG_TYPE aBagType,
        ByteArray* aBagValue
)
{
    DEBUG_OUTCON( printf("StoreBag::setData(), bagType: %d", aBagType); ba_print(stdout, aBagValue); )
    m_BagType = aBagType;
    m_BagValue.set(aBagValue);
    if (aBagType == BAG_TYPE::KEY) {
        m_BagType = BAG_TYPE::DATA;
        char* s_param1 = nullptr;
        char* s_param2 = nullptr;
        if ((private_key_get_info(aBagValue, &s_param1, &s_param2) == RET_OK) && s_param1 && s_param2) {
            m_MechanismId = string(s_param1);
            m_ParameterId = string(s_param2);
            free(s_param1);
            free(s_param2);
            s_param1 = nullptr;
            s_param2 = nullptr;
            if (keyid_by_privkeyinfo(aBagValue, &m_KeyId) == RET_OK) {
                m_BagType = BAG_TYPE::KEY;
                if (oid_is_parent(OID_DSTU4145_WITH_DSTU7564, m_MechanismId.c_str()) ||
                    oid_is_parent(OID_DSTU4145_WITH_GOST3411, m_MechanismId.c_str())
                ) {
                    (void)StoreBag::keyIdFromPrivKeyInfo(HASH_ALG_DSTU7564_256, aBagValue, &m_KeyId2);
                }
            }
        }
    }
}

void StoreBag::setEncodedBag (
        const ByteArray* baEncoded
)
{
    m_EncodedBag.clear();
    m_EncodedBag.set((ByteArray*)baEncoded);
}

bool StoreBag::setFriendlyName (
        const char* utf8label
)
{
    SmartBA sba_encoded;
    if (Util::encodeBmpString(utf8label, &sba_encoded) != RET_OK) return false;

    StoreAttr* store_attr = setBagAttr(OID_PKCS9_FRIENDLY_NAME);
    if (!store_attr) return false;

    DEBUG_OUTCON(printf("StoreBag::setFriendlyName(), oid: '%s', data: ", store_attr->oid.c_str()); ba_print(stdout, sba_encoded.get()); )
    store_attr->data = sba_encoded.pop();
    return true;
}

bool StoreBag::setKeyId (
        const ByteArray* baKeyId
)
{
    if (ba_get_len(baKeyId) == 0) return true;

    m_KeyId.clear();
    return m_KeyId.set(ba_copy_with_alloc(baKeyId, 0, ba_get_len(baKeyId)));
}

void StoreBag::setPbes2Param (
        const char* oidKdf,
        const char* oidCipher
)
{
    m_Pbes2param.kdf = oidKdf;
    m_Pbes2param.cipher = oidCipher;
}

bool StoreBag::certContainKeyId (
        const ByteArray* baEncoded,
        const ByteArray* baKeyId
)
{

    int ret = RET_OK;
    Certificate_t* cert = nullptr;
    string s_keyalgo;
    SmartBA sba_keyid, sba_keyid2, sba_pubkey;
    HashAlg hash_alg = HASH_ALG_SHA1;
    bool is_contain = false;

    cert = (Certificate_t*)asn_decode_ba_with_alloc(get_Certificate_desc(), baEncoded);
    if (!cert) return false;

    DO(Util::oidFromAsn1(&cert->tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm, s_keyalgo));
    DO(asn_BITSTRING2ba(&cert->tbsCertificate.subjectPublicKeyInfo.subjectPublicKey, &sba_pubkey));

    if (oid_is_parent(OID_DSTU4145_WITH_GOST3411, s_keyalgo.c_str())) {
        hash_alg = HASH_ALG_GOST34311;
    }
    DO(::hash(hash_alg, sba_pubkey.get(), &sba_keyid));

    is_contain = (ba_cmp(sba_keyid.get(), baKeyId) == 0);
    if (!is_contain && (hash_alg == HASH_ALG_GOST34311)) {
        DO(::hash(HASH_ALG_DSTU7564_256, sba_pubkey.get(), &sba_keyid2));
        is_contain = (ba_cmp(sba_keyid2.get(), baKeyId) == 0);
    }

cleanup:
    asn_free(get_Certificate_desc(), cert);
    return is_contain;
}

bool StoreBag::keyIdFromPrivKeyInfo (
        const HashAlg hashAlg,
        const ByteArray* baPrivKeyInfo,
        ByteArray** baKeyId
)
{
    SmartBA sba_pubkey, sba_spki;
    if (private_key_get_spki(baPrivKeyInfo, &sba_spki) != RET_OK) return false;
    if (spki_get_subject_publickey(sba_spki.get(), &sba_pubkey) != RET_OK) return false;
    if (::hash(hashAlg, sba_pubkey.get(), baKeyId) != RET_OK) return false;
    return true;
}
