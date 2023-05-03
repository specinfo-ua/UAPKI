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
    , m_BagValue(nullptr)
    , m_EncodedBag(nullptr)
    , m_KeyId(nullptr)
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
    ba_free(m_BagValue);
    m_BagValue = nullptr;
    for (auto& it : m_BagAttributes) {
        delete it;
    }
    m_BagAttributes.clear();
    setEncodedBag(nullptr);
    ba_free(m_KeyId);
    m_KeyId = nullptr;
    m_PtrFriendlyName = nullptr;
    m_PtrLocalKeyId = nullptr;
}

int StoreBag::encodeBag (const char* password, const size_t iterations)
{
    ba_free(m_EncodedBag);
    m_EncodedBag = nullptr;
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
    m_EncodedBag = ba_data;
    ba_data = nullptr;
    DEBUG_OUTCON( printf("m_EncodedBag: "); ba_print(stdout, m_EncodedBag); )

cleanup:
    ba_free(ba_data);
    asn_free(get_SafeBag_desc(), safe_bag);
    return ret;
}

StoreAttr* StoreBag::findAttrByOid (const char* oid)
{
    for (size_t i = 0; i < m_BagAttributes.size(); i++) {
        if (oid_is_equal(m_BagAttributes[i]->oid.c_str(), oid)) {
            return m_BagAttributes[i];
        }
    }
    return nullptr;
}

bool StoreBag::getKeyInfo (StoreKeyInfo& keyInfo)
{
    char* s_param1 = nullptr;
    char* s_param2 = nullptr;
    if (bagValue() == nullptr) return false;

    if ((ba_to_hex_with_alloc(keyId(), &s_param1) == RET_OK) && s_param1) {
        keyInfo.id = string(s_param1);
        free(s_param1);
        s_param1 = nullptr;
    }

    if ((private_key_get_info(bagValue(), &s_param1, &s_param2) == RET_OK) && s_param1 && s_param2) {
        keyInfo.mechanismId = string(s_param1);
        keyInfo.parameterId = string(s_param2);
        free(s_param1);
        free(s_param2);
        s_param1 = nullptr;
        s_param2 = nullptr;
    }

    const ByteArray* ba_attrvalue = friendlyName();
    if (ba_attrvalue) {
        if ((UapkiNS::Util::decodeBmpString(ba_attrvalue, &s_param1) == RET_OK) && s_param1) {
            keyInfo.label = string(s_param1);
            free(s_param1);
            s_param1 = nullptr;
        }
    }

    ba_attrvalue = localKeyId();
    if (ba_attrvalue) {
        ByteArray* ba_data = nullptr;
        if (UapkiNS::Util::decodeOctetString(ba_attrvalue, &ba_data) == RET_OK) {
            if ((ba_to_hex_with_alloc(ba_data, &s_param1) == RET_OK) && s_param1) {
                keyInfo.application = string(s_param1);
                free(s_param1);
                s_param1 = nullptr;
            }
            ba_free(ba_data);
        }
    }

    free(s_param1);
    free(s_param2);
    return true;
}

void StoreBag::scanStdAttrs (void)
{
    StoreAttr* store_attr = findAttrByOid(OID_PKCS9_FRIENDLY_NAME);
    m_PtrFriendlyName = (store_attr) ? store_attr->data : nullptr;
    store_attr = findAttrByOid(OID_PKCS9_LOCAL_KEYID);
    m_PtrLocalKeyId = (store_attr) ? store_attr->data : nullptr;
}

void StoreBag::setBagId (const char* oid)
{
    if (oid && strlen(oid)) {
        m_BagId = string(oid);
    }
}

void StoreBag::setData (const BAG_TYPE bagType, ByteArray* bagValue)
{
    //DEBUG_OUTCON( printf("StoreBag::setData(), bagType: %d", bagType); ba_print(stdout, bagValue); )
    m_BagType = bagType;
    m_BagValue = bagValue;
    if (bagType == BAG_TYPE::KEY) {
        const int ret = keyid_by_privkeyinfo(bagValue, &m_KeyId);
        if (ret != RET_OK) {
            m_BagType = BAG_TYPE::DATA;
        }
    }
}

void StoreBag::setEncodedBag (const ByteArray* baEncoded)
{
    ba_free(m_EncodedBag);
    m_EncodedBag = (ByteArray*)baEncoded;
}

bool StoreBag::setFriendlyName (const char* utf8label)
{
    ByteArray* ba_encoded = nullptr;
    if (UapkiNS::Util::encodeBmpString(utf8label, &ba_encoded) != RET_OK) return false;

    StoreAttr* store_attr = findAttrByOid(OID_PKCS9_FRIENDLY_NAME);
    if (!store_attr) {
        store_attr = new StoreAttr(OID_PKCS9_FRIENDLY_NAME);
        if (!store_attr) {
            ba_free(ba_encoded);
            return false;
        }
        m_BagAttributes.push_back(store_attr);
    }

    DEBUG_OUTCON( printf("StoreBag::setFriendlyName(), oid: '%s', data: ", store_attr->oid.c_str()); ba_print(stdout, ba_encoded); )
    ba_free(store_attr->data);
    store_attr->data = ba_encoded;
    return true;
}

bool StoreBag::setLocalKeyID (const char* hex)
{
    ByteArray* ba_data = ba_alloc_from_hex(hex);
    if (!ba_data) return false;

    ByteArray* ba_encoded = nullptr;
    if (UapkiNS::Util::encodeOctetString(ba_data, &ba_encoded) != RET_OK) {
        ba_free(ba_data);
        return false;
    }

    ba_free(ba_data);

    StoreAttr* store_attr = findAttrByOid(OID_PKCS9_LOCAL_KEYID);
    if (!store_attr) {
        store_attr = new StoreAttr(OID_PKCS9_LOCAL_KEYID);
        if (!store_attr) {
            ba_free(ba_encoded);
            return false;
        }
        m_BagAttributes.push_back(store_attr);
    }

    DEBUG_OUTCON( printf("StoreBag::setLocalKeyID(), oid: '%s', data: ", store_attr->oid.c_str()); ba_print(stdout, ba_encoded); )
    ba_free(store_attr->data);
    store_attr->data = ba_encoded;
    return true;
}

void StoreBag::setPbes2Param (const char* oidKdf, const char* oidCipher)
{
    m_Pbes2param.kdf = oidKdf;
    m_Pbes2param.cipher = oidCipher;
}

