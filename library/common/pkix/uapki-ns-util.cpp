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

#define FILE_MARKER "common/pkix/uapki-ns-util.cpp"

#include "uapki-ns-util.h"
#include "iconv-utils.h"
#include "macros-internal.h"
#include "oids.h"
#include "oid-utils.h"
#include "time-util.h"
#include "uapki-errors.h"


using namespace std;


namespace UapkiNS {


constexpr uint64_t UTC_TIME_MS_END  = 2524608000000ul;
static const char* HEX_SYMBOLS      = "0123456789ABCDEF";


int Util::algorithmIdentifierFromAsn1 (
        const AlgorithmIdentifier_t& asn1,
        AlgorithmIdentifier& algoId
)
{
    int ret = RET_OK;
    char* s_algo = nullptr;

    //  =algorithm=
    DO(asn_oid_to_text(&asn1.algorithm, &s_algo));
    algoId.algorithm = string(s_algo);

    //  =parameters=
    if (asn1.parameters) {
        algoId.baParameters = ba_alloc_from_uint8(asn1.parameters->buf, asn1.parameters->size);
        if (!algoId.baParameters) {
            SET_ERROR(RET_UAPKI_GENERAL_ERROR);
        }
    }

cleanup:
    ::free(s_algo);
    return ret;
}

int Util::algorithmIdentifierToAsn1 (
        AlgorithmIdentifier_t& asn1,
        const char* algo,
        const ByteArray* baParams
)
{
    int ret = RET_OK;

    if (!algo || !oid_is_valid(algo)) return RET_UAPKI_INVALID_PARAMETER;

    //  =algorithm=
    DO(asn_set_oid_from_text(algo, &asn1.algorithm));

    //  =parameters=
    if (baParams) {
        asn1.parameters = (ANY_t*)asn_decode_ba_with_alloc(get_ANY_desc(), baParams);
        if (!asn1.parameters) {
            SET_ERROR(RET_UAPKI_GENERAL_ERROR);
        }
    }

cleanup:
    return ret;
}

int Util::algorithmIdentifierToAsn1 (
        AlgorithmIdentifier_t& asn1,
        const AlgorithmIdentifier& algoId
)
{
    return algorithmIdentifierToAsn1(asn1, algoId.algorithm.c_str(), algoId.baParameters);
}

int Util::encodeAlgorithmIdentifier (
        const string& algoId,
        const ByteArray* baParams,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    AlgorithmIdentifier_t* aid = nullptr;

    ASN_ALLOC_TYPE(aid, AlgorithmIdentifier_t);

    DO(algorithmIdentifierToAsn1(*aid, algoId.c_str(), baParams));

    DO(asn_encode_ba(get_AlgorithmIdentifier_desc(), aid, baEncoded));

cleanup:
    asn_free(get_AlgorithmIdentifier_desc(), aid);
    return ret;
}

int Util::attributeFromAsn1 (
        const Attribute_t& asn1,
        Attribute& attr
)
{
    int ret = RET_OK;

    //  =attrType=
    DO(oidFromAsn1((OBJECT_IDENTIFIER_t*)&asn1.type, attr.type));

    //  =attrValues=
    if (asn1.value.list.count > 0) {
        const AttributeValue_t& attr_value = *asn1.value.list.array[0];
        attr.baValues = ba_alloc_from_uint8(attr_value.buf, attr_value.size);
    }
    else {
        attr.baValues = ba_alloc();
    }
    if (!attr.baValues) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

cleanup:
    return ret;
}

int Util::attributeToAsn1 (
        Attribute_t& asn1,
        const char* type,
        const ByteArray* baValues
)
{
    int ret = RET_OK;
    ANY_t* any = nullptr;

    if (!type || !oid_is_valid(type)) return RET_UAPKI_INVALID_PARAMETER;

    //  =attrType=
    DO(asn_set_oid_from_text(type, &asn1.type));

    //  =attrValues=
    if (baValues) {
        CHECK_NOT_NULL(any = (ANY_t*)asn_decode_ba_with_alloc(get_ANY_desc(), baValues));
        DO(ASN_SET_ADD(&asn1.value.list, any));
        any = nullptr;
    }

cleanup:
    asn_free(get_ANY_desc(), any);
    return ret;
}

int Util::attributeToAsn1 (
        Attribute_t& asn1,
        const Attribute& attr
)
{
    return attributeToAsn1(asn1, attr.type.c_str(), attr.baValues);
}

int Util::addToAttributes (
        Attributes_t* attrs,
        const char* type,
        const ByteArray* baValues
)
{
    int ret = RET_OK;
    Attribute_t* attr = nullptr;

    CHECK_PARAM(attrs != nullptr);

    ASN_ALLOC_TYPE(attr, Attribute_t);
    DO(attributeToAsn1(*attr, type, baValues));

    DO(ASN_SET_ADD(&attrs->list, attr));
    attr = nullptr;

cleanup:
    asn_free(get_Attribute_desc(), attr);
    return ret;
}

int Util::addToAttributes (
        Attributes_t* attrs,
        const Attribute& attr
)
{
    return addToAttributes(attrs, attr.type.c_str(), attr.baValues);
}

const Attribute_t* Util::attributeFromAttributes (
        const Attributes_t* attrs,
        const char* oidType
)
{
    if (attrs && oidType) {
        for (int i = 0; i < attrs->list.count; i++) {
            const Attribute_t* attr = attrs->list.array[i];
            if (OID_is_equal_oid(&attr->type, oidType)) {
                return attr;
            }
        }
    }
    return nullptr;
}

int Util::attrValueFromAttributes (
        const Attributes_t* attrs,
        const char* oidType,
        ByteArray** baAttrValue
)
{
    int ret = RET_OK;
    if (!attrs || !oidType || !baAttrValue) return RET_UAPKI_INVALID_PARAMETER;

    const Attribute_t* attr = attributeFromAttributes(attrs, oidType);
    if (!attr) {
        ret = RET_UAPKI_ATTRIBUTE_NOT_PRESENT;
        goto cleanup;
    }

    if (attr->value.list.count > 0) {
        const AttributeValue_t* attr_value = attr->value.list.array[0];
        *baAttrValue = ba_alloc_from_uint8(attr_value->buf, attr_value->size);
    }
    else {
        *baAttrValue = ba_alloc();
    }
    CHECK_NOT_NULL(*baAttrValue);

cleanup:
    return ret;
}

int Util::addToExtensions (
        Extensions_t* extns,
        const char* extnId,
        const bool critical,
        const ByteArray* baExtnValue
)
{
    int ret = RET_OK;
    Extension_t* extn = nullptr;
    BOOLEAN_t cr = true;

    if (!extns || !extnId || !baExtnValue) return RET_UAPKI_INVALID_PARAMETER;

    ASN_ALLOC_TYPE(extn, Extension_t);

    DO(asn_set_oid_from_text(extnId, &extn->extnID));
    if (critical) {
        CHECK_NOT_NULL(extn->critical = (BOOLEAN_t*)asn_copy_with_alloc(get_BOOLEAN_desc(), &cr));
    }
    DO(asn_ba2OCTSTRING(baExtnValue, &extn->extnValue));

    DO(ASN_SEQUENCE_ADD(&extns->list, extn));
    extn = nullptr;

cleanup:
    asn_free(get_Extension_desc(), extn);
    return ret;
}

int Util::decodeExtension (
        const ByteArray* baEncoded,
        UapkiNS::Extension& decodedExtn
)
{
    int ret = RET_OK;
    Extension_t* extn = nullptr;

    if (!baEncoded) return RET_UAPKI_INVALID_PARAMETER;

    CHECK_NOT_NULL(extn = (Extension_t*)asn_decode_ba_with_alloc(get_Extension_desc(), baEncoded));

    DO(extensionFromAsn1(*extn, decodedExtn));

cleanup:
    asn_free(get_Extension_desc(), extn);
    return ret;
}

int Util::encodeExtension (
        const string& extnId,
        const bool critical,
        const ByteArray* baExtnValue,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    Extension_t* extn = nullptr;
    BOOLEAN_t cr = true;

    if (extnId.empty() || !baExtnValue || !baEncoded) return RET_UAPKI_INVALID_PARAMETER;

    ASN_ALLOC_TYPE(extn, Extension_t);

    DO(oidToAsn1(&extn->extnID, extnId));
    if (critical) {
        CHECK_NOT_NULL(extn->critical = (BOOLEAN_t*)asn_copy_with_alloc(get_BOOLEAN_desc(), &cr));
    }
    DO(asn_ba2OCTSTRING(baExtnValue, &extn->extnValue));

    DO(asn_encode_ba(get_Extension_desc(), extn, baEncoded));

cleanup:
    asn_free(get_Extension_desc(), extn);
    return ret;
}

int Util::extensionFromAsn1 (
        const Extension_t& asn1,
        UapkiNS::Extension& extn
)
{
    int ret = RET_OK;

    //  =extnId=
    DO(oidFromAsn1((OBJECT_IDENTIFIER_t*)&asn1.extnID, extn.extnId));

    //  =critical=, optional
    if (asn1.critical) {
        extn.critical = *asn1.critical;
    }

    //  =extnValue=
    DO(asn_OCTSTRING2ba(&asn1.extnValue, &extn.baExtnValue));

cleanup:
    return ret;
}

const Extension_t* Util::extensionFromExtensions (
        const Extensions_t* extns,
        const char* extnId
)
{
    if (extns && extnId) {
        for (int i = 0; i < extns->list.count; i++) {
            const Extension_t* extn = extns->list.array[i];
            if (OID_is_equal_oid(&extn->extnID, extnId)) {
                return extn;
            }
        }
    }
    return nullptr;
}

int Util::extnValueFromExtensions (
        const Extensions_t* extns,
        const char* extnId,
        bool* critical,
        ByteArray** baExtnValue
)
{
    int ret = RET_OK;
    if (!extns || !extnId || !baExtnValue) return RET_UAPKI_INVALID_PARAMETER;

    const Extension_t* extn = extensionFromExtensions(extns, extnId);
    if (!extn) {
        ret = RET_UAPKI_EXTENSION_NOT_PRESENT;
        goto cleanup;
    }

    if (critical) {
        *critical = false;
        if (extn->critical) {
            *critical = (extn->critical != 0);
        }
    }

    DO(asn_OCTSTRING2ba(&extn->extnValue, baExtnValue));

cleanup:
    return ret;
}

int Util::encodeGenTime (
        const uint64_t msTime,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    GeneralizedTime_t* gen_time = nullptr;

    if (!baEncoded) return RET_UAPKI_INVALID_PARAMETER;

    ASN_ALLOC_TYPE(gen_time, GeneralizedTime_t);

    DO(asn_time2GT(gen_time, msTime, nullptr));

    DO(asn_encode_ba(get_GeneralizedTime_desc(), gen_time, baEncoded));

cleanup:
    asn_free(get_GeneralizedTime_desc(), gen_time);
    return ret;
}

int Util::encodeOctetString (
        const ByteArray* baData,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    OCTET_STRING_t* octet_string = nullptr;

    if (!baData || !baEncoded) return RET_UAPKI_INVALID_PARAMETER;

    ASN_ALLOC_TYPE(octet_string, OCTET_STRING_t);

    DO(asn_ba2OCTSTRING(baData, octet_string));

    DO(asn_encode_ba(get_OCTET_STRING_desc(), octet_string, baEncoded));

cleanup:
    asn_free(get_OCTET_STRING_desc(), octet_string);
    return ret;
}

int Util::encodePkixTime (
        const PKIXTime_PR frmTime,
        const uint64_t msTime,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    PKIXTime_PR frm_time = frmTime;

    if (!baEncoded) return RET_UAPKI_INVALID_PARAMETER;

    if (frm_time == PKIXTime_PR_NOTHING) {
        frm_time = (msTime < UTC_TIME_MS_END) ? PKIXTime_PR_utcTime : PKIXTime_PR_generalTime;
    }

    switch (frm_time) {
    case PKIXTime_PR_utcTime:
        DO(encodeUtcTime(msTime, baEncoded));
        break;
    case PKIXTime_PR_generalTime:
        DO(encodeGenTime(msTime, baEncoded));
        break;
    default:
        break;
    }

cleanup:
    return ret;
}

int Util::encodeUtcTime (
        const uint64_t msTime,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    UTCTime_t* utc_time = nullptr;

    if (!baEncoded) return RET_UAPKI_INVALID_PARAMETER;

    ASN_ALLOC_TYPE(utc_time, UTCTime_t);

    DO(asn_time2UT(utc_time, msTime, nullptr));

    DO(asn_encode_ba(get_UTCTime_desc(), utc_time, baEncoded));

cleanup:
    asn_free(get_UTCTime_desc(), utc_time);
    return ret;
}

bool Util::equalValueOctetString (
        const OCTET_STRING_t& octetString1,
        const OCTET_STRING_t& octetString2
)
{
    return (
        (octetString1.size == octetString2.size) &&
        (memcmp(octetString1.buf, octetString2.buf, (size_t)octetString2.size) == 0)
    );
}

bool Util::equalValuePrimitiveType (
        const ASN__PRIMITIVE_TYPE_t& primType1,
        const ASN__PRIMITIVE_TYPE_t& primType2
)
{
    return (
        (primType1.size == primType2.size) &&
        (memcmp(primType1.buf, primType2.buf, (size_t)primType2.size) == 0)
    );
}

int Util::genTimeFromAsn1 (
        const GeneralizedTime_t* genTime,
        uint64_t& msTime
)
{
    if (!genTime) return RET_UAPKI_INVALID_PARAMETER;

    msTime = asn_GT2time(genTime, nullptr);
    return RET_OK;
}

int Util::pkixTimeFromAsn1 (
        const PKIXTime_t* pkixTime,
        uint64_t& msTime
)
{
    int ret = RET_OK;

    if (!pkixTime) return RET_UAPKI_INVALID_PARAMETER;

    switch (pkixTime->present) {
    case PKIXTime_PR_utcTime:
        msTime = asn_UT2time(&pkixTime->choice.utcTime, nullptr);
        break;
    case PKIXTime_PR_generalTime:
        msTime = asn_GT2time(&pkixTime->choice.generalTime, nullptr);
        break;
    default:
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

cleanup:
    return ret;
}

int Util::utcTimeFromAsn1 (
        const UTCTime_t* utcTime,
        uint64_t& msTime
)
{
    if (!utcTime) return RET_UAPKI_INVALID_PARAMETER;

    msTime = asn_UT2time(utcTime, nullptr);
    return RET_OK;
}

int Util::bitStringEncapOctetFromAsn1 (
        const BIT_STRING_t* bsEncapOctet,
        ByteArray** baData
)
{
    int ret = RET_OK;
    OCTET_STRING_t* octet_str = nullptr;
    SmartBA sba_encoded;

    CHECK_PARAM(bsEncapOctet);
    CHECK_PARAM(baData);

    if (bsEncapOctet->bits_unused != 0) {
        SET_ERROR(RET_UAPKI_UNEXPECTED_BIT_STRING);
    }

    DO(asn_BITSTRING2ba(bsEncapOctet, &sba_encoded));
    CHECK_NOT_NULL(octet_str = (OCTET_STRING_t*)asn_decode_ba_with_alloc(get_OCTET_STRING_desc(), sba_encoded.get()));
    DO(asn_OCTSTRING2ba(octet_str, baData));

cleanup:
    asn_free(get_OCTET_STRING_desc(), octet_str);
    return ret;
}

int Util::bitStringFromAsn1 (
        const BIT_STRING_t* bs,
        uint32_t* bits
)
{
    int ret = RET_OK;
    ByteArray* ba_bitvalues = nullptr;
    uint32_t i, value = 0;
    const uint8_t* buf = nullptr;

    CHECK_PARAM(bs);
    CHECK_PARAM(bits);

    if (bs->bits_unused > 7) {
        SET_ERROR(RET_UAPKI_INVALID_BIT_STRING);
    }
    if (bs->size > 4) {
        SET_ERROR(RET_UAPKI_TOO_LONG_BIT_STRING);
    }

    *bits = 0;
    DO(asn_BITSTRING2ba(bs, &ba_bitvalues));

    buf = ba_get_buf_const(ba_bitvalues);
    for (i = 0; i < (uint32_t)ba_get_len(ba_bitvalues); i++) {
        value <<= 8;
        value |= buf[i];
    }
    value >>= bs->bits_unused;
    *bits = value;

cleanup:
    ba_free(ba_bitvalues);
    return ret;
}

int Util::bmpStringFromAsn1 (
        const BMPString_t* bmpStr,
        string& sValue
)
{
    int ret = RET_OK;
    char* str = nullptr;

    CHECK_PARAM(bmpStr);

    DO(utf16be_to_utf8(bmpStr->buf, bmpStr->size, &str));
    if (str) {
        sValue = string(str);
        ::free(str);
    }

cleanup:
    return ret;
}

int Util::enumeratedFromAsn1 (
        const ENUMERATED_t* enumerated,
        uint32_t* enumValue
)
{
    int ret = RET_OK;
    unsigned long value = 0;

    CHECK_PARAM(enumerated);
    CHECK_PARAM(enumValue);

    if ((enumerated->size > 0) && (enumerated->size < 4)) {
        DO(asn_INTEGER2ulong(enumerated, &value));
        *enumValue = (uint32_t)value;
    }
    else {
        SET_ERROR(RET_INVALID_PARAM);
    }

cleanup:
    return ret;
}

int Util::decodeAsn1Header (
        const ByteArray* baEncoded,
        uint32_t& tag,
        size_t& hlen,
        size_t& vlen
)
{
    return decodeAsn1Header(
        ba_get_buf_const(baEncoded),
        ba_get_len(baEncoded),
        tag,
        hlen,
        vlen
    );
}

int Util::decodeAsn1Header (
        const uint8_t* bufEncoded,
        const size_t lenEncoded,
        uint32_t& tag,
        size_t& hlen,
        size_t& vlen
)
{
    if (lenEncoded < 2) return false;

    tag = bufEncoded[0];
    hlen = 2;
    vlen = 0;

    size_t v = bufEncoded[1];
    if (v < 0x80) {
        vlen = v;
    }
    else {
        const size_t size = v & 0x07;
        hlen += size;
        if (lenEncoded < size + 2) return false;
        for (size_t i = 2; i < hlen; i++) {
            vlen <<= 8;
            v = bufEncoded[i];
            vlen |= v;
        }
    }
    return true;
}

int Util::decodeAnyString (
        const uint8_t* buf,
        const size_t len,
        string& sValue
)
{
    int ret = RET_OK;
    OCTET_STRING_t* octet_str = nullptr;
    asn_TYPE_descriptor_t* desc = nullptr;

    if (!buf) return RET_UAPKI_INVALID_PARAMETER;
    if (len < 2) return RET_UAPKI_INVALID_STRUCT;

    switch (buf[0]) {
    case 0x0C: desc = get_UTF8String_desc();      break;
    case 0x13: desc = get_PrintableString_desc(); break;
    case 0x14: desc = get_TeletexString_desc();   break;
    case 0x16: desc = get_IA5String_desc();       break;
    default:
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

    octet_str = (OCTET_STRING_t*)asn_decode_with_alloc(desc, buf, len);
    if (!octet_str) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

    DO(Util::pbufToStr(octet_str->buf, (size_t)octet_str->size, sValue));

cleanup:
    asn_free(get_OCTET_STRING_desc(), octet_str);
    return ret;
}

int Util::decodeAnyString (
        const ByteArray* baEncoded,
        string& sValue
)
{
    return decodeAnyString(ba_get_buf_const(baEncoded), ba_get_len(baEncoded), sValue);
}

int Util::decodeBmpString (
        const ByteArray* baEncoded,
        string& sValue
)
{
    int ret = RET_OK;
    BMPString_t* prim_bmpstr = nullptr;

    CHECK_PARAM(baEncoded);

    CHECK_NOT_NULL(prim_bmpstr = (BMPString_t*)asn_decode_ba_with_alloc(get_BMPString_desc(), baEncoded));
    DO(bmpStringFromAsn1(prim_bmpstr, sValue));

cleanup:
    asn_free(get_BMPString_desc(), prim_bmpstr);
    return ret;
}

int Util::decodeBoolean (
        const ByteArray* baEncoded,
        bool& value
)
{
    int ret = RET_OK;
    BOOLEAN_t* prim_boolean = nullptr;

    CHECK_NOT_NULL(prim_boolean = (BOOLEAN_t*)asn_decode_ba_with_alloc(get_BOOLEAN_desc(), baEncoded));
    value = *prim_boolean;

cleanup:
    asn_free(get_BOOLEAN_desc(), prim_boolean);
    return ret;
}

int Util::decodeEnumerated (
        const ByteArray* baEncoded,
        uint32_t* enumValue
)
{
    int ret = RET_OK;
    ENUMERATED_t* prim_enum = nullptr;

    CHECK_PARAM(baEncoded);
    CHECK_PARAM(enumValue);

    CHECK_NOT_NULL(prim_enum = (ENUMERATED_t*)asn_decode_ba_with_alloc(get_ENUMERATED_desc(), baEncoded));
    DO(enumeratedFromAsn1(prim_enum, enumValue));

cleanup:
    asn_free(get_ENUMERATED_desc(), prim_enum);
    return ret;
}

int Util::decodeOctetString (
        const ByteArray* baEncoded,
        ByteArray** baData
)
{
    int ret = RET_OK;
    OCTET_STRING_t* prim_octetstr = nullptr;

    if (!baEncoded || !baData) return RET_UAPKI_INVALID_PARAMETER;

    CHECK_NOT_NULL(prim_octetstr = (OCTET_STRING_t*)asn_decode_ba_with_alloc(get_OCTET_STRING_desc(), baEncoded));
    DO(asn_OCTSTRING2ba(prim_octetstr, baData));

cleanup:
    asn_free(get_OCTET_STRING_desc(), prim_octetstr);
    return ret;
}

int Util::decodeOid (
        const ByteArray* baEncoded,
        string& oid
)
{
    int ret = RET_OK;
    OBJECT_IDENTIFIER_t* prim_oid = nullptr;

    if (!baEncoded) return RET_UAPKI_INVALID_PARAMETER;

    CHECK_NOT_NULL(prim_oid = (OBJECT_IDENTIFIER_t*)asn_decode_ba_with_alloc(get_OBJECT_IDENTIFIER_desc(), baEncoded));
    DO(oidFromAsn1(prim_oid, oid));

cleanup:
    asn_free(get_OBJECT_IDENTIFIER_desc(), prim_oid);
    return ret;
}

int Util::decodePkixTime (
        const ByteArray* baEncoded,
        uint64_t& msTime
)
{
    int ret = RET_OK;
    PKIXTime_t* pkix_time = nullptr;

    if (!baEncoded) return RET_UAPKI_INVALID_PARAMETER;

    CHECK_NOT_NULL(pkix_time = (PKIXTime_t*)asn_decode_ba_with_alloc(get_PKIXTime_desc(), baEncoded));
    DO(pkixTimeFromAsn1(pkix_time, msTime));

cleanup:
    asn_free(get_PKIXTime_desc(), pkix_time);
    return ret;
}

int Util::encodeBmpString (
        const char* strUtf8,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    ByteArray* ba_utf16be = nullptr;
    uint8_t* utf16 = nullptr;
    size_t utf16_len = 0;

    CHECK_PARAM(strUtf8);
    CHECK_PARAM(baEncoded);

    DO(utf8_to_utf16be(strUtf8, &utf16, &utf16_len));
    CHECK_NOT_NULL(ba_utf16be = ba_alloc_from_uint8(utf16, utf16_len));
    DO(encodeOctetString(ba_utf16be, baEncoded));
    DO(ba_set_byte(*baEncoded, 0, 0x1E));

cleanup:
    ba_free(ba_utf16be);
    free(utf16);
    return ret;
}

int Util::encodeBoolean (
        const bool value,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    BOOLEAN_t* prim_boolean = nullptr;

    CHECK_PARAM(baEncoded);

    ASN_ALLOC_TYPE(prim_boolean, BOOLEAN_t);
    *prim_boolean = value ? 1 : 0;
    DO(asn_encode_ba(get_BOOLEAN_desc(), prim_boolean, baEncoded));

cleanup:
    asn_free(get_BOOLEAN_desc(), prim_boolean);
    return ret;
}

int Util::encodeIa5String (
        const char* strLatin,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    IA5String_t* ia5_str = nullptr;

    CHECK_PARAM(strLatin);
    CHECK_PARAM(baEncoded);

    ASN_ALLOC_TYPE(ia5_str, IA5String_t);
    if (strLatin) {
        DO(asn_bytes2OCTSTRING(ia5_str, (const uint8_t*)strLatin, strlen(strLatin)));
    }
    DO(asn_encode_ba(get_IA5String_desc(), ia5_str, baEncoded));

cleanup:
    asn_free(get_IA5String_desc(), ia5_str);
    return ret;
}

int Util::encodeInteger (
        const ByteArray* baData,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    INTEGER_t* prim_integer = nullptr;

    CHECK_PARAM(baData);
    CHECK_PARAM(baEncoded);

    ASN_ALLOC_TYPE(prim_integer, INTEGER_t);
    DO(asn_ba2INTEGER(baData, prim_integer));
    DO(asn_encode_ba(get_INTEGER_desc(), prim_integer, baEncoded));

cleanup:
    asn_free(get_INTEGER_desc(), prim_integer);
    return ret;
}

int Util::encodeInteger (
        const int32_t value,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    INTEGER_t* prim_integer = nullptr;

    CHECK_PARAM(baEncoded);

    ASN_ALLOC_TYPE(prim_integer, INTEGER_t);
    DO(asn_long2INTEGER(prim_integer, value));
    DO(asn_encode_ba(get_INTEGER_desc(), prim_integer, baEncoded));

cleanup:
    asn_free(get_INTEGER_desc(), prim_integer);
    return ret;
}

int Util::encodeOid (
        const char* oid,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    OBJECT_IDENTIFIER_t* asn_oid = nullptr;

    CHECK_PARAM(oid);
    CHECK_PARAM(baEncoded);

    ASN_ALLOC_TYPE(asn_oid, OBJECT_IDENTIFIER_t);
    DO(asn_set_oid_from_text(oid, asn_oid));
    DO(asn_encode_ba(get_OBJECT_IDENTIFIER_desc(), asn_oid, baEncoded));

cleanup:
    asn_free(get_OBJECT_IDENTIFIER_desc(), asn_oid);
    return ret;
}

int Util::encodePrintableString (
        const char* strLatin,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    PrintableString_t* printable_str = nullptr;

    CHECK_PARAM(strLatin);
    CHECK_PARAM(baEncoded);

    ASN_ALLOC_TYPE(printable_str, PrintableString_t);
    if (strLatin) {
        DO(asn_bytes2OCTSTRING(printable_str, (const uint8_t*)strLatin, strlen(strLatin)));
    }
    DO(asn_encode_ba(get_PrintableString_desc(), printable_str, baEncoded));

cleanup:
    asn_free(get_PrintableString_desc(), printable_str);
    return ret;
}

int Util::encodeUtf8string (
        const char* strUtf8,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    UTF8String_t* utf8_str = nullptr;

    CHECK_PARAM(strUtf8);
    CHECK_PARAM(baEncoded);

    ASN_ALLOC_TYPE(utf8_str, UTF8String_t);
    if (strUtf8) {
        DO(asn_bytes2OCTSTRING(utf8_str, (const uint8_t*)strUtf8, strlen(strUtf8)));
    }
    DO(asn_encode_ba(get_UTF8String_desc(), utf8_str, baEncoded));

cleanup:
    asn_free(get_UTF8String_desc(), utf8_str);
    return ret;
}

int Util::oidFromAsn1 (
        const OBJECT_IDENTIFIER_t* oid,
        string& sOid
)
{
    char* s_oid = nullptr;
    const int ret = asn_oid_to_text(oid, &s_oid);
    if ((ret == RET_OK) && s_oid) {
        sOid = string(s_oid);
    }
    ::free(s_oid);
    return ret;
}

int Util::oidToAsn1 (
        OBJECT_IDENTIFIER_t* oid,
        const string& sOid
)
{
    return asn_set_oid_from_text(sOid.c_str(), oid);
}

int Util::pbufToStr (
        const uint8_t* buf,
        const size_t len,
        char** str
)
{
    int ret = RET_OK;

    CHECK_PARAM(buf);
    CHECK_PARAM(str);

    if (len > 0) {
        *str = (char*)calloc(1, len + 1);
        if (*str == NULL) {
            ret = RET_MEMORY_ALLOC_ERROR;
        }
        memcpy(*str, buf, len);
    }
    else {
        *str = nullptr;
    }

cleanup:
    return ret;
}

int Util::pbufToStr (
        const uint8_t* buf,
        const size_t len,
        string& sValue
)
{
    if (!buf) return RET_UAPKI_INVALID_PARAMETER;

    if (len > 0) {
        sValue.resize(len);
        memcpy((void*)sValue.data(), buf, len);
    }

    return RET_OK;
}

string Util::baToHex (
        const ByteArray* baData
)
{
    string rv_shex;
    const size_t len = ba_get_len(baData);
    if (len > 0) {
        rv_shex.resize(2 * len);
        const uint8_t* src = ba_get_buf_const(baData);
        uint8_t* dst = (uint8_t*)rv_shex.data();
        for (size_t i = 0, j = 0; i < len; i++) {
            dst[j++] = HEX_SYMBOLS[src[i] >> 4];
            dst[j++] = HEX_SYMBOLS[src[i] & 0x0F];
        }
    }
    return rv_shex;
}

string Util::joinStrings (
        const vector<string>& strings,
        const char separator
)
{
    string rv_s;
    for (const auto& it : strings) {
        rv_s += it;
        rv_s.push_back(separator);
    }
    if (!rv_s.empty()) {
        rv_s.pop_back();
    }
    return rv_s;
}


}   //  end namespace UapkiNS
