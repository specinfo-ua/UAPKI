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


#ifndef UAPKI_NS_UTIL_H
#define UAPKI_NS_UTIL_H


#include "uapki-ns.h"
#include "uapkif.h"


namespace UapkiNS {

namespace Util {

    int algorithmIdentifierFromAsn1 (
        const AlgorithmIdentifier_t& asn1,
        UapkiNS::AlgorithmIdentifier& algoId
    );
    int algorithmIdentifierToAsn1 (
        AlgorithmIdentifier_t& asn1,
        const char* algo, const ByteArray* baParams
    );
    int algorithmIdentifierToAsn1 (
        AlgorithmIdentifier_t& asn1,
        const UapkiNS::AlgorithmIdentifier& algoId
    );
    int encodeAlgorithmIdentifier (
        const std::string& algoId,
        const ByteArray* baParams,
        ByteArray** baEncoded
    );

    int attributeFromAsn1 (
        const Attribute_t& asn1,
        UapkiNS::Attribute& attr
    );
    int attributeToAsn1 (
        Attribute_t& asn1,
        const char* type,
        const ByteArray* baValues
    );
    int attributeToAsn1 (
        Attribute_t& asn1,
        const UapkiNS::Attribute& attr
    );
    int addToAttributes (
        Attributes_t* attrs,
        const char* type,
        const ByteArray* baValues
    );
    int addToAttributes (
        Attributes_t* attrs,
        const UapkiNS::Attribute& attr
    );
    const Attribute_t* attributeFromAttributes (
        const Attributes_t* attrs,
        const char* oidType
    );
    int attrValueFromAttributes (
        const Attributes_t* attrs,
        const char* oidType,
        ByteArray** baAttrValue
    );

    int addToExtensions (
        Extensions_t* extns,
        const char* extnId,
        const bool critical,
        const ByteArray* baExtnValue
    );
    int decodeExtension (
        const ByteArray* baEncoded,
        UapkiNS::Extension& extn
    );
    int encodeExtension (
        const std::string& extnId,
        const bool critical,
        const ByteArray* baExtnValue,
        ByteArray** baEncoded
    );
    int extensionFromAsn1 (
        const Extension_t& asn1,
        UapkiNS::Extension& extn
    );
    const Extension_t* extensionFromExtensions (
        const Extensions_t* extns,
        const char* extnId
    );
    int extnValueFromExtensions (
        const Extensions_t* extns,
        const char* extnId,
        bool* critical,
        ByteArray** baExtnValue
    );

    bool equalValueOctetString (
        const OCTET_STRING_t& octetString1,
        const OCTET_STRING_t& octetString2
    );
    bool equalValuePrimitiveType (
        const ASN__PRIMITIVE_TYPE_t& primType1,
        const ASN__PRIMITIVE_TYPE_t& primType2
    );

    int genTimeFromAsn1 (
        const GeneralizedTime_t* genTime,
        uint64_t& msTime
    );
    int pkixTimeFromAsn1 (
        const PKIXTime_t* pkixTime,
        uint64_t& msTime
    );
    int utcTimeFromAsn1 (
        const UTCTime_t* utcTime,
        uint64_t& msTime
    );

    int bitStringEncapOctetFromAsn1 (
        const BIT_STRING_t* bsEncapOctet,
        ByteArray** baData
    );
    int bitStringFromAsn1 (
        const BIT_STRING_t* bs,
        uint32_t* bits
    );
    int bmpStringFromAsn1 (
        const BMPString_t* bmpStr,
        std::string& sValue
    );
    int enumeratedFromAsn1 (
        const ENUMERATED_t* enumerated,
        uint32_t* enumValue
    );

    int decodeAsn1Header (
        const ByteArray* baEncoded,
        uint32_t& tag,
        size_t& hlen,
        size_t& vlen
    );
    int decodeAsn1Header (
        const uint8_t* bufEncoded,
        const size_t lenEncoded,
        uint32_t& tag,
        size_t& hlen,
        size_t& vlen
    );

    int decodeAnyString (
        const uint8_t* buf,
        const size_t len,
        std::string& sValue
    );
    int decodeAnyString (
        const ByteArray* baEncoded,
        std::string& sValue
    );
    int decodeBmpString (
        const ByteArray* baEncoded,
        std::string& sValue
    );
    int decodeBoolean (
        const ByteArray* baEncoded,
        bool& value
    );
    int decodeEnumerated (
        const ByteArray* baEncoded,
        uint32_t* enumValue
    );
    int decodeOctetString (
        const ByteArray* baEncoded,
        ByteArray** baData
    );
    int decodeOid (
        const ByteArray* baEncoded,
        std::string& oid
    );
    int decodePkixTime (
        const ByteArray* baEncoded,
        uint64_t& msTime
    );

    int encodeBmpString (
        const char* strUtf8,
        ByteArray** baEncoded
    );
    int encodeBoolean (
        const bool value,
        ByteArray** baEncoded
    );
    int encodeGenTime (
        const uint64_t msTime,
        ByteArray** baEncoded
    );
    int encodeIa5String (
        const char* strLatin,
        ByteArray** baEncoded
    );
    int encodeInteger (
        const ByteArray* baData,
        ByteArray** baEncoded
    );
    int encodeInteger (
        const int32_t value,
        ByteArray** baEncoded
    );
    int encodeOctetString (
        const ByteArray* baData,
        ByteArray** baEncoded
    );
    int encodeOid (
        const char* oid,
        ByteArray** baEncoded
    );
    int encodePkixTime (
        const PKIXTime_PR frmTime,
        const uint64_t msTime,
        ByteArray** baEncoded
    );
    int encodePrintableString (
        const char* strLatin,
        ByteArray** baEncoded
    );
    int encodeUtcTime (
        const uint64_t msTime,
        ByteArray** baEncoded
    );
    int encodeUtf8string (
        const char* strUtf8,
        ByteArray** baEncoded
    );

    int oidFromAsn1 (
        const OBJECT_IDENTIFIER_t* oid,
        std::string& sOid
    );
    int oidToAsn1 (
        OBJECT_IDENTIFIER_t* oid,
        const std::string& sOid
    );
    int pbufToStr (
        const uint8_t* buf,
        const size_t len,
        char** str
    );
    int pbufToStr (
        const uint8_t* buf,
        const size_t len,
        std::string& sValue
    );

    std::string baToHex (
        const ByteArray* baData
    );
    std::string joinStrings (
        const std::vector<std::string>& strings,
        const char separator = ';'
    );

}   //  end namespace Util

}   //  end namespace UapkiNS


#endif
