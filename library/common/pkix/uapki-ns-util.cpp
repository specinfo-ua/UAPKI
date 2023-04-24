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

//  Last update: 2023-04-24

#include "uapki-ns-util.h"
#include "macros-internal.h"
#include "oids.h"
#include "time-utils.h"
#include "uapki-errors.h"


using namespace std;


namespace UapkiNS {


constexpr uint64_t UTC_TIME_MS_END = 2524608000000ul;


int Util::algorithmIdentifierFromAsn1 (const AlgorithmIdentifier_t& asn1, AlgorithmIdentifier& algoId)
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

int Util::algorithmIdentifierToAsn1 (AlgorithmIdentifier_t& asn1, const char* algo, const ByteArray* baParams)
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

int Util::algorithmIdentifierToAsn1 (AlgorithmIdentifier_t& asn1, const AlgorithmIdentifier& algoId)
{
    return algorithmIdentifierToAsn1(asn1, algoId.algorithm.c_str(), algoId.baParameters);
}

int Util::attributeFromAsn1 (const Attribute_t& asn1, Attribute& attr)
{
    int ret = RET_OK;
    char* s_type = nullptr;

    //  =attrType=
    DO(asn_oid_to_text(&asn1.type, &s_type));
    attr.type = string(s_type);

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
    ::free(s_type);
    return ret;
}

int Util::attributeToAsn1 (Attribute_t& asn1, const char* type, const ByteArray* baValues)
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

int Util::attributeToAsn1 (Attribute_t& asn1, const Attribute& attr)
{
    return attributeToAsn1(asn1, attr.type.c_str(), attr.baValues);
}

int Util::addToAttributes (Attributes_t* attrs, const char* type, const ByteArray* baValues)
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

int Util::addToAttributes (Attributes_t* attrs, const Attribute& attr)
{
    return addToAttributes(attrs, attr.type.c_str(), attr.baValues);
}

int Util::encodeGenTime (
        const uint64_t msTime,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    GeneralizedTime_t* gen_time = NULL;
    ::tm tm_data;
    string s_time;
    UapkiNS::SmartBA sba_stime;

    if (!baEncoded) return RET_UAPKI_INVALID_PARAMETER;

    s_time.resize(15);
    if (
        !TimeUtils::mstimeToTm(tm_data, msTime, false) ||
        (strftime((char*)s_time.data(), s_time.length(), "%Y%m%d%H%M%S", &tm_data) != 14)
    ) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    s_time[14] = 'Z';
    if (!sba_stime.set(ba_alloc_from_str(s_time.c_str()))) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    ASN_ALLOC_TYPE(gen_time, GeneralizedTime_t);

    DO(asn_ba2OCTSTRING(sba_stime.get(), gen_time));

    DO(asn_encode_ba(get_GeneralizedTime_desc(), gen_time, baEncoded));

cleanup:
    asn_free(get_GeneralizedTime_desc(), gen_time);
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
    ::tm tm_data;
    string s_time;
    UapkiNS::SmartBA sba_stime;

    if (!baEncoded) return RET_UAPKI_INVALID_PARAMETER;

    s_time.resize(13);
    if (
        !TimeUtils::mstimeToTm(tm_data, msTime, false) ||
        (strftime((char*)s_time.data(), s_time.length(), "%y%m%d%H%M%S", &tm_data) != 12)
    ) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    s_time[12] = 'Z';
    if (!sba_stime.set(ba_alloc_from_str(s_time.c_str()))) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    ASN_ALLOC_TYPE(utc_time, UTCTime_t);

    DO(asn_ba2OCTSTRING(sba_stime.get(), utc_time));

    DO(asn_encode_ba(get_UTCTime_desc(), utc_time, baEncoded));

cleanup:
    asn_free(get_UTCTime_desc(), utc_time);
    return ret;
}


}   //  end namespace UapkiNS
