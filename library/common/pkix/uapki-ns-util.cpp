//  Last update: 2022-07-27


#include "uapki-ns-util.h"
#include "macros-internal.h"
#include "oids.h"
#include "uapki-errors.h"


using namespace std;


namespace UapkiNS {


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
            SET_ERROR(RET_MEMORY_ALLOC_ERROR);
        }
    }

cleanup:
    ::free(s_algo);
    return ret;
}

int Util::algorithmIdentifierToAsn1 (AlgorithmIdentifier_t& asn1, const char* algo, const ByteArray* baParams)
{
    int ret = RET_OK;

    if (!algo || !oid_is_valid(algo)) return RET_INVALID_PARAM;

    //  =algorithm=
    DO(asn_set_oid_from_text(algo, &asn1.algorithm));

    //  =parameters=
    if (baParams) {
        asn1.parameters = (ANY_t*)asn_decode_ba_with_alloc(get_ANY_desc(), baParams);
        if (!asn1.parameters) {
            SET_ERROR(RET_MEMORY_ALLOC_ERROR);
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
        SET_ERROR(RET_MEMORY_ALLOC_ERROR);
    }

cleanup:
    ::free(s_type);
    return ret;
}

int Util::attributeToAsn1 (Attribute_t& asn1, const char* type, const ByteArray* baValues)
{
    int ret = RET_OK;
    ANY_t* any = nullptr;

    if (!type || !oid_is_valid(type)) return RET_INVALID_PARAM;

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


}   //  end namespace UapkiNS
