//  Last update: 2022-07-23


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

int Util::algorithmIdentifierToAsn1 (const AlgorithmIdentifier& algoId, AlgorithmIdentifier_t& asn1)
{
    int ret = RET_OK;
    if (!algoId.isPresent()) return RET_INVALID_PARAM;

    //  =algorithm=
    DO(asn_set_oid_from_text(algoId.algorithm.c_str(), &asn1.algorithm));

    //  =parameters=
    if (algoId.baParameters) {
        asn1.parameters = (ANY_t*)asn_decode_ba_with_alloc(get_ANY_desc(), algoId.baParameters);
        if (!asn1.parameters) {
            SET_ERROR(RET_MEMORY_ALLOC_ERROR);
        }
    }

cleanup:
    return ret;
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

int Util::attributeToAsn1 (const Attribute& attr, Attribute_t& asn1)
{
    int ret = RET_OK;
    if (!attr.isPresent()) return RET_INVALID_PARAM;

    //  =attrType=
    DO(asn_set_oid_from_text(attr.type.c_str(), &asn1.type));

    //  =attrValues=
    //if (algoId.baParameters) {
    //    asn1.parameters = (ANY_t*)asn_decode_ba_with_alloc(get_ANY_desc(), algoId.baParameters);
    //    if (!asn1.parameters) {
    //        SET_ERROR(RET_MEMORY_ALLOC_ERROR);
    //    }
    //}

cleanup:
    return ret;
}


}   //  end namespace UapkiNS
