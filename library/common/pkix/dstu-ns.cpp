//  Last update: 2021-11-29

#include "dstu-ns.h"
#include "asn1-ba-utils.h"
#include "macros-internal.h"
#include "oid-utils.h"


int DstuNS::ba2BitStringEncapOctet (const ByteArray* baData, BIT_STRING_t* bsEncapOctet)
{
    int ret = RET_OK;
    ByteArray* ba_encap = nullptr;

    CHECK_PARAM(baData != nullptr);
    CHECK_PARAM(bsEncapOctet != nullptr);

    DO(ba_encode_octetstring(baData, &ba_encap));
    DO(asn_ba2BITSTRING(ba_encap, bsEncapOctet));

cleanup:
    ba_free(ba_encap);
    return ret;
}

int DstuNS::calcKeyId (const ByteArray* baPubkey, ByteArray** baKeyId)
{
    int ret = RET_OK;
    ByteArray* ba_encappubkey = nullptr;

    CHECK_PARAM(baPubkey != nullptr);
    CHECK_PARAM(baKeyId != nullptr);

    DO(ba_encode_octetstring(baPubkey, &ba_encappubkey));

    DO(::hash(HASH_ALG_GOST34311, ba_encappubkey, baKeyId));

cleanup:
    ba_free(ba_encappubkey);
    return ret;
}

bool DstuNS::isDstu4145family (const char* algo)
{
    return (algo && (oid_is_parent(OID_DSTU4145_WITH_DSTU7564, algo) || oid_is_parent(OID_DSTU4145_WITH_GOST3411, algo)));
}
