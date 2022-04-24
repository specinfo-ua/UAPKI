//  Last update: 2022-04-21

#include "dstu-ns.h"
#include "asn1-ba-utils.h"
#include "macros-internal.h"
#include "oid-utils.h"
#include "uapki-errors.h"
#include "uapki-ns.h"


#undef FILE_MARKER
#define FILE_MARKER "common/pkix/dstu-ns.cpp"


using namespace std;


constexpr size_t SIZE_DSTU4145_PARAM_M257_PB = 119;
constexpr size_t SIZE_DSTU4145_PARAM_M431_PB = 191;

static const char* SHEX_DSTU4145_PARAM_M257_PB =
                "307530070202010102010C020100042110BEE3DB6AEA9E1F86578C45C12594FF942394A7D738F9187E6515017294F4CE0102"
                "2100800000000000000000000000000000006759213AF182E987D3E17714907D470D0421B60FD2D8DCE8A93423C6101BCA91"
                "C47A007E6C300B26CD556C9B0E7D20EF292A00";

static const char* SHEX_DSTU4145_PARAM_M431_PB =
                "3081BC300F020201AF30090201010201030201050201010436F3CA40C669A4DA173149CA12C32DAE186B53AC6BC6365997DE"
                "AEAE8AD2D888F9BFD53401694EF9C4273D8CFE6DC28F706A0F4910CE0302363FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                "FFFFFFFFFFFFFFFFBA3175458009A8C0A724F02F81AA8A1FCBAF80D90C7A95110504CF04367C857C94C5433BFD991E17C226"
                "84065850A9A249ED7BC249AE5A4E878689F872EF7AD524082EC3038E9AEDE7BA6BA13381D979BA621A";


int DstuNS::ba2BitStringEncapOctet (const ByteArray* baData, BIT_STRING_t* bsEncapOctet)
{
    int ret = RET_OK;
    ByteArray* ba_encap = nullptr;

    CHECK_PARAM(baData != nullptr);
    CHECK_PARAM(bsEncapOctet != nullptr);

    DO(ba_encode_octetstring(baData, &ba_encap));

    bsEncapOctet->bits_unused = 0;
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

bool DstuNS::isDstu4145family (const string& algo)
{
    return isDstu4145family(algo.c_str());
}

int DstuNS::Dstu4145::decodeParams (const ByteArray* baEncoded, string& oidNamedCurve)
{
    int ret = RET_OK;
    DSTU4145Params_t* params = nullptr;
    UapkiNS::SmartBA sba_ecbinary, sba_pattern;
    char* s_oid = nullptr;

    CHECK_PARAM(baEncoded != nullptr);

    CHECK_NOT_NULL(params = (DSTU4145Params_t*)asn_decode_ba_with_alloc(get_DSTU4145Params_desc(), baEncoded));

    if (params->ellipticCurve.present == DSTUEllipticCurve_PR_namedCurve) {
        DO(asn_oid_to_text(&params->ellipticCurve.choice.namedCurve, &s_oid));
        oidNamedCurve = string(s_oid);
    }
    else if (params->ellipticCurve.present == DSTUEllipticCurve_PR_ecbinary) {
        DO(asn_encode_ba(get_ECBinary_desc(), &params->ellipticCurve.choice.ecbinary, &sba_ecbinary));

        switch (sba_ecbinary.size()) {
        case SIZE_DSTU4145_PARAM_M257_PB:
            oidNamedCurve = string(OID_DSTU4145_PARAM_M257_PB);
            sba_pattern.set(ba_alloc_from_hex(SHEX_DSTU4145_PARAM_M257_PB));
            break;
        case SIZE_DSTU4145_PARAM_M431_PB:
            oidNamedCurve = string(OID_DSTU4145_PARAM_M431_PB);
            sba_pattern.set(ba_alloc_from_hex(SHEX_DSTU4145_PARAM_M431_PB));
            break;
        }

        if (sba_pattern.size() == 0) {
            SET_ERROR(RET_UAPKI_GENERAL_ERROR);
        }

        ret = ba_cmp(sba_ecbinary.get(), sba_pattern.get());
        if (ret != RET_OK) {
            oidNamedCurve.clear();
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
    }
    else {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

cleanup:
    asn_free(get_DSTU4145Params_desc(), params);
    ::free(s_oid);
    return ret;
}

int DstuNS::Dstu4145::encodeParams (const std::string& oidNamedCurve, const ByteArray* baDKE, ByteArray** baEncoded)
{
    int ret = RET_OK;
    DSTU4145Params_t* params = nullptr;

    ASN_ALLOC_TYPE(params, DSTU4145Params_t);

    params->ellipticCurve.present = DSTUEllipticCurve_PR_namedCurve;
    DO(asn_set_oid_from_text(oidNamedCurve.c_str(), &params->ellipticCurve.choice.namedCurve));

    if (baDKE) {
        ASN_ALLOC_TYPE(params->dke, OCTET_STRING_t);
        DO(asn_ba2OCTSTRING(baDKE, params->dke));
    }

    DO(asn_encode_ba(get_DSTU4145Params_desc(), params, baEncoded));

cleanup:
    asn_free(get_DSTU4145Params_desc(), params);
    return ret;
}
