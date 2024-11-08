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

#include "oid-utils.h"


const char* ecid_to_oid (EcParamsId ecid)
{
    switch (ecid) {
    case EC_PARAMS_ID_DSTU4145_M163_PB:
        return OID_DSTU4145_PARAM_M163_PB;
    case EC_PARAMS_ID_DSTU4145_M167_PB:
        return OID_DSTU4145_PARAM_M167_PB;
    case EC_PARAMS_ID_DSTU4145_M173_PB:
        return OID_DSTU4145_PARAM_M173_PB;
    case EC_PARAMS_ID_DSTU4145_M179_PB:
        return OID_DSTU4145_PARAM_M179_PB;
    case EC_PARAMS_ID_DSTU4145_M191_PB:
        return OID_DSTU4145_PARAM_M191_PB;
    case EC_PARAMS_ID_DSTU4145_M233_PB:
        return OID_DSTU4145_PARAM_M233_PB;
    case EC_PARAMS_ID_DSTU4145_M257_PB:
        return OID_DSTU4145_PARAM_M257_PB;
    case EC_PARAMS_ID_DSTU4145_M307_PB:
        return OID_DSTU4145_PARAM_M307_PB;
    case EC_PARAMS_ID_DSTU4145_M367_PB:
        return OID_DSTU4145_PARAM_M367_PB;
    case EC_PARAMS_ID_DSTU4145_M431_PB:
        return OID_DSTU4145_PARAM_M431_PB;
    case EC_PARAMS_ID_DSTU4145_M173_ONB:
        return OID_DSTU4145_PARAM_M173_ONB;
    case EC_PARAMS_ID_DSTU4145_M179_ONB:
        return OID_DSTU4145_PARAM_M179_ONB;
    case EC_PARAMS_ID_DSTU4145_M191_ONB:
        return OID_DSTU4145_PARAM_M191_ONB;
    case EC_PARAMS_ID_DSTU4145_M233_ONB:
        return OID_DSTU4145_PARAM_M233_ONB;
    case EC_PARAMS_ID_DSTU4145_M431_ONB:
        return OID_DSTU4145_PARAM_M431_ONB;
    case EC_PARAMS_ID_NIST_P192:
        return OID_NIST_P192;
    case EC_PARAMS_ID_NIST_P224:
        return OID_NIST_P224;
    case EC_PARAMS_ID_NIST_P256:
        return OID_NIST_P256;
    case EC_PARAMS_ID_NIST_P384:
        return OID_NIST_P384;
    case EC_PARAMS_ID_NIST_P521:
        return OID_NIST_P521;
    case EC_PARAMS_ID_NIST_B233:
        return OID_NIST_B233;
    case EC_PARAMS_ID_NIST_B283:
        return OID_NIST_B283;
    case EC_PARAMS_ID_NIST_B409:
        return OID_NIST_B409;
    case EC_PARAMS_ID_NIST_B571:
        return OID_NIST_B571;
    case EC_PARAMS_ID_NIST_K233:
        return OID_NIST_K233;
    case EC_PARAMS_ID_NIST_K283:
        return OID_NIST_K283;
    case EC_PARAMS_ID_NIST_K409:
        return OID_NIST_K409;
    case EC_PARAMS_ID_NIST_K571:
        return OID_NIST_K571;
    case EC_PARAMS_ID_SEC_P256_K1:
        return OID_SECP256K1;
    case EC_PARAMS_ID_BRAINPOOL_P224_R1:
        return OID_BRAINPOOL_P224R1;
    case EC_PARAMS_ID_BRAINPOOL_P256_R1:
        return OID_BRAINPOOL_P256R1;
    case EC_PARAMS_ID_BRAINPOOL_P384_R1:
        return OID_BRAINPOOL_P384R1;
    case EC_PARAMS_ID_BRAINPOOL_P512_R1:
        return OID_BRAINPOOL_P512R1;
    case EC_PARAMS_ID_GOST_P256_A:
        return OID_ECRDSA_256A;
    case EC_PARAMS_ID_GOST_P256_B:
        return OID_ECRDSA_256B;
    case EC_PARAMS_ID_GOST_P512_A:
        return OID_ECRDSA_512A;
    case EC_PARAMS_ID_GOST_P512_B:
        return OID_ECRDSA_512B;
    case EC_PARAMS_ID_SM2_P256:
        return OID_SM2DSA_P256;
    default:
        return NULL;
    }
}

EcParamsId ecid_from_oid (const char* oid)
{
    if (oid_is_equal(OID_DSTU4145_PARAM_M257_PB, oid)) return EC_PARAMS_ID_DSTU4145_M257_PB;
    if (oid_is_equal(OID_DSTU4145_PARAM_M431_PB, oid)) return EC_PARAMS_ID_DSTU4145_M431_PB;
    if (oid_is_equal(OID_DSTU4145_PARAM_M307_PB, oid)) return EC_PARAMS_ID_DSTU4145_M307_PB;
    if (oid_is_equal(OID_DSTU4145_PARAM_M367_PB, oid)) return EC_PARAMS_ID_DSTU4145_M367_PB;
    if (oid_is_equal(OID_DSTU4145_PARAM_M163_PB, oid)) return EC_PARAMS_ID_DSTU4145_M163_PB;
    if (oid_is_equal(OID_DSTU4145_PARAM_M167_PB, oid)) return EC_PARAMS_ID_DSTU4145_M167_PB;
    if (oid_is_equal(OID_DSTU4145_PARAM_M173_PB, oid)) return EC_PARAMS_ID_DSTU4145_M173_PB;
    if (oid_is_equal(OID_DSTU4145_PARAM_M179_PB, oid)) return EC_PARAMS_ID_DSTU4145_M179_PB;
    if (oid_is_equal(OID_DSTU4145_PARAM_M191_PB, oid)) return EC_PARAMS_ID_DSTU4145_M191_PB;
    if (oid_is_equal(OID_DSTU4145_PARAM_M233_PB, oid)) return EC_PARAMS_ID_DSTU4145_M233_PB;
    if (oid_is_equal(OID_DSTU4145_PARAM_M173_ONB, oid)) return EC_PARAMS_ID_DSTU4145_M173_ONB;
    if (oid_is_equal(OID_DSTU4145_PARAM_M179_ONB, oid)) return EC_PARAMS_ID_DSTU4145_M179_ONB;
    if (oid_is_equal(OID_DSTU4145_PARAM_M191_ONB, oid)) return EC_PARAMS_ID_DSTU4145_M191_ONB;
    if (oid_is_equal(OID_DSTU4145_PARAM_M233_ONB, oid)) return EC_PARAMS_ID_DSTU4145_M233_ONB;
    if (oid_is_equal(OID_DSTU4145_PARAM_M431_ONB, oid)) return EC_PARAMS_ID_DSTU4145_M431_ONB;
    if (oid_is_equal(OID_NIST_P192, oid)) return EC_PARAMS_ID_NIST_P192;
    if (oid_is_equal(OID_NIST_P224, oid)) return EC_PARAMS_ID_NIST_P224;
    if (oid_is_equal(OID_NIST_P256, oid)) return EC_PARAMS_ID_NIST_P256;
    if (oid_is_equal(OID_NIST_P384, oid)) return EC_PARAMS_ID_NIST_P384;
    if (oid_is_equal(OID_NIST_P521, oid)) return EC_PARAMS_ID_NIST_P521;
    if (oid_is_equal(OID_NIST_B233, oid)) return EC_PARAMS_ID_NIST_B233;
    if (oid_is_equal(OID_NIST_B283, oid)) return EC_PARAMS_ID_NIST_B283;
    if (oid_is_equal(OID_NIST_B409, oid)) return EC_PARAMS_ID_NIST_B409;
    if (oid_is_equal(OID_NIST_B571, oid)) return EC_PARAMS_ID_NIST_B571;
    if (oid_is_equal(OID_NIST_K233, oid)) return EC_PARAMS_ID_NIST_K233;
    if (oid_is_equal(OID_NIST_K283, oid)) return EC_PARAMS_ID_NIST_K283;
    if (oid_is_equal(OID_NIST_K409, oid)) return EC_PARAMS_ID_NIST_K409;
    if (oid_is_equal(OID_NIST_K571, oid)) return EC_PARAMS_ID_NIST_K571;
    if (oid_is_equal(OID_SECP256K1, oid)) return EC_PARAMS_ID_SEC_P256_K1;
    if (oid_is_equal(OID_BRAINPOOL_P224R1, oid)) return EC_PARAMS_ID_BRAINPOOL_P224_R1;
    if (oid_is_equal(OID_BRAINPOOL_P256R1, oid)) return EC_PARAMS_ID_BRAINPOOL_P256_R1;
    if (oid_is_equal(OID_BRAINPOOL_P384R1, oid)) return EC_PARAMS_ID_BRAINPOOL_P384_R1;
    if (oid_is_equal(OID_BRAINPOOL_P512R1, oid)) return EC_PARAMS_ID_BRAINPOOL_P512_R1;
    if (oid_is_equal(OID_ECRDSA_256A, oid)) return EC_PARAMS_ID_GOST_P256_A;
    if (oid_is_equal(OID_ECRDSA_256B, oid)) return EC_PARAMS_ID_GOST_P256_B;
    if (oid_is_equal(OID_ECRDSA_512A, oid)) return EC_PARAMS_ID_GOST_P512_A;
    if (oid_is_equal(OID_ECRDSA_512B, oid)) return EC_PARAMS_ID_GOST_P512_B;
    if (oid_is_equal(OID_SM2DSA_P256, oid)) return EC_PARAMS_ID_SM2_P256;
    return EC_PARAMS_ID_UNDEFINED;
}

EcParamsId ecid_from_OID (const OBJECT_IDENTIFIER_t* oid)
{
    EcParamsId rv_ecid = EC_PARAMS_ID_UNDEFINED;
    char* s_oid = NULL;
    if (asn_oid_to_text(oid, &s_oid) == RET_OK) {
        rv_ecid = ecid_from_oid(s_oid);
        free(s_oid);
    }
    return rv_ecid;
}

const char* hash_to_oid (HashAlg hash)
{
    switch (hash) {
    case HASH_ALG_DSTU7564_256:
        return OID_DSTU7564_256;
    case HASH_ALG_DSTU7564_384:
        return OID_DSTU7564_384;
    case HASH_ALG_DSTU7564_512:
        return OID_DSTU7564_512;
    case HASH_ALG_GOST34311:
        return OID_GOST34311;
    case HASH_ALG_SHA1:
        return OID_SHA1;
    case HASH_ALG_SHA224:
        return OID_SHA224;
    case HASH_ALG_SHA256:
        return OID_SHA256;
    case HASH_ALG_SHA384:
        return OID_SHA384;
    case HASH_ALG_SHA512:
        return OID_SHA512;
    case HASH_ALG_SHA3_224:
        return OID_SHA3_224;
    case HASH_ALG_SHA3_256:
        return OID_SHA3_256;
    case HASH_ALG_SHA3_384:
        return OID_SHA3_384;
    case HASH_ALG_SHA3_512:
        return OID_SHA3_512;
    case HASH_ALG_WHIRLPOOL:
        return OID_WHIRLPOOL;
    case HASH_ALG_SM3:
        return OID_SM3;
    case HASH_ALG_GOSTR3411_2012_256:
        return OID_STREEBOG_256;
    case HASH_ALG_GOSTR3411_2012_512:
        return OID_STREEBOG_512;
    case HASH_ALG_RIPEMD128:
        return OID_RIPEMD128;
    case HASH_ALG_RIPEMD160:
        return OID_RIPEMD160;
    case HASH_ALG_MD5:
        return OID_MD5;
    default:
        return NULL;
    }
}

HashAlg hash_from_oid (const char* oid)
{
    if (oid_is_equal(OID_DSTU7564_256, oid) ||
        oid_is_parent(OID_DSTU4145_WITH_DSTU7564_256, oid))
        return HASH_ALG_DSTU7564_256;
    if (oid_is_equal(OID_DSTU7564_384, oid) ||
        oid_is_parent(OID_DSTU4145_WITH_DSTU7564_384, oid))
        return HASH_ALG_DSTU7564_384;
    if (oid_is_equal(OID_DSTU7564_512, oid) ||
        oid_is_parent(OID_DSTU4145_WITH_DSTU7564_512, oid))
        return HASH_ALG_DSTU7564_512;
    if (oid_is_equal(OID_GOST34311, oid) ||
        oid_is_equal(OID_HMAC_GOST34311, oid) ||
        oid_is_parent(OID_DSTU4145_WITH_GOST3411, oid))
        return HASH_ALG_GOST34311;
    if (oid_is_equal(OID_SHA1, oid) ||
        oid_is_equal(OID_HMAC_SHA1, oid) ||
        oid_is_equal(OID_ECDSA_WITH_SHA1, oid) ||
        oid_is_equal(OID_ECKCDSA_WITH_SHA1, oid) ||
        oid_is_equal(OID_ECGDSA_SIGNATURE_WITH_SHA1, oid) ||
        oid_is_equal(OID_RSA_WITH_SHA1, oid))
        return HASH_ALG_SHA1;
    if (oid_is_equal(OID_SHA224, oid) ||
        oid_is_equal(OID_HMAC_SHA224, oid) ||
        oid_is_equal(OID_ECDSA_WITH_SHA224, oid) ||
        oid_is_equal(OID_ECKCDSA_WITH_SHA224, oid) ||
        oid_is_equal(OID_ECGDSA_SIGNATURE_WITH_SHA224, oid) ||
        oid_is_equal(OID_RSA_WITH_SHA224, oid))
        return HASH_ALG_SHA224;
    if (oid_is_equal(OID_SHA256, oid) ||
        oid_is_equal(OID_HMAC_SHA256, oid) ||
        oid_is_equal(OID_ECDSA_WITH_SHA256, oid) ||
        oid_is_equal(OID_ECKCDSA_WITH_SHA256, oid) ||
        oid_is_equal(OID_ECGDSA_SIGNATURE_WITH_SHA256, oid) ||
        oid_is_equal(OID_RSA_WITH_SHA256, oid))
        return HASH_ALG_SHA256;
    if (oid_is_equal(OID_SHA384, oid) ||
        oid_is_equal(OID_HMAC_SHA384, oid) ||
        oid_is_equal(OID_ECDSA_WITH_SHA384, oid) ||
        oid_is_equal(OID_ECGDSA_SIGNATURE_WITH_SHA384, oid) ||
        oid_is_equal(OID_RSA_WITH_SHA384, oid))
        return HASH_ALG_SHA384;
    if (oid_is_equal(OID_SHA512, oid) ||
        oid_is_equal(OID_HMAC_SHA512, oid) ||
        oid_is_equal(OID_ECDSA_WITH_SHA512, oid) ||
        oid_is_equal(OID_ECGDSA_SIGNATURE_WITH_SHA512, oid) ||
        oid_is_equal(OID_RSA_WITH_SHA512, oid))
        return HASH_ALG_SHA512;
    if (oid_is_equal(OID_SHA3_224, oid) ||
        oid_is_equal(OID_ECDSA_WITH_SHA3_224, oid) ||
        oid_is_equal(OID_RSA_WITH_SHA3_224, oid))
        return HASH_ALG_SHA3_224;
    if (oid_is_equal(OID_SHA3_256, oid) ||
        oid_is_equal(OID_ECDSA_WITH_SHA3_256, oid) ||
        oid_is_equal(OID_RSA_WITH_SHA3_256, oid))
        return HASH_ALG_SHA3_256;
    if (oid_is_equal(OID_SHA3_384, oid) ||
        oid_is_equal(OID_ECDSA_WITH_SHA3_384, oid) ||
        oid_is_equal(OID_RSA_WITH_SHA3_384, oid))
        return HASH_ALG_SHA3_384;
    if (oid_is_equal(OID_SHA3_512, oid) ||
        oid_is_equal(OID_ECDSA_WITH_SHA3_512, oid) ||
        oid_is_equal(OID_RSA_WITH_SHA3_512, oid))
        return HASH_ALG_SHA3_512;
    if (oid_is_equal(OID_SM3, oid) ||
        oid_is_equal(OID_SM3_ISO, oid) ||
        oid_is_equal(OID_SM2_WITH_SM3, oid) ||
        oid_is_equal(OID_RSA_WITH_SM3, oid))
        return HASH_ALG_SM3;
    if (oid_is_equal(OID_STREEBOG_256, oid) ||
        oid_is_equal(OID_GOST_3410_2012_256, oid))
        return HASH_ALG_GOSTR3411_2012_256;
    if (oid_is_equal(OID_STREEBOG_512, oid) ||
        oid_is_equal(OID_GOST_3410_2012_512, oid))
        return HASH_ALG_GOSTR3411_2012_512;
    if (oid_is_equal(OID_RIPEMD128, oid))
        return HASH_ALG_RIPEMD128;
    if (oid_is_equal(OID_RIPEMD160, oid) ||
        oid_is_equal(OID_HMAC_RIPEMD160, oid) ||
        oid_is_equal(OID_ECGDSA_SIGNATURE_WITH_RIPEMD160, oid))
        return HASH_ALG_RIPEMD160;
    if (oid_is_equal(OID_MD5, oid) ||
        oid_is_equal(OID_HMAC_MD5, oid) ||
        oid_is_equal(OID_RSA_WITH_MD5, oid))
        return HASH_ALG_MD5;
    if (oid_is_equal(OID_WHIRLPOOL, oid))
        return HASH_ALG_WHIRLPOOL;
    return HASH_ALG_UNDEFINED;
}

HashAlg hash_from_OID (const OBJECT_IDENTIFIER_t* oid)
{
    HashAlg rv_hashalg = HASH_ALG_UNDEFINED;
    char* s_oid = NULL;
    if (asn_oid_to_text(oid, &s_oid) == RET_OK) {
        rv_hashalg = hash_from_oid(s_oid);
        free(s_oid);
    }
    return rv_hashalg;
}

SignAlg signature_from_oid (const char* oid)
{
    if (oid_is_parent(OID_DSTU4145_PARAM_PB_LE, oid) ||
        oid_is_parent(OID_DSTU4145_WITH_DSTU7564, oid)) {
        return SIGN_DSTU4145;
    }

    if (oid_is_equal(OID_ECDSA_WITH_SHA1, oid) ||
        oid_is_parent("1.2.840.10045.4.3", oid) ||
        oid_is_equal(OID_ECDSA_WITH_SHA3_224, oid) ||
        oid_is_equal(OID_ECDSA_WITH_SHA3_256, oid) ||
        oid_is_equal(OID_ECDSA_WITH_SHA3_384, oid) ||
        oid_is_equal(OID_ECDSA_WITH_SHA3_512, oid)) {
        return SIGN_ECDSA;
    }

    if (oid_is_parent("1.2.410.200004.1.100.4", oid)) {
        return SIGN_ECKCDSA;
    }

    if (oid_is_parent(OID_ECGDSA_SIGNATURE, oid)) {
        return SIGN_ECGDSA;
    }

    if (oid_is_equal(OID_GOST_3410_2012_256, oid) ||
        oid_is_equal(OID_GOST_3410_2012_512, oid)) {
        return SIGN_ECRDSA;
    }

    if (oid_is_equal(OID_SM2_WITH_SM3, oid)) {
        return SIGN_SM2DSA;
    }

    if (oid_is_parent("1.2.840.113549.1.1", oid) ||
        oid_is_equal(OID_RSA_WITH_SHA3_224, oid) ||
        oid_is_equal(OID_RSA_WITH_SHA3_256, oid) ||
        oid_is_equal(OID_RSA_WITH_SHA3_384, oid) ||
        oid_is_equal(OID_RSA_WITH_SHA3_512, oid) ||
        oid_is_equal(OID_RSA_WITH_SM3, oid)) {
        return SIGN_RSA_PKCS_1_5;
    }

    if (oid_is_equal(OID_RSA_PSS, oid)) {
        return SIGN_RSA_PSS;
    }

    return SIGN_UNDEFINED;
}

SignAlg signature_from_OID (const OBJECT_IDENTIFIER_t* oid)
{
    SignAlg rv_signalg = SIGN_UNDEFINED;
    char* s_oid = NULL;
    if (asn_oid_to_text(oid, &s_oid) == RET_OK) {
        rv_signalg = signature_from_oid(s_oid);
        free(s_oid);
    }
    return rv_signalg;
}

bool OID_is_child_oid (const OBJECT_IDENTIFIER_t* oid, const char* strOidParent)
{
    bool is_child = false;
    char* s_oid = NULL;
    if (asn_oid_to_text(oid, &s_oid) == RET_OK) {
        is_child = oid_is_parent(strOidParent, s_oid);
        free(s_oid);
    }
    return is_child;
}

bool OID_is_equal_oid (const OBJECT_IDENTIFIER_t* oid, const char* strOid)
{
    bool is_equal = false;
    char* s_oid = NULL;
    if (asn_oid_to_text(oid, &s_oid) == RET_OK) {
        is_equal = oid_is_equal(strOid, s_oid);
        free(s_oid);
    }
    return is_equal;
}

const char* oid_to_rdname (const char* oid)
{
    const char* rv_s = oid;
    if (strcmp(oid,      OID_X520_CommonName            ) == 0) rv_s = "CN";
    else if (strcmp(oid, OID_X520_Surname               ) == 0) rv_s = "SN";
    else if (strcmp(oid, OID_X520_SerialNumber          ) == 0) rv_s = "SERIALNUMBER";
    else if (strcmp(oid, OID_X520_Country               ) == 0) rv_s = "C";
    else if (strcmp(oid, OID_X520_Locality              ) == 0) rv_s = "L";
    else if (strcmp(oid, OID_X520_State                 ) == 0) rv_s = "S";
    else if (strcmp(oid, OID_X520_StreetAddress         ) == 0) rv_s = "STREET";
    else if (strcmp(oid, OID_X520_Organization          ) == 0) rv_s = "O";
    else if (strcmp(oid, OID_X520_OrganizationalUnit    ) == 0) rv_s = "OU";
    else if (strcmp(oid, OID_X520_Title                 ) == 0) rv_s = "TITLE";
    else if (strcmp(oid, OID_X520_GivenName             ) == 0) rv_s = "G";
    else if (strcmp(oid, OID_X520_OrganizationIdentifier) == 0) rv_s = "OI";
    return rv_s;
}
