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

//  Last update: 2023-02-01

#ifndef UAPKI_OIDS_H
#define UAPKI_OIDS_H


#include <stdbool.h>


#ifdef __cplusplus
extern "C" {
#endif

#ifndef DEFINE_OID
#define DEFINE_OID(OID_NAME,OID_VAL) extern const char *OID_NAME
#endif

//--------------------------------------------------------------------------------------
//CIPHER MODES
//TDES
DEFINE_OID(OID_TDES_CBC, "1.2.840.113549.3.7");

//AES
DEFINE_OID(OID_AES,             "2.16.840.1.101.3.4.1");
DEFINE_OID(OID_AES128_ECB,      "2.16.840.1.101.3.4.1.1");
DEFINE_OID(OID_AES128_CBC_PAD,  "2.16.840.1.101.3.4.1.2");
DEFINE_OID(OID_AES128_OFB,      "2.16.840.1.101.3.4.1.3");
DEFINE_OID(OID_AES128_CFB,      "2.16.840.1.101.3.4.1.4");
DEFINE_OID(OID_AES128_WRAP,     "2.16.840.1.101.3.4.1.5");
DEFINE_OID(OID_AES128_GCM,      "2.16.840.1.101.3.4.1.6");
DEFINE_OID(OID_AES128_CCM,      "2.16.840.1.101.3.4.1.7");
DEFINE_OID(OID_AES128_WRAP_PAD, "2.16.840.1.101.3.4.1.8");
DEFINE_OID(OID_AES192_ECB,      "2.16.840.1.101.3.4.1.21");
DEFINE_OID(OID_AES192_CBC_PAD,  "2.16.840.1.101.3.4.1.22");
DEFINE_OID(OID_AES192_OFB,      "2.16.840.1.101.3.4.1.23");
DEFINE_OID(OID_AES192_CFB,      "2.16.840.1.101.3.4.1.24");
DEFINE_OID(OID_AES192_WRAP,     "2.16.840.1.101.3.4.1.25");
DEFINE_OID(OID_AES192_GCM,      "2.16.840.1.101.3.4.1.26");
DEFINE_OID(OID_AES192_CCM,      "2.16.840.1.101.3.4.1.27");
DEFINE_OID(OID_AES192_WRAP_PAD, "2.16.840.1.101.3.4.1.28");
DEFINE_OID(OID_AES256_ECB,      "2.16.840.1.101.3.4.1.41");
DEFINE_OID(OID_AES256_CBC_PAD,  "2.16.840.1.101.3.4.1.42");
DEFINE_OID(OID_AES256_OFB,      "2.16.840.1.101.3.4.1.43");
DEFINE_OID(OID_AES256_CFB,      "2.16.840.1.101.3.4.1.44");
DEFINE_OID(OID_AES256_WRAP,     "2.16.840.1.101.3.4.1.45");
DEFINE_OID(OID_AES256_GCM,      "2.16.840.1.101.3.4.1.46");
DEFINE_OID(OID_AES256_CCM,      "2.16.840.1.101.3.4.1.47");
DEFINE_OID(OID_AES256_WRAP_PAD, "2.16.840.1.101.3.4.1.48");

//GOST28147
DEFINE_OID(OID_GOST28147,       "1.2.804.2.1.1.1.1.1.1");
DEFINE_OID(OID_GOST28147_ECB,   "1.2.804.2.1.1.1.1.1.1.1");
DEFINE_OID(OID_GOST28147_CTR,   "1.2.804.2.1.1.1.1.1.1.2");
DEFINE_OID(OID_GOST28147_CFB,   "1.2.804.2.1.1.1.1.1.1.3");
DEFINE_OID(OID_GOST28147_CMAC,  "1.2.804.2.1.1.1.1.1.1.4");
DEFINE_OID(OID_GOST28147_WRAP,  "1.2.804.2.1.1.1.1.1.1.5");

//KALYNA
DEFINE_OID(OID_DSTU7624,            "1.2.804.2.1.1.1.1.1.3");
DEFINE_OID(OID_DSTU7624_ECB,        "1.2.804.2.1.1.1.1.1.3.1");
DEFINE_OID(OID_DSTU7624_128_ECB,    "1.2.804.2.1.1.1.1.1.3.1.1");
DEFINE_OID(OID_DSTU7624_256_ECB,    "1.2.804.2.1.1.1.1.1.3.1.2");
DEFINE_OID(OID_DSTU7624_512_ECB,    "1.2.804.2.1.1.1.1.1.3.1.3");
DEFINE_OID(OID_DSTU7624_CTR,        "1.2.804.2.1.1.1.1.1.3.2");
DEFINE_OID(OID_DSTU7624_128_CTR,    "1.2.804.2.1.1.1.1.1.3.2.1");
DEFINE_OID(OID_DSTU7624_256_CTR,    "1.2.804.2.1.1.1.1.1.3.2.2");
DEFINE_OID(OID_DSTU7624_512_CTR,    "1.2.804.2.1.1.1.1.1.3.2.3");
DEFINE_OID(OID_DSTU7624_CFB,        "1.2.804.2.1.1.1.1.1.3.3");
DEFINE_OID(OID_DSTU7624_128_CFB,    "1.2.804.2.1.1.1.1.1.3.3.1");
DEFINE_OID(OID_DSTU7624_256_CFB,    "1.2.804.2.1.1.1.1.1.3.3.2");
DEFINE_OID(OID_DSTU7624_512_CFB,    "1.2.804.2.1.1.1.1.1.3.3.3");
DEFINE_OID(OID_DSTU7624_CMAC,       "1.2.804.2.1.1.1.1.1.3.4");
DEFINE_OID(OID_DSTU7624_128_CMAC,   "1.2.804.2.1.1.1.1.1.3.4.1");
DEFINE_OID(OID_DSTU7624_256_CMAC,   "1.2.804.2.1.1.1.1.1.3.4.2");
DEFINE_OID(OID_DSTU7624_512_CMAC,   "1.2.804.2.1.1.1.1.1.3.4.3");
DEFINE_OID(OID_DSTU7624_CBC,        "1.2.804.2.1.1.1.1.1.3.5");
DEFINE_OID(OID_DSTU7624_128_CBC,    "1.2.804.2.1.1.1.1.1.3.5.1");
DEFINE_OID(OID_DSTU7624_256_CBC,    "1.2.804.2.1.1.1.1.1.3.5.2");
DEFINE_OID(OID_DSTU7624_512_CBC,    "1.2.804.2.1.1.1.1.1.3.5.3");
DEFINE_OID(OID_DSTU7624_OFB,        "1.2.804.2.1.1.1.1.1.3.6");
DEFINE_OID(OID_DSTU7624_128_OFB,    "1.2.804.2.1.1.1.1.1.3.6.1");
DEFINE_OID(OID_DSTU7624_256_OFB,    "1.2.804.2.1.1.1.1.1.3.6.2");
DEFINE_OID(OID_DSTU7624_512_OFB,    "1.2.804.2.1.1.1.1.1.3.6.3");
DEFINE_OID(OID_DSTU7624_GMAC,       "1.2.804.2.1.1.1.1.1.3.7");
DEFINE_OID(OID_DSTU7624_128_GMAC,   "1.2.804.2.1.1.1.1.1.3.7.1");
DEFINE_OID(OID_DSTU7624_256_GMAC,   "1.2.804.2.1.1.1.1.1.3.7.2");
DEFINE_OID(OID_DSTU7624_512_GMAC,   "1.2.804.2.1.1.1.1.1.3.7.3");
DEFINE_OID(OID_DSTU7624_CCM,        "1.2.804.2.1.1.1.1.1.3.8");
DEFINE_OID(OID_DSTU7624_128_CCM,    "1.2.804.2.1.1.1.1.1.3.8.1");
DEFINE_OID(OID_DSTU7624_256_CCM,    "1.2.804.2.1.1.1.1.1.3.8.2");
DEFINE_OID(OID_DSTU7624_512_CCM,    "1.2.804.2.1.1.1.1.1.3.8.3");
DEFINE_OID(OID_DSTU7624_XTS,        "1.2.804.2.1.1.1.1.1.3.9");
DEFINE_OID(OID_DSTU7624_128_XTS,    "1.2.804.2.1.1.1.1.1.3.9.1");
DEFINE_OID(OID_DSTU7624_256_XTS,    "1.2.804.2.1.1.1.1.1.3.9.2");
DEFINE_OID(OID_DSTU7624_512_XTS,    "1.2.804.2.1.1.1.1.1.3.9.3");
DEFINE_OID(OID_DSTU7624_KW,         "1.2.804.2.1.1.1.1.1.3.10");
DEFINE_OID(OID_DSTU7624_128_KW,     "1.2.804.2.1.1.1.1.1.3.10.1");
DEFINE_OID(OID_DSTU7624_256_KW,     "1.2.804.2.1.1.1.1.1.3.10.2");
DEFINE_OID(OID_DSTU7624_512_KW,     "1.2.804.2.1.1.1.1.1.3.10.3");
DEFINE_OID(OID_DSTU7624_WRAP,       "1.2.804.2.1.1.1.1.1.3.11");
DEFINE_OID(OID_DSTU7624_GCM,        "1.2.804.2.1.1.1.1.1.3.12");   //!!! NON STANDARD
DEFINE_OID(OID_DSTU7624_128_GCM,    "1.2.804.2.1.1.1.1.1.3.12.1"); //!!! NON STANDARD
DEFINE_OID(OID_DSTU7624_256_GCM,    "1.2.804.2.1.1.1.1.1.3.12.2"); //!!! NON STANDARD
DEFINE_OID(OID_DSTU7624_512_GCM,    "1.2.804.2.1.1.1.1.1.3.12.3"); //!!! NON STANDARD

//DES
DEFINE_OID(OID_DES_EDE3_CBC, "1.2.840.113549.3.7");

//--------------------------------------------------------------------------------------
//HASHSES AND HMACS
//GOST34311
DEFINE_OID(OID_GOST34311,       "1.2.804.2.1.1.1.1.2.1");
DEFINE_OID(OID_HMAC_GOST34311,  "1.2.804.2.1.1.1.1.1.2");

//KUPYNA
DEFINE_OID(OID_DSTU7564,            "1.2.804.2.1.1.1.1.2.2");
DEFINE_OID(OID_DSTU7564_256,        "1.2.804.2.1.1.1.1.2.2.1");
DEFINE_OID(OID_DSTU7564_384,        "1.2.804.2.1.1.1.1.2.2.2");
DEFINE_OID(OID_DSTU7564_512,        "1.2.804.2.1.1.1.1.2.2.3");
DEFINE_OID(OID_DSTU7564_256_MAC,    "1.2.804.2.1.1.1.1.2.2.4");
DEFINE_OID(OID_DSTU7564_384_MAC,    "1.2.804.2.1.1.1.1.2.2.5");
DEFINE_OID(OID_DSTU7564_512_MAC,    "1.2.804.2.1.1.1.1.2.2.6");

//MD5
DEFINE_OID(OID_MD5,         "1.2.840.113549.2.5");
DEFINE_OID(OID_HMAC_MD5,    "1.3.6.1.5.5.8.1.1");

//SHA1
DEFINE_OID(OID_SHA1,        "1.3.14.3.2.26");
DEFINE_OID(OID_HMAC_SHA1,   "1.2.840.113549.2.7");

//SHA2
DEFINE_OID(OID_SHA256,          "2.16.840.1.101.3.4.2.1");
DEFINE_OID(OID_SHA384,          "2.16.840.1.101.3.4.2.2");
DEFINE_OID(OID_SHA512,          "2.16.840.1.101.3.4.2.3");
DEFINE_OID(OID_SHA224,          "2.16.840.1.101.3.4.2.4");
DEFINE_OID(OID_SHA512_224,      "2.16.840.1.101.3.4.2.5");
DEFINE_OID(OID_SHA512_256,      "2.16.840.1.101.3.4.2.6");
DEFINE_OID(OID_HMAC_SHA224,     "1.2.840.113549.2.8");
DEFINE_OID(OID_HMAC_SHA256,     "1.2.840.113549.2.9");
DEFINE_OID(OID_HMAC_SHA384,     "1.2.840.113549.2.10");
DEFINE_OID(OID_HMAC_SHA512,     "1.2.840.113549.2.11");
DEFINE_OID(OID_HMAC_SHA512_224, "1.2.840.113549.2.12");
DEFINE_OID(OID_HMAC_SHA512_256, "1.2.840.113549.2.13");

//SHA3
DEFINE_OID(OID_SHA3_224,        "2.16.840.1.101.3.4.2.7");
DEFINE_OID(OID_SHA3_256,        "2.16.840.1.101.3.4.2.8");
DEFINE_OID(OID_SHA3_384,        "2.16.840.1.101.3.4.2.9");
DEFINE_OID(OID_SHA3_512,        "2.16.840.1.101.3.4.2.10");
DEFINE_OID(OID_SHA3_SHAKE128,   "2.16.840.1.101.3.4.2.11");
DEFINE_OID(OID_SHA3_SHAKE256,   "2.16.840.1.101.3.4.2.12");
DEFINE_OID(OID_HMAC_SHA3_224,   "2.16.840.1.101.3.4.2.13");
DEFINE_OID(OID_HMAC_SHA3_256,   "2.16.840.1.101.3.4.2.14");
DEFINE_OID(OID_HMAC_SHA3_384,   "2.16.840.1.101.3.4.2.15");
DEFINE_OID(OID_HMAC_SHA3_512, " 2.16.840.1.101.3.4.2.16");

//RIPEMD
DEFINE_OID(OID_RIPEMD160,       "1.3.36.3.2.1");
DEFINE_OID(OID_RIPEMD128,       "1.3.36.3.2.2");
DEFINE_OID(OID_HMAC_RIPEMD160,  "1.3.6.1.5.5.8.1.4");

//WHIRLPOOL
DEFINE_OID(OID_WHIRLPOOL, "1.0.10118.3.0.55");

//STREEBOG
DEFINE_OID(OID_STREEBOG_256, "1.2.643.7.1.1.2.2");
DEFINE_OID(OID_STREEBOG_512, "1.2.643.7.1.1.2.3");

//SM3
DEFINE_OID(OID_SM3, "1.2.156.10197.1.401");
DEFINE_OID(OID_SM3_ISO, "1.0.10118.3.0.65");

//-----------------------------------------------------------------------------------------
//SIGNATURES

//DSTU4145
DEFINE_OID(OID_DSTU4145_WITH_GOST3411,      "1.2.804.2.1.1.1.1.3.1");
DEFINE_OID(OID_DSTU4145_WITH_DSTU7564,      "1.2.804.2.1.1.1.1.3.6");
DEFINE_OID(OID_DSTU4145_WITH_DSTU7564_256,  "1.2.804.2.1.1.1.1.3.6.1");
DEFINE_OID(OID_DSTU4145_WITH_DSTU7564_384,  "1.2.804.2.1.1.1.1.3.6.2");
DEFINE_OID(OID_DSTU4145_WITH_DSTU7564_512,  "1.2.804.2.1.1.1.1.3.6.3");

//EC-DSA
DEFINE_OID(OID_EC_KEY,              "1.2.840.10045.2.1");
DEFINE_OID(OID_ECDSA_WITH_SHA1,     "1.2.840.10045.4.1");
DEFINE_OID(OID_ECDSA_WITH_SHA224,   "1.2.840.10045.4.3.1");
DEFINE_OID(OID_ECDSA_WITH_SHA256,   "1.2.840.10045.4.3.2");
DEFINE_OID(OID_ECDSA_WITH_SHA384,   "1.2.840.10045.4.3.3");
DEFINE_OID(OID_ECDSA_WITH_SHA512,   "1.2.840.10045.4.3.4");
DEFINE_OID(OID_ECDSA_WITH_SHA3_224, "2.16.840.1.101.3.4.3.9");
DEFINE_OID(OID_ECDSA_WITH_SHA3_256, "2.16.840.1.101.3.4.3.10");
DEFINE_OID(OID_ECDSA_WITH_SHA3_384, "2.16.840.1.101.3.4.3.11");
DEFINE_OID(OID_ECDSA_WITH_SHA3_512, "2.16.840.1.101.3.4.3.12");

//EC-KCDSA
DEFINE_OID(OID_ECKCDSA,             "1.0.14888.3.0.5");
DEFINE_OID(OID_ECKCDSA_WITH_SHA1,   "1.2.410.200004.1.100.4.3");
DEFINE_OID(OID_ECKCDSA_WITH_SHA224, "1.2.410.200004.1.100.4.4");
DEFINE_OID(OID_ECKCDSA_WITH_SHA256, "1.2.410.200004.1.100.4.5");

//EC-GDSA
DEFINE_OID(OID_ECGDSA_STD,                      "1.3.36.3.3.2.5");
DEFINE_OID(OID_ECGDSA_KEY,                      "1.3.36.3.3.2.5.2.1");
DEFINE_OID(OID_ECGDSA_SIGNATURE,                "1.3.36.3.3.2.5.4");
DEFINE_OID(OID_ECGDSA_SIGNATURE_WITH_RIPEMD160, "1.3.36.3.3.2.5.4.1");
DEFINE_OID(OID_ECGDSA_SIGNATURE_WITH_SHA1,      "1.3.36.3.3.2.5.4.2");
DEFINE_OID(OID_ECGDSA_SIGNATURE_WITH_SHA224,    "1.3.36.3.3.2.5.4.3");
DEFINE_OID(OID_ECGDSA_SIGNATURE_WITH_SHA256,    "1.3.36.3.3.2.5.4.4");
DEFINE_OID(OID_ECGDSA_SIGNATURE_WITH_SHA384,    "1.3.36.3.3.2.5.4.5");
DEFINE_OID(OID_ECGDSA_SIGNATURE_WITH_SHA512,    "1.3.36.3.3.2.5.4.6");

//GOST R 34.10-2012
DEFINE_OID(OID_GOST_KEY_3410_2012_256,  "1.2.643.7.1.1.1.1");
DEFINE_OID(OID_GOST_KEY_3410_2012_512,  "1.2.643.7.1.1.1.2");
DEFINE_OID(OID_GOST_3410_2012_256,      "1.2.643.7.1.1.3.2"); /*"GOST-34.10-2012-256/EMSA1(Streebog-256)"*/
DEFINE_OID(OID_GOST_3410_2012_512,      "1.2.643.7.1.1.3.3"); /*"GOST-34.10-2012-512/EMSA1(Streebog-512)"*/

//SM2 DSA
DEFINE_OID(OID_SM2,             "1.0.14888.3.0.14");
DEFINE_OID(OID_SM2_WITH_SM3,    "1.2.156.10197.1.501");

//RSA
DEFINE_OID(OID_RSA,                 "1.2.840.113549.1.1.1");
DEFINE_OID(OID_RSA_WITH_MD5,        "1.2.840.113549.1.1.4");
DEFINE_OID(OID_RSA_WITH_SHA1,       "1.2.840.113549.1.1.5");
DEFINE_OID(OID_RSA_WITH_SHA224,     "1.2.840.113549.1.1.14");
DEFINE_OID(OID_RSA_WITH_SHA256,     "1.2.840.113549.1.1.11");
DEFINE_OID(OID_RSA_WITH_SHA384,     "1.2.840.113549.1.1.12");
DEFINE_OID(OID_RSA_WITH_SHA512,     "1.2.840.113549.1.1.13");
DEFINE_OID(OID_RSA_WITH_SHA3_224,   "2.16.840.1.101.3.4.3.13");
DEFINE_OID(OID_RSA_WITH_SHA3_256,   "2.16.840.1.101.3.4.3.14");
DEFINE_OID(OID_RSA_WITH_SHA3_384,   "2.16.840.1.101.3.4.3.15");
DEFINE_OID(OID_RSA_WITH_SHA3_512,   "2.16.840.1.101.3.4.3.16");
DEFINE_OID(OID_RSA_WITH_SM3,        "1.2.156.10197.1.504");
DEFINE_OID(OID_RSA_PSS,             "1.2.840.113549.1.1.10");

//-----------------------------------------------------------------------------------------
//EC PARAMETERS
//DSTU4145
DEFINE_OID(OID_DSTU4145_PARAM_PB_LE,    "1.2.804.2.1.1.1.1.3.1.1");
DEFINE_OID(OID_DSTU4145_PARAM_SPECIAL_CURVES_PB, "1.2.804.2.1.1.1.1.3.1.1.1");
DEFINE_OID(OID_DSTU4145_PARAM_PB_BE,    "1.2.804.2.1.1.1.1.3.1.1.1.1");
DEFINE_OID(OID_DSTU4145_PARAM_NAMED_CURVES_PB, "1.2.804.2.1.1.1.1.3.1.1.2");
DEFINE_OID(OID_DSTU4145_PARAM_M163_PB,  "1.2.804.2.1.1.1.1.3.1.1.2.0");
DEFINE_OID(OID_DSTU4145_PARAM_M167_PB,  "1.2.804.2.1.1.1.1.3.1.1.2.1");
DEFINE_OID(OID_DSTU4145_PARAM_M173_PB,  "1.2.804.2.1.1.1.1.3.1.1.2.2");
DEFINE_OID(OID_DSTU4145_PARAM_M179_PB,  "1.2.804.2.1.1.1.1.3.1.1.2.3");
DEFINE_OID(OID_DSTU4145_PARAM_M191_PB,  "1.2.804.2.1.1.1.1.3.1.1.2.4");
DEFINE_OID(OID_DSTU4145_PARAM_M233_PB,  "1.2.804.2.1.1.1.1.3.1.1.2.5");
DEFINE_OID(OID_DSTU4145_PARAM_M257_PB,  "1.2.804.2.1.1.1.1.3.1.1.2.6");
DEFINE_OID(OID_DSTU4145_PARAM_M307_PB,  "1.2.804.2.1.1.1.1.3.1.1.2.7");
DEFINE_OID(OID_DSTU4145_PARAM_M367_PB,  "1.2.804.2.1.1.1.1.3.1.1.2.8");
DEFINE_OID(OID_DSTU4145_PARAM_M431_PB,  "1.2.804.2.1.1.1.1.3.1.1.2.9");
DEFINE_OID(OID_DSTU4145_PARAM_ONB_LE,   "1.2.804.2.1.1.1.1.3.1.2");
DEFINE_OID(OID_DSTU4145_PARAM_SPECIAL_CURVES_ONB, "1.2.804.2.1.1.1.1.3.1.2.1");
DEFINE_OID(OID_DSTU4145_PARAM_ONB_BE,   "1.2.804.2.1.1.1.1.3.1.2.1.1");
DEFINE_OID(OID_DSTU4145_PARAM_CURVES_ONB, "1.2.804.2.1.1.1.1.3.1.2.2");
DEFINE_OID(OID_DSTU4145_PARAM_M173_ONB, "1.2.804.2.1.1.1.1.3.1.2.2.0");
DEFINE_OID(OID_DSTU4145_PARAM_M179_ONB, "1.2.804.2.1.1.1.1.3.1.2.2.1");
DEFINE_OID(OID_DSTU4145_PARAM_M191_ONB, "1.2.804.2.1.1.1.1.3.1.2.2.2");
DEFINE_OID(OID_DSTU4145_PARAM_M233_ONB, "1.2.804.2.1.1.1.1.3.1.2.2.3");
DEFINE_OID(OID_DSTU4145_PARAM_M431_ONB, "1.2.804.2.1.1.1.1.3.1.2.2.4");

//EC-DSA
DEFINE_OID(OID_NIST_P192, "1.2.840.10045.3.1.1"); //secp192r1
DEFINE_OID(OID_NIST_P224, "1.3.132.0.33"); //secp224r1
DEFINE_OID(OID_NIST_P256, "1.2.840.10045.3.1.7"); //secp256kr1
DEFINE_OID(OID_NIST_P384, "1.3.132.0.34"); //secp384r1
DEFINE_OID(OID_NIST_P521, "1.3.132.0.35"); //secp521r1
DEFINE_OID(OID_NIST_K233, "1.3.132.0.26"); //sect233k1
DEFINE_OID(OID_NIST_B233, "1.3.132.0.27"); //sect233r1
DEFINE_OID(OID_NIST_K283, "1.3.132.0.16"); //sect283k1
DEFINE_OID(OID_NIST_B283, "1.3.132.0.17"); //sect283r1
DEFINE_OID(OID_NIST_K409, "1.3.132.0.36"); //sect409k1
DEFINE_OID(OID_NIST_B409, "1.3.132.0.37"); //sect409r1
DEFINE_OID(OID_NIST_K571, "1.3.132.0.38"); //sect571k1
DEFINE_OID(OID_NIST_B571, "1.3.132.0.39"); //sect571r1
DEFINE_OID(OID_SECP256K1, "1.3.132.0.10");
DEFINE_OID(OID_SECT239K1, "1.3.132.0.3");

// EC-GDSA
DEFINE_OID(OID_BRAINPOOL,        "1.3.36.3.3.2.8");
DEFINE_OID(OID_BRAINPOOL_EC,     "1.3.36.3.3.2.8.1");
DEFINE_OID(OID_BRAINPOOL_P224R1, "1.3.36.3.3.2.8.1.1.5");
DEFINE_OID(OID_BRAINPOOL_P224T1, "1.3.36.3.3.2.8.1.1.6");
DEFINE_OID(OID_BRAINPOOL_P256R1, "1.3.36.3.3.2.8.1.1.7");
DEFINE_OID(OID_BRAINPOOL_P256T1, "1.3.36.3.3.2.8.1.1.8");
DEFINE_OID(OID_BRAINPOOL_P320R1, "1.3.36.3.3.2.8.1.1.9");
DEFINE_OID(OID_BRAINPOOL_P320T1, "1.3.36.3.3.2.8.1.1.10");
DEFINE_OID(OID_BRAINPOOL_P384R1, "1.3.36.3.3.2.8.1.1.11");
DEFINE_OID(OID_BRAINPOOL_P384T1, "1.3.36.3.3.2.8.1.1.12");
DEFINE_OID(OID_BRAINPOOL_P512R1, "1.3.36.3.3.2.8.1.1.13");
DEFINE_OID(OID_BRAINPOOL_P512T1, "1.3.36.3.3.2.8.1.1.14");

// EC-RDSA
DEFINE_OID(OID_ECRDSA_256A, "1.2.643.7.1.2.1.1.1");
DEFINE_OID(OID_ECRDSA_256B, "1.2.643.7.1.2.1.1.2");
DEFINE_OID(OID_ECRDSA_512A, "1.2.643.7.1.2.1.2.1");
DEFINE_OID(OID_ECRDSA_512B, "1.2.643.7.1.2.1.2.2");

//SM2-DSA
DEFINE_OID(OID_SM2DSA_P256, "1.2.156.10197.1.301");

//-----------------------------------------------------------------------------------------
//PKIX
DEFINE_OID(OID_X520_CommonName,             "2.5.4.3");
DEFINE_OID(OID_X520_Surname,                "2.5.4.4");
DEFINE_OID(OID_X520_SerialNumber,           "2.5.4.5");
DEFINE_OID(OID_X520_Country,                "2.5.4.6");
DEFINE_OID(OID_X520_Locality,               "2.5.4.7");
DEFINE_OID(OID_X520_State,                  "2.5.4.8");
DEFINE_OID(OID_X520_StreetAddress,          "2.5.4.9");
DEFINE_OID(OID_X520_Organization,           "2.5.4.10");
DEFINE_OID(OID_X520_OrganizationalUnit,     "2.5.4.11");
DEFINE_OID(OID_X520_Title,                  "2.5.4.12");
DEFINE_OID(OID_X520_GivenName,              "2.5.4.42");
DEFINE_OID(OID_X520_Initials,               "2.5.4.43");
DEFINE_OID(OID_X520_GenerationalQualifier,  "2.5.4.44");
DEFINE_OID(OID_X520_DNQualifier,            "2.5.4.46");
DEFINE_OID(OID_X520_Pseudonym,              "2.5.4.65");
DEFINE_OID(OID_X520_OrganizationIdentifier, "2.5.4.97");

DEFINE_OID(OID_X509v3_SubjectDirectoryAttributes,   "2.5.29.9");
DEFINE_OID(OID_X509v3_SubjectKeyIdentifier,         "2.5.29.14");
DEFINE_OID(OID_X509v3_KeyUsage,                     "2.5.29.15");
DEFINE_OID(OID_X509v3_PrivateKeyUsagePeriod,        "2.5.29.16");
DEFINE_OID(OID_X509v3_SubjectAlternativeName,       "2.5.29.17");
DEFINE_OID(OID_X509v3_IssuerAlternativeName,        "2.5.29.18");
DEFINE_OID(OID_X509v3_BasicConstraints,             "2.5.29.19");
DEFINE_OID(OID_X509v3_CRLNumber,                    "2.5.29.20");
DEFINE_OID(OID_X509v3_CRLReason,                    "2.5.29.21");
DEFINE_OID(OID_X509v3_HoldInstructionCode,          "2.5.29.23");
DEFINE_OID(OID_X509v3_InvalidityDate,               "2.5.29.24");
DEFINE_OID(OID_X509v3_DeltaCRLIndicator,            "2.5.29.27");
DEFINE_OID(OID_X509v3_CRLIssuingDistributionPoint,  "2.5.29.28");
DEFINE_OID(OID_X509v3_NameConstraints,              "2.5.29.30");
DEFINE_OID(OID_X509v3_CRLDistributionPoints,        "2.5.29.31");
DEFINE_OID(OID_X509v3_CertificatePolicies,          "2.5.29.32");
DEFINE_OID(OID_X509v3_AuthorityKeyIdentifier,       "2.5.29.35");
DEFINE_OID(OID_X509v3_PolicyConstraints,            "2.5.29.36");
DEFINE_OID(OID_X509v3_ExtendedKeyUsage,             "2.5.29.37");
DEFINE_OID(OID_X509v3_FreshestCRL,                  "2.5.29.46");

//-----------------------------------------------------------------------------------------
//PKIX
DEFINE_OID(OID_PKIX_AuthorityInfoAccess,        "1.3.6.1.5.5.7.1.1");
DEFINE_OID(OID_PKIX_QcStatements,               "1.3.6.1.5.5.7.1.3");
DEFINE_OID(OID_PKIX_SubjectInfoAccess,          "1.3.6.1.5.5.7.1.11");
DEFINE_OID(OID_PKIX_PolicyQualifierIds,         "1.3.6.1.5.5.7.2");
DEFINE_OID(OID_PKIX_PqiCps,                     "1.3.6.1.5.5.7.2.1");
DEFINE_OID(OID_PKIX_PqiUnotice,                 "1.3.6.1.5.5.7.2.2");
DEFINE_OID(OID_PKIX_PqiTextNotice,              "1.3.6.1.5.5.7.2.3");
DEFINE_OID(OID_PKIX_OCSP,                       "1.3.6.1.5.5.7.48.1");
DEFINE_OID(OID_PKIX_OcspBasic,                  "1.3.6.1.5.5.7.48.1.1");
DEFINE_OID(OID_PKIX_OcspNonce,                  "1.3.6.1.5.5.7.48.1.2");
DEFINE_OID(OID_PKIX_OcspCrl,                    "1.3.6.1.5.5.7.48.1.3");
DEFINE_OID(OID_PKIX_OcspResponse,               "1.3.6.1.5.5.7.48.1.4");
DEFINE_OID(OID_PKIX_CaIssuers,                  "1.3.6.1.5.5.7.48.2");
DEFINE_OID(OID_PKIX_TimeStamping,               "1.3.6.1.5.5.7.48.3");

//-----------------------------------------------------------------------------------------
//PKCS5
DEFINE_OID(OID_PKCS5_PBKDF2,            "1.2.840.113549.1.5.12");
DEFINE_OID(OID_PKCS5_PBES2,             "1.2.840.113549.1.5.13");
DEFINE_OID(OID_PBE_WITH_SHA1_TDES_CBC,  "1.2.840.113549.1.12.1.3");

//-----------------------------------------------------------------------------------------
//MEDOC
DEFINE_OID(OID_MEDOC_DIGEST,            "1.32.113549.1.7.1.524545");  // OID алгоритма хеширования MacData хранилища MEDOC PKCS12

//-----------------------------------------------------------------------------------------
//IIT
DEFINE_OID(OID_IIT_KEYSTORE,                     "1.3.6.1.4.1.19398.1.1.1.2"); // OID хранилища закрытого ключа IIT Key-6.dat
DEFINE_OID(OID_IIT_KEYSTORE_ATTR_RSA_PRIVKEY,    "1.3.6.1.4.1.19398.1.1.1.5"); // RSA ключ ("почти" RSAPrivateKey из RFC 8017)
DEFINE_OID(OID_IIT_KEYSTORE_ATTR_SIGN_KEYID,     "1.3.6.1.4.1.19398.1.1.2.1"); // Subject Key Identifier
DEFINE_OID(OID_IIT_KEYSTORE_ATTR_KEP_SPKI,       "1.3.6.1.4.1.19398.1.1.2.2"); // Параметры KEP ключа
DEFINE_OID(OID_IIT_KEYSTORE_ATTR_KEP_PRIVKEY,    "1.3.6.1.4.1.19398.1.1.2.3"); // KEP ключ
DEFINE_OID(OID_IIT_KEYSTORE_ATTR_KEP_KEYID,      "1.3.6.1.4.1.19398.1.1.2.5"); // KEP Subject Key Identifier
DEFINE_OID(OID_IIT_KEYSTORE_ATTR_HMAC_GOST34311, "1.3.6.1.4.1.19398.1.1.2.6"); // sbox (64 byte), key (8 byte), hash (32 byte)
DEFINE_OID(OID_IIT_KEYSTORE_ATTR_RSA_KEYID,      "1.3.6.1.4.1.19398.1.1.2.7"); // RSA Subject Key Identifier

//-----------------------------------------------------------------------------------------
//PKCS7
DEFINE_OID(OID_PKCS7_DATA,              "1.2.840.113549.1.7.1");
DEFINE_OID(OID_PKCS7_SIGNED_DATA,       "1.2.840.113549.1.7.2");
DEFINE_OID(OID_PKCS7_ENVELOPED_DATA,    "1.2.840.113549.1.7.3");
DEFINE_OID(OID_PKCS7_DIGESTED_DATA,     "1.2.840.113549.1.7.5");
DEFINE_OID(OID_PKCS7_ENCRYPTED_DATA,    "1.2.840.113549.1.7.6");

//-----------------------------------------------------------------------------------------
//PKCS9
DEFINE_OID(OID_PKCS9_CONTENT_TYPE,          "1.2.840.113549.1.9.3");
DEFINE_OID(OID_PKCS9_MESSAGE_DIGEST,        "1.2.840.113549.1.9.4");
DEFINE_OID(OID_PKCS9_SIGNING_TIME,          "1.2.840.113549.1.9.5");
DEFINE_OID(OID_PKCS9_CHALLENGE_PASSWORD,    "1.2.840.113549.1.9.7");
DEFINE_OID(OID_PKCS9_EXTENSION_REQUEST,     "1.2.840.113549.1.9.14");
DEFINE_OID(OID_PKCS9_FRIENDLY_NAME,         "1.2.840.113549.1.9.20");
DEFINE_OID(OID_PKCS9_LOCAL_KEYID,           "1.2.840.113549.1.9.21");
DEFINE_OID(OID_PKCS9_X509_CERTIFICATE,      "1.2.840.113549.1.9.22.1");
DEFINE_OID(OID_PKCS9_SDSI_CERTIFICATE,      "1.2.840.113549.1.9.22.2");
DEFINE_OID(OID_PKCS9_X509_CRL,              "1.2.840.113549.1.9.23.1");

//-----------------------------------------------------------------------------------------
//PKCS9/SMIME
DEFINE_OID(OID_PKCS9_TST_INFO,              "1.2.840.113549.1.9.16.1.4");
DEFINE_OID(OID_PKCS9_TIMESTAMP_TOKEN,       "1.2.840.113549.1.9.16.2.14");
DEFINE_OID(OID_PKCS9_SIG_POLICY_ID,         "1.2.840.113549.1.9.16.2.15");
DEFINE_OID(OID_PKCS9_COMMITMENT_TYPE,       "1.2.840.113549.1.9.16.2.16");
DEFINE_OID(OID_PKCS9_CONTENT_TIMESTAMP,     "1.2.840.113549.1.9.16.2.20");
DEFINE_OID(OID_PKCS9_CERTIFICATE_REFS,      "1.2.840.113549.1.9.16.2.21");
DEFINE_OID(OID_PKCS9_REVOCATION_REFS,       "1.2.840.113549.1.9.16.2.22");
DEFINE_OID(OID_PKCS9_CERT_VALUES,           "1.2.840.113549.1.9.16.2.23");
DEFINE_OID(OID_PKCS9_REVOCATION_VALUES,     "1.2.840.113549.1.9.16.2.24");
DEFINE_OID(OID_PKCS9_CADES_C_TIMESTAMP,     "1.2.840.113549.1.9.16.2.25");
DEFINE_OID(OID_PKCS9_CERT_CRL_TIMESTAMP,    "1.2.840.113549.1.9.16.2.26");
DEFINE_OID(OID_PKCS9_SIGNING_CERTIFICATE_V2,"1.2.840.113549.1.9.16.2.47");
//  Note: "1.2.840.113549.1.9.16.2.48" (id-aa-ets-archiveTimestampV2) is deprecated
//        in 'ETSI EN 319 122-1 V1.2.1 (2021-10)' - use "0.4.0.1733.2.4" (archive-time-stamp-v3).
//        https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.02.01_60/en_31912201v010201p.pdf

//-----------------------------------------------------------------------------------------
//PKCS12
DEFINE_OID(OID_PKCS12_BAGTYPES,             "1.2.840.113549.1.12.10.1");
DEFINE_OID(OID_PKCS12_KEY_BAG,              "1.2.840.113549.1.12.10.1.1");
DEFINE_OID(OID_PKCS12_P8_SHROUDED_KEY_BAG,  "1.2.840.113549.1.12.10.1.2");
DEFINE_OID(OID_PKCS12_CERT_BAG,             "1.2.840.113549.1.12.10.1.3");
DEFINE_OID(OID_PKCS12_CRL_BAG,              "1.2.840.113549.1.12.10.1.4");
DEFINE_OID(OID_PKCS12_SECRET_BAG,           "1.2.840.113549.1.12.10.1.5");
DEFINE_OID(OID_PKCS12_SAFE_CONTENTS_BAG,    "1.2.840.113549.1.12.10.1.6");

//-----------------------------------------------------------------------------------------
//ECDH(Ukraine)
DEFINE_OID(OID_COFACTOR_DH_DSTU7564_KDF,    "1.2.804.2.1.1.1.1.3.7");
DEFINE_OID(OID_STD_DH_DSTU7564_KDF,         "1.2.804.2.1.1.1.1.3.8");
DEFINE_OID(OID_COFACTOR_DH_GOST34311_KDF,   "1.2.804.2.1.1.1.1.3.4");
DEFINE_OID(OID_STD_DH_GOST34311_KDF,        "1.2.804.2.1.1.1.1.3.5");
//-----------------------------------------------------------------------------------------
//ECDH
DEFINE_OID(OID_DHSINGLEPASS_STD_DH_SHA1_KDF,        "1.3.133.16.840.63.0.2");
DEFINE_OID(OID_DHSINGLEPASS_COFACTOR_DH_SHA1_KDF,   "1.3.133.16.840.63.0.3");
DEFINE_OID(OID_DHSINGLEPASS_STD_DH_SHA256_KDF,      "1.3.132.1.11.1");
//-----------------------------------------------------------------------------------------
//JKS
DEFINE_OID(OID_JKS_KEY_PROTECTOR,           "1.3.6.1.4.1.42.2.17.1.1");
//-----------------------------------------------------------------------------------------
//Personal data of the signer (Ukraine)
DEFINE_OID(OID_PDS_UKRAINE_DRFO,            "1.2.804.2.1.1.1.11.1.4.1.1");
DEFINE_OID(OID_PDS_UKRAINE_EDRPOU,          "1.2.804.2.1.1.1.11.1.4.2.1");
DEFINE_OID(OID_PDS_UKRAINE_EDDR,            "1.2.804.2.1.1.1.11.1.4.11.1");
//-----------------------------------------------------------------------------------------
//ETSI
DEFINE_OID(OID_ETSI_ARCHIVE_TIMESTAMP_V3,   "0.4.0.1733.2.4");
//-----------------------------------------------------------------------------------------


bool oid_is_equal (const char* oid1, const char* oid2);
bool oid_is_parent (const char* parent, const char* oid);
bool oid_is_valid (const char* oid);


#ifdef __cplusplus
}
#endif

#endif
