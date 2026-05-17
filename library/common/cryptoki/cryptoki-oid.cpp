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

#include "pkcs11types.h"


namespace Cryptoki {

namespace OID {


//  ECDSA-family
const char* EC_KEY              = "1.2.840.10045.2.1";
const char* NIST_P256           = "1.2.840.10045.3.1.7";
const char* NIST_P384           = "1.3.132.0.34";
const char* NIST_P521           = "1.3.132.0.35";
const char* ECDSA_WITH_SHA1     = "1.2.840.10045.4.1";
const char* ECDSA_WITH_SHA256   = "1.2.840.10045.4.3.2";
const char* ECDSA_WITH_SHA384   = "1.2.840.10045.4.3.3";
const char* ECDSA_WITH_SHA512   = "1.2.840.10045.4.3.4";
const char* ECDSA_WITH_SHA3_256 = "2.16.840.1.101.3.4.3.10";
const char* ECDSA_WITH_SHA3_384 = "2.16.840.1.101.3.4.3.11";
const char* ECDSA_WITH_SHA3_512 = "2.16.840.1.101.3.4.3.12";

//  RSA-family
const char* RSA                 = "1.2.840.113549.1.1.1";
const char* RSA_WITH_SHA1       = "1.2.840.113549.1.1.5";
const char* RSA_WITH_SHA256     = "1.2.840.113549.1.1.11";
const char* RSA_WITH_SHA384     = "1.2.840.113549.1.1.12";
const char* RSA_WITH_SHA512     = "1.2.840.113549.1.1.13";
const char* RSA_WITH_SHA3_256   = "2.16.840.1.101.3.4.3.14";
const char* RSA_WITH_SHA3_384   = "2.16.840.1.101.3.4.3.15";
const char* RSA_WITH_SHA3_512   = "2.16.840.1.101.3.4.3.16";

//  Bottom OIDs used defines from pathed pkcs11types.h
const char* AES128_KEY_WRAP     = OID_AES128_KEY_WRAP;
const char* AES192_KEY_WRAP     = OID_AES192_KEY_WRAP;
const char* AES256_KEY_WRAP     = OID_AES256_KEY_WRAP;
const char* GOST28147_KEY_WRAP  = OID_GOST28147_KEY_WRAP;

const char* DSTU4145_PARAM_M163_PB  = OID_DSTU4145_POLY_CURVE_163;
const char* DSTU4145_PARAM_M167_PB  = OID_DSTU4145_POLY_CURVE_167;
const char* DSTU4145_PARAM_M173_PB  = OID_DSTU4145_POLY_CURVE_173;
const char* DSTU4145_PARAM_M179_PB  = OID_DSTU4145_POLY_CURVE_179;
const char* DSTU4145_PARAM_M191_PB  = OID_DSTU4145_POLY_CURVE_191;
const char* DSTU4145_PARAM_M233_PB  = OID_DSTU4145_POLY_CURVE_233;
const char* DSTU4145_PARAM_M257_PB  = OID_DSTU4145_POLY_CURVE_257;
const char* DSTU4145_PARAM_M307_PB  = OID_DSTU4145_POLY_CURVE_307;
const char* DSTU4145_PARAM_M367_PB  = OID_DSTU4145_POLY_CURVE_367;
const char* DSTU4145_PARAM_M431_PB  = OID_DSTU4145_POLY_CURVE_431;

const char* GOST28147_SBOX_1    = OID_GOST28147_SBOX_1;
const char* GOST28147_SBOX_2    = OID_GOST28147_SBOX_2;
const char* GOST28147_SBOX_3    = OID_GOST28147_SBOX_3;
const char* GOST28147_SBOX_4    = OID_GOST28147_SBOX_4;
const char* GOST28147_SBOX_5    = OID_GOST28147_SBOX_5;
const char* GOST28147_SBOX_6    = OID_GOST28147_SBOX_6;
const char* GOST28147_SBOX_7    = OID_GOST28147_SBOX_7;
const char* GOST28147_SBOX_8    = OID_GOST28147_SBOX_8;
const char* GOST28147_SBOX_9    = OID_GOST28147_SBOX_9;
const char* GOST28147_SBOX_10   = OID_GOST28147_SBOX_10;


}   //  end namespace OID

}   //  end namespace Cryptoki

