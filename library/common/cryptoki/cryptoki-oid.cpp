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

#include "pkcs11.h"


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

const char* AES128_KEY_WRAP = "2.16.840.1.101.3.4.1.5";
const char* AES192_KEY_WRAP = "2.16.840.1.101.3.4.1.25";
const char* AES256_KEY_WRAP = "2.16.840.1.101.3.4.1.45";
const char* GOST28147_KEY_WRAP = "1.2.804.2.1.1.1.1.1.1.5";
const char* DSTU4145_POLY_CURVE_163 = "1.2.804.2.1.1.1.1.3.1.1.2.0";
const char* DSTU4145_POLY_CURVE_167 = "1.2.804.2.1.1.1.1.3.1.1.2.1";
const char* DSTU4145_POLY_CURVE_173 = "1.2.804.2.1.1.1.1.3.1.1.2.2";
const char* DSTU4145_POLY_CURVE_179 = "1.2.804.2.1.1.1.1.3.1.1.2.3";
const char* DSTU4145_POLY_CURVE_191 = "1.2.804.2.1.1.1.1.3.1.1.2.4";
const char* DSTU4145_POLY_CURVE_233 = "1.2.804.2.1.1.1.1.3.1.1.2.5";
const char* DSTU4145_POLY_CURVE_257 = "1.2.804.2.1.1.1.1.3.1.1.2.6";
const char* DSTU4145_POLY_CURVE_307 = "1.2.804.2.1.1.1.1.3.1.1.2.7";
const char* DSTU4145_POLY_CURVE_367 = "1.2.804.2.1.1.1.1.3.1.1.2.8";
const char* DSTU4145_POLY_CURVE_431 = "1.2.804.2.1.1.1.1.3.1.1.2.9";
const char* GOST28147_SBOX_1 = "1.2.804.2.1.1.1.1.1.1.10.1";
const char* GOST28147_SBOX_2 = "1.2.804.2.1.1.1.1.1.1.10.2";
const char* GOST28147_SBOX_3 = "1.2.804.2.1.1.1.1.1.1.10.3";
const char* GOST28147_SBOX_4 = "1.2.804.2.1.1.1.1.1.1.10.4";
const char* GOST28147_SBOX_5 = "1.2.804.2.1.1.1.1.1.1.10.5";
const char* GOST28147_SBOX_6 = "1.2.804.2.1.1.1.1.1.1.10.6";
const char* GOST28147_SBOX_7 = "1.2.804.2.1.1.1.1.1.1.10.7";
const char* GOST28147_SBOX_8 = "1.2.804.2.1.1.1.1.1.1.10.8";
const char* GOST28147_SBOX_9 = "1.2.804.2.1.1.1.1.1.1.10.9";
const char* GOST28147_SBOX_10 = "1.2.804.2.1.1.1.1.1.1.10.10";
}   //  end namespace OID

}   //  end namespace Cryptoki

