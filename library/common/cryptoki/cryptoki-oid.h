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

#ifndef CRYPTOKI_OID_H
#define CRYPTOKI_OID_H


namespace Cryptoki {

namespace OID {

//  ECDSA-family
extern const char* EC_KEY;
extern const char* NIST_P256;
extern const char* NIST_P384;
extern const char* NIST_P521;
extern const char* ECDSA_WITH_SHA1;
extern const char* ECDSA_WITH_SHA256;
extern const char* ECDSA_WITH_SHA384;
extern const char* ECDSA_WITH_SHA512;
extern const char* ECDSA_WITH_SHA3_256;
extern const char* ECDSA_WITH_SHA3_384;
extern const char* ECDSA_WITH_SHA3_512;

//  RSA-family
extern const char* RSA;
extern const char* RSA_WITH_SHA1;
extern const char* RSA_WITH_SHA256;
extern const char* RSA_WITH_SHA384;
extern const char* RSA_WITH_SHA512;
extern const char* RSA_WITH_SHA3_256;
extern const char* RSA_WITH_SHA3_384;
extern const char* RSA_WITH_SHA3_512;

//  Bottom OIDs used defines from pathed pkcs11types.h
extern const char* AES128_KEY_WRAP;
extern const char* AES192_KEY_WRAP;
extern const char* AES256_KEY_WRAP;
extern const char* GOST28147_KEY_WRAP;

extern const char* DSTU4145_PARAM_M163_PB;
extern const char* DSTU4145_PARAM_M167_PB;
extern const char* DSTU4145_PARAM_M173_PB;
extern const char* DSTU4145_PARAM_M179_PB;
extern const char* DSTU4145_PARAM_M191_PB;
extern const char* DSTU4145_PARAM_M233_PB;
extern const char* DSTU4145_PARAM_M257_PB;
extern const char* DSTU4145_PARAM_M307_PB;
extern const char* DSTU4145_PARAM_M367_PB;
extern const char* DSTU4145_PARAM_M431_PB;

extern const char* GOST28147_SBOX_1;
extern const char* GOST28147_SBOX_2;
extern const char* GOST28147_SBOX_3;
extern const char* GOST28147_SBOX_4;
extern const char* GOST28147_SBOX_5;
extern const char* GOST28147_SBOX_6;
extern const char* GOST28147_SBOX_7;
extern const char* GOST28147_SBOX_8;
extern const char* GOST28147_SBOX_9;
extern const char* GOST28147_SBOX_10;


}   //  end namespace OID

}   //  end namespace Cryptoki


#endif
