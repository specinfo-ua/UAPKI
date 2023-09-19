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

#ifndef UAPKI_OID_UTILS_H
#define UAPKI_OID_UTILS_H


#include <stddef.h>
#include "../../uapkic/include/ec-default-params.h"
#include "../../uapkic/include/hash.h"
#include "oids.h"
#include "uapkif.h"


#ifdef __cplusplus
extern "C" {
#endif


typedef enum {
    SIGN_UNDEFINED = 0,
    SIGN_DSTU4145 = 1,
    SIGN_ECDSA = 2,
    SIGN_ECKCDSA = 3,
    SIGN_ECGDSA = 4,
    SIGN_ECRDSA = 5,
    SIGN_SM2DSA = 6,
    SIGN_RSA_PKCS_1_5 = 7,
    SIGN_RSA_PSS = 8
} SignAlg;


const char* ecid_to_oid (EcParamsId ecid);
EcParamsId ecid_from_oid (const char* oid);
EcParamsId ecid_from_OID (const OBJECT_IDENTIFIER_t* oid);
const char* hash_to_oid (HashAlg hash);
HashAlg hash_from_oid (const char* oid);
HashAlg hash_from_OID (const OBJECT_IDENTIFIER_t* oid);
SignAlg signature_from_oid (const char* oid);
SignAlg signature_from_OID (const OBJECT_IDENTIFIER_t* oid);
bool OID_is_child_oid (const OBJECT_IDENTIFIER_t* oid, const char* strOidParent);
bool OID_is_equal_oid (const OBJECT_IDENTIFIER_t* oid, const char* strOid);
const char* oid_to_rdname (const char* oid);


#ifdef __cplusplus
}
#endif

#endif
