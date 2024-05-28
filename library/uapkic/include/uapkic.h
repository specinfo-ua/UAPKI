/*
 * Copyright 2021 The UAPKI Project Authors.
 * Copyright 2016 PrivatBank IT <acsk@privatbank.ua>
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

#ifndef UAPKIC_H
#define UAPKIC_H

#define UAPKIC_VERSION 2001

#include "entropy.h"
#include "drbg.h"
#include "des.h"
#include "aes.h"
#include "gost28147.h"
#include "dstu7624.h"
#include "dstu8845.h"
#include "ecdsa.h"
#include "ecgdsa.h"
#include "eckcdsa.h"
#include "ecrdsa.h"
#include "sm2dsa.h"
#include "dstu4145.h"
#include "rsa.h"
#include "ec-default-params.h"
#include "ec-cache.h"
#include "md5.h"
#include "ripemd.h"
#include "sha1.h"
#include "sha2.h"
#include "sha3.h"
#include "whirlpool.h"
#include "sm3.h"
#include "gost34311.h"
#include "dstu7564.h"
#include "whirlpool.h"
#include "gostr3411-2012.h"
#include "hash.h"
#include "hmac.h"
#include "pbkdf.h"
#include "keywrap.h"
#include "paddings.h"
//#include "stacktrace.h"
#include "uapkic-errors.h"


#define SELF_TEST_ENTROPY_FAIL   0x00000001
#define SELF_TEST_DRBG_FAIL      0x00000002

#define SELF_TEST_DSTU7564_FAIL  0x00000004
#define SELF_TEST_GOST34311_FAIL 0x00000008
#define SELF_TEST_SHA1_FAIL      0x00000010
#define SELF_TEST_SHA2_FAIL      0x00000020
#define SELF_TEST_SHA3_FAIL      0x00000040
#define SELF_TEST_WHIRLPOOL_FAIL 0x00000080
#define SELF_TEST_SM3_FAIL       0x00000100
#define SELF_TEST_GOSTR3411_FAIL 0x00000200
#define SELF_TEST_RIPEMD_FAIL    0x00000400
#define SELF_TEST_MD5_FAIL       0x00000800

#define SELF_TEST_DSTU4145_FAIL  0x00001000
#define SELF_TEST_ECDSA_FAIL     0x00002000
#define SELF_TEST_ECGDSA_FAIL    0x00004000
#define SELF_TEST_ECKCDSA_FAIL   0x00008000
#define SELF_TEST_ECRDSA_FAIL    0x00010000
#define SELF_TEST_SM2DSA_FAIL    0x00020000
#define SELF_TEST_RSA_FAIL       0x00040000

#define SELF_TEST_HMAC_FAIL      0x00080000

#define SELF_TEST_DSTU7624_FAIL  0x01000000
#define SELF_TEST_GOST28147_FAIL 0x02000000
#define SELF_TEST_AES_FAIL       0x04000000
#define SELF_TEST_3DES_FAIL      0x08000000
#define SELF_TEST_DSTU8845_FAIL  0x10000000

#define SELF_TEST_KEY_WRAP_FAIL  0x20000000
#define SELF_TEST_PBKDF_FAIL     0x40000000

#define SELF_TEST_ECDH_FAIL      0x80000000

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Ініціалізує ГПВП, проводить самотестування
 *
 * @param version повертає версію бібліотеки
 * @param self_test_status повертає результат самотестування, якщо NULL - самотестування не виконується
 * @return код помилки
 */
UAPKIC_EXPORT int uapkic_init(uint32_t* version, uint32_t* self_test_status);

#ifdef  __cplusplus
}
#endif

#endif
