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

#ifndef UAPKIC_ERRORS_H
#define UAPKIC_ERRORS_H

#ifdef  __cplusplus
extern "C" {
#endif

#define RET_OK                           0
#define RET_MEMORY_ALLOC_ERROR           1
#define RET_INVALID_PARAM                2
#define RET_VERIFY_FAILED                3
#define RET_CONTEXT_NOT_READY            4
#define RET_INVALID_CTX                  5
#define RET_INVALID_PRIVATE_KEY          6
#define RET_INVALID_PUBLIC_KEY           7
#define RET_OS_PRNG_ERROR                8
#define RET_JITTER_RNG_ERROR             9
#define RET_UNSUPPORTED                  10
#define RET_INVALID_KEY_SIZE             11
#define RET_INVALID_IV_SIZE              12
#define RET_RSA_DECRYPTION_ERROR         13
#define RET_INVALID_CTX_MODE             14
#define RET_INVALID_EC_PARAMS            15
#define RET_DATA_TOO_LONG                16
#define RET_INVALID_RSA_N                17
#define RET_INVALID_RSA_D                18
#define RET_INVALID_RSA_DMP              19
#define RET_INVALID_RSA_DMQ              20
#define RET_INVALID_RSA_IQMP             21
#define RET_INVALID_HASH_LEN             22
#define RET_INVALID_MAC                  23
#define RET_CTX_ALREADY_IN_CACHE         24
#define RET_POINT_NOT_ON_CURVE           25
#define RET_INVALID_OID                  26
#define RET_INVALID_DATA_LEN             27
#define RET_INVALID_UTF8_STR             28
#define RET_INVALID_HEX_STRING           29
#define RET_INVALID_BASE64_STRING        30
#define RET_INDEX_OUT_OF_RANGE           31
#define RET_SELF_TEST_NOT_ALLOWED        32
#define RET_SELF_TEST_FAIL               33

#ifdef  __cplusplus
}
#endif

#endif
