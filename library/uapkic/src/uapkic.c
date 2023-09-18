/*
 * Copyright 2021 The UAPKI Project Authors.
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
 
#define FILE_MARKER "uapkic/uapkic.c"

#include "uapkic.h"
#include "macros-internal.h"

uint32_t uapkic_self_test(void)
{
	uint32_t test_status = 0;

	// ENTROPY
	if (entropy_self_test() != RET_OK) test_status |= SELF_TEST_ENTROPY_FAIL;

	// DRBG-HMAC-SHA-512
	if (drbg_self_test() != RET_OK) test_status |= SELF_TEST_DRBG_FAIL;

	// HASHES
	if (dstu7564_self_test() != RET_OK) test_status |= SELF_TEST_DSTU7564_FAIL;
	if (gost34311_self_test() != RET_OK) test_status |= SELF_TEST_DSTU7564_FAIL;
	if (sha1_self_test() != RET_OK) test_status |= SELF_TEST_SHA1_FAIL;
	if (sha2_self_test() != RET_OK) test_status |= SELF_TEST_SHA2_FAIL;
	if (sha3_self_test() != RET_OK) test_status |= SELF_TEST_SHA3_FAIL;
	if (whirlpool_self_test() != RET_OK) test_status |= SELF_TEST_WHIRLPOOL_FAIL;
	if (sm3_self_test() != RET_OK) test_status |= SELF_TEST_SM3_FAIL;
	if (gostr3411_self_test() != RET_OK) test_status |= SELF_TEST_GOSTR3411_FAIL;
	if (ripemd_self_test() != RET_OK) test_status |= SELF_TEST_RIPEMD_FAIL;
	if (md5_self_test() != RET_OK) test_status |= SELF_TEST_MD5_FAIL;

	// HMAC
	if (hmac_self_test() != RET_OK) test_status |= SELF_TEST_HMAC_FAIL;

	// SIGNATURES
	if (dstu4145_self_test() != RET_OK) test_status |= SELF_TEST_DSTU4145_FAIL;
	if (ecdsa_self_test() != RET_OK) test_status |= SELF_TEST_ECDSA_FAIL;
	if (ecgdsa_self_test() != RET_OK) test_status |= SELF_TEST_ECGDSA_FAIL;
	if (eckcdsa_self_test() != RET_OK) test_status |= SELF_TEST_ECKCDSA_FAIL;
	if (ecrdsa_self_test() != RET_OK) test_status |= SELF_TEST_ECRDSA_FAIL;
	if (sm2dsa_self_test() != RET_OK) test_status |= SELF_TEST_SM2DSA_FAIL;
	if (rsa_self_test() != RET_OK) test_status |= SELF_TEST_RSA_FAIL;

	// CIPHER
	if (dstu7624_self_test() != RET_OK) test_status |= SELF_TEST_DSTU7624_FAIL;
	if (gost28147_self_test() != RET_OK) test_status |= SELF_TEST_GOST28147_FAIL;
	if (aes_self_test() != RET_OK) test_status |= SELF_TEST_AES_FAIL;
	if (des3_self_test() != RET_OK) test_status |= SELF_TEST_3DES_FAIL;
	if (dstu8845_self_test() != RET_OK) test_status |= SELF_TEST_DSTU8845_FAIL;

	// UKRAINE KEY WRAP
	if (key_wrap_self_test() != RET_OK) test_status |= SELF_TEST_KEY_WRAP_FAIL;

	// PBKDF
	if (pbkdf_self_test() != RET_OK) test_status |= SELF_TEST_PBKDF_FAIL;

	// PBKDF
	if (ec_dh_self_test() != RET_OK) test_status |= SELF_TEST_ECDH_FAIL;

	return test_status;
}

int drbg_init(void);

static int initialized = 0;

int uapkic_init(uint32_t *version, uint32_t* self_test_status)
{
	int ret = RET_OK;

	if (version) {
		*version = UAPKIC_VERSION;
	}

	if (self_test_status) {
		*self_test_status = uapkic_self_test();
	}

	if (initialized == 0) {
		DO(drbg_init());
		initialized = 1;
	}

	if (self_test_status && (*self_test_status != 0)) {
		SET_ERROR(RET_SELF_TEST_FAIL);
	}

cleanup:
	return ret;
}
