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

#define FILE_MARKER "uapkic/drbg.c"

#include <string.h>
#include "drbg.h"
#include "pthread-internal.h"
#include "entropy-internal.h"
#include "macros-internal.h"
#include "byte-array-internal.h"

#include "hmac.h"

static ByteArray *drbg_Key = NULL;
static ByteArray *drbg_V = NULL;
static size_t drbg_reseed_counter = 0;
static bool drbg_prediction_resistance = false;
static HmacCtx* drbg_hmac_ctx = NULL;
static pthread_mutex_t drbg_mutex = PTHREAD_MUTEX_INITIALIZER;

static const uint8_t _separator0 = 0x00;
static const uint8_t _separator1 = 0x01;

static const ByteArray separator0 = { (uint8_t*)&_separator0, sizeof(_separator0) };
static const ByteArray separator1 = { (uint8_t*)&_separator1, sizeof(_separator1) };

static void drbg_free_internal(void)
{
	hmac_free(drbg_hmac_ctx);
	drbg_hmac_ctx = NULL;
	ba_free(drbg_Key);
	drbg_Key = NULL;
	ba_free(drbg_V);
	drbg_V = NULL;
	drbg_reseed_counter = 0;
}

static int drbg_update(const ByteArray *provided_data)
{
	int ret = RET_OK;
	ByteArray* tmp = NULL;
	
	DO(hmac_init(drbg_hmac_ctx, drbg_Key));
	DO(hmac_update(drbg_hmac_ctx, drbg_V));
	DO(hmac_update(drbg_hmac_ctx, &separator0));

	if (provided_data != NULL) {
		DO(hmac_update(drbg_hmac_ctx, provided_data));
	}

	DO(hmac_final(drbg_hmac_ctx, &tmp));
	ba_free_private(drbg_Key);
	drbg_Key = tmp;
	tmp = NULL;

	DO(hmac_init(drbg_hmac_ctx, drbg_Key));
	DO(hmac_update(drbg_hmac_ctx, drbg_V));
	DO(hmac_final(drbg_hmac_ctx, &tmp));
	ba_free_private(drbg_V);
	drbg_V = tmp;
	tmp = NULL;

	if (provided_data == NULL) {
		goto cleanup;
	}

	DO(hmac_init(drbg_hmac_ctx, drbg_Key));
	DO(hmac_update(drbg_hmac_ctx, drbg_V));
	DO(hmac_update(drbg_hmac_ctx, &separator1));
	DO(hmac_update(drbg_hmac_ctx, provided_data));

	DO(hmac_final(drbg_hmac_ctx, &tmp));
	ba_free_private(drbg_Key);
	drbg_Key = tmp;
	tmp = NULL;

	DO(hmac_init(drbg_hmac_ctx, drbg_Key));
	DO(hmac_update(drbg_hmac_ctx, drbg_V));
	DO(hmac_final(drbg_hmac_ctx, &tmp));
	ba_free_private(drbg_V);
	drbg_V = tmp;
	tmp = NULL;

cleanup:
	return ret;
}

static int drbg_init_internal(const ByteArray *entropy)
{
	int ret = RET_OK;

	CHECK_NOT_NULL(drbg_hmac_ctx = hmac_alloc(HASH_ALG_SHA512));
	CHECK_NOT_NULL(drbg_Key = ba_alloc_by_len(64));
	CHECK_NOT_NULL(drbg_V = ba_alloc_by_len(64));

	memset(drbg_Key->buf, 0x00, drbg_Key->len);
	memset(drbg_V->buf, 0x01, drbg_V->len);

	DO(drbg_update(entropy));
	drbg_reseed_counter = 1;

cleanup:
	if (ret != 0) {
		drbg_free_internal();
	}
	return ret;
}

int drbg_init(void)
{
	int ret = RET_OK;
	ByteArray *entropy = NULL;

	DO(entropy_get(&entropy));

	DO(drbg_init_internal(entropy));

cleanup:
	ba_free_private(entropy);
	return ret;
}

static int drbg_reseed_internal(const ByteArray* seed_material)
{
	int ret = RET_OK;

	DO(drbg_update(seed_material));

	drbg_reseed_counter = 1;

cleanup:
	return ret;
}

int drbg_reseed(const ByteArray* additional_input)
{
	int ret = RET_OK;
	ByteArray* seed_material = NULL;
	ByteArray* entropy = NULL;

	pthread_mutex_lock(&drbg_mutex);

	if (drbg_Key == NULL || drbg_V == NULL || drbg_hmac_ctx == NULL) {
		DO(drbg_init());
	}

	DO(entropy_get(&entropy));

	if (additional_input != NULL) {
		CHECK_NOT_NULL(seed_material = ba_join(entropy, additional_input));
		DO(drbg_reseed_internal(seed_material));
	}
	else {
		DO(drbg_reseed_internal(entropy));
	}

	DO(drbg_reseed_internal(additional_input));

cleanup:
	pthread_mutex_unlock(&drbg_mutex);
	ba_free_private(seed_material);
	ba_free_private(entropy);
	return ret;
}

static int drbg_random_internal(ByteArray* random)
{
	int ret = RET_OK;
	uint8_t* bufptr = random->buf;
	size_t current_len, outlen = random->len;
	ByteArray* tmp = NULL;

	if (outlen > (1 << 19)) {
		return -1;
	}
	
	if (drbg_Key == NULL || drbg_V == NULL || drbg_hmac_ctx == NULL) {
		DO(drbg_init());
	}

	if ((drbg_reseed_counter > 1000000) || drbg_prediction_resistance) {
		DO(drbg_reseed_internal(NULL));
	}

	drbg_reseed_counter++;

	while (outlen > 0) {
		DO(hmac_init(drbg_hmac_ctx, drbg_Key));
		DO(hmac_update(drbg_hmac_ctx, drbg_V));
		DO(hmac_final(drbg_hmac_ctx, &tmp));
		ba_free_private(drbg_V);
		drbg_V = tmp;
		tmp = NULL;

		current_len = (drbg_V->len > outlen) ? outlen : drbg_V->len;
		memcpy(bufptr, drbg_V->buf, current_len);

		bufptr += current_len;
		outlen -= current_len;
	}

	DO(drbg_update(NULL));

cleanup:
	return ret;
}
 
int drbg_random(ByteArray* random)
{
	int ret;
	pthread_mutex_lock(&drbg_mutex);
	ret = drbg_random_internal(random);
	pthread_mutex_unlock(&drbg_mutex);
	return ret;
}

int drbg_self_test(void)
{
	//Source: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip
	static const uint8_t test_drbg_init_entropy[] = {
		// EntropyInput
		0x48, 0xC1, 0x21, 0xB1, 0x87, 0x33, 0xAF, 0x15, 0xC2, 0x7E, 0x1D, 0xD9, 0xBA, 0x66, 0xA9, 0xA8,
		0x1A, 0x55, 0x79, 0xCD, 0xBA, 0x0F, 0x5B, 0x65, 0x7E, 0xC5, 0x3C, 0x2B, 0x9E, 0x90, 0xBB, 0xF6,
		// Nonce 
		0xBB, 0xB7, 0xC7, 0x77, 0x42, 0x80, 0x68, 0xFA, 0xD9, 0x97, 0x08, 0x91, 0xF8, 0x79, 0xB1, 0xAF };

	static const uint8_t test_drbg_reseed_entropy[] = {
		// AdditionalInputReseed
		0xE0, 0xFF, 0xEF, 0xDA, 0xDB, 0x9C, 0xCF, 0x99, 0x05, 0x04, 0xD5, 0x68, 0xBD, 0xB4, 0xD8, 0x62,
		0xCB, 0xE1, 0x7C, 0xCC, 0xE6, 0xE2, 0x2D, 0xFC, 0xAB, 0x8B, 0x48, 0x04, 0xFD, 0x21, 0x42, 0x1A };

	static const uint8_t test_drbg_expected_bits[] = {
		0x05, 0xDA, 0x6A, 0xAC, 0x7D, 0x98, 0x0D, 0xA0, 0x38, 0xF6, 0x5F, 0x39, 0x28, 0x41, 0x47, 0x6D,
		0x37, 0xFE, 0x70, 0xFB, 0xD3, 0xE3, 0x69, 0xD1, 0xF8, 0x01, 0x96, 0xE6, 0x6E, 0x54, 0xB8, 0xFA,
		0xDB, 0x1D, 0x60, 0xE1, 0xA0, 0xF3, 0xD4, 0xDC, 0x17, 0x37, 0x69, 0xD7, 0x5F, 0xC3, 0x41, 0x05,
		0x49, 0xD7, 0xA8, 0x43, 0x27, 0x0A, 0x54, 0xA0, 0x68, 0xB4, 0xFE, 0x76, 0x7D, 0x7D, 0x9A, 0x59,
		0x60, 0x45, 0x10, 0xA8, 0x75, 0xAD, 0x1E, 0x97, 0x31, 0xC8, 0xAF, 0xD0, 0xFD, 0x50, 0xB8, 0x25,
		0xE2, 0xC5, 0x0D, 0x06, 0x25, 0x76, 0x17, 0x51, 0x06, 0xA9, 0x98, 0x1B, 0xE3, 0x7E, 0x02, 0xEC,
		0x7C, 0x5C, 0xD0, 0xA6, 0x9A, 0xA0, 0xCA, 0x65, 0xBD, 0xDA, 0xEE, 0x1B, 0x0D, 0xE5, 0x32, 0xE1,
		0x0C, 0xFA, 0x1F, 0x5B, 0xF6, 0xA0, 0x26, 0xE4, 0x73, 0x79, 0x73, 0x6A, 0x09, 0x9D, 0x67, 0x50,
		0xAB, 0x12, 0x1D, 0xBE, 0x36, 0x22, 0xB8, 0x41, 0xBA, 0xF8, 0xBD, 0xCB, 0xE8, 0x75, 0xC8, 0x5B,
		0xA4, 0xB5, 0x86, 0xB8, 0xB5, 0xB5, 0x7B, 0x0F, 0xEC, 0xBE, 0xC0, 0x8C, 0x12, 0xFF, 0x2A, 0x94,
		0x53, 0xC4, 0x7C, 0x6E, 0x32, 0xA5, 0x21, 0x03, 0xD9, 0x72, 0xC6, 0x2A, 0xB9, 0xAF, 0xFB, 0x8E,
		0x72, 0x8A, 0x31, 0xFC, 0xEF, 0xBB, 0xCC, 0xC5, 0x56, 0xC0, 0xF0, 0xA3, 0x5F, 0x4B, 0x10, 0xAC,
		0xE2, 0xD9, 0x6B, 0x90, 0x6E, 0x36, 0xCB, 0xB7, 0x22, 0x33, 0x20, 0x1E, 0x53, 0x6D, 0x3E, 0x13,
		0xB0, 0x45, 0x18, 0x7B, 0x41, 0x7D, 0x24, 0x49, 0xCA, 0xD1, 0xED, 0xD1, 0x92, 0xE0, 0x61, 0xF1,
		0x2D, 0x22, 0x14, 0x7B, 0x0A, 0x17, 0x6E, 0xA8, 0xD9, 0xC4, 0xC3, 0x54, 0x04, 0x39, 0x5B, 0x65,
		0x02, 0xEF, 0x33, 0x3A, 0x81, 0x3B, 0x65, 0x86, 0x03, 0x74, 0x79, 0xE0, 0xFA, 0x3C, 0x6A, 0x23 };

	static const ByteArray ba_test_drbg_init_entropy = { (uint8_t*)&test_drbg_init_entropy, sizeof(test_drbg_init_entropy) };
	static const ByteArray ba_test_reseed_entropy = { (uint8_t*)&test_drbg_reseed_entropy, sizeof(test_drbg_reseed_entropy) };

	int ret = RET_OK;
	ByteArray *test_drbg_out = NULL;
	
	if (drbg_Key || drbg_V || drbg_hmac_ctx) {
		return RET_SELF_TEST_NOT_ALLOWED;
	}

	pthread_mutex_lock(&drbg_mutex);

	DO(drbg_init_internal(&ba_test_drbg_init_entropy));
	DO(drbg_reseed_internal(&ba_test_reseed_entropy));

	CHECK_NOT_NULL(test_drbg_out = ba_alloc_by_len(sizeof(test_drbg_expected_bits)));

	DO(drbg_random_internal(test_drbg_out));
	DO(drbg_random_internal(test_drbg_out));
	if (memcmp(test_drbg_out->buf, test_drbg_expected_bits, sizeof(test_drbg_expected_bits)) != 0) {
		SET_ERROR(RET_SELF_TEST_FAIL);
	}

cleanup:
	drbg_free_internal();
	pthread_mutex_unlock(&drbg_mutex);
	ba_free(test_drbg_out);
	return ret;
}
