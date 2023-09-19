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

#define FILE_MARKER "common/pkix/aid.c"

#include "aid.h"
#include "oids.h"
#include "macros-internal.h"


void aid_clean(AlgorithmIdentifier_t* aid)
{
	ASN_FREE_CONTENT_PTR(get_AlgorithmIdentifier_desc(), aid);
}

int aid_create_dstu4145_default(const char* alg, const char* curve, AlgorithmIdentifier_t** out)
{
	int ret = RET_OK;
	AlgorithmIdentifier_t* aid = NULL;
	DSTU4145Params_t* dstu4145_params = NULL;

	ASN_ALLOC(dstu4145_params);

	dstu4145_params->ellipticCurve.present = DSTUEllipticCurve_PR_namedCurve;
	DO(asn_set_oid_from_text(curve, &dstu4145_params->ellipticCurve.choice.namedCurve));

	ASN_ALLOC(aid);

	DO(asn_set_oid_from_text(alg, &aid->algorithm));
	DO(asn_create_any(get_DSTU4145Params_desc(), dstu4145_params, &aid->parameters));
	*out = aid;
	aid = NULL;

cleanup:
	asn_free(get_DSTU4145Params_desc(), dstu4145_params);
	asn_free(get_AlgorithmIdentifier_desc(), aid);
	return ret;
}

int aid_create_ec_default(const char* alg, const char* curve, AlgorithmIdentifier_t** out)
{
	int ret = RET_OK;
	AlgorithmIdentifier_t* aid = NULL;
	ECParameters_t* ec_params = NULL;

	ASN_ALLOC(ec_params);

	ec_params->present = ECParameters_PR_namedCurve;
	DO(asn_set_oid_from_text(curve, &ec_params->choice.namedCurve));

	ASN_ALLOC(aid);

	DO(asn_set_oid_from_text(alg, &aid->algorithm));
	DO(asn_create_any(get_ECParameters_desc(), ec_params, &aid->parameters));

	*out = aid;
	aid = NULL;

cleanup:
	asn_free(get_ECParameters_desc(), ec_params);
	asn_free(get_AlgorithmIdentifier_desc(), aid);
	return ret;
}

int aid_create_rsa(AlgorithmIdentifier_t** out)
{
	int ret = RET_OK;
	AlgorithmIdentifier_t* aid = NULL;
	NULL_t* null_params = NULL;

	ASN_ALLOC(aid);
	ASN_ALLOC(null_params);
	DO(asn_set_oid_from_text(OID_RSA, &aid->algorithm));
	DO(asn_create_any(get_NULL_desc(), null_params, &aid->parameters));

	*out = aid;
	aid = NULL;

cleanup:
	asn_free(get_AlgorithmIdentifier_desc(), aid);
	asn_free(get_NULL_desc(), null_params);
	return ret;
}

int aid_gost28147_get_iv_and_sbox(const AlgorithmIdentifier_t* aid, ByteArray** iv, ByteArray** sbox)
{
	int ret = RET_OK;
	uint8_t* dke = NULL;
	GOST28147ParamsOptionalDke_t* gost28147_params = NULL;

	CHECK_NOT_NULL(gost28147_params = asn_any2type(aid->parameters, get_GOST28147ParamsOptionalDke_desc()));
	if (iv) {
		DO(asn_OCTSTRING2ba(&gost28147_params->iv, iv));
	}

	if (sbox) {
		size_t i, j, count, dke_size;
		uint8_t sbox_buf[128] = { 0 };

		if (gost28147_params->dke != NULL) {
			DO(asn_OCTSTRING2bytes(gost28147_params->dke, &dke, &dke_size));
			if (dke_size != 64) {
				SET_ERROR(RET_INVALID_PARAM);
			}
			//decompress sbox
			count = 0;
			for (i = 0; i < 8; i++) {
				for (j = 0; j < 16; j++) {
					sbox_buf[count++] = (dke[(i << 3) + (j >> 1)] >> ((~j & 1) << 2)) & 0xf;
				}
			}

			CHECK_NOT_NULL(*sbox = ba_alloc_from_uint8(sbox_buf, 128));
		}
	}

cleanup:
	free(dke);
	ASN_FREE(get_GOST28147ParamsOptionalDke_desc(), gost28147_params);
	return ret;
}
