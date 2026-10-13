/* Jitter RNG: SHA-3 Implementation
 *
 * Copyright (C) 2021 - 2025, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/*
 * UAPKI: this file replaces the SHA-3 implementation of the Jitter RNG by calls to the SHA-3 of the uapkic library.
 * The interface is the one of the original jitterentropy-sha3.c.
 */

#include "jitterentropy-sha3.h"
#include "jitterentropy.h"

#include <string.h>

#include "byte-array-internal.h"
#include "sha3.h"

void jent_sha3_256_init(struct jent_sha_ctx *ctx)
{
	/* A context on the stack is not initialized: nothing is read from it */
	ctx->impl = NULL;
}

void jent_sha3_update(struct jent_sha_ctx *ctx, const uint8_t *in, size_t inlen)
{
	ByteArray data;

	if (!ctx->impl)
		ctx->impl = sha3_alloc(SHA3_VARIANT_256);
	if (!ctx->impl || !in || !inlen)
		return;

	data.buf = (uint8_t *)in;
	data.len = inlen;
	(void)sha3_update((Sha3Ctx *)ctx->impl, &data);
}

void jent_sha3_final(struct jent_sha_ctx *ctx, uint8_t *digest)
{
	ByteArray *hash = NULL;

	if (!ctx->impl)
		ctx->impl = sha3_alloc(SHA3_VARIANT_256);
	if (ctx->impl && (sha3_final((Sha3Ctx *)ctx->impl, &hash) == 0) && hash &&
	    (hash->len == JENT_SHA3_256_SIZE_DIGEST)) {
		memcpy(digest, hash->buf, JENT_SHA3_256_SIZE_DIGEST);
	} else {
		/* No digest: the caller gets no data of the previous one */
		memset(digest, 0, JENT_SHA3_256_SIZE_DIGEST);
	}
	ba_free_private(hash);
	/* The context is left ready for the next message */
	sha3_free((Sha3Ctx *)ctx->impl);
	ctx->impl = NULL;
}

int jent_sha3_alloc(void **hash_state)
{
	struct jent_sha_ctx *tmp;

	tmp = jent_zalloc(JENT_SHA_MAX_CTX_SIZE);
	if (!tmp)
		return 1;

	*hash_state = tmp;

	return 0;
}

void jent_sha3_dealloc(void *hash_state)
{
	struct jent_sha_ctx *ctx = (struct jent_sha_ctx *)hash_state;

	if (!ctx)
		return;
	sha3_free((Sha3Ctx *)ctx->impl);
	ctx->impl = NULL;
	jent_zfree(ctx, JENT_SHA_MAX_CTX_SIZE);
}

int jent_sha3_tester(void)
{
	HASH_CTX_ON_STACK(ctx);
	static const uint8_t msg_256[] = { 0x5E, 0x5E, 0xD6 };
	static const uint8_t exp_256[] = { 0xF1, 0x6E, 0x66, 0xC0, 0x43, 0x72,
					   0xB4, 0xA3, 0xE1, 0xE3, 0x2E, 0x07,
					   0xC4, 0x1C, 0x03, 0x40, 0x8A, 0xD5,
					   0x43, 0x86, 0x8C, 0xC4, 0x0E, 0xC5,
					   0x5E, 0x00, 0xBB, 0xBB, 0xBD, 0xF5,
					   0x91, 0x1E };
	uint8_t act[JENT_SHA3_256_SIZE_DIGEST] = { 0 };
	unsigned int i;

	jent_sha3_256_init(&ctx);
	jent_sha3_update(&ctx, msg_256, 3);
	jent_sha3_final(&ctx, act);

	for (i = 0; i < JENT_SHA3_256_SIZE_DIGEST; i++) {
		if (exp_256[i] != act[i])
			return 1;
	}

	return 0;
}
