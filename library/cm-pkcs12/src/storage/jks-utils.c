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

#define FILE_MARKER "cm-pkcs12/storage/jks-utils.c"

#include "jks-buffer.h"
#include "jks-entry.h"
#include "jks-utils.h"
#include "cm-errors.h"
#include "iconv-utils.h"
#include "macros-internal.h"
#include "oids.h"
#include "oid-utils.h"


#define SHA1_HASH_LEN           20
#define SALT_LEN                20

static const uint32_t MAGIC = 0xFEEDFEED;
static const char* MAC_SALT = "Mighty Aphrodite";


int jks_read_header (JksBufferCtx* buffer, uint32_t* version, uint32_t* countEntries)
{
    int ret = RET_OK;
    uint32_t magic = 0;

    CHECK_PARAM(buffer != NULL);
    CHECK_PARAM(version != NULL);
    CHECK_PARAM(countEntries != NULL);

    DO(jks_buffer_read_int(buffer, &magic));
    DO(jks_buffer_read_int(buffer, version));

    if ((magic != MAGIC) || ((*version != JKS_VERSION_1) && (*version != JKS_VERSION_2))) {
        SET_ERROR(RET_CM_UNSUPPORTED_KEY_CONTAINER);
    }

    DO(jks_buffer_read_int(buffer, countEntries));

cleanup:
    return ret;
}

static int jks_pass_to_ba(const char* pass, ByteArray** pass_ba)
{
    int ret = RET_OK;
    uint8_t* pass_utf16be = NULL;
    size_t pass_utf16be_len = 0;

    CHECK_PARAM(pass != NULL);
    CHECK_PARAM(pass_ba != NULL);

    DO(utf8_to_utf16be(pass, &pass_utf16be, &pass_utf16be_len));

    //  without end symbol
    pass_utf16be_len -= 2;

    CHECK_NOT_NULL(*pass_ba = ba_alloc_from_uint8(pass_utf16be, pass_utf16be_len));

cleanup:

    memset(pass_utf16be, 0x00, pass_utf16be_len);
    free(pass_utf16be);

    return ret;
}

int jks_hash_store (const char* password, const ByteArray* data, ByteArray** hash)
{
    int ret = RET_OK;
    HashCtx* ctx = NULL;
    ByteArray* ba_pass = NULL;
    ByteArray* ba_salt = NULL;

    CHECK_PARAM(password != NULL);
    CHECK_PARAM(data != NULL);
    CHECK_PARAM(hash != NULL);

    DO(jks_pass_to_ba(password, &ba_pass));
    CHECK_NOT_NULL(ba_salt = ba_alloc_from_str(MAC_SALT));

    CHECK_NOT_NULL(ctx = hash_alloc(HASH_ALG_SHA1));
    //  Хеш от пароля пользователя
    DO(hash_update(ctx, ba_pass));
    //  Хеш от "соли"
    DO(hash_update(ctx, ba_salt));
    //  Хеш от данных хранилища
    DO(hash_update(ctx, data));
    DO(hash_final(ctx, hash));

cleanup:
    ba_free_private(ba_pass);
    ba_free(ba_salt);
    hash_free(ctx);
    return ret;
}

static int jks_xor_key(Sha1Ctx* ctx,
    const ByteArray* protected_key,
    const ByteArray* password,
    const ByteArray* salt,
    ByteArray** key)
{
    int ret = RET_OK;
    size_t num_rounds, i;
    size_t key_len;
    size_t offset = 0; //   offset in xorKey where next digest will be stored

    ByteArray* hash = NULL;
    ByteArray* xor_key = NULL;

    CHECK_PARAM(protected_key != NULL);
    CHECK_PARAM(password != NULL);
    CHECK_PARAM(salt != NULL);
    CHECK_PARAM(key != NULL);

    //  Determine the number of digest rounds
    key_len = ba_get_len(protected_key);
    num_rounds = key_len / SHA1_HASH_LEN;
    if ((key_len % SHA1_HASH_LEN) != 0) {
        num_rounds++;
    }

    CHECK_NOT_NULL(xor_key = ba_alloc());

    //  Compute the digests, and store them in "xorKey"
    DO(sha1_update(ctx, password));
    DO(sha1_update(ctx, salt));
    DO(sha1_final(ctx, &hash));
    DO(ba_append(hash, 0, 0, xor_key));
    offset += SHA1_HASH_LEN;

    for (i = 1; i < num_rounds; i++, offset += SHA1_HASH_LEN) {
        DO(sha1_update(ctx, password));
        DO(sha1_update(ctx, hash));

        ba_free(hash);
        hash = NULL;

        DO(sha1_final(ctx, &hash));

        //  Copy the digest into "xorKey"
        if (i < num_rounds - 1) {
            DO(ba_append(hash, 0, 0, xor_key));
        }
        else {
            DO(ba_append(hash, 0, key_len - offset, xor_key));
        }
    }

    //  XOR "plainKey" with "xorKey", and store the result in "tmpKey"
    DO(ba_xor(xor_key, protected_key));

    *key = xor_key;
    xor_key = NULL;

cleanup:

    ba_free(hash);
    ba_free_private(xor_key);

    return ret;
}

int jks_decrypt_key (const EncryptedPrivateKeyInfo_t* container, const char* pass, ByteArray** key)
{
    int ret = RET_OK;
    size_t offset;
    size_t protected_key_len;
    ByteArray* encrypted = NULL;
    ByteArray* salt = NULL;
    ByteArray* protected_key = NULL;
    ByteArray* xor_key = NULL;
    char* s_oid = NULL;

    Sha1Ctx* ctx = NULL;
    ByteArray* pass_ba = NULL;
    ByteArray* hash_exp = NULL;
    ByteArray* hash_act = NULL;

    CHECK_PARAM(container != NULL);
    CHECK_PARAM(pass != NULL);
    CHECK_PARAM(key != NULL);

    DO(asn_oid_to_text(&container->encryptionAlgorithm.algorithm, &s_oid));
    if (strcmp(s_oid, OID_JKS_KEY_PROTECTOR) != 0) {
        SET_ERROR(RET_CM_UNSUPPORTED_KEY_CONTAINER);
    }

    DO(asn_OCTSTRING2ba(&container->encryptedData, &encrypted));

    protected_key_len = ba_get_len(encrypted) - SALT_LEN - SHA1_HASH_LEN;
    offset = 0;
    CHECK_NOT_NULL(salt = ba_copy_with_alloc(encrypted, offset, SALT_LEN));

    offset += SALT_LEN;
    CHECK_NOT_NULL(protected_key = ba_copy_with_alloc(encrypted, offset, protected_key_len));

    offset += protected_key_len;
    CHECK_NOT_NULL(hash_exp = ba_copy_with_alloc(encrypted, offset, SHA1_HASH_LEN));

    DO(jks_pass_to_ba(pass, &pass_ba));
    CHECK_NOT_NULL(ctx = sha1_alloc());

    DO(jks_xor_key(ctx, protected_key, pass_ba, salt, &xor_key));
    /*
     * Check the integrity of the recovered key by concatenating it with
     * the password, digesting the concatenation, and comparing the
     * result of the digest operation with the digest provided at the end
     * of <code>protectedKey</code>. If the two digest values are
     * different, throw an exception.
     */

    DO(sha1_update(ctx, pass_ba));
    DO(sha1_update(ctx, xor_key));

    DO(sha1_final(ctx, &hash_act));

    if (ba_cmp(hash_exp, hash_act)) {
        SET_ERROR(RET_CM_INVALID_PASSWORD);
    }

    *key = xor_key;
    xor_key = NULL;

cleanup:

    sha1_free(ctx);

    ba_free_private(pass_ba);
    ba_free_private(xor_key);

    ba_free(encrypted);
    ba_free(salt);
    ba_free(protected_key);
    ba_free(hash_exp);
    ba_free(hash_act);

    return ret;
}
