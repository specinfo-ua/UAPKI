/*
 * Copyright (c) 2022, The UAPKI Project Authors.
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

#include "api-json-internal.h"
#include "oid-utils.h"
#include "parson-helper.h"

#undef FILE_MARKER
#define FILE_MARKER "api/digest.cpp"

#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif

#define FILE_BLOCK_SIZE (10 * 1024 * 1024)

using namespace  std;

//  See: byte-array-internal.h
struct ByteArray_st {
    const uint8_t* buf;
    size_t len;
};

static int digest_bytes (const HashAlg hashAlgo, JSON_Object* joParams, ByteArray** baHash)
{
    int ret = RET_OK;
    UapkiNS::SmartBA sba_data;

    if (!sba_data.set(json_object_get_base64(joParams, "bytes"))) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    DO(::hash(hashAlgo, sba_data.get(), baHash));

cleanup:
    return ret;
}

static int digest_file (const HashAlg hashAlgo, JSON_Object* joParams, ByteArray** baHash)
{
    int ret = RET_OK;
    HashCtx* hash_ctx = nullptr;
    ByteArray* ba_data = nullptr;
    const char* filename = nullptr;
    FILE* f = nullptr;

    filename = json_object_get_string(joParams, "file");
    if (!filename) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    f = fopen(filename, "rb");
    if (!f) {
        SET_ERROR(RET_UAPKI_FILE_OPEN_ERROR);
    }

    CHECK_NOT_NULL(hash_ctx = hash_alloc(hashAlgo));

    CHECK_NOT_NULL(ba_data = ba_alloc_by_len(FILE_BLOCK_SIZE));

    do {
        ba_data->len = fread(ba_get_buf(ba_data), 1, FILE_BLOCK_SIZE, f);
        DO(hash_update(hash_ctx, ba_data));
    } while (ba_data->len == FILE_BLOCK_SIZE);

    if (ferror(f)) {
        SET_ERROR(RET_UAPKI_FILE_READ_ERROR);
    }

    DO(hash_final(hash_ctx, baHash));

cleanup:
    ba_free(ba_data);
    hash_free(hash_ctx);
    return ret;
}

static int digest_memory (const HashAlg hashAlgo, JSON_Object* joParams, ByteArray** baHash)
{
    int ret = RET_OK;
    UapkiNS::SmartBA sba_ptr;
    ByteArray ba_local = { nullptr, 0 };
    double f_len = 0;

    sba_ptr.set(json_object_get_hex(joParams, "ptr"));
    f_len = json_object_get_number(joParams, "size");
    ba_local.len = (size_t)f_len;
    if ((sba_ptr.size() != sizeof(void*)) || (f_len < 0) || ((double)ba_local.len != f_len)) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    DO(ba_swap(sba_ptr.get()));
    memcpy(&ba_local.buf, sba_ptr.buf(), sba_ptr.size());

    DEBUG_OUTCON(printf("ptr=%p\n", ba_local.buf));
    if (ba_local.buf == 0) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    DO(::hash(hashAlgo, &ba_local, baHash));

cleanup:
    return ret;
}


int uapki_digest (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    UapkiNS::SmartBA sba_hash;
    const char* s_hashalgo = nullptr;
    const char* s_signalgo = nullptr;
    HashAlg hash_algo = HashAlg::HASH_ALG_UNDEFINED;

    s_hashalgo = json_object_get_string(joParams, "hashAlgo");
    if (!s_hashalgo) {
        s_signalgo = json_object_get_string(joParams, "signAlgo");
    }
    if (!s_hashalgo && !s_signalgo) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    hash_algo = hash_from_oid((s_hashalgo) ? s_hashalgo : s_signalgo);
    if (hash_algo == HashAlg::HASH_ALG_UNDEFINED) {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }
    DO_JSON(json_object_set_string(joResult, "hashAlgo", (s_hashalgo) ? s_hashalgo : hash_to_oid(hash_algo)));

    if (ParsonHelper::jsonObjectHasValue(joParams, "bytes", JSONString)) {
        DO(digest_bytes(hash_algo, joParams, &sba_hash));
    }
    else if (ParsonHelper::jsonObjectHasValue(joParams, "file", JSONString)) {
        DO(digest_file(hash_algo, joParams, &sba_hash));
    }
    else if (ParsonHelper::jsonObjectHasValue(joParams, "ptr", JSONString)
          && ParsonHelper::jsonObjectHasValue(joParams, "size", JSONNumber)) {
        DO(digest_memory(hash_algo, joParams, &sba_hash));
    }
    else {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    DO_JSON(json_object_set_base64(joResult, "bytes", sba_hash.get()));

cleanup:
    return ret;
}
