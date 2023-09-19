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

#define FILE_MARKER "cm-pkcs12/storage/jks-buffer.c"

#include <string.h>
#include "jks-buffer.h"
#include "macros-internal.h"

#define SHA1_HASH_LEN               20


JksBufferCtx* jks_buffer_alloc(void)
{
    int ret = RET_OK;
    JksBufferCtx *ctx = NULL;

    CALLOC_CHECKED(ctx, sizeof(JksBufferCtx));

    CHECK_NOT_NULL(ctx->buffer = ba_alloc());

    return ctx;

cleanup:

    jks_buffer_free(ctx);

    return NULL;
}

JksBufferCtx* jks_buffer_alloc_ba(const ByteArray *data)
{
    int ret = RET_OK;
    size_t offset = 0;
    JksBufferCtx *ctx = NULL;

    MALLOC_CHECKED(ctx, sizeof(JksBufferCtx));

    offset = ba_get_len(data) - SHA1_HASH_LEN;

    CHECK_NOT_NULL(ctx->buffer = ba_copy_with_alloc(data, 0, offset));
    CHECK_NOT_NULL(ctx->hash = ba_copy_with_alloc(data, offset, SHA1_HASH_LEN));
    ctx->read_off = 0;

    return ctx;

cleanup:

    jks_buffer_free(ctx);

    return NULL;
}

void jks_buffer_free(JksBufferCtx *buffer_ctx)
{
    if (buffer_ctx) {
        ba_free(buffer_ctx->buffer);
        ba_free(buffer_ctx->hash);

        free(buffer_ctx);
    }
}

static int jks_buffer_read_short(JksBufferCtx *ctx, uint16_t *value)
{
    int ret = RET_OK;
    const uint8_t *buffer;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(ba_get_len(ctx->buffer) >= ctx->read_off + sizeof(uint16_t));

    buffer = ba_get_buf(ctx->buffer);

    *value =  buffer[ctx->read_off++] << 8;
    *value |= buffer[ctx->read_off++] & 0xff;

cleanup:

    return ret;
}

int jks_buffer_read_int(JksBufferCtx *ctx, uint32_t *value)
{
    int ret = RET_OK;
    const uint8_t *buffer;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(ba_get_len(ctx->buffer) >= ctx->read_off + sizeof(uint32_t));

    buffer = ba_get_buf(ctx->buffer);

    *value =   buffer[ctx->read_off++] << 24;
    *value |= (buffer[ctx->read_off++] & 0xff) << 16;
    *value |= (buffer[ctx->read_off++] & 0xff) << 8;
    *value |= (buffer[ctx->read_off++] & 0xff) << 0;

cleanup:

    return ret;
}

int jks_buffer_read_long(JksBufferCtx *ctx, uint64_t *value)
{
    int ret = RET_OK;
    const uint8_t *buffer;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(ba_get_len(ctx->buffer) >= ctx->read_off + sizeof(uint64_t));

    buffer = ba_get_buf(ctx->buffer);

    *value =  (uint64_t)buffer[ctx->read_off++] << 56;
    *value |= (uint64_t)buffer[ctx->read_off++] << 48;
    *value |= (uint64_t)buffer[ctx->read_off++] << 40;
    *value |= (uint64_t)buffer[ctx->read_off++] << 32;
    *value |= (uint64_t)buffer[ctx->read_off++] << 24;
    *value |= (uint64_t)buffer[ctx->read_off++] << 16;
    *value |= (uint64_t)buffer[ctx->read_off++] << 8;
    *value |= (uint64_t)buffer[ctx->read_off++] << 0;

cleanup:

    return ret;
}

int jks_buffer_read_data(JksBufferCtx *ctx, ByteArray **data)
{
    int ret = RET_OK;
    uint32_t len = 0;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(data != NULL);

    DO(jks_buffer_read_int(ctx, &len));

    CHECK_NOT_NULL(*data = ba_copy_with_alloc(ctx->buffer, ctx->read_off, len));

    ctx->read_off += len;

cleanup:

    return ret;
}

int jks_buffer_read_string(JksBufferCtx *ctx, char **string)
{
    int ret = RET_OK;
    uint16_t string_len = 0;
    const uint8_t *buffer;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(string != NULL);

    DO(jks_buffer_read_short(ctx, &string_len));

    buffer = ba_get_buf(ctx->buffer);

    CALLOC_CHECKED(*string, string_len + 1);
    memcpy(*string, buffer + ctx->read_off, string_len);

    ctx->read_off += string_len;

cleanup:

    return ret;
}

int jks_buffer_get_hash(const JksBufferCtx *ctx, ByteArray **hash)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(hash != NULL);

    CHECK_NOT_NULL(*hash = ba_copy_with_alloc(ctx->hash, 0, 0));

cleanup:

    return ret;
}

int jks_buffer_get_body(const JksBufferCtx *ctx, ByteArray **body)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(body != NULL);

    CHECK_NOT_NULL(*body = ba_copy_with_alloc(ctx->buffer, 0, 0));

cleanup:

    return ret;
}

int jks_buffer_to_ba(const JksBufferCtx *ctx, ByteArray **ba)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(ba != NULL);

    *ba = ba_join(ctx->buffer, ctx->hash);

cleanup:

    return ret;
}

