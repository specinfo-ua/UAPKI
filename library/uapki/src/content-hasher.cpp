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

#define FILE_MARKER "uapki/content-hasher.cpp"

#include "content-hasher.h"
#include "ba-utils.h"
#include "macros-internal.h"
#include "uapkic-errors.h"
#include "uapki-errors.h"
#include <cstring>


#define FILE_BLOCK_SIZE (10 * 1024 * 1024)


 //  See: byte-array-internal.h
struct ByteArray_st {
    const uint8_t*  buf;
    size_t          len;
};


using namespace std;

namespace UapkiNS {


ContentHasher::ContentHasher (void)
    : m_SourceType(SourceType::UNDEFINED)
    , m_HashAlgo(HASH_ALG_UNDEFINED)
    , m_Bytes(nullptr)
    , m_AutoReleaseBytes(false)
    , m_MemoryPtr(nullptr)
    , m_MemorySize(0)
{
}

ContentHasher::~ContentHasher (void)
{
    reset();
}

int ContentHasher::digest (
        const HashAlg hashAlgo
)
{
    if (
        (hashAlgo == HASH_ALG_UNDEFINED) ||
        (m_SourceType == SourceType::UNDEFINED)
    ) RET_UAPKI_INVALID_PARAMETER;

    if (m_HashAlgo == hashAlgo) return RET_OK;

    setSourceType(m_SourceType);

    int ret = RET_OK;
    switch (m_SourceType) {
    case SourceType::BYTEARRAY:
        ret = ::hash(hashAlgo, m_Bytes, &m_Value);
        break;
    case SourceType::FILE:
        ret = digestFile(hashAlgo);
        break;
    case SourceType::MEMORY:
        ret = digestMemory(hashAlgo);
        break;
    default:
        ret = RET_UAPKI_INVALID_PARAMETER;
        break;
    }

    if (ret == RET_OK) {
        m_HashAlgo = hashAlgo;
    }
    return ret;
}

void ContentHasher::reset (void)
{
    if (m_AutoReleaseBytes && m_Bytes) {
        ba_free(m_Bytes);
        m_Bytes = nullptr;
    }
    m_Filename.clear();
    m_MemoryPtr = nullptr;
    m_MemorySize = 0;
    m_SourceType = SourceType::UNDEFINED;
}

int ContentHasher::setContent (
        const ByteArray* baBytes,
        const bool autoRelease
)
{
    if (!baBytes) return RET_UAPKI_INVALID_PARAMETER;

    setSourceType(SourceType::BYTEARRAY);
    m_Bytes = (ByteArray*)baBytes;
    m_AutoReleaseBytes = autoRelease;
    return RET_OK;
}

int ContentHasher::setContent (
        const char* filename
)
{
    if (!filename) return RET_UAPKI_INVALID_PARAMETER;

    setSourceType(SourceType::FILE);
    m_Filename = string(filename);
    return RET_OK;
}

int ContentHasher::setContent (
        const uint8_t* ptr,
        const size_t size
)
{
    if (!ptr) return RET_UAPKI_INVALID_PARAMETER;

    setSourceType(SourceType::MEMORY);
    m_MemoryPtr = ptr;
    m_MemorySize = size;
    return RET_OK;
}

const uint8_t* ContentHasher::baToPtr (
        const ByteArray* baPtr
)
{
    const uint8_t* rv_ptr = nullptr;
    if ((ba_get_len(baPtr) == sizeof(void*))) {
        (void)ba_swap(baPtr);
        memcpy(&rv_ptr, ba_get_buf_const(baPtr), sizeof(void*));
        (void)ba_swap(baPtr);
    }
    return rv_ptr;
}

bool ContentHasher::numberToSize (
        const double fSize,
        size_t& size
)
{
    size = (size_t)fSize;
    return (fSize >= 0) && ((double)size == fSize);
}

int ContentHasher::digestFile (
        const HashAlg hashAlgo
)
{
    int ret = RET_OK;
    HashCtx* hash_ctx = nullptr;
    ByteArray* ba_data = nullptr;
    FILE* f = nullptr;

    f = fopen_utf8(m_Filename.c_str(), 0);
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

    DO(hash_final(hash_ctx, &m_Value));

cleanup:
    if (f) {
        fclose(f);
    }
    ba_free(ba_data);
    hash_free(hash_ctx);
    return ret;
}

int ContentHasher::digestMemory (
        const HashAlg hashAlgo
)
{
    ByteArray ba_local = { m_MemoryPtr, m_MemorySize };
    return ::hash(hashAlgo, &ba_local, &m_Value);
}

void ContentHasher::setSourceType (
        const SourceType sourceType
)
{
    m_SourceType = sourceType;
    m_HashAlgo = HASH_ALG_UNDEFINED;
    m_Value.clear();
}


}   //  end namespace UapkiNS
