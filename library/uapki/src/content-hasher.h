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

#ifndef UAPKI_CONTENT_HASHER_H
#define UAPKI_CONTENT_HASHER_H


#include "uapki-ns.h"
#include "hash.h"
#include <string>


namespace UapkiNS {


class ContentHasher {
public:
    enum class SourceType : uint32_t {
        UNDEFINED   = 0,
        BYTEARRAY   = 1,
        FILE        = 2,
        MEMORY      = 3
    };  //  end enum SourceType

private:
    SourceType  m_SourceType;
    HashAlg     m_HashAlgo;
    ByteArray*  m_Bytes;
    bool        m_AutoReleaseBytes;
    std::string m_Filename;
    const uint8_t*
                m_MemoryPtr;
    size_t      m_MemorySize;
    SmartBA     m_Value;

public:
    ContentHasher (void);
    ~ContentHasher (void);

    int digest (
        const HashAlg hashAlgo
    );
    void reset (void);
    int setContent (
        const ByteArray* baBytes,
        const bool autoRelease
    );
    int setContent (
        const char* filename
    );
    int setContent (
        const uint8_t* ptr,
        const size_t size
    );

public:
    const ByteArray* getContentBytes (void) const {
        return m_Bytes;
    }
    const ByteArray* getHashValue (void) const {
        return m_Value.get();
    }
    SourceType getSourceType (void) const {
        return m_SourceType;
    }
    bool isPresent (void) const {
        return (m_SourceType != SourceType::UNDEFINED);
    }

public:
    static const uint8_t* baToPtr (
        const ByteArray* baPtr
    );
    static bool numberToSize (
        const double fSize,
        size_t& size
    );

private:
    int digestFile (
        const HashAlg hashAlgo
    );
    int digestMemory (
        const HashAlg hashAlgo
    );
    void setSourceType (
        const SourceType sourceType
    );

};  //  end class ContentHasher


}   //  end namespace UapkiNS


#endif
