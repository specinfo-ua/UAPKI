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

#ifndef UAPKI_CRL_STORE_H
#define UAPKI_CRL_STORE_H

#include "cer-item.h"
#include "crl-item.h"


namespace UapkiNS {

namespace Crl {


class CrlStore {
    std::mutex  m_Mutex;
    std::mutex  m_MutexFirstDownloading;
    std::string m_Path;
    bool        m_UseDeltaCrl;
    std::vector<CrlItem*>
                m_Items;

public:
    CrlStore (void);
    ~CrlStore (void);

    void setParams (
        const std::string& path,
        bool useDeltaCrl
    );

public:
    //  The group of functions that have lock_guard
    int addCrl (
        const ByteArray* baEncoded,
        const bool permanent,
        bool& isUnique,
        CrlItem** crlItem
    );
    int getCount (
        size_t& count
    );
    CrlItem* getCrl (
        const ByteArray* baAuthorityKeyId,
        const Type crlType,
        const std::vector<std::string>& urisDelta
    );
    int getCrlByCrlId (
        const ByteArray* baCrlId,
        CrlItem** crlItem
    );
    int getCrlByIndex (
        const size_t index,
        CrlItem** crlItem
    );
    std::vector<CrlItem*> getCrlItems (void);
    int load (void);
    int removeCrl (
        const ByteArray* baCrlId,
        const bool permanent
    );

public:
    std::mutex& getMutexFirstDownloading (void) {
        return m_MutexFirstDownloading;
    }
    bool useDeltaCrl (void) const {
        return m_UseDeltaCrl;
    }

private:
    CrlItem* addItem (
        CrlItem* crlStoreItem
    );
    int loadDir (void);
    int removeObsolete (void);
    void reset (void);

};  //  end class CrlStore


}   //  end namespace Crl

}   //  end namespace UapkiNS

#endif
