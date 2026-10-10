/*
 * Copyright (c) 2026, The UAPKI Project Authors.
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

#include "der-helper.h"


using namespace std;


namespace UapkiNS {

namespace Der {


bool read (
        const uint8_t* p,
        const size_t len,
        size_t& lenHeader,
        size_t& lenBody
)
{
    if (len < 2) return false;
    size_t pos = 1, n = p[pos++];
    if (n & 0x80) {
        const size_t cnt = n & 0x7F;
        if ((cnt == 0) || (cnt > sizeof(size_t)) || (pos + cnt > len)) return false;
        n = 0;
        for (size_t i = 0; i < cnt; i++) n = (n << 8) | p[pos++];
    }
    if (pos + n > len) return false;
    lenHeader = pos;
    lenBody = n;
    return true;
}

vector<uint8_t> wrap (
        const uint8_t tag,
        const vector<uint8_t>& body
)
{
    vector<uint8_t> rv = { tag };
    if (body.size() < 0x80) {
        rv.push_back((uint8_t)body.size());
    }
    else {
        vector<uint8_t> n;
        for (size_t l = body.size(); l > 0; l >>= 8) n.insert(n.begin(), (uint8_t)(l & 0xFF));
        rv.push_back((uint8_t)(0x80 | n.size()));
        rv.insert(rv.end(), n.begin(), n.end());
    }
    rv.insert(rv.end(), body.begin(), body.end());
    return rv;
}

bool children (
        const uint8_t* p,
        const size_t len,
        vector<vector<uint8_t>>& children
)
{
    size_t lh = 0, lb = 0;
    if (!read(p, len, lh, lb)) return false;
    size_t pos = lh;
    while (pos < lh + lb) {
        size_t clh = 0, clb = 0;
        if (!read(p + pos, lh + lb - pos, clh, clb)) return false;
        children.push_back(vector<uint8_t>(p + pos, p + pos + clh + clb));
        pos += clh + clb;
    }
    return (pos == lh + lb);
}


}   //  end namespace Der

}   //  end namespace UapkiNS
