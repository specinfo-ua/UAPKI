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

#ifndef UAPKI_LIBRARY_CONFIG_H
#define UAPKI_LIBRARY_CONFIG_H


#include <string>
#include <vector>


using namespace std;


class LibraryConfig {
public:
    struct TspParams {
        bool    forced;
        string  policyId;
        vector<string>
                uris;

        TspParams (void)
            : forced(false) {
        }
    };  //  end struct TspParams

private:
    bool    m_IsInitialized;
    bool    m_Offline;
    TspParams
            m_TspParams;

public:
    LibraryConfig (void)
        : m_IsInitialized(false), m_Offline(false)
    {
    }

    ~LibraryConfig (void) {
        m_IsInitialized = false;
    }

    bool getOffline (void) const { return m_Offline; }
    const TspParams& getTsp (void) const { return m_TspParams; }
    bool isInitialized (void) const { return m_IsInitialized; }

    void setInitialized (bool isInitialized) { m_IsInitialized = isInitialized; }
    void setOffline (bool offline) { m_Offline = offline; }
    void setTsp (const TspParams& params) {
        m_TspParams.forced = params.forced;
        m_TspParams.policyId = params.policyId;
        m_TspParams.uris = params.uris;
    }

};  //  end class LibraryConfig


#endif
