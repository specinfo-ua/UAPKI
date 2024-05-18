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

#ifndef UAPKI_LIBRARY_CONFIG_H
#define UAPKI_LIBRARY_CONFIG_H


#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>


namespace UapkiNS {


class LibraryConfig {
public:
    struct OcspParams {
        static const size_t NONCE_LEN_DEFAULT = 20;

        size_t  nonceLen;

        OcspParams (void)
            : nonceLen (NONCE_LEN_DEFAULT)
        {
        }
    };  //  end struct OcspParams

    struct TspParams {
        static const size_t NONCE_LEN_DEFAULT = 8;

        bool    certReq;
        bool    forced;
        size_t  nonceLen;
        std::string
                policyId;
        std::vector<std::string>
                uris;

        TspParams (void)
            : certReq(false)
            , forced(false)
            , nonceLen(NONCE_LEN_DEFAULT)
        {
        }
    };  //  end struct TspParams

private:
    bool    m_IsInitialized;
    OcspParams
            m_OcspParams;
    bool    m_Offline;
    TspParams
            m_TspParams;
    bool    m_ValidationByCrl;

public:
    LibraryConfig (void)
        : m_IsInitialized(false), m_Offline(false), m_ValidationByCrl(false)
    {
    }

    ~LibraryConfig (void) {
        m_IsInitialized = false;
    }

    const OcspParams& getOcsp (void) const {
        return m_OcspParams;
    }
    bool getOffline (void) const {
        return m_Offline;
    }
    const TspParams& getTsp (void) const {
        return m_TspParams;
    }
    bool getValidationByCrl (void) const {
        return m_ValidationByCrl;
    }
    bool isInitialized (void) const {
        return m_IsInitialized;
    }

    void setInitialized (bool isInitialized) {
        m_IsInitialized = isInitialized;
    }
    void setOcsp (const OcspParams& ocspParams) {
        m_OcspParams.nonceLen = ocspParams.nonceLen;
    }
    void setOffline (bool offline) {
        m_Offline = offline;
    }
    void setTsp (const TspParams& tspParams) {
        m_TspParams.certReq = tspParams.certReq;
        m_TspParams.forced = tspParams.forced;
        m_TspParams.nonceLen = tspParams.nonceLen;
        m_TspParams.policyId = tspParams.policyId;
        m_TspParams.uris = tspParams.uris;
    }
    void setValidationByCrl (bool validationByCrl) {
        m_ValidationByCrl = validationByCrl;
    }

};  //  end class LibraryConfig


}   //  end namespace UapkiNS

#endif
