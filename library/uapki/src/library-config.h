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

#ifndef UAPKI_LIBRARY_CONFIG_H
#define UAPKI_LIBRARY_CONFIG_H


#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>
#include "http-helper.h"


namespace UapkiNS {


class LibraryConfig {
public:
    struct OcspParams {
        static const size_t NONCE_LEN_DEFAULT = 20;
        //  Minutes. A cached response without nextUpdate is used up to thisUpdate + cacheTime; a response
        //  without nextUpdate is fresh if issued after the validation time - maxFreshness (EN 319 102-1, 5.2.5.4):
        //  by default the time to publish a change of the status. cacheTime < maxFreshness: the responses
        //  embedded by signing pass VERIFY
        static const uint32_t CACHE_TIME_DEFAULT = 30;
        static const uint32_t MAX_FRESHNESS_DEFAULT = 120;
        //  Bytes. The CRL of an OCSP responder without id-pkix-ocsp-nocheck is embedded into a CAdES-B-LT/B-LTA
        //  signature only up to this size (the size of the signature: a CRL of a CA may be megabytes); a bigger one
        //  is used for the validation but not embedded - the signature is then not a complete B-LT
        //  (EN 319 122-1, table 1, o). By default only small CRLs (e.g. of the central certification authority)
        static const uint32_t RESPONDER_CRL_EMBED_MAX_SIZE_DEFAULT = 10240;

        size_t  nonceLen;
        uint32_t
                cacheTime;
        uint32_t
                maxFreshness;
        uint32_t
                responderCrlEmbedMaxSize;

        OcspParams (void)
            : nonceLen (NONCE_LEN_DEFAULT)
            , cacheTime (CACHE_TIME_DEFAULT)
            , maxFreshness (MAX_FRESHNESS_DEFAULT)
            , responderCrlEmbedMaxSize (RESPONDER_CRL_EMBED_MAX_SIZE_DEFAULT)
        {
        }
        //  The time a response may be used from the cache: up to nextUpdate, without it thisUpdate + cacheTime
        uint64_t cacheValidTime (
            const uint64_t msThisUpdate,
            const uint64_t msNextUpdate
        ) const {
            return (msNextUpdate > 0) ? msNextUpdate : (msThisUpdate + (uint64_t)cacheTime * 60000);
        }
        //  The response is fresh for the validation time: nextUpdate later than it, without nextUpdate
        //  thisUpdate later than validateTime - maxFreshness
        bool isFresh (
            const uint64_t msThisUpdate,
            const uint64_t msNextUpdate,
            const uint64_t validateTime
        ) const {
            if (msNextUpdate > 0) return (msNextUpdate > validateTime);
            return (msThisUpdate + (uint64_t)maxFreshness * 60000 > validateTime);
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
    std::string
            m_InitParams;
    HttpHelper::Params
            m_HttpParams;
    OcspParams
            m_OcspParams;
    TspParams
            m_TspParams;
    bool    m_ValidationByCrl;
    //  Seconds: the accuracy of a time-stamp token without the accuracy field when the order of the time-stamps
    //  is checked (RFC 3161, 2.4.2; ETSI EN 319 102-1, 5.5.4 4) e)); 0 - as a token with zero accuracy
    uint32_t
            m_TimeStampOrderTolerance;

public:
    LibraryConfig (void)
        : m_IsInitialized(false), m_ValidationByCrl(false), m_TimeStampOrderTolerance(0)
    {
    }

    ~LibraryConfig (void) {
        m_IsInitialized = false;
    }

    const HttpHelper::Params& getHttp (void) const {
        return m_HttpParams;
    }
    const OcspParams& getOcsp (void) const {
        return m_OcspParams;
    }
    bool getOffline (void) const {
        return m_HttpParams.offline;
    }
    const TspParams& getTsp (void) const {
        return m_TspParams;
    }
    bool getValidationByCrl (void) const {
        return m_ValidationByCrl;
    }
    uint32_t getTimeStampOrderTolerance (void) const {
        return m_TimeStampOrderTolerance;
    }
    bool isInitialized (void) const {
        return m_IsInitialized;
    }

    void setInitialized (bool initialized) {
        m_IsInitialized = initialized;
    }
    //  The parameters the library (the session) was initialized with, as JSON; without the proxy credentials
    const std::string& getInitParams (void) const {
        return m_InitParams;
    }
    void setInitParams (const std::string& initParams) {
        m_InitParams = initParams;
    }
    void setOcsp (const OcspParams& ocspParams) {
        m_OcspParams.nonceLen = ocspParams.nonceLen;
        m_OcspParams.cacheTime = ocspParams.cacheTime;
        m_OcspParams.maxFreshness = ocspParams.maxFreshness;
        m_OcspParams.responderCrlEmbedMaxSize = ocspParams.responderCrlEmbedMaxSize;
    }
    void setOffline (bool offline) {
        m_HttpParams.offline = offline;
    }
    void setProxy (const char* proxyUrl, const char* proxyCredentials) {
        m_HttpParams.proxyUrl = (proxyUrl) ? std::string(proxyUrl) : std::string();
        m_HttpParams.proxyCredentials = (proxyCredentials && !m_HttpParams.proxyUrl.empty())
            ? std::string(proxyCredentials) : std::string();
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
    void setTimeStampOrderTolerance (uint32_t seconds) {
        m_TimeStampOrderTolerance = seconds;
    }

};  //  end class LibraryConfig


}   //  end namespace UapkiNS

#endif
