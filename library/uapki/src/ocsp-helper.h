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

#ifndef OCSP_HELPER_H
#define OCSP_HELPER_H


#include "uapkic.h"
#include "uapkif.h"
#include "cer-store.h"
#include "crl-store.h"
#include "common.h"
#include "ocsp-utils.h"
#include "verify-status.h"
#include "uapki-ns.h"
#include <vector>


using namespace std;


class OcspClientHelper
{
public:
    enum class ResponderIdType : int32_t {
        UNDEFINED   = -1,
        BY_NAME     = 0,
        BY_KEY      = 1
    };  //  end enum ResponderIdType

    enum class ResponseStatus : int32_t {
        UNDEFINED           = -1,
        SUCCESSFUL          = 0,
        MALFORMED_REQUEST   = 1,
        INTERNAL_ERROR      = 2,
        TRY_LATER           = 3,
        // not used          (4)
        SIG_REQUIRED        = 5,
        UNAUTHORIZED        = 6
    };  //  end enum ResponseStatus

    struct OcspRecord {
        UapkiNS::CertStatus
                    status;
        uint64_t    msThisUpdate;
        uint64_t    msNextUpdate;
        uint64_t    msRevocationTime;
        UapkiNS::CrlReason
                    revocationReason;
        OcspRecord (void)
            : status(UapkiNS::CertStatus::UNDEFINED), msThisUpdate(0), msNextUpdate(0)
            , msRevocationTime(0), revocationReason(UapkiNS::CrlReason::UNDEFINED)
        {}
    };  //  end struct OcspRecord

private:
    vector<OcspRecord>
                m_OcspRecords;
    OCSPRequest_t*
                m_OcspRequest;
    BasicOCSPResponse_t*
                m_BasicOcspResp;
    ByteArray*  m_Nonce;
    ByteArray*  m_ResponseData;
    uint64_t    m_ProducedAt;

public:
    OcspClientHelper (void);
    ~OcspClientHelper (void);

    void reset (void);

    int createRequest (void);
    int addCert (const CerStore::Item* cerIssuer, const CerStore::Item* cerSubject);
    int addSN (const CerStore::Item* cerIssuer, const ByteArray* baSerialNumber);
    int setNonce (size_t nonceLen);
    int setNonce (const ByteArray* baNonce);
    int encodeRequest (ByteArray** baEncoded);

    const size_t countOcspRecords (void) const { return m_OcspRecords.size(); };
    const OcspRecord* getOcspRecord (const size_t index) const;
    uint64_t getProducedAt (void) const { return m_ProducedAt; }
    const ByteArray* getResponseData (void) const { return m_ResponseData; }

    int parseResponse (const ByteArray* baEncoded, ResponseStatus& responseStatus);
    int getCerts (vector<ByteArray*>& certs);
    int getResponderId (ResponderIdType &responderIdType, ByteArray** baResponderId);
    int verifyTbsResponseData (const CerStore::Item* cerResponder, SIGNATURE_VERIFY::STATUS& statusSign);
    int checkNonce (void);
    int scanSingleResponses (void);

public:
    static const char* responseStatusToStr (const ResponseStatus status);

};  //  end class OcspClientHelper


#endif
