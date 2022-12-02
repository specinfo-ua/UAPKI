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

#ifndef UAPKI_NS_OCSP_HELPER_H
#define UAPKI_NS_OCSP_HELPER_H


#include <vector>
#include "byte-array.h"
#include "cer-store.h"
#include "crl-store.h"
#include "uapki-ns.h"
#include "uapkif.h"
#include "verify-status.h"


namespace UapkiNS {

namespace Ocsp {

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


    class OcspHelper
    {
    public:
        static const size_t NONCE_MAXLEN    = 64;
        static const size_t NONCE_MINLEN    = 8;

        struct OcspRecord {
            UapkiNS::CertStatus
                        status;
            uint64_t    msThisUpdate;
            uint64_t    msNextUpdate;
            uint64_t    msRevocationTime;
            UapkiNS::CrlReason
                        revocationReason;
            OcspRecord (void)
                : status(UapkiNS::CertStatus::UNDEFINED)
                , msThisUpdate(0)
                , msNextUpdate(0)
                , msRevocationTime(0)
                , revocationReason(UapkiNS::CrlReason::UNDEFINED)
            {}
        };  //  end struct OcspRecord

    private:
        std::vector<OcspRecord>
                    m_OcspRecords;
        OCSPRequest_t*
                    m_OcspRequest;
        BasicOCSPResponse_t*
                    m_BasicOcspResp;
        ByteArray*  m_BaNonce;
        ByteArray*  m_BaEncoded;
        ByteArray*  m_BaTbsEncoded;
        ByteArray*  m_BaBasicOcspResponse;
        ByteArray*  m_BaTbsResponseData;
        uint64_t    m_ProducedAt;
        ResponseStatus
                    m_ResponseStatus;

    public:
        OcspHelper (void);
        ~OcspHelper (void);

        void reset (void);

        int init (void);
        int addCert (
            const CerStore::Item* cerIssuer,
            const CerStore::Item* cerSubject
        );
        int addSN (
            const CerStore::Item* cerIssuer,
            const ByteArray* baSerialNumber
        );
        int genNonce (
            const size_t nonceLen
        );
        int setNonce (
            const ByteArray* baNonce
        );

        int encodeTbsRequest (void);
        int setSignature (
            const UapkiNS::AlgorithmIdentifier& aidSignature,
            const ByteArray* baSignValue,
            const std::vector<ByteArray*>& certs = std::vector<ByteArray*>()
        );

        int encodeRequest (void);
        ByteArray* getRequestEncoded (
            const bool move = false
        );

        int parseResponse (
            const ByteArray* baEncoded
        );
        int checkNonce (void);
        int generateOtherHash (
            const UapkiNS::AlgorithmIdentifier& aidHash,
            ByteArray** baEncoded
        );
        ByteArray* getBasicOcspResponseEncoded (
            const bool move = false
        );
        int getCerts (
            std::vector<ByteArray*>& certs
        );
        int getOcspIdentifier (     //  Note: used for complete-revocation-references Attribute (rfc5126, $6.2.2)
            ByteArray** baOcspIdentifier
        );
        const OcspRecord& getOcspRecord (
            const size_t index
        ) const;
        int getResponderId (
            ResponderIdType &responderIdType,
            ByteArray** baResponderId
        );
        int scanSingleResponses (void);
        int verifyTbsResponseData (
            const CerStore::Item* cerResponder,
            SIGNATURE_VERIFY::STATUS& statusSign
        );

        const size_t countOcspRecords (void) const { return m_OcspRecords.size(); };
        const ByteArray* getNonce (void) const { return m_BaNonce; }
        uint64_t getProducedAt (void) const { return m_ProducedAt; }
        ResponseStatus getResponseStatus (void) const { return m_ResponseStatus; }
        const ByteArray* getTbsEncoded (void) const { return m_BaTbsEncoded; }
        const ByteArray* getTbsResponseData (void) const { return m_BaTbsResponseData; }

    public:
        int addNonceToExtension (void);
        int parseOcspResponse (const ByteArray* baEncoded);

    public:
        static int generateOtherHash (
            const ByteArray* baOcspResponseEncoded,
            const UapkiNS::AlgorithmIdentifier& aidHash,
            ByteArray** baEncoded
        );

    };  //  end class OcspHelper


    const char* responseStatusToStr (
        const ResponseStatus status
    );


}   //  end namespace Ocsp

}   //  end namespace UapkiNS

#endif
