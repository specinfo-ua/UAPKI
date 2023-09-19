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

#ifndef UAPKI_NS_OCSP_HELPER_H
#define UAPKI_NS_OCSP_HELPER_H


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

    static const size_t NONCE_MAXLEN    = 64;
    static const size_t NONCE_MINLEN    = 8;
    static const uint64_t OFFSET_EXPIRE_DEFAULT = 30 * 60000;

    class OcspHelper
    {
    public:
        struct SingleResponseInfo {
            CertStatus  certStatus;
            uint64_t    msThisUpdate;
            uint64_t    msNextUpdate;
            uint64_t    msRevocationTime;
            CrlReason   revocationReason;

            SingleResponseInfo (void)
                : certStatus(CertStatus::UNDEFINED)
                , msThisUpdate(0)
                , msNextUpdate(0)
                , msRevocationTime(0)
                , revocationReason(CrlReason::UNDEFINED)
            {}

        };  //  end struct SingleResponseInfo

    private:
        std::vector<SingleResponseInfo>
                    m_SingleResponseInfos;
        OCSPRequest_t*
                    m_OcspRequest;
        BasicOCSPResponse_t*
                    m_BasicOcspResp;
        ByteArray*  m_BaBasicOcspResponse;
        ByteArray*  m_BaNonce;
        ByteArray*  m_BaRequestEncoded;
        ByteArray*  m_BaTbsRequestEncoded;
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
            const Cert::CerItem* cerIssuer,
            const Cert::CerItem* cerSubject
        );
        int addCertId (
            const UapkiNS::AlgorithmIdentifier& hashAlgorithm,
            const ByteArray* baIssuerNameHash,
            const ByteArray* baIssuerKeyHash,
            const ByteArray* baSerialNumber
        );
        int addIssuerAndSN (
            const Cert::CerItem* cerIssuer,
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

        int parseBasicOcspResponse (
            const ByteArray* baEncoded
        );
        int parseResponse (
            const ByteArray* baEncoded
        );
        int checkNonce (void);
        ByteArray* getBasicOcspResponseEncoded (
            const bool move = false
        );
        int getCerts (
            std::vector<ByteArray*>& certs
        );
        int getOcspIdentifier (     //  Note: used for complete-revocation-references Attribute (rfc5126, $6.2.2)
            ByteArray** baOcspIdentifier
        );
        const SingleResponseInfo& getSingleResponseInfo (
            const size_t index
        ) const;
        int getResponderId (
            ResponderIdType &responderIdType,
            ByteArray** baResponderId
        );
        int getSerialNumberFromCertId (
            const size_t index,
            ByteArray** baSerialNumber
        );
        int scanSingleResponses (void);
        int verifyTbsResponseData (
            const Cert::CerItem* cerResponder,
            SignatureVerifyStatus& statusSign
        );

    public:
        const size_t countSingleResponses (void) const {
            return m_SingleResponseInfos.size();
        };
        const ByteArray* getNonce (void) const {
            return m_BaNonce;
        }
        uint64_t getProducedAt (void) const {
            return m_ProducedAt;
        }
        ResponseStatus getResponseStatus (void) const {
            return m_ResponseStatus;
        }
        const ByteArray* getTbsRequestEncoded (void) const {
            return m_BaTbsRequestEncoded;
        }
        const ByteArray* getTbsResponseData (void) const {
            return m_BaTbsResponseData;
        }

    public:
        int addNonceToExtension (void);
        int parseOcspResponse (
            const ByteArray* baEncoded
        );

    };  //  end class OcspHelper

    struct ResponseInfo {
        ResponseStatus
                    responseStatus;
        ResponderIdType
                    responderIdType;
        SmartBA     baResponderId;
        uint64_t    msProducedAt;
        OcspHelper::SingleResponseInfo
                    singleResponseInfo;
        SignatureVerifyStatus
                    statusSignature;
        Cert::CerItem*
                    cerResponder;

        ResponseInfo (void)
        : responseStatus(ResponseStatus::UNDEFINED)
        , responderIdType(ResponderIdType::UNDEFINED)
        , msProducedAt(0)
        , statusSignature(SignatureVerifyStatus::UNDEFINED)
        , cerResponder(nullptr)
        {}

    };  //  end struct ResponseInfo

    int generateOtherHash (
        const ByteArray* baOcspResponseEncoded,
        const UapkiNS::AlgorithmIdentifier& aidHash,
        ByteArray** baEncoded
    );

    const char* responseStatusToStr (
        const ResponseStatus status
    );


}   //  end namespace Ocsp

}   //  end namespace UapkiNS

#endif
