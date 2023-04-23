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

#ifndef UAPKI_NS_TSP_HELPER_H
#define UAPKI_NS_TSP_HELPER_H


#include <string>
#include "byte-array.h"
#include "signeddata-helper.h"
#include "uapki-ns.h"
#include "uapkif.h"


namespace UapkiNS {

namespace Tsp {

    static const size_t NONCE_MAXLEN    = 32;
    static const size_t NONCE_MINLEN    = 4;

    enum class PkiStatus : int32_t {
        UNDEFINED               = -1,
        GRANTED                 = 0 ,
        GRANTED_WITHMODS        = 1,
        REJECTION               = 2,
        WAITING                 = 3,
        REVOCATION_WARNING      = 4,
        REVOCATION_NOTIFICATION = 5
    };  //  end enum PkiStatus

    class TspHelper
    {
        TimeStampReq_t*
                    m_TspRequest;
        TSTInfo_t*  m_TstInfo;
        ByteArray*  m_BaNonce;
        ByteArray*  m_BaEncoded;
        PkiStatus   m_Status;
        ByteArray*  m_BaTsToken;

    public:
        TspHelper (void);
        ~TspHelper (void);

        void reset (void);

        int init (void);
        int genNonce (
            const size_t nonceLen
        );
        int setCertReq (
            const bool certReq
        );
        int setMessageImprint (
            const UapkiNS::AlgorithmIdentifier& aidHashAlgo,
            const ByteArray* baHashedMessage
        );
        int setNonce (
            const ByteArray* baNonce
        );
        int setReqPolicy (
            const std::string& reqPolicy
        );

        int encodeRequest (void);
        ByteArray* getRequestEncoded (
            const bool move = false
        );

        int parseResponse (
            const ByteArray* baEncoded
        );
        ByteArray* getTsToken (
            const bool move = false
        );
        int tstInfoIsEqualRequest (void);

        PkiStatus getStatus (void) const { return m_Status; }

    };  //  end class TspHelper

    class TsTokenParser
    {
        UapkiNS::Pkcs7::SignedDataParser
                    m_SignedDataParser;
        ByteArray*  m_BaHashedMessage;
        uint64_t    m_GenTime;
        std::string m_HashAlgo;
        std::string m_PolicyId;

    public:
        TsTokenParser (void);
        ~TsTokenParser (void);

        int parse (
            const ByteArray* baEncoded
        );
        ByteArray* getHashedMessage (
            const bool move = false
        );

        uint64_t getGenTime (void) const {
            return m_GenTime;
        }
        const std::string& getHashAlgo (void) const {
            return m_HashAlgo;
        }
        const std::string& getPolicyId (void) const {
            return m_PolicyId;
        }
        UapkiNS::Pkcs7::SignedDataParser& getSignedDataParser (void) {
            return m_SignedDataParser;
        }

    };  //  end class TsTokenParser


}   //  end namespace Tsp

}   //  end namespace UapkiNS

#endif
