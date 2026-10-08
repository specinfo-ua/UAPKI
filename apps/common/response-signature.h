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

//  Перевірка підпису відповіді TSP/OCSP. Чинність сертифіката підписувача не перевіряється

#ifndef RESPONSE_SIGNATURE_H
#define RESPONSE_SIGNATURE_H


#include <functional>
#include <string>
#include "uapki-ns.h"
#include "signeddata-helper.h"


namespace ResponseSignature {

enum class SignerIdType {
    UNDEFINED,
    ISSUER_AND_SN,  //  value: IssuerAndSerialNumber, DER
    KEY_ID,         //  value: ідентифікатор ключа
    NAME            //  value: Name, DER
};

struct SignerId {
    SignerIdType
                type = SignerIdType::UNDEFINED;
    UapkiNS::SmartBA
                value;
};

//  SID підписувача CMS (повний TLV)
int signerIdFromSid (
    const ByteArray* baSidEncoded,
    SignerId& signerId
);

//  Перевіряє підпис ключем, що приходить у SPKI підписувача
using VerifyFunc = std::function<int(const ByteArray* baSpki)>;

//  Шукає сертифікат підписувача у відповіді, а якщо там нема — у responderCertFile,
//  і перевіряє підпис. Хід перевірки дописує в report.
//  RET_OK лише для дійсного підпису
int verify (
    const UapkiNS::VectorBA& responseCerts,
    const std::string& responderCertFile,
    const SignerId& signerId,
    const std::string& signAlgo,
    const VerifyFunc& verifyFunc,
    std::string& report
);

//  Підпис SignerInfo: messageDigest = hash(encapContent), підпис над signedAttrs
int verifySignerInfo (
    const UapkiNS::Pkcs7::SignedDataParser::SignerInfo& signerInfo,
    const ByteArray* baEncapContent,
    const ByteArray* baSpki
);

}   //  end namespace ResponseSignature


#endif
