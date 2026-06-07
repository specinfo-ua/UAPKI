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

#ifndef DOC_SIGN_H
#define DOC_SIGN_H

#include "archive-timestamp-helper.h"
#include "attribute-helper.h"
#include "cert-validator.h"
#include "content-hasher.h"
#include "library-config.h"
#include "signature-format.h"
#include "signeddata-helper.h"
#include "tsp-helper.h"
#include "uapki-ns.h"


namespace UapkiNS {

namespace Doc {

namespace Sign {


static const size_t MAX_COUNT_DOCS = 100;
static const size_t MAX_TIMESTAMPS = 3;

enum class TsAttr : uint32_t {
    CONTENT_TIMESTAMP   = 0,
    TIMESTAMP_TOKEN     = 1,
    ARCHIVE_TIMESTAMP   = 2
};  //  end enum TsAttr

struct Options {
    bool ignoreCertStatus;

    Options (void)
        : ignoreCertStatus(false)
    {
    }

};  //  end struct Options

struct Params {
    SignatureFormat
                signatureFormat;
    AlgorithmIdentifier
                aidSignature;
    AlgorithmIdentifier
                aidDigest;      //  For digest-message, tsp, ess-cert; by default use digestAlgo from signAlgo
    bool        detachedData;
    HashAlg     hashDigest;
    HashAlg     hashSignature;
    bool        includeCert;
    bool        includeTime;
    bool        includeContentTS;
    bool        includeSignatureTS;
    bool        isCadesCXA;
    bool        isCadesFormat;
    bool        sidUseKeyId;

    Params (void)
        : signatureFormat(SignatureFormat::UNDEFINED)
        , detachedData(true)
        , hashDigest(HashAlg::HASH_ALG_UNDEFINED)
        , hashSignature(HashAlg::HASH_ALG_UNDEFINED)
        , includeCert(false)
        , includeTime(false)
        , includeContentTS(false)
        , includeSignatureTS(false)
        , isCadesCXA(false)
        , isCadesFormat(false)
        , sidUseKeyId(false)
    {
    }

};  //  end struct Params

struct SharedData : Params {
    Options     options;
    CertValidator::CertValidator
                certValidator;
    Cert::CerItem*
                cerSigner;
    SmartBA     keyId;
    LibraryConfig::OcspParams
                ocsp;
    LibraryConfig::TspParams
                tsp;
    SmartBA     encodedSigningCert;
    SmartBA     encodedSignPolicy;

    SharedData (void);

    int encodeSignaturePolicy (
        const std::string& sigPolicyiId
    );
    int encodeSigningCertificate (void);
    int paramsBySignatureFormat (void);
    int setupTsp (
        const LibraryConfig::TspParams& tspParams
    );

};  //  end struct SharedData

class SigningDoc {
public:
    SharedData*
                sharedData;
    Pkcs7::SignedDataBuilder
                builder;
    CertValidator::CertValidator
                certValidatorTs[MAX_TIMESTAMPS];
    Pkcs7::SignedDataBuilder::SignerInfo*
                signerInfo;
    std::string id;
    bool        isDigest;
    ContentHasher
                contentHasher;
    std::string contentType;
    SmartBA     messageDigest;
    uint64_t    signingTime;
    SmartBA     hashSignedAttrs;
    SmartBA     signature;
    std::string tspUri;
    uint64_t    contentTimeStamp;
    uint64_t    signatureTimeStamp;
    uint64_t    archiveTimeStamp;

private:
    Pkcs7::ArchiveTs3Helper
                m_ArchiveTsHelper;
    std::vector<Attribute*>
                m_SignedAttrs;
    std::vector<Attribute*>
                m_UnsignedAttrs;

public:
    SigningDoc (void);
    ~SigningDoc (void);

    int init (
        SharedData* iSharedData
    );
    int addArchiveAttribute (
        const std::string& type,
        const ByteArray* baValues
    );
    int addSignedAttribute (
        const std::string& type,
        const ByteArray* baValues
    );
    int addTimestamp (
        const TsAttr tsAttr
    );
    int addUnsignedAttribute (
        const std::string& type,
        const ByteArray* baValues
    );
    int buildSignedAttributes (void);
    int buildSignedData (void);
    int buildUnsignedAttributes (void);
    int digestMessage (void);
    int digestSignature (
        ByteArray** baHash
    );
    int digestSignedAttributes (void);
    int getTimestamp (
        CertValidator::CertValidator& certValidator,
        Tsp::TspHelper& tspHelper
    );
    int importSignedAttributes (
        const ByteArray* baEncoded
    );
    int setSignature (
        const ByteArray* baSignValue
    );
    int setupSignerIdentifier (void);

    ByteArray* getEncoded (void);

    int collectExpectedItems (
        CertValidator::CertValidator& certValidator
    ) const;

    const ByteArray* getAtsHash (void) const {
        return m_ArchiveTsHelper.getHashValue();
    }

private:
    std::vector<CertValidator::CertChainItem*> collectCerts (void) const;
    int encodeCertValues (
        const std::vector<CertValidator::CertChainItem*>& certs,
        ByteArray** baEncoded
    );
    int encodeCertificateRefs (
        const std::vector<CertValidator::CertChainItem*>& certs,
        ByteArray** baEncoded
    );
    int encodeRevocationRefs (
        const std::vector<CertValidator::CertChainItem*>& certs,
        ByteArray** baEncoded
    );
    int encodeRevocationValues (    //  Note: supported OCSP-responses only
        const std::vector<CertValidator::CertChainItem*>& certs,
        ByteArray** baEncoded
    );

};  //  end class SigningDoc

int verifySignedData (
        CertValidator::CertValidator& certValidator,
        const ByteArray* baEncoded,
        Cert::CerItem** cerSigner
);


}   //  end namespace Sign

}   //  end namespace Doc

}   //  end namespace UapkiNS


#endif
