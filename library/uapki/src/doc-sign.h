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
#include "cer-store.h"
#include "crl-store.h"
#include "library-config.h"
#include "signature-format.h"
#include "signeddata-helper.h"
#include "uapki-ns.h"


namespace UapkiNS {

namespace Doc {

namespace Sign {


class SigningDoc {
public:
    static const size_t MAX_COUNT_DOCS  = 100;

    struct CerDataItem {
        Cert::CerItem*
                    pCerSubject;
        Cert::CerItem*
                    pCerIssuer;
        bool        isSelfSigned;
        SmartBA     basicOcspResponse;
        SmartBA     ocspIdentifier;
        SmartBA     ocspRespHash;
        Crl::CrlItem*
                    pCrl;
        Cert::CerItem*
                    pCerResponder;

        CerDataItem (void);
        ~CerDataItem (void);

        int set (const CerDataItem& src);

    };  //  end struct CerDataItem

    struct SignParams {
        SignatureFormat
                    signatureFormat;
        bool        isCadesCXA;
        bool        isCadesFormat;
        HashAlg     hashDigest;
        HashAlg     hashSignature;
        AlgorithmIdentifier
                    aidDigest;      //  For digest-message, tsp, ess-cert; by default use digestAlgo from signAlgo
        AlgorithmIdentifier
                    aidSignature;
        CerDataItem signer;
        SmartBA     keyId;
        bool        detachedData;
        bool        includeCert;
        bool        includeTime;
        bool        includeContentTS;
        bool        includeSignatureTS;
        bool        sidUseKeyId;
        LibraryConfig::OcspParams
                    ocsp;
        LibraryConfig::TspParams
                    tsp;
        Attribute   attrSigningCert;
        Attribute   attrSignPolicy;
        std::vector<CerDataItem*>
                    chainCerts;

        SignParams (void);
        ~SignParams (void);

        int addCert (
            Cert::CerItem* cerItem
        );
        int setSignatureFormat (
            const SignatureFormat signatureFormat
        );

    };  //  end struct SignParams

    const SignParams*
                signParams;
    Pkcs7::SignedDataBuilder
                builder;
    Pkcs7::SignedDataBuilder::SignerInfo*
                signerInfo;
    std::string id;
    std::string contentType;
    bool        isDigest;
    SmartBA     data;
    SmartBA     messageDigest;
    SmartBA     hashSignedAttrs;
    SmartBA     signature;
    std::string tspUri;

private:
    Pkcs7::ArchiveTs3Helper
                m_ArchiveTsHelper;
    std::vector<CerDataItem*>
                m_Certs;
    std::vector<Attribute*>
                m_SignedAttrs;
    std::vector<Attribute*>
                m_UnsignedAttrs;

public:
    SigningDoc (void);
    ~SigningDoc (void);

    int init (
        const SignParams* iSignParams
    );
    int addCert (
        Cert::CerItem* cerItem
    );
    int addArchiveAttribute (
        const std::string& type,
        const ByteArray* baValues
    );
    int addSignedAttribute (
        const std::string& type,
        const ByteArray* baValues
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
    int setSignature (
        const ByteArray* baSignValue
    );
    int setupSignerIdentifier (void);

    ByteArray* getEncoded (void);

    std::vector<CerDataItem*> getCerts (void) {
        return m_Certs;
    }
    const ByteArray* getAtsHash (void) const {
        return m_ArchiveTsHelper.getHashValue();
    }

public:
    static int encodeSignaturePolicy (
        const std::string& sigPolicyiId,
        Attribute& attr
    );
    static int encodeSigningCertificate (
        const EssCertId& essCertId,
        Attribute& attr
    );

private:
    int encodeCertValues (
        Attribute& attr
    );
    int encodeCertificateRefs (
        Attribute& attr
    );
    int encodeRevocationRefs (
        Attribute& attr
    );
    int encodeRevocationValues (    //  Note: supported OCSP-responses only
        Attribute& attr
    );

};  //  end class SigningDoc


}   //  end namespace Sign

}   //  end namespace Doc

}   //  end namespace UapkiNS


#endif
