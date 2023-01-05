/*
 * Copyright (c) 2023, The UAPKI Project Authors.
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

#ifndef DOC_SIGNFLOW_H
#define DOC_SIGNFLOW_H

#include "cer-store.h"
#include "library-config.h"
#include "ocsp-helper.h"
#include "signature-format.h"
#include "signeddata-helper.h"
#include "uapki-ns.h"


class SigningDoc {
public:
    static const size_t MAX_COUNT_DOCS  = 100;

    struct OcspResponseItem {
        ByteArray*  baBasicOcspResponse;
        ByteArray*  baOcspIdentifier;
        ByteArray*  baOcspRespHash;
        CerStore::Item*
                    cerResponder;   //  ref

        OcspResponseItem (void);
        ~OcspResponseItem (void);

        int set (const OcspResponseItem& src);

    };  //  end struct OcspResponseItem

    struct SignParams {
        UapkiNS::SignatureFormat
                    signatureFormat;
        bool        isCadesCXA;
        bool        isCadesFormat;
        HashAlg     hashDigest;
        HashAlg     hashSignature;
        UapkiNS::AlgorithmIdentifier
                    aidDigest;      //  For digest-message, tsp, ess-cert; by default use digestAlgo from signAlgo
        UapkiNS::AlgorithmIdentifier
                    aidSignature;
        CerStore::Item*
                    cerSigner;      //  ref
        ByteArray*  baKeyId;
        bool        detachedData;
        bool        includeCert;
        bool        includeTime;
        bool        includeContentTS;
        bool        includeSignatureTS;
        bool        sidUseKeyId;
        LibraryConfig::TspParams
                    tsp;
        UapkiNS::Attribute
                    attrSigningCert;
        UapkiNS::Attribute
                    attrSignPolicy;
        std::vector<CerStore::Item*>
                    chainCerts;     //  refs[] - chain certs for user certificate and OCSP-cert
        std::vector<OcspResponseItem*>
                    ocspRespItems;  //  All responses for user-cert and chain of user-cert

        SignParams (void);
        ~SignParams (void);

        bool addCert (
            CerStore::Item* cerStoreItem
        );
        void addOcspResponseItem (
            OcspResponseItem* ocspRespItem
        );
        int setSignatureFormat (
            const UapkiNS::SignatureFormat signatureFormat
        );

    };  //  end struct SignParams

    const SignParams*
                signParams;     //  ref
    UapkiNS::Pkcs7::SignedDataBuilder
                builder;
    UapkiNS::Pkcs7::SignedDataBuilder::SignerInfo*
                signerInfo;
    std::string id;
    std::string contentType;
    bool        isDigest;
    ByteArray*  baData;
    ByteArray*  baMessageDigest;
    ByteArray*  baHashSignedAttrs;
    ByteArray*  baSignature;
    std::string tspUri;

private:
    UapkiNS::Attribute
                m_AttrCertificateRefs;
    UapkiNS::Attribute
                m_AttrRevocationRefs;
    UapkiNS::Attribute
                m_AttrCertValues;
    UapkiNS::Attribute
                m_AttrRevocationValues;
    std::vector<CerStore::Item*>
                m_Certs;
    std::vector<OcspResponseItem*>
                m_OcspRespItems;
    std::vector<UapkiNS::Attribute*>
                m_SignedAttrs;
    std::vector<UapkiNS::Attribute*>
                m_UnsignedAttrs;

public:
    SigningDoc (void);
    ~SigningDoc (void);

    int init (
        const SignParams* signParams
    );
    void addCert (
        CerStore::Item* cerStoreItem
    );
    void addOcspResponseItem (
        OcspResponseItem* ocspRespItem
    );
    int addSignedAttribute (
        const std::string& type,
        ByteArray* baValues
    );
    int addUnsignedAttribute (
        const std::string& type,
        ByteArray* baValues
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

    ByteArray* getEncoded (void);

    std::vector<CerStore::Item*> getCerts (void) { return m_Certs; }

public:
    static int encodeSignaturePolicy (
        const std::string& sigPolicyiId,
        UapkiNS::Attribute& attr
    );
    static int encodeSigningCertificate (
        const UapkiNS::EssCertId& essCertId,
        UapkiNS::Attribute& attr
    );

private:
    int encodeCertValues (
        UapkiNS::Attribute& attr
    );
    int encodeCertificateRefs (
        UapkiNS::Attribute& attr
    );
    int encodeRevocationRefs (
        UapkiNS::Attribute& attr
    );
    int encodeRevocationValues (
        UapkiNS::Attribute& attr
    );

};  //  end class SigningDoc


#endif
