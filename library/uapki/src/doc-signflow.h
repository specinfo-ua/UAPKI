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

#ifndef DOC_SIGNFLOW_H
#define DOC_SIGNFLOW_H

#include "uapkic.h"
#include "uapkif.h"
#include "cer-store.h"
#include "ocsp-helper.h"
#include "signature-format.h"
#include "signeddata-helper.h"
#include "uapki-ns.h"
#include <string>
#include <vector>


class SigningDoc {
public:
    struct OcspResponseItem {
        ByteArray*  baBasicOcspResponse;
        ByteArray*  baOcspIdentifier;
        ByteArray*  baOcspRespHash;

        OcspResponseItem (void);
        ~OcspResponseItem (void);

    };  //  end struct OcspResponseItem

    struct SignParams {
        UapkiNS::SignatureFormat
                    signatureFormat;
        HashAlg     hashDigest;
        HashAlg     hashSignature;
        UapkiNS::AlgorithmIdentifier
                    aidDigest;      //  For digest-message, tsp, ess-cert; by default use digestAlgo from signAlgo
        UapkiNS::AlgorithmIdentifier
                    aidSignature;
        CerStore::Item*
                    cerStoreItem;   //  ref
        ByteArray*  baKeyId;
        bool        detachedData;
        bool        includeCert;
        bool        includeTime;
        bool        includeContentTS;
        bool        includeSignatureTS;
        bool        sidUseKeyId;
        UapkiNS::Attribute
                    attrSigningCert;
        UapkiNS::Attribute
                    attrSignPolicy;
        UapkiNS::Attribute
                    attrCertificateRefs;
        UapkiNS::Attribute
                    attrRevocationRefs;
        UapkiNS::Attribute
                    attrCertValues;
        UapkiNS::Attribute
                    attrRevocationValues;
        std::vector<std::string>
                    tspUris;
        const char* tspPolicy;

        SignParams (void);
        ~SignParams (void);

        int setSignatureFormat (const UapkiNS::SignatureFormat signatureFormat);

    };  //  end struct SignParams

    class CadesBuilder {
        CerStore*   m_CerStore;
        SignParams  m_SignParams;
        bool        m_IsCadesFormat;
        std::vector<CerStore::Item*>
                    m_ChainCerts;
        std::vector<UapkiNS::EssCertId>
                    m_EssCertids;
        vector<OcspResponseItem*>
                    m_OcspResponseItems;

    public:
        CadesBuilder (CerStore* iCerStore);
        ~CadesBuilder (void);

        CerStore* getCerStore (void) { return m_CerStore; }
        std::vector<CerStore::Item*>& getChainCerts (void) { return m_ChainCerts; }
        SignParams& getSignParams (void) { return m_SignParams; }
        bool isCadesFormat (void) const { return m_IsCadesFormat; }

        int init (void);
        int buildChainCerts (void);
        OcspResponseItem* addOcspResponseItem (void);
        int process (void);

    private:
        int encodeCertValues (UapkiNS::Attribute& attr);
        int encodeCertificateRefs (UapkiNS::Attribute& attr);
        int encodeRevocationRefs (UapkiNS::Attribute& attr);
        int encodeRevocationValues (UapkiNS::Attribute& attr);
        int encodeSigningCertificate (UapkiNS::Attribute& attr);

    };  //  end class CadesBuilder

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
    std::vector<UapkiNS::Attribute*>
                m_SignedAttrs;
    std::vector<UapkiNS::Attribute*>
                m_UnsignedAttrs;

public:
    SigningDoc (void);
    ~SigningDoc (void);

    int init (const SignParams* signParams);
    int addSignedAttribute (const std::string& type, ByteArray* baValues);
    int addUnsignedAttribute (const std::string& type, ByteArray* baValues);
    int buildSignedAttributes (void);
    int buildSignedData (void);
    int digestMessage (void);
    int digestSignature (ByteArray** baHash);
    int digestSignedAttributes (void);
    int setSignature (const ByteArray* baSignValue);

    ByteArray* getEncoded (void);

};  //  end class SigningDoc


#endif
