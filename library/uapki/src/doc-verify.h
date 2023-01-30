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

#ifndef DOC_VERIFY_H
#define DOC_VERIFY_H

#include "archive-timestamp-helper.h"
#include "cer-store.h"
#include "crl-store.h"
#include "signature-format.h"
#include "signeddata-helper.h"
#include "uapki-ns.h"
#include "verify-status.h"


namespace UapkiNS {

namespace Doc {

namespace Verify {


struct AttrTimeStamp {
    std::string policy;
    std::string hashAlgo;
    SmartBA     hashedMessage;
    uint64_t    msGenTime;
    CerStore::Item*
                signerCertId;
    SIGNATURE_VERIFY::STATUS
                statusDigest;
    SIGNATURE_VERIFY::STATUS
                statusSignature;

    AttrTimeStamp (void);
    ~AttrTimeStamp (void);

    bool isPresent (void) const;
    int  verifyDigest (const ByteArray* baData);

};  //  end struct AttrTimeStamp

class VerifiedSignerInfo {
    CerStore*   m_CerStore;
    Pkcs7::SignedDataParser::SignerInfo
                m_SignerInfo;
    CerStore::Item*
                m_CerStoreItem;
    SIGNATURE_VERIFY::STATUS
                m_StatusSignature;
    SIGNATURE_VERIFY::STATUS
                m_StatusMessageDigest;
    bool        m_IsDigest;
    uint64_t    m_SigningTime;
    SignatureFormat
                m_SignatureFormat;
    std::vector<EssCertId>
                m_EssCerts;
    SIGNATURE_VERIFY::STATUS
                m_StatusEssCert;
    std::string m_SigPolicyId;
    AttrTimeStamp
                m_ContentTS;
    AttrTimeStamp
                m_SignatureTS;
    AttrTimeStamp
                m_ArchiveTS;
    Pkcs7::ArchiveTs3Helper
                m_ArchiveTsHelper;

public:
    VerifiedSignerInfo (void);
    ~VerifiedSignerInfo (void);

    int init (
        CerStore* iCerStore,
        const bool isDigest
    );
    int verifyArchiveTS (
        std::vector<const CerStore::Item*>& certs,
        std::vector<const CrlStore::Item*>& crls
    );
    int verifySignerInfo (
        const ByteArray* baContent
    );

public:
    const AttrTimeStamp& getArchiveTS (void) const {
        return m_ArchiveTS;
    }
    CerStore* getCerStore (void) const {
        return m_CerStore;
    }
    const AttrTimeStamp& getContentTS (void) const {
        return m_ContentTS;
    }
    const std::string& getSigPolicyId (void) const {
        return m_SigPolicyId;
    }
    SignatureFormat getSignatureFormat (void) const {
        return m_SignatureFormat;
    }
    const AttrTimeStamp& getSignatureTS (void) const {
        return m_SignatureTS;
    }
    const ByteArray* getSignerCertId (void) const {
        return (m_CerStoreItem) ? m_CerStoreItem->baCertId : nullptr;
    }
    Pkcs7::SignedDataParser::SignerInfo& getSignerInfo (void) {
        return m_SignerInfo;
    }
    uint64_t getSigningTime (void) const {
        return m_SigningTime;
    }
    SIGNATURE_VERIFY::STATUS getStatusEssCert (void) const {
        return m_StatusEssCert;
    }
    SIGNATURE_VERIFY::STATUS getStatusMessageDigest (void) const {
        return m_StatusMessageDigest;
    }
    SIGNATURE_VERIFY::STATUS getStatusSignature (void) const {
        return m_StatusSignature;
    }

private:
    int decodeSignedAttrs (
        const std::vector<Attribute>& signedAattrs
    );
    int decodeUnsignedAttrs (
        const std::vector<Attribute>& unsignedAttrs
    );
    int verifySigningCertificateV2 (void);

};  //  end class VerifiedSignerInfo


int decodeAttrTimestamp (
    const ByteArray* baValues,
    AttrTimeStamp& attrTS
);

int verifySignedData (
    CerStore& cerStore,
    Pkcs7::SignedDataParser& sdataParser,
    CerStore::Item** cerSigner
);


}   //  end namespace Verify

}   //  end namespace Doc

}   //  end namespace UapkiNS


#endif
