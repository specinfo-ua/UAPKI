/*
 * Copyright 2026 The UAPKI Project Authors.
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

// Local UAPKI patch: the generated asn1c aliases used to overwrite global
// descriptors on first encode/decode/free. A decoder could see the new function
// pointer before the SEQUENCE metadata, even when sessions were independent.
// Complete all aliases before any caller can dispatch through a descriptor.
#include "asn_application.h"
#include "uapkic-errors.h"
#include <mutex>

extern "C" {
extern asn_TYPE_descriptor_t ObjectDigestInfo_desc;
extern asn_TYPE_descriptor_t ANY_desc;
extern asn_TYPE_descriptor_t AlgorithmIdentifier_desc;
extern asn_TYPE_descriptor_t AttCertVersion_desc;
extern asn_TYPE_descriptor_t AttCertVersionV1_desc;
extern asn_TYPE_descriptor_t AttributeCertificate_desc;
extern asn_TYPE_descriptor_t AttributeCertificateV2_desc;
extern asn_TYPE_descriptor_t AttributeType_desc;
extern asn_TYPE_descriptor_t AttributeTypeAndValue_desc;
extern asn_TYPE_descriptor_t AttributeValue_desc;
extern asn_TYPE_descriptor_t AttributeValueAssertion_desc;
extern asn_TYPE_descriptor_t Attributes_desc;
extern asn_TYPE_descriptor_t BIT_STRING_desc;
extern asn_TYPE_descriptor_t CMSVersion_desc;
extern asn_TYPE_descriptor_t CRLDistributionPoints_desc;
extern asn_TYPE_descriptor_t CRLNumber_desc;
extern asn_TYPE_descriptor_t CRLReason_desc;
extern asn_TYPE_descriptor_t CertPolicyId_desc;
extern asn_TYPE_descriptor_t CertificateSerialNumber_desc;
extern asn_TYPE_descriptor_t ContentEncryptionAlgorithmIdentifier_desc;
extern asn_TYPE_descriptor_t ContentInfo_desc;
extern asn_TYPE_descriptor_t ContentType_desc;
extern asn_TYPE_descriptor_t Digest_desc;
extern asn_TYPE_descriptor_t DigestAlgorithmIdentifier_desc;
extern asn_TYPE_descriptor_t ENUMERATED_desc;
extern asn_TYPE_descriptor_t EncryptedContent_desc;
extern asn_TYPE_descriptor_t EncryptedKey_desc;
extern asn_TYPE_descriptor_t EncryptedPrivateKeyInfo_desc;
extern asn_TYPE_descriptor_t FreshestCRL_desc;
extern asn_TYPE_descriptor_t GeneralNames_desc;
extern asn_TYPE_descriptor_t Hash_desc;
extern asn_TYPE_descriptor_t INTEGER_desc;
extern asn_TYPE_descriptor_t IssuerAltName_desc;
extern asn_TYPE_descriptor_t KeyBag_desc;
extern asn_TYPE_descriptor_t KeyDerivationAlgorithmIdentifier_desc;
extern asn_TYPE_descriptor_t KeyEncryptionAlgorithmIdentifier_desc;
extern asn_TYPE_descriptor_t KeyHash_desc;
extern asn_TYPE_descriptor_t KeyIdentifier_desc;
extern asn_TYPE_descriptor_t KeyPurposeId_desc;
extern asn_TYPE_descriptor_t KeyUsage_desc;
extern asn_TYPE_descriptor_t MessageAuthenticationCodeAlgorithm_desc;
extern asn_TYPE_descriptor_t MonetaryValue_desc;
extern asn_TYPE_descriptor_t NULL_desc;
extern asn_TYPE_descriptor_t NetworkAddress_desc;
extern asn_TYPE_descriptor_t NumericString_desc;
extern asn_TYPE_descriptor_t NumericUserIdentifier_desc;
extern asn_TYPE_descriptor_t OBJECT_IDENTIFIER_desc;
extern asn_TYPE_descriptor_t OCSPResponseStatus_desc;
extern asn_TYPE_descriptor_t OCTET_STRING_desc;
extern asn_TYPE_descriptor_t OrganizationName_desc;
extern asn_TYPE_descriptor_t OrganizationalUnitName_desc;
extern asn_TYPE_descriptor_t OtherHashAlgAndValue_desc;
extern asn_TYPE_descriptor_t OtherHashValue_desc;
extern asn_TYPE_descriptor_t OtherRevRefType_desc;
extern asn_TYPE_descriptor_t OtherRevValType_desc;
extern asn_TYPE_descriptor_t PKCS8ShroudedKeyBag_desc;
extern asn_TYPE_descriptor_t PKIFailureInfo_desc;
extern asn_TYPE_descriptor_t PKIStatus_desc;
extern asn_TYPE_descriptor_t PolicyQualifierId_desc;
extern asn_TYPE_descriptor_t PrintableString_desc;
extern asn_TYPE_descriptor_t PrivateKeyInfo_desc;
extern asn_TYPE_descriptor_t QcEuLimitValue_desc;
extern asn_TYPE_descriptor_t ReasonFlags_desc;
extern asn_TYPE_descriptor_t SigPolicyHash_desc;
extern asn_TYPE_descriptor_t SigPolicyId_desc;
extern asn_TYPE_descriptor_t SigPolicyQualifierId_desc;
extern asn_TYPE_descriptor_t SignatureAlgorithmIdentifier_desc;
extern asn_TYPE_descriptor_t SignedAttributes_desc;
extern asn_TYPE_descriptor_t SubjectAltName_desc;
extern asn_TYPE_descriptor_t SubjectKeyIdentifier_desc;
extern asn_TYPE_descriptor_t TSAPolicyId_desc;
extern asn_TYPE_descriptor_t TSVersion_desc;
extern asn_TYPE_descriptor_t TerminalIdentifier_desc;
extern asn_TYPE_descriptor_t TimeStampToken_desc;
extern asn_TYPE_descriptor_t UnauthAttributes_desc;
extern asn_TYPE_descriptor_t UniqueIdentifier_desc;
extern asn_TYPE_descriptor_t UnknownInfo_desc;
extern asn_TYPE_descriptor_t UnprotectedAttributes_desc;
extern asn_TYPE_descriptor_t UnsignedAttributes_desc;
extern asn_TYPE_descriptor_t UserKeyingMaterial_desc;
extern asn_TYPE_descriptor_t Version_desc;
extern asn_TYPE_descriptor_t X121Address_desc;
}

namespace {
void inherit(asn_TYPE_descriptor_t& td, const asn_TYPE_descriptor_t& base) {
    td.free_struct = base.free_struct;
    td.print_struct = base.print_struct;
    td.check_constraints = base.check_constraints;
    td.ber_decoder = base.ber_decoder;
    td.der_encoder = base.der_encoder;
    td.xer_decoder = base.xer_decoder;
    td.xer_encoder = base.xer_encoder;
    td.uper_decoder = base.uper_decoder;
    td.uper_encoder = base.uper_encoder;
    if (!td.per_constraints) td.per_constraints = base.per_constraints;
    td.elements = base.elements;
    td.elements_count = base.elements_count;
    td.specifics = base.specifics;
}
}

namespace {
void init_descriptors(void) {
    static std::once_flag once;
    std::call_once(once, [] {
        inherit(AttCertVersion_desc, INTEGER_desc);
        inherit(AttCertVersionV1_desc, INTEGER_desc);
        inherit(AttributeCertificateV2_desc, AttributeCertificate_desc);
        inherit(AttributeType_desc, OBJECT_IDENTIFIER_desc);
        inherit(AttributeValue_desc, ANY_desc);
        inherit(AttributeValueAssertion_desc, AttributeTypeAndValue_desc);
        inherit(CMSVersion_desc, INTEGER_desc);
        inherit(CRLNumber_desc, INTEGER_desc);
        inherit(CRLReason_desc, ENUMERATED_desc);
        inherit(CertPolicyId_desc, OBJECT_IDENTIFIER_desc);
        inherit(CertificateSerialNumber_desc, INTEGER_desc);
        inherit(ContentEncryptionAlgorithmIdentifier_desc, AlgorithmIdentifier_desc);
        inherit(ContentType_desc, OBJECT_IDENTIFIER_desc);
        inherit(Digest_desc, OCTET_STRING_desc);
        inherit(DigestAlgorithmIdentifier_desc, AlgorithmIdentifier_desc);
        inherit(EncryptedContent_desc, OCTET_STRING_desc);
        inherit(EncryptedKey_desc, OCTET_STRING_desc);
        inherit(FreshestCRL_desc, CRLDistributionPoints_desc);
        inherit(Hash_desc, OCTET_STRING_desc);
        inherit(IssuerAltName_desc, GeneralNames_desc);
        inherit(KeyBag_desc, PrivateKeyInfo_desc);
        inherit(KeyDerivationAlgorithmIdentifier_desc, AlgorithmIdentifier_desc);
        inherit(KeyEncryptionAlgorithmIdentifier_desc, AlgorithmIdentifier_desc);
        inherit(KeyHash_desc, OCTET_STRING_desc);
        inherit(KeyIdentifier_desc, OCTET_STRING_desc);
        inherit(KeyPurposeId_desc, OBJECT_IDENTIFIER_desc);
        inherit(KeyUsage_desc, BIT_STRING_desc);
        inherit(MessageAuthenticationCodeAlgorithm_desc, AlgorithmIdentifier_desc);
        inherit(X121Address_desc, NumericString_desc);
        inherit(NetworkAddress_desc, X121Address_desc);
        inherit(NumericUserIdentifier_desc, NumericString_desc);
        inherit(OCSPResponseStatus_desc, ENUMERATED_desc);
        inherit(OrganizationName_desc, PrintableString_desc);
        inherit(OrganizationalUnitName_desc, PrintableString_desc);
        inherit(OtherHashValue_desc, OCTET_STRING_desc);
        inherit(OtherRevRefType_desc, OBJECT_IDENTIFIER_desc);
        inherit(OtherRevValType_desc, OBJECT_IDENTIFIER_desc);
        inherit(PKCS8ShroudedKeyBag_desc, EncryptedPrivateKeyInfo_desc);
        inherit(PKIFailureInfo_desc, BIT_STRING_desc);
        inherit(PKIStatus_desc, INTEGER_desc);
        inherit(PolicyQualifierId_desc, OBJECT_IDENTIFIER_desc);
        inherit(QcEuLimitValue_desc, MonetaryValue_desc);
        inherit(ReasonFlags_desc, BIT_STRING_desc);
        inherit(SigPolicyHash_desc, OtherHashAlgAndValue_desc);
        inherit(SigPolicyId_desc, OBJECT_IDENTIFIER_desc);
        inherit(SigPolicyQualifierId_desc, OBJECT_IDENTIFIER_desc);
        inherit(SignatureAlgorithmIdentifier_desc, AlgorithmIdentifier_desc);
        inherit(SignedAttributes_desc, Attributes_desc);
        inherit(SubjectAltName_desc, GeneralNames_desc);
        inherit(SubjectKeyIdentifier_desc, OCTET_STRING_desc);
        inherit(TSAPolicyId_desc, OBJECT_IDENTIFIER_desc);
        inherit(TSVersion_desc, INTEGER_desc);
        inherit(TerminalIdentifier_desc, PrintableString_desc);
        inherit(TimeStampToken_desc, ContentInfo_desc);
        inherit(UnauthAttributes_desc, Attributes_desc);
        inherit(UniqueIdentifier_desc, BIT_STRING_desc);
        inherit(UnknownInfo_desc, NULL_desc);
        inherit(UnprotectedAttributes_desc, Attributes_desc);
        inherit(UnsignedAttributes_desc, Attributes_desc);
        inherit(UserKeyingMaterial_desc, OCTET_STRING_desc);
        inherit(Version_desc, INTEGER_desc);
        // This generated ENUMERATED subtype is private to ObjectDigestInfo.c.
        // Retain its explicit enumeration map while replacing dispatch slots.
        auto& nested = *ObjectDigestInfo_desc.elements[0].type;
        const void* specifics = nested.specifics;
        inherit(nested, ENUMERATED_desc);
        nested.specifics = specifics;
    });
}
}

extern "C" int uapkif_init_asn1_descriptors(void) {
    try {
        init_descriptors();
    }
    catch (...) {
        //  std::call_once can throw only on system resource exhaustion
        return RET_MEMORY_ALLOC_ERROR;
    }
    return RET_OK;
}

// C++ static initializer runs at image load (MSVC, GCC, Clang), including native C/C++ embedding.
namespace {
struct Asn1DescriptorsInit {
    Asn1DescriptorsInit() {
        (void)uapkif_init_asn1_descriptors();
    }
} asn1_descriptors_init;
}
