//  Last update: 2022-07-30

#ifndef UAPKI_NS_ATTRIBUTE_HELPER_H
#define UAPKI_NS_ATTRIBUTE_HELPER_H


#include "uapki-ns.h"
#include "byte-array.h"
#include <vector>


namespace UapkiNS {

    struct AttrCertId {
        UapkiNS::AlgorithmIdentifier
                    hashAlgorithm;
        ByteArray*  baHashValue;
        struct IssuerSerial {
            ByteArray*  baIssuer;
            ByteArray*  baSerialNumber;
            IssuerSerial (void)
                : baIssuer(nullptr), baSerialNumber(nullptr) {
            }
            ~IssuerSerial (void) {
                ba_free(baIssuer);
                ba_free(baSerialNumber);
            }
            bool isPresent (void) const {
                return (baIssuer && baSerialNumber);
            }
        }           issuerSerial;

        AttrCertId (void)
            : baHashValue(nullptr) {
        }
        ~AttrCertId (void) {
            ba_free(baHashValue);
        }
        bool isPresent (void) const {
            return (hashAlgorithm.isPresent() && baHashValue);
        }
    };  //  end struct AttrCertId

    using EssCertId = AttrCertId;
    using OtherCertId = AttrCertId;

namespace AttributeHelper {

    int decodeCertValues (const ByteArray* baEncoded, std::vector<ByteArray*>& certValues);
    int decodeCertificateRefs (const ByteArray* baEncoded, std::vector<OtherCertId>& otherCertIds);
    int decodeContentType (const ByteArray* baEncoded, std::string& contentType);
    int decodeMessageDigest (const ByteArray* baEncoded, ByteArray** baMessageDigest);
    int decodeSignaturePolicy (const ByteArray* baEncoded, std::string& sigPolicyId);
    int decodeSigningCertificate (const ByteArray* baEncoded, std::vector<EssCertId>& essCertIds);
    int decodeSigningTime (const ByteArray* baEncoded, uint64_t& signingTime);

    int encodeCertValues (const std::vector<const ByteArray*>& certValues, ByteArray** baEncoded);
    int encodeCertificateRefs (const std::vector<OtherCertId>& otherCertIds, ByteArray** baEncoded);
    int encodeSignaturePolicy (const std::string& sigPolicyId, ByteArray** baEncoded);
    int encodeSigningCertificate (const std::vector<EssCertId>& essCertIds, ByteArray** baEncoded);

}   //  end namespace AttributeHelper

}   //  end namespace UapkiNS


#endif
