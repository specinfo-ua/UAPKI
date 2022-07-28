//  Last update: 2022-07-27

#ifndef UAPKI_NS_ATTRIBUTE_HELPER_H
#define UAPKI_NS_ATTRIBUTE_HELPER_H


#include "uapki-ns.h"
#include "byte-array.h"
#include <vector>


namespace UapkiNS {

    struct EssCertId {
        UapkiNS::AlgorithmIdentifier
                    hashAlgorithm;  //  default: {algorithm id-sha256}
        ByteArray*  baCertHash;
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
        }           issuerSerial;   // optional

        EssCertId (void)
            : baCertHash(nullptr) {
        }
        ~EssCertId (void) {
            ba_free(baCertHash);
        }
        bool isPresent (void) const {
            return (hashAlgorithm.isPresent() && baCertHash);
        }
    };  //  end struct EssCertId

namespace AttributeHelper {

    int decodeContentType (const ByteArray* baEncoded, std::string& contentType);
    int decodeMessageDigest (const ByteArray* baEncoded, ByteArray** baMessageDigest);
    int decodeSignaturePolicy (const ByteArray* baEncoded, std::string& sigPolicyId);
    int decodeSigningCertificate (const ByteArray* baEncoded, std::vector<EssCertId>& essCertIds);
    int decodeSigningTime (const ByteArray* baEncoded, uint64_t& signingTime);

    int encodeSignaturePolicy (const std::string& sigPolicyId, ByteArray** baEncoded);
    int encodeSigningCertificate (const std::vector<EssCertId>& essCertIds, ByteArray** baEncoded);

}   //  end namespace AttributeHelper

}   //  end namespace UapkiNS


#endif
