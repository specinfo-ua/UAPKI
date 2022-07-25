//  Last update: 2022-07-24

#ifndef UAPKI_NS_ATTRIBUTE_HELPER_H
#define UAPKI_NS_ATTRIBUTE_HELPER_H


#include "uapki-ns.h"
#include "byte-array.h"
#include <vector>


namespace UapkiNS {

    struct EssCertIDv2 {
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

        EssCertIDv2 (void)
            : baCertHash(nullptr) {
        }
        ~EssCertIDv2 (void) {
            ba_free(baCertHash);
        }
        bool isPresent (void) const {
            return (hashAlgorithm.isPresent() && baCertHash);
        }
    };  //  end struct EssCertIDv2

namespace AttributeHelper {

    int decodeContentType (const ByteArray* baEncoded, std::string& contentType);
    int decodeMessageDigest (const ByteArray* baEncoded, ByteArray** baMessageDigest);
    int decodeSignaturePolicy (const ByteArray* baEncoded, std::string& sigPolicyId);
    int decodeSigningCertificate (const ByteArray* baEncoded, std::vector<EssCertIDv2>& essCertIds);
    int decodeSigningTime (const ByteArray* baEncoded, uint64_t& signingTime);

}   //  end namespace AttributeHelper

}   //  end namespace UapkiNS


#endif
