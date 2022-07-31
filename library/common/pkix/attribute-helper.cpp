//  Last update: 2022-07-31


#include "attribute-helper.h"
#include "asn1-ba-utils.h"
#include "attribute-utils.h"
#include "ba-utils.h"
#include "macros-internal.h"
#include "oids.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"


#undef FILE_MARKER
#define FILE_MARKER "common/pkix/attribute-helper.cpp"


using namespace std;


namespace UapkiNS {


int AttributeHelper::decodeCertValues (const ByteArray* baEncoded, std::vector<ByteArray*>& certValues)
{
    int ret = RET_OK;
    Certificates_t* cert_values = nullptr;

    CHECK_NOT_NULL(cert_values = (Certificates_t*)asn_decode_ba_with_alloc(get_Certificates_desc(), baEncoded));

    if (cert_values->list.count > 0) {
        certValues.resize((size_t)cert_values->list.count);
        for (int i = 0; i < cert_values->list.count; i++) {
            DO(asn_encode_ba(get_Certificate_desc(), cert_values->list.array[i], &certValues[i]));
        }
    }

cleanup:
    asn_free(get_Certificates_desc(), cert_values);
    return ret;
}

int AttributeHelper::decodeCertificateRefs (const ByteArray* baEncoded, std::vector<OtherCertId>& otherCertIds)
{
    int ret = RET_OK;
    CompleteCertificateRefs_t* cert_refs = nullptr;

    CHECK_NOT_NULL(cert_refs = (CompleteCertificateRefs_t*)asn_decode_ba_with_alloc(get_CompleteCertificateRefs_desc(), baEncoded));

    if (cert_refs->list.count > 0) {
        size_t idx = 0;
        otherCertIds.resize((size_t)cert_refs->list.count);
        for (auto& it: otherCertIds) {
            const OtherCertID_t& other_certid = *cert_refs->list.array[idx++];
            //  =otherCertHash= (default: id-sha1)
            switch (other_certid.otherCertHash.present) {
            case OtherHash_PR_sha1Hash:
                it.hashAlgorithm.algorithm = string(OID_SHA1);
                DO(asn_OCTSTRING2ba(&other_certid.otherCertHash.choice.sha1Hash, &it.baHashValue));
                break;
            case OtherHash_PR_otherHash:
                DO(Util::algorithmIdentifierFromAsn1(other_certid.otherCertHash.choice.otherHash.hashAlgorithm, it.hashAlgorithm));
                DO(asn_OCTSTRING2ba(&other_certid.otherCertHash.choice.otherHash.hashValue, &it.baHashValue));
                break;
            default:
                SET_ERROR(RET_UAPKI_INVALID_STRUCT);
            }

            //  =issuerSerial= (optional)
            if (other_certid.issuerSerial) {
                //  =issuer=
                DO(asn_encode_ba(get_GeneralNames_desc(), &other_certid.issuerSerial->issuer, &it.issuerSerial.baIssuer));
                //  =serialNumber=
                DO(asn_INTEGER2ba(&other_certid.issuerSerial->serialNumber, &it.issuerSerial.baSerialNumber));
            }
        }
    }

cleanup:
    asn_free(get_CompleteCertificateRefs_desc(), cert_refs);
    return ret;
}

int AttributeHelper::decodeContentType (const ByteArray* baEncoded, string& contentType)
{
    int ret = RET_OK;
    char* s_contenttype = nullptr;

    DO(ba_decode_oid(baEncoded, &s_contenttype));
    contentType = string(s_contenttype);

cleanup:
    ::free(s_contenttype);
    return ret;
}

int AttributeHelper::decodeMessageDigest (const ByteArray* baEncoded, ByteArray** baMessageDigest)
{
    return ba_decode_octetstring(baEncoded, baMessageDigest);
}

int AttributeHelper::decodeSignaturePolicy (const ByteArray* baEncoded, string& sigPolicyId)
{
    //  Note: current implementation ignore params sigPolicyHash and sigPolicyQualifiers (rfc3126)
    int ret = RET_OK;
    SignaturePolicyIdentifier_t* sig_policy = nullptr;
    char* s_policyid = nullptr;

    CHECK_NOT_NULL(sig_policy = (SignaturePolicyIdentifier_t*)asn_decode_ba_with_alloc(get_SignaturePolicyIdentifier_desc(), baEncoded));
    if (sig_policy->present == SignaturePolicyIdentifier_PR_signaturePolicyId) {
        const SignaturePolicyId_t& signature_policyid = sig_policy->choice.signaturePolicyId;
        //  =sigPolicyId=
        DO(asn_oid_to_text(&signature_policyid.sigPolicyId, &s_policyid));
        sigPolicyId = string(s_policyid);
        //  =sigPolicyHash=
        //  Now skipped, later impl
        //  =sigPolicyQualifiers= (optional)
        //  Now skipped, later impl
    }
    else {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

cleanup:
    asn_free(get_SignaturePolicyIdentifier_desc(), sig_policy);
    ::free(s_policyid);
    return ret;
}

int AttributeHelper::decodeSigningCertificate (const ByteArray* baEncoded, vector<EssCertId>& essCertIds)
{
    int ret = RET_OK;
    SigningCertificateV2_t* signing_cert = nullptr;

    CHECK_NOT_NULL(signing_cert = (SigningCertificateV2_t*)asn_decode_ba_with_alloc(get_SigningCertificateV2_desc(), baEncoded));

    //  =certs=
    if (signing_cert->certs.list.count > 0) {
        size_t idx = 0;
        essCertIds.resize((size_t)signing_cert->certs.list.count);
        for (auto& it : essCertIds) {
            const ESSCertIDv2_t& ess_certid = *signing_cert->certs.list.array[idx++];
            //  =hashAlgorithm= (default: id-sha256)
            if (ess_certid.hashAlgorithm) {
                DO(Util::algorithmIdentifierFromAsn1(*ess_certid.hashAlgorithm, it.hashAlgorithm));
            }
            else {
                it.hashAlgorithm.algorithm = string(OID_SHA256);
            }
            //  =certHash=
            DO(asn_OCTSTRING2ba(&ess_certid.certHash, &it.baHashValue));
            //  =issuerSerial= (optional)
            if (ess_certid.issuerSerial) {
                //  =issuer=
                DO(asn_encode_ba(get_GeneralNames_desc(), &ess_certid.issuerSerial->issuer, &it.issuerSerial.baIssuer));
                //  =serialNumber=
                DO(asn_INTEGER2ba(&ess_certid.issuerSerial->serialNumber, &it.issuerSerial.baSerialNumber));
            }
        }
    }

    //  =policies= (optional)
    //TODO: later, signing_cert->policies

cleanup:
    asn_free(get_SigningCertificateV2_desc(), signing_cert);
    return ret;
}

int AttributeHelper::decodeSigningTime (const ByteArray* baEncoded, uint64_t& signingTime)
{
    return ba_decode_pkixtime(baEncoded, &signingTime);
}

int AttributeHelper::encodeCertValues (const std::vector<const ByteArray*>& certValues, ByteArray** baEncoded)
{
    int ret = RET_OK;
    Certificates_t* cert_values = nullptr;
    Certificate_t* cert = nullptr;

    ASN_ALLOC_TYPE(cert_values, Certificates_t);

    for (const auto& it : certValues) {
        CHECK_NOT_NULL(cert = (Certificate_t*)asn_decode_ba_with_alloc(get_Certificate_desc(), it));

        DO(ASN_SEQUENCE_ADD(&cert_values->list, cert));
        cert = nullptr;
    }

    DO(asn_encode_ba(get_Certificates_desc(), cert_values, baEncoded));

cleanup:
    asn_free(get_Certificates_desc(), cert_values);
    asn_free(get_Certificate_desc(), cert);
    return ret;
}

int AttributeHelper::encodeCertificateRefs (const vector<OtherCertId>& otherCertIds, ByteArray** baEncoded)
{
    int ret = RET_OK;
    CompleteCertificateRefs_t* cert_refs = nullptr;
    OtherCertID_t* other_certid = nullptr;

    ASN_ALLOC_TYPE(cert_refs, CompleteCertificateRefs_t);

    for (const auto& it : otherCertIds) {
        ASN_ALLOC_TYPE(other_certid, OtherCertID_t);

        //  =otherCertHash= (default: id-sha1)
        if (it.isPresent() && (it.hashAlgorithm.algorithm != string(OID_SHA1))) {
            other_certid->otherCertHash.present = OtherHash_PR_otherHash;
            DO(Util::algorithmIdentifierToAsn1(other_certid->otherCertHash.choice.otherHash.hashAlgorithm, it.hashAlgorithm));
            DO(asn_ba2OCTSTRING(it.baHashValue, &other_certid->otherCertHash.choice.otherHash.hashValue));
        }
        else {
            other_certid->otherCertHash.present = OtherHash_PR_sha1Hash;
            DO(asn_ba2OCTSTRING(it.baHashValue, &other_certid->otherCertHash.choice.sha1Hash));
        }

        //  =issuerSerial= (optional)
        if (it.issuerSerial.isPresent()) {
            ASN_ALLOC_TYPE(other_certid->issuerSerial, IssuerSerial_t);
            DO(asn_decode_ba(get_GeneralNames_desc(), &other_certid->issuerSerial->issuer, it.issuerSerial.baIssuer));
            DO(asn_ba2INTEGER(it.issuerSerial.baSerialNumber, &other_certid->issuerSerial->serialNumber));
        }

        DO(ASN_SEQUENCE_ADD(&cert_refs->list, other_certid));
        other_certid = nullptr;
    }

    DO(asn_encode_ba(get_CompleteCertificateRefs_desc(), cert_refs, baEncoded));

cleanup:
    asn_free(get_CompleteCertificateRefs_desc(), cert_refs);
    asn_free(get_OtherCertID_desc(), other_certid);
    return ret;
}

int AttributeHelper::encodeSignaturePolicy (const string& sigPolicyId, ByteArray** baEncoded)
{
    int ret = RET_OK;
    SignaturePolicyIdentifier_t* sig_policy = nullptr;

    if (sigPolicyId.empty() || !oid_is_valid(sigPolicyId.c_str())) return RET_UAPKI_INVALID_PARAMETER;

    ASN_ALLOC_TYPE(sig_policy, SignaturePolicyIdentifier_t);

    sig_policy->present = SignaturePolicyIdentifier_PR_signaturePolicyId;
    DO(asn_set_oid_from_text(sigPolicyId.c_str(), &sig_policy->choice.signaturePolicyId.sigPolicyId));

    DO(asn_encode_ba(get_SignaturePolicyIdentifier_desc(), sig_policy, baEncoded));

cleanup:
    asn_free(get_SignaturePolicyIdentifier_desc(), sig_policy);
    return ret;
}

int AttributeHelper::encodeSigningCertificate (const vector<EssCertId>& essCertIds, ByteArray** baEncoded)
{
    int ret = RET_OK;
    SigningCertificateV2_t* signing_certv2 = nullptr;
    ESSCertIDv2_t* ess_certidv2 = nullptr;

    ASN_ALLOC_TYPE(signing_certv2, SigningCertificateV2_t);

    for (const auto& it : essCertIds) {
        ASN_ALLOC_TYPE(ess_certidv2, ESSCertIDv2_t);

        //  =hashAlgorithm= (default: id-sha256)
        if (it.hashAlgorithm.isPresent() && (it.hashAlgorithm.algorithm != string(OID_SHA256))) {
            ASN_ALLOC_TYPE(ess_certidv2->hashAlgorithm, AlgorithmIdentifier_t);
            DO(Util::algorithmIdentifierToAsn1(*ess_certidv2->hashAlgorithm, it.hashAlgorithm));
        }

        //  =certHash=
        DO(asn_ba2OCTSTRING(it.baHashValue, &ess_certidv2->certHash));

        //  =issuerSerial= (optional)
        if (it.issuerSerial.isPresent()) {
            ASN_ALLOC_TYPE(ess_certidv2->issuerSerial, IssuerSerial_t);
            DO(asn_decode_ba(get_GeneralNames_desc(), &ess_certidv2->issuerSerial->issuer, it.issuerSerial.baIssuer));
            DO(asn_ba2INTEGER(it.issuerSerial.baSerialNumber, &ess_certidv2->issuerSerial->serialNumber));
        }

        DO(ASN_SEQUENCE_ADD(&signing_certv2->certs.list, (ESSCertIDv2_t*)ess_certidv2));
        ess_certidv2 = nullptr;
    }

    DO(asn_encode_ba(get_SigningCertificateV2_desc(), signing_certv2, baEncoded));

cleanup:
    asn_free(get_SigningCertificateV2_desc(), signing_certv2);
    asn_free(get_ESSCertIDv2_desc(), ess_certidv2);
    return ret;
}


}   //  end namespace UapkiNS
