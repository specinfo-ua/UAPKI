//  Last update: 2022-07-27


#include "attribute-helper.h"
#include "asn1-ba-utils.h"
#include "attribute-utils.h"
#include "ba-utils.h"
#include "macros-internal.h"
#include "oids.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"


using namespace std;


namespace UapkiNS {


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
    //  Current implementation ignore params sigPolicyHash and sigPolicyQualifiers (rfc3126)
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
        essCertIds.resize((size_t)signing_cert->certs.list.count);
        for (size_t i = 0; i < signing_cert->certs.list.count; i++) {
            EssCertId& dst_esscertid = essCertIds[i];
            const ESSCertIDv2_t& src_esscertid = *signing_cert->certs.list.array[i];
            //  =hashAlgorithm= (default: sha256)
            if (src_esscertid.hashAlgorithm) {
                DO(Util::algorithmIdentifierFromAsn1(*src_esscertid.hashAlgorithm, dst_esscertid.hashAlgorithm));
            }
            else {
                dst_esscertid.hashAlgorithm.algorithm = string(OID_SHA256);
            }
            //  =certHash=
            DO(asn_OCTSTRING2ba(&src_esscertid.certHash, &dst_esscertid.baCertHash));
            //  =issuerSerial= (optional)
            if (src_esscertid.issuerSerial) {
                //  =issuer=
                DO(asn_encode_ba(get_GeneralNames_desc(), &src_esscertid.issuerSerial->issuer, &dst_esscertid.issuerSerial.baIssuer));
                //  =serialNumber=
                DO(asn_INTEGER2ba(&src_esscertid.issuerSerial->serialNumber, &dst_esscertid.issuerSerial.baSerialNumber));
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

        //  =hashAlgorithm= (default: algorithm id-sha256)
        if (it.hashAlgorithm.isPresent() && (it.hashAlgorithm.algorithm != string(OID_SHA256))) {
            ASN_ALLOC_TYPE(ess_certidv2->hashAlgorithm, AlgorithmIdentifier_t);
            DO(Util::algorithmIdentifierToAsn1(*ess_certidv2->hashAlgorithm, it.hashAlgorithm));
        }

        //  =certHash=
        DO(asn_ba2OCTSTRING(it.baCertHash, &ess_certidv2->certHash));

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
