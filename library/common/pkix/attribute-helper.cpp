//  Last update: 2022-07-24


#include "attribute-helper.h"
#include "asn1-ba-utils.h"
#include "attribute-utils.h"
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
    SignaturePolicyIdentifier_t* sigpolicyid = nullptr;
    char* s_policyid = nullptr;

    CHECK_NOT_NULL(sigpolicyid = (SignaturePolicyIdentifier_t*)asn_decode_ba_with_alloc(get_SignaturePolicyIdentifier_desc(), baEncoded));
    if (sigpolicyid->present == SignaturePolicyIdentifier_PR_signaturePolicyId) {
        const SignaturePolicyId_t& signature_policyid = sigpolicyid->choice.signaturePolicyId;
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
    asn_free(get_SignaturePolicyIdentifier_desc(), sigpolicyid);
    ::free(s_policyid);
    return ret;
}

int AttributeHelper::decodeSigningCertificate (const ByteArray* baEncoded, vector<EssCertIDv2>& essCertIds)
{
    int ret = RET_OK;
    SigningCertificateV2_t* signing_cert = nullptr;

    CHECK_NOT_NULL(signing_cert = (SigningCertificateV2_t*)asn_decode_ba_with_alloc(get_SigningCertificateV2_desc(), baEncoded));

    if (signing_cert->certs.list.count > 0) {
        essCertIds.resize((size_t)signing_cert->certs.list.count);
        for (size_t i = 0; i < signing_cert->certs.list.count; i++) {
            EssCertIDv2& dst_esscertid = essCertIds[i];
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
            if (src_esscertid.issuerSerial) {//a need check
                //  =issuer=
                DO(asn_encode_ba(get_GeneralNames_desc(), &src_esscertid.issuerSerial->issuer, &dst_esscertid.issuerSerial.baIssuer));
                //  =serialNumber=
                DO(asn_INTEGER2ba(&src_esscertid.issuerSerial->serialNumber, &dst_esscertid.issuerSerial.baSerialNumber));
            }
        }
    }

cleanup:
    asn_free(get_SigningCertificateV2_desc(), signing_cert);
    return ret;
}

int AttributeHelper::decodeSigningTime (const ByteArray* baEncoded, uint64_t& signingTime)
{
    return ba_decode_pkixtime(baEncoded, &signingTime);
}


}   //  end namespace UapkiNS
