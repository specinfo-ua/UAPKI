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

//  Last update: 2023-01-15


#include "attribute-helper.h"
#include "asn1-ba-utils.h"
#include "attribute-utils.h"
#include "ba-utils.h"
#include "macros-internal.h"
#include "oids.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"
#include "uapkif.h"


#undef FILE_MARKER
#define FILE_MARKER "common/pkix/attribute-helper.cpp"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


namespace UapkiNS {

namespace AttributeHelper {


int decodeCertValues (const ByteArray* baEncoded, vector<ByteArray*>& certValues)
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

int decodeCertificateRefs (const ByteArray* baEncoded, vector<OtherCertId>& otherCertIds)
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

int decodeContentType (const ByteArray* baEncoded, string& contentType)
{
    int ret = RET_OK;
    char* s_contenttype = nullptr;

    DO(ba_decode_oid(baEncoded, &s_contenttype));
    contentType = string(s_contenttype);

cleanup:
    ::free(s_contenttype);
    return ret;
}

int decodeMessageDigest (const ByteArray* baEncoded, ByteArray** baMessageDigest)
{
    return ba_decode_octetstring(baEncoded, baMessageDigest);
}

int decodeSignaturePolicy (const ByteArray* baEncoded, string& sigPolicyId)
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

int decodeSigningCertificate (const ByteArray* baEncoded, vector<EssCertId>& essCertIds)
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

int decodeSigningTime (const ByteArray* baEncoded, uint64_t& signingTime)
{
    return ba_decode_pkixtime(baEncoded, &signingTime);
}

int encodeCertValues (const vector<const ByteArray*>& certValues, ByteArray** baEncoded)
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

int encodeCertificateRefs (const vector<OtherCertId>& otherCertIds, ByteArray** baEncoded)
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

int encodeSignaturePolicy (
        const string& sigPolicyId,
        ByteArray** baEncoded
)
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

int encodeSigningCertificate (
        const EssCertId& essCertId,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    SigningCertificateV2_t* signing_certv2 = nullptr;
    ESSCertIDv2_t* ess_certidv2 = nullptr;

    ASN_ALLOC_TYPE(signing_certv2, SigningCertificateV2_t);

    ASN_ALLOC_TYPE(ess_certidv2, ESSCertIDv2_t);

    //  =hashAlgorithm= (default: id-sha256)
    if (essCertId.hashAlgorithm.isPresent() && (essCertId.hashAlgorithm.algorithm != string(OID_SHA256))) {
        ASN_ALLOC_TYPE(ess_certidv2->hashAlgorithm, AlgorithmIdentifier_t);
        DO(Util::algorithmIdentifierToAsn1(*ess_certidv2->hashAlgorithm, essCertId.hashAlgorithm));
    }

    //  =certHash=
    DO(asn_ba2OCTSTRING(essCertId.baHashValue, &ess_certidv2->certHash));

    //  =issuerSerial= (optional)
    if (essCertId.issuerSerial.isPresent()) {
        ASN_ALLOC_TYPE(ess_certidv2->issuerSerial, IssuerSerial_t);
        DO(asn_decode_ba(get_GeneralNames_desc(), &ess_certidv2->issuerSerial->issuer, essCertId.issuerSerial.baIssuer));
        DO(asn_ba2INTEGER(essCertId.issuerSerial.baSerialNumber, &ess_certidv2->issuerSerial->serialNumber));
    }

    DO(ASN_SEQUENCE_ADD(&signing_certv2->certs.list, (ESSCertIDv2_t*)ess_certidv2));
    ess_certidv2 = nullptr;

    DO(asn_encode_ba(get_SigningCertificateV2_desc(), signing_certv2, baEncoded));

cleanup:
    asn_free(get_SigningCertificateV2_desc(), signing_certv2);
    asn_free(get_ESSCertIDv2_desc(), ess_certidv2);
    return ret;
}

int encodeSigningCertificate (
        const vector<EssCertId>& essCertIds,
        ByteArray** baEncoded
)
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


AtsHashIndexBuilder::AtsHashIndexBuilder (void)
    : m_AtsHashIndexDefault(nullptr)
    , m_AtsHashIndexFull(nullptr)
    , m_BaEncoded(nullptr)
{
    DEBUG_OUTCON(puts("AtsHashIndexBuilder::AtsHashIndexBuilder()"));
}

AtsHashIndexBuilder::~AtsHashIndexBuilder (void)
{
    DEBUG_OUTCON(puts("AtsHashIndexBuilder::~AtsHashIndexBuilder()"));
    asn_free(get_ATSHashIndexDefault_desc(), m_AtsHashIndexDefault);
    asn_free(get_ATSHashIndexFull_desc(), m_AtsHashIndexFull);
    ba_free(m_BaEncoded);
}

int AtsHashIndexBuilder::init (const char* hashIndAlgorithm, const ByteArray* baParameters)
{
    if (!hashIndAlgorithm || (strlen(hashIndAlgorithm) < 2)) return RET_UAPKI_INVALID_PARAMETER;

    if (oid_is_equal(OID_SHA256, hashIndAlgorithm)) {
        m_AtsHashIndexDefault = (ATSHashIndexDefault_t*)calloc(1, sizeof(ATSHashIndexDefault_t));
        return (m_AtsHashIndexDefault) ? RET_OK : RET_UAPKI_GENERAL_ERROR;
    }

    m_AtsHashIndexFull = (ATSHashIndexFull_t*)calloc(1, sizeof(ATSHashIndexFull_t));
    if (!m_AtsHashIndexFull) return RET_UAPKI_GENERAL_ERROR;

    return Util::algorithmIdentifierToAsn1(m_AtsHashIndexFull->hashIndAlgorithm, hashIndAlgorithm, baParameters);
}

int AtsHashIndexBuilder::init (const AlgorithmIdentifier& hashIndAlgorithm)
{
    return init(hashIndAlgorithm.algorithm.c_str(), hashIndAlgorithm.baParameters);
}

int AtsHashIndexBuilder::addHashCert (const ByteArray* baCertEncoded)
{
    if (!m_AtsHashIndexDefault && !m_AtsHashIndexFull) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    CertificatesHashIndex_t& certs_hashindex = (m_AtsHashIndexDefault)
        ? m_AtsHashIndexDefault->certificatesHashIndex : m_AtsHashIndexFull->certificatesHashIndex;
    OCTET_STRING_t* octet_str = (OCTET_STRING_t*)calloc(1, sizeof(OCTET_STRING_t));
    if (!octet_str) return RET_UAPKI_GENERAL_ERROR;

    DO(asn_ba2OCTSTRING(baCertEncoded, octet_str));
    DO(ASN_SEQUENCE_ADD(&certs_hashindex.list, octet_str));
    octet_str = nullptr;

cleanup:
    asn_free(get_OCTET_STRING_desc(), octet_str);
    return ret;
}

int AtsHashIndexBuilder::addHashCrl (const ByteArray* baCrlEncoded)
{
    if (!m_AtsHashIndexDefault && !m_AtsHashIndexFull) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    CrlsHashIndex_t& crls_hashindex = (m_AtsHashIndexDefault)
        ? m_AtsHashIndexDefault->crlsHashIndex : m_AtsHashIndexFull->crlsHashIndex;
    OCTET_STRING_t* octet_str = (OCTET_STRING_t*)calloc(1, sizeof(OCTET_STRING_t));
    if (!octet_str) return RET_UAPKI_GENERAL_ERROR;

    DO(asn_ba2OCTSTRING(baCrlEncoded, octet_str));
    DO(ASN_SEQUENCE_ADD(&crls_hashindex.list, octet_str));
    octet_str = nullptr;

cleanup:
    asn_free(get_OCTET_STRING_desc(), octet_str);
    return ret;
}

int AtsHashIndexBuilder::addHashUnsignedAttr (const ByteArray* baAttrEncoded)
{
    if (!m_AtsHashIndexDefault && !m_AtsHashIndexFull) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    UnsignedAttrsHashIndex_t& unsattrs_hashindex = (m_AtsHashIndexDefault)
        ? m_AtsHashIndexDefault->unsignedAttrsHashIndex : m_AtsHashIndexFull->unsignedAttrsHashIndex;
    OCTET_STRING_t* octet_str = (OCTET_STRING_t*)calloc(1, sizeof(OCTET_STRING_t));
    if (!octet_str) return RET_UAPKI_GENERAL_ERROR;

    DO(asn_ba2OCTSTRING(baAttrEncoded, octet_str));
    DO(ASN_SEQUENCE_ADD(&unsattrs_hashindex.list, octet_str));
    octet_str = nullptr;

cleanup:
    asn_free(get_OCTET_STRING_desc(), octet_str);
    return ret;
}

int AtsHashIndexBuilder::encode (void)
{
    int ret = RET_UAPKI_INVALID_PARAMETER;
    if (m_AtsHashIndexDefault) {
        ret = asn_encode_ba(get_ATSHashIndexDefault_desc(), m_AtsHashIndexDefault, &m_BaEncoded);
    }
    else if (m_AtsHashIndexFull) {
        ret = asn_encode_ba(get_ATSHashIndexFull_desc(), m_AtsHashIndexFull, &m_BaEncoded);
    }
    return ret;
}

ByteArray* AtsHashIndexBuilder::getEncoded (const bool move)
{
    ByteArray* rv_ba = m_BaEncoded;
    if (move) {
        m_BaEncoded = nullptr;
    }
    return rv_ba;
}


AtsHashIndexParser::AtsHashIndexParser (void)
{
    DEBUG_OUTCON(puts("AtsHashIndexParser::AtsHashIndexParser()"));
}

AtsHashIndexParser::~AtsHashIndexParser (void)
{
    DEBUG_OUTCON(puts("AtsHashIndexParser::~AtsHashIndexParser()"));
}

static int parse_sequence_of_octet_string (CertificatesHashIndex_t& asnHashIndex, VectorBA& vbaResult)
{
    int ret = RET_OK;
    ByteArray* ba_hash = nullptr;

    for (int i = 0; i < asnHashIndex.list.count; i++) {
        DO(asn_OCTSTRING2ba(asnHashIndex.list.array[i], &ba_hash));
        vbaResult.push_back(ba_hash);
        ba_hash = nullptr;
    }

cleanup:
    ba_free(ba_hash);
    return ret;
}

int AtsHashIndexParser::parse (const ByteArray* baEncoded)
{
    int ret = RET_OK;
    ATSHashIndexDefault_t* ats_hashinddef = nullptr;
    ATSHashIndexFull_t* ats_hashindfull = nullptr;

    ats_hashindfull = (ATSHashIndexFull_t*)asn_decode_ba_with_alloc(get_ATSHashIndexFull_desc(), baEncoded);
    if (ats_hashindfull) {
        DO(Util::algorithmIdentifierFromAsn1(ats_hashindfull->hashIndAlgorithm, m_HashIndAlgorithm));
        DO(parse_sequence_of_octet_string(ats_hashindfull->certificatesHashIndex, m_CertsHashIndex));
        DO(parse_sequence_of_octet_string((CertificatesHashIndex_t&)ats_hashindfull->crlsHashIndex, m_CrlsHashIndex));
        DO(parse_sequence_of_octet_string((CertificatesHashIndex_t&)ats_hashindfull->unsignedAttrsHashIndex, m_UnsignedAttrsHashIndex));
    }
    else {
        ats_hashinddef = (ATSHashIndexDefault_t*)asn_decode_ba_with_alloc(get_ATSHashIndexDefault_desc(), baEncoded);
        if (!ats_hashinddef) {
            SET_ERROR(RET_UAPKI_INVALID_STRUCT);
        }
        m_HashIndAlgorithm.algorithm = string(OID_SHA256);
        DO(parse_sequence_of_octet_string(ats_hashinddef->certificatesHashIndex, m_CertsHashIndex));
        DO(parse_sequence_of_octet_string((CertificatesHashIndex_t&)ats_hashinddef->crlsHashIndex, m_CrlsHashIndex));
        DO(parse_sequence_of_octet_string((CertificatesHashIndex_t&)ats_hashinddef->unsignedAttrsHashIndex, m_UnsignedAttrsHashIndex));
    }

cleanup:
    asn_free(get_ATSHashIndexDefault_desc(), ats_hashinddef);
    asn_free(get_ATSHashIndexFull_desc(), ats_hashindfull);
    return ret;
}


RevocationRefsBuilder::RevocationRefsBuilder (void)
    : m_RevRefs(nullptr)
    , m_BaEncoded(nullptr)
{
    DEBUG_OUTCON(puts("RevocationRefsBuilder::RevocationRefsBuilder()"));
}

RevocationRefsBuilder::~RevocationRefsBuilder (void)
{
    DEBUG_OUTCON(puts("RevocationValuesBuilder::~RevocationValuesBuilder()"));
    asn_free(get_CompleteRevocationRefs_desc(), m_RevRefs);
    for (auto& it : m_CrlOcspRefs) {
        delete it;
    }
    ba_free(m_BaEncoded);
}

int RevocationRefsBuilder::init (void)
{
    m_RevRefs = (CompleteRevocationRefs_t*)calloc(1, sizeof(CompleteRevocationRefs_t));
    return (m_RevRefs) ? RET_OK : RET_UAPKI_GENERAL_ERROR;
}

int RevocationRefsBuilder::addCrlOcspRef (void)
{
    int ret = RET_OK;
    CrlOcspRef_t* crlocsp_ref = nullptr;

    if (!m_RevRefs) return RET_UAPKI_INVALID_PARAMETER;

    ASN_ALLOC_TYPE(crlocsp_ref, CrlOcspRef_t);

    DO(ASN_SEQUENCE_ADD(&m_RevRefs->list, crlocsp_ref));
    m_CrlOcspRefs.push_back(new CrlOcspRef(crlocsp_ref));
    crlocsp_ref = nullptr;

cleanup:
    asn_free(get_CrlOcspRef_desc(), crlocsp_ref);
    return ret;
}

RevocationRefsBuilder::CrlOcspRef* RevocationRefsBuilder::getCrlOcspRef (
        const size_t index
) const
{
    if (index >= m_CrlOcspRefs.size()) return nullptr;

    return m_CrlOcspRefs[index];
}

int RevocationRefsBuilder::encode (void)
{
    if (!m_RevRefs) return RET_UAPKI_INVALID_PARAMETER;

    return asn_encode_ba(get_CompleteRevocationRefs_desc(), m_RevRefs, &m_BaEncoded);
}

ByteArray* RevocationRefsBuilder::getEncoded (
        const bool move
)
{
    ByteArray* rv_ba = m_BaEncoded;
    if (move) {
        m_BaEncoded = nullptr;
    }
    return rv_ba;
}

RevocationRefsBuilder::CrlOcspRef::CrlOcspRef (CrlOcspRef_t* iRefCrlOcspRef)
    : m_RefCrlOcspRef(iRefCrlOcspRef)
{
    DEBUG_OUTCON(puts("RevocationRefsBuilder::CrlOcspRef::CrlOcspRef()"));
}

RevocationRefsBuilder::CrlOcspRef::~CrlOcspRef (void)
{
    DEBUG_OUTCON(puts("RevocationRefsBuilder::CrlOcspRef::~CrlOcspRef()"));
}

int RevocationRefsBuilder::CrlOcspRef::addCrlValidatedId (
        const UapkiNS::OtherHash& crlHash,
        const ByteArray* baCrlIdentifier
)
{
    int ret = RET_OK;
    CrlValidatedID_t* crl_validatedid = nullptr;

    if (!m_RefCrlOcspRef || !crlHash.isPresent()) return RET_UAPKI_INVALID_PARAMETER;

    if (!m_RefCrlOcspRef->crlids) {
        ASN_ALLOC_TYPE(m_RefCrlOcspRef->crlids, CRLListID_t);
    }

    ASN_ALLOC_TYPE(crl_validatedid, CrlValidatedID_t);

    //  =crlHash=
    if (crlHash.hashAlgorithm.algorithm != string(OID_SHA1)) {
        crl_validatedid->crlHash.present = OtherHash_PR_otherHash;
        DO(UapkiNS::Util::algorithmIdentifierToAsn1(crl_validatedid->crlHash.choice.otherHash.hashAlgorithm, crlHash.hashAlgorithm));
        DO(asn_ba2OCTSTRING(crlHash.baHashValue, &crl_validatedid->crlHash.choice.otherHash.hashValue));
    }
    else {
        crl_validatedid->crlHash.present = OtherHash_PR_sha1Hash;
        DO(asn_ba2OCTSTRING(crlHash.baHashValue, &crl_validatedid->crlHash.choice.sha1Hash));
    }

    //  =crlIdentifier= (optional)
    if (baCrlIdentifier) {
        CHECK_NOT_NULL(crl_validatedid->crlIdentifier = (CrlIdentifier_t*)asn_decode_ba_with_alloc(get_CrlIdentifier_desc(), baCrlIdentifier));
    }

    DO(ASN_SEQUENCE_ADD(&m_RefCrlOcspRef->crlids->crls.list, crl_validatedid));
    crl_validatedid = nullptr;

cleanup:
    asn_free(get_CrlValidatedID_desc(), crl_validatedid);
    return ret;
}

int RevocationRefsBuilder::CrlOcspRef::addOcspResponseId (
        const ByteArray* baOcspIdentifier,
        const ByteArray* baOcspRespHash
)
{
    int ret = RET_OK;
    OcspResponsesID_t* ocsp_respsid = nullptr;

    if (!m_RefCrlOcspRef || !baOcspIdentifier) return RET_UAPKI_INVALID_PARAMETER;

    if (!m_RefCrlOcspRef->ocspids) {
        ASN_ALLOC_TYPE(m_RefCrlOcspRef->ocspids, OcspListID_t);
    }

    ASN_ALLOC_TYPE(ocsp_respsid, OcspResponsesID_t);
    DO(asn_decode_ba(get_OcspIdentifier_desc(), &ocsp_respsid->ocspIdentifier, baOcspIdentifier));
    if (baOcspRespHash) {
        CHECK_NOT_NULL(ocsp_respsid->ocspRepHash = (OtherHash_t*)asn_decode_ba_with_alloc(get_OtherHash_desc(), baOcspRespHash));
    }

    DO(ASN_SEQUENCE_ADD(&m_RefCrlOcspRef->ocspids->ocspResponses.list, ocsp_respsid));
    ocsp_respsid = nullptr;

cleanup:
    asn_free(get_OcspResponsesID_desc(), ocsp_respsid);
    return ret;
}

int RevocationRefsBuilder::CrlOcspRef::setOtherRevRefs (
        const char* otherRevRefType,
        const ByteArray* baOtherRevRefs
)
{
    int ret = RET_OK;

    if (!m_RefCrlOcspRef || !otherRevRefType || !baOtherRevRefs) return RET_UAPKI_INVALID_PARAMETER;

    ASN_ALLOC_TYPE(m_RefCrlOcspRef->otherRev, OtherRevRefs_t);
    DO(asn_set_oid_from_text(otherRevRefType, &m_RefCrlOcspRef->otherRev->otherRevRefType));
    DO(asn_decode_ba(get_ANY_desc(), &m_RefCrlOcspRef->otherRev->otherRevRefs, baOtherRevRefs));

cleanup:
    return ret;
}

int RevocationRefsBuilder::CrlOcspRef::setOtherRevRefs (
        const string& otherRevRefType,
        const ByteArray* baOtherRevRefs
)
{
    if (otherRevRefType.empty() || !baOtherRevRefs) return RET_UAPKI_INVALID_PARAMETER;

    return setOtherRevRefs(otherRevRefType.c_str(), baOtherRevRefs);
}


RevocationRefsParser::RevocationRefsParser (void)
    : m_RevRefs(nullptr)
    , m_CountCrlOcspRefs(0)
{
    DEBUG_OUTCON(puts("RevocationRefsParser::RevocationRefsParser()"));
}

RevocationRefsParser::~RevocationRefsParser (void)
{
    DEBUG_OUTCON(puts("RevocationRefsParser::~RevocationRefsParser()"));
    asn_free(get_CompleteRevocationRefs_desc(), m_RevRefs);
}

int RevocationRefsParser::parse (
        const ByteArray* baEncoded
)
{
    int ret = RET_OK;

    CHECK_NOT_NULL(m_RevRefs = (CompleteRevocationRefs_t*)asn_decode_ba_with_alloc(get_CompleteRevocationRefs_desc(), baEncoded));
    m_CountCrlOcspRefs = (size_t)m_RevRefs->list.count;

cleanup:
    return ret;
}

int RevocationRefsParser::parseCrlOcspRef (
        const size_t index,
        CrlOcspRef& crlOcspRef
)
{
    if (index >= m_CountCrlOcspRefs) return RET_INDEX_OUT_OF_RANGE;

    return crlOcspRef.parse(*m_RevRefs->list.array[index]);
}


RevocationRefsParser::CrlOcspRef::CrlOcspRef (void)
{
    DEBUG_OUTCON(puts("RevocationRefsParser::CrlOcspRef::CrlOcspRef()"));
}

RevocationRefsParser::CrlOcspRef::~CrlOcspRef (void)
{
    DEBUG_OUTCON(puts("RevocationRefsParser::CrlOcspRef::~CrlOcspRef()"));
}

int RevocationRefsParser::CrlOcspRef::parse (
        const CrlOcspRef_t& crlOcspRef
)
{
    int ret = RET_OK;
    char* s_type = nullptr;

    //  =crlids= (optional)
    if (crlOcspRef.crlids && (crlOcspRef.crlids->crls.list.count > 0)) {
        m_CrlIds.resize((size_t)crlOcspRef.crlids->crls.list.count);
        for (size_t i = 0; i < m_CrlIds.size(); i++) {
            const CrlValidatedID_t* crl_valid = crlOcspRef.crlids->crls.list.array[i];
            DO(asn_encode_ba(get_OtherHash_desc(), &crl_valid->crlHash, &m_CrlIds[i].baHash));
            if (crl_valid->crlIdentifier) {//TODO: crlIdentifier need check
                DO(asn_encode_ba(get_CrlIdentifier_desc(), crl_valid->crlIdentifier, &m_CrlIds[i].baId));
            }
        }
    }

    //  =ocspids= (optional)
    if (crlOcspRef.ocspids && (crlOcspRef.ocspids->ocspResponses.list.count > 0)) {
        m_OcspIds.resize((size_t)crlOcspRef.ocspids->ocspResponses.list.count);
        for (size_t i = 0; i < m_OcspIds.size(); i++) {
            const OcspResponsesID_t* ocsp_respsid = crlOcspRef.ocspids->ocspResponses.list.array[i];
            DO(asn_encode_ba(get_OcspIdentifier_desc(), &ocsp_respsid->ocspIdentifier, &m_OcspIds[i].baId));
            if (ocsp_respsid->ocspRepHash) {
                DO(asn_encode_ba(get_OtherHash_desc(), ocsp_respsid->ocspRepHash, &m_OcspIds[i].baHash));
            }
        }
    }

    //  =otherRev= (optional)
    if (crlOcspRef.otherRev) {
        const OtherRevRefs_t* other_revrefs = crlOcspRef.otherRev;
        DO(asn_oid_to_text(&other_revrefs->otherRevRefType, &s_type));
        m_OtherRevRefs.type = string(s_type);
        m_OtherRevRefs.baValues = ba_alloc_from_uint8(other_revrefs->otherRevRefs.buf, other_revrefs->otherRevRefs.size);
    }

cleanup:
    ::free(s_type);
    return ret;
}


RevocationValuesBuilder::RevocationValuesBuilder (void)
    : m_RevValues(nullptr)
    , m_BaEncoded(nullptr)
{
    DEBUG_OUTCON(puts("RevocationValuesBuilder::RevocationValuesBuilder()"));
}

RevocationValuesBuilder::~RevocationValuesBuilder (void)
{
    DEBUG_OUTCON(puts("RevocationValuesBuilder::~RevocationValuesBuilder()"));
    asn_free(get_RevocationValues_desc(), m_RevValues);
    ba_free(m_BaEncoded);
}

int RevocationValuesBuilder::init (void)
{
    m_RevValues = (RevocationValues_t*)calloc(1, sizeof(RevocationValues_t));
    return (m_RevValues) ? RET_OK : RET_UAPKI_GENERAL_ERROR;
}

int RevocationValuesBuilder::addCrlValue (
        const ByteArray* baCrlEncoded
)
{
    int ret = RET_OK;
    CertificateList_t* crl = nullptr;

    if (!m_RevValues) return RET_UAPKI_INVALID_PARAMETER;

    if (!m_RevValues->crlVals) {
        void* ptr = calloc(1, sizeof(*RevocationValues_t::crlVals));
        if (!ptr) return RET_UAPKI_GENERAL_ERROR;
        memcpy(&m_RevValues->crlVals, &ptr, sizeof(ptr));
    }

    if (baCrlEncoded) {
        CHECK_NOT_NULL(crl = (CertificateList_t*)asn_decode_ba_with_alloc(get_CertificateList_desc(), baCrlEncoded));
        DO(ASN_SEQUENCE_ADD(&m_RevValues->crlVals->list, crl));
        crl = nullptr;
    }

cleanup:
    asn_free(get_CertificateList_desc(), crl);
    return ret;
}

int RevocationValuesBuilder::addOcspValue (
        const ByteArray* baBasicOcspResponseEncoded
)
{
    int ret = RET_OK;
    BasicOCSPResponse_t* ocsp_resp = nullptr;

    if (!m_RevValues) return RET_UAPKI_INVALID_PARAMETER;

    if (!m_RevValues->ocspVals) {
        void* ptr = calloc(1, sizeof(*RevocationValues_t::ocspVals));
        if (!ptr) return RET_UAPKI_GENERAL_ERROR;
        memcpy(&m_RevValues->ocspVals, &ptr, sizeof(ptr));
    }

    if (baBasicOcspResponseEncoded) {
        CHECK_NOT_NULL(ocsp_resp = (BasicOCSPResponse_t*)asn_decode_ba_with_alloc(get_BasicOCSPResponse_desc(), baBasicOcspResponseEncoded));
        DO(ASN_SEQUENCE_ADD(&m_RevValues->ocspVals->list, ocsp_resp));
        ocsp_resp = nullptr;
    }

cleanup:
    asn_free(get_BasicOCSPResponse_desc(), ocsp_resp);
    return ret;
}

int RevocationValuesBuilder::setCrlValues (
        const vector<const ByteArray*>& abaCrlValues
)
{
    int ret = RET_OK;
    CertificateList_t* crl = nullptr;

    if (!m_RevValues) return RET_UAPKI_INVALID_PARAMETER;

    void* ptr = calloc(1, sizeof(*RevocationValues_t::crlVals));
    if (!ptr) return RET_UAPKI_GENERAL_ERROR;
    memcpy(&m_RevValues->crlVals, &ptr, sizeof(ptr));

    for (const auto& it : abaCrlValues) {
        if (it) {
            CHECK_NOT_NULL(crl = (CertificateList_t*)asn_decode_ba_with_alloc(get_CertificateList_desc(), it));
            DO(ASN_SEQUENCE_ADD(&m_RevValues->crlVals->list, crl));
            crl = nullptr;
        }
    }

cleanup:
    asn_free(get_CertificateList_desc(), crl);
    return ret;
}

int RevocationValuesBuilder::setOcspValues (
        const vector<const ByteArray*>& abaOcspValues
)
{
    int ret = RET_OK;
    BasicOCSPResponse_t* ocsp_resp = nullptr;

    if (!m_RevValues) return RET_UAPKI_INVALID_PARAMETER;

    void* ptr = calloc(1, sizeof(*RevocationValues_t::ocspVals));
    if (!ptr) return RET_UAPKI_GENERAL_ERROR;
    memcpy(&m_RevValues->ocspVals, &ptr, sizeof(ptr));

    for (const auto& it : abaOcspValues) {
        if (it) {
            CHECK_NOT_NULL(ocsp_resp = (BasicOCSPResponse_t*)asn_decode_ba_with_alloc(get_BasicOCSPResponse_desc(), it));
            DO(ASN_SEQUENCE_ADD(&m_RevValues->ocspVals->list, ocsp_resp));
            ocsp_resp = nullptr;
        }
    }

cleanup:
    asn_free(get_BasicOCSPResponse_desc(), ocsp_resp);
    return ret;
}

int RevocationValuesBuilder::setOtherRevVals (
        const char* otherRevValType,
        const ByteArray* baOtherRevVals
)
{
    int ret = RET_OK;

    if (!m_RevValues || !otherRevValType || !baOtherRevVals) return RET_UAPKI_INVALID_PARAMETER;

    ASN_ALLOC_TYPE(m_RevValues->otherRevVals, OtherRevVals_t);
    DO(asn_set_oid_from_text(otherRevValType, &m_RevValues->otherRevVals->otherRevValType));
    DO(asn_decode_ba(get_ANY_desc(), &m_RevValues->otherRevVals->otherRevVals, baOtherRevVals));

cleanup:
    return ret;
}

int RevocationValuesBuilder::setOtherRevVals (
        const string& otherRevValType,
        const ByteArray* baOtherRevVals
)
{
    if (otherRevValType.empty() || !baOtherRevVals) return RET_UAPKI_INVALID_PARAMETER;

    return setOtherRevVals(otherRevValType.c_str(), baOtherRevVals);
}

int RevocationValuesBuilder::encode (void)
{
    if (!m_RevValues) return RET_UAPKI_INVALID_PARAMETER;

    return asn_encode_ba(get_RevocationValues_desc(), m_RevValues, &m_BaEncoded);
}

ByteArray* RevocationValuesBuilder::getEncoded (
        const bool move
)
{
    ByteArray* rv_ba = m_BaEncoded;
    if (move) {
        m_BaEncoded = nullptr;
    }
    return rv_ba;
}


RevocationValuesParser::RevocationValuesParser (void)
{
    DEBUG_OUTCON(puts("RevocationValuesParser::RevocationValuesParser()"));
}

RevocationValuesParser::~RevocationValuesParser (void)
{
    DEBUG_OUTCON(puts("RevocationValuesParser::~RevocationValuesParser()"));
}

int RevocationValuesParser::parse (
        const ByteArray* baEncoded
)
{
    int ret = RET_OK;
    RevocationValues_t* rev_values;
    char* s_type = nullptr;

    CHECK_NOT_NULL(rev_values = (RevocationValues_t*)asn_decode_ba_with_alloc(get_RevocationValues_desc(), baEncoded));

    //  =crlVals= (optional)
    if (rev_values->crlVals && (rev_values->crlVals->list.count > 0)) {
        m_CrlVals.resize((size_t)rev_values->crlVals->list.count);
        for (size_t i = 0; i < m_CrlVals.size(); i++) {
            DO(asn_encode_ba(get_CertificateList_desc(), rev_values->crlVals->list.array[i], &m_CrlVals[i]));
        }
    }

    //  =ocspVals= (optional)
    if (rev_values->ocspVals && (rev_values->ocspVals->list.count > 0)) {
        m_OcspVals.resize((size_t)rev_values->ocspVals->list.count);
        for (size_t i = 0; i < m_OcspVals.size(); i++) {
            DO(asn_encode_ba(get_BasicOCSPResponse_desc(), rev_values->ocspVals->list.array[i], &m_OcspVals[i]));
        }
    }

    //  =otherRevVals= (optional)
    if (rev_values->otherRevVals) {
        const OtherRevVals_t* other_revvals = rev_values->otherRevVals;
        DO(asn_oid_to_text(&other_revvals->otherRevValType, &s_type));
        m_OtherRevVals.type = string(s_type);
        m_OtherRevVals.baValues = ba_alloc_from_uint8(other_revvals->otherRevVals.buf, other_revvals->otherRevVals.size);
    }

cleanup:
    asn_free(get_RevocationValues_desc(), rev_values);
    ::free(s_type);
    return ret;
}

}   //  end namespace AttributeHelper

}   //  end namespace UapkiNS
