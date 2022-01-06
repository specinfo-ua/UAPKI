//  Last update: 2022-01-06


#include "certreq-builder.h"
#include "asn1-ba-utils.h"
#include "ba-utils.h"
#include "attribute-utils.h"
#include "dstu-ns.h"
#include "extension-utils.h"
#include "macros-internal.h"
#include "oid-utils.h"
#include "uapki-errors.h"
#include <stdio.h>


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


namespace UapkiNS {


CertReqBuilder::CertReqBuilder (void)
    : m_TbsCsrInfo(nullptr)
    , m_BaTbsEncoded(nullptr)
    , m_BaCsrEncoded(nullptr)
{
    DEBUG_OUTCON(puts("CertReqBuilder::CertReqBuilder()"));
}

CertReqBuilder::~CertReqBuilder (void)
{
    DEBUG_OUTCON(puts("CertReqBuilder::~CertReqBuilder()"));
    asn_free(get_CertificationRequestInfo_desc(), m_TbsCsrInfo);
    ba_free(m_BaTbsEncoded);
    ba_free(m_BaCsrEncoded);
}

int CertReqBuilder::init (const uint32_t version)
{
    if (version < 1) return RET_UAPKI_INVALID_PARAMETER;

    m_TbsCsrInfo = (CertificationRequestInfo_t*)calloc(1, sizeof(CertificationRequestInfo_t));
    if (!m_TbsCsrInfo) return RET_UAPKI_GENERAL_ERROR;

    m_TbsCsrInfo->subject.present = Name_PR_rdnSequence;
    const int ret = asn_ulong2INTEGER(&m_TbsCsrInfo->version, (unsigned long)version - 1);
    return ret;
}

int CertReqBuilder::setSubject (const ByteArray* baNameEncoded)
{
    if (!m_TbsCsrInfo || (ba_get_len(baNameEncoded) == 0)) return RET_UAPKI_INVALID_PARAMETER;

    return asn_decode_ba(get_Name_desc(), &m_TbsCsrInfo->subject, baNameEncoded);
}

int CertReqBuilder::setSubject (const vector<UapkiNS::RdName>& rdNames)
{
    int ret = RET_OK;

    if (!m_TbsCsrInfo) return RET_UAPKI_INVALID_PARAMETER;

    for (auto& it : rdNames) {
        if (!it.isPresent()) return RET_UAPKI_INVALID_PARAMETER;
        DO(nameAddRdName(&m_TbsCsrInfo->subject, it));
    }

cleanup:
    return ret;
}

int CertReqBuilder::setSubjectPublicKeyInfo (const ByteArray* baSpkiEncoded)
{
    int ret = RET_OK;
    char* s_keyalgo = nullptr;

    if (!m_TbsCsrInfo || !baSpkiEncoded) return RET_UAPKI_INVALID_PARAMETER;

    DO(asn_decode_ba(get_SubjectPublicKeyInfo_desc(), &m_TbsCsrInfo->subjectPKInfo, baSpkiEncoded));
    DO(asn_oid_to_text(&m_TbsCsrInfo->subjectPKInfo.algorithm.algorithm, &s_keyalgo));

    m_KeyAlgo = string(s_keyalgo);

cleanup:
    ::free(s_keyalgo);
    return ret;
}

int CertReqBuilder::setSubjectPublicKeyInfo (const ByteArray* baAlgoId, const ByteArray* baSubjectPublicKey)
{
    int ret = RET_OK;
    char* s_keyalgo = nullptr;

    if (!m_TbsCsrInfo || !baAlgoId || !baSubjectPublicKey) return RET_UAPKI_INVALID_PARAMETER;

    //  Set algorithm(algorithm, parameters)
    DO(asn_decode_ba(get_AlgorithmIdentifier_desc(), &m_TbsCsrInfo->subjectPKInfo.algorithm, baAlgoId));
    DO(asn_oid_to_text(&m_TbsCsrInfo->subjectPKInfo.algorithm.algorithm, &s_keyalgo));

    //  Set publickey
    if (!DstuNS::isDstu4145family(s_keyalgo)) {
        DO(asn_ba2BITSTRING(baSubjectPublicKey, &m_TbsCsrInfo->subjectPKInfo.subjectPublicKey));
    }
    else {
        DO(DstuNS::ba2BitStringEncapOctet(baSubjectPublicKey, &m_TbsCsrInfo->subjectPKInfo.subjectPublicKey));
    }

    m_KeyAlgo = string(s_keyalgo);

cleanup:
    ::free(s_keyalgo);
    return ret;
}

int CertReqBuilder::setSubjectPublicKeyInfo (const UapkiNS::AlgorithmIdentifier& algorithm, const ByteArray* baSubjectPublicKey)
{
    int ret = RET_OK;

    if (!m_TbsCsrInfo || !algorithm.isPresent() || !baSubjectPublicKey) return RET_UAPKI_INVALID_PARAMETER;

    //  Set algorithm(algorithm, parameters)
    DO(asn_set_oid_from_text(algorithm.algorithm.c_str(), &m_TbsCsrInfo->subjectPKInfo.algorithm.algorithm));
    if (algorithm.baParameters) {
        CHECK_NOT_NULL(m_TbsCsrInfo->subjectPKInfo.algorithm.parameters = (ANY_t*)asn_decode_ba_with_alloc(get_ANY_desc(), algorithm.baParameters));
    }

    //  Set publickey
    if (!DstuNS::isDstu4145family(algorithm.algorithm.c_str())) {
        DO(asn_ba2BITSTRING(baSubjectPublicKey, &m_TbsCsrInfo->subjectPKInfo.subjectPublicKey));
    }
    else {
        DO(DstuNS::ba2BitStringEncapOctet(baSubjectPublicKey, &m_TbsCsrInfo->subjectPKInfo.subjectPublicKey));
    }

    m_KeyAlgo = algorithm.algorithm;

cleanup:
    return ret;
}

int CertReqBuilder::addExtensions (const vector<UapkiNS::Extension>& extensions)
{
    int ret = RET_OK;
    ByteArray* ba_extnvalue = nullptr;

    if (!m_TbsCsrInfo) return RET_UAPKI_INVALID_PARAMETER;

    if (!extensions.empty()) {
        DO(encodeExtensions(extensions, &ba_extnvalue));
        DO(attrs_add_attribute(&m_TbsCsrInfo->attributes, OID_PKCS9_EXTENSION_REQUEST, ba_extnvalue));
    }

cleanup:
    ba_free(ba_extnvalue);
    return ret;
}

int CertReqBuilder::encodeTbs (void)
{
    if (!m_TbsCsrInfo) return RET_UAPKI_INVALID_PARAMETER;

    return asn_encode_ba(get_CertificationRequestInfo_desc(), m_TbsCsrInfo, &m_BaTbsEncoded);
}

int CertReqBuilder::encodeCertRequest (const UapkiNS::AlgorithmIdentifier& aidSignature, const ByteArray* baSignature)
{
    int ret = RET_OK;
    X509Tbs_t* csr = nullptr;

    if (!m_BaTbsEncoded || !aidSignature.isPresent() || !baSignature) return RET_UAPKI_INVALID_PARAMETER;

    ASN_ALLOC_TYPE(csr, X509Tbs);

    //  Set TBS-certReqInfo
    DO(asn_decode_ba(get_ANY_desc(), &csr->tbsData, m_BaTbsEncoded));

    //  Set signature(algorithm,parameters)
    DO(asn_set_oid_from_text(aidSignature.algorithm.c_str(), &csr->signAlgo.algorithm));
    if (aidSignature.baParameters) {
        CHECK_NOT_NULL(csr->signAlgo.parameters =
            (ANY_t*)asn_decode_ba_with_alloc(get_ANY_desc(), aidSignature.baParameters));
    }

    //  Set signature(value)
    if (DstuNS::isDstu4145family(aidSignature.algorithm.c_str())) {
        DO(DstuNS::ba2BitStringEncapOctet(baSignature, &csr->signValue));
    }
    else {
        DO(asn_ba2BITSTRING(baSignature, &csr->signValue));
    }

    //  Encode certificate
    DO(asn_encode_ba(get_X509Tbs_desc(), csr, &m_BaCsrEncoded));

cleanup:
    asn_free(get_X509Tbs_desc(), csr);
    return ret;
}

ByteArray* CertReqBuilder::getCsrEncoded (const bool move)
{
    ByteArray* rv_ba = m_BaCsrEncoded;
    if (move) {
        m_BaCsrEncoded = nullptr;
    }
    return rv_ba;
}

int CertReqBuilder::encodeExtensions (const vector<UapkiNS::Extension>& extensions, ByteArray** baEncoded)
{
    int ret = RET_OK;
    Extensions_t* extns = nullptr;

    ASN_ALLOC_TYPE(extns, Extensions_t);

    for (auto& it : extensions) {
        DO(extns_add_extension(extns, it.extnId.c_str(), it.critical, it.baExtnValue));
    }

    DO(asn_encode_ba(get_Extensions_desc(), extns, baEncoded));

cleanup:
    asn_free(get_Extensions_desc(), extns);
    return ret;
}

int CertReqBuilder::nameAddRdName (Name_t* name, const UapkiNS::RdName& rdName)
{
    int ret = RET_OK;
    RelativeDistinguishedName_t* rdname = nullptr;
    AttributeTypeAndValue_t* atav = nullptr;
    ByteArray* ba_encoded = nullptr;

    ASN_ALLOC_TYPE(rdname, RelativeDistinguishedName_t);

    ASN_ALLOC_TYPE(atav, AttributeTypeAndValue_t);
    DO(asn_set_oid_from_text(rdName.type.c_str(), &atav->type));
    switch (rdName.stringType) {
    case UapkiNS::RdName::StringType::PRINTABLE:
        DO(ba_encode_printablestring(rdName.value.c_str(), &ba_encoded));
        break;
    case UapkiNS::RdName::StringType::UTF8:
        DO(ba_encode_utf8string(rdName.value.c_str(), &ba_encoded));
        break;
    default:
        SET_ERROR(RET_UAPKI_NOT_SUPPORTED);
    }
    DO(asn_decode_ba(get_ANY_desc(), &atav->value, ba_encoded));

    DO(ASN_SEQUENCE_ADD(&rdname->list, atav));
    atav = nullptr;

    DO(ASN_SET_ADD(&name->choice.rdnSequence.list, rdname));
    rdname = nullptr;

cleanup:
    asn_free(get_RelativeDistinguishedName_desc(), rdname);
    asn_free(get_AttributeTypeAndValue_desc(), atav);
    ba_free(ba_encoded);
    return ret;
}


}   //  end namespace UapkiNS
