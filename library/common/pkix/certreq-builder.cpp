/*
 * Copyright (c) 2021, The UAPKI Project Authors.
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

#define FILE_MARKER "common/pkix/certreq-builder.cpp"

#include "certreq-builder.h"
#include "ba-utils.h"
#include "dstu-ns.h"
#include "macros-internal.h"
#include "oid-utils.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"
#include <stdio.h>


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;

namespace UapkiNS {


CertReqBuilder::CertReqBuilder (void)
    : m_TbsCsrInfo(nullptr)
{
    DEBUG_OUTCON(puts("CertReqBuilder::CertReqBuilder()"));
}

CertReqBuilder::~CertReqBuilder (void)
{
    DEBUG_OUTCON(puts("CertReqBuilder::~CertReqBuilder()"));
    asn_free(get_CertificationRequestInfo_desc(), m_TbsCsrInfo);
}

int CertReqBuilder::init (
        const uint32_t version
)
{
    if (version < 1) return RET_UAPKI_INVALID_PARAMETER;

    m_TbsCsrInfo = (CertificationRequestInfo_t*)calloc(1, sizeof(CertificationRequestInfo_t));
    if (!m_TbsCsrInfo) return RET_UAPKI_GENERAL_ERROR;

    m_TbsCsrInfo->subject.present = Name_PR_rdnSequence;
    const int ret = asn_ulong2INTEGER(&m_TbsCsrInfo->version, (unsigned long)version - 1);
    return ret;
}

int CertReqBuilder::init (
    const ByteArray* tbsEncoded
)
{
    if (!tbsEncoded) return RET_UAPKI_INVALID_PARAMETER;

    m_TbsCsrInfo = (CertificationRequestInfo_t*)asn_decode_ba_with_alloc(get_CertificationRequestInfo_desc(), tbsEncoded);
    return m_TbsCsrInfo ? RET_OK : RET_UAPKI_INVALID_STRUCT;
}

int CertReqBuilder::setSubject (
        const ByteArray* nameEncoded
)
{
    if (!m_TbsCsrInfo || (ba_get_len(nameEncoded) == 0)) return RET_UAPKI_INVALID_PARAMETER;

    return asn_decode_ba(get_Name_desc(), &m_TbsCsrInfo->subject, nameEncoded);
}

int CertReqBuilder::setSubject (
        const vector<UapkiNS::RdName>& rdNames
)
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

int CertReqBuilder::setSubjectPublicKeyInfo (
        const ByteArray* spkiEncoded
)
{
    int ret = RET_OK;

    if (!m_TbsCsrInfo || !spkiEncoded) return RET_UAPKI_INVALID_PARAMETER;

    DO(asn_decode_ba(get_SubjectPublicKeyInfo_desc(), &m_TbsCsrInfo->subjectPKInfo, spkiEncoded));
    DO(Util::oidFromAsn1(&m_TbsCsrInfo->subjectPKInfo.algorithm.algorithm, m_KeyAlgo));

cleanup:
    return ret;
}

int CertReqBuilder::setSubjectPublicKeyInfo (
        const ByteArray* algoIdEncoded,
        const ByteArray* publicKey
)
{
    int ret = RET_OK;

    if (!m_TbsCsrInfo || !algoIdEncoded || !publicKey) return RET_UAPKI_INVALID_PARAMETER;

    //  Set algorithm(algorithm, parameters)
    DO(asn_decode_ba(get_AlgorithmIdentifier_desc(), &m_TbsCsrInfo->subjectPKInfo.algorithm, algoIdEncoded));
    DO(Util::oidFromAsn1(&m_TbsCsrInfo->subjectPKInfo.algorithm.algorithm, m_KeyAlgo));

    //  Set publickey
    if (!DstuNS::isDstu4145family(m_KeyAlgo)) {
        DO(asn_ba2BITSTRING(publicKey, &m_TbsCsrInfo->subjectPKInfo.subjectPublicKey));
    }
    else {
        DO(DstuNS::ba2BitStringEncapOctet(publicKey, &m_TbsCsrInfo->subjectPKInfo.subjectPublicKey));
    }

cleanup:
    return ret;
}

int CertReqBuilder::setSubjectPublicKeyInfo (
        const UapkiNS::AlgorithmIdentifier& algorithm,
        const ByteArray* publicKey
)
{
    int ret = RET_OK;

    if (!m_TbsCsrInfo || !algorithm.isPresent() || !publicKey) return RET_UAPKI_INVALID_PARAMETER;

    //  Set algorithm(algorithm, parameters)
    DO(asn_set_oid_from_text(algorithm.algorithm.c_str(), &m_TbsCsrInfo->subjectPKInfo.algorithm.algorithm));
    if (algorithm.baParameters) {
        CHECK_NOT_NULL(m_TbsCsrInfo->subjectPKInfo.algorithm.parameters = (ANY_t*)asn_decode_ba_with_alloc(get_ANY_desc(), algorithm.baParameters));
    }

    //  Set publickey
    if (!DstuNS::isDstu4145family(algorithm.algorithm.c_str())) {
        DO(asn_ba2BITSTRING(publicKey, &m_TbsCsrInfo->subjectPKInfo.subjectPublicKey));
    }
    else {
        DO(DstuNS::ba2BitStringEncapOctet(publicKey, &m_TbsCsrInfo->subjectPKInfo.subjectPublicKey));
    }

    m_KeyAlgo = algorithm.algorithm;

cleanup:
    return ret;
}

int CertReqBuilder::addExtensions (
        const ByteArray* extensionsEncoded
)
{
    int ret = RET_OK;
    SmartBA sba_extnvalue;

    if (!m_TbsCsrInfo) return RET_UAPKI_INVALID_PARAMETER;

    if (extensionsEncoded) {
        DO(Util::addToAttributes(&m_TbsCsrInfo->attributes, OID_PKCS9_EXTENSION_REQUEST, extensionsEncoded));
    }

cleanup:
    return ret;
}

int CertReqBuilder::addExtensions (
        const vector<UapkiNS::Extension>& extensions
)
{
    int ret = RET_OK;
    SmartBA sba_extnvalue;

    if (!extensions.empty()) {
        DO(encodeExtensions(extensions, &sba_extnvalue));
        DO(addExtensions(sba_extnvalue.get()));
    }

cleanup:
    return ret;
}

int CertReqBuilder::addExtensions (
        const vector<ByteArray*>& vbaEncodedExtensions
)
{
    int ret = RET_OK;
    SmartBA sba_extnvalue;

    if (!vbaEncodedExtensions.empty()) {
        DO(encodeExtensions(vbaEncodedExtensions, &sba_extnvalue));
        DO(addExtensions(sba_extnvalue.get()));
    }

cleanup:
    return ret;
}

int CertReqBuilder::encodeTbs (void)
{
    if (!m_TbsCsrInfo) return RET_UAPKI_INVALID_PARAMETER;

    return asn_encode_ba(get_CertificationRequestInfo_desc(), m_TbsCsrInfo, &m_TbsEncoded);
}

int CertReqBuilder::encodeCertRequest (
        const char* signAlgo,
        const ByteArray* signAlgoParam,
        const ByteArray* signature
)
{
    int ret = RET_OK;
    X509Tbs_t* csr = nullptr;

    if (m_TbsEncoded.empty() || !signAlgo || !signature) return RET_UAPKI_INVALID_PARAMETER;

    ASN_ALLOC_TYPE(csr, X509Tbs);

    //  Set TBS-certReqInfo
    DO(asn_decode_ba(get_ANY_desc(), &csr->tbsData, m_TbsEncoded.get()));

    //  Set signature(algorithm,parameters)
    DO(asn_set_oid_from_text(signAlgo, &csr->signAlgo.algorithm));
    if (ba_get_len(signAlgoParam) > 0) {
        CHECK_NOT_NULL(csr->signAlgo.parameters =
            (ANY_t*)asn_decode_ba_with_alloc(get_ANY_desc(), signAlgoParam));
    }

    //  Set signature(value)
    if (DstuNS::isDstu4145family(signAlgo)) {
        DO(DstuNS::ba2BitStringEncapOctet(signature, &csr->signValue));
    }
    else {
        DO(asn_ba2BITSTRING(signature, &csr->signValue));
    }

    //  Encode certificate
    DO(asn_encode_ba(get_X509Tbs_desc(), csr, &m_CsrEncoded));

cleanup:
    asn_free(get_X509Tbs_desc(), csr);
    return ret;
}

int CertReqBuilder::encodeCertRequest (
        const UapkiNS::AlgorithmIdentifier& aidSignature,
        const ByteArray* signature
)
{
    if (!aidSignature.isPresent()) return RET_UAPKI_INVALID_PARAMETER;

    return encodeCertRequest(aidSignature.algorithm.c_str(), aidSignature.baParameters, signature);
}

ByteArray* CertReqBuilder::getCsrEncoded (
        const bool move
)
{
    return (move) ? m_CsrEncoded.pop() : m_CsrEncoded.get();
}

int CertReqBuilder::encodeExtensions (
        const vector<UapkiNS::Extension>& extensions,
        ByteArray** encoded
)
{
    int ret = RET_OK;
    Extensions_t* extns = nullptr;

    ASN_ALLOC_TYPE(extns, Extensions_t);

    for (auto& it : extensions) {
        DO(Util::addToExtensions(extns, it.extnId.c_str(), it.critical, it.baExtnValue));
    }

    DO(asn_encode_ba(get_Extensions_desc(), extns, encoded));

cleanup:
    asn_free(get_Extensions_desc(), extns);
    return ret;
}

int CertReqBuilder::encodeExtensions (
        const vector<ByteArray*>& vbaEncodedExtensions,
        ByteArray** encoded
)
{
    int ret = RET_OK;
    Extensions_t* extns = nullptr;

    ASN_ALLOC_TYPE(extns, Extensions_t);

    for (auto& it : vbaEncodedExtensions) {
        UapkiNS::Extension extn;
        DO(Util::decodeExtension(it, extn));
        DO(Util::addToExtensions(extns, extn.extnId.c_str(), extn.critical, extn.baExtnValue));
    }

    DO(asn_encode_ba(get_Extensions_desc(), extns, encoded));

cleanup:
    asn_free(get_Extensions_desc(), extns);
    return ret;
}

int CertReqBuilder::nameAddRdName (
        Name_t* name,
        const UapkiNS::RdName& rdName
)
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
        DO(Util::encodePrintableString(rdName.value.c_str(), &ba_encoded));
        break;
    case UapkiNS::RdName::StringType::UTF8:
        DO(Util::encodeUtf8string(rdName.value.c_str(), &ba_encoded));
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
