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

#include "archive-timestamp-helper.h"
#include "asn1-ba-utils.h"
#include "ba-utils.h"
#include "byte-array.h"
#include "macros-internal.h"
#include "oid-utils.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"
#include "uapkif.h"


#undef FILE_MARKER
#define FILE_MARKER "common/pkix/archive-timestamp-helper.cpp"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


namespace UapkiNS {

namespace Pkcs7 {


ArchiveTs3Helper::ArchiveTs3Helper (void)
    : m_HashIndAlgorithm(nullptr)
    , m_HashAlgo(HASH_ALG_UNDEFINED)
{
    DEBUG_OUTCON(puts("ArchiveTs3Helper::ArchiveTs3Helper()"));
}

ArchiveTs3Helper::~ArchiveTs3Helper (void)
{
    DEBUG_OUTCON(puts("ArchiveTs3Helper::~ArchiveTs3Helper()"));
}

int ArchiveTs3Helper::init (
        const AlgorithmIdentifier* hashIndAlgorithm
)
{
    if (hashIndAlgorithm) {
        if (hashIndAlgorithm->isPresent()) {
            m_HashAlgo = hash_from_oid(hashIndAlgorithm->algorithm.c_str());
        }
        if (m_HashAlgo == HASH_ALG_UNDEFINED) return RET_UAPKI_INVALID_PARAMETER;

        m_HashIndAlgorithm = hashIndAlgorithm;
    }

    return RET_OK;
}

int ArchiveTs3Helper::setHashContent (
        const string& contentType,
        const ByteArray* baHashContent
)
{
    if (contentType.empty() || !baHashContent) return RET_UAPKI_INVALID_PARAMETER;

    const int ret = ba_encode_oid(contentType.c_str(), &m_Parts.contentType);
    if (ret != RET_OK) return ret;

    if (!m_Parts.hashContent.set(ba_copy_with_alloc(baHashContent, 0, 0))) return RET_UAPKI_GENERAL_ERROR;

    return RET_OK;
}

int ArchiveTs3Helper::setSignerInfo (
        const SignerInfo_t* signerInfo
)
{
    if (!signerInfo) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    SignerInfo_t* signer_info = (SignerInfo_t*)asn_copy_with_alloc(get_SignerInfo_desc(), signerInfo);
    ANY_t* any_unsignedattrs = nullptr;

    if (!signer_info) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    any_unsignedattrs = signer_info->unsignedAttrs;
    signer_info->unsignedAttrs = nullptr;

    DO(asn_encode_ba(get_SignerInfo_desc(), signer_info, &m_Parts.signerInfo));

cleanup:
    signer_info->unsignedAttrs = any_unsignedattrs;
    asn_free(get_SignerInfo_desc(), signer_info);
    return ret;
}

int ArchiveTs3Helper::setUnsignedAttrs (
        const Attributes_t* unsignedAttrs
)
{
    if (!unsignedAttrs) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    Attributes_t* unsigned_attrs = nullptr;
    Attribute_t* attr = nullptr;
    SmartBA sba_encoded;

    unsigned_attrs = (Attributes_t*)asn_copy_with_alloc(get_Attributes_desc(), unsignedAttrs);
    if (!unsigned_attrs) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }
    DO(asn_encode_ba(get_Attributes_desc(), unsigned_attrs, &sba_encoded));
    asn_free(get_Attributes_desc(), unsigned_attrs);

    unsigned_attrs = (Attributes_t*)asn_decode_ba_with_alloc(get_Attributes_desc(), sba_encoded.get());
    if (!unsigned_attrs) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    m_ATSHashIndex.unsignedAttrHashes.reserve((size_t)unsigned_attrs->list.count);
    for (int i = 0; i < unsigned_attrs->list.count; i++) {
        sba_encoded.clear();
        attr = (Attribute_t*)asn_copy_with_alloc(get_Attribute_desc(), unsigned_attrs->list.array[i]);
        if (!unsigned_attrs) {
            SET_ERROR(RET_UAPKI_GENERAL_ERROR);
        }
        DO(asn_encode_ba(get_Attribute_desc(), attr, &sba_encoded));
        asn_free(get_Attribute_desc(), attr);
        attr = nullptr;
        DO(addUnsignedAttr(sba_encoded.get()));
    }

cleanup:
    asn_free(get_Attributes_desc(), unsigned_attrs);
    asn_free(get_Attribute_desc(), attr);
    return ret;
}

int ArchiveTs3Helper::addCertificate (
        const ByteArray* baCertEncoded
)
{
    return hashAndAdd(m_ATSHashIndex.certHashes, baCertEncoded);
}

int ArchiveTs3Helper::addCrl (
        const ByteArray* baCrlEncoded
)
{
    return hashAndAdd(m_ATSHashIndex.crlHashes, baCrlEncoded);
}

int ArchiveTs3Helper::addUnsignedAttr (
        const ByteArray* baAttrEncoded
)
{
    return hashAndAdd(m_ATSHashIndex.unsignedAttrHashes, baAttrEncoded);
}

int ArchiveTs3Helper::calcHash (void)
{
    int ret = RET_UAPKI_INVALID_PARAMETER;
    AttributeHelper::AtsHashIndexBuilder atshi_builder;
    UapkiNS::SmartBA sba_concatdata;
    size_t len, offset = 0;

    DO(atshi_builder.init(*m_HashIndAlgorithm));
    for (const auto& it : m_ATSHashIndex.certHashes) {
        DO(atshi_builder.addHashCert(it));
    }
    for (const auto& it : m_ATSHashIndex.crlHashes) {
        DO(atshi_builder.addHashCrl(it));
    }
    for (const auto& it : m_ATSHashIndex.unsignedAttrHashes) {
        DO(atshi_builder.addHashUnsignedAttr(it));
    }
    DO(atshi_builder.encode());
    (void)m_Parts.atsHashIndex.set(atshi_builder.getEncoded(true));

    DEBUG_OUTCON(printf("ArchiveTs3Helper::calcHash(), contentType, hex: ");  ba_print(stdout, m_Parts.contentType.get()));
    DEBUG_OUTCON(printf("ArchiveTs3Helper::calcHash(), hashContent, hex: ");  ba_print(stdout, m_Parts.hashContent.get()));
    DEBUG_OUTCON(printf("ArchiveTs3Helper::calcHash(), signerInfo, hex: ");  ba_print(stdout, m_Parts.signerInfo.get()));
    DEBUG_OUTCON(printf("ArchiveTs3Helper::calcHash(), atsHashIndex, hex: ");  ba_print(stdout, m_Parts.atsHashIndex.get()));

    len = m_Parts.contentType.size() + m_Parts.hashContent.size() + m_Parts.signerInfo.size() + m_Parts.atsHashIndex.size();
    if (!sba_concatdata.set(ba_alloc_by_len(len))) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    len = m_Parts.contentType.size();
    DO(ba_copy(m_Parts.contentType.get(), 0, len, sba_concatdata.get(), offset));
    offset += len;

    len = m_Parts.hashContent.size();
    DO(ba_copy(m_Parts.hashContent.get(), 0, len, sba_concatdata.get(), offset));
    offset += len;

    len = m_Parts.signerInfo.size();
    DO(ba_copy(m_Parts.signerInfo.get(), 0, len, sba_concatdata.get(), offset));
    offset += len;

    len = m_Parts.atsHashIndex.size();
    DO(ba_copy(m_Parts.atsHashIndex.get(), 0, len, sba_concatdata.get(), offset));

    DEBUG_OUTCON(printf("ArchiveTs3Helper::calcHash(), sba_concatdata, hex: ");  ba_print(stdout, sba_concatdata.get()));

    DO(::hash(m_HashAlgo, sba_concatdata.get(), &m_HashValue));

cleanup:
    return ret;
}

int ArchiveTs3Helper::hashAndAdd (
        VectorBA& hashes,
        const ByteArray* baData
)
{
    if (!baData) return RET_OK;

    ByteArray* ba_hash = nullptr;
    const int ret = ::hash(m_HashAlgo, baData, &ba_hash);
    if (ret == RET_OK) {
        hashes.push_back(ba_hash);
    }
    return ret;
}


}   //  end namespace Pkcs7

}   //  end namespace UapkiNS
