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

#define FILE_MARKER "uapki/crl-item.cpp"

#include <map>
#include <string.h>
#include "crl-item.h"
#include "ba-utils.h"
#include "dirent-internal.h"
#include "extension-helper.h"
#include "macros-internal.h"
#include "oids.h"
#include "time-util.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"
#include "uapki-ns-verify.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;

namespace UapkiNS {

namespace Crl {


static const char* CERT_STATUS_STRINGS[4] = {
    "UNDEFINED", "GOOD", "REVOKED", "UNKNOWN"
};

static const char* CRL_REASON_STRINGS[12] = {
    "UNDEFINED", "UNSPECIFIED", "KEY_COMPROMISE", "CA_COMPROMISE", "AFFILIATION_CHANGED",
    "SUPERSEDED", "CESSATION_OF_OPERATION", "CERTIFICATE_HOLD", "", "REMOVE_FROM_CRL",
    "PRIVILEGE_WITHDRAWN", "AA_COMPROMISE"
};


static int add_revokedcert (
        const uint8_t* bufEncoded,
        size_t lenEncoded,
        size_t offset,
        vector<const RevokedCertItem*>& revokedItems
)
{
    if (offset >= lenEncoded) return RET_UAPKI_INVALID_STRUCT;

    bufEncoded += offset;
    lenEncoded -= offset;

    uint32_t tag;
    size_t hlen, vlen;
    bool ok = Util::decodeAsn1Header(bufEncoded, lenEncoded, tag, hlen, vlen);
    if (!ok || (tag != 0x30) || (hlen + vlen > lenEncoded)) return RET_UAPKI_INVALID_STRUCT;

    RevokedCertificate_t* revoked_cert = (RevokedCertificate_t*)asn_decode_with_alloc(get_RevokedCertificate_desc(), bufEncoded, hlen + vlen);
    if (!revoked_cert) return RET_UAPKI_INVALID_STRUCT;

    int ret = RET_OK;
    uint64_t invalidity_date = 0, revocation_date = 0;
    UapkiNS::CrlReason crl_reason = UapkiNS::CrlReason::UNDEFINED;
    const RevokedCertItem* revcert_item = nullptr;

    DO(Util::pkixTimeFromAsn1(&revoked_cert->revocationDate, revocation_date));
    if (revoked_cert->crlEntryExtensions) {
        uint32_t u32_crlreason = 0;
        ret = ExtensionHelper::getCrlReason(revoked_cert->crlEntryExtensions, u32_crlreason);
        if (ret == RET_OK) {
            crl_reason = (UapkiNS::CrlReason)u32_crlreason;
        }
        ExtensionHelper::getCrlInvalidityDate(revoked_cert->crlEntryExtensions, invalidity_date);
    }

    revcert_item = new RevokedCertItem(revocation_date, crl_reason, invalidity_date);
    if (revcert_item) {
        revokedItems.push_back(revcert_item);
    }

cleanup:
    asn_free(get_RevokedCertificate_desc(), revoked_cert);
    return ret;
}   //  add_revokedcert

static int encode_crlid (
        const TBSCertListAlt_t& tbs,
        const ByteArray* baCrlNumber,
        ByteArray** baIssuerAndSN
)
{
    int ret = RET_OK;
    IssuerAndSerialNumber_t* issuer_and_sn = (IssuerAndSerialNumber_t*)calloc(1, sizeof(IssuerAndSerialNumber_t));
    if (!issuer_and_sn) return RET_UAPKI_GENERAL_ERROR;

    DO(asn_copy(get_Name_desc(), &tbs.issuer, &issuer_and_sn->issuer));
    DO(asn_ba2INTEGER(baCrlNumber, &issuer_and_sn->serialNumber));

    DO(asn_encode_ba(get_IssuerAndSerialNumber_desc(), issuer_and_sn, baIssuerAndSN));

cleanup:
    asn_free(get_IssuerAndSerialNumber_desc(), issuer_and_sn);
    return ret;
}   //  encode_crlid

static int encode_crlidentifier (
        const TBSCertListAlt_t& tbs,
        const ByteArray* baCrlNumber,
        ByteArray** baCrlIdentifier
)
{
    int ret = RET_OK;
    CrlIdentifier_t* crl_identifier = nullptr;
    ByteArray* ba_crlissuedtime = nullptr;

    CHECK_NOT_NULL(crl_identifier = (CrlIdentifier_t*)calloc(1, sizeof(CrlIdentifier_t)));

    DO(asn_copy(get_Name_desc(), &tbs.issuer, &crl_identifier->crlissuer));
    switch (tbs.thisUpdate.present) {
    case PKIXTime_PR_utcTime:
        DO(asn_OCTSTRING2ba(&tbs.thisUpdate.choice.utcTime, &ba_crlissuedtime));
        DO(asn_ba2OCTSTRING(ba_crlissuedtime, &crl_identifier->crlIssuedTime));
        break;
    case PKIXTime_PR_generalTime:
        DO(asn_OCTSTRING2ba(&tbs.thisUpdate.choice.generalTime, &ba_crlissuedtime));
        DO(asn_bytes2OCTSTRING(&crl_identifier->crlIssuedTime, ba_get_buf_const(ba_crlissuedtime) + 2, ba_get_len(ba_crlissuedtime) - 2));
        break;
    default:
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }
    if (baCrlNumber) {
        CHECK_NOT_NULL(crl_identifier->crlNumber = (INTEGER_t*)calloc(1, sizeof(INTEGER_t)));
        DO(asn_ba2INTEGER(baCrlNumber, crl_identifier->crlNumber));
    }

    DO(asn_encode_ba(get_CrlIdentifier_desc(), crl_identifier, baCrlIdentifier));

cleanup:
    asn_free(get_CrlIdentifier_desc(), crl_identifier);
    ba_free(ba_crlissuedtime);
    return ret;
}   //  encode_crlidentifier

static size_t search_offset (
        const vector<RevokedCertOffset>& revokedCertOffsets,
        const size_t offsetSn
)
{
    //  Note: 0 (and 1) - impossible offset value
    if (revokedCertOffsets.empty()) return 0;

    size_t left = 0, right = revokedCertOffsets.size() - 1;
    while (left <= right) {
        size_t mid = left + (right - left) / 2;
        const RevokedCertOffset& item = revokedCertOffsets[mid];
        if (item.offsetSn < offsetSn) {
            left = mid + 1;
        }
        else if (item.offsetSn > offsetSn) {
            right = mid - 1;
        }
        else {
            return item.offset;
        }
    }

    return 0;
}   //  search_offset

static vector<size_t> find_equal_sn (
        const uint8_t* bufEncoded,
        size_t lenEncoded,
        const uint8_t* bufSerialNumber,
        size_t lenSerialNumber,
        const vector<RevokedCertOffset>& revokedCertOffsets
)
{
    vector<size_t> sn_offsets, rv_offsets;
    lenEncoded -= lenSerialNumber;
    for (size_t i = 0; i < lenEncoded; i++, bufEncoded++) {
        if (memcmp(bufEncoded, bufSerialNumber, lenSerialNumber) == 0) {
            sn_offsets.push_back(i);
        }
    }

    for (const auto& it_sn : sn_offsets) {
        const size_t offset = search_offset(revokedCertOffsets, it_sn);
        if (offset > 0) {
            rv_offsets.push_back(offset);
        }
    }

    return rv_offsets;
}   //  find_equal_sn


CrlItem::CrlItem (
        const Type iType
)
    : m_Version(0)
    , m_Type(iType)
    , m_Encoded(nullptr)
    , m_TbsCrl(nullptr)
    , m_CrlId(nullptr)
    , m_Issuer(nullptr)
    , m_ThisUpdate(0)
    , m_NextUpdate(0)
    , m_AuthorityKeyId(nullptr)
    , m_CrlNumber(nullptr)
    , m_DeltaCrl(nullptr)
    , m_StatusSign(Cert::VerifyStatus::UNDEFINED)
    , m_CrlIdentifier(nullptr)
    , m_Actuality(Actuality::UNDEFINED)
{}

CrlItem::~CrlItem (void)
{
    ba_free((ByteArray*)m_Encoded);
    asn_free(get_TBSCertListAlt_desc(), (TBSCertListAlt_t*)m_TbsCrl);
    ba_free((ByteArray*)m_CrlId);
    ba_free((ByteArray*)m_Issuer);
    m_ThisUpdate = 0;
    m_NextUpdate = 0;
    ba_free((ByteArray*)m_AuthorityKeyId);
    ba_free((ByteArray*)m_CrlNumber);
    ba_free((ByteArray*)m_DeltaCrl);
    m_StatusSign = Cert::VerifyStatus::UNDEFINED;
    ba_free((ByteArray*)m_CrlIdentifier);
    for (auto& it : m_CrlHashes) {
        delete it;
    }
}

int CrlItem::generateHash (
        const UapkiNS::AlgorithmIdentifier& aidDigest,
        const UapkiNS::OtherHash** crlHash
)
{
    lock_guard<mutex> lock(m_Mutex);

    if (!aidDigest.isPresent() || !crlHash) return RET_UAPKI_INVALID_PARAMETER;

    for (const auto& it : m_CrlHashes) {
        if (it->hashAlgorithm.algorithm == aidDigest.algorithm) {
            *crlHash = it;
            return RET_OK;
        }
    }

    const HashAlg hash_alg = hash_from_oid(aidDigest.algorithm.c_str());
    if (hash_alg == HashAlg::HASH_ALG_UNDEFINED) return RET_UAPKI_UNSUPPORTED_ALG;

    SmartBA sba_hashvalue;
    const int ret = ::hash(hash_alg, m_Encoded, &sba_hashvalue);
    if (ret != RET_OK) return ret;

    UapkiNS::OtherHash* crl_hash = new UapkiNS::OtherHash();
    if (!crl_hash) return RET_UAPKI_GENERAL_ERROR;
    
    if (!crl_hash->hashAlgorithm.copy(aidDigest)) {
        delete crl_hash;
        return RET_UAPKI_GENERAL_ERROR;
    }
    crl_hash->baHashValue = sba_hashvalue.pop();

    m_CrlHashes.push_back(crl_hash);
    *crlHash = crl_hash;
    return RET_OK;
}

int CrlItem::saveToFile (const string& dirName)
{
    lock_guard<mutex> lock(m_Mutex);

    const string s_fullpath = dirName + m_FileName;
    return ba_to_file(m_Encoded, s_fullpath.c_str());
}

void CrlItem::setActuality (
        const Actuality actuality
)
{
    lock_guard<mutex> lock(m_Mutex);

    m_Actuality = actuality;
}

bool CrlItem::setFileName (
        const string& fileName
)
{
    lock_guard<mutex> lock(m_Mutex);

    m_FileName = fileName;
    return (!m_FileName.empty());
}

int CrlItem::verify (
        const Cert::CerItem* cerIssuer,
        const bool force
)
{
    lock_guard<mutex> lock(m_Mutex);

    if (!force) {
        if (m_StatusSign > Cert::VerifyStatus::INDETERMINATE) return RET_OK;
    }

    m_StatusSign = Cert::VerifyStatus::INDETERMINATE;
    if (!cerIssuer) return RET_OK;

    int ret = RET_OK;
    SmartBA sba_signvalue, sba_tbs;
    string s_signalgo;

    X509Tbs_t* x509_tbs = (X509Tbs_t*)asn_decode_ba_with_alloc(get_X509Tbs_desc(), m_Encoded);
    if (!x509_tbs) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }
    if (!sba_tbs.set(ba_alloc_from_uint8(x509_tbs->tbsData.buf, x509_tbs->tbsData.size))) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    DO(Util::oidFromAsn1(&x509_tbs->signAlgo.algorithm, s_signalgo));
    if (
        oid_is_parent(OID_DSTU4145_WITH_DSTU7564, s_signalgo.c_str()) ||
        oid_is_parent(OID_DSTU4145_WITH_GOST3411, s_signalgo.c_str())
    ) {
        DO(Util::bitStringEncapOctetFromAsn1(&x509_tbs->signValue, &sba_signvalue));
    }
    else {
        DO(asn_BITSTRING2ba(&x509_tbs->signValue, &sba_signvalue));
    }

    ret = Verify::verifySignature(s_signalgo.c_str(), sba_tbs.get(), false, cerIssuer->getSpki(), sba_signvalue.get());
    switch (ret) {
    case RET_OK:
        m_StatusSign = Cert::VerifyStatus::VALID;
        break;
    case RET_VERIFY_FAILED:
        m_StatusSign = Cert::VerifyStatus::INVALID;
        break;
    default:
        m_StatusSign = Cert::VerifyStatus::FAILED;
    }

cleanup:
    asn_free(get_X509Tbs_desc(), x509_tbs);
    return ret;
}

string CrlItem::generateFileName (void) const
{
    string rv_s;
    const string s_authkeyid = Util::baToHex(m_AuthorityKeyId);
    const string s_crlnumber = Util::baToHex(m_CrlNumber);
    if (s_authkeyid.empty() || s_crlnumber.empty()) return rv_s;

    string s_crltype;
    switch (m_Type) {
    case Type::FULL:  s_crltype = "-full-";  break;
    case Type::DELTA: s_crltype = "-delta-"; break;
    default:          s_crltype = "-";       break;
    }

    rv_s = s_authkeyid + s_crltype + s_crlnumber + string(CRL_EXT);
    return rv_s;
}

int CrlItem::parsedRevokedCert (
        const size_t index,
        ByteArray** baSerialNumber,
        uint64_t& revocationDate,
        UapkiNS::CrlReason& crlReason,
        uint64_t& invalidityDate
) const
{
    if (index >= m_RevokedCertOffsets.size()) return RET_UAPKI_INVALID_PARAMETER;

    const uint8_t* buf = m_TbsCrl->revokedCertificates.buf + m_RevokedCertOffsets[index].offset;
    uint32_t tag;
    size_t hlen, vlen;

    if (!Util::decodeAsn1Header(buf, 6, tag, hlen, vlen)) return RET_UAPKI_INVALID_STRUCT;

    int ret = RET_OK;
    RevokedCertificate_t* revoked_cert = (RevokedCertificate_t*)asn_decode_with_alloc(get_RevokedCertificate_desc(), buf, hlen + vlen);
    if (!revoked_cert) return RET_UAPKI_INVALID_STRUCT;

    revocationDate = invalidityDate = 0;
    crlReason = UapkiNS::CrlReason::UNDEFINED;

    DO(asn_INTEGER2ba(&revoked_cert->userCertificate, baSerialNumber));
    DO(Util::pkixTimeFromAsn1(&revoked_cert->revocationDate, revocationDate));

    if (revoked_cert->crlEntryExtensions) {
        uint32_t u32_crlreason = 0;
        ret = ExtensionHelper::getCrlReason(revoked_cert->crlEntryExtensions, u32_crlreason);
        if (ret == RET_OK) {
            crlReason = (CrlReason)u32_crlreason;
        }
        ret = RET_OK;
        (void)ExtensionHelper::getCrlInvalidityDate(revoked_cert->crlEntryExtensions, invalidityDate);
    }

cleanup:
    asn_free(get_RevokedCertificate_desc(), revoked_cert);
    return ret;
}

int CrlItem::revokedCerts (
        const Cert::CerItem* cerSubject,
        vector<const RevokedCertItem*>& revokedItems
)
{
    if (!cerSubject) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    SmartBA sba_snencoded;
    vector<size_t> offsets;

    DEBUG_OUTCON(printf("CrlItem::revokedCerts() cerSubject->baSerialNumber, hex: "); ba_print(stdout, cerSubject->getSerialNumber()));
    DO(Util::encodeInteger(cerSubject->getSerialNumber(), &sba_snencoded));

    if (m_RevokedCertOffsets.empty()) return RET_OK;
    if (sba_snencoded.size() > (size_t)m_TbsCrl->revokedCertificates.size) return RET_UAPKI_INVALID_STRUCT;

    offsets = find_equal_sn(
        m_TbsCrl->revokedCertificates.buf,
        (size_t)m_TbsCrl->revokedCertificates.size,
        sba_snencoded.buf(),
        sba_snencoded.size(),
        m_RevokedCertOffsets
    );

    for (const auto& it : offsets) {
        DO(add_revokedcert(
            m_TbsCrl->revokedCertificates.buf,
            (size_t)m_TbsCrl->revokedCertificates.size,
            it,
            revokedItems
        ));
    }

cleanup:
    return ret;
}



const char* certStatusToStr (
        const UapkiNS::CertStatus status
)
{
    int32_t idx = (int32_t)status + 1;
    return CERT_STATUS_STRINGS[(idx < 4) ? idx : 0];
}

const char* crlReasonToStr (
        const UapkiNS::CrlReason reason
)
{
    int32_t idx = (int32_t)reason + 1;
    return CRL_REASON_STRINGS[(idx < 12) ? idx : 0];
}

int decodeCrlIdentifier (
        const ByteArray* baEncoded,
        ByteArray** baIssuer,
        uint64_t& msIssuedTime,
        ByteArray** baCrlNumber
)
{
    int ret = RET_OK;
    CrlIdentifier_t* crl_identifier = nullptr;

    CHECK_NOT_NULL(crl_identifier = (CrlIdentifier_t*)asn_decode_ba_with_alloc(get_CrlIdentifier_desc(), baEncoded));

    //  =crlIssuer=
    DO(asn_encode_ba(get_Name_desc(), &crl_identifier->crlissuer, baIssuer));
    //  =crlIssuedTime=
    DO(Util::utcTimeFromAsn1(&crl_identifier->crlIssuedTime, msIssuedTime));
    //  =crlNumber= (optional)
    if (crl_identifier->crlNumber) {
        DO(asn_INTEGER2ba(crl_identifier->crlNumber, baCrlNumber));
    }

cleanup:
    asn_free(get_CrlIdentifier_desc(), crl_identifier);
    return ret;
}

const RevokedCertItem* findNearBefore (
        const vector<const RevokedCertItem*>& revokedItems,
        const uint64_t validateTime
)
{
    const RevokedCertItem* rv_item = nullptr;
    if (!revokedItems.empty()) {
        //  Search first near
        for (auto& it : revokedItems) {
            if (validateTime > it->getDate()) {
                rv_item = it;
                break;
            }
        }

        //  Search nearest
        if (rv_item) {
            uint64_t near_date = rv_item->getDate();
            for (auto& it : revokedItems) {
                if (it != rv_item) {
                    const uint64_t cur_date = it->getDate();
                    if ((validateTime > cur_date) && (cur_date > near_date)) {
                        near_date = rv_item->getDate();
                        rv_item = it;
                    }
                }
            }
        }
    }
    return rv_item;
}

bool findRevokedCert (
        const vector<const RevokedCertItem*>& revokedItems,
        const uint64_t validateTime,
        UapkiNS::CertStatus& status,
        RevokedCertItem& revokedCertItem
)
{
    bool rv_isfound = false;
    if (revokedItems.empty()) {
        status = UapkiNS::CertStatus::GOOD;
    }
    else {
        const RevokedCertItem* revcert_before = findNearBefore(revokedItems, validateTime);
        if (revcert_before) {
            DEBUG_OUTCON(printf("revocationDate: %lld  crlReason: %i  invalidityDate: %lld\n",
                revcert_before->revocationDate, revcert_before->crlReason, revcert_before->invalidityDate));
            switch (revcert_before->crlReason) {
            case UapkiNS::CrlReason::REMOVE_FROM_CRL:
                status = UapkiNS::CertStatus::GOOD;
                break;
            case UapkiNS::CrlReason::UNDEFINED:
                status = UapkiNS::CertStatus::UNDEFINED;
                break;
            case UapkiNS::CrlReason::UNSPECIFIED:
                status = UapkiNS::CertStatus::UNKNOWN;
                break;
            default:
                status = UapkiNS::CertStatus::REVOKED;
                revokedCertItem.revocationDate = revcert_before->revocationDate;
                revokedCertItem.crlReason = revcert_before->crlReason;
                revokedCertItem.invalidityDate = revcert_before->invalidityDate;
                break;
            }
            rv_isfound = true;
        }
        else {
            status = UapkiNS::CertStatus::GOOD;
        }
    }
    return rv_isfound;
}

int parseRevokedCerts (
        std::vector<RevokedCertOffset>& Offsets,
        const uint8_t* bufEncoded,
        const int lenEncoded
)
{
    Offsets.clear();
    if (!bufEncoded || (lenEncoded == 0)) return RET_OK;

    uint32_t tag;
    size_t hlen, vlen, offset;
    bool ok = Util::decodeAsn1Header(bufEncoded, (size_t) lenEncoded, tag, hlen, vlen);
    if (!ok || (tag != 0x30) || (hlen + vlen > lenEncoded)) return RET_UAPKI_INVALID_STRUCT;
    if (vlen == 0) return RET_OK;

    bufEncoded += hlen;
    offset = hlen;

    size_t hlen2, vlen2, size2;
    ok = Util::decodeAsn1Header(bufEncoded, vlen, tag, hlen2, vlen2);
    if (!ok || (tag != 0x30) || (vlen2 < 4)) return RET_UAPKI_INVALID_STRUCT;

    size2 = hlen2 + vlen2;
    RevokedCertificate_t* revoked_cert = (RevokedCertificate_t*)asn_decode_with_alloc(get_RevokedCertificate_desc(), bufEncoded, size2);
    if (!revoked_cert) return RET_UAPKI_INVALID_STRUCT;
    asn_free(get_RevokedCertificate_desc(), revoked_cert);
    revoked_cert = nullptr;

    size_t reserved_size = (lenEncoded / (size2)) + 1;
    Offsets.reserve(reserved_size);
    Offsets.push_back(RevokedCertOffset(offset, offset + hlen2));
    bufEncoded += size2;
    offset += size2;
    vlen -= size2;

    while (vlen > 2) {
        ok = Util::decodeAsn1Header(bufEncoded, vlen, tag, hlen2, vlen2);
        if (!ok || (tag != 0x30) || (vlen2 < 4)) return RET_UAPKI_INVALID_STRUCT;

        Offsets.push_back(RevokedCertOffset(offset, offset + hlen2));
        bufEncoded += size2;
        offset += size2;
        vlen -= size2;
    }

    return 0;
}

int parseCrl (
        const ByteArray* baEncoded,
        CrlItem** crlItem
)
{
    if (!baEncoded || !crlItem) return RET_UAPKI_INVALID_PARAMETER;

    X509Tbs_t* x509_tbs = (X509Tbs_t*)asn_decode_ba_with_alloc(get_X509Tbs_desc(), baEncoded);
    if (!x509_tbs || (x509_tbs->tbsData.size < 12)) return RET_UAPKI_INVALID_STRUCT;

    int ret = RET_OK;
    Extensions_t* extns = nullptr;
    unsigned long version = 0;
    SmartBA sba_authoritykeyid;
    SmartBA sba_crlid;
    SmartBA sba_crlident;
    SmartBA sba_crlnumber;
    SmartBA sba_deltacrl;
    SmartBA sba_issuer;
    CrlItem* crl_item = nullptr;
    Type crl_type = Type::UNDEFINED;
    uint64_t this_update = 0, next_update = 0;
    vector<RevokedCertOffset> revcert_offsets;
    CrlItem::Uris uris;

    TBSCertListAlt_t* tbs = (TBSCertListAlt_t*)asn_decode_with_alloc(get_TBSCertListAlt_desc(), x509_tbs->tbsData.buf, x509_tbs->tbsData.size);
    if (!tbs) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

    if (tbs->version) {
        DO(asn_INTEGER2ulong(tbs->version, &version));
    }
    if (version < 1) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT_VERSION);
    }
    if (!Util::equalValuePrimitiveType(tbs->signature.algorithm, x509_tbs->signAlgo.algorithm)) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }
    DO(asn_encode_ba(get_Name_desc(), &tbs->issuer, &sba_issuer));
    DO(Util::pkixTimeFromAsn1(&tbs->thisUpdate, this_update));
    DO(Util::pkixTimeFromAsn1(&tbs->nextUpdate, next_update));

    DO(parseRevokedCerts(revcert_offsets, tbs->revokedCertificates.buf, tbs->revokedCertificates.size));

    extns = tbs->crlExtensions;
    DO(ExtensionHelper::getAuthorityKeyId(extns, &sba_authoritykeyid));
    DO(ExtensionHelper::getCrlNumber(extns, &sba_crlnumber));
    ret = ExtensionHelper::getDeltaCrlIndicator(extns, &sba_deltacrl);
    switch (ret) {
    case RET_OK:
        crl_type = Type::DELTA;
        break;
    case RET_UAPKI_EXTENSION_NOT_PRESENT:
        crl_type = Type::FULL;
        break;
    default:
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }
    DO(encode_crlid(*tbs, sba_crlnumber.get(), &sba_crlid));
    DO(encode_crlidentifier(*tbs, sba_crlnumber.get(), &sba_crlident));
    ret = ExtensionHelper::getCrlUris(extns, OID_X509v3_CRLDistributionPoints, uris.fullCrl);
    if ((ret != RET_OK) && (ret != RET_UAPKI_EXTENSION_NOT_PRESENT)) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }
    ret = ExtensionHelper::getCrlUris(extns, OID_X509v3_FreshestCRL, uris.deltaCrl);
    if ((ret != RET_OK) && (ret != RET_UAPKI_EXTENSION_NOT_PRESENT)) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }
    ret = RET_OK;

    crl_item = new CrlItem(crl_type);
    if (crl_item) {
        crl_item->m_Encoded = baEncoded;
        crl_item->m_Version = (uint32_t)version;
        crl_item->m_TbsCrl = tbs;
        crl_item->m_CrlId = sba_crlid.pop();
        crl_item->m_Issuer = sba_issuer.pop();
        crl_item->m_ThisUpdate = this_update;
        crl_item->m_NextUpdate = next_update;
        crl_item->m_RevokedCertOffsets = revcert_offsets;
        crl_item->m_AuthorityKeyId = sba_authoritykeyid.pop();
        crl_item->m_CrlNumber = sba_crlnumber.pop();
        crl_item->m_DeltaCrl = sba_deltacrl.pop();
        crl_item->m_CrlIdentifier = sba_crlident.pop();
        crl_item->m_Uris = uris;

        tbs = nullptr;

        *crlItem = crl_item;
        crl_item = nullptr;
    }

cleanup:
    asn_free(get_TBSCertListAlt_desc(), tbs);
    asn_free(get_X509Tbs_desc(), x509_tbs);
    delete crl_item;
    return ret;
}


}   //  end namespace Crl

}   //  end namespace UapkiNS
