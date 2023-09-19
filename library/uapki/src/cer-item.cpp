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

#define FILE_MARKER "uapki/cer-item.cpp"

#include <string.h>
#include "cer-item.h"
#include "ba-utils.h"
#include "dstu-ns.h"
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

namespace Cert {


#ifdef DEBUG_CERITEM_INFO
string debug_ceritem_info_get_commonname (const Name_t& name)
{
    string rv_s;
    if (name.present != Name_PR_rdnSequence) return rv_s;

    for (size_t i = 0; i < name.choice.rdnSequence.list.count; i++) {
        const RelativeDistinguishedName_t* rdname_src = name.choice.rdnSequence.list.array[i];
        for (size_t j = 0; j < rdname_src->list.count; j++) {
            const AttributeTypeAndValue_t* attr = rdname_src->list.array[j];
            if (OID_is_equal_oid(&attr->type, OID_X520_CommonName)) {
                const int ret = Util::decodeAnyString(attr->value.buf, (const size_t)attr->value.size, rv_s);
                if (ret == RET_OK) break;
            }
        }
    }
    return rv_s;
}   //  debug_ceritem_info_get_commonname

void debug_ceritem_info (CerItem& cerItem)
{
    cerItem.devsSubject = debug_ceritem_info_get_commonname(cerItem.getCert()->tbsCertificate.subject);
    cerItem.devsIssuerAndSn = Util::baToHex(cerItem.getSerialNumber())
        + string("; ") + debug_ceritem_info_get_commonname(cerItem.getCert()->tbsCertificate.issuer);
    cerItem.devsValidity = TimeUtil::mtimeToFtime(cerItem.getNotBefore())
        + string(" - ") + TimeUtil::mtimeToFtime(cerItem.getNotAfter());
}   //  debug_ceritem_info
#endif

static int encode_issuer_and_sn (
        const TBSCertificate_t* tbsCert,
        ByteArray** baIssuerAndSN
)
{
    int ret = RET_OK;
    IssuerAndSerialNumber_t* issuer_and_sn = nullptr;

    if (!tbsCert || !baIssuerAndSN) return RET_UAPKI_INVALID_PARAMETER;

    CHECK_NOT_NULL(issuer_and_sn = (IssuerAndSerialNumber_t*)calloc(1, sizeof(IssuerAndSerialNumber_t)));

    DO(asn_copy(get_Name_desc(), &tbsCert->issuer, &issuer_and_sn->issuer));
    DO(asn_copy(get_INTEGER_desc(), &tbsCert->serialNumber, &issuer_and_sn->serialNumber));

    DO(asn_encode_ba(get_IssuerAndSerialNumber_desc(), issuer_and_sn, baIssuerAndSN));

cleanup:
    asn_free(get_IssuerAndSerialNumber_desc(), issuer_and_sn);
    return ret;
}   //  encode_issuer_and_sn

static int scan_and_parse_uris (
        const Extensions_t& extns,
        CerItem::Uris& uris
)
{
    int ret = RET_OK;
    for (int i = 0; i < extns.list.count; i++) {
        const Extension_t* extn = extns.list.array[i];
        if (OID_is_equal_oid(&extn->extnID, OID_X509v3_CRLDistributionPoints)) {
            SmartBA sba_extnvalue;
            DO(asn_OCTSTRING2ba(&extn->extnValue, &sba_extnvalue));
            DO(ExtensionHelper::decodeDistributionPoints(sba_extnvalue.get(), uris.fullCrl));
        }
        else if (OID_is_equal_oid(&extn->extnID, OID_X509v3_FreshestCRL)) {
            SmartBA sba_extnvalue;
            DO(asn_OCTSTRING2ba(&extn->extnValue, &sba_extnvalue));
            DO(ExtensionHelper::decodeDistributionPoints(sba_extnvalue.get(), uris.deltaCrl));
        }
        else if (OID_is_equal_oid(&extn->extnID, OID_PKIX_AuthorityInfoAccess)) {
            SmartBA sba_extnvalue;
            DO(asn_OCTSTRING2ba(&extn->extnValue, &sba_extnvalue));
            DO(ExtensionHelper::decodeAccessDescriptions(sba_extnvalue.get(), OID_PKIX_OCSP, uris.ocsp));
        }
        else if (OID_is_equal_oid(&extn->extnID, OID_PKIX_SubjectInfoAccess)) {
            SmartBA sba_extnvalue;
            DO(asn_OCTSTRING2ba(&extn->extnValue, &sba_extnvalue));
            DO(ExtensionHelper::decodeAccessDescriptions(sba_extnvalue.get(), OID_PKIX_TimeStamping, uris.tsp));
        }
    }

cleanup:
    return ret;
}   //  scan_and_parse_uris


CertStatusInfo::CertStatusInfo (
        const ValidationType validationType
)
    : type(validationType)
    , needUpdate(true)
    , baResult(nullptr)
    , status(UapkiNS::CertStatus::UNDEFINED)
    , validTime(0)
{
}

CertStatusInfo::~CertStatusInfo (void)
{
    reset();
}

bool CertStatusInfo::isExpired (
        const uint64_t time
)
{
    needUpdate = (time > validTime);
    return needUpdate;
}

void CertStatusInfo::reset (void)
{
    ba_free(baResult);
    baResult = nullptr;
    status = UapkiNS::CertStatus::UNDEFINED;
    validTime = 0;
}

int CertStatusInfo::set (
        const UapkiNS::CertStatus status,
        const uint64_t validTime,
        const ByteArray* baResult
)
{
    reset();
    this->needUpdate = false;
    this->status = status;
    this->validTime = validTime;
    this->baResult = ba_copy_with_alloc(baResult, 0, 0);
    return (this->baResult) ? RET_OK : RET_UAPKI_GENERAL_ERROR;
}


CerItem::CerItem (void)
    : m_Encoded(nullptr)
    , m_Cert(nullptr)
    , m_AuthorityKeyId(nullptr)
    , m_CertId(nullptr)
    , m_SerialNumber(nullptr)
    , m_KeyId(nullptr)
    , m_Issuer(nullptr)
    , m_Subject(nullptr)
    , m_Spki(nullptr)
    , m_AlgoKeyId(HashAlg::HASH_ALG_UNDEFINED)
    , m_NotBefore(0)
    , m_NotAfter(0)
    , m_KeyUsage(0)
    , m_Trusted(false)
    , m_VerifyStatus(VerifyStatus::UNDEFINED)
    , m_CertStatusByCrl(ValidationType::CRL)
    , m_CertStatusByOcsp(ValidationType::OCSP)
    , m_MarkedToRemove(false)
{
}

CerItem::~CerItem (void)
{
    ba_free((ByteArray*)m_Encoded);
    asn_free(get_Certificate_desc(), (Certificate_t*)m_Cert);
    ba_free((ByteArray*)m_AuthorityKeyId);
    ba_free((ByteArray*)m_CertId);
    ba_free((ByteArray*)m_SerialNumber);
    ba_free((ByteArray*)m_KeyId);
    ba_free((ByteArray*)m_Issuer);
    ba_free((ByteArray*)m_Subject);
    ba_free((ByteArray*)m_Spki);
    m_AlgoKeyId = HashAlg::HASH_ALG_UNDEFINED;
    m_NotBefore = 0;
    m_NotAfter = 0;
    m_KeyUsage = 0;
    m_VerifyStatus = VerifyStatus::UNDEFINED;
    for (auto& it : m_EssCertIds) {
        delete it;
    }
}

int CerItem::generateEssCertId (
        const UapkiNS::AlgorithmIdentifier& aidDigest,
        const UapkiNS::EssCertId** essCertId
)
{
    lock_guard<mutex> lock(m_Mutex);

    if (!aidDigest.isPresent() || !essCertId) return RET_UAPKI_INVALID_PARAMETER;

    for (const auto& it : m_EssCertIds) {
        if (it->hashAlgorithm.algorithm == aidDigest.algorithm) {
            *essCertId = it;
            return RET_OK;
        }
    }

    const HashAlg hash_alg = hash_from_oid(aidDigest.algorithm.c_str());
    if (hash_alg == HashAlg::HASH_ALG_UNDEFINED) return RET_UAPKI_UNSUPPORTED_ALG;

    SmartBA sba_hashvalue;
    int ret = ::hash(hash_alg, m_Encoded, &sba_hashvalue);
    if (ret != RET_OK) return ret;

    UapkiNS::EssCertId* ess_certid = new UapkiNS::EssCertId();
    if (!ess_certid) return RET_UAPKI_GENERAL_ERROR;

    if (!ess_certid->hashAlgorithm.copy(aidDigest)) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }
    ess_certid->baHashValue = sba_hashvalue.pop();
    DO(issuerToGeneralNames(m_Issuer, &ess_certid->issuerSerial.baIssuer));
    ess_certid->issuerSerial.baSerialNumber = ba_copy_with_alloc(m_SerialNumber, 0, 0);
    if (!ess_certid->issuerSerial.baSerialNumber) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    m_EssCertIds.push_back(ess_certid);
    *essCertId = ess_certid;
    ess_certid = nullptr;

cleanup:
    delete ess_certid;
    return ret;
}

void CerItem::markToRemove (
        const bool marked
)
{
    lock_guard<mutex> lock(m_Mutex);

    m_MarkedToRemove = marked;
}

bool CerItem::setFileName (
        const std::string& fileName
)
{
    lock_guard<mutex> lock(m_Mutex);

    m_FileName = fileName;
    return (!m_FileName.empty());
}

void CerItem::setTrusted (
        const bool trusted
)
{
    lock_guard<mutex> lock(m_Mutex);

    m_Trusted = trusted;
}

int CerItem::verify (
        const CerItem* cerIssuer,
        const bool force
)
{
    lock_guard<mutex> lock(m_Mutex);

    if (!force) {
        if (m_VerifyStatus > VerifyStatus::INDETERMINATE) return RET_OK;
    }

    m_VerifyStatus = VerifyStatus::INDETERMINATE;
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

    DO(Util::oidFromAsn1(&m_Cert->signatureAlgorithm.algorithm, s_signalgo));
    if (m_AlgoKeyId == HASH_ALG_GOST34311) {
        DO(Util::bitStringEncapOctetFromAsn1(&m_Cert->signature, &sba_signvalue));
    }
    else {
        DO(asn_BITSTRING2ba(&m_Cert->signature, &sba_signvalue));
    }

    ret = Verify::verifySignature(s_signalgo.c_str(), sba_tbs.get(), false, cerIssuer->getSpki(), sba_signvalue.get());
    switch (ret) {
    case RET_OK:
        m_VerifyStatus = VerifyStatus::VALID;
        break;
    case RET_VERIFY_FAILED:
        m_VerifyStatus = VerifyStatus::INVALID;
        break;
    default:
        m_VerifyStatus = VerifyStatus::FAILED;
        break;
    }

    if (m_VerifyStatus == VerifyStatus::VALID) {
        bool is_digitalsign = false;
        DO(cerIssuer->keyUsageByBit(KeyUsage_keyCertSign, is_digitalsign));
        if (!is_digitalsign) {
            m_VerifyStatus = VerifyStatus::VALID_WITHOUT_KEYUSAGE;
        }
    }

cleanup:
    asn_free(get_X509Tbs_desc(), x509_tbs);
    return ret;
}

int CerItem::checkValidity (
        const uint64_t validateTime
) const
{
    if ((m_NotBefore == 0) || (m_NotAfter == 0)) return RET_UAPKI_TIME_ERROR;

    if (m_NotBefore > validateTime) return RET_UAPKI_CERT_VALIDITY_NOT_BEFORE_ERROR;

    if (m_NotAfter < validateTime) return RET_UAPKI_CERT_VALIDITY_NOT_AFTER_ERROR;

    return RET_OK;
}

string CerItem::generateFileName (void) const
{
    string rv_s;
    const string s_keyid = Util::baToHex(m_KeyId);
    string s_authkeyid = Util::baToHex(m_AuthorityKeyId);
    if (s_keyid.empty() || s_authkeyid.empty()) return rv_s;

    if (s_authkeyid.length() > 16) {
        s_authkeyid.resize(16);
    }

    rv_s = s_keyid + string("-") + s_authkeyid + string(CER_EXT);
    return rv_s;
}

int CerItem::getIssuerAndSN (
        ByteArray** baIssuerAndSN
) const
{
    const int ret = encode_issuer_and_sn(&m_Cert->tbsCertificate, baIssuerAndSN);
    return ret;
}

int CerItem::keyUsageByBit (
        const uint32_t bitNum,
        bool& bitValue
) const
{
    const uint32_t masked_bit = (uint32_t)(1 << bitNum);
    bitValue = ((m_KeyUsage & masked_bit) > 0);
    return RET_OK;
}



bool addCertIfUnique (
        vector<CerItem*>& cerItems,
        CerItem* cerItem
)
{
    if (!cerItem) return false;

    for (const auto& it : cerItems) {
        if (ba_cmp(cerItem->getCertId(), it->getCertId()) == 0) return false;
    }
    cerItems.push_back(cerItem);
    return true;
}

int calcKeyId (
        const HashAlg algoKeyId,
        const ByteArray* baPubkey,
        ByteArray** baKeyId
)
{
    int ret = RET_OK;
    const ByteArray* ref_ba = nullptr;
    ByteArray* ba_encappubkey = nullptr;

    CHECK_PARAM(baPubkey != nullptr);
    CHECK_PARAM(baKeyId != nullptr);

    if (algoKeyId == HASH_ALG_GOST34311) {
        DO(Util::encodeOctetString(baPubkey, &ba_encappubkey));
        ref_ba = ba_encappubkey;
    }
    else {
        ref_ba = baPubkey;
    }

    DO(::hash(algoKeyId, ref_ba, baKeyId));

cleanup:
    ba_free(ba_encappubkey);
    return ret;
}

int encodeIssuerAndSN (
        const ByteArray* baIssuer,
        const ByteArray* baSerialNumber,
        ByteArray** baIssuerAndSN
)
{
    int ret = RET_OK;
    IssuerAndSerialNumber_t* issuer_and_sn = nullptr;

    if (!baIssuer || !baSerialNumber || !baIssuerAndSN) return RET_UAPKI_INVALID_PARAMETER;

    CHECK_NOT_NULL(issuer_and_sn = (IssuerAndSerialNumber_t*)calloc(1, sizeof(IssuerAndSerialNumber_t)));

    DO(asn_decode_ba(get_Name_desc(), &issuer_and_sn->issuer, baIssuer));
    DO(asn_ba2INTEGER(baSerialNumber, &issuer_and_sn->serialNumber));

    DO(asn_encode_ba(get_IssuerAndSerialNumber_desc(), issuer_and_sn, baIssuerAndSN));

cleanup:
    asn_free(get_IssuerAndSerialNumber_desc(), issuer_and_sn);
    return ret;
}

CerItem* findCertByCertId (
        const vector<CerItem*>& cerItems,
        const ByteArray* baCertId
)
{
    for (size_t i = 0; i < cerItems.size(); i++) {
        if (ba_cmp(baCertId, cerItems[i]->getCertId()) == 0) {
            return cerItems[i];
        }
    }
    return nullptr;
}

int issuerFromGeneralNames (
        const ByteArray* baEncoded,
        ByteArray** baIssuer
)
{
    int ret = RET_OK;
    GeneralNames_t* general_names = nullptr;
    bool is_found = false;

    if (!baEncoded || !baIssuer) return RET_UAPKI_INVALID_PARAMETER;

    CHECK_NOT_NULL(general_names = (GeneralNames_t*)asn_decode_ba_with_alloc(get_GeneralNames_desc(), baEncoded));

    for (int i = 0; i < general_names->list.count; i++) {
        GeneralName_t& general_name = *general_names->list.array[i];
        if (general_name.present == GeneralName_PR_directoryName) {
            DO(asn_encode_ba(get_Name_desc(), &general_name.choice.directoryName, baIssuer));
            is_found = true;
            break;
        }
    }

    if (!is_found) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

cleanup:
    asn_free(get_GeneralNames_desc(), general_names);
    return ret;
}

int issuerToGeneralNames (
        const ByteArray* baIssuer,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    GeneralName_t* general_name = nullptr;
    GeneralNames_t* general_names = nullptr;

    if (!baIssuer || !baEncoded) return RET_UAPKI_INVALID_PARAMETER;

    ASN_ALLOC_TYPE(general_name, GeneralName_t);
    general_name->present = GeneralName_PR_directoryName;
    DO(asn_decode_ba(get_Name_desc(), &general_name->choice.directoryName, baIssuer));

    ASN_ALLOC_TYPE(general_names, GeneralNames_t);
    DO(ASN_SET_ADD(&general_names->list, (void*)general_name));
    general_name = nullptr;

    DO(asn_encode_ba(get_GeneralNames_desc(), general_names, baEncoded));

cleanup:
    asn_free(get_GeneralName_desc(), general_name);
    asn_free(get_GeneralNames_desc(), general_names);
    return ret;
}

int keyIdFromSID (
        const ByteArray* baEncoded,
        ByteArray** baKeyId
)
{
    int ret = RET_OK;
    SignerIdentifier_t* sid = nullptr;

    if ((ba_get_len(baEncoded) < 3) || !baKeyId) return RET_UAPKI_INVALID_PARAMETER;

    CHECK_NOT_NULL(sid = (SignerIdentifier_t*)asn_decode_ba_with_alloc(get_SignerIdentifier_desc(), baEncoded));
    if (sid->present == SignerIdentifier_PR_subjectKeyIdentifier) {
        DO(asn_OCTSTRING2ba(&sid->choice.subjectKeyIdentifier, baKeyId));
    }
    else {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

cleanup:
    asn_free(get_SignerIdentifier_desc(), sid);
    return ret;
}

int keyIdToSID (
        const ByteArray* baKeyId,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    SignerIdentifier_t* sid = nullptr;

    if ((ba_get_len(baKeyId) == 0) || !baEncoded) return RET_UAPKI_INVALID_PARAMETER;

    ASN_ALLOC_TYPE(sid, SignerIdentifier_t);
    sid->present = SignerIdentifier_PR_subjectKeyIdentifier;
    DO(asn_ba2OCTSTRING(baKeyId, &sid->choice.subjectKeyIdentifier));

    DO(asn_encode_ba(get_SignerIdentifier_desc(), sid, baEncoded));

cleanup:
    asn_free(get_SignerIdentifier_desc(), sid);
    return ret;
}

int parseCert (
        const ByteArray* baEncoded,
        CerItem** cerItem
)
{
    if (!baEncoded || !cerItem) return RET_UAPKI_INVALID_PARAMETER;

    Certificate_t* cert = (Certificate_t*)asn_decode_ba_with_alloc(get_Certificate_desc(), baEncoded);
    if (!cert || !cert->tbsCertificate.extensions) return RET_UAPKI_INVALID_STRUCT;

    int ret = RET_OK;
    TBSCertificate_t& tbs = cert->tbsCertificate;
    Extensions_t* extns = tbs.extensions;
    SmartBA sba_authoritykeyid;
    SmartBA sba_certid;
    SmartBA sba_encoded;
    SmartBA sba_issuer;
    SmartBA sba_keyid;
    SmartBA sba_pubkey;
    SmartBA sba_serialnum;
    SmartBA sba_spki;
    SmartBA sba_subject;
    CerItem* cer_item = nullptr;
    HashAlg algo_keyid = HASH_ALG_SHA1;
    string s_keyalgo;
    uint64_t not_after = 0, not_before = 0;
    uint32_t key_usage = 0;
    CerItem::Uris uris;

    DO(asn_INTEGER2ba(&tbs.serialNumber, &sba_serialnum));
    DO(asn_encode_ba(get_Name_desc(), &tbs.issuer, &sba_issuer));
    DO(Util::pkixTimeFromAsn1(&tbs.validity.notBefore, not_before));
    DO(Util::pkixTimeFromAsn1(&tbs.validity.notAfter, not_after));
    DO(asn_encode_ba(get_Name_desc(), &tbs.subject, &sba_subject));
    DO(asn_encode_ba(get_SubjectPublicKeyInfo_desc(), &tbs.subjectPublicKeyInfo, &sba_spki));
    DO(Util::oidFromAsn1(&tbs.subjectPublicKeyInfo.algorithm.algorithm, s_keyalgo));
    if (DstuNS::isDstu4145family(s_keyalgo)) {
        algo_keyid = HASH_ALG_GOST34311;
        //  Note: calcKeyId() automatic wrapped pubkey into octet-string before compute hash
        DO(Util::bitStringEncapOctetFromAsn1(&tbs.subjectPublicKeyInfo.subjectPublicKey, &sba_pubkey));
    }
    else {
        DO(asn_BITSTRING2ba(&tbs.subjectPublicKeyInfo.subjectPublicKey, &sba_pubkey));
    }

    DO(calcKeyId(algo_keyid, sba_pubkey.get(), &sba_keyid));
    DO(encode_issuer_and_sn(&tbs, &sba_certid));

    ret = ExtensionHelper::getKeyUsage(extns, key_usage);
    if (ret != RET_OK) {
        if (ret == RET_UAPKI_EXTENSION_NOT_PRESENT) {
            key_usage = 0;
            ret = RET_OK;
        }
    }
    //  Required attribute authorityKeyIdentifier
    DO(ExtensionHelper::getAuthorityKeyId(extns, &sba_authoritykeyid));

    DO(scan_and_parse_uris(*extns, uris));

    if (!sba_encoded.set(ba_copy_with_alloc(baEncoded, 0, 0))) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    cer_item = new CerItem();
    if (!cer_item) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    cer_item->m_Encoded = sba_encoded.pop();
    cer_item->m_Cert = cert;
    cer_item->m_AuthorityKeyId = sba_authoritykeyid.pop();
    cer_item->m_CertId = sba_certid.pop();
    cer_item->m_KeyAlgo = s_keyalgo;
    cer_item->m_SerialNumber = sba_serialnum.pop();
    cer_item->m_KeyId = sba_keyid.pop();
    cer_item->m_Issuer = sba_issuer.pop();
    cer_item->m_Subject = sba_subject.pop();
    cer_item->m_Spki = sba_spki.pop();
    cer_item->m_AlgoKeyId = algo_keyid;
    cer_item->m_NotBefore = not_before;
    cer_item->m_NotAfter = not_after;
    cer_item->m_KeyUsage = key_usage;
    cer_item->m_Uris = uris;

    cert = nullptr;

    *cerItem = cer_item;
#ifdef DEBUG_CERITEM_INFO
    debug_ceritem_info(*cer_item);
#endif
    cer_item = nullptr;

cleanup:
    asn_free(get_Certificate_desc(), cert);
    delete cer_item;
    return ret;
}

int parseIssuerAndSN (
        const ByteArray* baEncoded,
        ByteArray** baIssuer,
        ByteArray** baSerialNumber
)
{
    int ret = RET_OK;
    IssuerAndSerialNumber_t* issuer_and_sn = nullptr;
    SmartBA sba_issuer, sba_serialnumber;

    if ((ba_get_len(baEncoded) < 3) || !baIssuer || !baSerialNumber) return RET_UAPKI_INVALID_PARAMETER;

    issuer_and_sn = (IssuerAndSerialNumber_t*)asn_decode_ba_with_alloc(get_IssuerAndSerialNumber_desc(), baEncoded);
    if (!issuer_and_sn) return RET_UAPKI_INVALID_PARAMETER;

    DO(asn_encode_ba(get_Name_desc(), &issuer_and_sn->issuer, &sba_issuer));
    DO(asn_INTEGER2ba(&issuer_and_sn->serialNumber, &sba_serialnumber));
    *baIssuer = sba_issuer.pop();
    *baSerialNumber = sba_serialnumber.pop();

cleanup:
    asn_free(get_IssuerAndSerialNumber_desc(), issuer_and_sn);
    return ret;
}

int parseSID (
        const ByteArray* baEncoded,
        ByteArray** baIssuer,
        ByteArray** baSerialNumber,
        ByteArray** baKeyId
)
{
    int ret = RET_OK;
    SignerIdentifier_t* sid = nullptr;
    SmartBA sba_issuer, sba_serialnumber;

    if ((ba_get_len(baEncoded) < 3) || !baIssuer || !baSerialNumber || !baKeyId) return RET_UAPKI_INVALID_PARAMETER;

    CHECK_NOT_NULL(sid = (SignerIdentifier_t*)asn_decode_ba_with_alloc(get_SignerIdentifier_desc(), baEncoded));
    switch (sid->present) {
    case SignerIdentifier_PR_issuerAndSerialNumber:
        DO(asn_encode_ba(get_Name_desc(), &sid->choice.issuerAndSerialNumber.issuer, &sba_issuer));
        DO(asn_INTEGER2ba(&sid->choice.issuerAndSerialNumber.serialNumber, &sba_serialnumber));
        *baIssuer = sba_issuer.pop();
        *baSerialNumber = sba_serialnumber.pop();
        break;
    case SignerIdentifier_PR_subjectKeyIdentifier:
        DO(asn_OCTSTRING2ba(&sid->choice.subjectKeyIdentifier, baKeyId));
        break;
    default:
        break;
    }

cleanup:
    asn_free(get_SignerIdentifier_desc(), sid);
    return ret;
}

ValidationType validationTypeFromStr (
        const string& validationType
)
{
    ValidationType rv_type = ValidationType::UNDEFINED;
    if (validationType.empty() || (validationType == string("NONE"))) {
        rv_type = ValidationType::NONE;
    }
    else if (validationType == string("CHAIN")) {
        rv_type = ValidationType::CHAIN;
    }
    else if (validationType == string("CRL")) {
        rv_type = ValidationType::CRL;
    }
    else if (validationType == string("OCSP")) {
        rv_type = ValidationType::OCSP;
    }
    return rv_type;
}

const char* verifyStatusToStr (
        const VerifyStatus status
)
{
    static const char* VERIFY_STATUS_STRINGS[6] = {
        "UNDEFINED",
        "INDETERMINATE",
        "FAILED",
        "INVALID",
        "VALID WITHOUT KEYUSAGE",
        "VALID"
    };
    return VERIFY_STATUS_STRINGS[((uint32_t)status < 6) ? (uint32_t)status : 0];
}


}   //  end namespace Cert

}   //  end namespace UapkiNS
