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

#include <mutex>
#include <string.h>
#include "cer-store.h"
#include "asn1-ba-utils.h"
#include "ba-utils.h"
#include "crl-store.h"
#include "dirent-internal.h"
#include "dstu-ns.h"
#include "extension-helper.h"
#include "extension-utils.h"
#include "macros-internal.h"
#include "oids.h"
#include "str-utils.h"
#include "time-utils.h"
#include "uapki-errors.h"
#include "verify-utils.h"


#undef FILE_MARKER
#define FILE_MARKER "src/cer-store.cpp"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


static const string CER_EXT = ".cer";


#ifdef DEBUG_CERSTOREITEM_INFO
string debug_cerstoreitem_info_get_commonname (const Name_t& name)
{
    string rv_s;
    if (name.present != Name_PR_rdnSequence) return rv_s;

    for (size_t i = 0; i < name.choice.rdnSequence.list.count; i++) {
        const RelativeDistinguishedName_t* rdname_src = name.choice.rdnSequence.list.array[i];
        for (size_t j = 0; j < rdname_src->list.count; j++) {
            const AttributeTypeAndValue_t* attr = rdname_src->list.array[j];
            if (OID_is_equal_oid(&attr->type, OID_X520_CommonName)) {
                char* s_value = nullptr;
                int ret = asn_decode_anystring(attr->value.buf, (const size_t)attr->value.size, &s_value);
                if (ret == RET_OK) {
                    rv_s = string(s_value);
                    ::free(s_value);
                    break;
                }
            }
        }
    }
    return rv_s;
}   //  debug_cerstoreitem_info_get_commonname

void debug_cerstoreitem_info (CerStore::Item& cerStoreItem)
{
    cerStoreItem.devsSubject = debug_cerstoreitem_info_get_commonname(cerStoreItem.cert->tbsCertificate.subject);
    cerStoreItem.devsIssuerAndSn = StrUtils::hexFromBa(cerStoreItem.baSerialNumber)
        + string("; ") + debug_cerstoreitem_info_get_commonname(cerStoreItem.cert->tbsCertificate.issuer);
    cerStoreItem.devsValidity = TimeUtils::mstimeToFormat(cerStoreItem.notBefore)
        + string(" - ") + TimeUtils::mstimeToFormat(cerStoreItem.notAfter);
}   //  debug_cerstoreitem_info
#endif

static int encode_issuer_and_sn (const TBSCertificate_t* tbsCert, ByteArray** baIssuerAndSN)
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



CerStore::CertStatusInfo::CertStatusInfo (
        const ValidationType validationType
)
    : type(validationType)
    , baResult(nullptr)
    , status(UapkiNS::CertStatus::UNDEFINED)
    , validTime(0)
{
}

CerStore::CertStatusInfo::~CertStatusInfo (void)
{
    reset();
}

bool CerStore::CertStatusInfo::isExpired (
        const uint64_t time
) const
{
    return (time > validTime);
}

void CerStore::CertStatusInfo::reset (void)
{
    ba_free(baResult);
    baResult = nullptr;
    status = UapkiNS::CertStatus::UNDEFINED;
    validTime = 0;
}

int CerStore::CertStatusInfo::set (
        const UapkiNS::CertStatus status,
        const uint64_t validTime,
        const ByteArray* baResult
)
{
    reset();
    this->status = status;
    this->validTime = validTime;
    this->baResult = ba_copy_with_alloc(baResult, 0, 0);
    return (this->baResult) ? RET_OK : RET_UAPKI_GENERAL_ERROR;
}



CerStore::Item::Item (void)
    : baEncoded(nullptr)
    , cert(nullptr)
    , baCertId(nullptr)
    , keyAlgo(nullptr)
    , baSerialNumber(nullptr)
    , baKeyId(nullptr)
    , baIssuer(nullptr)
    , baSubject(nullptr)
    , baSPKI(nullptr)
    , algoKeyId(HashAlg::HASH_ALG_UNDEFINED)
    , notBefore(0)
    , notAfter(0)
    , keyUsage(0)
    , trusted(false)
    , verifyStatus(VerifyStatus::UNDEFINED)
    , certStatusByCrl(ValidationType::CRL)
    , certStatusByOcsp(ValidationType::OCSP)
{
}

CerStore::Item::~Item (void)
{
    ba_free((ByteArray*)baEncoded);
    asn_free(get_Certificate_desc(), (Certificate_t*)cert);
    ba_free((ByteArray*)baCertId);
    ba_free((ByteArray*)baSerialNumber);
    ba_free((ByteArray*)baKeyId);
    ba_free((ByteArray*)baIssuer);
    ba_free((ByteArray*)baSubject);
    ba_free((ByteArray*)baSPKI);
    ::free((char*)keyAlgo);
    algoKeyId = HashAlg::HASH_ALG_UNDEFINED;
    notBefore = 0;
    notAfter = 0;
    keyUsage = 0;
    verifyStatus = VerifyStatus::UNDEFINED;
}

int CerStore::Item::checkValidity (
        const uint64_t validateTime
) const
{
    if ((notBefore == 0) || (notAfter == 0)) return RET_UAPKI_TIME_ERROR;

    if (notBefore > validateTime) return RET_UAPKI_CERT_VALIDITY_NOT_BEFORE_ERROR;

    if (notAfter < validateTime) return RET_UAPKI_CERT_VALIDITY_NOT_AFTER_ERROR;

    return RET_OK;
}

int CerStore::Item::generateEssCertId (
        const UapkiNS::AlgorithmIdentifier& aidDigest,
        UapkiNS::EssCertId& essCertId
) const
{
    return CerStore::generateEssCertId(this, aidDigest, essCertId);
}

int CerStore::Item::getCrlUris (
        const bool isFull,
        vector<string>& uris
) const
{
    int ret = RET_OK;
    const char* oid_extnid = isFull ? OID_X509v3_CRLDistributionPoints : OID_X509v3_FreshestCRL;
    UapkiNS::SmartBA sba_extnvalue;

    DO(extns_get_extnvalue_by_oid(cert->tbsCertificate.extensions, oid_extnid, nullptr, &sba_extnvalue));

    DO(ExtensionHelper::Decode::distributionPoints(sba_extnvalue.get(), uris));

cleanup:
    return ret;
}

int CerStore::Item::getIssuerAndSN (
        ByteArray** baIssuerAndSN
) const
{
    const int ret = encode_issuer_and_sn(&cert->tbsCertificate, baIssuerAndSN);
    return ret;
}

int CerStore::Item::getOcspUris (
        vector<string>& uris
) const
{
    int ret = RET_OK;
    UapkiNS::SmartBA sba_extnvalue;

    DO(extns_get_extnvalue_by_oid(cert->tbsCertificate.extensions, OID_PKIX_AuthorityInfoAccess, nullptr, &sba_extnvalue));

    DO(ExtensionHelper::Decode::accessDescriptions(sba_extnvalue.get(), OID_PKIX_OCSP, uris));

cleanup:
    return ret;
}

int CerStore::Item::getTspUris (
        vector<string>& uris
) const
{
    int ret = RET_OK;
    UapkiNS::SmartBA sba_extnvalue;

    DO(extns_get_extnvalue_by_oid(cert->tbsCertificate.extensions, OID_PKIX_SubjectInfoAccess, nullptr, &sba_extnvalue));

    DO(ExtensionHelper::Decode::accessDescriptions(sba_extnvalue.get(), OID_PKIX_TimeStamping, uris));

cleanup:
    return ret;
}

int CerStore::Item::keyUsageByBit (
        const uint32_t bitNum,
        bool& bitValue
) const
{
    const uint32_t masked_bit = (uint32_t)(1 << bitNum);
    bitValue = ((keyUsage & masked_bit) > 0);
    return RET_OK;
}

int CerStore::Item::verify (const CerStore::Item* cerIssuer)
{
    verifyStatus = VerifyStatus::INDETERMINATE;
    if (!cerIssuer) return RET_OK;

    int ret = RET_OK;
    X509Tbs_t* x509_cert = nullptr;
    UapkiNS::SmartBA sba_signvalue, sba_tbs;
    char* s_signalgo = nullptr;

    CHECK_NOT_NULL(x509_cert = (X509Tbs_t*)asn_decode_ba_with_alloc(get_X509Tbs_desc(), baEncoded));
    if (!sba_tbs.set(ba_alloc_from_uint8(x509_cert->tbsData.buf, x509_cert->tbsData.size))) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    DO(asn_oid_to_text(&cert->signatureAlgorithm.algorithm, &s_signalgo));
    if (algoKeyId == HASH_ALG_GOST34311) {
        DO(asn_decodevalue_bitstring_encap_octet(&cert->signature, &sba_signvalue));
    }
    else {
        DO(asn_BITSTRING2ba(&cert->signature, &sba_signvalue));
    }

    
    ret = verify_signature(s_signalgo, sba_tbs.get(), false, cerIssuer->baSPKI, sba_signvalue.get());
    switch (ret) {
    case RET_OK:
        verifyStatus = VerifyStatus::VALID;
        break;
    case RET_VERIFY_FAILED:
        verifyStatus = VerifyStatus::INVALID;
        break;
    default:
        verifyStatus = VerifyStatus::FAILED;
        break;
    }

    if (verifyStatus == VerifyStatus::VALID) {
        bool is_digitalsign = false;
        DO(cerIssuer->keyUsageByBit(KeyUsage_keyCertSign, is_digitalsign));
        if (!is_digitalsign) {
            verifyStatus = VerifyStatus::VALID_WITHOUT_KEYUSAGE;
        }
    }

cleanup:
    asn_free(get_X509Tbs_desc(), x509_cert);
    ::free(s_signalgo);
    return ret;
}



CerStore::CerStore (void)
{
}

CerStore::~CerStore (void)
{
    reset();
}

int CerStore::addCert (
        const ByteArray* baEncoded,
        const bool copyWithAlloc,
        const bool permanent,
        const bool trusted,
        bool& isUnique,
        Item** cerStoreItem
)
{
    int ret = RET_OK;
    Item* cer_parsed = nullptr;
    Item* cer_added = nullptr;

    DO(parseCert(baEncoded, &cer_parsed));
    cer_parsed->trusted = trusted;

    if (copyWithAlloc) {
        cer_parsed->baEncoded = ba_copy_with_alloc(baEncoded, 0, 0);
        if (!cer_parsed->baEncoded) {
            SET_ERROR(RET_UAPKI_GENERAL_ERROR);
        }
    }

    cer_added = addItem(cer_parsed);
    isUnique = (cer_added == cer_parsed);
    cer_parsed = nullptr;
    if (cerStoreItem) {
        *cerStoreItem = cer_added;
    }

    if (permanent) {
        saveToFile(cer_added);
    }

cleanup:
    delete cer_parsed;
    return ret;
}

int CerStore::getCertByCertId (const ByteArray* baCertId, Item** cerStoreItem)
{
    mutex mtx;
    int ret = RET_UAPKI_CERT_NOT_FOUND;
    mtx.lock();

    for (auto& it : m_Items) {
        if (ba_cmp(baCertId, it->baCertId) == RET_OK) {
            *cerStoreItem = it;
            ret = RET_OK;
            break;
        }
    }

    mtx.unlock();
    return ret;
}

int CerStore::getCertByEncoded (const ByteArray* baEncoded, Item** cerStoreItem)
{
    mutex mtx;
    int ret = RET_UAPKI_CERT_NOT_FOUND;
    mtx.lock();

    for (auto& it : m_Items) {
        if (ba_cmp(baEncoded, it->baEncoded) == RET_OK) {
            *cerStoreItem = it;
            ret = RET_OK;
            break;
        }
    }

    mtx.unlock();
    return ret;
}

int CerStore::getCertByIndex (const size_t index, Item** cerStoreItem)
{
    mutex mtx;
    int ret = RET_UAPKI_CERT_NOT_FOUND;
    mtx.lock();

    if (index < m_Items.size()) {
        *cerStoreItem = m_Items[index];
        ret = RET_OK;
    }

    mtx.unlock();
    return ret;
}

int CerStore::getCertByIssuerAndSn (
        const ByteArray* baIssuer,
        const ByteArray* baSerialNumber,
        Item** cerStoreItem
)
{
    mutex mtx;
    int ret = RET_UAPKI_CERT_NOT_FOUND;
    mtx.lock();
    for (auto& it : m_Items) {
        if ((ba_cmp(baSerialNumber, it->baSerialNumber) == RET_OK) && (ba_cmp(baIssuer, it->baIssuer) == RET_OK)) {
            *cerStoreItem = it;
            ret = RET_OK;
            break;
        }
    }

    mtx.unlock();
    return ret;
}

int CerStore::getCertByKeyId (
        const ByteArray* baKeyId,
        Item** cerStoreItem
)
{
    mutex mtx;
    int ret = RET_UAPKI_CERT_NOT_FOUND;
    mtx.lock();

    for (auto& it : m_Items) {
        if (ba_cmp(baKeyId, it->baKeyId) == RET_OK) {
            *cerStoreItem = it;
            ret = RET_OK;
            break;
        }
    }

    mtx.unlock();
    return ret;
}

int CerStore::getCertBySID (
        const ByteArray* baSID,
        Item** cerStoreItem
)
{
    mutex mtx;
    int ret = RET_OK;
    UapkiNS::SmartBA sba_issuer, sba_keyid, sba_serialnum;

    ret = parseSID(baSID, &sba_issuer, &sba_serialnum, &sba_keyid);
    if (ret != RET_OK) return ret;

    if (sba_keyid.size() > 0) {
        ret = getCertByKeyId(sba_keyid.get(), cerStoreItem);
        return ret;
    }

    ret = RET_UAPKI_CERT_NOT_FOUND;
    mtx.lock();
    for (auto& it : m_Items) {
        if (
            (ba_cmp(sba_serialnum.get(), it->baSerialNumber) == RET_OK) &&
            (ba_cmp(sba_issuer.get(), it->baIssuer) == RET_OK)
        ) {
            *cerStoreItem = it;
            ret = RET_OK;
            break;
        }
    }

    mtx.unlock();
    return ret;
}

int CerStore::getCertBySPKI (const ByteArray* baSPKI, Item** cerStoreItem)
{
    mutex mtx;
    int ret = RET_UAPKI_CERT_NOT_FOUND;
    mtx.lock();

    for (auto& it : m_Items) {
        if (ba_cmp(baSPKI, it->baSPKI) == RET_OK) {
            *cerStoreItem = it;
            ret = RET_OK;
            break;
        }
    }

    mtx.unlock();
    return ret;
}

int CerStore::getCertBySubject (const ByteArray* baSubject, Item** cerStoreItem)
{
    mutex mtx;
    int ret = RET_UAPKI_CERT_NOT_FOUND;
    mtx.lock();

    for (auto& it : m_Items) {
        if (ba_cmp(baSubject, it->baSubject) == RET_OK) {
            *cerStoreItem = it;
            ret = RET_OK;
            break;
        }
    }

    mtx.unlock();
    return ret;
}

int CerStore::load (
        const char* path
)
{
    mutex mtx;
    if (path == nullptr) return RET_UAPKI_INVALID_PARAMETER;

    mtx.lock();
    m_Path = string(path);
    const int ret = loadDir();
    mtx.unlock();
    if (ret != RET_OK) {
        reset();
    }
    return ret;
}

int CerStore::getChainCerts (
        const Item* cerSubject,
        vector<Item*>& chainCerts
)
{
    int ret = RET_OK;
    Item* cer_subject = (Item*)cerSubject;
    Item* cer_issuer = nullptr;
    bool is_selfsigned = false;

    while (true) {
        DO(getIssuerCert(cer_subject, &cer_issuer, is_selfsigned));
        if (is_selfsigned) break;
        chainCerts.push_back(cer_issuer);
        cer_subject = cer_issuer;
    }

cleanup:
    return ret;
}

int CerStore::getCount (
        size_t& count
)
{
    mutex mtx;
    //  Note: getCount() may (by type provider) return RET_UAPKI_NOT_SUPPORTED
    int ret = RET_OK;
    mtx.lock();

    count = m_Items.size();

    mtx.unlock();
    return ret;
}

int CerStore::getCountTrusted (
        size_t& count
)
{
    mutex mtx;
    //  Note: getCount() may (by type provider) return RET_UAPKI_NOT_SUPPORTED
    int ret = RET_OK;
    count = 0;
    mtx.lock();

    for (auto& it : m_Items) {
        count += (it->trusted) ? 1 : 0;
    }

    mtx.unlock();
    return ret;
}

int CerStore::getIssuerCert (
        const Item* cerSubject,
        Item** cerIssuer,
        bool& isSelfSigned
)
{
    int ret = RET_OK;
    UapkiNS::SmartBA sba_authkeyid;

    CHECK_PARAM(cerSubject != nullptr);
    CHECK_PARAM(cerIssuer != nullptr);

    DO(extns_get_authority_keyid(cerSubject->cert->tbsCertificate.extensions, &sba_authkeyid));

    if (ba_cmp(cerSubject->baKeyId, sba_authkeyid.get()) != 0) {
        isSelfSigned = false;
        ret = getCertByKeyId(sba_authkeyid.get(), cerIssuer);
        if (ret == RET_UAPKI_CERT_NOT_FOUND) {
            ret = RET_UAPKI_CERT_ISSUER_NOT_FOUND;
        }
    }
    else {
        isSelfSigned = true;
        *cerIssuer = (Item*)cerSubject;
    }

cleanup:
    return ret;
}

int CerStore::reload (void)
{
    mutex mtx;
    mtx.lock();
    const int ret = loadDir();
    mtx.unlock();
    if (ret != RET_OK) {
        reset();
    }
    return ret;
}

int CerStore::removeCert (
        const ByteArray* baCertId,
        const bool permanent
)
{
    mutex mtx;
    int ret = RET_UAPKI_CERT_NOT_FOUND;
    mtx.lock();

    for (auto it = m_Items.begin(); it != m_Items.end(); it++) {
        if (ba_cmp(baCertId, (*it)->baCertId) == RET_OK) {
            CerStore::Item* cer_item = *it;
            m_Items.erase(it);
            delete cer_item;//tmp solution, need add m_RemovedItems
            ret = RET_OK;
            break;
        }
    }

    mtx.unlock();
    return ret;
}

void CerStore::reset (void)
{
    mutex mtx;
    mtx.lock();
    for (auto& it : m_Items) {
        delete it;
    }
    m_Items.clear();
    mtx.unlock();
}

int CerStore::calcKeyId (
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
        DO(ba_encode_octetstring(baPubkey, &ba_encappubkey));
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

int CerStore::encodeIssuerAndSN (
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

int CerStore::generateEssCertId (
        const Item* cerStoreItem,
        const UapkiNS::AlgorithmIdentifier& aidDigest,
        UapkiNS::EssCertId& essCertId
)
{
    int ret = RET_OK;
    HashAlg hash_alg = HashAlg::HASH_ALG_UNDEFINED;

    if (!cerStoreItem || !aidDigest.isPresent()) return RET_UAPKI_INVALID_PARAMETER;

    hash_alg = hash_from_oid(aidDigest.algorithm.c_str());
    if (hash_alg == HashAlg::HASH_ALG_UNDEFINED) return RET_UAPKI_UNSUPPORTED_ALG;

    DO(::hash(hash_alg, cerStoreItem->baEncoded, &essCertId.baHashValue));
    if (!essCertId.hashAlgorithm.copy(aidDigest)) return RET_UAPKI_GENERAL_ERROR;

    DO(issuerToGeneralNames(cerStoreItem->baIssuer, &essCertId.issuerSerial.baIssuer));
    CHECK_NOT_NULL(essCertId.issuerSerial.baSerialNumber = ba_copy_with_alloc(cerStoreItem->baSerialNumber, 0, 0));

cleanup:
    return ret;
}

int CerStore::issuerFromGeneralNames (
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

int CerStore::issuerToGeneralNames (
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

int CerStore::parseCert (
        const ByteArray* baEncoded,
        Item** item
)
{
    int ret = RET_OK;
    Certificate_t* cert = nullptr;
    ByteArray* ba_certid = nullptr;
    ByteArray* ba_issuer = nullptr;
    ByteArray* ba_keyid = nullptr;
    ByteArray* ba_pubkey = nullptr;
    ByteArray* ba_serialnum = nullptr;
    ByteArray* ba_spki = nullptr;
    ByteArray* ba_subject = nullptr;
    Item* cer_item = nullptr;
    HashAlg algo_keyid = HASH_ALG_SHA1;
    uint64_t not_after = 0, not_before = 0;
    uint32_t key_usage = 0;
    char* s_keyalgo = nullptr;

    CHECK_PARAM(baEncoded != nullptr);
    CHECK_PARAM(item != nullptr);

    CHECK_NOT_NULL(cert = (Certificate_t*)asn_decode_ba_with_alloc(get_Certificate_desc(), baEncoded));

    DO(asn_INTEGER2ba(&cert->tbsCertificate.serialNumber, &ba_serialnum));
    DO(asn_encode_ba(get_Name_desc(), &cert->tbsCertificate.issuer, &ba_issuer));
    DO(asn_decodevalue_pkixtime(&cert->tbsCertificate.validity.notBefore, &not_before));
    DO(asn_decodevalue_pkixtime(&cert->tbsCertificate.validity.notAfter, &not_after));
    DO(asn_encode_ba(get_Name_desc(), &cert->tbsCertificate.subject, &ba_subject));
    DO(asn_encode_ba(get_SubjectPublicKeyInfo_desc(), &cert->tbsCertificate.subjectPublicKeyInfo, &ba_spki));
    DO(asn_oid_to_text(&cert->tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm, &s_keyalgo));
    if (DstuNS::isDstu4145family(s_keyalgo)) {
        algo_keyid = HASH_ALG_GOST34311;
        //  Note: calcKeyId() automatic wrapped pubkey into octet-string before compute hash
        DO(asn_decodevalue_bitstring_encap_octet(&cert->tbsCertificate.subjectPublicKeyInfo.subjectPublicKey, &ba_pubkey));
    }
    else {
        DO(asn_BITSTRING2ba(&cert->tbsCertificate.subjectPublicKeyInfo.subjectPublicKey, &ba_pubkey));
    }

    DO(calcKeyId(algo_keyid, ba_pubkey, &ba_keyid));
    DO(encode_issuer_and_sn(&cert->tbsCertificate, &ba_certid));

    if (cert->tbsCertificate.extensions) {
        ret = extns_get_key_usage(cert->tbsCertificate.extensions, &key_usage);
        if (ret != RET_OK) {
            if (ret == RET_UAPKI_EXTENSION_NOT_PRESENT) {
                key_usage = 0;
                ret = RET_OK;
            }
        }
    }

    cer_item = new Item();
    if (cer_item) {
        cer_item->baEncoded = baEncoded;
        cer_item->cert = cert;
        cer_item->baCertId = ba_certid;
        cer_item->keyAlgo = s_keyalgo;
        cer_item->baSerialNumber = ba_serialnum;
        cer_item->baKeyId = ba_keyid;
        cer_item->baIssuer = ba_issuer;
        cer_item->baSubject = ba_subject;
        cer_item->baSPKI = ba_spki;
        cer_item->algoKeyId = algo_keyid;
        cer_item->notBefore = not_before;
        cer_item->notAfter = not_after;
        cer_item->keyUsage = key_usage;

        cert = nullptr;
        ba_certid = nullptr;
        ba_serialnum = nullptr;
        ba_issuer = nullptr;
        ba_keyid = nullptr;
        ba_spki = nullptr;
        ba_subject = nullptr;
        s_keyalgo = nullptr;
        *item = cer_item;
#ifdef DEBUG_CERSTOREITEM_INFO
        debug_cerstoreitem_info(*cer_item);
#endif
        cer_item = nullptr;
    }

cleanup:
    asn_free(get_Certificate_desc(), cert);
    ba_free(ba_certid);
    ba_free(ba_issuer);
    ba_free(ba_keyid);
    ba_free(ba_pubkey);
    ba_free(ba_serialnum);
    ba_free(ba_spki);
    ba_free(ba_subject);
    ::free(s_keyalgo);
    delete cer_item;
    return ret;
}

int CerStore::parseSID (
        const ByteArray* baSID,
        ByteArray** baIssuer,
        ByteArray** baSerialNumber,
        ByteArray** baKeyId
)
{
    int ret = RET_OK;
    IssuerAndSerialNumber_t* issuer_and_sn = nullptr;
    ByteArray* ba_issuer = nullptr;
    ByteArray* ba_serialnum = nullptr;
    ByteArray* ba_keyid = nullptr;
    uint8_t tag = 0x00;

    CHECK_PARAM(ba_get_len(baSID) > 0);
    CHECK_PARAM(baIssuer != nullptr);
    CHECK_PARAM(baSerialNumber != nullptr);
    CHECK_PARAM(baKeyId != nullptr);

    DO(ba_get_byte(baSID, 0, &tag));
    if (tag == 0x30) {
        CHECK_NOT_NULL(issuer_and_sn = (IssuerAndSerialNumber_t*)asn_decode_ba_with_alloc(get_IssuerAndSerialNumber_desc(), baSID));
        DO(asn_encode_ba(get_Name_desc(), &issuer_and_sn->issuer, &ba_issuer));
        DO(asn_INTEGER2ba(&issuer_and_sn->serialNumber, &ba_serialnum));
        *baIssuer = ba_issuer;
        *baSerialNumber = ba_serialnum;
        ba_issuer = nullptr;
        ba_serialnum = nullptr;
    }
    else if (tag == 0x80) {
        DO(ba_decode_octetstring(baSID, baKeyId));
    }
    else {
        ret = RET_UAPKI_INVALID_STRUCT;
    }

cleanup:
    asn_free(get_IssuerAndSerialNumber_desc(), issuer_and_sn);
    ba_free(ba_issuer);
    ba_free(ba_serialnum);
    ba_free(ba_keyid);
    return ret;
}

CerStore::ValidationType CerStore::validationTypeFromStr (
        const string& validationType
)
{
    ValidationType rv_type = ValidationType::UNDEFINED;
    if (validationType.empty() || (validationType == string("NONE"))) {
        rv_type = ValidationType::NONE;
    }
    else if (validationType == string("CRL")) {
        rv_type = ValidationType::CRL;
    }
    else if (validationType == string("OCSP")) {
        rv_type = ValidationType::OCSP;
    }
    return rv_type;
}

const char* CerStore::verifyStatusToStr (
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

CerStore::Item* CerStore::addItem (Item* item)
{
    for (auto& it : m_Items) {
        const int ret = ba_cmp(item->baKeyId, it->baKeyId);
        if (ret == RET_OK) {
            DEBUG_OUTCON(printf("CerStore::addItem(), cert is found. keyId: "); ba_print(stdout, it->baKeyId));
            return it;
        }
    }

    m_Items.push_back(item);
    DEBUG_OUTCON(printf("CerStore::addItem(), cert is unique - add it. keyId: "); ba_print(stdout, item->baKeyId));
    return item;
}

int CerStore::loadDir (void)
{
    DIR* dir = nullptr;
    struct dirent* in_file;

    if (m_Path.empty()) return RET_OK;

    dir = opendir(m_Path.c_str());
    if (!dir) return RET_UAPKI_CERT_STORE_LOAD_ERROR;

    while ((in_file = readdir(dir))) {
        if (!strcmp(in_file->d_name, ".") || !strcmp(in_file->d_name, "..")) {
            continue;
        }

        //  Check ext of file
        const string s_name = string(in_file->d_name);
        size_t pos = s_name.rfind(CER_EXT.c_str());
        if (pos != s_name.length() - 4) {
            continue;
        }

        const string cer_path = m_Path + s_name;
        if (!is_dir(cer_path.c_str())) {
            ByteArray* ba_encoded = nullptr;
            int ret = ba_alloc_from_file(cer_path.c_str(), &ba_encoded);
            if (ret != RET_OK) continue;

            Item* cer_item = nullptr;
            ret = parseCert(ba_encoded, &cer_item);
            if (ret == RET_OK) {
                addItem(cer_item);
            }
            else {
                ba_free(ba_encoded);
            }
        }
    }

    closedir(dir);
    return RET_OK;
}

int CerStore::saveToFile (const Item* cerStoreItem)
{
    if (m_Path.empty()) return RET_OK;

    string s_hex = StrUtils::hexFromBa(cerStoreItem->baKeyId);
    if (s_hex.empty()) return RET_OK;

    const string s_path = m_Path + s_hex + CER_EXT;
    const int ret = ba_to_file(cerStoreItem->baEncoded, s_path.c_str());
    return ret;
}

void CerStore::saveStatToLog (
        const string& message
)
{
    static size_t ctr_stat = 0;

    FILE* f = fopen("uapki-cer-store.log", "a");
    if (!f) return;

    uint64_t ms = TimeUtils::nowMsTime();
    string s_line = string("*** STAT[") + to_string(ctr_stat) + string("] BEGIN *** '") + message;
    s_line += string("' TIME ") + TimeUtils::mstimeToFormat(ms) + string(" ***\n");
    fputs(s_line.c_str(), f);

    size_t idx = 0;
    for (const auto& it : m_Items) {
        s_line = string("CER[") + to_string(idx++) + string("]\n");
        s_line += string("KeyId: ") + StrUtils::hexFromBa(it->baKeyId) + string("\n");
        s_line += string("SerialNumber: ") + StrUtils::hexFromBa(it->baSerialNumber) + string("\n");
        s_line += string("OCSP, status: ") + CrlStore::certStatusToStr(it->certStatusByOcsp.status) + string("\n");
        s_line += string("OCSP, validTime: ") + string(it->certStatusByOcsp.isExpired(ms) ? "IS EXPIRED " : "IS VALID   ");
        s_line += TimeUtils::mstimeToFormat(it->certStatusByOcsp.validTime) + string("\n");
        s_line += string("\n");
        fputs(s_line.c_str(), f);
    }

    s_line = string("*** STAT[") + to_string(ctr_stat++) + string("] END *****\n\n");
    fputs(s_line.c_str(), f);

    fclose(f);
}
