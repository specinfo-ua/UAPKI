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
#include "crl-store.h"
#include "asn1-ba-utils.h"
#include "ba-utils.h"
#include "dirent-internal.h"
#include "extension-utils.h"
#include "macros-internal.h"
#include "oids.h"
#include "str-utils.h"
#include "uapki-errors.h"
#include "verify-utils.h"


#undef FILE_MARKER
#define FILE_MARKER "src/crl-store.cpp"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


static const string CRL_EXT = ".crl";


static const char* CERT_STATUS_STRINGS[4] = {
    "UNDEFINED", "GOOD", "REVOKED", "UNKNOWN"
};

static const char* CRL_REASON_STRINGS[12] = {
    "UNDEFINED", "UNSPECIFIED", "KEY_COMPROMISE", "CA_COMPROMISE", "AFFILIATION_CHANGED",
    "SUPERSEDED", "CESSATION_OF_OPERATION", "CERTIFICATE_HOLD", "", "REMOVE_FROM_CRL",
    "PRIVILEGE_WITHDRAWN", "AA_COMPROMISE"
};


static int encode_crlid (
        const TBSCertList_t* tbs,
        const ByteArray* baCrlNumber,
        ByteArray** baIssuerAndSN
)
{
    int ret = RET_OK;
    IssuerAndSerialNumber_t* issuer_and_sn = nullptr;

    CHECK_PARAM(tbs != nullptr);
    CHECK_PARAM(baCrlNumber != nullptr);
    CHECK_PARAM(baIssuerAndSN != nullptr);

    CHECK_NOT_NULL(issuer_and_sn = (IssuerAndSerialNumber_t*)calloc(1, sizeof(IssuerAndSerialNumber_t)));

    DO(asn_copy(get_Name_desc(), &tbs->issuer, &issuer_and_sn->issuer));
    DO(asn_ba2INTEGER(baCrlNumber, &issuer_and_sn->serialNumber));

    DO(asn_encode_ba(get_IssuerAndSerialNumber_desc(), issuer_and_sn, baIssuerAndSN));

cleanup:
    asn_free(get_IssuerAndSerialNumber_desc(), issuer_and_sn);
    return ret;
}   //  encode_crlid

static int encode_crlidentifier (
        const TBSCertList_t* tbs,
        const ByteArray* baCrlNumber,
        ByteArray** baCrlIdentifier
)
{
    int ret = RET_OK;
    CrlIdentifier_t* crl_ident = nullptr;
    ByteArray* ba_crlissuedtime = nullptr;

    CHECK_PARAM(tbs != nullptr);
    CHECK_PARAM(baCrlIdentifier != nullptr);

    CHECK_NOT_NULL(crl_ident = (CrlIdentifier_t*)calloc(1, sizeof(CrlIdentifier_t)));

    DO(asn_copy(get_Name_desc(), &tbs->issuer, &crl_ident->crlissuer));
    switch (tbs->thisUpdate.present) {
    case PKIXTime_PR_utcTime:
        DO(asn_OCTSTRING2ba(&tbs->thisUpdate.choice.utcTime, &ba_crlissuedtime));
        DO(asn_ba2OCTSTRING(ba_crlissuedtime, &crl_ident->crlIssuedTime));
        break;
    case PKIXTime_PR_generalTime:
        DO(asn_OCTSTRING2ba(&tbs->thisUpdate.choice.generalTime, &ba_crlissuedtime));
        DO(asn_bytes2OCTSTRING(&crl_ident->crlIssuedTime, ba_get_buf_const(ba_crlissuedtime) + 2, ba_get_len(ba_crlissuedtime) - 2));
        break;
    default:
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }
    if (baCrlNumber) {
        CHECK_NOT_NULL(crl_ident->crlNumber = (INTEGER_t*)calloc(1, sizeof(INTEGER_t)));
        DO(asn_ba2INTEGER(baCrlNumber, crl_ident->crlNumber));
    }

    DO(asn_encode_ba(get_CrlIdentifier_desc(), crl_ident, baCrlIdentifier));

cleanup:
    asn_free(get_CrlIdentifier_desc(), crl_ident);
    ba_free(ba_crlissuedtime);
    return ret;
}   //  encode_crlidentifier


CrlStore::Item::Item (const CrlType iType)
    : actuality(Actuality::UNDEFINED)
    , type(iType)
    , baEncoded(nullptr)
    , crl(nullptr)
    , baCrlId(nullptr)
    , baIssuer(nullptr)
    , thisUpdate(0)
    , nextUpdate(0)
    , baAuthorityKeyId(nullptr)
    , baCrlNumber(nullptr)
    , baDeltaCrl(nullptr)
    , statusSign(SIGNATURE_VERIFY::STATUS::UNDEFINED)
    , baCrlIdentifier(nullptr)
{}

CrlStore::Item::~Item (void)
{
    type = CrlType::UNDEFINED;
    ba_free((ByteArray*)baEncoded);
    asn_free(get_CertificateList_desc(), (CertificateList_t*)crl);
    ba_free((ByteArray*)baCrlId);
    ba_free((ByteArray*)baIssuer);
    thisUpdate = 0;
    nextUpdate = 0;
    ba_free((ByteArray*)baAuthorityKeyId);
    ba_free((ByteArray*)baCrlNumber);
    ba_free((ByteArray*)baDeltaCrl);
    statusSign = SIGNATURE_VERIFY::STATUS::UNDEFINED;
    ba_free((ByteArray*)baCrlIdentifier);
}

size_t CrlStore::Item::countRevokedCerts (void) const
{
    size_t rv_cnt = 0;
    if (crl && crl->tbsCertList.revokedCertificates) {
        rv_cnt = (size_t)crl->tbsCertList.revokedCertificates->list.count;
    }
    return rv_cnt;
}

int CrlStore::Item::getHash (
        const UapkiNS::AlgorithmIdentifier& aidDigest,
        const ByteArray** baHashValue
)
{
    if (!aidDigest.isPresent() || !baHashValue) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    if (!crlHash.baHashValue || (crlHash.hashAlgorithm.algorithm != aidDigest.algorithm)) {
        const HashAlg hash_alg = hash_from_oid(aidDigest.algorithm.c_str());
        if (hash_alg == HashAlg::HASH_ALG_UNDEFINED) return RET_UAPKI_UNSUPPORTED_ALG;

        ba_free(crlHash.baHashValue);
        crlHash.baHashValue = nullptr;
        crlHash.hashAlgorithm.clear();

        DO(::hash(hash_alg, this->baEncoded, &crlHash.baHashValue));
        crlHash.hashAlgorithm.algorithm = aidDigest.algorithm;
    }

    *baHashValue = crlHash.baHashValue;

cleanup:
    return ret;
}

int CrlStore::Item::revokedCerts (
        const CerStore::Item* cerSubject,
        vector<const RevokedCertItem*>& revokedItems
)
{
    int ret = RET_OK;
    const RevokedCertificates_t* revoked_certs = nullptr;
    ASN__PRIMITIVE_TYPE_t user_sn;

    CHECK_PARAM(cerSubject != nullptr);

    DEBUG_OUTCON(printf("CrlStore::Item::revokedCerts() cerSubject->baSerialNumber, hex: "); ba_print(stdout, cerSubject->baSerialNumber));
    revoked_certs = crl->tbsCertList.revokedCertificates;
    if (revoked_certs) {
        DEBUG_OUTCON(printf("CrlStore::Item::revokedCerts() count: %d\n", revoked_certs->list.count));
        user_sn.buf = (uint8_t*)ba_get_buf_const(cerSubject->baSerialNumber);
        user_sn.size = (int)ba_get_len(cerSubject->baSerialNumber);
        for (int i = 0; i < revoked_certs->list.count; i++) {
            const RevokedCertificate_t* revoked_cert = revoked_certs->list.array[i];
            if (asn_primitive_data_is_equals((ASN__PRIMITIVE_TYPE_t*)&revoked_cert->userCertificate, &user_sn)) {
                DEBUG_OUTCON(printf("equal SerialNumber, index: %d\n", i));
                const RevokedCertItem* revcert_item = nullptr;
                uint64_t invalidity_date = 0, revocation_date = 0;
                UapkiNS::CrlReason crl_reason = UapkiNS::CrlReason::UNDEFINED;

                DO(asn_decodevalue_pkixtime(&revoked_cert->revocationDate, &revocation_date));
                if (revoked_cert->crlEntryExtensions) {
                    uint32_t u32_crlreason = 0;
                    ret = extns_get_crl_reason(revoked_cert->crlEntryExtensions, &u32_crlreason);
                    if (ret == RET_OK) {
                        crl_reason = (UapkiNS::CrlReason)u32_crlreason;
                    }
                    extns_get_crl_invalidity_date(revoked_cert->crlEntryExtensions, &invalidity_date);
                }

                revcert_item = new RevokedCertItem((size_t)i, revocation_date, crl_reason, invalidity_date);
                if (revcert_item) {
                    revokedItems.push_back(revcert_item);
                }
            }
        }
    }

cleanup:
    return ret;
}

int CrlStore::Item::verify (
        const CerStore::Item* cerIssuer
)
{
    int ret = RET_OK;
    X509Tbs_t* x509_tbs = nullptr;
    ByteArray* ba_signature = nullptr;
    ByteArray* ba_tbs = nullptr;
    char* s_signalgo = nullptr;

    CHECK_PARAM(cerIssuer != nullptr);

    if (statusSign == SIGNATURE_VERIFY::STATUS::UNDEFINED) {
        CHECK_NOT_NULL(x509_tbs = (X509Tbs_t*)asn_decode_ba_with_alloc(get_X509Tbs_desc(), baEncoded));
        CHECK_NOT_NULL(ba_tbs = ba_alloc_from_uint8(x509_tbs->tbsData.buf, x509_tbs->tbsData.size));

        DO(asn_oid_to_text(&crl->signatureAlgorithm.algorithm, &s_signalgo));
        if (oid_is_parent(OID_DSTU4145_WITH_DSTU7564, s_signalgo)
            || oid_is_parent(OID_DSTU4145_WITH_GOST3411, s_signalgo)) {
            DO(asn_decodevalue_bitstring_encap_octet(&crl->signatureValue, &ba_signature));
        }
        else {
            DO(asn_BITSTRING2ba(&crl->signatureValue, &ba_signature));
        }

        ret = verify_signature(s_signalgo, ba_tbs, false, cerIssuer->baSPKI, ba_signature);
        switch (ret) {
        case RET_OK:
            statusSign = SIGNATURE_VERIFY::STATUS::VALID;
            break;
        case RET_VERIFY_FAILED:
            statusSign = SIGNATURE_VERIFY::STATUS::INVALID;
            break;
        default:
            statusSign = SIGNATURE_VERIFY::STATUS::FAILED;
        }
    }
    else {
        //  Nothing
    }

cleanup:
    asn_free(get_X509Tbs_desc(), x509_tbs);
    ba_free(ba_signature);
    ba_free(ba_tbs);
    ::free(s_signalgo);
    return ret;
}


static CrlStore::Item* crlstore_find_last_available (vector<CrlStore::Item*> crlItems)
{
    CrlStore::Item* rv_item = nullptr;
    const ByteArray* ba_maxnumber = nullptr;

    rv_item = crlItems[0];
    if (crlItems.size() > 1) {
        int res = 0;
        ba_maxnumber = rv_item->baCrlNumber;
        DEBUG_OUTCON(printf("find_last_available() [0]  ba_maxnumber: "); ba_print(stdout, ba_maxnumber));
        for (size_t i = 1; i < crlItems.size(); i++) {
            res = ba_cmp(ba_maxnumber, crlItems[i]->baCrlNumber);
            if (res < 0) {
                rv_item = crlItems[i];
                ba_maxnumber = rv_item->baCrlNumber;
                DEBUG_OUTCON(printf("find_last_available() [%d]  ba_maxnumber: ", (int)i); ba_print(stdout, ba_maxnumber));
            }
        }
    }

    return rv_item;
}


CrlStore::CrlStore (void)
{
}

CrlStore::~CrlStore (void)
{
    reset();
}

int CrlStore::addCrl (
        const ByteArray* baEncoded,
        const bool permanent,
        bool& isUnique,
        const Item** crlStoreItem
)
{
    int ret = RET_OK;
    Item* crl_parsed = nullptr;
    const Item* crl_added = nullptr;

    DO(parseCrl(baEncoded, &crl_parsed));

    crl_added = addItem(crl_parsed);
    isUnique = true;//TODO: see CerStore::addCert()
    crl_parsed = nullptr;
    if (crlStoreItem) {
        *crlStoreItem = crl_added;
    }

    if (permanent) {
        saveToFile(crl_added);
    }

cleanup:
    delete crl_parsed;
    return ret;
}

int CrlStore::getCount (
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

CrlStore::Item* CrlStore::getCrl (
        const ByteArray* baAuthorityKeyId,
        const CrlType type
)
{
    mutex mtx;
    mtx.lock();
    vector<Item*> crl_items;
    for (auto& it : m_Items) {
        if ((ba_cmp(it->baAuthorityKeyId, baAuthorityKeyId) == 0) && (it->actuality != Actuality::OBSOLETE) && (it->type == type)) {
            DEBUG_OUTCON(printf("CrlStore::getCrl(): thisUpdate %lld, nextUpdate %lld\n", it->thisUpdate, it->nextUpdate));
            crl_items.push_back(it);
        }
    }

    Item* rv_item = nullptr;
    if (!crl_items.empty()) {
        rv_item = crlstore_find_last_available(crl_items);
        if (rv_item) {
            for (auto& it : crl_items) {
                it->actuality = Actuality::OBSOLETE;
            }
            rv_item->actuality = Actuality::LAST_AVAILABLE;
        }
    }

    mtx.unlock();
    return rv_item;
}

int CrlStore::getCrlByCrlId (
        const ByteArray* baCrlId,
        const Item** crlStoreItem
)
{
    mutex mtx;
    int ret = RET_UAPKI_CRL_NOT_FOUND;
    mtx.lock();

    for (auto& it : m_Items) {
        if (ba_cmp(baCrlId, it->baCrlId) == RET_OK) {
            *crlStoreItem = it;
            ret = RET_OK;
            break;
        }
    }

    mtx.unlock();
    return ret;
}

int CrlStore::load (
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

int CrlStore::reload (void)
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

void CrlStore::reset (void)
{
    mutex mtx;
    mtx.lock();
    for (auto& it : m_Items) {
        delete it;
    }
    m_Items.clear();
    mtx.unlock();
}

const char* CrlStore::certStatusToStr (
        const UapkiNS::CertStatus status
)
{
    int32_t idx = (int32_t)status + 1;
    return CERT_STATUS_STRINGS[(idx < 4) ? idx : 0];
}

const char* CrlStore::crlReasonToStr (
        const UapkiNS::CrlReason reason
)
{
    int32_t idx = (int32_t)reason + 1;
    return CRL_REASON_STRINGS[(idx < 12) ? idx : 0];
}

const CrlStore::RevokedCertItem* CrlStore::foundNearAfter (
        const vector<const RevokedCertItem*>& revokedItems,
        const uint64_t validityTime
)
{
    const RevokedCertItem* rv_item = nullptr;
    if (!revokedItems.empty()) {
        //  Search first near
        for (auto& it : revokedItems) {
            if (validityTime < it->getDate()) {
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
                    if ((validityTime < cur_date) && (cur_date < near_date)) {
                        near_date = rv_item->getDate();
                        rv_item = it;
                    }
                }
            }
        }
    }
    return rv_item;
}

const CrlStore::RevokedCertItem* CrlStore::foundNearBefore (
        const vector<const RevokedCertItem*>& revokedItems,
        const uint64_t validityTime
)
{
    const RevokedCertItem* rv_item = nullptr;
    if (!revokedItems.empty()) {
        //  Search first near
        for (auto& it : revokedItems) {
            if (validityTime > it->getDate()) {
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
                    if ((validityTime > cur_date) && (cur_date > near_date)) {
                        near_date = rv_item->getDate();
                        rv_item = it;
                    }
                }
            }
        }
    }
    return rv_item;
}

int CrlStore::parseCrl (
        const ByteArray* baEncoded,
        Item** item
)
{
    int ret = RET_OK;
    CertificateList_t* crl = nullptr;
    TBSCertList_t* tbs = nullptr;
    ByteArray* ba_authoritykeyid = nullptr;
    ByteArray* ba_crlid = nullptr;
    ByteArray* ba_crlident = nullptr;
    ByteArray* ba_crlnumber = nullptr;
    ByteArray* ba_deltacrl = nullptr;
    ByteArray* ba_issuer = nullptr;
    Item* crl_item = nullptr;
    CrlType crl_type = CrlType::UNDEFINED;
    uint64_t this_update = 0, next_update = 0;
    unsigned long version = 0;

    CHECK_PARAM(baEncoded != nullptr);
    CHECK_PARAM(item != nullptr);

    CHECK_NOT_NULL(crl = (CertificateList_t*)asn_decode_ba_with_alloc(get_CertificateList_desc(), baEncoded));
    tbs = &crl->tbsCertList;

    if (tbs->version) {
        DO(asn_INTEGER2ulong(tbs->version, &version));
    }
    if (!asn_primitive_data_is_equals(&tbs->signature.algorithm, &crl->signatureAlgorithm.algorithm)) {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }
    DO(asn_encode_ba(get_Name_desc(), &tbs->issuer, &ba_issuer));
    DO(asn_decodevalue_pkixtime(&tbs->thisUpdate, &this_update));
    DO(asn_decodevalue_pkixtime(&tbs->nextUpdate, &next_update));

    if (tbs->crlExtensions) {
        DO(extns_get_authority_keyid(tbs->crlExtensions, &ba_authoritykeyid));
        DO(extns_get_crl_number(tbs->crlExtensions, &ba_crlnumber));
        ret = extns_get_delta_crl_indicator(tbs->crlExtensions, &ba_deltacrl);
        switch (ret) {
        case RET_OK:
            crl_type = CrlType::DELTA;
            break;
        case RET_UAPKI_EXTENSION_NOT_PRESENT:
            crl_type = CrlType::FULL;
            break;
        default:
            SET_ERROR(RET_UAPKI_INVALID_STRUCT);
        }
        DO(encode_crlid(tbs, ba_crlnumber, &ba_crlid));
        DO(encode_crlidentifier(tbs, ba_crlnumber, &ba_crlident));
    }
    else {
        crl_type = CrlType::V1;
    }

    crl_item = new Item(crl_type);
    if (crl_item) {
        crl_item->baEncoded = baEncoded;
        crl_item->crl = crl;
        crl_item->baCrlId = ba_crlid;
        crl_item->baIssuer = ba_issuer;
        crl_item->thisUpdate = this_update;
        crl_item->nextUpdate = next_update;
        crl_item->baAuthorityKeyId = ba_authoritykeyid;
        crl_item->baCrlNumber = ba_crlnumber;
        crl_item->baDeltaCrl = ba_deltacrl;
        crl_item->baCrlIdentifier = ba_crlident;

        crl = nullptr;
        ba_authoritykeyid = nullptr;
        ba_crlid = nullptr;
        ba_crlident = nullptr;
        ba_crlnumber = nullptr;
        ba_deltacrl = nullptr;
        ba_issuer = nullptr;
        *item = crl_item;
        crl_item = nullptr;
    }

cleanup:
    asn_free(get_CertificateList_desc(), crl);
    ba_free(ba_authoritykeyid);
    ba_free(ba_crlid);
    ba_free(ba_crlident);
    ba_free(ba_crlnumber);
    ba_free(ba_deltacrl);
    ba_free(ba_issuer);
    delete crl_item;
    return ret;
}

CrlStore::Item* CrlStore::addItem (
        Item* item
)
{
    mutex mtx;
    mtx.lock();

    DEBUG_OUTCON(printf("CRL info:\n  crlType: %d\n  thisUpdate: %llu\n  nextUpdate: %llu\n", (int)item->type, item->thisUpdate, item->nextUpdate));
    DEBUG_OUTCON(if (item->crl->tbsCertList.revokedCertificates) { printf("  count revoked certs: %d\n", item->crl->tbsCertList.revokedCertificates->list.count); });
    DEBUG_OUTCON(printf("  AuthorityKeyId,    hex: ");  ba_print(stdout, item->baAuthorityKeyId));
    DEBUG_OUTCON(printf("  CrlNumber,         hex: ");  ba_print(stdout, item->baCrlNumber));
    DEBUG_OUTCON(if (item->type == CrlType::DELTA) { printf("  DeltaCrlIndicator, hex: ");  ba_print(stdout, item->baDeltaCrl); });
    m_Items.push_back(item);

    mtx.unlock();
    return item;
}

int CrlStore::loadDir (void)
{
    DIR* dir = nullptr;
    struct dirent* in_file;

    if (m_Path.empty()) return RET_OK;

    dir = opendir(m_Path.c_str());
    if (!dir) return RET_UAPKI_CRL_STORE_LOAD_ERROR;

    while ((in_file = readdir(dir))) {
        if (!strcmp(in_file->d_name, ".") || !strcmp(in_file->d_name, "..")) {
            continue;
        }

        //  Check ext of file
        const string s_name = string(in_file->d_name);
        size_t pos = s_name.rfind(CRL_EXT.c_str());
        if (pos != s_name.length() - 4) {
            continue;
        }

        const string crl_path = m_Path + s_name;
        if (!is_dir(crl_path.c_str())) {
            ByteArray* ba_encoded = nullptr;
            int ret = ba_alloc_from_file(crl_path.c_str(), &ba_encoded);
            if (ret != RET_OK) continue;

            Item* crl_item = nullptr;
            ret = parseCrl(ba_encoded, &crl_item);
            if (ret == RET_OK) {
                addItem(crl_item);
            }
            else {
                ba_free(ba_encoded);
            }
        }
    }

    closedir(dir);
    return RET_OK;
}

int CrlStore::saveToFile (
        const Item* crlStoreItem
)
{
    if (m_Path.empty() || ((crlStoreItem->type != CrlType::FULL) && (crlStoreItem->type != CrlType::DELTA))) return RET_OK;

    string s_hex = StrUtils::hexFromBa(crlStoreItem->baAuthorityKeyId);
    if (s_hex.empty()) return RET_OK;

    string s_path = m_Path + s_hex + ((crlStoreItem->type == CrlType::FULL) ? "-full-" : "-delta-");
    s_hex = StrUtils::hexFromBa(crlStoreItem->baCrlNumber);
    s_path += s_hex + CRL_EXT;

    const int ret = ba_to_file(crlStoreItem->baEncoded, s_path.c_str());
    return ret;
}

