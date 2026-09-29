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

#define FILE_MARKER "uapki/src/cer-store.cpp"

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <string.h>
#include "cer-store.h"
#include <algorithm>
#include "ba-utils.h"
#include "crl-item.h"
#include "dirent-internal.h"
#include "dstu-ns.h"
#include "extension-helper.h"
#include "macros-internal.h"
#include "oids.h"
#include "path-lock.h"
#include "time-util.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


static const size_t CERSTORE_RESERVE_ITEMS = 10000;


namespace UapkiNS {

namespace Cert {

static bool set_ceritem_by_notbefore_internal (
        CerItem** cerItemActual,
        const CerItem* cerItemNew
)
{
    if (cerItemNew->isUniqueKeyId()) {
        // one cert - to break (return true)
        *cerItemActual = (CerItem*)cerItemNew;
        return true;
    }

    // few certs - to continue search (return false)
    if (*cerItemActual == nullptr) {
        *cerItemActual = (CerItem*)cerItemNew;
    }
    else {
        if (cerItemNew->getNotBefore() > (*cerItemActual)->getNotBefore()) {
            *cerItemActual = (CerItem*)cerItemNew;
        }
    }
    return false;
}

static int get_cert_by_keyid_internal (
        const vector<CerItem*>& cerItems,
        const ByteArray* baKeyId,
        CerItem** cerItem
)
{
    int ret = RET_UAPKI_CERT_NOT_FOUND;
    for (auto& it : cerItems) {
        if (ba_cmp(baKeyId, it->getKeyId()) == 0) {
            ret = RET_OK;
            if (set_ceritem_by_notbefore_internal(cerItem, it)) {
                break;
            }
        }
    }
    return ret;
}


CerStore::CerStore (void)
    : m_Overlay(nullptr)
    , m_Base(nullptr)
{
    m_Items.reserve(CERSTORE_RESERVE_ITEMS);
}

CerStore::CerStore (
        CerStore* overlay,
        CerStore* base
)
    : m_Overlay(overlay)
    , m_Base(base)
{
}

CerStore::~CerStore (void)
{
    reset();
}

void CerStore::setParams (
        const string& path
)
{
    if (m_Overlay) return m_Overlay->setParams(path);

    m_Path = path;
}

int CerStore::addCerts (
        const bool trusted,
        const bool permanent,
        const VectorBA& vbaEncodedCerts,
        vector<AddedCerItem>& addedCerItems
)
{
    if (m_Overlay) {
        if (permanent) return m_Base->addCerts(trusted, permanent, vbaEncodedCerts, addedCerItems);

        //  Certificates the shared base already holds are reported from there, only unknown ones enter the overlay
        addedCerItems.assign(vbaEncodedCerts.size(), AddedCerItem());
        VectorBA vba_unknown;
        vector<size_t> idx_unknown;
        for (size_t i = 0; i < vbaEncodedCerts.size(); i++) {
            CerItem* cer_item = nullptr;
            if (m_Overlay->getCertByEncoded(vbaEncodedCerts[i], &cer_item) == RET_OK ||
                m_Base->getCertByEncoded(vbaEncodedCerts[i], &cer_item) == RET_OK) {
                addedCerItems[i].cerItem = cer_item;
            }
            else {
                vba_unknown.push_back(vbaEncodedCerts[i]);
                idx_unknown.push_back(i);
            }
        }

        int ret = RET_OK;
        if (!vba_unknown.empty()) {
            vector<AddedCerItem> added_unknown;
            ret = m_Overlay->addCerts(trusted, permanent, vba_unknown, added_unknown);
            for (size_t i = 0; (ret == RET_OK) && (i < added_unknown.size()); i++) {
                addedCerItems[idx_unknown[i]] = added_unknown[i];
            }
        }
        vba_unknown.clear();
        return ret;
    }

    if (vbaEncodedCerts.empty()) return RET_OK;

    addedCerItems.assign(vbaEncodedCerts.size(), AddedCerItem());
    std::vector<bool> parsed(vbaEncodedCerts.size(), false);
    // Parse only new certificates, outside the store lock. ApiGate keeps
    // returned items alive; addItem below resolves concurrent insertions.
    for (size_t i = 0; i < vbaEncodedCerts.size(); i++) {
        AddedCerItem& item = addedCerItems[i];
        if (getCertByEncoded(vbaEncodedCerts[i], &item.cerItem) == RET_OK) continue;
        item.errorCode = parseCert(vbaEncodedCerts[i], &item.cerItem);
        parsed[i] = (item.errorCode == RET_OK);
    }

    lock_guard<mutex> lock(m_Mutex);
    for (size_t i = 0; i < addedCerItems.size(); i++) {
        if (!parsed[i]) continue;
        AddedCerItem& it = addedCerItems[i];
        if (it.errorCode != RET_OK) continue;

        CerItem* added_ceritem = addItem(it.cerItem);
        it.isUnique = (it.cerItem == added_ceritem);
        if (it.isUnique) {
            it.cerItem->setTrusted(trusted);
            it.cerItem->markToRemove(!trusted && !permanent);
        }
        else {
            //  Delete parsed CerItem and set existing CerItem
            delete it.cerItem;
            it.cerItem = added_ceritem;
        }
    }

    if (permanent && !m_Path.empty()) {
        for (auto& it : addedCerItems) {
            if ((it.errorCode == RET_OK) && it.isUnique) {
                CerItem& cer_item = *it.cerItem;
                if (cer_item.setFileName(cer_item.generateFileName())) {
                    const string s_fullpath = m_Path + cer_item.getFileName();
                    it.errorCode = ba_to_file(cer_item.getEncoded(), s_fullpath.c_str());
                }
                else {
                    it.errorCode = RET_UAPKI_GENERAL_ERROR;
                }
            }
        }
    }

    return RET_OK;
}

vector<CerItem*> CerStore::getCerItems (
        const FilterListCerts& filter
)
{
    if (m_Overlay) {
        vector<CerItem*> rv_listcerts = m_Overlay->getCerItems(filter);
        for (auto& it : m_Base->getCerItems(filter)) {
            bool is_present = false;
            for (const auto& it_overlay : rv_listcerts) {
                if (ba_cmp(it->getCertId(), it_overlay->getCertId()) == RET_OK) {
                    is_present = true;
                    break;
                }
            }
            if (!is_present) {
                rv_listcerts.push_back(it);
            }
        }
        return rv_listcerts;
    }

    lock_guard<mutex> lock(m_Mutex);

    vector<CerItem*> rv_listcerts;
    rv_listcerts.reserve(m_Items.size());
    for (auto& it : m_Items) {
        if (filter.check(it)) {
            rv_listcerts.push_back(it);
        }
    }

    return rv_listcerts;
}

int CerStore::getCertByCertId (
        const ByteArray* baCertId,
        CerItem** cerItem
)
{
    if (m_Overlay) {
        const int ret = m_Overlay->getCertByCertId(baCertId, cerItem);
        return (ret == RET_UAPKI_CERT_NOT_FOUND) ? m_Base->getCertByCertId(baCertId, cerItem) : ret;
    }

    lock_guard<mutex> lock(m_Mutex);

    int ret = RET_UAPKI_CERT_NOT_FOUND;
    for (auto& it : m_Items) {
        if (ba_cmp(baCertId, it->getCertId()) == RET_OK) {
            *cerItem = it;
            ret = RET_OK;
            break;
        }
    }
    return ret;
}

int CerStore::getCertByEncoded (
        const ByteArray* baEncoded,
        CerItem** cerItem
)
{
    if (m_Overlay) {
        const int ret = m_Overlay->getCertByEncoded(baEncoded, cerItem);
        return (ret == RET_UAPKI_CERT_NOT_FOUND) ? m_Base->getCertByEncoded(baEncoded, cerItem) : ret;
    }

    lock_guard<mutex> lock(m_Mutex);

    int ret = RET_UAPKI_CERT_NOT_FOUND;
    for (auto& it : m_Items) {
        if (ba_cmp(baEncoded, it->getEncoded()) == RET_OK) {
            *cerItem = it;
            ret = RET_OK;
            break;
        }
    }
    return ret;
}

int CerStore::getCertByIndex (
        const size_t index,
        CerItem** cerItem
)
{
    if (m_Overlay) {
        size_t count_overlay = 0;
        (void)m_Overlay->getCount(count_overlay);
        return (index < count_overlay)
            ? m_Overlay->getCertByIndex(index, cerItem)
            : m_Base->getCertByIndex(index - count_overlay, cerItem);
    }

    lock_guard<mutex> lock(m_Mutex);

    int ret = RET_UAPKI_CERT_NOT_FOUND;
    if (index < m_Items.size()) {
        *cerItem = m_Items[index];
        ret = RET_OK;
    }
    return ret;
}

int CerStore::getCertByIssuerAndSN (
        const ByteArray* baIssuerAndSN,
        CerItem** cerItem
)
{
    //  Note: Use implicit lock_guard, see: getCertByIssuerAndSN()
    SmartBA sba_issuer, sba_serialnumber;
    int ret = parseIssuerAndSN(baIssuerAndSN, &sba_issuer, &sba_serialnumber);
    if (ret == RET_OK) {
        ret = getCertByIssuerAndSN(sba_issuer.get(), sba_serialnumber.get(), cerItem);
    }
    return ret;
}

int CerStore::getCertByIssuerAndSN (
        const ByteArray* baIssuer,
        const ByteArray* baSerialNumber,
        CerItem** cerItem
)
{
    if (m_Overlay) {
        const int ret = m_Overlay->getCertByIssuerAndSN(baIssuer, baSerialNumber, cerItem);
        return (ret == RET_UAPKI_CERT_NOT_FOUND) ? m_Base->getCertByIssuerAndSN(baIssuer, baSerialNumber, cerItem) : ret;
    }

    lock_guard<mutex> lock(m_Mutex);

    int ret = RET_UAPKI_CERT_NOT_FOUND;
    for (auto& it : m_Items) {
        if (
            (ba_cmp(baSerialNumber, it->getSerialNumber()) == RET_OK) &&
            (ba_cmp(baIssuer, it->getIssuer()) == RET_OK)
        ) {
            *cerItem = it;
            ret = RET_OK;
            break;
        }
    }
    return ret;
}

int CerStore::getCertByKeyId (
        const ByteArray* baKeyId,
        CerItem** cerItem
)
{
    if (!cerItem) return RET_UAPKI_INVALID_PARAMETER;
    *cerItem = nullptr;

    if (m_Overlay) {
        const int ret = m_Overlay->getCertByKeyId(baKeyId, cerItem);
        return (ret == RET_UAPKI_CERT_NOT_FOUND) ? m_Base->getCertByKeyId(baKeyId, cerItem) : ret;
    }

    lock_guard<mutex> lock(m_Mutex);

    const int ret = get_cert_by_keyid_internal(m_Items, baKeyId, cerItem);
    return ret;
}

int CerStore::getCertBySID (
        const ByteArray* baSID,
        CerItem** cerItem
)
{
    if (!cerItem) return RET_UAPKI_INVALID_PARAMETER;
    *cerItem = nullptr;

    if (m_Overlay) {
        const int ret = m_Overlay->getCertBySID(baSID, cerItem);
        return (ret == RET_UAPKI_CERT_NOT_FOUND) ? m_Base->getCertBySID(baSID, cerItem) : ret;
    }

    lock_guard<mutex> lock(m_Mutex);

    SmartBA sba_issuer, sba_keyid, sba_serialnum;

    int ret = parseSID(baSID, &sba_issuer, &sba_serialnum, &sba_keyid);
    if (ret != RET_OK) return ret;

    if (sba_keyid.size() > 0) {
        ret = get_cert_by_keyid_internal(m_Items, sba_keyid.get(), cerItem);
        return ret;
    }

    ret = RET_UAPKI_CERT_NOT_FOUND;
    for (auto& it : m_Items) {
        if (
            (ba_cmp(sba_serialnum.get(), it->getSerialNumber()) == RET_OK) &&
            (ba_cmp(sba_issuer.get(), it->getIssuer()) == RET_OK)
        ) {
            *cerItem = it;
            ret = RET_OK;
            break;
        }
    }
    return ret;
}

int CerStore::getCertBySPKI (
        const ByteArray* baSPKI,
        CerItem** cerItem
)
{
    if (!cerItem) return RET_UAPKI_INVALID_PARAMETER;
    *cerItem = nullptr;

    if (m_Overlay) {
        const int ret = m_Overlay->getCertBySPKI(baSPKI, cerItem);
        return (ret == RET_UAPKI_CERT_NOT_FOUND) ? m_Base->getCertBySPKI(baSPKI, cerItem) : ret;
    }

    lock_guard<mutex> lock(m_Mutex);

    int ret = RET_UAPKI_CERT_NOT_FOUND;
    for (auto& it : m_Items) {
        if (ba_cmp(baSPKI, it->getSpki()) == RET_OK) {
            ret = RET_OK;
            if (set_ceritem_by_notbefore_internal(cerItem, it)) {
                break;
            }
        }
    }
    return ret;
}

int CerStore::getCertBySubject (
        const ByteArray* baSubject,
        CerItem** cerItem
)
{
    if (!cerItem) return RET_UAPKI_INVALID_PARAMETER;
    *cerItem = nullptr;

    if (m_Overlay) {
        const int ret = m_Overlay->getCertBySubject(baSubject, cerItem);
        return (ret == RET_UAPKI_CERT_NOT_FOUND) ? m_Base->getCertBySubject(baSubject, cerItem) : ret;
    }

    lock_guard<mutex> lock(m_Mutex);

    int ret = RET_UAPKI_CERT_NOT_FOUND;
    for (auto& it : m_Items) {
        if (ba_cmp(baSubject, it->getSubject()) == RET_OK) {
            ret = RET_OK;
            if (set_ceritem_by_notbefore_internal(cerItem, it)) {
                break;
            }
        }
    }
    return ret;
}

int CerStore::getChainCerts (
        const CerItem* cerSubject,
        vector<CerItem*>& chainCerts
)
{
    //  Note: Use implicit lock_guard, see: getIssuerCert()
    int ret = RET_OK;
    CerItem* cer_subject = (CerItem*)cerSubject;
    CerItem* cer_issuer = nullptr;
    bool is_selfsigned = false;

    while (true) {
        DO(getIssuerCert(cer_subject, &cer_issuer, is_selfsigned));
        if (is_selfsigned) break;
        if (cer_issuer == cerSubject || std::find(chainCerts.begin(), chainCerts.end(), cer_issuer) != chainCerts.end()) {
            SET_ERROR(RET_UAPKI_INVALID_STRUCT);
        }
        chainCerts.push_back(cer_issuer);
        cer_subject = cer_issuer;
    }

cleanup:
    return ret;
}

int CerStore::getChainCerts (
        const CerItem* cerSubject,
        vector<CerItem*>& chainCerts,
        const ByteArray** baIssuerKeyId
)
{
    //  Note: Use implicit lock_guard, see: getIssuerCert()
    int ret = RET_OK;
    CerItem* cer_subject = (CerItem*)cerSubject;
    CerItem* cer_issuer = nullptr;
    bool is_selfsigned = false;

    while (true) {
        ret = getIssuerCert(cer_subject, &cer_issuer, is_selfsigned);
        if (ret == RET_OK) {
            if (is_selfsigned) break;
            if (cer_issuer == cerSubject || std::find(chainCerts.begin(), chainCerts.end(), cer_issuer) != chainCerts.end()) {
                ret = RET_UAPKI_INVALID_STRUCT;
                break;
            }
            chainCerts.push_back(cer_issuer);
            cer_subject = cer_issuer;
        }
        else {
            if (ret == RET_UAPKI_CERT_ISSUER_NOT_FOUND) {
                *baIssuerKeyId = cer_subject->getAuthorityKeyId();
            }
            break;
        }
    }

    return ret;
}

int CerStore::getCount (
        size_t& count
)
{
    if (m_Overlay) {
        size_t count_base = 0;
        (void)m_Overlay->getCount(count);
        (void)m_Base->getCount(count_base);
        count += count_base;
        return RET_OK;
    }

    lock_guard<mutex> lock(m_Mutex);

    count = m_Items.size();
    return RET_OK;
}

int CerStore::getCount (
        size_t& count,
        size_t& countTrusted
)
{
    if (m_Overlay) {
        size_t count_base = 0, counttrusted_base = 0;
        (void)m_Overlay->getCount(count, countTrusted);
        (void)m_Base->getCount(count_base, counttrusted_base);
        count += count_base;
        countTrusted += counttrusted_base;
        return RET_OK;
    }

    lock_guard<mutex> lock(m_Mutex);

    count = m_Items.size();
    countTrusted = 0;
    for (auto& it : m_Items) {
        countTrusted += (it->isTrusted()) ? 1 : 0;
    }
    return RET_OK;
}

int CerStore::getIssuerCert (
        CerItem* cerSubject,
        CerItem** cerIssuer,
        bool& isSelfSigned
)
{
    //  Note: Use implicit lock_guard, see: getCertByKeyId()
    if (!cerSubject || !cerIssuer) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_OK;
    isSelfSigned = cerSubject->isSelfSigned();
    if (!isSelfSigned) {
        ret = getCertByKeyId(cerSubject->getAuthorityKeyId(), cerIssuer);
        if (ret == RET_UAPKI_CERT_NOT_FOUND) {
            ret = RET_UAPKI_CERT_ISSUER_NOT_FOUND;
        }
    }
    else {
        *cerIssuer = cerSubject;
    }

    return ret;
}

int CerStore::load (void)
{
    if (m_Overlay) return m_Overlay->load();

    lock_guard<mutex> lock_path(lockPath(m_Path));
    lock_guard<mutex> lock(m_Mutex);

    const int ret = loadDir();
    if (ret != RET_OK) {
        reset();
    }
    return ret;
}

int CerStore::removeCert (
        CerItem* cerSubject,
        const bool permanent
)
{
    if (m_Overlay) {
        const int ret = m_Overlay->removeCert(cerSubject, permanent);
        return (ret == RET_UAPKI_CERT_NOT_FOUND) ? m_Base->removeCert(cerSubject, permanent) : ret;
    }

    lock_guard<mutex> lock(m_Mutex);

    if (!cerSubject) return RET_UAPKI_INVALID_PARAMETER;

    int ret = RET_UAPKI_CERT_NOT_FOUND;
    for (auto it = m_Items.begin(); it != m_Items.end(); it++) {
        if (*it == cerSubject) {
            m_Items.erase(it);
            ret = RET_OK;
            break;
        }
    }
    if (ret != RET_OK) return ret;

    if (permanent && !m_Path.empty() && !cerSubject->getFileName().empty()) {
        const string fn_cert = m_Path + cerSubject->getFileName();
        if (delete_file(fn_cert.c_str()) != 0) {
            ret = RET_UAPKI_FILE_DELETE_ERROR;
        }
    }

    delete cerSubject;
    return ret;
}

int CerStore::removeMarkedCerts (void)
{
    if (m_Overlay) return m_Overlay->removeMarkedCerts();

    lock_guard<mutex> lock(m_Mutex);

    vector<CerItem*> new_items, removing_items;
    new_items.reserve(m_Items.capacity());
    removing_items.reserve(m_Items.capacity());

    for (const auto& it : m_Items) {
        if (!it->isMarkedToRemove()) {
            new_items.push_back(it);
        }
        else {
            removing_items.push_back(it);
        }
    }

    m_Items = new_items;
    for (auto it = removing_items.begin(); it != removing_items.end(); it++) {
        CerItem* cer_item = *it;
        delete cer_item;
    }

    return RET_OK;
}

CerItem* CerStore::addItem (
        CerItem* item
)
{
    for (auto& it : m_Items) {
        int ret = ba_cmp(item->getKeyId(), it->getKeyId());
        if (ret != 0) continue;

        ret = ba_cmp(item->getAuthorityKeyId(), it->getAuthorityKeyId());
        if (ret != 0) continue;

        DEBUG_OUTCON(
        printf("CerStore::addItem(), cert is found. keyId: "); ba_print(stdout, it->getKeyId());
        printf("  authorityKeyId: "); ba_print(stdout, it->getAuthorityKeyId());
        printf("  notBefore: %08X", uint32_t(it->getNotBefore()));
        );

        if (item->getNotBefore() != it->getNotBefore()) {
            DEBUG_OUTCON(puts("  detected duplicate keyId, reset flag for both"));
            item->setUniqueKeyId(false);
            if (it->isUniqueKeyId()) {
                it->setUniqueKeyId(false);
            }
            continue;
        }
        DEBUG_OUTCON(puts(""));

        return it;
    }

    m_Items.push_back(item);
    DEBUG_OUTCON(printf("CerStore::addItem(), cert is unique - add it. keyId: "); ba_print(stdout, item->getKeyId()));
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

        //  Check file-extension
        const string s_name = string(in_file->d_name);
        const size_t pos = s_name.rfind(CER_EXT);
        if (pos != s_name.length() - CER_EXT_LEN) {
            continue;
        }

        const string s_fullpath = m_Path + s_name;
        if (!is_dir(s_fullpath.c_str())) {
            SmartBA sba_encoded;
            int ret = ba_alloc_from_file(s_fullpath.c_str(), &sba_encoded);
            if (ret != RET_OK) continue;

            CerItem* parsed_item = nullptr;
            ret = parseCert(sba_encoded.get(), &parsed_item);
            if (ret == RET_OK) {
                (void)parsed_item->setFileName(s_name);
                CerItem* added_item = addItem(parsed_item);
                if (added_item != parsed_item) {
                    (void)delete_file(s_fullpath.c_str());
                    delete parsed_item;
                }
            }
        }
    }

    closedir(dir);

    for (auto& it : m_Items) {
        const string s_genname = it->generateFileName();
        if (s_genname != it->getFileName()) {
            const string s_oldpath = m_Path + it->getFileName();
            const string s_newpath = m_Path + s_genname;
            if (rename(s_oldpath.c_str(), s_newpath.c_str()) == 0) {
                (void)it->setFileName(s_genname);
            }
        }
    }

    return RET_OK;
}

void CerStore::reset (void)
{
    for (auto& it : m_Items) {
        delete it;
    }
    m_Items.clear();
}

void CerStore::saveStatToLog (
        const string& message
)
{
    if (m_Overlay) return m_Overlay->saveStatToLog(message);

    static size_t ctr_stat = 0;

    FILE* f = fopen("uapki-cer-store.log", "a");
    if (!f) return;

    uint64_t ms = TimeUtil::mtimeNow();
    string s_line = string("*** STAT[") + to_string(ctr_stat) + string("] BEGIN *** '") + message;
    s_line += string("' TIME ") + TimeUtil::mtimeToFtime(ms) + string(" ***\n");
    fputs(s_line.c_str(), f);

    size_t idx = 0;
    for (const auto& it : m_Items) {
        CertStatusInfo& certstatus_byocsp = it->getCertStatusByOcsp();
        s_line = string("CER[") + to_string(idx++) + string("]\n");
        s_line += string("KeyId: ") + Util::baToHex(it->getKeyId()) + string("\n");
        s_line += string("SerialNumber: ") + Util::baToHex(it->getSerialNumber()) + string("\n");
        s_line += string("OCSP, status: ") + Crl::certStatusToStr(certstatus_byocsp.status) + string("\n");
        s_line += string("OCSP, validTime: ") + string(certstatus_byocsp.isExpired(ms) ? "IS EXPIRED " : "IS VALID   ");
        s_line += TimeUtil::mtimeToFtime(certstatus_byocsp.validTime) + string("\n");
        s_line += string("\n");
        fputs(s_line.c_str(), f);
    }

    s_line = string("*** STAT[") + to_string(ctr_stat++) + string("] END *****\n\n");
    fputs(s_line.c_str(), f);

    fclose(f);
}

bool CerStore::FilterListCerts::check (
    const Cert::CerItem* cerItem
) const
{
    if (!subjectKeyIds.empty()) {
        bool is_equal = false;
        for (const auto& it : subjectKeyIds) {
            if (ba_cmp(it, cerItem->getKeyId()) == 0) {
                is_equal = true;
                break;
            }
        }
        if (!is_equal) {
            return false;
        }
    }

    if (!publicKeyBytes.empty()) {
        if (publicKeyBytes.size() != cerItem->getPublicKeySize()) {
            return false;
        }
        const ByteArray* ba_spki = cerItem->getSpki();
        if (ba_get_len(ba_spki) > publicKeyBytes.size()) {
            if (memcmp(ba_get_buf((ByteArray*)ba_spki) + ba_get_len(ba_spki) - publicKeyBytes.size(), publicKeyBytes.buf(), publicKeyBytes.size()) != 0) {
                return false;
            }
        }
        else {
            return false;
        }
    }

    return true;
}


}   //  end namespace Cert

}   //  end namespace UapkiNS
