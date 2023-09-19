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

#define FILE_MARKER "uapki/cer-store.cpp"

#include <string.h>
#include "cer-store.h"
#include "ba-utils.h"
#include "crl-item.h"
#include "dirent-internal.h"
#include "dstu-ns.h"
#include "extension-helper.h"
#include "macros-internal.h"
#include "oids.h"
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


static int get_cert_by_keyid_internal (
        const vector<CerItem*>& cerItems,
        const ByteArray* baKeyId,
        CerItem** cerItem
)
{
    int ret = RET_UAPKI_CERT_NOT_FOUND;
    for (auto& it : cerItems) {
        if (ba_cmp(baKeyId, it->getKeyId()) == RET_OK) {
            *cerItem = it;
            ret = RET_OK;
            break;
        }
    }
    return ret;
}


CerStore::CerStore (void)
{
    m_Items.reserve(CERSTORE_RESERVE_ITEMS);
}

CerStore::~CerStore (void)
{
    reset();
}

void CerStore::setParams (
        const string& path
)
{
    m_Path = path;
}

int CerStore::addCerts (
        const bool trusted,
        const bool permanent,
        const VectorBA& vbaEncodedCerts,
        vector<AddedCerItem>& addedCerItems
)
{
    lock_guard<mutex> lock(m_Mutex);

    if (vbaEncodedCerts.empty()) return RET_OK;

    addedCerItems.resize(vbaEncodedCerts.size());
    for (size_t i = 0; i < vbaEncodedCerts.size(); i++) {
        AddedCerItem& added_ceritem = addedCerItems[i];
        added_ceritem.errorCode = parseCert((const ByteArray*)vbaEncodedCerts[i], &added_ceritem.cerItem);
    }

    for (auto& it : addedCerItems) {
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

vector<CerItem*> CerStore::getCerItems (void)
{
    lock_guard<mutex> lock(m_Mutex);

    return m_Items;
}

int CerStore::getCertByCertId (
        const ByteArray* baCertId,
        CerItem** cerItem
)
{
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
    lock_guard<mutex> lock(m_Mutex);

    const int ret = get_cert_by_keyid_internal(m_Items, baKeyId, cerItem);
    return ret;
}

int CerStore::getCertBySID (
        const ByteArray* baSID,
        CerItem** cerItem
)
{
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
    lock_guard<mutex> lock(m_Mutex);

    int ret = RET_UAPKI_CERT_NOT_FOUND;
    for (auto& it : m_Items) {
        if (ba_cmp(baSPKI, it->getSpki()) == RET_OK) {
            *cerItem = it;
            ret = RET_OK;
            break;
        }
    }
    return ret;
}

int CerStore::getCertBySubject (
        const ByteArray* baSubject,
        CerItem** cerItem
)
{
    lock_guard<mutex> lock(m_Mutex);

    int ret = RET_UAPKI_CERT_NOT_FOUND;
    for (auto& it : m_Items) {
        if (ba_cmp(baSubject, it->getSubject()) == RET_OK) {
            *cerItem = it;
            ret = RET_OK;
            break;
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
    lock_guard<mutex> lock(m_Mutex);

    count = m_Items.size();
    return RET_OK;
}

int CerStore::getCount (
        size_t& count,
        size_t& countTrusted
)
{
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
    if (ba_cmp(cerSubject->getKeyId(), cerSubject->getAuthorityKeyId()) != 0) {
        isSelfSigned = false;
        ret = getCertByKeyId(cerSubject->getAuthorityKeyId(), cerIssuer);
        if (ret == RET_UAPKI_CERT_NOT_FOUND) {
            ret = RET_UAPKI_CERT_ISSUER_NOT_FOUND;
        }
    }
    else {
        isSelfSigned = true;
        *cerIssuer = cerSubject;
    }

    return ret;
}

int CerStore::load (void)
{
    lock_guard<mutex> lock(m_Mutex);

    const int ret = loadDir();
    if (ret != RET_OK) {
        reset();
    }
    return ret;
}

int CerStore::removeMarkedCerts (
        const bool permanent
)
{
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

    int ret = RET_OK;
    if (permanent && !m_Path.empty()) {
        for (auto it = removing_items.begin(); it != removing_items.end(); it++) {
            CerItem* cer_item = *it;
            if (!cer_item->getFileName().empty()) {
                const string fn_cert = m_Path + cer_item->getFileName();
                if (delete_file(fn_cert.c_str()) != 0) {
                    ret = RET_UAPKI_FILE_DELETE_ERROR;
                }
            }
        }
    }

    for (auto it = removing_items.begin(); it != removing_items.end(); it++) {
        CerItem* cer_item = *it;
        delete cer_item;
    }

    return ret;
}

CerItem* CerStore::addItem (
        CerItem* item
)
{
    for (auto& it : m_Items) {
        const int ret = ba_cmp(item->getKeyId(), it->getKeyId());
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


}   //  end namespace Cert

}   //  end namespace UapkiNS
