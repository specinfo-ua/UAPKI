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

#define FILE_MARKER "uapki/crl-store.cpp"

#include <map>
#include <string.h>
#include "crl-store.h"
#include "ba-utils.h"
#include "dirent-internal.h"
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

namespace UapkiNS {

namespace Crl {


static bool check_uris_delta (
        const Type crlType,
        const vector<string>& urisDeltaFromCrl,
        const vector<string>& urisDeltaFromCert
)
{
    if (crlType == Type::FULL) {
        if (!urisDeltaFromCrl.empty() && !urisDeltaFromCert.empty()) {
            return (urisDeltaFromCrl[0] == urisDeltaFromCert[0]);
        }
        //else: No checking - always return TRUE
    }
    //else: No checking - always return TRUE

    return true;
}   //  check_uris_delta

static CrlItem* find_last_available (
        const vector<CrlItem*>& crlItems
)
{
    CrlItem* rv_item = nullptr;
    if (!crlItems.empty()) {
        rv_item = crlItems[0];
        if (crlItems.size() > 1) {
            const ByteArray* ba_maxnumber = rv_item->getCrlNumber();
            DEBUG_OUTCON(
                printf("find_last_available() [0]  ba_maxnumber: ");
                ba_print(stdout, ba_maxnumber);
            )
            for (size_t i = 1; i < crlItems.size(); i++) {
                const int res = ba_cmp(ba_maxnumber, crlItems[i]->getCrlNumber());
                if (res < 0) {
                    rv_item = crlItems[i];
                    ba_maxnumber = rv_item->getCrlNumber();
                    DEBUG_OUTCON(
                        printf("find_last_available() [%d]  ba_maxnumber: ", (int)i);
                        ba_print(stdout, ba_maxnumber);
                    )
                }
            }
        }
    }
    return rv_item;
}   //  find_last_available


CrlStore::CrlStore (void)
    : m_UseDeltaCrl(true)
{
}

CrlStore::~CrlStore (void)
{
    reset();
}

void CrlStore::setParams (
        const string& path,
        bool useDeltaCrl
)
{
    m_Path = path;
    m_UseDeltaCrl = useDeltaCrl;
}

int CrlStore::addCrl (
        const ByteArray* baEncoded,
        const bool permanent,
        bool& isUnique,
        CrlItem** crlItem
)
{
    lock_guard<mutex> lock(m_Mutex);

    int ret = RET_OK;
    CrlItem* parsed_item = nullptr;
    CrlItem* added_item = nullptr;

    DO(parseCrl(baEncoded, &parsed_item));

    added_item = addItem(parsed_item);
    isUnique = (added_item == parsed_item);
    if (isUnique) {
        parsed_item = nullptr;
    }
    if (crlItem) {
        *crlItem = added_item;
    }

    if (isUnique && permanent && !m_Path.empty()) {
        if (added_item->setFileName(added_item->generateFileName())) {
            ret = added_item->saveToFile(m_Path);
        }
        else {
            ret = RET_UAPKI_GENERAL_ERROR;
        }
    }

cleanup:
    delete parsed_item;
    return ret;
}

int CrlStore::getCount (
        size_t& count
)
{
    lock_guard<mutex> lock(m_Mutex);

    count = m_Items.size();
    return RET_OK;
}

CrlItem* CrlStore::getCrl (
        const ByteArray* baAuthorityKeyId,
        const Type crlType,
        const vector<string>& urisDeltaFromCert
)
{
    lock_guard<mutex> lock(m_Mutex);

    DEBUG_OUTCON(
        printf("\nCrlStore::getCrl(authKeyId=");
        ba_print(stdout, baAuthorityKeyId);
        printf("  crlType=%d,\n  urisDeltaFromCert.size=%zu)\n", (int)crlType, urisDeltaFromCert.size());
        if (!urisDeltaFromCert.empty()) printf("   urisDeltaFromCert[0]='%s'\n", urisDeltaFromCert[0].c_str());
    );

    vector<CrlItem*> crl_items;
    for (auto& it : m_Items) {
        DEBUG_OUTCON(
            printf(" CrlItem:\n   authKeyId=");
            ba_print(stdout, it->getAuthorityKeyId());
            printf("   crlNumber=");
            ba_print(stdout, it->getCrlNumber());
            printf("   actuality=%d, crlType=%d, count deltaCrl=%zu\n", (int)it->getActuality(), (int)it->getType(), it->getUris().deltaCrl.size());
            if (!it->getUris().deltaCrl.empty()) printf("   deltaCrl[0]='%s'\n", it->getUris().deltaCrl[0].c_str());
        );
        if (
            (ba_cmp(it->getAuthorityKeyId(), baAuthorityKeyId) == 0) &&
            (it->getActuality() != CrlItem::Actuality::OBSOLETE) &&
            (it->getType() == crlType) &&
            check_uris_delta(crlType, it->getUris().deltaCrl, urisDeltaFromCert)
        ) {
            DEBUG_OUTCON(printf("   *** FOUND CrlItem: ThisUpdate %lld, NextUpdate %lld\n", it->getThisUpdate(), it->getNextUpdate()));
            crl_items.push_back(it);
        }
    }

    CrlItem* rv_item = find_last_available(crl_items);
    if (rv_item) {
        DEBUG_OUTCON(printf(" Last AVAILABLE CrlItem: ThisUpdate %lld, NextUpdate %lld\n", rv_item->getThisUpdate(), rv_item->getNextUpdate()));
        for (auto& it : crl_items) {
            it->setActuality((it == rv_item) ? CrlItem::Actuality::LAST_AVAILABLE : CrlItem::Actuality::OBSOLETE);
        }
    }
    else {
        DEBUG_OUTCON(printf(" Last AVAILABLE CrlItem: NOT FOUND\n"));
    }

    return rv_item;
}

int CrlStore::getCrlByCrlId (
        const ByteArray* baCrlId,
        CrlItem** crlItem
)
{
    lock_guard<mutex> lock(m_Mutex);

    int ret = RET_UAPKI_CRL_NOT_FOUND;
    for (auto& it : m_Items) {
        if (ba_cmp(baCrlId, it->getCrlId()) == RET_OK) {
            *crlItem = it;
            ret = RET_OK;
            break;
        }
    }

    return ret;
}

int CrlStore::getCrlByIndex (
        const size_t index,
        CrlItem** crlItem
)
{
    lock_guard<mutex> lock(m_Mutex);

    int ret = RET_UAPKI_CRL_NOT_FOUND;
    if (index < m_Items.size()) {
        *crlItem = m_Items[index];
        ret = RET_OK;
    }

    return ret;
}

vector<CrlItem*> CrlStore::getCrlItems (void)
{
    lock_guard<mutex> lock(m_Mutex);

    return m_Items;
}

int CrlStore::load (void)
{
    lock_guard<mutex> lock(m_Mutex);

    const int ret = loadDir();
    if (ret != RET_OK) {
        reset();
    }
    return ret;
}

int CrlStore::removeCrl (
        const ByteArray* baCrlId,
        const bool permanent
)
{
    lock_guard<mutex> lock(m_Mutex);

    int ret = RET_OK;
    vector<CrlItem*> deleting_items, items, items2;
    
    if (baCrlId) {
        for (auto& it : m_Items) {
            if (ba_cmp(baCrlId, it->getCrlId()) == RET_OK) {
                deleting_items.push_back(it);
            }
            else {
                items.push_back(it);
            }
        }
        if (deleting_items.empty()) {
            return RET_UAPKI_CRL_NOT_FOUND;
        }
    }
    else {
        items = m_Items;
    }

    for (auto& it : items) {
        if (it->getActuality() == CrlItem::Actuality::OBSOLETE) {
            deleting_items.push_back(it);
        }
        else {
            items2.push_back(it);
        }
    }

    m_Items = items2;
    for (auto& it : deleting_items) {
        if (permanent) {
            const string s_fullpath = m_Path + it->getFileName();
            (void)delete_file(s_fullpath.c_str());
        }
        delete it;
    }

    return ret;
}

CrlItem* CrlStore::addItem (
        CrlItem* item
)
{
    for (auto& it : m_Items) {
        const bool authoritykeyid_is_equal = (ba_cmp(item->getAuthorityKeyId(), it->getAuthorityKeyId()) == 0);
        const bool crlnumber_is_equal = (ba_cmp(item->getCrlNumber(), it->getCrlNumber()) == 0);
        if (authoritykeyid_is_equal && crlnumber_is_equal) {
            DEBUG_OUTCON(
                printf("CrlStore::addItem(), CRL is found. AuthorityKeyId and CrlNumber: ");
                ba_print(stdout, it->getAuthorityKeyId());
                ba_print(stdout, it->getCrlNumber());
            )
            return it;
        }
    }

    DEBUG_OUTCON(printf("CRL info:\n  crlType: %d\n  m_ThisUpdate: %llu\n  m_nextUpdate: %llu\n", (int)item->getType(), item->getThisUpdate(), item->getNextUpdate()));
    DEBUG_OUTCON(if (item->getCrl()->tbsCertList.revokedCertificates) { printf("  count revoked certs: %d\n", item->getCrl()->tbsCertList.revokedCertificates->list.count); });
    DEBUG_OUTCON(printf("  AuthorityKeyId,    hex: ");  ba_print(stdout, item->getAuthorityKeyId()));
    DEBUG_OUTCON(printf("  CrlNumber,         hex: ");  ba_print(stdout, item->getCrlNumber()));
    DEBUG_OUTCON(if (item->getType() == Type::DELTA) { printf("  DeltaCrlIndicator, hex: ");  ba_print(stdout, item->getDeltaCrl()); });
    m_Items.push_back(item);
    DEBUG_OUTCON(
        printf("CrlStore::addItem(), CRL is unique - add it. AuthorityKeyId and CrlNumber: ");
        ba_print(stdout, item->getAuthorityKeyId());
        ba_print(stdout, item->getCrlNumber());
    )
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

        //  Check file-extension
        const string s_name = string(in_file->d_name);
        const size_t pos = s_name.rfind(CRL_EXT);
        if (pos != s_name.length() - CRL_EXT_LEN) {
            continue;
        }

        const string s_fullpath = m_Path + s_name;
        if (!is_dir(s_fullpath.c_str())) {
            SmartBA sba_encoded;
            int ret = ba_alloc_from_file(s_fullpath.c_str(), &sba_encoded);
            if (ret != RET_OK) continue;

            CrlItem* parsed_item = nullptr;
            ret = parseCrl(sba_encoded.get(), &parsed_item);
            if (ret == RET_OK) {
                (void)sba_encoded.set(nullptr);
                (void)parsed_item->setFileName(s_name);
                CrlItem* added_item = addItem(parsed_item);
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

    return removeObsolete();
}

int CrlStore::removeObsolete (void)
{
    //  Build maps and list
    map<string, CrlItem*> map_fullcrls, map_deltacrls;
    vector<CrlItem*> deleting_items;
    for (const auto& it : m_Items) {
        string s_id = Util::baToHex(it->getAuthorityKeyId());
        if (s_id.empty()) continue;

        if (it->getType() == Type::FULL) {
            //  Check unique CRL-files
            if (!it->getUris().deltaCrl.empty()) {
                s_id += "-" + it->getUris().deltaCrl[0];
            }

            auto it_value = map_fullcrls.find(s_id);
            if (it_value == map_fullcrls.end()) {
                map_fullcrls.insert(pair<string, CrlItem*>(s_id, it));
            }
            else {
                //  Check freshest full-CRL
                if (it->getThisUpdate() > it_value->second->getThisUpdate()) {
                    deleting_items.push_back(it_value->second);
                    it_value->second = it;
                }
            }
        }
        else {
            //  Check unique CRL-files
            const string s_deltacrl = Util::baToHex(it->getDeltaCrl());
            if (s_deltacrl.empty()) continue;

            s_id += "-" + s_deltacrl;
            auto it_value = map_deltacrls.find(s_id);
            if (it_value == map_deltacrls.end()) {
                map_deltacrls.insert(pair<string, CrlItem*>(s_id, it));
            }
            else {
                //  Check freshest delta-CRL
                if (it->getThisUpdate() > it_value->second->getThisUpdate()) {
                    deleting_items.push_back(it_value->second);
                    it_value->second = it;
                }
            }
        }
    }

    //  Check delta with present her full
    for (auto& it_delta : map_deltacrls) {
        bool is_found = false;
        for (const auto& it_full : map_fullcrls) {
            is_found = (ba_cmp(it_delta.second->getDeltaCrl(), it_full.second->getCrlNumber()) == 0);
            if (is_found) break;
        }
        if (!is_found) {
            deleting_items.push_back(it_delta.second);
            it_delta.second = nullptr;
        }
    }

    //  Delete CRL from FS and release CrlStore::CrlItem
    for (auto& it : deleting_items) {
        const string s_fullpath = m_Path + it->getFileName();
        (void)delete_file(s_fullpath.c_str());
        delete it;
    }

    //  Create new list CrlStore::CrlItem
    m_Items.clear();
    for (const auto& it : map_fullcrls) {
        m_Items.push_back(it.second);
    }
    for (const auto& it : map_deltacrls) {
        if (it.second) {
            m_Items.push_back(it.second);
        }
    }

    return RET_OK;
}

void CrlStore::reset (void)
{
    for (auto& it : m_Items) {
        delete it;
    }
    m_Items.clear();
}


}   //  end namespace Crl

}   //  end namespace UapkiNS
