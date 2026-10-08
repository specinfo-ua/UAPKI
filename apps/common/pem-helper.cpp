/*
 * Copyright (c) 2024, The UAPKI Project Authors.
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

#include "pem-helper.h"
#include "ba-utils.h"
#include "uapkic.h"
#include "uapkif.h"
#include "uapki-errors.h"
#include "uapki-ns.h"
#include <stdio.h>
#include <string.h>


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;
using namespace UapkiNS;


static const char* LINE_CERT_BEGIN  = "-----BEGIN CERTIFICATE-----\n";
static const char* LINE_CERT_END    = "\n-----END CERTIFICATE-----\n";
static const size_t PEM_LIN_SIZE    = 64;


static string text_to_cols (
        const char* pstr
)
{
    const size_t len = strlen(pstr);
    string rv_s;
    rv_s.reserve(len + (len + PEM_LIN_SIZE - 1) / PEM_LIN_SIZE);
    for (size_t cnt = 0; pstr[0]; pstr++, cnt++) {
        if (cnt == PEM_LIN_SIZE) {
            rv_s.push_back('\n');
            cnt = 0;
        }
        rv_s.push_back(pstr[0]);
    }
    return rv_s;
}   //  text_to_cols


PemHelper::PemHelper (void)
{
    DEBUG_OUTCON(puts("PemHelper::PemHelper()"));
}

PemHelper::~PemHelper (void)
{
    DEBUG_OUTCON(puts("PemHelper::~PemHelper()"));
}

int PemHelper::addCert (
        const ByteArray* baCertEncoded
)
{
    string s_item;
    if (!baCertEncoded) return RET_UAPKI_INVALID_PARAMETER;

    s_item += string(LINE_CERT_BEGIN);
    char* s_base64 = nullptr;
    int ret = ba_to_base64_with_alloc(baCertEncoded, &s_base64);
    if (ret != RET_OK) return ret;

    s_item += text_to_cols(s_base64);
    uapkic_free(s_base64);

    s_item += string(LINE_CERT_END);
    m_Items.push_back(s_item);
    return RET_OK;
}

int PemHelper::toFile (
        const string& fileName
) const
{
    size_t len = 0;
    for (const auto& it : m_Items) {
        len += it.length();
    }

    SmartBA sba_data;
    if (!sba_data.set(ba_alloc_by_len(len))) {
        return RET_UAPKI_GENERAL_ERROR;
    }

    uint8_t* buf = sba_data.buf();
    for (const auto& it : m_Items) {
        memcpy(buf, it.c_str(), it.length());
        buf += it.length();
    }

    const int ret = ba_to_file(sba_data.get(), fileName.c_str());
    return ret;
}

int PemHelper::loadCerts (
        const string& fileName,
        vector<ByteArray*>& certs
)
{
    static const string BEGIN = "-----BEGIN CERTIFICATE-----";
    static const string END = "-----END CERTIFICATE-----";

    SmartBA sba_file;
    int ret = ba_alloc_from_file(fileName.c_str(), &sba_file);
    if (ret != RET_OK) return ret;
    if (sba_file.empty()) return RET_UAPKI_INVALID_STRUCT;

    const string text((const char*)sba_file.buf(), sba_file.size());
    size_t pos = text.find(BEGIN);
    if (pos == string::npos) {
        //  DER
        certs.push_back(sba_file.pop());
        return RET_OK;
    }

    while (pos != string::npos) {
        const size_t start = pos + BEGIN.length();
        const size_t end = text.find(END, start);
        if (end == string::npos) return RET_UAPKI_INVALID_STRUCT;

        string s_base64;
        for (size_t i = start; i < end; i++) {
            const char c = text[i];
            if ((c != '\r') && (c != '\n') && (c != ' ') && (c != '\t')) {
                s_base64.push_back(c);
            }
        }
        ByteArray* ba_cert = ba_alloc_from_base64(s_base64.c_str());
        if (!ba_cert) return RET_UAPKI_INVALID_STRUCT;
        certs.push_back(ba_cert);

        pos = text.find(BEGIN, end + END.length());
    }
    return RET_OK;
}
