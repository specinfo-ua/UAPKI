/*
 * Copyright (c) 2026, The UAPKI Project Authors.
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

#include "app-common.h"
#include <chrono>
#include <stdio.h>
#include "ba-utils.h"
#include "http-helper.h"
#include "pem-helper.h"


extern "C" const char* error_code_to_str (int errorCode);


using namespace std;


namespace AppCommon {

const char* LF  = "\n";
const char* TAB = "  ";


int HttpSession::init (void)
{
    return HttpHelper::init(false, "", "");
}

HttpSession::~HttpSession (void)
{
    HttpHelper::deinit();
}

WorkFlowInfo::~WorkFlowInfo (void)
{
    static const char* SEPARATOR = "\n========================================\n";
    puts("");
    for (const string* section : { &cert, &http, &detail, &signature, &save }) {
        if (!section->empty()) printf("%s%s", SEPARATOR, section->c_str());
    }
    printf("%sResult: %s\n", SEPARATOR, errcodeToStr(ret).c_str());
}

string baToHex (
        const ByteArray* ba
)
{
    static const char HEX[] = "0123456789ABCDEF";
    const uint8_t* pbuf = ba_get_buf_const(ba);
    const size_t len = ba_get_len(ba);
    string rv_hex;
    if (pbuf) {
        for (size_t i = 0; i < len; i++) {
            rv_hex.push_back(HEX[(pbuf[i] >> 4) & 0x0F]);
            rv_hex.push_back(HEX[pbuf[i] & 0x0F]);
        }
    }
    return rv_hex;
}

string errcodeToStr (
        const int errCode
)
{
    const char* s_err = error_code_to_str(errCode);
    return string(s_err ? s_err : "");
}

int showOptionError (
        const int errCode,
        const string& errMessage
)
{
    printf("Error: %s\n", errMessage.c_str());
    puts("Type --help for a list.");
    return errCode;
}

int checkParsedOptions (
        const GetOptHelper::Error error,
        const GetOptHelper& helper,
        const int argc
)
{
    switch (error) {
    case GetOptHelper::Error::OK:
        return RET_OK;
    case GetOptHelper::Error::INVALID_COUNT_ARGUMENTS:
        return showOptionError(-1, string("invalid count arguments - ") + to_string(argc - 1));
    case GetOptHelper::Error::INVALID_OPTION:
        return showOptionError(-1, string("invalid option ") + helper.lastArg());
    case GetOptHelper::Error::UNKNOWN_OPTION:
        return showOptionError(-1, string("unknown option ") + helper.lastArg());
    case GetOptHelper::Error::ALREADY_OPTION:
        return showOptionError(-1, string("already option ") + helper.lastArg());
    case GetOptHelper::Error::OPTION_NEED_PARAMETER:
        return showOptionError(-1, string("option ") + helper.lastArg() + string(" need parameter"));
    default:
        return showOptionError(-1, string("invalid options"));
    }
}

int saveToFile (
        const ByteArray* baData,
        const string& fileName,
        const string& what,
        WorkFlowInfo& wfi
)
{
    const int ret = ba_to_file(baData, fileName.c_str());
    wfi.save += what + string(" is ") + string((ret == RET_OK) ? "saved" : "not saved");
    wfi.save += string(" to file: ") + fileName + LF;
    return ret;
}

int saveCertsToPem (
        const vector<ByteArray*>& certs,
        const string& fileName,
        WorkFlowInfo& wfi
)
{
    PemHelper pem_helper;
    for (const auto& it : certs) {
        (void)pem_helper.addCert(it);
    }
    const int ret = pem_helper.toFile(fileName);
    wfi.save += string("Certificates (") + to_string(certs.size()) + string(") are ");
    wfi.save += string((ret == RET_OK) ? "saved" : "not saved") + string(" to file: ") + fileName + LF;
    return ret;
}

int postRequest (
        const string& url,
        const string& header,
        const ByteArray* baRequest,
        const string& what,
        ByteArray** baResponse,
        WorkFlowInfo& wfi
)
{
    wfi.http += string("POST url=") + url + LF;
    wfi.http += TAB + header + LF;
    wfi.http += TAB + string("Content-Length: ") + to_string(ba_get_len(baRequest)) + LF;

    const auto dt_start = chrono::high_resolution_clock::now();
    const int ret = HttpHelper::post(url, header.c_str(), baRequest, baResponse);
    const chrono::duration<float> difference = chrono::high_resolution_clock::now() - dt_start;

    wfi.http += TAB + string("HTTP/UAPKI result: ") + errcodeToStr(ret) + LF;
    wfi.http += TAB + string("Elapsed time: ") + to_string(static_cast<int>(1000 * difference.count())) + string(" ms") + LF;
    if (ret == RET_OK) {
        wfi.http += string("Received ") + what + string(", bytes: ") + to_string(ba_get_len(*baResponse)) + LF;
    }
    return ret;
}

}   //  end namespace AppCommon
