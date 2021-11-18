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

#include <stddef.h>
#include <stdio.h>
#include <chrono>
#include <thread>
#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <iostream>
#include <string>
#include "uapki-loader.h"

#if defined(_WIN32) || defined(__WINDOWS__)
#include <fcntl.h>
#endif

//#define DEBUG_LOG_ENABLE
#define SLEEP_MS 50

#if defined(_WIN32) || defined(__WINDOWS__)
#include <direct.h>
#elif defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#include <unistd.h>
#else
#error "Target platform undefined"
#endif

using namespace std;

static const string NAME_HOSTAPP = "UAPKI-HOSTAPP";
static const string VERSION_HOSTAPP = "2.0.2";
static const string JSON_REQ_HOSTAPP_VERSION = "{\"method\":\"HOSTAPP_VERSION\"}";
static const string JSON_RESULT_HOSTAPP_VERSION = "{\"hostName\":\"" + NAME_HOSTAPP + "\",\"hostVersion\":\"" + VERSION_HOSTAPP + "\"}";

UapkiLoader uapki;

#ifdef DEBUG_LOG_ENABLE
void dbg_log(const char* fnLog, const string& buf)
{
    static const char* STR_NL = "\n";
    FILE* f = fopen(fnLog, "a+");
    if (f != nullptr) {
        const void* data_ptr = buf.c_str();
        fwrite(data_ptr, buf.size(), 1, f);
        fwrite(STR_NL, strlen(STR_NL), 1, f);
        fclose(f);
    }
}
#define DBG_LOG(fn,text) dbg_log(fn,text);
#else
#define DBG_LOG(fn,text)
#endif

static string get_browser_msg()
{
    uint32_t msg_len = 0;
    cin.read((char*)&msg_len, 4);
    if (msg_len > 100 * 1024 * 1024) {
        return string();
    }

    string msg(msg_len, 0);
    cin.read(&msg[0], msg_len);
    return msg;
}

static void send_browser_msg(const string& msg)
{
    uint32_t msg_len = (uint32_t)msg.length();
    cout.write((char*)&msg_len, 4);
    cout << msg;
    cout << flush;
}

static void set_work_dir(void)
{
#if defined(_WIN32) || defined(__WINDOWS__)
    //  Note: actual for Firefox by Windows - difference path lib and CWD
    string s_path;
    s_path.resize(FILENAME_MAX);
    if (GetModuleFileNameA(uapki.getHandle(), (char*)s_path.data(), FILENAME_MAX) == 0) return;

    DBG_LOG("uapki-hostapp.log", "path: " + string(s_path.c_str()));
    s_path.resize(strlen(s_path.c_str()), 0);
    const size_t len = strlen(uapki.filename());
    if (s_path.size() >= len) {
        s_path.resize(s_path.size() - len, 0);
    }
    DBG_LOG("uapki-hostapp.log", "*path: " + string(s_path.c_str()));
    (void)_chdir(s_path.c_str());

#elif defined(__linux__) || defined(__APPLE__) || defined(__unix__)
//
#endif
}

static string json_stringify (const int errCode, const string& errText, const string& stringifiedResult) {
    string rv_s = "{\"errorCode\":" + to_string(errCode);
    if (!errText.empty()) {
        rv_s += ",\"error\":\"" + errText + "\"";
    }
    if (!stringifiedResult.empty()) {
        rv_s += ",\"result\":" + stringifiedResult;
    }
    rv_s += "}";
    return rv_s;
}

int main (void)
{
    DBG_LOG("uapki-hostapp.log", "START");
    string s_req, s_resp;

    if (uapki.load()) {
        DBG_LOG("uapki-hostapp.log", "IS_LOADED");
        set_work_dir();

        bool loop = true;
        while (loop) {
            s_resp.clear();
            s_req = get_browser_msg();
            if (s_req.empty()) {
                this_thread::sleep_for(chrono::milliseconds(SLEEP_MS));
                continue;
            }
            DBG_LOG("uapki-hostapp.log", "MSG: '" + s_req + "'");

            if (s_req == "{}") {
                DBG_LOG("uapki-hostapp.log", "IS_LOADED, HOSTAPP_CLOSE");
                s_resp = json_stringify(0, "", "");
                loop = false;
            }
            else if (s_req != JSON_REQ_HOSTAPP_VERSION) {
                DBG_LOG("uapki-hostapp.log", "IS_LOADED, HOSTAPP PROXY");
                char* s_json = uapki.process(s_req.c_str());
                DBG_LOG("uapki-hostapp.log", "IS_LOADED, uapki.process() PROCESSED");
                if (s_json) {
                    s_resp = string(s_json);
                    uapki.jsonFree(s_json);
                    DBG_LOG("uapki-hostapp.log", "IS_LOADED, doProxy() resp: '" + s_resp + "'");
                }
                else {
                    DBG_LOG("uapki-hostapp.log", "IS_LOADED, doProxy() NO RESPONSE");
                    s_resp = json_stringify(-22, "Inter-operation error.", "");
                }
            }
            else {
                DBG_LOG("uapki-hostapp.log", "IS_LOADED, HOSTAPP_VERSION");
                s_resp = json_stringify(0, "", JSON_RESULT_HOSTAPP_VERSION);
            }

            DBG_LOG("uapki-hostapp.log", "IS_LOADED, JSON-resp: '" + s_resp + "'");
            send_browser_msg(s_resp);
        }
    }
    else {
        DBG_LOG("uapki-hostapp.log", "IS_NOT_LOADED");

        s_req = get_browser_msg();
        DBG_LOG("uapki-hostapp.log", "JSON-req: '" + s_req + "'");

        s_resp = (s_req == JSON_REQ_HOSTAPP_VERSION) ? JSON_RESULT_HOSTAPP_VERSION : "";
        s_resp = json_stringify(-21, "Library UAPKI is not loaded. Expected name '" + string(UapkiLoader::filename()) + "'.", s_resp);
        DBG_LOG("uapki-hostapp.log", "IS_NOT_LOADED, JSON-resp: '" + s_resp + "'");

        send_browser_msg(s_resp);
    }

    DBG_LOG("uapki-hostapp.log", "END");
    return 0;
}
