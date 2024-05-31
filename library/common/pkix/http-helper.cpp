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

#define CURL_STATICLIB
#include "curl/curl.h"
#include "ba-utils.h"
#include "http-helper.h"
#include "uapkic.h"
#include "uapki-errors.h"
#include "uapki-ns.h"
#include <string.h>
#include <map>
#include <mutex>


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


const char* HttpHelper::CONTENT_TYPE_APP_JSON       = "Content-Type:application/json";
const char* HttpHelper::CONTENT_TYPE_OCSP_REQUEST   = "Content-Type:application/ocsp-request";
const char* HttpHelper::CONTENT_TYPE_TSP_REQUEST    = "Content-Type:application/timestamp-query";


struct HTTP_HELPER {
    bool    isInitialized;
    bool    offlineMode;
    string  proxyUrl;
    string  proxyCredentials;
    mutex   mtx;
    map<string, mutex>
            mtxByUrl;

    HTTP_HELPER (void)
        : isInitialized(false)
        , offlineMode(false)
    {}

    void reset (void)
    {
        isInitialized = false;
        offlineMode = false;
        proxyUrl.clear();
        proxyCredentials.clear();
    }
};  //  end struct HTTP_HELPER

static HTTP_HELPER http_helper;


static size_t cb_curlwrite (
        void* dataIn,
        size_t size,
        size_t nmemb,
        void* userp
)
{
    size_t realsize = size * nmemb;
    ByteArray* data = (ByteArray*)userp;
    size_t old_len = ba_get_len(data);
    uint8_t* buf;

    ba_change_len(data, old_len + realsize);
    buf = (uint8_t*)ba_get_buf(data);
    memcpy(&(buf[old_len]), dataIn, realsize);

    return realsize;
}   //  cb_curlwrite

static bool curl_set_url_and_proxy (
        CURL* curl,
        const string& uri
)
{
    CURLcode rv_ccode = curl_easy_setopt(curl, CURLOPT_URL, uri.c_str());
    if (rv_ccode != CURLE_OK) return false;

    if (!http_helper.proxyUrl.empty()) {
        rv_ccode = curl_easy_setopt(curl, CURLOPT_PROXY, http_helper.proxyUrl.c_str());
        if (rv_ccode != CURLE_OK) return false;

        curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_ANY);

        if (!http_helper.proxyCredentials.empty()) {
            rv_ccode = curl_easy_setopt(curl, CURLOPT_PROXYUSERPWD, http_helper.proxyCredentials.c_str());
            if (rv_ccode != CURLE_OK) return false;
        }
    }

    return true;
}   //  curl_set_url_and_proxy


int HttpHelper::init (
        const bool offlineMode,
        const char* proxyUrl,
        const char* proxyCredentials
)
{
    int ret = RET_OK;
    http_helper.offlineMode = offlineMode;
    if (!http_helper.isInitialized) {
        const CURLcode curl_code = curl_global_init(CURL_GLOBAL_ALL);
        http_helper.isInitialized = (curl_code == CURLE_OK);
        if (proxyUrl && http_helper.isInitialized) {
            http_helper.proxyUrl = string(proxyUrl);
            if (proxyCredentials && !http_helper.proxyUrl.empty()) {
                http_helper.proxyCredentials = string(proxyCredentials);
            }
        }
        ret = (http_helper.isInitialized) ? RET_OK : RET_UAPKI_GENERAL_ERROR;
    }
    return ret;
}

void HttpHelper::deinit (void)
{
    if (http_helper.isInitialized) {
        http_helper.reset();
        curl_global_cleanup();
    }
}

bool HttpHelper::isOfflineMode (void)
{
    return http_helper.offlineMode;
}

const string& HttpHelper::getProxyUrl (void)
{
    return http_helper.proxyUrl;
}

int HttpHelper::get (
        const string& uri,
        ByteArray** baResponse
)
{
    DEBUG_OUTCON(printf("HttpHelper::get(uri='%s')\n", uri.c_str()));
    CURL* curl;
    CURLcode curl_code;
    int ret;

    if (http_helper.offlineMode) {
        return RET_UAPKI_OFFLINE_MODE;
    }

    // get a curl handle 
    if ((curl = curl_easy_init()) == NULL) {
        return RET_UAPKI_CONNECTION_ERROR;
    }

    // First set the URL that is about to receive our POST. This URL can
    // just as well be a https:// URL if that is what should receive the data.
    if (!curl_set_url_and_proxy(curl, uri)) {
        return RET_UAPKI_CONNECTION_ERROR;
    }

    // send all data to this function
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb_curlwrite);

    *baResponse = ba_alloc();
    // we pass our 'chunk' struct to the callback function
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, *baResponse);

    // Perform the request, res will get the return code
    curl_code = curl_easy_perform(curl);
    if (curl_code == CURLE_OK) {
        long http_code = 0;
        curl_code = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        ret = (http_code == 200) ? RET_OK : RET_UAPKI_HTTP_STATUS_NOT_OK;
    }
    else {
        ret = RET_UAPKI_CONNECTION_ERROR;
    }

    // always cleanup
    curl_easy_cleanup(curl);

    return ret;
}

int HttpHelper::post (
        const string& uri,
        const char* contentType,
        const ByteArray* baRequest,
        ByteArray** baResponse
)
{
    DEBUG_OUTCON(
        printf("HttpHelper::post(uri='%s', contentType='%s'), Request:\n", uri.c_str(), contentType);
        ba_print(stdout, baRequest);
    )
    CURL* curl;
    CURLcode curl_code;
    int ret;

    if (http_helper.offlineMode) {
        return RET_UAPKI_OFFLINE_MODE;
    }

    // get a curl handle 
    if ((curl = curl_easy_init()) == NULL) {
        return RET_UAPKI_GENERAL_ERROR;
    }

    struct curl_slist* chunk = NULL;

    // Add a custom header 
    chunk = curl_slist_append(chunk, contentType);

    // set our custom set of headers
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

    // First set the URL that is about to receive our POST. This URL can
    // just as well be a https:// URL if that is what should receive the data.
    if (!curl_set_url_and_proxy(curl, uri)) {
        return RET_UAPKI_CONNECTION_ERROR;
    }
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    // Now specify the POST data
    // binary data
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, ba_get_buf_const(baRequest));
    // size of the POST data
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)ba_get_len(baRequest));

    // send all data to this function
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb_curlwrite);

    *baResponse = ba_alloc();
    // we pass our 'chunk' struct to the callback function
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, *baResponse);

    // Perform the request, res will get the return code
    curl_code = curl_easy_perform(curl);
    if (curl_code == CURLE_OK) {
        long http_code = 0;
        curl_code = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        ret = (http_code == 200) ? RET_OK : RET_UAPKI_HTTP_STATUS_NOT_OK;
    }
    else {
        ret = RET_UAPKI_CONNECTION_ERROR;
    }

    // always cleanup
    curl_easy_cleanup(curl);
    curl_slist_free_all(chunk);

    return ret;
}

int HttpHelper::post (
        const string& uri,
        const char* contentType,
        const char* userPwd,
        const string& authorizationBearer,
        const string& request,
        ByteArray** baResponse
)
{
    DEBUG_OUTCON(
        printf("HttpHelper::post(uri='%s', contentType='%s', userPwd='%s', authorizationBearer='%s', request='%s')\n",
                uri.c_str(), contentType, userPwd, authorizationBearer.c_str(), request.c_str());
    )
    CURL* curl;
    CURLcode curl_code;
    int ret;

    if (http_helper.offlineMode) {
        return RET_UAPKI_OFFLINE_MODE;
    }

    // get a curl handle 
    if ((curl = curl_easy_init()) == NULL) {
        return RET_UAPKI_GENERAL_ERROR;
    }

    if (userPwd) {
        curl_easy_setopt(curl, CURLOPT_USERPWD, userPwd);
    }

#ifdef HTTP_HELPER_DISABLE_VERIFYSSL
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
#endif

    struct curl_slist* chunk = NULL;

    // Add a custom header 
    chunk = curl_slist_append(chunk, contentType);
    if (!authorizationBearer.empty()) {
        chunk = curl_slist_append(chunk, authorizationBearer.c_str());
    }

    // set our custom set of headers
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

    // First set the URL that is about to receive our POST. This URL can
    // just as well be a https:// URL if that is what should receive the
    // data.
    if (!curl_set_url_and_proxy(curl, uri)) {
        return RET_UAPKI_CONNECTION_ERROR;
    }
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    // Now specify the POST data
    // binary data
    if (!request.empty()) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.c_str());
    }
    // size of the POST data
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)request.length());

    // send all data to this function
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb_curlwrite);

    *baResponse = ba_alloc();
    // we pass our 'chunk' struct to the callback function
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, *baResponse);

    // Perform the request, res will get the return code
    curl_code = curl_easy_perform(curl);
    if (curl_code == CURLE_OK) {
        long http_code = 0;
        curl_code = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        ret = (http_code == 200) ? RET_OK : RET_UAPKI_HTTP_STATUS_NOT_OK;
    }
    else {
        ret = RET_UAPKI_CONNECTION_ERROR;
    }

    // always cleanup
    curl_easy_cleanup(curl);

    return ret;
}

mutex& HttpHelper::lockUri (
        const string& uri
)
{
    lock_guard<mutex> lock(http_helper.mtx);

    return http_helper.mtxByUrl[uri];
}

vector<string> HttpHelper::randomURIs (
        const vector<string>& uris
)
{
    if (uris.size() < 2) return uris;

    UapkiNS::SmartBA sba_randoms;
    if (!sba_randoms.set(ba_alloc_by_len(uris.size() - 1))) return uris;

    if (drbg_random(sba_randoms.get()) != RET_OK) return uris;

    vector<string> rv_uris, src = uris;
    const uint8_t* buf = sba_randoms.buf();
    for (size_t i = 0; i < uris.size() - 1; i++) {
        const size_t rnd = buf[i] % src.size();
        rv_uris.push_back(src[rnd]);
        src.erase(src.begin() + rnd);
    }
    rv_uris.push_back(src[0]);
    return rv_uris;
}
