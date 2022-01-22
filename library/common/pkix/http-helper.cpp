/*
 * Copyright (c) 2022, The UAPKI Project Authors.
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

#include <string.h>
#include "ba-utils.h"
#include "http-helper.h"
#include "uapki-errors.h"
#define CURL_STATICLIB
#include "curl/curl.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


const char* HttpHelper::CONTENT_TYPE_APP_JSON = "Content-Type:application/json";
const char* HttpHelper::CONTENT_TYPE_OCSP_REQUEST = "Content-Type:application/ocsp-request";
const char* HttpHelper::CONTENT_TYPE_TSP_REQUEST = "Content-Type:application/timestamp-query";


typedef struct HTTP_HELPER_ST {
    bool isInitialized;
    bool offlineMode;

    HTTP_HELPER_ST(void)
        : isInitialized(false), offlineMode(false)
    {}
} HTTP_HELPER;

static HTTP_HELPER http_helper;


static size_t cb_curlwrite (void* dataIn, size_t size, size_t nmemb, void* userp)
{
    size_t realsize = size * nmemb;
    ByteArray* data = (ByteArray*)userp;
    size_t old_len = ba_get_len(data);
    uint8_t* buf;

    ba_change_len(data, old_len + realsize);
    buf = (uint8_t*)ba_get_buf(data);
    memcpy(&(buf[old_len]), dataIn, realsize);

    return realsize;
}


int HttpHelper::init (const bool offlineMode)
{
    int ret = RET_OK;
    http_helper.offlineMode = offlineMode;
    if (!http_helper.isInitialized) {
        const CURLcode curl_code = curl_global_init(CURL_GLOBAL_ALL);
        http_helper.isInitialized = (curl_code == CURLE_OK);
        ret = (http_helper.isInitialized) ? RET_OK : RET_UAPKI_GENERAL_ERROR;
    }
    return ret;
}

void HttpHelper::deinit (void)
{
    if (http_helper.isInitialized) {
        http_helper.isInitialized = false;
        curl_global_cleanup();
    }
}

bool HttpHelper::isOfflineMode (void)
{
    return http_helper.offlineMode;
}

int HttpHelper::get (const char* url, ByteArray** baResponse)
{
    DEBUG_OUTCON(printf("HttpHelper::get(url='%s')\n", url));
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
    curl_easy_setopt(curl, CURLOPT_URL, url);

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

int HttpHelper::post (const char* url, const char* httpContentType, const ByteArray* baRequest, ByteArray** baResponse)
{
    DEBUG_OUTCON(printf("HttpHelper::post(url='%s', httpContentType='%s'), Request:\n", url, httpContentType); ba_print(stdout, baRequest));
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
    chunk = curl_slist_append(chunk, httpContentType);

    // set our custom set of headers
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

    // First set the URL that is about to receive our POST. This URL can
    // just as well be a https:// URL if that is what should receive the data.
    curl_easy_setopt(curl, CURLOPT_URL, url);
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

    return ret;
}

int HttpHelper::post (const char* url, const char* httpContentType,
                    const char* userPwd, const char* authorizationBearer, const char* request, ByteArray** baResponse)
{
    DEBUG_OUTCON(printf("HttpHelper::post(url='%s', httpContentType='%s', userPwd='%s', authorizationBearer='%s', request='%s')\n",
            url, httpContentType, userPwd, authorizationBearer, request));
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

    struct curl_slist* chunk = NULL;

    // Add a custom header 
    chunk = curl_slist_append(chunk, httpContentType);
    if (authorizationBearer) {
        chunk = curl_slist_append(chunk, authorizationBearer);
    }

    // set our custom set of headers
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

    // First set the URL that is about to receive our POST. This URL can
    // just as well be a https:// URL if that is what should receive the
    // data.
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    // Now specify the POST data
    // binary data
    if (request) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request);
    }
    // size of the POST data
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (request) ? (long)strlen(request) : 0);

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
