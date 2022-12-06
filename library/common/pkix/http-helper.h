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

#ifndef UAPKI_HTTP_HELPER_H
#define UAPKI_HTTP_HELPER_H


#include <string>
#include <vector>
#include "byte-array.h"


class HttpHelper {
public:
    static const char* CONTENT_TYPE_APP_JSON;
    static const char* CONTENT_TYPE_OCSP_REQUEST;
    static const char* CONTENT_TYPE_TSP_REQUEST;

    static int init (
        const bool offlineMode
    );
    static void deinit (void);

    static bool isOfflineMode (void);
    static int get (
        const char* url,
        ByteArray** baResponse
    );
    static int post (
        const char* url,
        const char* contentType,
        const ByteArray* baRequest,
        ByteArray** baResponse
    );
    static int post (
        const char* url,
        const char* httpContentType,
        const char* userPwd,
        const char* authorizationBearer,
        const char* request,
        ByteArray** baResponse
    );

    static std::vector<std::string> randomURIs (
        const std::vector<std::string>& uris
    );

};  //  end class HttpHelper


#endif
