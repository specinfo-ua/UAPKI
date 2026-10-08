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

#ifndef TSP_CHECKER_OPTIONS_H
#define TSP_CHECKER_OPTIONS_H


#include "getopt-helper.h"


struct TspCheckerOptions {
    GetOptHelper
                helper;
    std::string hashAlgo;
    bool        hashParamNull;
    std::string hashedMessage;
    std::string reqPolicy;
    std::string nonceHex;
    std::string nonceLen;
    bool        certReq;
    //  HTTP specific
    std::string url;
    std::string header;
    //  Signature verification
    std::string responderCert;
    //  Result
    std::string savePem;
    std::string saveRequest;
    std::string saveResponse;
    //  Other
    bool        outHelp;
    bool        outVersion;

    TspCheckerOptions (void);

    GetOptHelper::Error parse (
        int argc,
        char* argv[]
    );

};  //  end struct TspCheckerOptions


#endif
