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

#include "ocsp-checker-options.h"
#include <stdio.h>


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


OcspCheckerOptions::OcspCheckerOptions (void)
    : outHelp(false)
    , outVersion(false)
{
    helper.addOptionArgs("cert", 1);
    //helper.addOptionArgs("cert-issuer", 1);
    //helper.addOptionArgs("serial-number", 1);
    //helper.addOptionArgs("digest-algo", 1);
    helper.addOptionArgs("nonce-hex", 1);
    helper.addOptionArgs("nonce-len", 1);
    //  HTTP specific
    helper.addOptionArgs("header", 1);
    //  Signature verification
    helper.addOptionArgs("responder-cert", 1);
    //  Result
    helper.addOptionArgs("save-pem", 1);
    helper.addOptionArgs("save-request", 1);
    helper.addOptionArgs("save-response", 1);
    //  Other
    helper.addOptionArgs("help", 0);
    helper.addOptionArgs("version", 0);
}

GetOptHelper::Error OcspCheckerOptions::parse (
        int argc,
        char* argv[]
)
{
    GetOptHelper::Error rv_err = helper.parse(argc, argv);
    DEBUG_OUTCON(printf("helper.parse: %u\n", rv_err));
    if (rv_err != GetOptHelper::Error::OK) return rv_err;

    certFile = helper.getValue("cert");
    DEBUG_OUTCON(printf("cert: '%s'\n", certFile.c_str()));

    //certIssuer = helper.getValue("cert-issuer");
    //DEBUG_OUTCON(printf("cert-issuer: '%s'\n", certIssuer.c_str()));

    //serialNumber = helper.getValue("serial-number");
    //DEBUG_OUTCON(printf("serial-number: '%s'\n", serialNumber.c_str()));

    //hashAlgo = helper.getValue("digest-algo");
    //DEBUG_OUTCON(printf("digest-algo: '%s'\n", hashAlgo.c_str()));

    nonceHex = helper.getValue("nonce-hex");
    DEBUG_OUTCON(printf("nonce-hex: %s\n", nonceHex.c_str()));
    if (nonceHex.empty()) {
        nonceLen = helper.getValue("nonce-len");
        DEBUG_OUTCON(printf("nonce-len: %s\n", nonceLen.c_str()));
    }

    header = helper.getValue("header");
    DEBUG_OUTCON(printf("header: '%s'\n", header.c_str()));

    responderCert = helper.getValue("responder-cert");
    DEBUG_OUTCON(printf("responder-cert: '%s'\n", responderCert.c_str()));

    savePem = helper.getValue("save-pem");
    DEBUG_OUTCON(printf("save-pem: '%s'\n", savePem.c_str()));

    saveRequest = helper.getValue("save-request");
    DEBUG_OUTCON(printf("save-request: '%s'\n", saveRequest.c_str()));

    saveResponse = helper.getValue("save-response");
    DEBUG_OUTCON(printf("save-response: '%s'\n", saveResponse.c_str()));

    outHelp = helper.hasValue("help");
    DEBUG_OUTCON(printf("help: %s\n", (outHelp ? "TRUE" : "FALSE")));

    outVersion = helper.hasValue("version");
    DEBUG_OUTCON(printf("version: %s\n", (outVersion ? "TRUE" : "FALSE")));

    return rv_err;
}
