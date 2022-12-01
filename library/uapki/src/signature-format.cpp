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

#include "signature-format.h"


using namespace std;


static const char* UNDEFINED_STR    = "UNDEFINED";
static const char* RAW_STR          = "RAW";
static const char* CMS_STR          = "CMS";
static const char* CADES_BES_STR    = "CAdES-BES";
static const char* CADES_T_STR      = "CAdES-T";
static const char* CADES_C_STR      = "CAdES-C";
static const char* CADES_A_V3_STR   = "CAdES-Av3";

static constexpr size_t COUNT_SIGNATURE_FORMATS = 7;
static const char* STR_SIGNATURE_FORMATS[COUNT_SIGNATURE_FORMATS] = {
    UNDEFINED_STR,  //  0 = UNDEFINED
    RAW_STR,        //  1 = RAW
    CMS_STR,        //  2 = CMS_SID_KEYID
    CADES_BES_STR,  //  3 = CADES_BES
    CADES_T_STR,    //  4 = CADES_T
    CADES_C_STR,    //  5 = CADES_C
    CADES_A_V3_STR  //  6 = CADES_Av3
};


UapkiNS::SignatureFormat UapkiNS::signatureFormatFromString (const string& str)
{
    SignatureFormat rv = SignatureFormat::UNDEFINED;
    if ((str == string(CADES_BES_STR)) || str.empty()) {
        rv = SignatureFormat::CADES_BES;
    }
    else if (str == string(CADES_T_STR)) {
        rv = SignatureFormat::CADES_T;
    }
    else if (str == string(CADES_C_STR)) {
        rv = SignatureFormat::CADES_C;
    }
    else if (str == string(CADES_A_V3_STR)) {
        rv = SignatureFormat::CADES_Av3;
    }
    else if (str == string(CMS_STR)) {
        rv = SignatureFormat::CMS_SID_KEYID;
    }
    else if (str == string(RAW_STR)) {
        rv = SignatureFormat::RAW;
    }
    return rv;
}

const char* UapkiNS::signatureFormatToStr (const SignatureFormat signatureFormat)
{
    const size_t idx = ((size_t)signatureFormat <= (size_t)SignatureFormat::CADES_Av3)
        ? (size_t)signatureFormat : (size_t)SignatureFormat::UNDEFINED;
    return STR_SIGNATURE_FORMATS[idx];
}

string UapkiNS::signatureFormatToString (const SignatureFormat signatureFormat)
{
    return string(signatureFormatToStr(signatureFormat));
}
