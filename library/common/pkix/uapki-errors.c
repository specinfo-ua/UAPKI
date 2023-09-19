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

#define COUNT_UAPKIC_ERRORS 34
#define COUNT_ASN1_ERRORS   4
#define COUNT_CM_ERRORS     64
#define COUNT_UAPKI_ERRORS  128
#define OFFSET_ASN1_ERRORS  100

#ifndef CM_ERROR_NAME_CODE
#define CM_ERROR_NAME_CODE 0x0400
#endif

#ifndef UAPKI_ERROR_NAME_CODE
#define UAPKI_ERROR_NAME_CODE 0x1000
#endif


static const char* STR_UAPKIC_ERRORS[COUNT_UAPKIC_ERRORS] = {
    "OK",                   //   0
    "MEMORY_ALLOC_ERROR",   //   1
    "INVALID_PARAM",        //   2
    "VERIFY_FAILED",        //   3
    "CONTEXT_NOT_READY",    //   4
    "INVALID_CTX",          //   5
    "INVALID_PRIVATE_KEY",  //   6
    "INVALID_PUBLIC_KEY",   //   7
    "OS_PRNG_ERROR",        //   8
    "JITTER_RNG_ERROR",     //   9
    "UNSUPPORTED",          //  10
    "INVALID_KEY_SIZE",     //  11
    "INVALID_IV_SIZE",      //  12
    "RSA_DECRYPTION_ERROR", //  13
    "INVALID_CTX_MODE",     //  14
    "INVALID_EC_PARAMS",    //  15
    "DATA_TOO_LONG",        //  16
    "INVALID_RSA_N",        //  17
    "INVALID_RSA_D",        //  18
    "INVALID_RSA_DMP",      //  19
    "INVALID_RSA_DMQ",      //  20
    "INVALID_RSA_IQMP",     //  21
    "INVALID_HASH_LEN",     //  22
    "INVALID_MAC",          //  23
    "CTX_ALREADY_IN_CACHE", //  24
    "POINT_NOT_ON_CURVE",   //  25
    "INVALID_OID",          //  26
    "INVALID_DATA_LEN",     //  27
    "INVALID_UTF8_STR",     //  28
    "INVALID_HEX_STRING",   //  29
    "INVALID_BASE64_STRING",//  30
    "INDEX_OUT_OF_RANGE",   //  31
    "SELF_TEST_NOT_ALLOWED",//  32
    "SELF_TEST_FAIL"        //  33
};

static const char* STR_ASN1_ERRORS[COUNT_ASN1_ERRORS] = {
    "ASN1_ERROR",           //  100
    "ASN1_ENCODE_ERROR",    //  101
    "ASN1_DECODE_ERROR",    //  102
    "ASN1_TIME_ERROR"       //  103
};

static const char* STR_CM_ERRORS[COUNT_CM_ERRORS] = {
    "",
    "GENERAL_ERROR",                //  (CM_ERROR_NAME_CODE | 0x00000001)
    "INVALID_PARAMETER",            //  (CM_ERROR_NAME_CODE | 0x00000002)
    "LIBRARY_NOT_LOADED",           //  (CM_ERROR_NAME_CODE | 0x00000003)
    "ALREADY_INITIALIZED",          //  (CM_ERROR_NAME_CODE | 0x00000004)
    "NOT_INITIALIZED",              //  (CM_ERROR_NAME_CODE | 0x00000005)
    "UNSUPPORTED_API",              //  (CM_ERROR_NAME_CODE | 0x00000006)
    "UNSUPPORTED_PARAMETER",        //  (CM_ERROR_NAME_CODE | 0x00000007)
    "NO_SESSION",                   //  (CM_ERROR_NAME_CODE | 0x00000008)
    "INVALID_MECHANISM",            //  (CM_ERROR_NAME_CODE | 0x00000009)
    "UNSUPPORTED_MAC",              //  (CM_ERROR_NAME_CODE | 0x0000000A)
    "INVALID_MAC",                  //  (CM_ERROR_NAME_CODE | 0x0000000B)
    "WITHOUT_MAC",                  //  (CM_ERROR_NAME_CODE | 0x0000000C)
    "INVALID_CONTENT_INFO",         //  (CM_ERROR_NAME_CODE | 0x0000000D)
    "UNSUPPORTED_CONTENT_INFO",     //  (CM_ERROR_NAME_CODE | 0x0000000E)
    "INVALID_SAFE_BAG",             //  (CM_ERROR_NAME_CODE | 0x0000000F)
    "NOT_AUTHORIZED",               //  (CM_ERROR_NAME_CODE | 0x00000010)
    "INVALID_PASSWORD",             //  (CM_ERROR_NAME_CODE | 0x00000011)
    "READONLY_SESSION",             //  (CM_ERROR_NAME_CODE | 0x00000012)
    "BAG_NOT_FOUND",                //  (CM_ERROR_NAME_CODE | 0x00000013)
    "KEY_NOT_FOUND",                //  (CM_ERROR_NAME_CODE | 0x00000014)
    "CERTIFICATE_NOT_FOUND",        //  (CM_ERROR_NAME_CODE | 0x00000015)
    "KEY_NOT_SELECTED",             //  (CM_ERROR_NAME_CODE | 0x00000016)
    "UNSUPPORTED_ALG",              //  (CM_ERROR_NAME_CODE | 0x00000017)
    "UNSUPPORTED_CIPHER_ALG",       //  (CM_ERROR_NAME_CODE | 0x00000018)
    "UNSUPPORTED_ELLIPTIC_CURVE",   //  (CM_ERROR_NAME_CODE | 0x00000019)
    "UNSUPPORTED_RSA_LEN",          //  (CM_ERROR_NAME_CODE | 0x0000001A)
    "UNSUPPORTED_KDF_ALG",          //  (CM_ERROR_NAME_CODE | 0x0000001B)
    "INVALID_HASH",                 //  (CM_ERROR_NAME_CODE | 0x0000001C)
    "INVALID_KEY",                  //  (CM_ERROR_NAME_CODE | 0x0000001D)
    "INVALID_ELLIPTIC_CURVE",       //  (CM_ERROR_NAME_CODE | 0x0000001E)
    "INVALID_UTF8_STR",             //  (CM_ERROR_NAME_CODE | 0x0000001F)
    "INVALID_JSON",                 //  (CM_ERROR_NAME_CODE | 0x00000020)
    "INVALID_PARAM_DH",             //  (CM_ERROR_NAME_CODE | 0x00000021)
    "UNSUPPORTED_KEY_CONTAINER",    //  (CM_ERROR_NAME_CODE | 0x00000022)
    "UNSUPPORTED_FORMAT",           //  (CM_ERROR_NAME_CODE | 0x00000023)
    "CONNECTION_ERROR",             //  (CM_ERROR_NAME_CODE | 0x00000024)
    "INVALID_RESPONSE",             //  (CM_ERROR_NAME_CODE | 0x00000025)
    "RESPONSE_ERROR",               //  (CM_ERROR_NAME_CODE | 0x00000026)
    "ACCESS_DENIED",                //  (CM_ERROR_NAME_CODE | 0x00000027)
    "JSON_FAILURE",                 //  (CM_ERROR_NAME_CODE | 0x00000028)
    "STORAGE_NOT_OPEN",             //  (CM_ERROR_NAME_CODE | 0x00000029)
    "TOKEN_ERROR",                  //  (CM_ERROR_NAME_CODE | 0x0000002A)
    "TOKEN_NO_FREE_SESSIONS",       //  (CM_ERROR_NAME_CODE | 0x0000002B)
    "TOKEN_NO_FREE_SPACE",          //  (CM_ERROR_NAME_CODE | 0x0000002C)
    "TOKEN_ALREADY_LOGGED",         //  (CM_ERROR_NAME_CODE | 0x0000002D)
    "ERROR_0x2E",                   //  (CM_ERROR_NAME_CODE | 0x0000002E)
    "STORAGE_NOT_FOUND",            //  (CM_ERROR_NAME_CODE | 0x0000002F)
    "FILE_OPEN_ERROR",              //  (CM_ERROR_NAME_CODE | 0x00000030)
    "FILE_READ_ERROR",              //  (CM_ERROR_NAME_CODE | 0x00000031)
    "FILE_WRITE_ERROR",             //  (CM_ERROR_NAME_CODE | 0x00000032)
    "FILE_DELETE_ERROR",            //  (CM_ERROR_NAME_CODE | 0x00000033)
    "DECODE_ASN1_ERROR",            //  (CM_ERROR_NAME_CODE | 0x00000034)
    "ENCODE_ASN1_ERROR",            //  (CM_ERROR_NAME_CODE | 0X00000035)
    "PASSWORD_NOT_SET",             //  (CM_ERROR_NAME_CODE | 0x00000036)
    "INVALID_CERTIFICATE",          //  (CM_ERROR_NAME_CODE | 0x00000037)
    "INVALID_KEYID",                //  (CM_ERROR_NAME_CODE | 0x00000038)
    "INVALID_WRAPPED_KEY",          //  (CM_ERROR_NAME_CODE | 0x00000039)
    "ERROR_0x3A",                   //  (CM_ERROR_NAME_CODE | 0x0000003A)
    "ERROR_0x3B",                   //  (CM_ERROR_NAME_CODE | 0x0000003B)
    "ERROR_0x3C",                   //  (CM_ERROR_NAME_CODE | 0x0000003C)
    "ERROR_0x3D",                   //  (CM_ERROR_NAME_CODE | 0x0000003D)
    "ERROR_0x3E",                   //  (CM_ERROR_NAME_CODE | 0x0000003E)
    "ERROR_0x3F"                    //  (CM_ERROR_NAME_CODE | 0x0000003F)
};

static const char* STR_UAPKI_ERRORS[COUNT_UAPKI_ERRORS] = {
    "",
    "GENERAL_ERROR",                //  (UAPKI_ERROR_NAME_CODE | 0x00000001)
    "CONNECTION_ERROR",             //  (UAPKI_ERROR_NAME_CODE | 0x00000002)
    "INVALID_JSON_FORMAT",          //  (UAPKI_ERROR_NAME_CODE | 0x00000003)
    "INVALID_METHOD",               //  (UAPKI_ERROR_NAME_CODE | 0x00000004)
    "INVALID_PARAMETER",            //  (UAPKI_ERROR_NAME_CODE | 0x00000005)
    "UNKNOWN_PROVIDER",             //  (UAPKI_ERROR_NAME_CODE | 0x00000006)
    "FILENAME_REQUIRED",            //  (UAPKI_ERROR_NAME_CODE | 0x00000007)
    "LOGIN_REQUIRED",               //  (UAPKI_ERROR_NAME_CODE | 0x00000008)
    "NOT_INITIALIZED",              //  (UAPKI_ERROR_NAME_CODE | 0x00000009)
    "ALREADY_INITIALIZED",          //  (UAPKI_ERROR_NAME_CODE | 0x0000000A)
    "NO_STORAGE",                   //  (UAPKI_ERROR_NAME_CODE | 0x0000000B)
    "NO_KEY",                       //  (UAPKI_ERROR_NAME_CODE | 0x0000000C)
    "INVALID_KEY_USAGE",            //  (UAPKI_ERROR_NAME_CODE | 0x0000000D)
    "UNSUPPORTED_ALG",              //  (UAPKI_ERROR_NAME_CODE | 0x0000000E)
    "INVALID_HASH_SIZE",            //  (UAPKI_ERROR_NAME_CODE | 0x0000000F)
    "INVALID_KEY_ID",               //  (UAPKI_ERROR_NAME_CODE | 0x00000010)
    "JSON_FAILURE",                 //  (UAPKI_ERROR_NAME_CODE | 0x00000011)
    "INVALID_BIT_STRING",           //  (UAPKI_ERROR_NAME_CODE | 0x00000012)
    "UNEXPECTED_BIT_STRING",        //  (UAPKI_ERROR_NAME_CODE | 0x00000013)
    "TOO_LONG_BIT_STRING",          //  (UAPKI_ERROR_NAME_CODE | 0x00000014)
    "TIME_ERROR",                   //  (UAPKI_ERROR_NAME_CODE | 0x00000015)
    "NOT_SUPPORTED",                //  (UAPKI_ERROR_NAME_CODE | 0x00000016)
    "NOT_ALLOWED",                  //  (UAPKI_ERROR_NAME_CODE | 0x00000017)
    "OFFLINE_MODE",                 //  (UAPKI_ERROR_NAME_CODE | 0x00000018)
    "STORAGE_NOT_OPEN",             //  (UAPKI_ERROR_NAME_CODE | 0x00000019)
    "PROVIDER_NOT_LOADED",          //  (UAPKI_ERROR_NAME_CODE | 0x0000001A)
    "UNSUPPORTED_CM_API",           //  (UAPKI_ERROR_NAME_CODE | 0x0000001B)
    "MANY_METHODS_ARE_RUNNING",     //  (UAPKI_ERROR_NAME_CODE | 0x0000001C)
    "SERIAL_METHOD_IS_RUNNING",     //  (UAPKI_ERROR_NAME_CODE | 0x0000001D)
    "",
    "",
    "FILE_OPEN_ERROR",              //  (UAPKI_ERROR_NAME_CODE | 0x00000020)
    "FILE_READ_ERROR",              //  (UAPKI_ERROR_NAME_CODE | 0x00000021)
    "FILE_WRITE_ERROR",             //  (UAPKI_ERROR_NAME_CODE | 0x00000022)
    "FILE_GET_SIZE_ERROR",          //  (UAPKI_ERROR_NAME_CODE | 0x00000023)
    "FILE_DELETE_ERROR",            //  (UAPKI_ERROR_NAME_CODE | 0x00000024)
    "HTTP_STATUS_NOT_OK",           //  (UAPKI_ERROR_NAME_CODE | 0x00000025)
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "INVALID_CONTENT_INFO",         //  (UAPKI_ERROR_NAME_CODE | 0x00000030)
    "INVALID_STRUCT",               //  (UAPKI_ERROR_NAME_CODE | 0x00000031)
    "INVALID_STRUCT_VERSION",       //  (UAPKI_ERROR_NAME_CODE | 0x00000032)
    "CONTENT_NOT_PRESENT",          //  (UAPKI_ERROR_NAME_CODE | 0x00000033)
    "INVALID_ATTRIBUTE",            //  (UAPKI_ERROR_NAME_CODE | 0x00000034)
    "ATTRIBUTE_NOT_PRESENT",        //  (UAPKI_ERROR_NAME_CODE | 0x00000035)
    "EXTENSION_NOT_PRESENT",        //  (UAPKI_ERROR_NAME_CODE | 0x00000036)
    "EXTENSION_NOT_SET_CRITICAL",   //  (UAPKI_ERROR_NAME_CODE | 0x00000037)
    "INVALID_COUNT_ITEMS",          //  (UAPKI_ERROR_NAME_CODE | 0x00000038)
    "INVALID_DIGEST",               //  (UAPKI_ERROR_NAME_CODE | 0x00000039)
    "OTHER_RECIPIENT",              //  (UAPKI_ERROR_NAME_CODE | 0x0000003A)
    "",
    "",
    "",
    "",
    "",
    "CERT_STORE_LOAD_ERROR",            //  (UAPKI_ERROR_NAME_CODE | 0x00000040)
    "CERT_NOT_FOUND",                   //  (UAPKI_ERROR_NAME_CODE | 0x00000041)
    "CERT_VALIDITY_NOT_BEFORE_ERROR",   //  (UAPKI_ERROR_NAME_CODE | 0x00000042)
    "CERT_VALIDITY_NOT_AFTER_ERROR",    //  (UAPKI_ERROR_NAME_CODE | 0x00000043)
    "CERT_ISSUER_NOT_FOUND",            //  (UAPKI_ERROR_NAME_CODE | 0x00000044)
    "CERT_STATUS_REVOKED",              //  (UAPKI_ERROR_NAME_CODE | 0x00000045)
    "CERT_STATUS_UNKNOWN",              //  (UAPKI_ERROR_NAME_CODE | 0x00000046)
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",

    "CRL_STORE_LOAD_ERROR",             //  (UAPKI_ERROR_NAME_CODE | 0x00000050)
    "CRL_URL_NOT_PRESENT",              //  (UAPKI_ERROR_NAME_CODE | 0x00000051)
    "CRL_NOT_DOWNLOADED",               //  (UAPKI_ERROR_NAME_CODE | 0x00000052)
    "CRL_NOT_FOUND",                    //  (UAPKI_ERROR_NAME_CODE | 0x00000053)
    "CRL_EXPIRED",                      //  (UAPKI_ERROR_NAME_CODE | 0x00000054)
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",

    "OCSP_URL_NOT_PRESENT",             //  (UAPKI_ERROR_NAME_CODE | 0x00000060)
    "OCSP_NOT_RESPONDING",              //  (UAPKI_ERROR_NAME_CODE | 0x00000061)
    "OCSP_RESPONSE_NOT_SUCCESSFUL",     //  (UAPKI_ERROR_NAME_CODE | 0x00000062)
    "OCSP_RESPONSE_VERIFY_FAILED",      //  (UAPKI_ERROR_NAME_CODE | 0x00000063)
    "OCSP_RESPONSE_VERIFY_ERROR",       //  (UAPKI_ERROR_NAME_CODE | 0x00000064)
    "OCSP_RESPONSE_INVALID_NONCE",      //  (UAPKI_ERROR_NAME_CODE | 0x00000065)
    "OCSP_RESPONSE_INVALID",            //  (UAPKI_ERROR_NAME_CODE | 0x00000066)
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",

    "TSP_URL_NOT_PRESENT",              //  (UAPKI_ERROR_NAME_CODE | 0x00000070)
    "TSP_NOT_RESPONDING",               //  (UAPKI_ERROR_NAME_CODE | 0x00000071)
    "TSP_RESPONSE_NOT_GRANTED",         //  (UAPKI_ERROR_NAME_CODE | 0x00000072)
    "TSP_RESPONSE_NOT_EQUAL_REQUEST",   //  (UAPKI_ERROR_NAME_CODE | 0X00000073)
    "TSP_RESPONSE_INVALID",             //  (UAPKI_ERROR_NAME_CODE | 0x00000074)
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    ""
};


#ifdef __cplusplus
extern "C" {
#endif

const char* error_code_to_str (int errorCode)
{
    const char* rv_s = NULL;
    if ((errorCode >= 0) && (errorCode < COUNT_UAPKIC_ERRORS)) {
        rv_s = STR_UAPKIC_ERRORS[errorCode];
    }
    else if ((errorCode >= OFFSET_ASN1_ERRORS) && (errorCode < OFFSET_ASN1_ERRORS + COUNT_ASN1_ERRORS)) {
        rv_s = STR_ASN1_ERRORS[errorCode - OFFSET_ASN1_ERRORS];
    }
    else if ((errorCode >= CM_ERROR_NAME_CODE) && (errorCode < CM_ERROR_NAME_CODE + COUNT_CM_ERRORS)) {
        rv_s = STR_CM_ERRORS[errorCode - CM_ERROR_NAME_CODE];
    }
    else if ((errorCode >= UAPKI_ERROR_NAME_CODE) && (errorCode < UAPKI_ERROR_NAME_CODE + COUNT_UAPKI_ERRORS)) {
        rv_s = STR_UAPKI_ERRORS[errorCode - UAPKI_ERROR_NAME_CODE];
    }
    return rv_s;
}

#ifdef __cplusplus
}
#endif

