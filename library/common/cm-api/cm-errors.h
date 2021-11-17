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

#ifndef CM_ERRORS_H
#define CM_ERRORS_H

#ifndef RET_OK
#define RET_OK 0
#endif

#define CM_ERROR_NAME_CODE                                         0x0400

#define RET_CM_GENERAL_ERROR                         (CM_ERROR_NAME_CODE | 0x00000001)
#define RET_CM_INVALID_PARAMETER                     (CM_ERROR_NAME_CODE | 0x00000002)
#define RET_CM_LIBRARY_NOT_LOADED                    (CM_ERROR_NAME_CODE | 0x00000003)
#define RET_CM_ALREADY_INITIALIZED                   (CM_ERROR_NAME_CODE | 0x00000004)
#define RET_CM_NOT_INITIALIZED                       (CM_ERROR_NAME_CODE | 0x00000005)
#define RET_CM_UNSUPPORTED_API                       (CM_ERROR_NAME_CODE | 0x00000006)
#define RET_CM_UNSUPPORTED_PARAMETER                 (CM_ERROR_NAME_CODE | 0x00000007)
#define RET_CM_NO_SESSION                            (CM_ERROR_NAME_CODE | 0x00000008)
#define RET_CM_INVALID_MECHANISM                     (CM_ERROR_NAME_CODE | 0x00000009)
#define RET_CM_UNSUPPORTED_MAC                       (CM_ERROR_NAME_CODE | 0x0000000A)
#define RET_CM_INVALID_MAC                           (CM_ERROR_NAME_CODE | 0x0000000B)
#define RET_CM_WITHOUT_MAC                           (CM_ERROR_NAME_CODE | 0x0000000C)
#define RET_CM_INVALID_CONTENT_INFO                  (CM_ERROR_NAME_CODE | 0x0000000D)
#define RET_CM_UNSUPPORTED_CONTENT_INFO              (CM_ERROR_NAME_CODE | 0x0000000E)
#define RET_CM_INVALID_SAFE_BAG                      (CM_ERROR_NAME_CODE | 0x0000000F)
#define RET_CM_NOT_AUTHORIZED                        (CM_ERROR_NAME_CODE | 0x00000010)
#define RET_CM_INVALID_PASSWORD                      (CM_ERROR_NAME_CODE | 0x00000011)
#define RET_CM_READONLY_SESSION                      (CM_ERROR_NAME_CODE | 0x00000012)
#define RET_CM_BAG_NOT_FOUND                         (CM_ERROR_NAME_CODE | 0x00000013)
#define RET_CM_KEY_NOT_FOUND                         (CM_ERROR_NAME_CODE | 0x00000014)
#define RET_CM_CERTIFICATE_NOT_FOUND                 (CM_ERROR_NAME_CODE | 0x00000015)
#define RET_CM_KEY_NOT_SELECTED                      (CM_ERROR_NAME_CODE | 0x00000016)
#define RET_CM_UNSUPPORTED_ALG                       (CM_ERROR_NAME_CODE | 0x00000017)
#define RET_CM_UNSUPPORTED_CIPHER_ALG                (CM_ERROR_NAME_CODE | 0x00000018)
#define RET_CM_UNSUPPORTED_ELLIPTIC_CURVE            (CM_ERROR_NAME_CODE | 0x00000019)
#define RET_CM_UNSUPPORTED_RSA_LEN                   (CM_ERROR_NAME_CODE | 0x0000001A)
#define RET_CM_UNSUPPORTED_KEY_DERIVATION_FUNC_ALG   (CM_ERROR_NAME_CODE | 0x0000001B)
#define RET_CM_INVALID_HASH                          (CM_ERROR_NAME_CODE | 0x0000001C)
#define RET_CM_INVALID_KEY                           (CM_ERROR_NAME_CODE | 0x0000001D)
#define RET_CM_INVALID_ELLIPTIC_CURVE                (CM_ERROR_NAME_CODE | 0x0000001E)
#define RET_CM_INVALID_UTF8_STR                      (CM_ERROR_NAME_CODE | 0x0000001F)
#define RET_CM_INVALID_JSON                          (CM_ERROR_NAME_CODE | 0x00000020)
#define RET_CM_INVALID_PARAM_DH                      (CM_ERROR_NAME_CODE | 0x00000021)
#define RET_CM_UNSUPPORTED_KEY_CONTAINER             (CM_ERROR_NAME_CODE | 0x00000022)
#define RET_CM_UNSUPPORTED_FORMAT                    (CM_ERROR_NAME_CODE | 0x00000023)
#define RET_CM_CONNECTION_ERROR                      (CM_ERROR_NAME_CODE | 0x00000024)
#define RET_CM_RESPONSE_INVALID                      (CM_ERROR_NAME_CODE | 0x00000025)
#define RET_CM_RESPONSE_ERROR                        (CM_ERROR_NAME_CODE | 0x00000026)
#define RET_CM_ACCESS_DENIED                         (CM_ERROR_NAME_CODE | 0x00000027)
#define RET_CM_JSON_FAILURE                          (CM_ERROR_NAME_CODE | 0x00000028)
#define RET_CM_STORAGE_NOT_OPEN                      (CM_ERROR_NAME_CODE | 0x00000029)
#define RET_CM_TOKEN_ERROR                           (CM_ERROR_NAME_CODE | 0x0000002A)
#define RET_CM_TOKEN_NO_FREE_SESSIONS                (CM_ERROR_NAME_CODE | 0x0000002B)
#define RET_CM_TOKEN_NO_FREE_SPACE                   (CM_ERROR_NAME_CODE | 0x0000002C)
#define RET_CM_TOKEN_ALREADY_LOGGED                  (CM_ERROR_NAME_CODE | 0x0000002D)
#define RET_CM_TOKEN_NOT_LOGGED                      (CM_ERROR_NAME_CODE | 0x0000002E)
#define RET_CM_TOKEN_RESERVED                        (CM_ERROR_NAME_CODE | 0x0000002F)
#define RET_CM_FILE_OPEN_ERROR                       (CM_ERROR_NAME_CODE | 0x00000030)
#define RET_CM_FILE_READ_ERROR                       (CM_ERROR_NAME_CODE | 0x00000031)
#define RET_CM_FILE_WRITE_ERROR                      (CM_ERROR_NAME_CODE | 0x00000032)
#define RET_CM_FILE_DELETE_ERROR                     (CM_ERROR_NAME_CODE | 0x00000033)
#define RET_CM_DECODE_ASN1_ERROR                     (CM_ERROR_NAME_CODE | 0x00000034)
#define RET_CM_ENCODE_ASN1_ERROR                     (CM_ERROR_NAME_CODE | 0x00000035)


#endif
