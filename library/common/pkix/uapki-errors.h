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

//  Last update: 2021-08-31

#ifndef _UAPKI_ERRORS_H_
#define _UAPKI_ERRORS_H_

#define UAPKI_ERROR_NAME_CODE                                         0x1000

/** Невизначена помилка. */
#define RET_UAPKI_GENERAL_ERROR                                       (UAPKI_ERROR_NAME_CODE | 0x00000001)
/** Помилка з'єднання з сервером. */
#define RET_UAPKI_CONNECTION_ERROR                                    (UAPKI_ERROR_NAME_CODE | 0x00000002)
/** Неправильний формат JSON запиту. */
#define RET_UAPKI_INVALID_JSON_FORMAT                                 (UAPKI_ERROR_NAME_CODE | 0x00000003)
/** Невказаний або неправильний метод. */
#define RET_UAPKI_INVALID_METHOD                                      (UAPKI_ERROR_NAME_CODE | 0x00000004)
/** Невказаний або неправильний метод. */
#define RET_UAPKI_INVALID_PARAMETER                                   (UAPKI_ERROR_NAME_CODE | 0x00000005)
/** Потребує ім'я файлу як ідентифікатор сховища. */
#define RET_UAPKI_UNKNOWN_PROVIDER                                    (UAPKI_ERROR_NAME_CODE | 0x00000006)
/** Потребує ім'я файлу як ідентифікатор сховища. */
#define RET_UAPKI_FILENAME_REQUIRED                                   (UAPKI_ERROR_NAME_CODE | 0x00000007)
/** Потребує ім'я користувача як ідентифікатор сховища. */
#define RET_UAPKI_LOGIN_REQUIRED                                      (UAPKI_ERROR_NAME_CODE | 0x00000008)
/** Бібліотеку не ініціалізовано. */
#define RET_UAPKI_NOT_INITIALIZED                                     (UAPKI_ERROR_NAME_CODE | 0x00000009)
/** Бібліотеку вже ініціалізовано. */
#define RET_UAPKI_ALREADY_INITIALIZED                                 (UAPKI_ERROR_NAME_CODE | 0x0000000A)
/** Сховище не відкрито. */
#define RET_UAPKI_NO_STORAGE                                          (UAPKI_ERROR_NAME_CODE | 0x0000000B)
/** Ключ не вибрано. */
#define RET_UAPKI_KEY_NOT_SELECTED                                    (UAPKI_ERROR_NAME_CODE | 0x0000000C)
/** Ключ не може бути використаний для операції за призначенням. */
#define RET_UAPKI_INVALID_KEY_USAGE                                   (UAPKI_ERROR_NAME_CODE | 0x0000000D)

#define RET_UAPKI_UNSUPPORTED_ALG                                     (UAPKI_ERROR_NAME_CODE | 0x0000000E)

#define RET_UAPKI_INVALID_HASH_SIZE                                   (UAPKI_ERROR_NAME_CODE | 0x0000000F)

#define RET_UAPKI_INVALID_KEY_ID                                      (UAPKI_ERROR_NAME_CODE | 0x00000010)

#define RET_UAPKI_JSON_FAILURE                                        (UAPKI_ERROR_NAME_CODE | 0x00000011)

#define RET_UAPKI_INVALID_BIT_STRING                                  (UAPKI_ERROR_NAME_CODE | 0x00000012)

#define RET_UAPKI_UNEXPECTED_BIT_STRING                               (UAPKI_ERROR_NAME_CODE | 0x00000013)

#define RET_UAPKI_TOO_LONG_BIT_STRING                                 (UAPKI_ERROR_NAME_CODE | 0x00000014)

#define RET_UAPKI_TIME_ERROR                                          (UAPKI_ERROR_NAME_CODE | 0x00000015)

#define RET_UAPKI_NOT_SUPPORTED                                       (UAPKI_ERROR_NAME_CODE | 0x00000016)

#define RET_UAPKI_NOT_ALLOWED                                         (UAPKI_ERROR_NAME_CODE | 0x00000017)

#define RET_UAPKI_OFFLINE_MODE                                        (UAPKI_ERROR_NAME_CODE | 0x00000018)


#define RET_UAPKI_FILE_OPEN_ERROR                                     (UAPKI_ERROR_NAME_CODE | 0x00000020)
#define RET_UAPKI_FILE_READ_ERROR                                     (UAPKI_ERROR_NAME_CODE | 0x00000021)
#define RET_UAPKI_FILE_WRITE_ERROR                                    (UAPKI_ERROR_NAME_CODE | 0x00000022)
#define RET_UAPKI_FILE_GET_SIZE_ERROR                                 (UAPKI_ERROR_NAME_CODE | 0x00000023)
#define RET_UAPKI_FILE_DELETE_ERROR                                   (UAPKI_ERROR_NAME_CODE | 0x00000024)
#define RET_UAPKI_HTTP_STATUS_NOT_OK                                  (UAPKI_ERROR_NAME_CODE | 0x00000025)


#define RET_UAPKI_INVALID_CONTENT_INFO                                (UAPKI_ERROR_NAME_CODE | 0x00000030)
#define RET_UAPKI_INVALID_STRUCT                                      (UAPKI_ERROR_NAME_CODE | 0x00000031)
#define RET_UAPKI_INVALID_STRUCT_VERSION                              (UAPKI_ERROR_NAME_CODE | 0x00000032)
#define RET_UAPKI_CONTENT_NOT_PRESENT                                 (UAPKI_ERROR_NAME_CODE | 0x00000033)
#define RET_UAPKI_INVALID_ATTRIBUTE                                   (UAPKI_ERROR_NAME_CODE | 0x00000034)
#define RET_UAPKI_ATTRIBUTE_NOT_PRESENT                               (UAPKI_ERROR_NAME_CODE | 0x00000035)
#define RET_UAPKI_EXTENSION_NOT_PRESENT                               (UAPKI_ERROR_NAME_CODE | 0x00000036)
#define RET_UAPKI_EXTENSION_NOT_SET_CRITICAL                          (UAPKI_ERROR_NAME_CODE | 0x00000037)


#define RET_UAPKI_CERT_STORE_LOAD_ERROR                               (UAPKI_ERROR_NAME_CODE | 0x00000040)
#define RET_UAPKI_CERT_NOT_FOUND                                      (UAPKI_ERROR_NAME_CODE | 0x00000041)
#define RET_UAPKI_CERT_VALIDITY_NOT_BEFORE_ERROR                      (UAPKI_ERROR_NAME_CODE | 0x00000042)
#define RET_UAPKI_CERT_VALIDITY_NOT_AFTER_ERROR                       (UAPKI_ERROR_NAME_CODE | 0x00000043)
#define RET_UAPKI_CERT_ISSUER_NOT_FOUND                               (UAPKI_ERROR_NAME_CODE | 0x00000044)

#define RET_UAPKI_CRL_STORE_LOAD_ERROR                                (UAPKI_ERROR_NAME_CODE | 0x00000050)
#define RET_UAPKI_CRL_URL_NOT_PRESENT                                 (UAPKI_ERROR_NAME_CODE | 0x00000051)
#define RET_UAPKI_CRL_NOT_DOWNLOADED                                  (UAPKI_ERROR_NAME_CODE | 0x00000052)
#define RET_UAPKI_CRL_NOT_FOUND                                       (UAPKI_ERROR_NAME_CODE | 0x00000053)


#define RET_UAPKI_OCSP_URL_NOT_PRESENT                                (UAPKI_ERROR_NAME_CODE | 0x00000060)
#define RET_UAPKI_OCSP_NOT_RESPONDING                                 (UAPKI_ERROR_NAME_CODE | 0x00000061)
#define RET_UAPKI_OCSP_RESPONSE_NOT_SUCCESSFUL                        (UAPKI_ERROR_NAME_CODE | 0x00000062)
#define RET_UAPKI_OCSP_VERIFY_RESPONSE_FAILED                         (UAPKI_ERROR_NAME_CODE | 0x00000063)
#define RET_UAPKI_OCSP_VERIFY_RESPONSE_ERROR                          (UAPKI_ERROR_NAME_CODE | 0x00000064)
#define RET_UAPKI_OCSP_INVALID_NONCE                                  (UAPKI_ERROR_NAME_CODE | 0x00000065)
#define RET_UAPKI_OCSP_RESPONSE_INVALID_CONTENT                       (UAPKI_ERROR_NAME_CODE | 0x00000066)


#define RET_UAPKI_TSP_URL_NOT_PRESENT                                 (UAPKI_ERROR_NAME_CODE | 0x00000070)
#define RET_UAPKI_TSP_NOT_RESPONDING                                  (UAPKI_ERROR_NAME_CODE | 0x00000071)
#define RET_UAPKI_TSP_RESPONSE_NOT_GRANTED                            (UAPKI_ERROR_NAME_CODE | 0x00000072)
#define RET_UAPKI_TSP_RESPONSE_NOT_EQUAL_REQUEST                      (UAPKI_ERROR_NAME_CODE | 0X00000073)

#endif
