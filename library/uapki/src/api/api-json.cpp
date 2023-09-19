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

#define FILE_MARKER "uapki/api/api-json.cpp"

#include "api-json-internal.h"
#include "global-objects.h"
#include "parson-helper.h"
#include "time-util.h"
#include <atomic>
#include <chrono>
#include <mutex>


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
 #define DEBUG_OUTCON(expression) expression
#endif


extern "C" const char* error_code_to_str (int errorCode);


typedef int (*fUapkiMethod)(JSON_Object* joParams, JSON_Object* joResult);


using namespace std;


/*static int dev_method(JSON_Object* joParams, JSON_Object* joResult)
{
    (void)joResult;
    const char* s_msg = json_object_get_string(joParams, "message");
    if (s_msg) {
        printf("@@@ dev_method, message: '%s' @@@\n", s_msg);
    }
    const uint32_t ms = ParsonHelper::jsonObjectGetUint32(joParams, "sleep", 0);
    if (ms > 0) {
        sleep_ms(ms);
    }
    return RET_OK;
}// */

enum class UapkiMethod : uint32_t {
    VERSION             = 0,
    INIT                = 1,
    DEINIT              = 2,
    PROVIDERS           = 3,
    STORAGES            = 4,
    STORAGE_INFO        = 5,
    OPEN                = 6,
    CLOSE               = 7,
    KEYS                = 8,
    SELECT_KEY          = 9,
    CREATE_KEY          = 10,
    DELETE_KEY          = 11,
    GET_CSR             = 12,
    CHANGE_PASSWORD     = 13,
    INIT_KEY_USAGE      = 14,
    SIGN                = 15,
    VERIFY              = 16,
    ADD_CERT            = 17,
    CERT_INFO           = 18,
    GET_CERT            = 19,
    LIST_CERTS          = 20,
    REMOVE_CERT         = 21,
    VERIFY_CERT         = 22,
    ADD_CRL             = 23,
    CRL_INFO            = 24,
    LIST_CRLS           = 25,
    REMOVE_CRL          = 26,
    DECRYPT             = 27,
    ENCRYPT             = 28,
    RANDOM_BYTES        = 29,
    CERT_STATUS_BY_OCSP = 30,
    DIGEST              = 31,
    ASN1_DECODE         = 32,
    ASN1_ENCODE         = 33,
    UNDEFINED           = 34
};  //  end enum UapkiMethod

static const fUapkiMethod UAPKI_METHODS[34] = {
    uapki_version,
    uapki_init,
    uapki_deinit,
    uapki_list_providers,
    uapki_provider_list_storages,
    uapki_provider_storage_info,
    uapki_storage_open,
    uapki_storage_close,
    uapki_session_list_keys,
    uapki_session_select_key,
    uapki_session_key_create,
    uapki_session_key_delete,
    uapki_key_get_csr,
    uapki_storage_change_password,
    uapki_key_init_usage,
    uapki_sign,
    uapki_verify_signature,
    uapki_add_cert,
    uapki_cert_info,
    uapki_get_cert,
    uapki_list_certs,
    uapki_remove_cert,
    uapki_verify_cert,
    uapki_add_crl,
    uapki_crl_info,
    uapki_list_crls,
    uapki_remove_crl,
    uapki_decrypt,
    uapki_encrypt,
    uapki_random_bytes,
    uapki_cert_status_by_ocsp,
    uapki_digest,
    uapki_asn1_decode,
    uapki_asn1_encode
};


static atomic_uint api_counter_methods(0);
static atomic_bool api_serialmethod_is_running(false);
static mutex api_mtx_serialmethod;


static UapkiMethod method_from_str (const char* method)
{
    UapkiMethod rv_method = UapkiMethod::UNDEFINED;
    if (method) {
        if (strcmp(method, "VERSION") == 0) {
            rv_method = UapkiMethod::VERSION;
        }
        else if (strcmp(method, "INIT") == 0) {
            rv_method = UapkiMethod::INIT;
        }
        else if (strcmp(method, "DEINIT") == 0) {
            rv_method = UapkiMethod::DEINIT;
        }
        else if (strcmp(method, "PROVIDERS") == 0) {
            rv_method = UapkiMethod::PROVIDERS;
        }
        else if (strcmp(method, "STORAGES") == 0) {
            rv_method = UapkiMethod::STORAGES;
        }
        else if (strcmp(method, "STORAGE_INFO") == 0) {
            rv_method = UapkiMethod::STORAGE_INFO;
        }
        else if (strcmp(method, "OPEN") == 0) {
            rv_method = UapkiMethod::OPEN;
        }
        else if (strcmp(method, "CLOSE") == 0) {
            rv_method = UapkiMethod::CLOSE;
        }
        else if (strcmp(method, "KEYS") == 0) {
            rv_method = UapkiMethod::KEYS;
        }
        else if (strcmp(method, "SELECT_KEY") == 0) {
            rv_method = UapkiMethod::SELECT_KEY;
        }
        else if (strcmp(method, "CREATE_KEY") == 0) {
            rv_method = UapkiMethod::CREATE_KEY;
        }
        else if (strcmp(method, "DELETE_KEY") == 0) {
            rv_method = UapkiMethod::DELETE_KEY;
        }
        else if (strcmp(method, "GET_CSR") == 0) {
            rv_method = UapkiMethod::GET_CSR;
        }
        else if (strcmp(method, "CHANGE_PASSWORD") == 0) {
            rv_method = UapkiMethod::CHANGE_PASSWORD;
        }
        else if (strcmp(method, "INIT_KEY_USAGE") == 0) {
            rv_method = UapkiMethod::INIT_KEY_USAGE;
        }
        else if (strcmp(method, "SIGN") == 0) {
            rv_method = UapkiMethod::SIGN;
        }
        else if (strcmp(method, "VERIFY") == 0) {
            rv_method = UapkiMethod::VERIFY;
        }
        else if (strcmp(method, "ADD_CERT") == 0) {
            rv_method = UapkiMethod::ADD_CERT;
        }
        else if (strcmp(method, "CERT_INFO") == 0) {
            rv_method = UapkiMethod::CERT_INFO;
        }
        else if (strcmp(method, "GET_CERT") == 0) {
            rv_method = UapkiMethod::GET_CERT;
        }
        else if (strcmp(method, "LIST_CERTS") == 0) {
            rv_method = UapkiMethod::LIST_CERTS;
        }
        else if (strcmp(method, "REMOVE_CERT") == 0) {
            rv_method = UapkiMethod::REMOVE_CERT;
        }
        else if (strcmp(method, "VERIFY_CERT") == 0) {
            rv_method = UapkiMethod::VERIFY_CERT;
        }
        else if (strcmp(method, "ADD_CRL") == 0) {
            rv_method = UapkiMethod::ADD_CRL;
        }
        else if (strcmp(method, "CRL_INFO") == 0) {
            rv_method = UapkiMethod::CRL_INFO;
        }
        else if (strcmp(method, "LIST_CRLS") == 0) {
            rv_method = UapkiMethod::LIST_CRLS;
        }
        else if (strcmp(method, "REMOVE_CRL") == 0) {
            rv_method = UapkiMethod::REMOVE_CRL;
        }
        else if (strcmp(method, "DECRYPT") == 0) {
            rv_method = UapkiMethod::DECRYPT;
        }
        else if (strcmp(method, "ENCRYPT") == 0) {
            rv_method = UapkiMethod::ENCRYPT;
        }
        else if (strcmp(method, "RANDOM_BYTES") == 0) {
            rv_method = UapkiMethod::RANDOM_BYTES;
        }
        else if (strcmp(method, "CERT_STATUS_BY_OCSP") == 0) {
            rv_method = UapkiMethod::CERT_STATUS_BY_OCSP;
        }
        else if (strcmp(method, "DIGEST") == 0) {
            rv_method = UapkiMethod::DIGEST;
        }
        else if (strcmp(method, "ASN1_DECODE") == 0) {
            rv_method = UapkiMethod::ASN1_DECODE;
        }
        else if (strcmp(method, "ASN1_ENCODE") == 0) {
            rv_method = UapkiMethod::ASN1_ENCODE;
        }
    }
    return rv_method;
}


static int call_serial_method (UapkiMethod method, JSON_Object* joParams, JSON_Object* joResult)
{
    lock_guard<mutex> lock(api_mtx_serialmethod);
    api_serialmethod_is_running = true;

    unsigned int cnt_threadmethods = api_counter_methods;
    DEBUG_OUTCON(printf("call_serial_method(), count T-methods: %d", cnt_threadmethods));
    while (cnt_threadmethods > 0) {
        //  If running thread methods then wait all thread methods are completed
        TimeUtil::msSleep(1);
        cnt_threadmethods = api_counter_methods;
        DEBUG_OUTCON(printf("%d", cnt_threadmethods));
    }

    const fUapkiMethod f_method = UAPKI_METHODS[(uint32_t)method];
    const int ret = f_method(joParams, joResult);
    DEBUG_OUTCON(printf("  ret[M:%d]=%d\n", method, ret));

    api_serialmethod_is_running = false;
    return ret;
}

static int call_static_method (UapkiMethod method, JSON_Object* joParams, JSON_Object* joResult)
{
    const fUapkiMethod f_method = UAPKI_METHODS[(uint32_t)method];
    return f_method(joParams, joResult);
}

static int call_thread_method (UapkiMethod method, JSON_Object* joParams, JSON_Object* joResult)
{
    bool serialmethod_is_running = api_serialmethod_is_running;
    DEBUG_OUTCON(printf("call_thread_method(), serial method is running: %c", serialmethod_is_running ? '+' : '-'));
    while (serialmethod_is_running) {
        //  If running serial method then wait serial method be completed
        TimeUtil::msSleep(1);
        serialmethod_is_running = api_serialmethod_is_running;
        DEBUG_OUTCON(printf("%c", serialmethod_is_running ? '+' : '-'));
    }

    unsigned int cnt_methods = ++api_counter_methods;

    const fUapkiMethod f_method = UAPKI_METHODS[(uint32_t)method];
    const int ret = f_method(joParams, joResult);
    DEBUG_OUTCON(printf("  ret[M:%d]=%d\n", method, ret));

    cnt_methods = --api_counter_methods;
    return ret;
}


UAPKI_EXPORT char* process (const char* request)
{
    int err_code = RET_OK;
#ifdef ENABLE_ELAPSED_TIME
    const chrono::time_point<chrono::high_resolution_clock> dt_start = chrono::high_resolution_clock::now();
#endif
    ParsonHelper json_request, json_result;
    UapkiMethod method = UapkiMethod::UNDEFINED;
    JSON_Object* jo_params = nullptr;
    JSON_Object* jo_result = nullptr;
    const char* s_method = nullptr;
    char* rv_sjson = nullptr;

    json_result.create();
    json_result.setInt64("errorCode", RET_UAPKI_GENERAL_ERROR); //  Reserved first place in JSON-response

    if (!json_request.parse(request)) {
        err_code = RET_UAPKI_INVALID_JSON_FORMAT;
        goto cleanup;
    };

    s_method = json_request.getString("method");
    method = method_from_str(s_method);
    if (method == UapkiMethod::UNDEFINED) {
        err_code = RET_UAPKI_INVALID_METHOD;
        goto cleanup;
    }
    json_result.setString("method", s_method);

    jo_params = json_request.getObject("parameters");
    jo_result = json_result.setObject("result");
    if (!jo_result) {
        err_code = RET_UAPKI_GENERAL_ERROR;
        goto cleanup;
    }

    switch (method) {
    //  List serial(monopoly access)-methods
    case UapkiMethod::INIT:
    case UapkiMethod::DEINIT:
    case UapkiMethod::PROVIDERS:
    case UapkiMethod::STORAGES:
    case UapkiMethod::STORAGE_INFO:
    case UapkiMethod::OPEN:
    case UapkiMethod::CLOSE:
    case UapkiMethod::KEYS:
    case UapkiMethod::SELECT_KEY:
    case UapkiMethod::CREATE_KEY:
    case UapkiMethod::DELETE_KEY:
    case UapkiMethod::GET_CSR:
    case UapkiMethod::CHANGE_PASSWORD:
    case UapkiMethod::INIT_KEY_USAGE:
    case UapkiMethod::REMOVE_CERT:
    case UapkiMethod::REMOVE_CRL:
        err_code = call_serial_method(method, jo_params, jo_result);
        break;
    //  List thread(parallel access)-methods
    case UapkiMethod::SIGN:
    case UapkiMethod::VERIFY:
    case UapkiMethod::ADD_CERT:
    case UapkiMethod::CERT_INFO:
    case UapkiMethod::GET_CERT:
    case UapkiMethod::LIST_CERTS:
    case UapkiMethod::VERIFY_CERT:
    case UapkiMethod::ADD_CRL:
    case UapkiMethod::CRL_INFO:
    case UapkiMethod::LIST_CRLS:
    case UapkiMethod::DECRYPT:
    case UapkiMethod::ENCRYPT:
    case UapkiMethod::RANDOM_BYTES:
    case UapkiMethod::CERT_STATUS_BY_OCSP:
        err_code = call_thread_method(method, jo_params, jo_result);
        break;
    //  List static-methods
    case UapkiMethod::VERSION:
    case UapkiMethod::DIGEST:
    case UapkiMethod::ASN1_DECODE:
    case UapkiMethod::ASN1_ENCODE:
        err_code = call_static_method(method, jo_params, jo_result);
        break;
    default:
        break;
    }

cleanup:
    json_result.setInt32("errorCode", err_code);
    if (err_code != RET_OK) {
        json_result.setString("error", error_code_to_str(err_code));
    }
    if (ParsonHelper::jsonObjectGetBoolean(jo_params, "reportTime", false)) {
        const string s_time = TimeUtil::mtimeToFtime(TimeUtil::mtimeNow());
        (void)json_object_set_string(jo_result, "reportTime", s_time.c_str());
    }
#ifdef ENABLE_ELAPSED_TIME
    const chrono::duration<float> difference = chrono::high_resolution_clock::now() - dt_start;
    const int elapsed_time = static_cast<int>(1000 * difference.count());
    ParsonHelper::jsonObjectSetInt32(jo_result, "elapsedTime", elapsed_time);
#endif
    json_result.serialize(&rv_sjson);
    return rv_sjson;
}

UAPKI_EXPORT void json_free (char* buf)
{ 
    free(buf);
}
