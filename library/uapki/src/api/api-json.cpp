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


using namespace std;

typedef int (*fUapkiMethod)(JSON_Object* joParams, JSON_Object* joResult);
typedef int (*fUapkiMethodType)(fUapkiMethod method, JSON_Object* joParams, JSON_Object* joResult);

struct UapkiMethod {
    const char* name;
    const fUapkiMethod
                method;
    const fUapkiMethodType
                methodType;
};

static int call_serial_method (fUapkiMethod fMethod, JSON_Object* joParams, JSON_Object* joResult);
static int call_static_method (fUapkiMethod fMethod, JSON_Object* joParams, JSON_Object* joResult);
static int call_thread_method (fUapkiMethod fMethod, JSON_Object* joParams, JSON_Object* joResult);

static const UapkiMethod uapki_methods[] = {
    {
        "VERSION",
        uapki_version,
        call_static_method
    },
    {
        "INIT",
        uapki_init,
        call_serial_method
    },
    {
        "DEINIT",
        uapki_deinit,
        call_serial_method
    },
    {
        "PROVIDERS",
        uapki_list_providers,
        call_serial_method
    },
    {
        "STORAGES",
        uapki_provider_list_storages,
        call_serial_method
    },
    {
        "STORAGE_INFO",
        uapki_provider_storage_info,
        call_serial_method
    },
    {
        "OPEN",
        uapki_storage_open,
        call_serial_method
    },
    {
        "CLOSE",
        uapki_storage_close,
        call_serial_method
    },
    {
        "KEYS",
        uapki_session_list_keys,
        call_serial_method
    },
    {
        "SELECT_KEY",
        uapki_session_select_key,
        call_serial_method
    },
    {
        "CREATE_KEY",
        uapki_session_key_create,
        call_serial_method
    },
    {
        "DELETE_KEY",
        uapki_session_key_delete,
        call_serial_method
    },
    {
        "GET_CSR",
        uapki_key_get_csr,
        call_serial_method
    },
    {
        "CHANGE_PASSWORD",
        uapki_storage_change_password,
        call_serial_method
    },
    {
        "INIT_KEY_USAGE",
        uapki_key_init_usage,
        call_serial_method
    },
    {
        "SIGN",
        uapki_sign,
        call_thread_method
    },
    {
        "VERIFY",
        uapki_verify_signature,
        call_thread_method
    },
    {
        "BUILD_CMS_2PASS",
        uapki_build_cms_2pass,
        call_thread_method
    },
    {
        "BUILD_CSR_2PASS",
        uapki_build_csr_2pass,
        call_static_method
    },
    {
        "ADD_CERT",
        uapki_add_cert,
        call_thread_method
    },
    {
        "CERT_INFO",
        uapki_cert_info,
        call_thread_method
    },
    {
        "GET_CERT",
        uapki_get_cert,
        call_thread_method
    },
    {
        "LIST_CERTS",
        uapki_list_certs,
        call_thread_method
    },
    {
        "REMOVE_CERT",
        uapki_remove_cert,
        call_serial_method
    },
    {
        "VERIFY_CERT",
        uapki_verify_cert,
        call_thread_method
    },
    {
        "ADD_CRL",
        uapki_add_crl,
        call_thread_method
    },
    {
        "CRL_INFO",
        uapki_crl_info,
        call_thread_method
    },
    {
        "LIST_CRLS",
        uapki_list_crls,
        call_thread_method
    },
    {
        "REMOVE_CRL",
        uapki_remove_crl,
        call_serial_method
    },
    {
        "DECRYPT",
        uapki_decrypt,
        call_thread_method
    },
    {
        "ENCRYPT",
        uapki_encrypt,
        call_thread_method
    },
    {
        "RANDOM_BYTES",
        uapki_random_bytes,
        call_thread_method
    },
    {
        "CERT_STATUS_BY_OCSP",
        uapki_cert_status_by_ocsp,
        call_thread_method
    },
    {
        "DIGEST",
        uapki_digest,
        call_static_method
    },
    {
        "VERIFY_CSR",
        uapki_verify_csr,
        call_static_method
    },
    {
        "GENERATE_CERTBUNDLE",
        uapki_generate_certbundle,
        call_static_method
    },
    {
        "MODIFY_CMS",
        uapki_modify_cms,
        call_static_method
    },
    {
        "ASN1_DECODE",
        uapki_asn1_decode,
        call_static_method
    },
    {
        "ASN1_ENCODE",
        uapki_asn1_encode,
        call_static_method
    },
#ifdef API_JSON_CUSTOM_METHODS
    API_JSON_CUSTOM_METHODS
#endif
};


static atomic_uint api_counter_methods(0);
static atomic_bool api_serialmethod_is_running(false);
static mutex api_mtx_serialmethod;


static int call_serial_method (
        fUapkiMethod fMethod,
        JSON_Object* joParams,
        JSON_Object* joResult
)
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

    const int ret = fMethod(joParams, joResult);
    DEBUG_OUTCON(printf("  ret=%d\n", ret));
    api_serialmethod_is_running = false;
    return ret;
}

static int call_static_method (
        fUapkiMethod fMethod,
        JSON_Object* joParams,
        JSON_Object* joResult
)
{
    const int ret = fMethod(joParams, joResult);
    DEBUG_OUTCON(printf("  ret=%d\n", ret));
    return ret;
}

static int call_thread_method (
        fUapkiMethod fMethod,
        JSON_Object* joParams,
        JSON_Object* joResult
)
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

    const int ret = fMethod(joParams, joResult);
    DEBUG_OUTCON(printf("  ret=%d\n", ret));
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
    const UapkiMethod* uapki_method = nullptr;
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
    if (!s_method) {
        err_code = RET_UAPKI_INVALID_METHOD;
        goto cleanup;
    }

    json_result.setString("method", s_method);
    for (size_t i = 0; i < sizeof(uapki_methods) / sizeof(UapkiMethod); i++) {
        if (strcmp(s_method, uapki_methods[i].name) == 0) {
            uapki_method = &uapki_methods[i];
            break;
        }
    }
    if (!uapki_method) {
        err_code = RET_UAPKI_INVALID_METHOD;
        goto cleanup;
    }

    jo_params = json_request.getObject("parameters");
    jo_result = json_result.setObject("result");
    if (!jo_result) {
        err_code = RET_UAPKI_GENERAL_ERROR;
        goto cleanup;
    }

    err_code = uapki_method->methodType(uapki_method->method, jo_params, jo_result);

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
