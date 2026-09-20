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
#include "parson-helper.h"
#include "time-util.h"
#include "uapki-sessions-export.h"
#include <stdint.h>
#include <chrono>
#include <memory>
#include <mutex>
#include <unordered_map>


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
 #define DEBUG_OUTCON(expression) expression
#endif


extern "C" const char* error_code_to_str (int errorCode);


using namespace std;
using namespace UapkiNS;

struct UapkiMethod;

typedef int (*fUapkiMethod)(Context& context, JSON_Object* joParams, JSON_Object* joResult);
typedef int (*fUapkiMethodType)(Context& context, const UapkiMethod& method, JSON_Object* joParams, JSON_Object* joResult);

struct UapkiMethod {
    const char* name;
    const fUapkiMethod
                method;
    const fUapkiMethodType
                methodType;
    //  removes items from the shared memory when a session uses one, so it needs exclusive access to it
    const bool  sharedExclusive;
    //  may be executed directly on a shared memory object
    const bool  sharedMemory;
};

static int call_serial_method (Context& context, const UapkiMethod& method, JSON_Object* joParams, JSON_Object* joResult);
static int call_static_method (Context& context, const UapkiMethod& method, JSON_Object* joParams, JSON_Object* joResult);
static int call_thread_method (Context& context, const UapkiMethod& method, JSON_Object* joParams, JSON_Object* joResult);

static const UapkiMethod uapki_methods[] = {
    {
        "VERSION",
        uapki_version,
        call_static_method,
        false, true
    },
    {
        "INIT",
        uapki_init,
        call_serial_method,
        false, true
    },
    {
        "DEINIT",
        uapki_deinit,
        call_serial_method,
        false, true
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
        call_thread_method,
        false, true
    },
    {
        "CERT_INFO",
        uapki_cert_info,
        call_thread_method,
        false, true
    },
    {
        "GET_CERT",
        uapki_get_cert,
        call_thread_method,
        false, true
    },
    {
        "LIST_CERTS",
        uapki_list_certs,
        call_thread_method,
        false, true
    },
    {
        "REMOVE_CERT",
        uapki_remove_cert,
        call_serial_method,
        true, true
    },
    {
        "VERIFY_CERT",
        uapki_verify_cert,
        call_thread_method
    },
    {
        "ADD_CRL",
        uapki_add_crl,
        call_thread_method,
        false, true
    },
    {
        "CRL_INFO",
        uapki_crl_info,
        call_thread_method,
        false, true
    },
    {
        "LIST_CRLS",
        uapki_list_crls,
        call_thread_method,
        false, true
    },
    {
        "REMOVE_CRL",
        uapki_remove_crl,
        call_serial_method,
        true, true
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


//  Handles are never reused, so a stale handle can not alias a session created later;
//  sessions get odd handles and shared memories even ones, so the two kinds never alias either
class SessionRegistry {
    mutex       m_Mutex;
    uintptr_t   m_NextHandle;
    unordered_map<const void*, shared_ptr<Session>>
                m_Sessions;

    explicit SessionRegistry (const uintptr_t firstHandle)
        : m_NextHandle(firstHandle)
    {}

public:
    static SessionRegistry& sessions (void)
    {
        static SessionRegistry* registry = new SessionRegistry(1);
        return *registry;
    }

    static SessionRegistry& sharedMemories (void)
    {
        static SessionRegistry* registry = new SessionRegistry(2);
        return *registry;
    }

    const void* create (void)
    {
        shared_ptr<Session> session(new Session());
        lock_guard<mutex> lock(m_Mutex);
        const void* handle = reinterpret_cast<const void*>(m_NextHandle);
        m_NextHandle += 2;
        m_Sessions[handle] = session;
        return handle;
    }

    shared_ptr<Session> find (const void* handle)
    {
        lock_guard<mutex> lock(m_Mutex);
        auto it = m_Sessions.find(handle);
        return (it != m_Sessions.end()) ? it->second : shared_ptr<Session>();
    }

    void remove (const void* handle)
    {
        shared_ptr<Session> session;
        {
            lock_guard<mutex> lock(m_Mutex);
            auto it = m_Sessions.find(handle);
            if (it == m_Sessions.end()) return;
            session = std::move(it->second);
            m_Sessions.erase(it);
        }
    }

};  //  end class SessionRegistry


//  Lock order is always: the session's gate, then the shared memory's gate
static int call_serial_method (
        Context& context,
        const UapkiMethod& method,
        JSON_Object* joParams,
        JSON_Object* joResult
)
{
    ApiGate::SerialLock lock(context.session().apiGate());
    int ret;
    if (context.shared() && method.sharedExclusive) {
        ApiGate::SerialLock lock_shared(context.shared()->apiGate());
        ret = method.method(context, joParams, joResult);
    }
    else if (context.shared()) {
        ApiGate::ThreadLock lock_shared(context.shared()->apiGate());
        ret = method.method(context, joParams, joResult);
    }
    else {
        ret = method.method(context, joParams, joResult);
    }
    DEBUG_OUTCON(printf("call_serial_method(), ret=%d\n", ret));
    return ret;
}

static int call_static_method (
        Context& context,
        const UapkiMethod& method,
        JSON_Object* joParams,
        JSON_Object* joResult
)
{
    const int ret = method.method(context, joParams, joResult);
    DEBUG_OUTCON(printf("call_static_method(), ret=%d\n", ret));
    return ret;
}

static int call_thread_method (
        Context& context,
        const UapkiMethod& method,
        JSON_Object* joParams,
        JSON_Object* joResult
)
{
    ApiGate::ThreadLock lock(context.session().apiGate());
    int ret;
    if (context.shared()) {
        ApiGate::ThreadLock lock_shared(context.shared()->apiGate());
        ret = method.method(context, joParams, joResult);
    }
    else {
        ret = method.method(context, joParams, joResult);
    }
    DEBUG_OUTCON(printf("call_thread_method(), ret=%d\n", ret));
    return ret;
}

static char* process_request (
        Context& context,
        const char* request,
        const bool sharedMemoryOnly = false
)
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
    if (sharedMemoryOnly && !uapki_method->sharedMemory) {
        err_code = RET_UAPKI_NOT_ALLOWED;
        goto cleanup;
    }

    jo_params = json_request.getObject("parameters");
    jo_result = json_result.setObject("result");
    if (!jo_result) {
        err_code = RET_UAPKI_GENERAL_ERROR;
        goto cleanup;
    }

    err_code = uapki_method->methodType(context, *uapki_method, jo_params, jo_result);

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

static char* error_response (
        const int errorCode
)
{
    ParsonHelper json_result;
    char* rv_sjson = nullptr;
    json_result.create();
    json_result.setInt32("errorCode", errorCode);
    json_result.setString("error", error_code_to_str(errorCode));
    json_result.serialize(&rv_sjson);
    return rv_sjson;
}

static char* general_error_response (void)
{
    static const char RESPONSE[] = "{\"errorCode\":4097,\"error\":\"GENERAL_ERROR\"}";
    char* rv_sjson = (char*)malloc(sizeof(RESPONSE));
    if (rv_sjson) {
        memcpy(rv_sjson, RESPONSE, sizeof(RESPONSE));
    }
    return rv_sjson;
}

//  Benign DO()/ERROR_ADD failures inside a method grow uapkic's per-thread error trace, which is
//  reset only by the next SET_ERROR on that thread. The JSON API never reads it: release it per call.
struct StacktraceRelease {
    ~StacktraceRelease (void) {
        stacktrace_free_current();
    }
};

UAPKI_EXPORT char* process (const char* request)
{
    StacktraceRelease stacktrace_release;
    try {
        Context context(Session::global());
        return process_request(context, request);
    }
    catch (...) {
        return general_error_response();
    }
}

UAPKI_EXPORT void json_free (char* buf)
{ 
    free(buf);
}

UAPKI_EXPORT UAPKI_SESSION* uapki_session_create (void)
{
    try {
        return reinterpret_cast<UAPKI_SESSION*>(const_cast<void*>(SessionRegistry::sessions().create()));
    }
    catch (...) {
        return nullptr;
    }
}

UAPKI_EXPORT void uapki_session_free (UAPKI_SESSION* session)
{
    try {
        SessionRegistry::sessions().remove(session);
    }
    catch (...) {
    }
}

UAPKI_EXPORT char* uapki_session_process (UAPKI_SESSION* session, UAPKI_SESSION_SHARED_MEMORY* memory, const char* request)
{
    StacktraceRelease stacktrace_release;
    try {
        shared_ptr<Session> found = SessionRegistry::sessions().find(session);
        if (!found) return error_response(RET_UAPKI_INVALID_SESSION);

        shared_ptr<Session> found_memory;
        if (memory) {
            found_memory = SessionRegistry::sharedMemories().find(memory);
            if (!found_memory) return error_response(RET_UAPKI_INVALID_SHARED_MEMORY);
        }

        Context context(*found, found_memory);
        return process_request(context, request);
    }
    catch (...) {
        return general_error_response();
    }
}

UAPKI_EXPORT UAPKI_SESSION_SHARED_MEMORY* uapki_session_shared_memory_create (void)
{
    try {
        return reinterpret_cast<UAPKI_SESSION_SHARED_MEMORY*>(const_cast<void*>(SessionRegistry::sharedMemories().create()));
    }
    catch (...) {
        return nullptr;
    }
}

UAPKI_EXPORT void uapki_session_shared_memory_free (UAPKI_SESSION_SHARED_MEMORY* memory)
{
    try {
        SessionRegistry::sharedMemories().remove(memory);
    }
    catch (...) {
    }
}

UAPKI_EXPORT char* uapki_session_shared_memory_process (UAPKI_SESSION_SHARED_MEMORY* memory, const char* request)
{
    StacktraceRelease stacktrace_release;
    try {
        shared_ptr<Session> found = SessionRegistry::sharedMemories().find(memory);
        if (!found) return error_response(RET_UAPKI_INVALID_SHARED_MEMORY);

        Context context(*found, shared_ptr<Session>(), true);
        return process_request(context, request, true);
    }
    catch (...) {
        return general_error_response();
    }
}
