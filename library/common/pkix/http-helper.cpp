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

#if defined(UAPKI_NO_HTTP)
//  no HTTP transport at all
#elif defined(__ANDROID__)
#include <jni.h>
#include <cstdlib>
#include "uapki-export.h"
#else
#define CURL_STATICLIB
#include "curl/curl.h"
#endif
#include "ba-utils.h"
#include "http-helper.h"
#include "uapkic.h"
#include "uapki-errors.h"
#include "uapki-ns.h"
#include <string.h>
#include <map>
#include <mutex>


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


const char* HttpHelper::CONTENT_TYPE_APP_JSON       = "Content-Type:application/json";
const char* HttpHelper::CONTENT_TYPE_OCSP_REQUEST   = "Content-Type:application/ocsp-request";
const char* HttpHelper::CONTENT_TYPE_TSP_REQUEST    = "Content-Type:application/timestamp-query";


struct HTTP_HELPER {
    bool    isInitialized;
    bool    offlineMode;
    string  proxyUrl;
    string  proxyCredentials;
    mutex   mtx;
    map<string, mutex>
            mtxByUrl;

    HTTP_HELPER (void)
        : isInitialized(false)
        , offlineMode(false)
    {}

    void reset (void)
    {
        isInitialized = false;
        offlineMode = false;
        proxyUrl.clear();
        proxyCredentials.clear();
    }
};  //  end struct HTTP_HELPER

static HTTP_HELPER http_helper;


#ifdef UAPKI_NO_HTTP
//  Build without libcurl (e.g. Android NDK has no system libcurl).
//  The library keeps its full API, but network requests are not performed:
//  every GET/POST reports RET_UAPKI_OFFLINE_MODE in offline mode and
//  RET_UAPKI_CONNECTION_ERROR otherwise. TSP/OCSP/CRL/LDAP fetching must be
//  done by the host application.

int HttpHelper::init (
        const bool offlineMode,
        const char* proxyUrl,
        const char* proxyCredentials
)
{
    http_helper.offlineMode = offlineMode;
    if (!http_helper.isInitialized) {
        http_helper.isInitialized = true;
        //  no transport - proxy settings are kept for diagnostics only
        if (proxyUrl) {
            http_helper.proxyUrl = string(proxyUrl);
            if (proxyCredentials && !http_helper.proxyUrl.empty()) {
                http_helper.proxyCredentials = string(proxyCredentials);
            }
        }
    }
    return RET_OK;
}

void HttpHelper::deinit (void)
{
    if (http_helper.isInitialized) {
        http_helper.reset();
    }
}

int HttpHelper::get (
        const string& uri,
        ByteArray** baResponse
)
{
    (void)uri;
    (void)baResponse;
    return (http_helper.offlineMode) ? RET_UAPKI_OFFLINE_MODE : RET_UAPKI_CONNECTION_ERROR;
}

int HttpHelper::post (
        const string& uri,
        const char* contentType,
        const ByteArray* baRequest,
        ByteArray** baResponse
)
{
    (void)uri;
    (void)contentType;
    (void)baRequest;
    (void)baResponse;
    return (http_helper.offlineMode) ? RET_UAPKI_OFFLINE_MODE : RET_UAPKI_CONNECTION_ERROR;
}

int HttpHelper::post (
        const string& uri,
        const char* contentType,
        const char* userPwd,
        const string& authorizationBearer,
        const string& request,
        ByteArray** baResponse
)
{
    (void)uri;
    (void)contentType;
    (void)userPwd;
    (void)authorizationBearer;
    (void)request;
    (void)baResponse;
    return (http_helper.offlineMode) ? RET_UAPKI_OFFLINE_MODE : RET_UAPKI_CONNECTION_ERROR;
}

#elif defined(__ANDROID__)
//  Android build: NDK has no system libcurl, so HTTP goes through
//  java.net.HttpURLConnection via JNI - the platform HTTP stack with the
//  system TLS and the system CA trust store (same idea as the fetch()
//  bridge in the Emscripten build).
//
//  The library needs a JavaVM* to make JNI calls:
//   - loaded with System.loadLibrary("uapki") - JNI_OnLoad stores it
//     automatically;
//   - loaded with plain dlopen() - the host application must call the
//     exported uapki_set_java_vm() first, otherwise every request reports
//     RET_UAPKI_CONNECTION_ERROR.
//
//  Note: since Android 9 cleartext HTTP is blocked by default at the Java
//  layer. CA endpoints (TSP/OCSP/CRL) are usually plain http://, so the
//  application must allow them with android:usesCleartextTraffic="true"
//  or a networkSecurityConfig.

static JavaVM* s_java_vm = nullptr;

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad (JavaVM* vm, void* reserved)
{
    (void)reserved;
    s_java_vm = vm;
    return JNI_VERSION_1_6;
}

extern "C" UAPKI_EXPORT void uapki_set_java_vm (void* vm)
{
    s_java_vm = (JavaVM*)vm;
}

namespace {

//  Attaches the current thread to the VM when needed, detaches on scope exit
struct JniEnvGuard {
    JNIEnv* env;
    bool    attached;

    JniEnvGuard (void)
        : env(nullptr), attached(false)
    {
        if (!s_java_vm) return;
        const jint rv = s_java_vm->GetEnv((void**)&env, JNI_VERSION_1_6);
        if (rv == JNI_EDETACHED) {
            if (s_java_vm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
                attached = true;
            }
            else {
                env = nullptr;
            }
        }
        else if (rv != JNI_OK) {
            env = nullptr;
        }
    }

    ~JniEnvGuard (void)
    {
        if (attached) s_java_vm->DetachCurrentThread();
    }
};  //  end struct JniEnvGuard

struct LocalFrame {
    JNIEnv* env;
    bool    pushed;

    LocalFrame (JNIEnv* iEnv, jint capacity)
        : env(iEnv), pushed(env->PushLocalFrame(capacity) == 0)
    {
        if (!pushed && env->ExceptionCheck()) env->ExceptionClear();
    }

    ~LocalFrame (void)
    {
        if (pushed) env->PopLocalFrame(nullptr);
    }
};  //  end struct LocalFrame

bool jni_pending (JNIEnv* env)
{
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return true;
    }
    return false;
}   //  jni_pending

//  "Content-Type:application/json" (curl header line) -> ("Content-Type", "application/json")
bool split_header_line (const string& line, string& name, string& value)
{
    const size_t colon = line.find(':');
    if ((colon == string::npos) || (colon == 0)) return false;
    name = line.substr(0, colon);
    size_t vbegin = colon + 1;
    while ((vbegin < line.size()) && (line[vbegin] == ' ')) vbegin++;
    value = line.substr(vbegin);
    return true;
}   //  split_header_line

bool parse_proxy_hostport (const string& proxyUrl, string& host, int& port)
{
    string s = proxyUrl;
    const size_t scheme = s.find("://");
    if (scheme != string::npos) s = s.substr(scheme + 3);
    const size_t slash = s.find('/');
    if (slash != string::npos) s = s.substr(0, slash);
    const size_t colon = s.rfind(':');
    if (colon != string::npos) {
        host = s.substr(0, colon);
        port = atoi(s.c_str() + colon + 1);
    }
    else {
        host = s;
        port = 8080;    //  conventional HTTP-proxy port
    }
    return (!host.empty() && (port > 0) && (port <= 65535));
}   //  parse_proxy_hostport

//  android.util.Base64.encodeToString(bytes, Base64.NO_WRAP), for Basic auth
jstring jni_base64 (JNIEnv* env, const string& data)
{
    jclass cls_b64 = env->FindClass("android/util/Base64");
    if (jni_pending(env) || !cls_b64) return nullptr;
    jmethodID mid = env->GetStaticMethodID(cls_b64, "encodeToString", "([BI)Ljava/lang/String;");
    if (jni_pending(env) || !mid) return nullptr;
    jbyteArray jbytes = env->NewByteArray((jsize)data.size());
    if (jni_pending(env) || !jbytes) return nullptr;
    env->SetByteArrayRegion(jbytes, 0, (jsize)data.size(), (const jbyte*)data.data());
    if (jni_pending(env)) return nullptr;
    jstring rv = (jstring)env->CallStaticObjectMethod(cls_b64, mid, jbytes, (jint)2 /*NO_WRAP*/);
    if (jni_pending(env)) return nullptr;
    return rv;
}   //  jni_base64

int jni_http_request (
        const string& uri,
        const char* method,
        const vector<string>& headerLines,
        const char* userPwd,
        const void* body,
        const size_t bodyLen,
        ByteArray** baResponse
)
{
    if (http_helper.offlineMode) return RET_UAPKI_OFFLINE_MODE;

    JniEnvGuard jni;
    JNIEnv* env = jni.env;
    if (!env) return RET_UAPKI_CONNECTION_ERROR;    //  JavaVM is not set

    LocalFrame frame(env, 96);
    if (!frame.pushed) return RET_UAPKI_CONNECTION_ERROR;

    //  url = new java.net.URL(uri)
    jclass cls_url = env->FindClass("java/net/URL");
    if (jni_pending(env) || !cls_url) return RET_UAPKI_CONNECTION_ERROR;
    jmethodID mid_url_init = env->GetMethodID(cls_url, "<init>", "(Ljava/lang/String;)V");
    if (jni_pending(env) || !mid_url_init) return RET_UAPKI_CONNECTION_ERROR;
    jstring juri = env->NewStringUTF(uri.c_str());
    if (jni_pending(env) || !juri) return RET_UAPKI_CONNECTION_ERROR;
    jobject url = env->NewObject(cls_url, mid_url_init, juri);
    if (jni_pending(env) || !url) return RET_UAPKI_CONNECTION_ERROR;

    //  conn = url.openConnection([proxy])
    jobject conn = nullptr;
    if (!http_helper.proxyUrl.empty()) {
        string proxy_host;
        int proxy_port = 0;
        if (!parse_proxy_hostport(http_helper.proxyUrl, proxy_host, proxy_port)) {
            return RET_UAPKI_CONNECTION_ERROR;
        }
        jclass cls_isa = env->FindClass("java/net/InetSocketAddress");
        if (jni_pending(env) || !cls_isa) return RET_UAPKI_CONNECTION_ERROR;
        jmethodID mid_isa_init = env->GetMethodID(cls_isa, "<init>", "(Ljava/lang/String;I)V");
        if (jni_pending(env) || !mid_isa_init) return RET_UAPKI_CONNECTION_ERROR;
        jstring jproxy_host = env->NewStringUTF(proxy_host.c_str());
        if (jni_pending(env) || !jproxy_host) return RET_UAPKI_CONNECTION_ERROR;
        jobject isa = env->NewObject(cls_isa, mid_isa_init, jproxy_host, (jint)proxy_port);
        if (jni_pending(env) || !isa) return RET_UAPKI_CONNECTION_ERROR;

        jclass cls_ptype = env->FindClass("java/net/Proxy$Type");
        if (jni_pending(env) || !cls_ptype) return RET_UAPKI_CONNECTION_ERROR;
        jfieldID fid_http = env->GetStaticFieldID(cls_ptype, "HTTP", "Ljava/net/Proxy$Type;");
        if (jni_pending(env) || !fid_http) return RET_UAPKI_CONNECTION_ERROR;
        jobject ptype = env->GetStaticObjectField(cls_ptype, fid_http);
        if (jni_pending(env) || !ptype) return RET_UAPKI_CONNECTION_ERROR;

        jclass cls_proxy = env->FindClass("java/net/Proxy");
        if (jni_pending(env) || !cls_proxy) return RET_UAPKI_CONNECTION_ERROR;
        jmethodID mid_proxy_init = env->GetMethodID(cls_proxy, "<init>", "(Ljava/net/Proxy$Type;Ljava/net/SocketAddress;)V");
        if (jni_pending(env) || !mid_proxy_init) return RET_UAPKI_CONNECTION_ERROR;
        jobject proxy = env->NewObject(cls_proxy, mid_proxy_init, ptype, isa);
        if (jni_pending(env) || !proxy) return RET_UAPKI_CONNECTION_ERROR;

        jmethodID mid_openconn = env->GetMethodID(cls_url, "openConnection", "(Ljava/net/Proxy;)Ljava/net/URLConnection;");
        if (jni_pending(env) || !mid_openconn) return RET_UAPKI_CONNECTION_ERROR;
        conn = env->CallObjectMethod(url, mid_openconn, proxy);
    }
    else {
        jmethodID mid_openconn = env->GetMethodID(cls_url, "openConnection", "()Ljava/net/URLConnection;");
        if (jni_pending(env) || !mid_openconn) return RET_UAPKI_CONNECTION_ERROR;
        conn = env->CallObjectMethod(url, mid_openconn);
    }
    if (jni_pending(env) || !conn) return RET_UAPKI_CONNECTION_ERROR;

    jclass cls_conn = env->FindClass("java/net/HttpURLConnection");
    if (jni_pending(env) || !cls_conn) return RET_UAPKI_CONNECTION_ERROR;
    jmethodID mid_setmethod = env->GetMethodID(cls_conn, "setRequestMethod", "(Ljava/lang/String;)V");
    jmethodID mid_setconntimeout = env->GetMethodID(cls_conn, "setConnectTimeout", "(I)V");
    jmethodID mid_setreadtimeout = env->GetMethodID(cls_conn, "setReadTimeout", "(I)V");
    jmethodID mid_setreqprop = env->GetMethodID(cls_conn, "setRequestProperty", "(Ljava/lang/String;Ljava/lang/String;)V");
    jmethodID mid_setdooutput = env->GetMethodID(cls_conn, "setDoOutput", "(Z)V");
    jmethodID mid_getoutputstream = env->GetMethodID(cls_conn, "getOutputStream", "()Ljava/io/OutputStream;");
    jmethodID mid_getresponsecode = env->GetMethodID(cls_conn, "getResponseCode", "()I");
    jmethodID mid_getinputstream = env->GetMethodID(cls_conn, "getInputStream", "()Ljava/io/InputStream;");
    jmethodID mid_geterrorstream = env->GetMethodID(cls_conn, "getErrorStream", "()Ljava/io/InputStream;");
    jmethodID mid_disconnect = env->GetMethodID(cls_conn, "disconnect", "()V");
    if (jni_pending(env) || !mid_setmethod || !mid_setconntimeout || !mid_setreadtimeout
            || !mid_setreqprop || !mid_setdooutput || !mid_getoutputstream || !mid_getresponsecode
            || !mid_getinputstream || !mid_geterrorstream || !mid_disconnect) {
        return RET_UAPKI_CONNECTION_ERROR;
    }

    jstring jmethod = env->NewStringUTF(method);
    if (jni_pending(env) || !jmethod) return RET_UAPKI_CONNECTION_ERROR;
    env->CallVoidMethod(conn, mid_setmethod, jmethod);
    if (jni_pending(env)) return RET_UAPKI_CONNECTION_ERROR;
    env->CallVoidMethod(conn, mid_setconntimeout, (jint)30000);
    if (jni_pending(env)) return RET_UAPKI_CONNECTION_ERROR;
    env->CallVoidMethod(conn, mid_setreadtimeout, (jint)60000);
    if (jni_pending(env)) return RET_UAPKI_CONNECTION_ERROR;

    //  set headers: raw "Name:value" lines, then Basic auth, then proxy credentials
    auto set_header = [&](const string& name, const string& value) -> bool {
        jstring jname = env->NewStringUTF(name.c_str());
        if (jni_pending(env) || !jname) return false;
        jstring jvalue = env->NewStringUTF(value.c_str());
        if (jni_pending(env) || !jvalue) return false;
        env->CallVoidMethod(conn, mid_setreqprop, jname, jvalue);
        if (jni_pending(env)) return false;
        env->DeleteLocalRef(jname);
        env->DeleteLocalRef(jvalue);
        return true;
    };

    for (const auto& line : headerLines) {
        string h_name, h_value;
        if (split_header_line(line, h_name, h_value)) {
            if (!set_header(h_name, h_value)) return RET_UAPKI_CONNECTION_ERROR;
        }
    }
    if (userPwd && (userPwd[0] != 0)) {
        jstring jb64 = jni_base64(env, string(userPwd));
        if (!jb64) return RET_UAPKI_CONNECTION_ERROR;
        const char* sz_b64 = env->GetStringUTFChars(jb64, nullptr);
        if (jni_pending(env) || !sz_b64) return RET_UAPKI_CONNECTION_ERROR;
        const bool is_ok = set_header("Authorization", string("Basic ") + sz_b64);
        env->ReleaseStringUTFChars(jb64, sz_b64);
        if (!is_ok) return RET_UAPKI_CONNECTION_ERROR;
    }
    if (!http_helper.proxyUrl.empty() && !http_helper.proxyCredentials.empty()) {
        jstring jb64 = jni_base64(env, http_helper.proxyCredentials);
        if (!jb64) return RET_UAPKI_CONNECTION_ERROR;
        const char* sz_b64 = env->GetStringUTFChars(jb64, nullptr);
        if (jni_pending(env) || !sz_b64) return RET_UAPKI_CONNECTION_ERROR;
        const bool is_ok = set_header("Proxy-Authorization", string("Basic ") + sz_b64);
        env->ReleaseStringUTFChars(jb64, sz_b64);
        if (!is_ok) return RET_UAPKI_CONNECTION_ERROR;
    }

    //  write request body
    if (body && (bodyLen > 0)) {
        env->CallVoidMethod(conn, mid_setdooutput, (jboolean)JNI_TRUE);
        if (jni_pending(env)) return RET_UAPKI_CONNECTION_ERROR;
        jobject ostream = env->CallObjectMethod(conn, mid_getoutputstream);
        if (jni_pending(env) || !ostream) return RET_UAPKI_CONNECTION_ERROR;
        jclass cls_ostream = env->FindClass("java/io/OutputStream");
        if (jni_pending(env) || !cls_ostream) return RET_UAPKI_CONNECTION_ERROR;
        jmethodID mid_os_write = env->GetMethodID(cls_ostream, "write", "([B)V");
        jmethodID mid_os_close = env->GetMethodID(cls_ostream, "close", "()V");
        if (jni_pending(env) || !mid_os_write || !mid_os_close) return RET_UAPKI_CONNECTION_ERROR;
        jbyteArray jbody = env->NewByteArray((jsize)bodyLen);
        if (jni_pending(env) || !jbody) return RET_UAPKI_CONNECTION_ERROR;
        env->SetByteArrayRegion(jbody, 0, (jsize)bodyLen, (const jbyte*)body);
        if (jni_pending(env)) return RET_UAPKI_CONNECTION_ERROR;
        env->CallVoidMethod(ostream, mid_os_write, jbody);
        if (jni_pending(env)) return RET_UAPKI_CONNECTION_ERROR;
        env->CallVoidMethod(ostream, mid_os_close);
        if (jni_pending(env)) return RET_UAPKI_CONNECTION_ERROR;
    }

    //  perform the request
    const jint http_status = env->CallIntMethod(conn, mid_getresponsecode);
    if (jni_pending(env)) return RET_UAPKI_CONNECTION_ERROR;

    //  read response body (error stream for HTTP >= 400, may be absent)
    jobject istream = env->CallObjectMethod(conn,
            (http_status >= 400) ? mid_geterrorstream : mid_getinputstream);
    if (jni_pending(env)) istream = nullptr;

    ByteArray* ba_resp = ba_alloc();
    if (!ba_resp) return RET_UAPKI_GENERAL_ERROR;

    bool read_failed = false;
    if (istream) {
        jclass cls_istream = env->FindClass("java/io/InputStream");
        jmethodID mid_is_read = (cls_istream) ? env->GetMethodID(cls_istream, "read", "([B)I") : nullptr;
        jmethodID mid_is_close = (cls_istream) ? env->GetMethodID(cls_istream, "close", "()V") : nullptr;
        jbyteArray jbuf = (!jni_pending(env) && mid_is_read && mid_is_close)
                ? env->NewByteArray(8192) : nullptr;
        if (jni_pending(env) || !jbuf) {
            read_failed = true;
        }
        else {
            for (;;) {
                const jint n = env->CallIntMethod(istream, mid_is_read, jbuf);
                if (jni_pending(env)) {
                    read_failed = true;     //  response truncated
                    break;
                }
                if (n <= 0) break;
                const size_t old_len = ba_get_len(ba_resp);
                if (ba_change_len(ba_resp, old_len + (size_t)n) != RET_OK) {
                    read_failed = true;
                    break;
                }
                env->GetByteArrayRegion(jbuf, 0, n, (jbyte*)(ba_get_buf(ba_resp) + old_len));
                if (jni_pending(env)) {
                    read_failed = true;
                    break;
                }
            }
            env->CallVoidMethod(istream, mid_is_close);
            jni_pending(env);
        }
    }

    env->CallVoidMethod(conn, mid_disconnect);
    jni_pending(env);

    if (read_failed) {
        ba_free(ba_resp);
        return RET_UAPKI_CONNECTION_ERROR;
    }

    *baResponse = ba_resp;
    return (http_status == 200) ? RET_OK : RET_UAPKI_HTTP_STATUS_NOT_OK;
}   //  jni_http_request

}   //  end anonymous namespace


int HttpHelper::init (
        const bool offlineMode,
        const char* proxyUrl,
        const char* proxyCredentials
)
{
    http_helper.offlineMode = offlineMode;
    if (!http_helper.isInitialized) {
        http_helper.isInitialized = true;
        if (proxyUrl) {
            http_helper.proxyUrl = string(proxyUrl);
            if (proxyCredentials && !http_helper.proxyUrl.empty()) {
                http_helper.proxyCredentials = string(proxyCredentials);
            }
        }
    }
    return RET_OK;
}

void HttpHelper::deinit (void)
{
    if (http_helper.isInitialized) {
        http_helper.reset();
    }
}

int HttpHelper::get (
        const string& uri,
        ByteArray** baResponse
)
{
    DEBUG_OUTCON(printf("HttpHelper::get(uri='%s'), HttpURLConnection\n", uri.c_str()));
    return jni_http_request(uri, "GET", vector<string>(), nullptr, nullptr, 0, baResponse);
}

int HttpHelper::post (
        const string& uri,
        const char* contentType,
        const ByteArray* baRequest,
        ByteArray** baResponse
)
{
    DEBUG_OUTCON(
        printf("HttpHelper::post(uri='%s', contentType='%s'), Request:\n", uri.c_str(), contentType);
        ba_print(stdout, baRequest);
    )
    vector<string> header_lines;
    if (contentType) header_lines.push_back(string(contentType));
    return jni_http_request(uri, "POST", header_lines, nullptr,
            ba_get_buf_const(baRequest), ba_get_len(baRequest), baResponse);
}

int HttpHelper::post (
        const string& uri,
        const char* contentType,
        const char* userPwd,
        const string& authorizationBearer,
        const string& request,
        ByteArray** baResponse
)
{
    DEBUG_OUTCON(
        printf("HttpHelper::post(uri='%s', contentType='%s', userPwd='%s', authorizationBearer='%s', request='%s')\n",
                uri.c_str(), contentType, userPwd, authorizationBearer.c_str(), request.c_str());
    )
    vector<string> header_lines;
    if (contentType) header_lines.push_back(string(contentType));
    if (!authorizationBearer.empty()) header_lines.push_back(authorizationBearer);
    return jni_http_request(uri, "POST", header_lines, userPwd,
            request.c_str(), request.length(), baResponse);
}

#else  //  curl-based build

static size_t cb_curlwrite (
        void* dataIn,
        size_t size,
        size_t nmemb,
        void* userp
)
{
    size_t realsize = size * nmemb;
    ByteArray* data = (ByteArray*)userp;
    size_t old_len = ba_get_len(data);
    uint8_t* buf;

    ba_change_len(data, old_len + realsize);
    buf = (uint8_t*)ba_get_buf(data);
    memcpy(&(buf[old_len]), dataIn, realsize);

    return realsize;
}   //  cb_curlwrite

static bool curl_set_url_and_proxy (
        CURL* curl,
        const string& uri
)
{
    CURLcode rv_ccode = curl_easy_setopt(curl, CURLOPT_URL, uri.c_str());
    if (rv_ccode != CURLE_OK) return false;

    if (!http_helper.proxyUrl.empty()) {
        rv_ccode = curl_easy_setopt(curl, CURLOPT_PROXY, http_helper.proxyUrl.c_str());
        if (rv_ccode != CURLE_OK) return false;

        curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_ANY);

        if (!http_helper.proxyCredentials.empty()) {
            rv_ccode = curl_easy_setopt(curl, CURLOPT_PROXYUSERPWD, http_helper.proxyCredentials.c_str());
            if (rv_ccode != CURLE_OK) return false;
        }
    }

    return true;
}   //  curl_set_url_and_proxy


int HttpHelper::init (
        const bool offlineMode,
        const char* proxyUrl,
        const char* proxyCredentials
)
{
    int ret = RET_OK;
    http_helper.offlineMode = offlineMode;
    if (!http_helper.isInitialized) {
        const CURLcode curl_code = curl_global_init(CURL_GLOBAL_ALL);
        http_helper.isInitialized = (curl_code == CURLE_OK);
        if (proxyUrl && http_helper.isInitialized) {
            http_helper.proxyUrl = string(proxyUrl);
            if (proxyCredentials && !http_helper.proxyUrl.empty()) {
                http_helper.proxyCredentials = string(proxyCredentials);
            }
        }
        ret = (http_helper.isInitialized) ? RET_OK : RET_UAPKI_GENERAL_ERROR;
    }
    return ret;
}

void HttpHelper::deinit (void)
{
    if (http_helper.isInitialized) {
        http_helper.reset();
        curl_global_cleanup();
    }
}

#endif  //  UAPKI_NO_HTTP / __ANDROID__ / curl

bool HttpHelper::isOfflineMode (void)
{
    return http_helper.offlineMode;
}

const string& HttpHelper::getProxyUrl (void)
{
    return http_helper.proxyUrl;
}

#if !defined(UAPKI_NO_HTTP) && !defined(__ANDROID__)

int HttpHelper::get (
        const string& uri,
        ByteArray** baResponse
)
{
    DEBUG_OUTCON(printf("HttpHelper::get(uri='%s')\n", uri.c_str()));
    CURL* curl;
    CURLcode curl_code;
    int ret;

    if (http_helper.offlineMode) {
        return RET_UAPKI_OFFLINE_MODE;
    }

    // get a curl handle 
    if ((curl = curl_easy_init()) == NULL) {
        return RET_UAPKI_CONNECTION_ERROR;
    }

    // First set the URL that is about to receive our POST. This URL can
    // just as well be a https:// URL if that is what should receive the data.
    if (!curl_set_url_and_proxy(curl, uri)) {
        return RET_UAPKI_CONNECTION_ERROR;
    }

    // send all data to this function
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb_curlwrite);

    *baResponse = ba_alloc();
    // we pass our 'chunk' struct to the callback function
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, *baResponse);

    // Perform the request, res will get the return code
    curl_code = curl_easy_perform(curl);
    if (curl_code == CURLE_OK) {
        long http_code = 0;
        curl_code = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        ret = (http_code == 200) ? RET_OK : RET_UAPKI_HTTP_STATUS_NOT_OK;
    }
    else {
        ret = RET_UAPKI_CONNECTION_ERROR;
    }

    // always cleanup
    curl_easy_cleanup(curl);

    return ret;
}

int HttpHelper::post (
        const string& uri,
        const char* contentType,
        const ByteArray* baRequest,
        ByteArray** baResponse
)
{
    DEBUG_OUTCON(
        printf("HttpHelper::post(uri='%s', contentType='%s'), Request:\n", uri.c_str(), contentType);
        ba_print(stdout, baRequest);
    )
    CURL* curl;
    CURLcode curl_code;
    int ret;

    if (http_helper.offlineMode) {
        return RET_UAPKI_OFFLINE_MODE;
    }

    // get a curl handle 
    if ((curl = curl_easy_init()) == NULL) {
        return RET_UAPKI_GENERAL_ERROR;
    }

    struct curl_slist* chunk = NULL;

    // Add a custom header 
    chunk = curl_slist_append(chunk, contentType);

    // set our custom set of headers
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

    // First set the URL that is about to receive our POST. This URL can
    // just as well be a https:// URL if that is what should receive the data.
    if (!curl_set_url_and_proxy(curl, uri)) {
        return RET_UAPKI_CONNECTION_ERROR;
    }
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    // Now specify the POST data
    // binary data
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, ba_get_buf_const(baRequest));
    // size of the POST data
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)ba_get_len(baRequest));

    // send all data to this function
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb_curlwrite);

    *baResponse = ba_alloc();
    // we pass our 'chunk' struct to the callback function
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, *baResponse);

    // Perform the request, res will get the return code
    curl_code = curl_easy_perform(curl);
    if (curl_code == CURLE_OK) {
        long http_code = 0;
        curl_code = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        ret = (http_code == 200) ? RET_OK : RET_UAPKI_HTTP_STATUS_NOT_OK;
    }
    else {
        ret = RET_UAPKI_CONNECTION_ERROR;
    }

    // always cleanup
    curl_easy_cleanup(curl);
    curl_slist_free_all(chunk);

    return ret;
}

int HttpHelper::post (
        const string& uri,
        const char* contentType,
        const char* userPwd,
        const string& authorizationBearer,
        const string& request,
        ByteArray** baResponse
)
{
    DEBUG_OUTCON(
        printf("HttpHelper::post(uri='%s', contentType='%s', userPwd='%s', authorizationBearer='%s', request='%s')\n",
                uri.c_str(), contentType, userPwd, authorizationBearer.c_str(), request.c_str());
    )
    CURL* curl;
    CURLcode curl_code;
    int ret;

    if (http_helper.offlineMode) {
        return RET_UAPKI_OFFLINE_MODE;
    }

    // get a curl handle 
    if ((curl = curl_easy_init()) == NULL) {
        return RET_UAPKI_GENERAL_ERROR;
    }

    if (userPwd) {
        curl_easy_setopt(curl, CURLOPT_USERPWD, userPwd);
    }

#ifdef HTTP_HELPER_DISABLE_VERIFYSSL
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
#endif

    struct curl_slist* chunk = NULL;

    // Add a custom header 
    chunk = curl_slist_append(chunk, contentType);
    if (!authorizationBearer.empty()) {
        chunk = curl_slist_append(chunk, authorizationBearer.c_str());
    }

    // set our custom set of headers
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

    // First set the URL that is about to receive our POST. This URL can
    // just as well be a https:// URL if that is what should receive the
    // data.
    if (!curl_set_url_and_proxy(curl, uri)) {
        return RET_UAPKI_CONNECTION_ERROR;
    }
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    // Now specify the POST data
    // binary data
    if (!request.empty()) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.c_str());
    }
    // size of the POST data
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)request.length());

    // send all data to this function
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb_curlwrite);

    *baResponse = ba_alloc();
    // we pass our 'chunk' struct to the callback function
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, *baResponse);

    // Perform the request, res will get the return code
    curl_code = curl_easy_perform(curl);
    if (curl_code == CURLE_OK) {
        long http_code = 0;
        curl_code = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        ret = (http_code == 200) ? RET_OK : RET_UAPKI_HTTP_STATUS_NOT_OK;
    }
    else {
        ret = RET_UAPKI_CONNECTION_ERROR;
    }

    // always cleanup
    curl_easy_cleanup(curl);

    return ret;
}

#endif  //  !UAPKI_NO_HTTP && !__ANDROID__

mutex& HttpHelper::lockUri (
        const string& uri
)
{
    lock_guard<mutex> lock(http_helper.mtx);

    return http_helper.mtxByUrl[uri];
}

vector<string> HttpHelper::randomURIs (
        const vector<string>& uris
)
{
    if (uris.size() < 2) return uris;

    UapkiNS::SmartBA sba_randoms;
    if (!sba_randoms.set(ba_alloc_by_len(uris.size() - 1))) return uris;

    if (drbg_random(sba_randoms.get()) != RET_OK) return uris;

    vector<string> rv_uris, src = uris;
    const uint8_t* buf = sba_randoms.buf();
    for (size_t i = 0; i < uris.size() - 1; i++) {
        const size_t rnd = buf[i] % src.size();
        rv_uris.push_back(src[rnd]);
        src.erase(src.begin() + rnd);
    }
    rv_uris.push_back(src[0]);
    return rv_uris;
}
