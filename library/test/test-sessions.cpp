/*
 * Copyright (c) 2026, The UAPKI Project Authors.
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

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include "parson-helper.h"
#include "uapki-session-loader.h"

#ifdef _WIN32
 #include <direct.h>
 #include <windows.h>
 #define MAKE_DIR(path) _mkdir(path)
 #define REMOVE_DIR(path) _rmdir(path)
#else
 #include <dirent.h>
 #include <sys/stat.h>
 #include <unistd.h>
 #define MAKE_DIR(path) mkdir(path, 0700)
 #define REMOVE_DIR(path) rmdir(path)
#endif
#if defined(__GLIBC__) && ((__GLIBC__ > 2) || (__GLIBC_MINOR__ >= 33))
 #include <malloc.h>
 #define HAVE_MALLINFO2 1
#endif


using namespace std;


static const char* DATA_TBS_B64 = "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==";
static const char* OID_RSA_MECHANISM = "1.2.840.113549.1.1.1";
static const char* OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11";
static const int ERR_CONNECTION_ERROR = 0x1002;
static const int ERR_NOT_INITIALIZED = 0x1009;
static const int ERR_KEY_NOT_SELECTED = 0x100C;
static const int ERR_NOT_ALLOWED = 0x1017;
static const int ERR_OFFLINE_MODE = 0x1018;
static const int ERR_STORAGE_NOT_OPEN = 0x1019;
static const int ERR_INVALID_SESSION = 0x101D;
static const int ERR_INVALID_SHARED_MEMORY = 0x101E;
static const int ERR_CERT_NOT_FOUND = 0x1041;
static const int ERR_CRL_NOT_FOUND = 0x1053;
static const int ERR_TSP_NOT_RESPONDING = 0x1071;
static const char* TSP_URL_UNREACHABLE = "http://127.0.0.1:1/";


struct Options {
    string      libName;
    string      storage;
    string      password;
    string      signerCertB64;
    string      providerDir;
    string      workDir;
    unsigned    countSessions;
    unsigned    countSigns;
    unsigned    rsaBits;
    unsigned    countCrls;
    unsigned    countCrlEntries;
    bool        runBenchmark;
    bool        runTests;

    Options (void)
        : storage("test-diia.p12")
        , password("testpassword")
        , workDir("test-sessions-work")
        , countSessions(0)
        , countSigns(20)
        , rsaBits(2048)
        , countCrls(200)
        , countCrlEntries(2000)
        , runBenchmark(true)
        , runTests(true)
    {}
};  //  end struct Options


struct Response {
    int         errorCode;
    string      error;
    ParsonHelper
                json;
    JSON_Object*
                result;

    Response (void)
        : errorCode(-1)
        , result(nullptr)
    {}

    bool parse (const char* sJson) {
        errorCode = -1;
        error.clear();
        result = nullptr;
        json.cleanup();
        if (!sJson || !json.parse(sJson)) return false;
        errorCode = json.getInt("errorCode");
        error = ParsonHelper::jsonObjectGetString(json.rootObject(), "error");
        result = json.getObject("result");
        return true;
    }
    bool ok (void) const {
        return (errorCode == 0);
    }
    string resultString (const char* key) const {
        return ParsonHelper::jsonObjectGetString(result, key);
    }
    string signatureBytes (void) const {
        JSON_Array* ja_signatures = json_object_get_array(result, "signatures");
        JSON_Object* jo_signature = json_array_get_object(ja_signatures, 0);
        return ParsonHelper::jsonObjectGetString(jo_signature, "bytes");
    }
};  //  end struct Response


//  Sends requests either through the legacy process() (no session) or through a session
//  Sends requests through the legacy process() (no session), a session (optionally with a shared memory)
//  or directly to a shared memory
class Api {
    UapkiSessionLoader&
                m_Loader;
    UAPKI_SESSION*
                m_Session;
    UAPKI_SESSION_SHARED_MEMORY*
                m_Memory;
    bool        m_UseSession;
    bool        m_UseMemory;

public:
    explicit Api (UapkiSessionLoader& loader)
        : m_Loader(loader), m_Session(nullptr), m_Memory(nullptr), m_UseSession(false), m_UseMemory(false)
    {}
    Api (UapkiSessionLoader& loader, UAPKI_SESSION* session, UAPKI_SESSION_SHARED_MEMORY* memory = nullptr)
        : m_Loader(loader), m_Session(session), m_Memory(memory), m_UseSession(true), m_UseMemory(false)
    {}
    Api (UapkiSessionLoader& loader, UAPKI_SESSION_SHARED_MEMORY* memory)
        : m_Loader(loader), m_Session(nullptr), m_Memory(memory), m_UseSession(false), m_UseMemory(true)
    {}

    bool call (const string& request, Response& response) {
        char* s_result = (m_UseMemory) ? m_Loader.sharedMemoryProcess(m_Memory, request.c_str())
            : (m_UseSession) ? m_Loader.sessionProcess(m_Session, m_Memory, request.c_str())
            : m_Loader.process(request.c_str());
        const bool ok = response.parse(s_result);
        m_Loader.jsonFree(s_result);
        return ok;
    }
    bool call (const string& request) {
        Response response;
        return call(request, response) && response.ok();
    }
    bool callSessionHandle (UAPKI_SESSION* session, const string& request, Response& response) {
        char* s_result = m_Loader.sessionProcess(session, nullptr, request.c_str());
        const bool ok = response.parse(s_result);
        m_Loader.jsonFree(s_result);
        return ok;
    }

};  //  end class Api


//  The self-test of the crypto library is needed once per process: it runs in the first session
//  (see run_self_test), every later INIT passes "skipSelfTest": true
static bool self_test_done = false;

//  Safety limit for workers that call until a freed session/shared memory rejects them
static const int REJECT_TIMEOUT_S = 60;

static void set_skip_self_test (JSON_Object* joParams)
{
    if (self_test_done) {
        json_object_set_boolean(joParams, "skipSelfTest", true);
    }
}

static string request_init (const bool offline, const char* tspUrl = nullptr)
{
    ParsonHelper json;
    json.create();
    json.setString("method", "INIT");
    JSON_Object* jo_params = json.setObject("parameters");
    json_object_set_value(jo_params, "cmProviders", json_value_init_object());
    JSON_Object* jo_providers = json_object_get_object(jo_params, "cmProviders");
    json_object_set_string(jo_providers, "dir", "");
    json_object_set_value(jo_providers, "allowedProviders", json_value_init_array());
    JSON_Array* ja_allowed = json_object_get_array(jo_providers, "allowedProviders");
    json_array_append_value(ja_allowed, json_value_init_object());
    json_object_set_string(json_array_get_object(ja_allowed, 0), "lib", "cm-pkcs12");
    json_object_dotset_string(jo_params, "certCache.path", "");
    json_object_dotset_string(jo_params, "crlCache.path", "");
    json_object_set_boolean(jo_params, "offline", offline);
    set_skip_self_test(jo_params);
    if (tspUrl) {
        json_object_dotset_string(jo_params, "tsp.url", tspUrl);
        json_object_dotset_boolean(jo_params, "tsp.forced", true);
    }
    string rv;
    json.serialize(rv);
    return rv;
}

//  INIT with certificate/CRL cache directories and no providers: what a shared memory (or a session
//  that keeps its own caches) is configured with
static string request_init_caches (const string& certDir, const string& crlDir, const bool offline = true)
{
    ParsonHelper json;
    json.create();
    json.setString("method", "INIT");
    JSON_Object* jo_params = json.setObject("parameters");
    json_object_dotset_string(jo_params, "certCache.path", certDir.c_str());
    json_object_dotset_string(jo_params, "crlCache.path", crlDir.c_str());
    json_object_set_boolean(jo_params, "offline", offline);
    set_skip_self_test(jo_params);
    string rv;
    json.serialize(rv);
    return rv;
}

static string request_get_cert (const string& certIdB64)
{
    return string("{\"method\":\"GET_CERT\",\"parameters\":{\"certId\":\"") + certIdB64 + "\"}}";
}

static string request_list_crls (void)
{
    return "{\"method\":\"LIST_CRLS\",\"parameters\":{\"pageSize\":1}}";
}

static string request_crl_info (const string& crlIdB64)
{
    return string("{\"method\":\"CRL_INFO\",\"parameters\":{\"crlId\":\"") + crlIdB64 + "\",\"showRevokedCerts\":false}}";
}

static string request_add_crl (const string& crlB64)
{
    return string("{\"method\":\"ADD_CRL\",\"parameters\":{\"bytes\":\"") + crlB64 + "\"}}";
}

static string request_remove_cert (const string& certIdB64, const bool permanent)
{
    return string("{\"method\":\"REMOVE_CERT\",\"parameters\":{\"certId\":\"") + certIdB64 + "\",\"permanent\":" + (permanent ? "true" : "false") + "}}";
}

static string request_add_cert_permanent (const string& certB64)
{
    return string("{\"method\":\"ADD_CERT\",\"parameters\":{\"certificates\":[\"") + certB64 + "\"],\"permanent\":true}}";
}

static string request_cert_status_by_ocsp (const string& issuerCertIdB64)
{
    return string("{\"method\":\"CERT_STATUS_BY_OCSP\",\"parameters\":{\"url\":\"") + TSP_URL_UNREACHABLE
        + "\",\"issuerCertId\":\"" + issuerCertIdB64 + "\",\"serialNumber\":\"01\"}}";
}

static string request_remove_crl (const string& crlIdB64)
{
    return string("{\"method\":\"REMOVE_CRL\",\"parameters\":{\"crlId\":\"") + crlIdB64 + "\"}}";
}

static string request_init_dir (const bool offline, const char* dir)
{
    string rv = request_init(offline);
    const string old_dir = "\"dir\":\"\"";
    rv.replace(rv.find(old_dir), old_dir.size(), string("\"dir\":\"") + dir + "\"");
    return rv;
}

static string request_init_unknown_provider (void)
{
    return "{\"method\":\"INIT\",\"parameters\":{\"cmProviders\":{\"dir\":\"\",\"allowedProviders\":[{\"lib\":\"cm-does-not-exist\"},{\"lib\":\"cm-pkcs12\"}]},"
        "\"certCache\":{\"path\":\"\"},\"crlCache\":{\"path\":\"\"},\"offline\":true"
        + string(self_test_done ? ",\"skipSelfTest\":true" : "") + "}}";
}

static string request_open (const string& storage, const string& password, const char* mode)
{
    ParsonHelper json;
    json.create();
    json.setString("method", "OPEN");
    JSON_Object* jo_params = json.setObject("parameters");
    json_object_set_string(jo_params, "provider", "PKCS12");
    json_object_set_string(jo_params, "storage", storage.c_str());
    json_object_set_string(jo_params, "password", password.c_str());
    json_object_set_string(jo_params, "mode", mode);
    string rv;
    json.serialize(rv);
    return rv;
}

static string request_method (const char* method)
{
    return string("{\"method\":\"") + method + "\"}";
}

static string request_select_key (const string& keyId)
{
    return string("{\"method\":\"SELECT_KEY\",\"parameters\":{\"id\":\"") + keyId + "\"}}";
}

static string request_create_key_rsa (const unsigned bits)
{
    return string("{\"method\":\"CREATE_KEY\",\"parameters\":{\"mechanismId\":\"") + OID_RSA_MECHANISM
        + "\",\"parameterId\":\"" + to_string(bits) + "\",\"label\":\"test-sessions\"}}";
}

static string request_sign_cades (void)
{
    return string("{\"method\":\"SIGN\",\"parameters\":{"
        "\"signParams\":{\"signatureFormat\":\"CAdES-BES\",\"detachedData\":false,\"includeCert\":true,\"includeTime\":true},"
        "\"options\":{\"ignoreCertStatus\":true},"
        "\"dataTbs\":[{\"id\":\"doc-0\",\"bytes\":\"") + DATA_TBS_B64 + "\"}]}}";
}

static string request_sign_cades_t (void)
{
    return string("{\"method\":\"SIGN\",\"parameters\":{"
        "\"signParams\":{\"signatureFormat\":\"CAdES-T\",\"detachedData\":false,\"includeCert\":true},"
        "\"options\":{\"ignoreCertStatus\":true},"
        "\"dataTbs\":[{\"id\":\"doc-0\",\"bytes\":\"") + DATA_TBS_B64 + "\"}]}}";
}

static string request_sign_raw_rsa (void)
{
    return string("{\"method\":\"SIGN\",\"parameters\":{"
        "\"signParams\":{\"signatureFormat\":\"RAW\",\"signAlgo\":\"") + OID_SHA256_WITH_RSA + "\"},"
        "\"dataTbs\":[{\"id\":\"doc-0\",\"bytes\":\"" + DATA_TBS_B64 + "\"}]}}";
}

static string base64_encode (const vector<uint8_t>& data)
{
    static const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    string rv;
    for (size_t i = 0; i < data.size(); i += 3) {
        const uint32_t octets = ((uint32_t)data[i] << 16)
            | ((i + 1 < data.size()) ? ((uint32_t)data[i + 1] << 8) : 0)
            | ((i + 2 < data.size()) ? (uint32_t)data[i + 2] : 0);
        rv += alphabet[(octets >> 18) & 0x3F];
        rv += alphabet[(octets >> 12) & 0x3F];
        rv += (i + 1 < data.size()) ? alphabet[(octets >> 6) & 0x3F] : '=';
        rv += (i + 2 < data.size()) ? alphabet[octets & 0x3F] : '=';
    }
    return rv;
}

//  Minimal DER writer, enough to build a CertificateList the library accepts
struct Der {
    typedef vector<uint8_t> Bytes;

    static Bytes tlv (const uint8_t tag, const Bytes& value) {
        Bytes rv;
        rv.push_back(tag);
        const size_t len = value.size();
        if (len < 0x80) {
            rv.push_back((uint8_t)len);
        }
        else {
            Bytes len_bytes;
            for (size_t v = len; v > 0; v >>= 8) len_bytes.insert(len_bytes.begin(), (uint8_t)(v & 0xFF));
            rv.push_back((uint8_t)(0x80 | len_bytes.size()));
            rv.insert(rv.end(), len_bytes.begin(), len_bytes.end());
        }
        rv.insert(rv.end(), value.begin(), value.end());
        return rv;
    }
    static Bytes concat (const Bytes& a, const Bytes& b) {
        Bytes rv = a;
        rv.insert(rv.end(), b.begin(), b.end());
        return rv;
    }
    static Bytes integer (uint64_t value) {
        Bytes content;
        do {
            content.insert(content.begin(), (uint8_t)(value & 0xFF));
            value >>= 8;
        } while (value > 0);
        if (content[0] & 0x80) content.insert(content.begin(), 0);
        return tlv(0x02, content);
    }
    static Bytes oid (const string& dotted) {
        vector<uint32_t> arcs;
        size_t pos = 0;
        while (pos <= dotted.size()) {
            const size_t next = dotted.find('.', pos);
            arcs.push_back((uint32_t)strtoul(dotted.substr(pos, next - pos).c_str(), nullptr, 10));
            if (next == string::npos) break;
            pos = next + 1;
        }
        Bytes content;
        content.push_back((uint8_t)(arcs[0] * 40 + arcs[1]));
        for (size_t i = 2; i < arcs.size(); i++) {
            Bytes chunk;
            uint32_t v = arcs[i];
            do {
                chunk.insert(chunk.begin(), (uint8_t)(v & 0x7F));
                v >>= 7;
            } while (v > 0);
            for (size_t k = 0; k + 1 < chunk.size(); k++) chunk[k] |= 0x80;
            content.insert(content.end(), chunk.begin(), chunk.end());
        }
        return tlv(0x06, content);
    }
    static Bytes utf8String (const string& text) {
        return tlv(0x0C, Bytes(text.begin(), text.end()));
    }
    static Bytes utcTime (const string& text) {
        return tlv(0x17, Bytes(text.begin(), text.end()));
    }
    static Bytes null (void) {
        return tlv(0x05, Bytes());
    }
    static Bytes octetString (const Bytes& value) {
        return tlv(0x04, value);
    }
    static Bytes bitString (const Bytes& value) {
        return tlv(0x03, concat(Bytes(1, 0), value));
    }
    static Bytes sequence (const Bytes& value) {
        return tlv(0x30, value);
    }
    static Bytes set (const Bytes& value) {
        return tlv(0x31, value);
    }
    static Bytes explicit0 (const Bytes& value) {
        return tlv(0xA0, value);
    }
};  //  end struct Der

//  A CRL v2 with the extensions the library requires (AuthorityKeyId, CRLNumber) and a dummy signature:
//  it parses and is cached exactly like a real one, which is all the memory measurement needs
static Der::Bytes synthetic_crl (const unsigned index, const unsigned countRevoked)
{
    const Der::Bytes sign_algo = Der::sequence(Der::concat(Der::oid(OID_SHA256_WITH_RSA), Der::null()));
    const Der::Bytes issuer = Der::sequence(Der::set(Der::sequence(Der::concat(Der::oid("2.5.4.3"), Der::utf8String("Synthetic CA " + to_string(index))))));

    Der::Bytes revoked;
    for (unsigned i = 0; i < countRevoked; i++) {
        const Der::Bytes entry = Der::concat(Der::integer(0x100000ULL * (index + 1) + i), Der::utcTime("260101000000Z"));
        const Der::Bytes seq = Der::sequence(entry);
        revoked.insert(revoked.end(), seq.begin(), seq.end());
    }

    Der::Bytes key_id(20, 0);
    for (size_t i = 0; i < key_id.size(); i++) key_id[i] = (uint8_t)(index >> (8 * (i % 4)));
    const Der::Bytes ext_akid = Der::sequence(Der::concat(Der::oid("2.5.29.35"), Der::octetString(Der::sequence(Der::tlv(0x80, key_id)))));
    const Der::Bytes ext_crlnumber = Der::sequence(Der::concat(Der::oid("2.5.29.20"), Der::octetString(Der::integer(index + 1))));
    const Der::Bytes extensions = Der::explicit0(Der::sequence(Der::concat(ext_akid, ext_crlnumber)));

    Der::Bytes tbs;
    for (const Der::Bytes& part : { Der::integer(1), sign_algo, issuer, Der::utcTime("260101000000Z"), Der::utcTime("351231235959Z"), Der::sequence(revoked), extensions }) {
        tbs.insert(tbs.end(), part.begin(), part.end());
    }
    return Der::sequence(Der::concat(Der::concat(Der::sequence(tbs), sign_algo), Der::bitString(Der::Bytes(256, 0x5A))));
}

static bool write_file (const string& fileName, const vector<uint8_t>& data)
{
    FILE* f = fopen(fileName.c_str(), "wb");
    if (!f) return false;
    const bool ok = (fwrite(data.data(), 1, data.size(), f) == data.size());
    fclose(f);
    return ok;
}

//  Bytes allocated on the heap by this process (0 when the platform gives no cheap answer)
static size_t heap_in_use (void)
{
#ifdef HAVE_MALLINFO2
    const struct mallinfo2 mi = mallinfo2();
    return mi.uordblks + mi.hblkhd;
#else
    return 0;
#endif
}

static double to_mib (const size_t bytes)
{
    return (double)bytes / (1024.0 * 1024.0);
}

static string read_file_base64 (const string& fileName)
{
    static const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    string rv;
    FILE* f = fopen(fileName.c_str(), "rb");
    if (!f) return rv;

    vector<uint8_t> data;
    uint8_t buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        data.insert(data.end(), buf, buf + n);
    }
    fclose(f);

    for (size_t i = 0; i < data.size(); i += 3) {
        const uint32_t octets = ((uint32_t)data[i] << 16)
            | ((i + 1 < data.size()) ? ((uint32_t)data[i + 1] << 8) : 0)
            | ((i + 2 < data.size()) ? (uint32_t)data[i + 2] : 0);
        rv += alphabet[(octets >> 18) & 0x3F];
        rv += alphabet[(octets >> 12) & 0x3F];
        rv += (i + 1 < data.size()) ? alphabet[(octets >> 6) & 0x3F] : '=';
        rv += (i + 2 < data.size()) ? alphabet[octets & 0x3F] : '=';
    }
    return rv;
}

static string request_add_cert (const string& certB64)
{
    return string("{\"method\":\"ADD_CERT\",\"parameters\":{\"certificates\":[\"") + certB64 + "\"]}}";
}

static bool copy_file (const string& from, const string& to)
{
    FILE* f_in = fopen(from.c_str(), "rb");
    if (!f_in) return false;
    FILE* f_out = fopen(to.c_str(), "wb");
    if (!f_out) {
        fclose(f_in);
        return false;
    }
    char buf[4096];
    size_t n;
    bool ok = true;
    while ((n = fread(buf, 1, sizeof(buf), f_in)) > 0) {
        if (fwrite(buf, 1, n, f_out) != n) {
            ok = false;
            break;
        }
    }
    fclose(f_out);
    fclose(f_in);
    return ok;
}

static double elapsed_ms (const chrono::steady_clock::time_point& start)
{
    return chrono::duration<double, milli>(chrono::steady_clock::now() - start).count();
}


class Checker {
    mutex       m_Mutex;
    vector<string>
                m_Failures;

public:
    void fail (const string& message) {
        lock_guard<mutex> lock(m_Mutex);
        m_Failures.push_back(message);
    }
    bool check (const bool condition, const string& message) {
        if (!condition) fail(message);
        return condition;
    }
    bool passed (void) {
        lock_guard<mutex> lock(m_Mutex);
        return m_Failures.empty();
    }
    void report (const char* testName) {
        lock_guard<mutex> lock(m_Mutex);
        printf("[%s] %s\n", m_Failures.empty() ? "PASS" : "FAIL", testName);
        for (const auto& it : m_Failures) {
            printf("    %s\n", it.c_str());
        }
    }
};  //  end class Checker


static bool call_ok (
        Api& api,
        const string& request,
        Response& response,
        Checker& checker,
        const string& what
)
{
    const bool ok = api.call(request, response) && response.ok();
    if (!ok) checker.fail(what + ": " + response.error);
    return ok;
}

//  First session: INIT without skipSelfTest runs the self-test of the crypto library
//  (an error SELF_TEST_FAIL is returned if it fails); later sessions skip it
static bool run_self_test (UapkiSessionLoader& loader)
{
    Checker checker;
    Response resp;
    UAPKI_SESSION* session = loader.sessionCreate();
    if (checker.check(session != nullptr, "uapki_session_create")) {
        Api api(loader, session);
        const chrono::steady_clock::time_point dt_start = chrono::steady_clock::now();
        if (call_ok(api, request_init(true), resp, checker, "INIT with self-test")) {
            self_test_done = true;
        }
        const int elapsed = (int)elapsed_ms(dt_start);
        api.call(request_method("DEINIT"));
        loader.sessionFree(session);
        checker.report(("self-test of the crypto library in the first session (" + to_string(elapsed) + " ms), later INITs skip it").c_str());
    }
    else {
        checker.report("self-test of the crypto library in the first session");
    }
    return checker.passed();
}

//  A session is ready for CAdES signing after INIT and adding the signer certificate to its cache
static bool init_session (
        Api& api,
        const Options& options,
        const bool offline,
        Response& response,
        Checker& checker
)
{
    return call_ok(api, request_init(offline), response, checker, "INIT")
        && call_ok(api, request_add_cert(options.signerCertB64), response, checker, "ADD_CERT");
}


//  Opens the storage, selects the first key and signs
static bool open_select_sign (
        Api& api,
        const string& storage,
        const string& password,
        const unsigned countSigns,
        const string& signRequest,
        string* firstSignature,
        Checker& checker,
        const string& keyId = string()
)
{
    Response resp;
    if (!call_ok(api, request_open(storage, password, "RO"), resp, checker, "OPEN")) return false;
    if (!call_ok(api, request_method("KEYS"), resp, checker, "KEYS")) return false;

    JSON_Array* ja_keys = json_object_get_array(resp.result, "keys");
    const string key_id = keyId.empty() ? ParsonHelper::jsonObjectGetString(json_array_get_object(ja_keys, 0), "id") : keyId;
    if (!call_ok(api, request_select_key(key_id), resp, checker, "SELECT_KEY")) return false;

    for (unsigned i = 0; i < countSigns; i++) {
        if (!call_ok(api, signRequest, resp, checker, "SIGN")) return false;
        if (firstSignature && (i == 0)) {
            *firstSignature = resp.signatureBytes();
        }
    }
    return call_ok(api, request_method("CLOSE"), resp, checker, "CLOSE");
}

static string select_first_key (
        Api& api,
        Response& resp,
        Checker& checker
)
{
    if (!call_ok(api, request_method("KEYS"), resp, checker, "KEYS")) return string();

    const string key_id = ParsonHelper::jsonObjectGetString(json_array_get_object(json_object_get_array(resp.result, "keys"), 0), "id");
    if (!call_ok(api, request_select_key(key_id), resp, checker, "SELECT_KEY")) return string();
    return key_id;
}


static bool run_benchmark (
        UapkiSessionLoader& loader,
        const Options& options,
        const vector<string>& storages
)
{
    const unsigned n = (unsigned)storages.size();
    const unsigned m = options.countSigns;
    const string sign_request = request_sign_cades();
    Checker checker;
    double ms_legacy = 0.0;

    printf("\nBenchmark: %u storages x %u CAdES-BES signatures each, %u hardware threads\n",
        n, m, thread::hardware_concurrency());
    printf("  timed work per storage: OPEN, KEYS, SELECT_KEY, %u x SIGN, CLOSE (INIT is done beforehand in both cases)\n", m);

    //  Legacy API: one library instance, one opened storage at a time,
    //  so the storages can only be processed one after another
    {
        Api api(loader);
        Response resp;
        if (!init_session(api, options, true, resp, checker)) {
            checker.report("benchmark, legacy INIT");
            return false;
        }
        const chrono::steady_clock::time_point dt_start = chrono::steady_clock::now();
        bool ok = true;
        for (unsigned i = 0; (i < n) && ok; i++) {
            ok = open_select_sign(api, storages[i], options.password, m, sign_request, nullptr, checker);
        }
        ms_legacy = elapsed_ms(dt_start);
        api.call(request_method("DEINIT"));
        if (!ok) {
            checker.report("benchmark, legacy API");
            return false;
        }
        printf("  process() (sequential, single opened storage): %8.1f ms total, %6.2f ms per signature\n",
            ms_legacy, ms_legacy / (n * m));
    }

    //  Sessions API: every storage lives in its own session; the sessions are initialized first,
    //  then all of them run the same per-storage work in parallel
    {
        vector<unique_ptr<UapkiSession>> sessions;
        for (unsigned i = 0; i < n; i++) {
            sessions.emplace_back(new UapkiSession(loader));
            Api api(loader, sessions[i]->getHandle());
            Response resp;
            checker.check(sessions[i]->isCreated(), "session not created");
            init_session(api, options, true, resp, checker);
        }
        if (!checker.passed()) {
            checker.report("benchmark, sessions INIT");
            return false;
        }

        atomic<bool> start(false);
        vector<thread> threads;
        for (unsigned i = 0; i < n; i++) {
            threads.emplace_back([&, i] {
                Api api(loader, sessions[i]->getHandle());
                while (!start) this_thread::yield();
                open_select_sign(api, storages[i], options.password, m, sign_request, nullptr, checker);
            });
        }
        const chrono::steady_clock::time_point dt_start = chrono::steady_clock::now();
        start = true;
        for (auto& it : threads) it.join();
        const double ms_total = elapsed_ms(dt_start);

        for (unsigned i = 0; i < n; i++) {
            Api api(loader, sessions[i]->getHandle());
            api.call(request_method("DEINIT"));
        }
        if (!checker.passed()) {
            checker.report("benchmark, sessions API");
            return false;
        }
        printf("  uapki_session_process() (%u parallel sessions):   %8.1f ms total, %6.2f ms per signature, speedup x%.1f\n",
            n, ms_total, ms_total / (n * m), (ms_total > 0.0) ? (ms_legacy / ms_total) : 0.0);
    }
    return true;
}


struct RsaStorages {
    vector<string>  files;
    vector<string>  keyIds;
    vector<string>  keyIds2;
    vector<string>  references;
    vector<string>  references2;
};  //  end struct RsaStorages

//  Every storage gets two RSA keys; PKCS#1 v1.5 signatures are deterministic, so the reference
//  signature of each key (made through the legacy API) identifies the key that produced a signature
static void prepare_rsa_storages (
        UapkiSessionLoader& loader,
        const Options& options,
        RsaStorages& rsa,
        Checker& checker
)
{
    const unsigned n = options.countSessions;
    rsa.files.assign(n, string());
    rsa.keyIds.assign(n, string());
    rsa.keyIds2.assign(n, string());
    rsa.references.assign(n, string());
    rsa.references2.assign(n, string());

    vector<thread> threads;
    for (unsigned i = 0; i < n; i++) {
        threads.emplace_back([&, i] {
            UapkiSession session(loader);
            Api api(loader, session.getHandle());
            Response resp;
            const string storage = options.workDir + "/rsa-" + to_string(i) + ".p12";
            if (!checker.check(session.isCreated(), "session not created")) return;
            if (!call_ok(api, request_init(true), resp, checker, "INIT")) return;
            if (!call_ok(api, request_open(storage, options.password, "CREATE"), resp, checker, "OPEN(CREATE)")) return;
            if (!call_ok(api, request_create_key_rsa(options.rsaBits), resp, checker, "CREATE_KEY")) return;
            rsa.keyIds[i] = resp.resultString("id");
            if (!call_ok(api, request_create_key_rsa(options.rsaBits), resp, checker, "CREATE_KEY")) return;
            rsa.keyIds2[i] = resp.resultString("id");
            rsa.files[i] = storage;
            api.call(request_method("CLOSE"));
            api.call(request_method("DEINIT"));
        });
    }
    for (auto& it : threads) it.join();
    if (!checker.passed()) return;

    Api api(loader);
    Response resp;
    const string sign_request = request_sign_raw_rsa();
    if (call_ok(api, request_init(true), resp, checker, "legacy INIT")) {
        for (unsigned i = 0; i < n; i++) {
            open_select_sign(api, rsa.files[i], options.password, 1, sign_request, &rsa.references[i], checker, rsa.keyIds[i]);
            open_select_sign(api, rsa.files[i], options.password, 1, sign_request, &rsa.references2[i], checker, rsa.keyIds2[i]);
        }
    }
    api.call(request_method("DEINIT"));
    for (unsigned i = 0; i < n; i++) {
        checker.check(!rsa.references[i].empty() && !rsa.references2[i].empty(), "empty reference signature " + to_string(i));
        checker.check(rsa.references[i] != rsa.references2[i], "both keys of storage " + to_string(i) + " produced the same signature");
        for (unsigned j = i + 1; j < n; j++) {
            checker.check(rsa.references[i] != rsa.references[j], "storages " + to_string(i) + " and " + to_string(j) + " produced the same signature");
        }
    }
}

//  N sessions sign in parallel with their own keys; a signature made with a foreign key is detected
static bool test_session_isolation (
        UapkiSessionLoader& loader,
        const Options& options,
        const RsaStorages& rsa
)
{
    Checker checker;
    const unsigned n = (unsigned)rsa.files.size();
    const string sign_request = request_sign_raw_rsa();

    vector<thread> threads;
    for (unsigned i = 0; i < n; i++) {
        threads.emplace_back([&, i] {
            UapkiSession session(loader);
            Api api(loader, session.getHandle());
            Response resp;
            if (!checker.check(session.isCreated(), "session not created")) return;
            if (!call_ok(api, request_init(true), resp, checker, "INIT")) return;
            if (!call_ok(api, request_open(rsa.files[i], options.password, "RO"), resp, checker, "OPEN")) return;
            if (call_ok(api, request_method("KEYS"), resp, checker, "KEYS")) {
                JSON_Array* ja_keys = json_object_get_array(resp.result, "keys");
                checker.check(json_array_get_count(ja_keys) == 2, "session " + to_string(i) + " sees " + to_string(json_array_get_count(ja_keys)) + " keys");
                for (size_t k = 0; k < json_array_get_count(ja_keys); k++) {
                    const string id = ParsonHelper::jsonObjectGetString(json_array_get_object(ja_keys, k), "id");
                    checker.check((id == rsa.keyIds[i]) || (id == rsa.keyIds2[i]), "session " + to_string(i) + " sees a foreign key");
                }
            }
            if (call_ok(api, request_select_key(rsa.keyIds[i]), resp, checker, "SELECT_KEY")) {
                for (unsigned k = 0; k < options.countSigns; k++) {
                    if (!call_ok(api, sign_request, resp, checker, "SIGN")) break;
                    checker.check(resp.signatureBytes() == rsa.references[i], "session " + to_string(i) + " signature #" + to_string(k) + " differs from its reference");
                }
            }
            api.call(request_method("CLOSE"));
            api.call(request_method("DEINIT"));
        });
    }
    for (auto& it : threads) it.join();
    checker.report("session isolation: N sessions sign in parallel with their own keys");
    return checker.passed();
}

//  Inside one session, serial methods that change the state (SELECT_KEY, CLOSE, OPEN) run
//  concurrently with thread methods (SIGN): every signature must come from the currently selected key
//  and every failure must be one of the two expected states, never a crash or garbage
static bool test_concurrent_methods_in_session (
        UapkiSessionLoader& loader,
        const Options& options,
        const RsaStorages& rsa
)
{
    Checker checker;
    UapkiSession session(loader);
    Api api(loader, session.getHandle());
    Response resp;
    const string sign_request = request_sign_raw_rsa();
    const string& storage = rsa.files[0];
    const unsigned count_threads = (options.countSessions < 2) ? 2 : options.countSessions;

    if (checker.check(session.isCreated(), "session not created")
        && call_ok(api, request_init(true), resp, checker, "INIT")
        && call_ok(api, request_open(storage, options.password, "RO"), resp, checker, "OPEN")
        && call_ok(api, request_select_key(rsa.keyIds[0]), resp, checker, "SELECT_KEY")
    ) {
        atomic<bool> serial_done(false);
        atomic<unsigned> count_signs(0), count_rejected(0);
        vector<thread> threads;
        for (unsigned t = 0; t < count_threads; t++) {
            threads.emplace_back([&] {
                Api thr_api(loader, session.getHandle());
                Response thr_resp;
                while (!serial_done && checker.passed()) {
                    if (!thr_api.call(sign_request, thr_resp)) {
                        checker.fail("no response for SIGN");
                        break;
                    }
                    if (thr_resp.ok()) {
                        const string signature = thr_resp.signatureBytes();
                        checker.check((signature == rsa.references[0]) || (signature == rsa.references2[0]), "signature made with an unknown key");
                        count_signs++;
                    }
                    else if ((thr_resp.errorCode == ERR_STORAGE_NOT_OPEN) || (thr_resp.errorCode == ERR_KEY_NOT_SELECTED)) {
                        count_rejected++;
                    }
                    else {
                        checker.fail("unexpected SIGN error: " + thr_resp.error);
                    }
                }
            });
        }
        for (unsigned k = 0; (k < 10 * options.countSigns) && checker.passed(); k++) {
            const string& key_id = ((k % 2) == 0) ? rsa.keyIds2[0] : rsa.keyIds[0];
            if (!call_ok(api, request_select_key(key_id), resp, checker, "SELECT_KEY")) break;
            if ((k % 5) == 4) {
                if (!call_ok(api, request_method("CLOSE"), resp, checker, "CLOSE")) break;
                if (!call_ok(api, request_open(storage, options.password, "RO"), resp, checker, "OPEN")) break;
            }
        }
        serial_done = true;
        for (auto& it : threads) it.join();
        checker.check(count_signs > 0, "no signature was made while the state was changing");
        printf("    (%u signatures, %u rejected while the storage was closed or no key was selected)\n", (unsigned)count_signs, (unsigned)count_rejected);
    }
    api.call(request_method("CLOSE"));
    api.call(request_method("DEINIT"));
    checker.report("serial and thread methods interleaved inside one session");
    return checker.passed();
}

//  The legacy process() instance and the sessions work at the same time, each with its own opened storage
static bool test_legacy_and_sessions_mixed (
        UapkiSessionLoader& loader,
        const Options& options,
        const string& storage,
        const RsaStorages& rsa
)
{
    Checker checker;
    const string sign_cades = request_sign_cades();
    const string sign_raw = request_sign_raw_rsa();
    vector<thread> threads;

    threads.emplace_back([&] {
        Api api(loader);
        Response resp;
        string signer_certid;
        if (init_session(api, options, true, resp, checker)
            && call_ok(api, request_open(storage, options.password, "RO"), resp, checker, "legacy OPEN")
            && !select_first_key(api, resp, checker).empty()
            && call_ok(api, sign_cades, resp, checker, "legacy SIGN")
        ) {
            signer_certid = resp.resultString("signerCertId");
            for (unsigned k = 0; k < options.countSigns; k++) {
                if (!call_ok(api, sign_cades, resp, checker, "legacy SIGN")) break;
                checker.check(resp.resultString("signerCertId") == signer_certid, "legacy signerCertId changed");
            }
            call_ok(api, request_method("CLOSE"), resp, checker, "legacy CLOSE");
        }
        api.call(request_method("DEINIT"));
    });
    for (size_t i = 0; i < rsa.files.size(); i++) {
        threads.emplace_back([&, i] {
            UapkiSession session(loader);
            Api api(loader, session.getHandle());
            Response resp;
            if (!checker.check(session.isCreated(), "session not created")) return;
            if (call_ok(api, request_init(true), resp, checker, "INIT")
                && call_ok(api, request_open(rsa.files[i], options.password, "RO"), resp, checker, "OPEN")
                && call_ok(api, request_select_key(rsa.keyIds[i]), resp, checker, "SELECT_KEY")
            ) {
                for (unsigned k = 0; k < options.countSigns; k++) {
                    if (!call_ok(api, sign_raw, resp, checker, "SIGN")) break;
                    checker.check(resp.signatureBytes() == rsa.references[i], "session " + to_string(i) + " signature differs from its reference");
                }
                call_ok(api, request_method("CLOSE"), resp, checker, "CLOSE");
            }
            api.call(request_method("DEINIT"));
        });
    }
    for (auto& it : threads) it.join();
    checker.report("legacy process() and sessions used concurrently");
    return checker.passed();
}

//  Invalid handles, double free, handle reuse, free while calls are in flight, create/free storm
static bool test_session_lifecycle (
        UapkiSessionLoader& loader,
        const Options& options,
        const string& storage
)
{
    Checker checker;
    Response resp;
    Api api(loader);
    bool called;

    UAPKI_SESSION* bogus = reinterpret_cast<UAPKI_SESSION*>(&checker);
    called = api.callSessionHandle(bogus, request_method("VERSION"), resp);
    checker.check(called && (resp.errorCode == ERR_INVALID_SESSION), "invalid handle: unexpected error " + to_string(resp.errorCode));
    called = api.callSessionHandle(nullptr, request_method("VERSION"), resp);
    checker.check(called && (resp.errorCode == ERR_INVALID_SESSION), "null handle is not rejected");

    UAPKI_SESSION* session = loader.sessionCreate();
    checker.check(session != nullptr, "session was not created");
    called = api.callSessionHandle(session, request_method("VERSION"), resp);
    checker.check(called && resp.ok(), "VERSION in a fresh session");
    called = api.callSessionHandle(session, request_method("KEYS"), resp);
    checker.check(called && (resp.errorCode == ERR_STORAGE_NOT_OPEN), "KEYS without storage: " + to_string(resp.errorCode));
    loader.sessionFree(session);
    loader.sessionFree(session);
    called = api.callSessionHandle(session, request_method("VERSION"), resp);
    checker.check(called && (resp.errorCode == ERR_INVALID_SESSION), "freed session still answers");
    loader.sessionFree(nullptr);

    for (unsigned k = 0; k < 100; k++) {
        UAPKI_SESSION* fresh = loader.sessionCreate();
        checker.check(fresh != session, "a freed handle was reused for a new session");
        loader.sessionFree(fresh);
    }
    called = api.callSessionHandle(session, request_method("VERSION"), resp);
    checker.check(called && (resp.errorCode == ERR_INVALID_SESSION), "a stale handle reached a session created later");

    {   //  a missing provider library is skipped, the remaining providers are loaded (legacy INIT semantics)
        UapkiSession session_unknown(loader);
        Api unknown_api(loader, session_unknown.getHandle());
        if (call_ok(unknown_api, request_init_unknown_provider(), resp, checker, "INIT with unknown provider")) {
            checker.check(ParsonHelper::jsonObjectGetUint32(resp.result, "countCmProviders", 0) == 1, "unknown provider changed the provider count");
        }
        unknown_api.call(request_method("DEINIT"));
    }

    {   //  free while other threads keep calling the session: calls in flight complete, later calls are rejected
        UAPKI_SESSION* victim = loader.sessionCreate();
        Api victim_api(loader, victim);
        const bool prepared = init_session(victim_api, options, true, resp, checker)
            && call_ok(victim_api, request_open(storage, options.password, "RO"), resp, checker, "OPEN")
            && !select_first_key(victim_api, resp, checker).empty();
        if (prepared) {
            const unsigned count_workers = (options.countSessions < 2) ? 2 : options.countSessions;
            atomic<bool> freed(false);
            atomic<unsigned> count_ok(0), count_invalid(0), count_finished(0);
            vector<thread> workers;
            for (unsigned t = 0; t < count_workers; t++) {
                workers.emplace_back([&] {
                    Api thr_api(loader, victim);
                    Response thr_resp;
                    const string sign_request = request_sign_cades();
                    //  Call until rejected: a fixed number of calls could all finish before the free on a slow runner
                    const chrono::steady_clock::time_point deadline = chrono::steady_clock::now() + chrono::seconds(REJECT_TIMEOUT_S);
                    while (chrono::steady_clock::now() < deadline) {
                        if (!thr_api.call(sign_request, thr_resp)) {
                            checker.fail("no response while the session is being freed");
                            break;
                        }
                        if (thr_resp.ok()) {
                            count_ok++;
                        }
                        else if (thr_resp.errorCode == ERR_INVALID_SESSION) {
                            checker.check(freed, "INVALID_SESSION before the session was freed");
                            count_invalid++;
                            break;
                        }
                        else {
                            checker.fail("unexpected error while the session is being freed: " + thr_resp.error);
                            break;
                        }
                    }
                    count_finished++;
                });
            }
            while ((count_ok < 3 * count_workers) && (count_finished < count_workers)) this_thread::yield();
            freed = true;
            loader.sessionFree(victim);
            for (auto& it : workers) it.join();
            checker.check(count_invalid == count_workers, "not every worker was rejected after the free");
        }
        else {
            loader.sessionFree(victim);
        }
    }

    {   //  create/free storm from many threads
        vector<thread> threads;
        for (unsigned t = 0; t < options.countSessions; t++) {
            threads.emplace_back([&] {
                for (unsigned k = 0; k < 50; k++) {
                    UapkiSession session_k(loader);
                    Api thr_api(loader, session_k.getHandle());
                    Response thr_resp;
                    if (!checker.check(session_k.isCreated(), "session not created in storm")) break;
                    if (!call_ok(thr_api, request_method("VERSION"), thr_resp, checker, "VERSION in storm")) break;
                    if (((k % 5) == 0) && !call_ok(thr_api, request_init(true), thr_resp, checker, "INIT in storm")) break;
                }
            });
        }
        for (auto& it : threads) it.join();
    }
    checker.report("session lifecycle: invalid handles, double free, stale handles, free during calls, create/free storm");
    return checker.passed();
}

//  Providers are shared between sessions: INIT/DEINIT storms must not unload a provider that another session is using
static bool test_provider_sharing (
        UapkiSessionLoader& loader,
        const Options& options,
        const string& storage
)
{
    Checker checker;
    UapkiSession keeper(loader);
    Api keeper_api(loader, keeper.getHandle());
    Response resp;
    const string sign_request = request_sign_cades();

    if (checker.check(keeper.isCreated(), "session not created")
        && init_session(keeper_api, options, true, resp, checker)
        && call_ok(keeper_api, request_open(storage, options.password, "RO"), resp, checker, "OPEN")
        && !select_first_key(keeper_api, resp, checker).empty()
    ) {
        atomic<bool> stop(false);
        vector<thread> threads;
        for (unsigned t = 0; t < options.countSessions; t++) {
            threads.emplace_back([&, t] {
                //  the same library named through another directory spelling must map to the same provider
                const bool other_dir = ((t % 2) == 1) && !options.providerDir.empty();
                const string init_request = other_dir ? request_init_dir(true, options.providerDir.c_str()) : request_init(true);
                for (unsigned k = 0; k < 20; k++) {
                    UapkiSession session_k(loader);
                    Api thr_api(loader, session_k.getHandle());
                    Response thr_resp;
                    if (!checker.check(session_k.isCreated(), "session not created")) break;
                    if (!call_ok(thr_api, init_request, thr_resp, checker, "INIT")) break;
                    checker.check(ParsonHelper::jsonObjectGetUint32(thr_resp.result, "countCmProviders", 0) == 1, "provider not loaded in a session");
                    if (!call_ok(thr_api, request_method("PROVIDERS"), thr_resp, checker, "PROVIDERS")) break;
                    if (!call_ok(thr_api, request_method("DEINIT"), thr_resp, checker, "DEINIT")) break;
                }
            });
        }
        thread signer([&] {
            Response thr_resp;
            while (!stop) {
                if (!call_ok(keeper_api, sign_request, thr_resp, checker, "keeper SIGN")) break;
            }
        });
        for (auto& it : threads) it.join();
        stop = true;
        signer.join();

        //  all other sessions are gone, the keeper must still be able to use its storage and its provider
        call_ok(keeper_api, sign_request, resp, checker, "keeper SIGN after storm");
        call_ok(keeper_api, request_method("CLOSE"), resp, checker, "keeper CLOSE");
        call_ok(keeper_api, request_method("DEINIT"), resp, checker, "keeper DEINIT");

        //  the provider was released by everyone; a new session must load it again
        UapkiSession session_new(loader);
        Api new_api(loader, session_new.getHandle());
        if (call_ok(new_api, request_init(true), resp, checker, "INIT after release")) {
            checker.check(ParsonHelper::jsonObjectGetUint32(resp.result, "countCmProviders", 0) == 1, "provider not reloaded");
            call_ok(new_api, request_open(storage, options.password, "RO"), resp, checker, "OPEN after reload");
        }
        new_api.call(request_method("CLOSE"));
        new_api.call(request_method("DEINIT"));
    }
    keeper_api.call(request_method("DEINIT"));
    checker.report("provider sharing across sessions with INIT/DEINIT storm");
    return checker.passed();
}

//  Configuration is per session: an offline session refuses network operations while an online one attempts them
static bool test_config_isolation (
        UapkiSessionLoader& loader,
        const Options& options,
        const string& storage
)
{
    Checker checker;
    UapkiSession offline_session(loader), online_session(loader);
    Api offline_api(loader, offline_session.getHandle()), online_api(loader, online_session.getHandle());
    Response resp;
    bool called;

    checker.check(offline_session.isCreated() && online_session.isCreated(), "session not created");
    if (call_ok(offline_api, request_init(true), resp, checker, "offline INIT")) {
        checker.check(ParsonHelper::jsonObjectGetBoolean(resp.result, "offline", false), "offline session reports online");
        call_ok(offline_api, request_add_cert(options.signerCertB64), resp, checker, "ADD_CERT");
    }
    if (call_ok(online_api, request_init(false, TSP_URL_UNREACHABLE), resp, checker, "online INIT")) {
        checker.check(!ParsonHelper::jsonObjectGetBoolean(resp.result, "offline", true), "online session reports offline");
        checker.check(ParsonHelper::jsonObjectGetString(json_object_get_object(resp.result, "tsp"), "url") == TSP_URL_UNREACHABLE, "online session lost its TSP url");
        call_ok(online_api, request_add_cert(options.signerCertB64), resp, checker, "ADD_CERT");
    }

    Api* apis[2] = { &offline_api, &online_api };
    for (Api* api : apis) {
        if (call_ok(*api, request_open(storage, options.password, "RO"), resp, checker, "OPEN")) {
            select_first_key(*api, resp, checker);
        }
    }

    if (checker.passed()) {
        //  CAdES-T needs a timestamp: the offline session must refuse, the online session must try its
        //  (unreachable) TSP and report that it does not respond
        called = offline_api.call(request_sign_cades_t(), resp);
        checker.check(called && (resp.errorCode == ERR_OFFLINE_MODE), "offline session: " + resp.error);
        called = online_api.call(request_sign_cades_t(), resp);
        checker.check(called && (resp.errorCode == ERR_TSP_NOT_RESPONDING), "online session: " + resp.error);
    }

    for (Api* api : apis) {
        api->call(request_method("CLOSE"));
        api->call(request_method("DEINIT"));
    }
    checker.report("configuration isolation between sessions (offline mode, TSP url)");
    return checker.passed();
}



struct SharedMemorySetup {
    string      certDir;
    string      crlDir;
    vector<string>
                crlsB64;
    vector<string>
                extraCrlsB64;
};  //  end struct SharedMemorySetup

//  The shared certificate base holds every certificate of the test data except the signer certificate,
//  which the tests add to sessions on purpose to show the session-private overlay
static bool prepare_shared_memory_data (
        const Options& options,
        const string& certSourceDir,
        SharedMemorySetup& setup
)
{
    setup.certDir = options.workDir + "/certs-base/";
    setup.crlDir = options.workDir + "/crls-synth/";
    (void)MAKE_DIR(setup.certDir.c_str());
    (void)MAKE_DIR(setup.crlDir.c_str());

    static const char* base_certs[] = {
        "CAO-05E19E2CD92EA2990100000001000000C1000000.cer",
        "diia-2023-tsp-05E19E2CD92EA29902000000010000004A010000.cer",
        "diia-CA-05E19E2CD92EA2990100000001000000E1000000.cer",
        "diia-ocsp-3ED5083160DBC59B0200000001000000202B0F00.cer",
        "diia-test-kep-7775604.cer",
    };
    for (const char* name : base_certs) {
        if (!copy_file(certSourceDir + name, setup.certDir + name)) {
            printf("Can't copy certificate '%s%s'\n", certSourceDir.c_str(), name);
            return false;
        }
    }

    for (unsigned i = 0; i < options.countCrls; i++) {
        const Der::Bytes crl = synthetic_crl(i, options.countCrlEntries);
        if (!write_file(setup.crlDir + "synthetic-" + to_string(i) + ".crl", crl)) return false;
        if (i < 4) setup.crlsB64.push_back(base64_encode(crl));
    }
    //  CRLs that are not in the directory: added and removed by concurrent writers
    for (unsigned i = 0; i < 4 * options.countSessions; i++) {
        setup.extraCrlsB64.push_back(base64_encode(synthetic_crl(options.countCrls + i, 16)));
    }
    return true;
}

static vector<string> list_dir (const string& dir)
{
    vector<string> rv;
#ifdef _WIN32
    WIN32_FIND_DATAA found;
    HANDLE h = FindFirstFileA((dir + "*").c_str(), &found);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) rv.push_back(found.cFileName);
        } while (FindNextFileA(h, &found));
        FindClose(h);
    }
#else
    DIR* d = opendir(dir.c_str());
    if (d) {
        while (struct dirent* entry = readdir(d)) {
            const string name = entry->d_name;
            if ((name != ".") && (name != "..")) rv.push_back(name);
        }
        closedir(d);
    }
#endif
    return rv;
}

static void cleanup_shared_memory_data (
        const SharedMemorySetup& setup
)
{
    //  the caches rename files to their canonical names, so the directories are cleared by listing
    for (const string& dir : { setup.certDir, setup.crlDir }) {
        for (const string& name : list_dir(dir)) {
            remove((dir + name).c_str());
        }
        (void)REMOVE_DIR(dir.c_str());
    }
}

static uint32_t list_crls_count (
        Api& api,
        Checker& checker,
        const string& what
)
{
    Response resp;
    if (!call_ok(api, request_list_crls(), resp, checker, what)) return 0;
    return ParsonHelper::jsonObjectGetUint32(resp.result, "count", 0);
}

//  RAM and load time: every session keeping its own copy of the caches (the only option without shared
//  memory) versus one shared memory used by all sessions
static bool run_shared_memory_benchmark (
        UapkiSessionLoader& loader,
        const Options& options,
        const SharedMemorySetup& setup
)
{
    Checker checker;
    const unsigned n = options.countSessions;
    const string init_request = request_init_caches(setup.certDir, setup.crlDir);
    Response resp;

    printf("\nShared memory benchmark: %u sessions, cache of %u CRLs x %u revoked entries + 5 certificates\n",
        n, options.countCrls, options.countCrlEntries);
    if (heap_in_use() == 0) {
        printf("  (heap measurement is not available on this platform, only the load time is reported)\n");
    }

    //  Private caches: each session loads and keeps its own copy
    const size_t heap_start = heap_in_use();
    const chrono::steady_clock::time_point dt_private = chrono::steady_clock::now();
    vector<unique_ptr<UapkiSession>> sessions;
    for (unsigned i = 0; i < n; i++) {
        sessions.emplace_back(new UapkiSession(loader));
        Api api(loader, sessions[i]->getHandle());
        if (call_ok(api, init_request, resp, checker, "private INIT")) {
            checker.check(ParsonHelper::jsonObjectGetUint32(json_object_get_object(resp.result, "crlCache"), "countCrls", 0) == options.countCrls, "private session did not load all CRLs");
        }
    }
    const double ms_private = elapsed_ms(dt_private);
    const size_t heap_private = heap_in_use();
    for (auto& it : sessions) {
        Api api(loader, it->getHandle());
        api.call(request_method("DEINIT"));
    }
    sessions.clear();
    const size_t heap_released = heap_in_use();

    //  Shared memory: one copy, every session attaches by passing the handle with its requests
    const chrono::steady_clock::time_point dt_shared = chrono::steady_clock::now();
    UapkiSharedMemory memory(loader);
    Api memory_api(loader, memory.getHandle());
    checker.check(memory.isCreated(), "shared memory not created");
    if (call_ok(memory_api, init_request, resp, checker, "shared memory INIT")) {
        checker.check(ParsonHelper::jsonObjectGetUint32(json_object_get_object(resp.result, "crlCache"), "countCrls", 0) == options.countCrls, "shared memory did not load all CRLs");
    }
    const size_t heap_memory = heap_in_use();
    for (unsigned i = 0; i < n; i++) {
        sessions.emplace_back(new UapkiSession(loader));
        Api api(loader, sessions[i]->getHandle(), memory.getHandle());
        //  the same INIT without caches: both columns hold n initialized sessions and differ only by where the caches live
        call_ok(api, request_init_caches("", ""), resp, checker, "INIT of a session using the shared memory");
        checker.check(list_crls_count(api, checker, "LIST_CRLS via shared memory") == options.countCrls, "session does not see the shared CRLs");
    }
    const double ms_shared = elapsed_ms(dt_shared);
    const size_t heap_shared = heap_in_use();

    //  Reads through the shared memory versus private caches: the extra reader lock must not cost anything visible
    double ms_read_private = 0.0, ms_read_shared = 0.0;
    {
        const unsigned count_reads = 200;
        UapkiSession session_private(loader);
        Api api_private(loader, session_private.getHandle());
        if (call_ok(api_private, init_request, resp, checker, "private INIT")) {
            const chrono::steady_clock::time_point dt = chrono::steady_clock::now();
            for (unsigned k = 0; k < count_reads; k++) list_crls_count(api_private, checker, "LIST_CRLS private");
            ms_read_private = elapsed_ms(dt);
            api_private.call(request_method("DEINIT"));
        }
        Api api_shared(loader, sessions[0]->getHandle(), memory.getHandle());
        const chrono::steady_clock::time_point dt = chrono::steady_clock::now();
        for (unsigned k = 0; k < count_reads; k++) list_crls_count(api_shared, checker, "LIST_CRLS shared");
        ms_read_shared = elapsed_ms(dt);
        printf("  %u x LIST_CRLS: private cache %.1f ms, shared memory %.1f ms\n", count_reads, ms_read_private, ms_read_shared);
    }
    sessions.clear();
    memory_api.call(request_method("DEINIT"));

    if (heap_start > 0) {
        const size_t bytes_private = (heap_private > heap_start) ? (heap_private - heap_start) : 0;
        const size_t bytes_memory = (heap_memory > heap_released) ? (heap_memory - heap_released) : 0;
        const size_t bytes_sessions = (heap_shared > heap_memory) ? (heap_shared - heap_memory) : 0;
        printf("  private caches:  %u sessions x %.1f MiB = %.1f MiB, loaded in %.0f ms\n",
            n, to_mib(bytes_private) / n, to_mib(bytes_private), ms_private);
        printf("  shared memory:   1 x %.1f MiB + %u sessions x %.2f MiB = %.1f MiB, loaded in %.0f ms (x%.1f less RAM)\n",
            to_mib(bytes_memory), n, to_mib(bytes_sessions) / n, to_mib(bytes_memory + bytes_sessions), ms_shared,
            (bytes_memory + bytes_sessions > 0) ? ((double)bytes_private / (double)(bytes_memory + bytes_sessions)) : 0.0);
        checker.check(heap_released < heap_start + bytes_private / 4, "private caches were not released by DEINIT");
        //  the reason the shared memory exists: with several sessions it must cost a fraction of the private caches
        if (n >= 2) {
            checker.check(bytes_memory + bytes_sessions < bytes_private * 6 / 10, "shared memory does not save RAM");
            checker.check(bytes_sessions / n < bytes_memory / 4, "a session using the shared memory still keeps a large cache of its own");
        }
    }
    else {
        printf("  private caches: loaded in %.0f ms; shared memory: loaded in %.0f ms\n", ms_private, ms_shared);
    }
    checker.report("shared memory benchmark");
    return checker.passed();
}

//  Certificates: the session overlay is private, the shared base is visible to every session;
//  CRLs come from the shared memory only
static bool test_shared_memory_layers (
        UapkiSessionLoader& loader,
        const Options& options,
        const SharedMemorySetup& setup,
        const string& storage
)
{
    Checker checker;
    Response resp;
    UapkiSharedMemory memory(loader);
    Api memory_api(loader, memory.getHandle());
    UapkiSession session_a(loader), session_b(loader);
    Api api_a(loader, session_a.getHandle(), memory.getHandle());
    Api api_b(loader, session_b.getHandle(), memory.getHandle());
    Api api_a_private(loader, session_a.getHandle());

    checker.check(memory.isCreated() && session_a.isCreated() && session_b.isCreated(), "objects not created");
    if (!call_ok(memory_api, request_init_caches(setup.certDir, setup.crlDir), resp, checker, "shared memory INIT")) {
        checker.report("shared memory layers");
        return false;
    }
    string base_certid;
    if (call_ok(memory_api, request_method("LIST_CERTS"), resp, checker, "LIST_CERTS on shared memory")) {
        JSON_Array* ja_certids = json_object_get_array(resp.result, "certIds");
        checker.check(json_array_get_count(ja_certids) == 5, "shared memory holds " + to_string(json_array_get_count(ja_certids)) + " certificates instead of 5");
        base_certid = ParsonHelper::jsonArrayGetString(ja_certids, 0);
    }

    //  both sessions have providers only: no certificate cache of their own
    call_ok(api_a_private, request_init(true), resp, checker, "INIT A");
    call_ok(api_b, request_init(true), resp, checker, "INIT B");

    //  the signer certificate goes to A's overlay
    string signer_certid;
    if (call_ok(api_a, request_add_cert(options.signerCertB64), resp, checker, "ADD_CERT in A")) {
        signer_certid = ParsonHelper::jsonObjectGetString(json_array_get_object(json_object_get_array(resp.result, "added"), 0), "certId");
    }
    bool called;
    called = api_a.call(request_get_cert(signer_certid), resp);
    checker.check(called && resp.ok(), "A does not see its own certificate: " + resp.error);
    called = api_b.call(request_get_cert(signer_certid), resp);
    checker.check(called && (resp.errorCode == ERR_CERT_NOT_FOUND), "B sees A's private certificate: " + to_string(resp.errorCode));
    called = memory_api.call(request_get_cert(signer_certid), resp);
    checker.check(called && (resp.errorCode == ERR_CERT_NOT_FOUND), "shared memory received A's private certificate: " + to_string(resp.errorCode));
    called = api_b.call(request_get_cert(base_certid), resp);
    checker.check(called && resp.ok(), "B does not see the shared base: " + resp.error);
    called = api_a_private.call(request_get_cert(base_certid), resp);
    checker.check(called && (resp.errorCode == ERR_CERT_NOT_FOUND), "A without shared memory sees the base: " + to_string(resp.errorCode));

    //  CAdES signing needs the signer certificate: A finds it in its overlay, B has nowhere to find it
    for (Api* api : { &api_a, &api_b }) {
        call_ok(*api, request_open(storage, options.password, "RO"), resp, checker, "OPEN");
        select_first_key(*api, resp, checker);
    }
    called = api_a.call(request_sign_cades(), resp);
    checker.check(called && resp.ok(), "A SIGN with overlay + base: " + resp.error);
    called = api_b.call(request_sign_cades(), resp);
    checker.check(called && (resp.errorCode == ERR_CERT_NOT_FOUND), "B signed without the signer certificate: " + to_string(resp.errorCode));

    //  CRLs are served by the shared memory only
    checker.check(list_crls_count(api_a, checker, "LIST_CRLS A") == options.countCrls, "A does not see the shared CRLs");
    checker.check(list_crls_count(api_a_private, checker, "LIST_CRLS A private") == 0, "A keeps a private CRL copy");

    for (Api* api : { &api_a, &api_b }) {
        api->call(request_method("CLOSE"));
        api->call(request_method("DEINIT"));
    }
    memory_api.call(request_method("DEINIT"));
    checker.report("shared memory: private certificate overlay, shared certificate base, shared CRLs");
    return checker.passed();
}

//  A session that was never initialized works through an initialized shared memory (its configuration
//  and caches); without the shared memory it is rejected as before
static bool test_shared_memory_autoinit (
        UapkiSessionLoader& loader,
        const Options& options,
        const SharedMemorySetup& setup
)
{
    Checker checker;
    Response resp;
    UapkiSharedMemory memory(loader);
    Api memory_api(loader, memory.getHandle());
    UapkiSession session(loader);
    Api api(loader, session.getHandle(), memory.getHandle());
    Api api_private(loader, session.getHandle());
    bool called;

    call_ok(memory_api, request_init_caches(setup.certDir, setup.crlDir), resp, checker, "shared memory INIT");
    called = api_private.call(request_list_crls(), resp);
    checker.check(called && (resp.errorCode == ERR_NOT_INITIALIZED), "uninitialized session answered without shared memory: " + to_string(resp.errorCode));
    checker.check(list_crls_count(api, checker, "LIST_CRLS via shared memory") == options.countCrls, "uninitialized session does not see the shared CRLs");
    called = api.call(request_method("KEYS"), resp);
    checker.check(called && (resp.errorCode == ERR_STORAGE_NOT_OPEN), "storage methods must still need the session: " + to_string(resp.errorCode));

    //  the shared memory is offline: an OCSP request through the uninitialized session is refused;
    //  after the session is initialized online it uses its own configuration and tries the (unreachable) responder
    string issuer_certid;
    if (call_ok(memory_api, request_method("LIST_CERTS"), resp, checker, "LIST_CERTS on shared memory")) {
        issuer_certid = ParsonHelper::jsonArrayGetString(json_object_get_array(resp.result, "certIds"), 0);
    }
    called = api.call(request_cert_status_by_ocsp(issuer_certid), resp);
    checker.check(called && (resp.errorCode == ERR_OFFLINE_MODE), "uninitialized session did not use the offline configuration of the shared memory: " + to_string(resp.errorCode));
    call_ok(api_private, request_init(false, TSP_URL_UNREACHABLE), resp, checker, "INIT online");
    called = api.call(request_cert_status_by_ocsp(issuer_certid), resp);
    checker.check(called && (resp.errorCode == ERR_CONNECTION_ERROR), "initialized session did not keep its own configuration: " + to_string(resp.errorCode));
    api.call(request_method("DEINIT"));
    memory_api.call(request_method("DEINIT"));
    checker.report("shared memory: uninitialized session borrows the shared memory configuration");
    return checker.passed();
}

//  Sessions read the shared memory while other threads delete from it (REMOVE_CRL, REMOVE_CERT),
//  re-load it (DEINIT/INIT on the shared memory) and re-initialize a reading session: deletions and
//  re-loads take the shared memory exclusively, so a reader can never hold an item that is being freed.
//  Every answer is checked against what the item must contain, so a stale pointer is detected even
//  without a sanitizer
static bool test_shared_memory_gate (
        UapkiSessionLoader& loader,
        const Options& options,
        const SharedMemorySetup& setup
)
{
    Checker checker;
    Response resp;
    UapkiSharedMemory memory(loader);
    Api memory_api(loader, memory.getHandle());
    const string init_request = request_init_caches(setup.certDir, setup.crlDir);

    if (!call_ok(memory_api, init_request, resp, checker, "shared memory INIT")) {
        checker.report("shared memory gate");
        return false;
    }
    vector<string> crl_ids;
    for (const string& crl_b64 : setup.crlsB64) {
        if (call_ok(memory_api, request_add_crl(crl_b64), resp, checker, "ADD_CRL")) {
            crl_ids.push_back(resp.resultString("crlId"));
        }
    }
    string base_certid;
    if (call_ok(memory_api, request_method("LIST_CERTS"), resp, checker, "LIST_CERTS")) {
        base_certid = ParsonHelper::jsonArrayGetString(json_object_get_array(resp.result, "certIds"), 0);
    }
    if (!checker.passed() || crl_ids.empty() || base_certid.empty()) {
        checker.report("shared memory gate");
        return false;
    }

    atomic<bool> stop(false);
    atomic<unsigned> count_reads(0), count_missing(0), count_reloading(0), count_mutations(0);
    unique_ptr<UapkiSession> restarted_session(new UapkiSession(loader));
    vector<thread> readers;
    for (unsigned t = 0; t < options.countSessions; t++) {
        readers.emplace_back([&, t] {
            UapkiSession own_session(loader);
            UAPKI_SESSION* session = (t == 0) ? restarted_session->getHandle() : own_session.getHandle();
            Api api(loader, session, memory.getHandle());
            Response thr_resp;
            while (!stop && checker.passed()) {
                const size_t idx = (t + count_reads) % crl_ids.size();
                if (!api.call(request_crl_info(crl_ids[idx]), thr_resp)) {
                    checker.fail("no response for CRL_INFO");
                    break;
                }
                if (thr_resp.ok()) {
                    const bool same_crl = (ParsonHelper::jsonObjectGetUint32(thr_resp.result, "countRevokedCerts", 0) == options.countCrlEntries)
                        && (ParsonHelper::jsonObjectGetString(json_object_get_object(thr_resp.result, "issuer"), "CN") == "Synthetic CA " + to_string(idx));
                    checker.check(same_crl, "CRL_INFO returned the wrong CRL");
                    count_reads++;
                }
                else if (thr_resp.errorCode == ERR_CRL_NOT_FOUND) count_missing++;
                else if (thr_resp.errorCode == ERR_NOT_INITIALIZED) count_reloading++;
                else checker.fail("unexpected CRL_INFO error: " + thr_resp.error);

                if (!api.call(request_get_cert(base_certid), thr_resp)) {
                    checker.fail("no response for GET_CERT");
                    break;
                }
                if (thr_resp.ok()) count_reads++;
                else if ((thr_resp.errorCode == ERR_CERT_NOT_FOUND) || (thr_resp.errorCode == ERR_NOT_INITIALIZED)) count_missing++;
                else checker.fail("unexpected GET_CERT error: " + thr_resp.error);
            }
        });
    }
    //  while the shared memory is being re-loaded by another mutator its methods answer NOT_INITIALIZED
    auto mutation_ok = [&checker] (Api& api, const string& request, Response& response, const char* what) {
        if (!api.call(request, response)) {
            checker.fail(string("no response for ") + what);
            return false;
        }
        if (response.ok() || (response.errorCode == ERR_NOT_INITIALIZED) || (response.errorCode == ERR_CRL_NOT_FOUND) || (response.errorCode == ERR_CERT_NOT_FOUND)) {
            return true;
        }
        checker.fail(string("unexpected ") + what + " error: " + response.error);
        return false;
    };
    vector<thread> mutators;
    mutators.emplace_back([&] {   //  CRLs replaced through the shared memory and through a session
        Response thr_resp;
        UapkiSession session(loader);
        Api api_via_session(loader, session.getHandle(), memory.getHandle());
        for (unsigned round = 0; (round < 10 * options.countSigns) && checker.passed(); round++) {
            for (size_t i = 0; i < crl_ids.size(); i++) {
                Api& api = ((round % 2) == 0) ? memory_api : api_via_session;
                if (!mutation_ok(api, request_remove_crl(crl_ids[i]), thr_resp, "REMOVE_CRL")) return;
                if (!mutation_ok(api, request_add_crl(setup.crlsB64[i]), thr_resp, "ADD_CRL")) return;
                count_mutations++;
            }
        }
    });
    mutators.emplace_back([&] {   //  the signer certificate added permanently to the base and removed again
        Response thr_resp;
        for (unsigned round = 0; (round < 10 * options.countSigns) && checker.passed(); round++) {
            if (!mutation_ok(memory_api, request_add_cert_permanent(options.signerCertB64), thr_resp, "ADD_CERT")) return;
            if (thr_resp.ok()) {
                const string cert_id = ParsonHelper::jsonObjectGetString(json_array_get_object(json_object_get_array(thr_resp.result, "added"), 0), "certId");
                //  The certificate file is already on disk: a removal that hits a re-load (NOT_INITIALIZED) is repeated,
                //  otherwise the next INIT of the shared memory loads the certificate again
                do {
                    if (!mutation_ok(memory_api, request_remove_cert(cert_id, true), thr_resp, "REMOVE_CERT")) return;
                    if (thr_resp.errorCode == ERR_NOT_INITIALIZED) this_thread::yield();
                } while ((thr_resp.errorCode == ERR_NOT_INITIALIZED) && checker.passed());
            }
            count_mutations++;
        }
    });
    mutators.emplace_back([&] {   //  the shared memory itself is dropped and re-loaded from disk
        Response thr_resp;
        for (unsigned round = 0; (round < options.countSigns) && checker.passed(); round++) {
            if (!call_ok(memory_api, request_method("DEINIT"), thr_resp, checker, "DEINIT of shared memory")) return;
            if (!call_ok(memory_api, init_request, thr_resp, checker, "INIT of shared memory")) return;
            count_mutations++;
        }
    });
    mutators.emplace_back([&] {   //  a reading session is initialized and de-initialized under its reader
        Response thr_resp;
        Api api(loader, restarted_session->getHandle());
        for (unsigned round = 0; (round < 10 * options.countSigns) && checker.passed(); round++) {
            if (!call_ok(api, request_init(true), thr_resp, checker, "INIT of a reading session")) return;
            if (!call_ok(api, request_method("DEINIT"), thr_resp, checker, "DEINIT of a reading session")) return;
            count_mutations++;
        }
    });
    for (auto& it : mutators) it.join();
    stop = true;
    for (auto& it : readers) it.join();
    checker.check(count_reads > 0, "no successful read");
    checker.check(count_mutations > 0, "no mutation");
    printf("    (%u reads, %u reads hit an item being replaced, %u reads hit the shared memory being re-loaded, %u mutations)\n",
        (unsigned)count_reads, (unsigned)count_missing, (unsigned)count_reloading, (unsigned)count_mutations);
    //  the CRLs used by the storm are the first ones of the directory and the certificate was removed again
    checker.check(list_crls_count(memory_api, checker, "LIST_CRLS") == options.countCrls, "CRL count changed after the storm");
    if (call_ok(memory_api, request_method("LIST_CERTS"), resp, checker, "LIST_CERTS")) {
        checker.check(json_array_get_count(json_object_get_array(resp.result, "certIds")) == 5, "certificate count changed after the storm");
    }
    memory_api.call(request_method("DEINIT"));
    checker.report("shared memory: readers in sessions vs deletions, re-loads and session restarts");
    return checker.passed();
}


//  uapki_session_shared_memory_process accepts the cache methods only: every other method of the library
//  is rejected with NOT_ALLOWED before anything is executed
static bool test_shared_memory_whitelist (
        UapkiSessionLoader& loader,
        const SharedMemorySetup& setup
)
{
    static const char* ALL_METHODS[] = {
        "VERSION", "INIT", "DEINIT", "PROVIDERS", "STORAGES", "STORAGE_INFO", "OPEN", "CLOSE", "KEYS", "SELECT_KEY",
        "CREATE_KEY", "DELETE_KEY", "GET_CSR", "CHANGE_PASSWORD", "INIT_KEY_USAGE", "SIGN", "VERIFY", "BUILD_CMS_2PASS",
        "BUILD_CSR_2PASS", "ADD_CERT", "CERT_INFO", "GET_CERT", "LIST_CERTS", "REMOVE_CERT", "VERIFY_CERT", "ADD_CRL",
        "CRL_INFO", "LIST_CRLS", "REMOVE_CRL", "DECRYPT", "ENCRYPT", "RANDOM_BYTES", "CERT_STATUS_BY_OCSP", "DIGEST",
        "VERIFY_CSR", "GENERATE_CERTBUNDLE", "MODIFY_CMS", "ASN1_DECODE", "ASN1_ENCODE",
    };
    static const char* ALLOWED_METHODS[] = {
        "VERSION", "INIT", "DEINIT", "ADD_CERT", "CERT_INFO", "GET_CERT", "LIST_CERTS", "REMOVE_CERT",
        "ADD_CRL", "CRL_INFO", "LIST_CRLS", "REMOVE_CRL",
    };
    Checker checker;
    Response resp;
    UapkiSharedMemory memory(loader);
    Api memory_api(loader, memory.getHandle());

    checker.check(memory.isCreated(), "shared memory not created");
    call_ok(memory_api, request_init_caches(setup.certDir, setup.crlDir), resp, checker, "shared memory INIT");
    for (const char* method : ALL_METHODS) {
        bool allowed = false;
        for (const char* it : ALLOWED_METHODS) allowed = allowed || (strcmp(it, method) == 0);
        if ((strcmp(method, "INIT") == 0) || (strcmp(method, "DEINIT") == 0)) continue;

        const bool called = memory_api.call(request_method(method), resp);
        checker.check(called, string("no response for ") + method);
        if (allowed) {
            checker.check(called && (resp.errorCode != ERR_NOT_ALLOWED), string(method) + " must be available on the shared memory");
        }
        else {
            checker.check(called && (resp.errorCode == ERR_NOT_ALLOWED), string(method) + " must be rejected on the shared memory: " + to_string(resp.errorCode));
        }
    }
    //  an unknown method is still reported as unknown, not as forbidden
    const bool called = memory_api.call(request_method("NO_SUCH_METHOD"), resp);
    checker.check(called && (resp.errorCode == 0x1004), "unknown method on the shared memory: " + to_string(resp.errorCode));
    call_ok(memory_api, request_method("DEINIT"), resp, checker, "DEINIT");
    checker.report("shared memory: only the cache methods are accepted by uapki_session_shared_memory_process");
    return checker.passed();
}

//  Concurrent writers on the shared memory itself (ADD_CRL, ADD_CERT from many threads) while sessions read it,
//  then concurrent removals: the caches must end up exactly as expected
static bool test_shared_memory_concurrent_writers (
        UapkiSessionLoader& loader,
        const Options& options,
        const SharedMemorySetup& setup
)
{
    Checker checker;
    Response resp;
    UapkiSharedMemory memory(loader);
    Api memory_api(loader, memory.getHandle());
    const unsigned count_writers = (options.countSessions < 2) ? 2 : options.countSessions;
    const size_t extras_per_writer = setup.extraCrlsB64.size() / count_writers;

    if (!call_ok(memory_api, request_init_caches(setup.certDir, setup.crlDir), resp, checker, "shared memory INIT")) {
        checker.report("shared memory concurrent writers");
        return false;
    }

    atomic<bool> stop(false);
    atomic<unsigned> count_reads(0);
    vector<thread> readers;
    for (unsigned t = 0; t < options.countSessions; t++) {
        readers.emplace_back([&] {
            UapkiSession session(loader);
            Api api(loader, session.getHandle(), memory.getHandle());
            Response thr_resp;
            while (!stop && checker.passed()) {
                if (!call_ok(api, request_list_crls(), thr_resp, checker, "LIST_CRLS")) break;
                if (!call_ok(api, request_method("LIST_CERTS"), thr_resp, checker, "LIST_CERTS")) break;
                count_reads++;
            }
        });
    }

    //  phase 1: every writer adds its own CRLs and the signer certificate (a duplicate for all but one writer)
    vector<vector<string>> crl_ids(count_writers);
    vector<thread> writers;
    for (unsigned w = 0; w < count_writers; w++) {
        writers.emplace_back([&, w] {
            Api api(loader, memory.getHandle());
            Response thr_resp;
            for (size_t i = w * extras_per_writer; i < (w + 1) * extras_per_writer; i++) {
                if (!call_ok(api, request_add_crl(setup.extraCrlsB64[i]), thr_resp, checker, "ADD_CRL")) return;
                checker.check(ParsonHelper::jsonObjectGetBoolean(thr_resp.result, "isUnique", false), "a new CRL was reported as known");
                crl_ids[w].push_back(thr_resp.resultString("crlId"));
            }
            call_ok(api, request_add_cert(options.signerCertB64), thr_resp, checker, "ADD_CERT");
        });
    }
    for (auto& it : writers) it.join();
    writers.clear();
    checker.check(list_crls_count(memory_api, checker, "LIST_CRLS") == options.countCrls + count_writers * extras_per_writer, "CRL count after concurrent adds");
    if (call_ok(memory_api, request_method("LIST_CERTS"), resp, checker, "LIST_CERTS")) {
        checker.check(json_array_get_count(json_object_get_array(resp.result, "certIds")) == 6, "the same certificate added by every writer must be stored once");
    }

    //  phase 2: every writer removes what it added (exclusive access, serialized with the readers)
    for (unsigned w = 0; w < count_writers; w++) {
        writers.emplace_back([&, w] {
            Api api(loader, memory.getHandle());
            Response thr_resp;
            for (const string& crl_id : crl_ids[w]) {
                call_ok(api, request_remove_crl(crl_id), thr_resp, checker, "REMOVE_CRL");
            }
        });
    }
    for (auto& it : writers) it.join();
    stop = true;
    for (auto& it : readers) it.join();
    checker.check(list_crls_count(memory_api, checker, "LIST_CRLS") == options.countCrls, "CRL count after concurrent removals");
    checker.check(count_reads > 0, "no reads");
    printf("    (%u writers x %zu CRLs added and removed concurrently, %u reads meanwhile)\n", count_writers, extras_per_writer, (unsigned)count_reads);
    memory_api.call(request_method("DEINIT"));
    checker.report("shared memory: concurrent writers on the shared memory with sessions reading it");
    return checker.passed();
}

//  Invalid handles, the method whitelist of a shared memory, free while sessions use it
static bool test_shared_memory_lifecycle (
        UapkiSessionLoader& loader,
        const Options& options,
        const SharedMemorySetup& setup
)
{
    Checker checker;
    Response resp;
    bool called;
    UapkiSession session(loader);
    UAPKI_SESSION_SHARED_MEMORY* bogus = reinterpret_cast<UAPKI_SESSION_SHARED_MEMORY*>(&checker);
    UAPKI_SESSION_SHARED_MEMORY* as_memory = reinterpret_cast<UAPKI_SESSION_SHARED_MEMORY*>(session.getHandle());

    Api api_bogus(loader, session.getHandle(), bogus);
    called = api_bogus.call(request_method("VERSION"), resp);
    checker.check(called && (resp.errorCode == ERR_INVALID_SHARED_MEMORY), "invalid shared memory handle: " + to_string(resp.errorCode));
    Api api_session_as_memory(loader, session.getHandle(), as_memory);
    called = api_session_as_memory.call(request_method("VERSION"), resp);
    checker.check(called && (resp.errorCode == ERR_INVALID_SHARED_MEMORY), "a session handle was accepted as shared memory: " + to_string(resp.errorCode));
    Api api_memory_bogus(loader, bogus);
    called = api_memory_bogus.call(request_method("VERSION"), resp);
    checker.check(called && (resp.errorCode == ERR_INVALID_SHARED_MEMORY), "invalid handle in shared memory process: " + to_string(resp.errorCode));

    UAPKI_SESSION_SHARED_MEMORY* memory = loader.sharedMemoryCreate();
    Api memory_api(loader, memory);
    checker.check(memory != nullptr, "shared memory not created");
    called = memory_api.call(request_open("x.p12", "x", "RO"), resp);
    checker.check(called && (resp.errorCode == ERR_NOT_ALLOWED), "storage method allowed on shared memory: " + to_string(resp.errorCode));
    called = memory_api.call(request_method("VERSION"), resp);
    checker.check(called && resp.ok(), "VERSION on shared memory");
    const bool prepared = call_ok(memory_api, request_init_caches(setup.certDir, setup.crlDir), resp, checker, "shared memory INIT");

    if (prepared) {   //  free while sessions keep reading: calls in flight complete, later calls are rejected
        const unsigned count_workers = (options.countSessions < 2) ? 2 : options.countSessions;
        atomic<bool> freed(false);
        atomic<unsigned> count_ok(0), count_invalid(0), count_finished(0);
        vector<thread> workers;
        for (unsigned t = 0; t < count_workers; t++) {
            workers.emplace_back([&] {
                UapkiSession thr_session(loader);
                Api api(loader, thr_session.getHandle(), memory);
                Response thr_resp;
                //  Call until rejected: a fixed number of calls could all finish before the free on a slow runner
                const chrono::steady_clock::time_point deadline = chrono::steady_clock::now() + chrono::seconds(REJECT_TIMEOUT_S);
                while (chrono::steady_clock::now() < deadline) {
                    if (!api.call(request_list_crls(), thr_resp)) {
                        checker.fail("no response while the shared memory is being freed");
                        break;
                    }
                    if (thr_resp.ok()) {
                        count_ok++;
                    }
                    else if (thr_resp.errorCode == ERR_INVALID_SHARED_MEMORY) {
                        checker.check(freed, "INVALID_SHARED_MEMORY before the free");
                        count_invalid++;
                        break;
                    }
                    else {
                        checker.fail("unexpected error while the shared memory is being freed: " + thr_resp.error);
                        break;
                    }
                }
                count_finished++;
            });
        }
        while ((count_ok < 3 * count_workers) && (count_finished < count_workers)) this_thread::yield();
        freed = true;
        loader.sharedMemoryFree(memory);
        for (auto& it : workers) it.join();
        checker.check(count_invalid == count_workers, "not every worker was rejected after the free");
    }
    loader.sharedMemoryFree(memory);
    called = memory_api.call(request_method("VERSION"), resp);
    checker.check(called && (resp.errorCode == ERR_INVALID_SHARED_MEMORY), "freed shared memory still answers");
    checker.report("shared memory lifecycle: invalid handles, method whitelist, free during calls");
    return checker.passed();
}

static unsigned parse_number (const char* text, const unsigned minValue, const unsigned maxValue)
{
    char* end = nullptr;
    const unsigned long value = strtoul(text, &end, 10);
    if ((end == text) || (*end != '\0') || (value < minValue) || (value > maxValue)) return UINT_MAX;
    return (unsigned)value;
}

static int show_usage (const char* msg)
{
    if (msg) puts(msg);
    puts("Usage: test-sessions <libName> [options]");
    puts("  --storage <file>     PKCS#12 storage for CAdES signing (default: test-diia.p12)");
    puts("  --password <pw>      storage password (default: testpassword)");
    puts("  --cert <file>        DER certificate of the storage key, added to every session (default: certs/diia-test-sign-7775603.cer)");
    puts("  --provider-dir <dir> directory of cm-pkcs12 (with trailing separator); used as a second spelling of the provider location");
    puts("  --sessions <N>       number of storages/sessions/threads (default: hardware threads)");
    puts("  --signs <M>          signatures per storage (default: 20)");
    puts("  --rsa-bits <bits>    key size of the generated RSA storages (default: 2048)");
    puts("  --crls <K>           number of synthetic CRLs in the shared memory benchmark (default: 200)");
    puts("  --crl-entries <R>    revoked entries per synthetic CRL (default: 2000)");
    puts("  --workdir <dir>      directory for generated storages (default: test-sessions-work)");
    puts("  --benchmark          run only the benchmark");
    puts("  --tests              run only the multithreading tests");
    return -1;
}

int main (int argc, char* argv[])
{
    if (argc < 2) return show_usage("Invalid count parameters");

    Options options;
    string cert_file = "certs/diia-test-sign-7775603.cer";
    options.libName = argv[1];
    for (int i = 2; i < argc; i++) {
        const string arg = argv[i];
        const bool has_value = (i + 1 < argc);
        if ((arg == "--storage") && has_value) options.storage = argv[++i];
        else if ((arg == "--password") && has_value) options.password = argv[++i];
        else if ((arg == "--cert") && has_value) cert_file = argv[++i];
        else if ((arg == "--provider-dir") && has_value) options.providerDir = argv[++i];
        else if ((arg == "--sessions") && has_value) options.countSessions = parse_number(argv[++i], 1, 1024);
        else if ((arg == "--signs") && has_value) options.countSigns = parse_number(argv[++i], 1, 100000);
        else if ((arg == "--rsa-bits") && has_value) options.rsaBits = parse_number(argv[++i], 1024, 4096);
        else if ((arg == "--crls") && has_value) options.countCrls = parse_number(argv[++i], 1, 100000);
        else if ((arg == "--crl-entries") && has_value) options.countCrlEntries = parse_number(argv[++i], 0, 1000000);
        else if ((arg == "--workdir") && has_value) options.workDir = argv[++i];
        else if (arg == "--benchmark") options.runTests = false;
        else if (arg == "--tests") options.runBenchmark = false;
        else return show_usage(("Unknown option: " + arg).c_str());
        if ((options.countSessions == UINT_MAX) || (options.countSigns == UINT_MAX) || (options.rsaBits == UINT_MAX)
            || (options.countCrls == UINT_MAX) || (options.countCrlEntries == UINT_MAX)) {
            return show_usage(("Invalid value for option " + arg).c_str());
        }
    }
    if (!options.runBenchmark && !options.runTests) return show_usage("Options --benchmark and --tests exclude each other");
    if (options.countSessions == 0) {
        options.countSessions = thread::hardware_concurrency();
        if (options.countSessions == 0) options.countSessions = 4;
    }

    options.signerCertB64 = read_file_base64(cert_file);
    if (options.signerCertB64.empty()) {
        return show_usage(("Can't read certificate '" + cert_file + "'").c_str());
    }

    UapkiSessionLoader loader;
    if (!loader.load(options.libName)) {
        return show_usage(("Can't load library '" + options.libName + "': " + UapkiSessionLoader::getDlError()).c_str());
    }
    if (!loader.isSessionsSupported()) {
        return show_usage("The library does not export the sessions API");
    }
    printf("Library '%s' loaded, sessions API is available\n", options.libName.c_str());

    (void)MAKE_DIR(options.workDir.c_str());
    vector<string> storages;
    for (unsigned i = 0; i < options.countSessions; i++) {
        const string copy = options.workDir + "/storage-" + to_string(i) + ".p12";
        if (!copy_file(options.storage, copy)) {
            return show_usage(("Can't copy storage '" + options.storage + "' to '" + copy + "'").c_str());
        }
        storages.push_back(copy);
    }

    SharedMemorySetup shared_setup;
    const string cert_source_dir = cert_file.substr(0, cert_file.find_last_of("/\\") + 1);
    if (!prepare_shared_memory_data(options, cert_source_dir, shared_setup)) {
        return show_usage("Can't prepare the shared memory test data");
    }

    bool ok = run_self_test(loader);
    if (options.runBenchmark) {
        ok = run_benchmark(loader, options, storages);
        ok = run_shared_memory_benchmark(loader, options, shared_setup) && ok;
    }

    if (options.runTests) {
        printf("\nMultithreading tests: %u sessions, %u signatures per session\n", options.countSessions, options.countSigns);
        Checker prepare;
        RsaStorages rsa;
        const chrono::steady_clock::time_point dt_start = chrono::steady_clock::now();
        prepare_rsa_storages(loader, options, rsa, prepare);
        prepare.report(("generate " + to_string(options.countSessions) + " RSA-" + to_string(options.rsaBits) + " storages with two keys each in parallel sessions (" + to_string((int)elapsed_ms(dt_start)) + " ms)").c_str());
        ok = prepare.passed() && ok;
        if (prepare.passed()) {
            const vector<function<bool (void)>> tests = {
                [&] { return test_session_isolation(loader, options, rsa); },
                [&] { return test_concurrent_methods_in_session(loader, options, rsa); },
                [&] { return test_legacy_and_sessions_mixed(loader, options, storages[0], rsa); },
                [&] { return test_session_lifecycle(loader, options, storages[0]); },
                [&] { return test_provider_sharing(loader, options, storages[0]); },
                [&] { return test_config_isolation(loader, options, storages[0]); },
                [&] { return test_shared_memory_layers(loader, options, shared_setup, storages[0]); },
                [&] { return test_shared_memory_autoinit(loader, options, shared_setup); },
                [&] { return test_shared_memory_gate(loader, options, shared_setup); },
                [&] { return test_shared_memory_whitelist(loader, shared_setup); },
                [&] { return test_shared_memory_concurrent_writers(loader, options, shared_setup); },
                [&] { return test_shared_memory_lifecycle(loader, options, shared_setup); },
            };
            for (const auto& it : tests) {
                ok = it() && ok;
            }
        }
        for (const auto& it : rsa.files) remove(it.c_str());
    }

    for (const auto& it : storages) remove(it.c_str());
    cleanup_shared_memory_data(shared_setup);
    (void)REMOVE_DIR(options.workDir.c_str());
    return ok ? 0 : 1;
}
