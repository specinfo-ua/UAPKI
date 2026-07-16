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

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <stddef.h>
#include <stdint.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <atomic>
#include <chrono>
#include <iostream>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>
#include <vector>
#include "parson-helper.h"
#include "uapki-loader.h"

#ifdef _WIN32
 #include <windows.h>
 #define SLEEP_MS(ms) Sleep((DWORD)ms)
#else
 #include <unistd.h>
 #define SLEEP_MS(ms) usleep((ms)*1000)
#endif


using namespace std;


enum class ActionByError {
    Undefined = 0,
    NoError,
    Ignore,
    Close,
    PromptClose,
    PromptStop,
    Stop,
};  //  end enum class ActionByError


static bool json_to_pretty (const char* sJsonIn, const bool withComments, string& strJsonOut);


struct Logger {
    FILE*   f;
    const char*
            fileName;
    bool    prettyEnabled;
    bool    elapsedTimeEnabled;
    Logger (void)
        : f(nullptr)
        , fileName(nullptr)
        , prettyEnabled(false)
        , elapsedTimeEnabled(false)
    {}
    ~Logger () {
        if (f) {
            fclose(f);
            f = nullptr;
            printf("Log file '%s' closed.\n", fileName);
        }
    }
    void open (void) {
        if (fileName) {
            f = fopen(fileName, "a");
        }
        if (f) printf("Log file '%s' opened.\n", fileName);
    }
    void addJson (const char* jsonLine) {
        if (!f) return;
        string s_jsonpretty;
        if (prettyEnabled && json_to_pretty(jsonLine, true, s_jsonpretty)) {
            addLine(s_jsonpretty);
        }
        else {
            addLine(jsonLine);
        }
    }
    void addLine (const char* line, bool con = false) {
        if (con) printf("%s", line);
        if (f) fprintf(f, "%s", line);
    }
    void addLine (const string& line, bool con = false) {
        if (con) printf("%s", line.c_str());
        if (f) fprintf(f, "%s", line.c_str());
    }
    void flush (void) {
        if (f) fflush(f);
    }
};

struct LogError {
    string  method;
    int     errCode;
    string  error;
    string  taskMsg;
};  //  end struct LogError

static vector<LogError> log_errors;


static ActionByError actionbyerr_from_str (
        const string& actionByErr
)
{
    ActionByError rv = ActionByError::Ignore;
    if ((actionByErr == "") || (actionByErr == "IGNORE")) {
        //  nothing
    }
    else if (actionByErr == "CLOSE") {
        rv = ActionByError::Close;
    }
    else if (actionByErr == "?CLOSE") {
        rv = ActionByError::PromptClose;
    }
    else if (actionByErr == "?STOP") {
        rv = ActionByError::PromptStop;
    }
    else if (actionByErr == "STOP") {
        rv = ActionByError::Stop;
    }
    return rv;
}   //  actionbyerr_from_str


static bool base64_decode (
        const uint8_t* in,
        size_t inlen,
        vector<uint8_t>& out
)
{
    static const uint8_t base64map[256] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255,  62, 255, 255, 255,  63,
    52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255,
    255, 254, 255, 255, 255,   0,   1,   2,   3,   4,   5,   6,
    7,   8,   9,  10,  11,  12,  13,  14,  15,  16,  17,  18,
    19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255, 255,
    255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,
    37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
    49,  50,  51, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255 };

    size_t t, x, y, z;
    uint8_t c;
    int g = 3;

    out.resize(inlen);
    for (x = y = z = t = 0; x < inlen; x++) {
        c = base64map[in[x] & 0xFF];
        if (c == 255) continue;

        if (c == 254) {
            c = 0;
            if (--g < 0) return false;
        }
        else if (g != 3) return false;

        t = (t << 6) | c;

        if (++y == 4) {
            if (z + g > out.size()) return false;
            out[z++] = (uint8_t)((t >> 16) & 255);
            if (g > 1) out[z++] = (uint8_t)((t >> 8) & 255);
            if (g > 2) out[z++] = (uint8_t)(t & 255);
            y = t = 0;
        }
    }
    if (y != 0) return false;

    out.resize(z);
    return true;
}   //  base64_decode

static string contentptr_to_hexptr (
        JSON_Object* joParam,
        vector<uint8_t>& buf
)
{
    string rv_strptr;
    string str = ParsonHelper::jsonObjectGetString(joParam, "contentHex");
    if (!str.empty()) {
        for (size_t i = 0; i < str.length(); i += 2) {
            const string s_hex = str.substr(i, 2);
            buf.push_back((uint8_t)strtol(s_hex.c_str(), NULL, 16));
        }
    }
    else {
        str = ParsonHelper::jsonObjectGetString(joParam, "contentText");
        for (const auto& it : str) {
            buf.push_back(it);
        }
    }

    char s_hex[3] = { 0, 0, 0 };
    uint64_t ptr64 = (uint64_t)(buf.data());
    rv_strptr.resize(2 * sizeof(void*));
    for (size_t i = 0, j = rv_strptr.size(); i < sizeof(void*); i++, j -= 2) {
        snprintf(s_hex, sizeof(s_hex), "%02X", (uint8_t)(ptr64 >> (i * 8)));
        rv_strptr[j - 2] = s_hex[0];
        rv_strptr[j - 1] = s_hex[1];
    }
    return rv_strptr;
}   //  contentptr_to_hexptr

static bool json_to_pretty (
        const char* sJsonIn,
        const bool withComments,
        string& strJsonOut
)
{
    JSON_Value* jv_root = (withComments) ? json_parse_string_with_comments(sJsonIn) : json_parse_string(sJsonIn);
    if (!jv_root) return false;

    bool rv_ok = false;
    const size_t size = json_serialization_size_pretty(jv_root);
    strJsonOut.clear();
    if (size > 0) {
        strJsonOut.resize(size - 1);
        if (!strJsonOut.empty()) {
            rv_ok = (json_serialize_to_buffer_pretty(jv_root, (char*)strJsonOut.data(), size) == JSONSuccess);
            if (!rv_ok) {
                strJsonOut.clear();
            }
        }
    }

    json_value_free(jv_root);
    return rv_ok;

}   //  json_to_pretty

static bool prompt_action (void)
{
    string s_submit;
    printf("For continue test enter YES|yes|+|Y|y: ");
    getline(cin, s_submit);
    if ((s_submit == "YES") || (s_submit == "yes") || (s_submit == "Y") || (s_submit == "y") || (s_submit == "+")) {
        return true;
    }
    return false;
}   //  prompt_action

static void save_file (
        const string& fileName,
        const string& b64value
)
{
    vector<uint8_t> buf;
    if (!base64_decode((const uint8_t*)b64value.data(), b64value.size(), buf)) return;

    FILE* f = fopen(fileName.c_str(), "wb");
    if (f) {
        if (fwrite(buf.data(), 1, buf.size(), f) == buf.size()) {
            printf("Result saved to file %s\n", fileName.c_str());
        }
        fclose(f);
    }
}   //  save_file

static const char* dir_saveresult = nullptr;

static void save_result (
        const string& saveResult,
        JSON_Object* joResponse
)
{
    if (saveResult.empty() || !joResponse) return;

    string fn_saveresult;
    if (dir_saveresult) fn_saveresult = string(dir_saveresult);
    fn_saveresult += saveResult;

    if (ParsonHelper::jsonObjectGetInt32(joResponse, "errorCode") == 0) {
        const string s_method = ParsonHelper::jsonObjectGetString(joResponse, "method");
        JSON_Object* jo_result = json_object_get_object(joResponse, "result");
        if ((s_method == "DIGEST") || (s_method == "ENCRYPT") || (s_method == "GENERATE_CERTBUNDLE") ||
            (s_method == "GET_CERT") || (s_method == "GET_CSR") || (s_method == "MODIFY_CMS")
        ) {
            const string b64_bytes = ParsonHelper::jsonObjectGetString(jo_result, "bytes");
            if (!b64_bytes.empty()) {
                save_file(fn_saveresult, b64_bytes);
            }
        }
        else if (s_method == "SIGN") {
            JSON_Array* ja_signatures = json_object_get_array(jo_result, "signatures");
            for (size_t i = 0; i < json_array_get_count(ja_signatures); i++) {
                JSON_Object* jo_signature = json_array_get_object(ja_signatures, i);
                const string id = ParsonHelper::jsonObjectGetString(jo_signature, "id");
                const string b64_bytes = ParsonHelper::jsonObjectGetString(jo_signature, "bytes");
                if (!id.empty() && !b64_bytes.empty()) {
                    save_file(fn_saveresult + "-" + id + ".p7s", b64_bytes);
                }
            }
        }
        else if ((s_method == "BUILD_CMS_2PASS") || (s_method == "BUILD_CSR_2PASS")) {
            JSON_Object* jo_step = json_object_get_object(jo_result, "step1");
            if (jo_step) {
                const string b64_bytes = ParsonHelper::jsonObjectGetString(jo_step, "bytes");
                if (!b64_bytes.empty()) {
                    save_file(fn_saveresult + "-step1.der", b64_bytes);
                }
            }
            jo_step = json_object_get_object(jo_result, "step2");
            if (jo_step) {
                const string b64_bytes = ParsonHelper::jsonObjectGetString(jo_step, "bytes");
                if (!b64_bytes.empty()) {
                    save_file(fn_saveresult, b64_bytes);
                }
            }
        }
    }
}   //  save_result

static bool run_task (
        UapkiLoader& uapki,
        Logger& log,
        JSON_Object* joTask,
        const string& completeMessage,
        ActionByError& actionByError
)
{
    const string s_method = ParsonHelper::jsonObjectGetString(joTask, "method");
    const size_t cnt_tasks = (size_t)ParsonHelper::jsonObjectGetUint32(joTask, "times", 1);
    JSON_Object* jo_params = json_object_get_object(joTask, "parameters");
    actionByError = actionbyerr_from_str(ParsonHelper::jsonObjectGetString(joTask, "actionByError"));
    const uint32_t sleep_ms = (size_t)ParsonHelper::jsonObjectGetUint32(joTask, "sleep", 0);

    for (size_t itest = 0; itest < cnt_tasks; itest++) {
        ParsonHelper json_req;
        string sjson_request;
        json_req.create();
        json_req.setString("method", s_method);
        if (jo_params) {
            JSON_Object* jo_dst = json_req.setObject("parameters");
            json_object_copy_all_items(jo_dst, jo_params);
        }
        json_req.serialize(sjson_request);
        if (sjson_request.empty()) return false;

        if ((itest == 0) || (itest == cnt_tasks - 1)) {
            if (cnt_tasks > 1) printf("Test[%zu]\n", itest);
            printf("Request:\n%s\n", sjson_request.c_str());
            if (log.f) {
                log.addLine("Request:\n");
                log.addJson(sjson_request.c_str());
                log.addLine("\n");
                log.flush();
            }
        }

        const chrono::time_point<chrono::high_resolution_clock> dt_start = chrono::high_resolution_clock::now();
        char* sjson_result = uapki.process(sjson_request.c_str());
        const chrono::duration<float> difference = chrono::high_resolution_clock::now() - dt_start;
        const int elapsed_time = static_cast<int>(1000 * difference.count());

        ParsonHelper json_resp;
        if (sjson_result && json_resp.parse(sjson_result)) {
            const int err_code = json_resp.getInt("errorCode");
            if (err_code == 0) {
                actionByError = ActionByError::NoError;
            }
            else {
                log_errors.push_back(LogError{
                    ParsonHelper::jsonObjectGetString(json_resp.rootObject(), "method"),
                    err_code,
                    json_resp.getString("error"),
                    completeMessage
                });
            }
        }
        else {
            actionByError = ActionByError::Undefined;
        }

        if ((itest == 0) && (cnt_tasks ==  1)) {
            if ((s_method == "BUILD_CMS_2PASS") || (s_method == "BUILD_CSR_2PASS") ||
                (s_method == "DIGEST") || (s_method == "ENCRYPT") || (s_method == "GENERATE_CERTBUNDLE") ||
                (s_method == "GET_CERT") || (s_method == "GET_CSR") || (s_method == "MODIFY_CMS") ||
                (s_method == "SIGN")
            ) {
                save_result(ParsonHelper::jsonObjectGetString(joTask, "saveResult"), json_resp.rootObject());
            }
        }

        if ((itest == 0) || (itest == cnt_tasks - 1)) {
            printf("%s - elapsed time: %dms\n", completeMessage.c_str(), elapsed_time);
            printf("Result:\n%s\n\n", sjson_result);
            if (log.f) {
                if (log.elapsedTimeEnabled) {
                    fprintf(log.f, "%s - elapsed time: %dms\n", completeMessage.c_str(), elapsed_time);
                }
                else {
                    fprintf(log.f, "%s\n", completeMessage.c_str());
                }
                log.addLine("Result:\n");
                log.addJson(sjson_result);
                log.addLine("\n\n");
                log.flush();
            }
        }
        uapki.jsonFree(sjson_result);
    }

    if (sleep_ms > 0) {
        SLEEP_MS(sleep_ms);
    }
    return true;
}   //  run_task

static string read_file (
        const char* fileName
)
{
    string rv_s;
    FILE* f = fopen(fileName, "rb");
    if (f == nullptr) return rv_s;

    fseek(f, 0, SEEK_END);
    const size_t file_size = static_cast<size_t>(ftell(f));
    fseek(f, 0, SEEK_SET);
    rv_s.resize(file_size);

    if (fread((void*)rv_s.data(), sizeof(char), file_size, f) != file_size) {
        rv_s.clear();
    }
    fclose(f);
    return rv_s;
}   //  read_file

static int show_usage (
        const string& msg,
        const int ret
)
{
    puts(msg.c_str());
    puts("Usage: test <libName> <task.json>");
    return ret;
}   //  show_usage

static atomic_int atomic_counter(0);

void thread_proc (
        UapkiLoader* uapki,
        uint32_t threadId,
        JSON_Array* jaTasks
)
{
    Logger log;
    const size_t cnt_tasks = json_array_get_count(jaTasks);
    for (size_t i = 0; i < cnt_tasks; i++) {
        JSON_Object* jo_task = json_array_get_object(jaTasks, i);
        int localvar_ctr = ++atomic_counter;
        printf("Thread %u (counter: %d) run task #%zu\n\n", threadId, localvar_ctr, i + 1);

        if (!jo_task) break;

        if (ParsonHelper::jsonObjectHasValue(jo_task, "comment")) {
            printf("Comment: '%s'\n", json_object_get_string(jo_task, "comment"));
        }

        string s_method = ParsonHelper::jsonObjectGetString(jo_task, "method");
        const bool skip_task = ParsonHelper::jsonObjectGetBoolean(jo_task, "skip", false);
        const uint32_t cnt_times = ParsonHelper::jsonObjectGetUint32(jo_task, "times", 1);
        if (s_method.empty() || skip_task || (cnt_times == 0)) {
            puts("Skipped task.");
            continue;
        }

        if (s_method[0] != '_') {
            ActionByError actionby_err = ActionByError::Undefined;
            const string s_completemsg = string("Thread ") + to_string(threadId)
                + string(" (counter: ") + to_string(localvar_ctr) + string(") completed task #") + to_string(i + 1);
            if (!run_task(*uapki, log, jo_task, s_completemsg, actionby_err)) break;
        }
        else if (s_method == string("_SLEEP_THREAD")) {
            const uint32_t sleep_ms = ParsonHelper::jsonObjectGetUint32(jo_task, "sleep", 0);
            if (sleep_ms > 0) {
                this_thread::sleep_for(chrono::milliseconds(sleep_ms));
            }
        }

        this_thread::sleep_for(chrono::milliseconds(50));
    }
}   //  thread_proc

int main (int argc, char *argv[])
{
    ParsonHelper::setEscapeSlashes(0);
    if (argc < 3) return show_usage("Test for library: invalid count parameters", -1);

    const string s_libname = string(argv[1]);
    UapkiLoader uapki;
    if (uapki.load(s_libname)) {
        printf("Test for library '%s'.\n", s_libname.c_str());
    }
    else {
        string s_msg = UapkiLoader::getDlError();
#if defined(_WIN32) || defined(__WINDOWS__)
        if (!s_msg.empty()) {
            const int err = ::stoi(s_msg);
            s_msg = ::system_category().message(err) + string(" (code: ") + s_msg + ")";
        }
#endif
        return show_usage(string("Can't load library '") + s_libname + "'\nError=" + s_msg, -2);
    }

    const char* fn_task = argv[2];
    const string s_json = read_file(fn_task);
    if (s_json.empty()) return show_usage(string("Error read the task: " + string(fn_task)), -1);

    ParsonHelper json;
    if (!json.parse(s_json.c_str(), true)) return show_usage("Invalid JSON", -2);

    if (json.hasValue("comment")) {
        printf("Comment: '%s'\n", json.getString("comment"));
    }

    if (json.hasValue("locale")) {
        printf("Set locale: '%s'\n", setlocale(LC_NUMERIC, json.getString("locale")));
    }

    dir_saveresult = json.getString("saveResultDir");

    Logger log;
    log.fileName = (argc >= 4) ? argv[3] : nullptr;
    log.prettyEnabled = json.getBoolean("logPretty", true);
    log.elapsedTimeEnabled = json.getBoolean("logElapsedTime", false);
    log.open();

    printf("hardware_concurrency: %d\n", thread::hardware_concurrency());
    vector<thread> threads;
    vector<uint32_t> threadIds;

    JSON_Array* ja_tasks = json.getArray("tasks");
    const size_t cnt_tasks = json_array_get_count(ja_tasks);
    log_errors.reserve(cnt_tasks);
    for (size_t i = 0; i < cnt_tasks; i++) {
        printf("\nRun task #%d\n", (int)i + 1);
        JSON_Object* jo_task = json_array_get_object(ja_tasks, i);
        if (!jo_task) break;

        if (ParsonHelper::jsonObjectHasValue(jo_task, "comment")) {
            printf("Comment: '%s'\n", json_object_get_string(jo_task, "comment"));
        }

        const string s_method = ParsonHelper::jsonObjectGetString(jo_task, "method");
        const bool skip_task = ParsonHelper::jsonObjectGetBoolean(jo_task, "skip", false);
        const uint32_t cnt_times = ParsonHelper::jsonObjectGetUint32(jo_task, "times", 1);
        if (s_method.empty() || skip_task || (cnt_times == 0)) {
            puts("Skipped task.");
            continue;
        }

        ActionByError actionby_err = ActionByError::Undefined;
        const string s_completemsg = string("Completed task #") + to_string(i + 1);
        if (s_method[0] != '_') {
            if (!run_task(uapki, log, jo_task, s_completemsg, actionby_err)) break;
        }
        else {
            if (s_method == string("_NEW_THREAD")) {
                const uint32_t thread_id = ParsonHelper::jsonObjectGetUint32(jo_task, "threadId", 0);
                JSON_Array* ja_newthrtasks = json_object_get_array(jo_task, "tasks");
                if (thread_id > 0) {
                    thread thr(
                        thread_proc,
                        &uapki,
                        thread_id,
                        ja_newthrtasks
                    );
                    threads.emplace_back(std::move(thr));
                    threadIds.push_back(thread_id);
                }
            }
            else if (s_method == string("_SLEEP_MAIN")) {
                const uint32_t sleep_ms = ParsonHelper::jsonObjectGetUint32(jo_task, "sleep", 0);
                if (sleep_ms > 0) {
                    SLEEP_MS(sleep_ms);
                }
            }
            else if (s_method == string("_WAIT_THREAD")) {
                const uint32_t thread_id = ParsonHelper::jsonObjectGetUint32(jo_task, "threadId", 0);
                for (size_t j = 0; j < threadIds.size(); j++) {
                    if (threadIds[j] == thread_id) {
                        threadIds[j] = 0;
                        threads[j].join();
                    }
                }
            }
            else if (
                (s_method == string("_DIGEST")) ||
                (s_method == string("_SIGN")) ||
                (s_method == string("_VERIFY"))
            ) {
                vector<uint8_t> local_buf;
                JSON_Object* jo_param = json_object_get_object(jo_task, "parameters");
                if (s_method == string("_DIGEST")) {
                    string str_ptr = contentptr_to_hexptr(jo_param, local_buf);
                    json_object_set_string(jo_param, "ptr", str_ptr.c_str());
                    ParsonHelper::jsonObjectSetUint64(jo_param, "size", local_buf.size());
                }
                else if (s_method == string("_SIGN")) {
                    JSON_Array* ja_datatbs = json_object_get_array(jo_param, "dataTbs");
                    JSON_Object* jo_tbs = json_array_get_object(ja_datatbs, 0);
                    string str_ptr = contentptr_to_hexptr(jo_tbs, local_buf);
                    json_object_set_string(jo_tbs, "ptr", str_ptr.c_str());
                    ParsonHelper::jsonObjectSetUint64(jo_tbs, "size", local_buf.size());
                }
                else if (s_method == string("_VERIFY")) {
                    JSON_Object* jo_subparam = json_object_get_object(jo_param, "signature");
                    string str_ptr = contentptr_to_hexptr(jo_subparam, local_buf);
                    json_object_set_string(jo_subparam, "ptr", str_ptr.c_str());
                    ParsonHelper::jsonObjectSetUint64(jo_subparam, "size", local_buf.size());
                }

                json_object_set_string(jo_task, "method", s_method.substr(1).c_str());

                if (!run_task(uapki, log, jo_task, s_completemsg, actionby_err)) break;
            }
        }

        if (actionby_err == ActionByError::Close) {
            log.addLine("\n*** CLOSE AND STOP TEST BY ERROR ***\n\n", true);
            json_array_append_value(ja_tasks, json_value_init_object());
            JSON_Object* jo_taskclose = json_array_get_object(ja_tasks, cnt_tasks);
            if (jo_taskclose) {
                json_object_set_string(jo_taskclose, "method", "CLOSE");
                run_task(uapki, log, jo_taskclose, s_completemsg, actionby_err);
            }
            break;
        }
        else if (actionby_err == ActionByError::PromptClose) {
            if (prompt_action()) {
                log.addLine("\n*** CONTINUE TEST AFTER ERROR ***\n\n", true);
            }
            else {
                log.addLine("\n*** CLOSE AND STOP TEST BY ERROR (AFTER PROMPT) ***\n\n", true);
                json_array_append_value(ja_tasks, json_value_init_object());
                JSON_Object* jo_taskclose = json_array_get_object(ja_tasks, cnt_tasks);
                if (jo_taskclose) {
                    json_object_set_string(jo_taskclose, "method", "CLOSE");
                    run_task(uapki, log, jo_taskclose, s_completemsg, actionby_err);
                }
                break;
            }
        }
        else if (actionby_err == ActionByError::PromptStop) {
            if (prompt_action()) {
                log.addLine("\n*** CONTINUE TEST AFTER ERROR ***\n\n", true);
            }
            else {
                log.addLine("\n*** STOP TEST BY ERROR (AFTER PROMPT) ***\n\n", true);
                break;
            }
        }
        else if (actionby_err == ActionByError::Stop) {
            log.addLine("\n*** STOP TEST BY ERROR ***\n\n", true);
            break;
        }
    }

    if (log_errors.empty()) {
        log.addLine(string("Completed ") + to_string(cnt_tasks) + string(" tasks WITHOUT registered ERRORS\n"), true);
    }
    else {
        log.addLine(string("Completed ") + to_string(cnt_tasks) + string(" tasks with registered ERRORS: " + to_string(log_errors.size()) + string("\n")), true);
        for (size_t i = 0; i < log_errors.size(); i++) {
            const LogError& log_err = log_errors[i];
            printf("Error[%zu]: method='%s' errorCode=%d (0x%04X) error='%s'\n",
                i + 1, log_err.method.c_str(), log_err.errCode, (uint32_t)log_err.errCode, log_err.error.c_str());
            printf("  taskMsg='%s'\n",  log_err.taskMsg.c_str());
            if (log.f) {
                fprintf(log.f, "Error[%zu]: method='%s' errorCode=%d (0x%04X) error='%s'\n",
                    i + 1, log_err.method.c_str(), log_err.errCode, (uint32_t)log_err.errCode, log_err.error.c_str());
                fprintf(log.f, "  taskMsg='%s'\n", log_err.taskMsg.c_str());
            }
        }
    }

    for (size_t i = 0; i < threadIds.size(); i++) {
        if (threadIds[i] > 0) {
            threads[i].join();
        }
    }

    //  non-zero exit code when any task registered an error - lets CI and
    //  scripts detect failures instead of parsing the output
    return (log_errors.empty()) ? 0 : 1;
}
