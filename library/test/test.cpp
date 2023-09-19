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
#include <stdint.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include "parson-helper.h"
#include "uapki-loader.h"

#ifdef _WIN32
 #include <windows.h>
 #define sleep_ms(ms) Sleep(ms)
#else
 #include <unistd.h>
 #define sleep_ms(ms) usleep((ms)*1000)
#endif


using namespace std;


static bool runTask (
        UapkiLoader& uapki,
        const string& method,
        JSON_Object* joParameter,
        const uint32_t countTasks,
        const string& completeMessage
)
{
    for (size_t itest = 0; itest < countTasks; itest++) {
        ParsonHelper json;
        string sjson_request;
        json.create();
        json.setString("method", method);
        if (joParameter) {
            JSON_Object* jo_dst = json.setObject("parameters");
            json_object_copy_all_items(jo_dst, joParameter);
        }
        json.serialize(sjson_request);
        if (sjson_request.empty()) return false;

        if ((itest == 0) || (itest == countTasks - 1)) {
            if (countTasks > 1) printf("Test[%zu]\n", itest);
            printf("Request:\n%s\n", sjson_request.c_str());
        }
        const chrono::time_point<chrono::high_resolution_clock> dt_start = chrono::high_resolution_clock::now();
        char* sjson_result = uapki.process(sjson_request.c_str());
        const chrono::duration<float> difference = chrono::high_resolution_clock::now() - dt_start;
        const int elapsed_time = static_cast<int>(1000 * difference.count());
        if ((itest == 0) || (itest == countTasks - 1)) {
            printf("%s - elapsed time: %dms\n", completeMessage.c_str(), elapsed_time);
            printf("Result:\n%s\n\n", sjson_result);
        }
        uapki.jsonFree(sjson_result);
    }
    return true;
}

static string readFile (
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
}

static int showUsage (
        const string& msg,
        const int ret
)
{
    puts(msg.c_str());
    puts("Usage: test <libName> <task.json>");
    return ret;
}

static atomic_int atomic_counter(0);

void thread_proc (
        UapkiLoader* uapki,
        uint32_t threadId,
        JSON_Array* jaTasks
)
{
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
        const bool skip_task = (json_object_get_boolean(jo_task, "skip") > 0);
        const uint32_t cnt_tasks = ParsonHelper::jsonObjectGetUint32(jo_task, "times", 1);
        if (s_method.empty() || skip_task || (cnt_tasks == 0)) {
            puts("Skipped task.");
            continue;
        }

        if (s_method[0] != '_') {
            const string s_completemsg = string("Thread ") + to_string(threadId)
                + string(" (counter: ") + to_string(localvar_ctr) + string(") completed task #") + to_string(i + 1);
            if (!runTask(
                *uapki,
                s_method,
                json_object_get_object(jo_task, "parameters"),
                cnt_tasks,
                s_completemsg
            )) break;
        }
        else if (s_method == string("_SLEEP_THREAD")) {
            const uint32_t ms = ParsonHelper::jsonObjectGetUint32(jo_task, "sleep", 0);
            if (ms > 0) {
                this_thread::sleep_for(chrono::milliseconds(ms));
            }
        }

        this_thread::sleep_for(chrono::milliseconds(50));
    }
}


int main (int argc, char *argv[])
{
    ParsonHelper::setEscapeSlashes(0);
    if (argc < 3) return showUsage("Test for library: invalid count parameters", -1);

    const string s_libname = string(argv[1]);
    UapkiLoader uapki;
    if (uapki.load(s_libname)) {
        printf("Test for library '%s'.\n", s_libname.c_str());
    }
    else {
        return showUsage(string("Can't load library '" + s_libname + "'"), -2);
    }

    const char* fn_task = argv[2];
    const string s_json = readFile(fn_task);
    if (s_json.empty()) return showUsage(string("Error read the task: " + string(fn_task)), -1);

    ParsonHelper json;
    if (!json.parse(s_json.c_str(), true)) return showUsage("Invalid JSON", -2);

    if (json.hasValue("comment")) {
        printf("Comment: '%s'\n", json.getString("comment"));
    }

    if (json.hasValue("locale")) {
        printf("Set locale: '%s'\n", setlocale(LC_NUMERIC, json.getString("locale")));
    }

    printf("hardware_concurrency: %d\n", thread::hardware_concurrency());
    vector<thread> threads;
    vector<uint32_t> threadIds;

    JSON_Array* ja_tasks = json.getArray("tasks");
    const size_t cnt_tasks = json_array_get_count(ja_tasks);
    for (size_t i = 0; i < cnt_tasks; i++) {
        printf("\nRun task #%d\n", (int)i + 1);
        JSON_Object* jo_task = json_array_get_object(ja_tasks, i);
        if (!jo_task) break;

        if (ParsonHelper::jsonObjectHasValue(jo_task, "comment")) {
            printf("Comment: '%s'\n", json_object_get_string(jo_task, "comment"));
        }

        string s_method = ParsonHelper::jsonObjectGetString(jo_task, "method");
        const bool skip_task = (json_object_get_boolean(jo_task, "skip") > 0);
        const uint32_t cnt_tasks = ParsonHelper::jsonObjectGetUint32(jo_task, "times", 1);
        if (s_method.empty() || skip_task || (cnt_tasks == 0)) {
            puts("Skipped task.");
            continue;
        }

        const string s_completemsg = string("Completed task #") + to_string(i + 1);
        if (s_method[0] != '_') {
            if (!runTask(
                uapki,
                s_method,
                json_object_get_object(jo_task, "parameters"),
                cnt_tasks,
                s_completemsg
            )) break;
        }
        else {
            if (s_method == string("_NEW_THREAD")) {
                const uint32_t thread_id = ParsonHelper::jsonObjectGetUint32(jo_task, "threadId", 0);
                JSON_Array* ja_tasks = json_object_get_array(jo_task, "tasks");
                if (thread_id > 0) {
                    thread thr(
                        thread_proc,
                        &uapki,
                        thread_id,
                        ja_tasks
                    );
                    threads.emplace_back(move(thr));
                    threadIds.push_back(thread_id);
                }
            }
            else if (s_method == string("_SLEEP_MAIN")) {
                const uint32_t ms = ParsonHelper::jsonObjectGetUint32(jo_task, "sleep", 0);
                if (ms > 0) {
                    sleep_ms(ms);
                }
            }
            else if (s_method == string("_WAIT_THREAD")) {
                const uint32_t thread_id = ParsonHelper::jsonObjectGetUint32(jo_task, "threadId", 0);
                for (size_t i = 0; i < threadIds.size(); i++) {
                    if (threadIds[i] == thread_id) {
                        threadIds[i] = 0;
                        threads[i].join();
                    }
                }
            }
            else if (s_method == string("_DIGEST")) {
                char s_hex[3] = { 0, 0, 0 };
                JSON_Object* jo_param = json_object_get_object(jo_task, "parameters");
                string str = ParsonHelper::jsonObjectGetString(jo_param, "text");
                uint64_t ptr64 = (uint64_t)(str.data());
                string str_ptr;
                str_ptr.resize(2 * sizeof(void*));
                for (size_t i = 0, j = str_ptr.size(); i < sizeof(void*); i++, j -= 2) {
                    sprintf(s_hex, "%02X", (uint8_t)(ptr64 >> (i * 8)));
                    str_ptr[j - 2] = s_hex[0];
                    str_ptr[j - 1] = s_hex[1];
                }

                json_object_set_string(jo_param, "ptr", str_ptr.c_str());
                ParsonHelper::jsonObjectSetUint64(jo_param, "size", str.length());
                if (!runTask(
                    uapki,
                    "DIGEST",
                    jo_param,
                    cnt_tasks,
                    s_completemsg
                )) break;
            }
        }
    }

    for (size_t i = 0; i < threadIds.size(); i++) {
        if (threadIds[i] > 0) {
            threads[i].join();
        }
    }

    return 0;
}
