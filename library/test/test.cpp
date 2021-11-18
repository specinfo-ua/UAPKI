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

#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "parson-helper.h"
#include "uapki-loader.h"

using namespace std;

static bool runTask(UapkiLoader& uapki, const char* method, JSON_Object* joParameter)
{
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

    printf("Request:\n%s\n", sjson_request.c_str());
    char* sjson_result = uapki.process(sjson_request.c_str());
    printf("Result:\n%s\n\n", sjson_result);
    uapki.jsonFree(sjson_result);
    return true;
}

static string readFile(const char* fileName)
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

static int showUsage(const char* msg, const int ret)
{
    puts(msg);
    puts("Usage: test <task.json>");
    return ret;
}


int main(int argc, char *argv[])
{
    ParsonHelper::setEscapeSlashes(0);
    if (argc < 2) return showUsage("Invalid count parameters", -1);

    const char* fn_task = argv[1];
    const string s_json = readFile(fn_task);
    if (s_json.empty()) return showUsage(string("Error read the task: " + string(fn_task)).c_str(), -1);

    ParsonHelper json;
    if (!json.parse(s_json.c_str(), true)) return showUsage("Invalid JSON", -1);

    if (json.hasValue("comment")) {
        printf("Comment: '%s'\n", json.getString("comment"));
    }

    if (json.hasValue("locale")) {
        printf("Set locale: '%s'\n", setlocale(LC_NUMERIC, json.getString("locale")));
    }

    UapkiLoader uapki;
    if (!uapki.load()) return showUsage("Can't load library", -2);

    JSON_Array* ja_tasks = json.getArray("tasks");
    const size_t cnt_tasks = json_array_get_count(ja_tasks);
    for (size_t i = 0; i < cnt_tasks; i++) {
        printf("\nRun task #%d\n", (int)i + 1);
        JSON_Object* jo_task = json_array_get_object(ja_tasks, i);
        if (!jo_task) break;

        if (ParsonHelper::jsonObjectHasValue(jo_task, "comment")) {
            printf("Comment: '%s'\n", json_object_get_string(jo_task, "comment"));
        }

        const char* method = json_object_get_string(jo_task, "method");
        const bool skip_task = (json_object_get_boolean(jo_task, "skip") > 0);
        if (!method || skip_task) {
            puts("Skipped task.");
            continue;
        }

        if (strcmp(method, "_DIGEST") != 0) {
            if (!runTask(uapki, method, json_object_get_object(jo_task, "parameters"))) break;
        }
        else {
            char s_hex[3] = { 0, 0, 0 };
            JSON_Object* jo_param = json_object_get_object(jo_task, "parameters");
            string str = ParsonHelper::jsonObjectGetString(jo_param, "text");
            uint64_t ptr64 = (uint64_t)(str.data());
            string str_ptr;
            str_ptr.resize(2 * sizeof(void*));
            for (size_t i = 0,  j = str_ptr.size(); i < sizeof(void*); i++, j -= 2) {
                sprintf(s_hex, "%02X", (uint8_t)(ptr64 >> (i * 8)));
                str_ptr[j - 2] = s_hex[0];
                str_ptr[j - 1] = s_hex[1];
            }

            json_object_set_string(jo_param, "ptr", str_ptr.c_str());
            ParsonHelper::jsonObjectSetUint64(jo_param, "size", str.length());
            if (!runTask(uapki, "DIGEST", jo_param)) break;
        }
    }

    return 0;
}
