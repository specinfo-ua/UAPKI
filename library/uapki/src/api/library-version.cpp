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

#define FILE_MARKER "uapki/api/library-version.cpp"

#include "api-json-internal.h"
#include "uapkic.h"
#include "uapkif.h"
#include <string>

#ifdef HAVE_RC_VERSION_H
#include "rc-version.h"
#else
 //  See uapki\CMakeLists.txt
#define STR_FILEVERSION "2.0.16"
#endif


static const char* LIB_NAME = "UAPKI";


using namespace std;


static string versionToStr (uint32_t version) {
    return to_string(version / 1000) + "." + to_string((version / 100) % 10) + "." + to_string(version % 100);
}

int uapki_version (JSON_Object* joParams, JSON_Object* joResult)
{
    (void)joParams;
    int ret = RET_OK;

    DO_JSON(json_object_set_string(joResult, "name", LIB_NAME));
    DO_JSON(json_object_set_string(joResult, "version", STR_FILEVERSION));
    DO_JSON(json_object_set_string(joResult, "uapkicVersion", versionToStr(UAPKIC_VERSION).c_str()));
    DO_JSON(json_object_set_string(joResult, "uapkifVersion", versionToStr(UAPKIF_VERSION).c_str()));

cleanup:
    return ret;
}
