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

#define FILE_MARKER "common/pkix/ba-utils.c"

#include <stdarg.h>
#include "ba-utils.h"
#include "macros-internal.h"
#include "uapki-errors.h"

#if defined _WIN32
#include <windows.h>
#endif

bool ba_is_equals(ByteArray *expected, ByteArray *actual)
{
    if (expected == actual) {
        return true;
    }

    return (ba_cmp(expected, actual) == 0);
}

void ba_free_many(int num, ...)
{
    int i;
    va_list args;

    va_start(args, num);
    for (i = 0; i < num; i++) {
        ba_free(va_arg(args, ByteArray *));
    }
    va_end(args);
}

int ba_print(FILE *stream, const ByteArray *ba)
{
    int ret = RET_OK;

    CHECK_PARAM(stream != NULL);

    size_t j = 0;
    const uint8_t *u8 = ba_get_buf_const(ba);
    size_t len = ba_get_len(ba);
    for (j = 0; j < len; j++) {
        DO(fprintf(stream, "%02X", u8[j]) > 0 ? RET_OK : RET_UAPKI_FILE_WRITE_ERROR);
        fflush(stream);
    }
    fprintf(stream, "\n");
    fflush(stream);

cleanup:
    return ret;
}


#ifdef _WIN32
static wchar_t* utf8_to_wchar(const char* in)
{
    int ret = RET_OK;
    wchar_t* wout = NULL;
    int res_len = MultiByteToWideChar(CP_UTF8, 0, in, -1, 0, 0);
    if (!res_len) {
        return NULL;
    }

    MALLOC_CHECKED(wout, res_len * sizeof(wchar_t));
    res_len = MultiByteToWideChar(CP_UTF8, 0, in, -1, wout, res_len);
    if (!res_len) {
        free(wout);
        return NULL;
    }

cleanup:
    return wout;
}
#endif


FILE* fopen_utf8(char const * utf8path, const int is_writemode)
{
    FILE* rv_f = NULL;

#ifdef _WIN32
    {
        wchar_t* ws_path = utf8_to_wchar(utf8path);
        if (ws_path != NULL) {
            _wfopen_s(&rv_f, ws_path, (is_writemode ? L"wb" : L"rb"));
            free(ws_path);
        }
    }
#elif defined(__linux__) || defined(__APPLE__) || defined(__GNUC__)
    rv_f = fopen(utf8path, (is_writemode ? "wb" : "rb"));
#else
#error Unsupported platform
#endif

    return rv_f;
}

int ba_alloc_from_file(const char * utf8path, ByteArray **out)
{
    FILE *p_file = NULL;
    size_t file_size;
    size_t result;
    ByteArray *ba = NULL;
    int ret = RET_OK;

    CHECK_PARAM(utf8path != NULL);
    CHECK_PARAM(out != NULL);

    p_file = fopen_utf8(utf8path, 0);
    if (!p_file) {
        SET_ERROR(RET_UAPKI_FILE_OPEN_ERROR);
    }

    fseek(p_file, 0, SEEK_END);
    file_size = ftell(p_file);
    rewind(p_file);

    if (file_size == (file_size) - 1L) {
        SET_ERROR(RET_UAPKI_FILE_GET_SIZE_ERROR);
    }

    CHECK_NOT_NULL(ba = ba_alloc_by_len(file_size));

    result = fread(ba_get_buf(ba), 1, file_size, p_file);
    if (result != file_size) {
        SET_ERROR(RET_UAPKI_FILE_READ_ERROR);
    }

    *out = ba;
    ba = NULL;

cleanup:

    if (p_file) {
        fclose(p_file);
    }

    ba_free(ba);

    return ret;
}

int ba_to_file(const ByteArray * ba, const char * utf8path)
{
    int ret = RET_OK;
    FILE *pFile = NULL;
    size_t result;

    CHECK_PARAM(ba != NULL);
    CHECK_PARAM(utf8path != NULL);

    pFile = fopen_utf8(utf8path, 1);

    if (!pFile) {
        SET_ERROR(RET_UAPKI_FILE_OPEN_ERROR);
    }

    result = fwrite(ba_get_buf_const(ba), sizeof(uint8_t), ba_get_len(ba), pFile);
    if (result != ba_get_len(ba)) {
        SET_ERROR(RET_UAPKI_FILE_WRITE_ERROR);
    }

cleanup:

    if (pFile) {
        fclose(pFile);
    }

    return ret;
}

int delete_file(const char * utf8path)
{
    int r = -1;

#ifdef _WIN32
    {
        wchar_t* ws_path = utf8_to_wchar(utf8path);
        if (ws_path != NULL) {
            r = _wremove(ws_path);
            free(ws_path);
        }
    }
#elif defined(__linux__) || defined(__APPLE__) || defined(__GNUC__)
    r = remove(utf8path);
#else
#error Unsupported platform
#endif

    return (r == 0) ? RET_OK : RET_UAPKI_FILE_DELETE_ERROR;
}
