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

#include "iconv-utils.h"
#include "uapkif.h"
#include "macros-internal.h"


#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#include <iconv.h>
#endif


char* utf8_to_cp1251 (const char * in)
{
#ifdef _WIN32
    wchar_t* wout = NULL;
    char* out = NULL;
    int res_len = 0;

    res_len = MultiByteToWideChar(CP_UTF8, 0, in, -1, 0, 0);
    if (!res_len) {
        return NULL;
    }

    wout = malloc(res_len * sizeof(wchar_t));

    res_len = MultiByteToWideChar(CP_UTF8, 0, in, -1, wout, res_len);
    if (!res_len) {
        free(wout);
        return NULL;
    }

    res_len = WideCharToMultiByte(1251, 0, (LPCWSTR)wout, -1, 0, 0, 0, 0);
    if (!res_len) {
        free(wout);
        return NULL;
    }

    out = malloc(res_len * sizeof(char));
    res_len = WideCharToMultiByte(1251, 0, (LPCWSTR)wout, -1, out, res_len, 0, 0);
    if (!res_len) {
        free(wout);
        free(out);
        return NULL;
    }

    return out;
#elif defined(__linux__) || defined(__APPLE__) || defined(__unix__)
    size_t in_len = strlen(in);
    size_t out_len = 2 * in_len + 1;
    char* out = (char*)malloc(out_len);
    size_t _out_len = 2 * in_len;
    char* _out = out;
    iconv_t cd;

    cd = iconv_open("CP1251", "UTF-8");

    if (cd == (iconv_t)(-1) || iconv(cd, (char**)&in, &in_len, &_out, &_out_len) == (size_t)-1) {
        free(out);
        out = NULL;
    }
    else {
        *_out = '\0';
    }

    iconv_close(cd);

    return out;
#else
#error Unsupported platform
#endif
}   //  utf8_to_cp1251

int utf8_to_utf16be (const char * in, unsigned char ** out, size_t * out_len)
{
    int ret = RET_OK;

    CHECK_PARAM(in);
    CHECK_PARAM(out);
    CHECK_PARAM(out_len);

#ifdef _WIN32

    wchar_t* wout = NULL;
    int wchar_len = 0;
    int i;

    wchar_len = MultiByteToWideChar(CP_UTF8, 0, in, -1, 0, 0);
    if (!wchar_len) {
        SET_ERROR(RET_INVALID_UTF8_STR);
    }

    MALLOC_CHECKED(wout, wchar_len * sizeof(wchar_t));

    wchar_len = MultiByteToWideChar(CP_UTF8, 0, in, -1, wout, wchar_len);
    if (!wchar_len) {
        SET_ERROR(RET_INVALID_UTF8_STR);
    }

    *out_len = wchar_len * 2;
    MALLOC_CHECKED(*out, (*out_len) * sizeof(char));

    /* LE to BE  UTF-16 */
    for (i = 0; i < wchar_len; i++) {
        (*out)[2 * i] = wout[i] >> 8;
        (*out)[2 * i + 1] = wout[i] & 0xff;
    }

    free(wout);

#elif defined(__linux__) || defined(__APPLE__) || defined(__GNUC__)
    size_t in_len = strlen(in) + 1;
    char* _out = (char*)malloc(2 * in_len);
    size_t _out_len = 2 * in_len;
    char* _out_ptr = _out;
    iconv_t cd;

    if (_out == NULL) {
        SET_ERROR(RET_MEMORY_ALLOC_ERROR);
    }

    cd = iconv_open("UTF-16BE", "UTF-8");

    if (cd == (iconv_t)(-1) || iconv(cd, (char**)&in, &in_len, &_out_ptr, &_out_len) == (size_t)-1) {
        free(_out);
        _out = NULL;
        _out_len = 0;
        SET_ERROR(RET_INVALID_UTF8_STR);
    }

    *out = (unsigned char*)_out;
    *out_len = (size_t)(_out_ptr - _out);

    iconv_close(cd);

#else
#error Unsupported platform
#endif
cleanup:
    return ret;
}   //  utf8_to_utf16be

int utf16be_to_utf8 (const unsigned char * in, size_t in_len, char ** out)
{
    int ret = RET_OK;

#ifdef _WIN32

    int i;
    wchar_t *in_le = NULL;
    int char_len = 0;
    int wchar_len = (int)(in_len / 2);

    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    MALLOC_CHECKED(in_le, wchar_len * sizeof(wchar_t));

    //  LE to UTF-16BE
    for (i = 0; i < wchar_len; i++) {
        in_le[i] = (in[2 * i] << 8) & 0xffff;
        in_le[i] |= in[2 * i + 1] & 0xff;
    }

    char_len = WideCharToMultiByte(CP_UTF8, 0, in_le, wchar_len, 0, 0, NULL, NULL);

    MALLOC_CHECKED(*out, (char_len + 1) * sizeof(char));

    WideCharToMultiByte(CP_UTF8, 0, in_le, wchar_len, *out, char_len, NULL, NULL);

    (*out)[char_len] = 0;

cleanup:
    if (in_le)
        free(in_le);

#elif defined(__linux__) || defined(__APPLE__) || defined(__GNUC__)
    char *_out = NULL;
    size_t out_len = in_len;
    char *_out_ptr;
    iconv_t cd;

    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    MALLOC_CHECKED(_out, in_len);

    _out_ptr = _out;

    cd = iconv_open("UTF-8", "UTF-16BE");

    if (cd == (iconv_t)(-1) || iconv(cd, (char **)&in, &in_len, &_out_ptr, &out_len) == (size_t) - 1) {
        free(_out);
        _out = NULL;
        ret = RET_INVALID_PARAM;
        ERROR_CREATE(ret);
    }

    _out_ptr[0] = 0;
    *out = _out;

    iconv_close(cd);

cleanup:
#else
#error Unsupported platform
#endif
    return ret;
}   //  utf16be_to_utf8

