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

#define FILE_MARKER "uapki/dirent-internal.c"

#include "dirent-internal.h"
#include "macros-internal.h"
#include "ba-utils.h"
#include "uapki-errors.h"


#if defined _WIN32

#include <windows.h>
#include <errno.h>
#include <io.h> /* _findfirst and _findnext set errno iff they return -1 */
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef ptrdiff_t handle_type; /* C99's intptr_t not sufficiently portable */

struct DIR {
    handle_type         handle; /* -1 for failed rewind */
    struct _wfinddata_t winfo;
    struct dirent       result; /* d_name null iff first time */
    wchar_t             *wname;  /* null-terminated char string */
    char                utf8_cur_file_name[260];  /* null-terminated char string */
};

wchar_t *utf8_to_wchar(const char *in)
{
    wchar_t *wout = NULL;
    int res_len = 0;
    int ret = RET_OK;

    res_len = MultiByteToWideChar(CP_UTF8, 0, in, -1, 0, 0);
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

DIR *opendir(const char *name)
{
    DIR *dir = 0;
    char *dir_name = NULL;

    if (name && name[0]) {
        size_t base_length = strlen(name);

        /* search pattern must end with suitable wildcard */
        const char *all = strchr("/\\", name[base_length - 1]) ? "*" : "/*";

        if ((dir = (DIR *) malloc(sizeof * dir)) != 0
                && (dir_name = (char *) malloc(base_length + strlen(all) + 1)) != 0) {

            strcat(strcpy(dir_name, name), all);

            dir->wname = utf8_to_wchar(dir_name);

            if ((dir->handle = (handle_type) _wfindfirst(dir->wname, &dir->winfo)) != -1) {
                dir->result.d_name = NULL;
            } else {
                /* rollback */
                free(dir->wname);
                free(dir);
                dir = 0;
            }
        } else {
            /* rollback */
            free(dir);
            dir = 0;
            errno = ENOMEM;
            ERROR_CREATE(RET_MEMORY_ALLOC_ERROR);
        }
    } else {
        errno = EINVAL;
        ERROR_CREATE(RET_UAPKI_FILE_OPEN_ERROR);
    }

    free(dir_name);

    return dir;
}

int closedir(DIR *dir)
{
    int result = -1;

    if (dir) {
        if (dir->handle != -1) {
            result = _findclose(dir->handle);
        }

        free(dir->wname);
        free(dir);
    }

    if (result == -1) {
        /* map all errors to EBADF */
        errno = EBADF;
    }

    return result;
}

struct dirent *readdir(DIR *dir)
{
    struct dirent *result = 0;

    if (dir && dir->handle != -1) {
        if (!dir->result.d_name || _wfindnext(dir->handle, &dir->winfo) != -1) {
            if (WideCharToMultiByte(CP_UTF8, 0, dir->winfo.name, -1, dir->utf8_cur_file_name, sizeof(dir->utf8_cur_file_name), 0,
                    0) > 0) {
                result         = &dir->result;
                result->d_name = dir->utf8_cur_file_name;
            } else {
                errno = EBADF;
            }
        }
    } else {
        errno = EBADF;
    }

    return result;
}

void rewinddir(DIR *dir)
{
    if (dir && dir->handle != -1) {
        _findclose(dir->handle);
        dir->handle = (handle_type) _wfindfirst(dir->wname, &dir->winfo);
        dir->result.d_name = 0;
    } else {
        errno = EBADF;
    }
}

bool is_dir(const char *path)
{
    bool is_dir = false;
    wchar_t *szPath = utf8_to_wchar(path);
    DWORD dwAttrib = GetFileAttributes((LPCSTR)szPath);

    is_dir = (dwAttrib != INVALID_FILE_ATTRIBUTES && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));

    free(szPath);

    return is_dir;
}

#ifdef __cplusplus
}
#endif
#else

#include <sys/stat.h>

bool is_dir(const char *path)
{
    struct stat path_stat;
    stat(path, &path_stat);
    return S_ISDIR(path_stat.st_mode) != 0;
}

#endif
