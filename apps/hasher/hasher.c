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

/*
 * Геш файлів на uapkic. Один вихідний файл — дві утиліти, алгоритм обирає макрос:
 *   HASHER_GOST34311  -> gost34311   (ГОСТ 34.311-95)
 *   HASHER_KUPYNA256  -> kupyna256   (ДСТУ 7564:2014 «Купина-256»)
 *
 * Вивід як у md5sum: "<hex>  <файл>" на кожен файл; без файлів або "-" — stdin.
 * Код повернення: 0 — успіх, 1 — помилка хоча б для одного файлу (текст у stderr).
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "uapkic.h"

#ifdef _WIN32
#  include <fcntl.h>
#  include <io.h>
#endif

#if defined(HASHER_GOST34311)
#  define HASHER_NAME       "gost34311"
#  define HASHER_ALG        HASH_ALG_GOST34311
#  define HASHER_SELF_TEST  SELF_TEST_GOST34311_FAIL
#elif defined(HASHER_KUPYNA256)
#  define HASHER_NAME       "kupyna256"
#  define HASHER_ALG        HASH_ALG_DSTU7564_256
#  define HASHER_SELF_TEST  SELF_TEST_DSTU7564_FAIL
#else
#  error "Define HASHER_GOST34311 or HASHER_KUPYNA256"
#endif

/* Файл читається частинами: розмір не обмежений пам'яттю й типом long */
#define CHUNK_SIZE (1024 * 1024)

typedef enum {
    FORMAT_HEX,
    FORMAT_BASE64,
    FORMAT_FULL
} OutputFormat;

static const char* USAGE =
    "Usage: " HASHER_NAME " [OPTION]... [FILE]...\n"
    "Print hash of each FILE; with no FILE, or when FILE is -, read standard input.\n"
    "\n"
    "  -b, --base64  print hash in base64 instead of hex\n"
    "  -f, --full    print file name, hash in hex and in base64, each on its own line\n"
    "  -h, --help    display this help and exit\n";

static void print_error(const char* path, const char* message)
{
    fprintf(stderr, HASHER_NAME ": %s: %s\n", path, message);
}

/* 0 — успіх; інакше помилку вже надруковано */
static int hash_stream(FILE* f, const char* path, ByteArray** hash_value)
{
    int ret = 1;
    size_t readed;
    HashCtx* ctx = hash_alloc(HASHER_ALG);
    uint8_t* buf = (uint8_t*)malloc(CHUNK_SIZE);

    if (ctx == NULL || buf == NULL) {
        print_error(path, "can not allocate memory");
        goto cleanup;
    }

    while ((readed = fread(buf, 1, CHUNK_SIZE, f)) > 0) {
        int hash_ret;
        ByteArray* chunk = ba_alloc_from_uint8(buf, readed);
        if (chunk == NULL) {
            print_error(path, "can not allocate memory");
            goto cleanup;
        }
        hash_ret = hash_update(ctx, chunk);
        ba_free(chunk);
        if (hash_ret != RET_OK) {
            print_error(path, "hash error");
            goto cleanup;
        }
    }

    if (ferror(f)) {
        print_error(path, strerror(errno));
        goto cleanup;
    }

    if (hash_final(ctx, hash_value) != RET_OK) {
        print_error(path, "hash error");
        goto cleanup;
    }
    ret = 0;

cleanup:
    free(buf);
    hash_free(ctx);
    return ret;
}

static void print_hex(const ByteArray* hash_value)
{
    static const char HEX[] = "0123456789abcdef";
    const uint8_t* buf = ba_get_buf_const(hash_value);
    size_t i;

    for (i = 0; i < ba_get_len(hash_value); i++) {
        putchar(HEX[buf[i] >> 4]);
        putchar(HEX[buf[i] & 0x0F]);
    }
}

static int print_hash(const ByteArray* hash_value, const char* path, OutputFormat format)
{
    char* b64 = NULL;

    if (format != FORMAT_HEX) {
        if (ba_to_base64_with_alloc(hash_value, &b64) != RET_OK) {
            print_error(path, "can not convert hash value to base64");
            return 1;
        }
    }

    switch (format) {
    case FORMAT_HEX:
        print_hex(hash_value);
        printf("  %s\n", path);
        break;
    case FORMAT_BASE64:
        printf("%s  %s\n", b64, path);
        break;
    case FORMAT_FULL:
        printf("FILE: %s\nHEX: ", path);
        print_hex(hash_value);
        printf("\nBASE64: %s\n", b64);
        break;
    }

    /* Рядок виділяє uapkic, тож і звільняє вона: у DLL своя купа */
    uapkic_free(b64);
    return 0;
}

static int process(const char* path, OutputFormat format)
{
    int ret;
    FILE* f;
    ByteArray* hash_value = NULL;
    const int is_stdin = (strcmp(path, "-") == 0);

    if (is_stdin) {
        f = stdin;
#ifdef _WIN32
        _setmode(_fileno(stdin), _O_BINARY);
#endif
    }
    else if ((f = fopen(path, "rb")) == NULL) {
        print_error(path, strerror(errno));
        return 1;
    }

    ret = hash_stream(f, path, &hash_value);
    if (!is_stdin) {
        fclose(f);
    }
    if (ret == 0) {
        ret = print_hash(hash_value, path, format);
    }
    ba_free(hash_value);
    return ret;
}

int main(int argc, char* argv[])
{
    int i;
    int first_file = argc;
    int failed = 0;
    uint32_t self_test = 0;
    OutputFormat format = FORMAT_HEX;

    for (i = 1; i < argc; i++) {
        const char* arg = argv[i];
        if (strcmp(arg, "--") == 0) {
            first_file = i + 1;
            break;
        }
        if (arg[0] != '-' || arg[1] == '\0') {
            first_file = i;
            break;
        }
        if (strcmp(arg, "-b") == 0 || strcmp(arg, "--base64") == 0) {
            format = FORMAT_BASE64;
        }
        else if (strcmp(arg, "-f") == 0 || strcmp(arg, "--full") == 0) {
            format = FORMAT_FULL;
        }
        else if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            fputs(USAGE, stdout);
            return 0;
        }
        else {
            fprintf(stderr, HASHER_NAME ": unknown option '%s'\n%s", arg, USAGE);
            return 1;
        }
    }

    /* Самотестування бібліотеки; зупиняємось лише на збої потрібного алгоритму */
    uapkic_init(NULL, &self_test);
    if (self_test & HASHER_SELF_TEST) {
        fprintf(stderr, HASHER_NAME ": self-test of the hash algorithm failed\n");
        return 1;
    }

    if (first_file >= argc) {
        failed |= process("-", format);
    }
    for (i = first_file; i < argc; i++) {
        failed |= process(argv[i], format);
    }

    return failed ? 1 : 0;
}
