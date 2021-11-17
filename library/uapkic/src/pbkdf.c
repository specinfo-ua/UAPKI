/*
 * Copyright 2021 The UAPKI Project Authors.
 * Copyright 2016 PrivatBank IT <acsk@privatbank.ua>
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

#ifdef _WIN32
#include <windows.h>
#elif defined(__linux__) || defined(__APPLE__) || defined(__GNUC__)
#include <iconv.h>
#endif

#include <string.h>
#include "macros-internal.h"
#include "byte-utils-internal.h"
#include "byte-array-internal.h"
#include "pbkdf.h"
#include "hmac.h"

#undef FILE_MARKER
#define FILE_MARKER "uapkic/pbkdf.c"

 //PBKDF1 && PBKDF2
 //RFC: https://www.ietf.org/rfc/rfc2898.txt

static int utf8_to_utf16be(const char* in, unsigned char** out, size_t* out_len)
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

    *out_len = (size_t)wchar_len * 2;
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

    *out = (uint8_t*)_out;
    *out_len = (size_t)(_out_ptr - _out);

    iconv_close(cd);
#else
#error Unsupported platform
#endif
cleanup:
    return ret;
}   //  utf8_to_utf16be

 //TODO: Это апгрейдженый pbkdf1, но нет описания в RFC.
 //https://github.com/openssl/openssl/blob/54c68d35c6b7e7650856beb949b45363ce40ca93/crypto/pkcs12/p12_key.c FUNC: PKCS12_key_gen_uni
 //TESTS: https://github.com/openssl/openssl/blob/76f572ed0469a277d92378848250b7a9705d3071/test/evptests.txt  FIND: # PKCS#12 tests
int pbkdf1(const char* pass, const ByteArray* salt, uint8_t id, size_t iter, size_t n, HashAlg hash_alg, ByteArray** out_ba)
{
    int ret = RET_OK;
    uint8_t* B = NULL, * I = NULL, * p = NULL, * Ai = NULL;
    size_t Slen, Plen, Ilen, saltlen;
    size_t i, j, u, v;
    HashCtx* hash_ctx = NULL;
    ByteArray* D = NULL;
    ByteArray* Aiba = NULL;
    ByteArray* Iba = NULL;
    size_t out_len = 0;
    uint8_t out[256] = { 0 };

    uint8_t* pass_utf16 = NULL;
    size_t pass_utf16_len = 0;

    CHECK_NOT_NULL(hash_ctx = hash_alloc(hash_alg));
    v = hash_get_block_size(hash_ctx);
    u = hash_get_size(hash_alg);

    if (n == 0) {
        n = u;
    }

    DO(utf8_to_utf16be(pass, &pass_utf16, &pass_utf16_len));

    saltlen = ba_get_len(salt);
    Slen = v * ((saltlen + v - 1) / v);
    Plen = (pass_utf16_len) ? v * ((pass_utf16_len + v - 1) / v) : 0;
    Ilen = Slen + Plen;

    MALLOC_CHECKED(Ai, u);
    MALLOC_CHECKED(B, v + 1);
    MALLOC_CHECKED(I, Ilen);

    CHECK_NOT_NULL(D = ba_alloc_by_len(v));
    DO(ba_set(D, id));

    p = I;
    for (i = 0; i < Slen; i++) {
        *p++ = ba_get_buf_const(salt)[i % saltlen];
    }
    for (i = 0; i < Plen; i++) {
        *p++ = pass_utf16[i % pass_utf16_len];
    }

    for (;;) {
        ba_free(Iba);
        ba_free(Aiba);
        Iba = NULL;
        Aiba = NULL;

        CHECK_NOT_NULL(Iba = ba_alloc_from_uint8(I, Ilen));
        DO(hash_update(hash_ctx, D));
        DO(hash_update(hash_ctx, Iba));
        DO(hash_final(hash_ctx, &Aiba));

        for (j = 1; j < iter; j++) {
            DO(hash_update(hash_ctx, Aiba));
            ba_free(Aiba);
            Aiba = NULL;
            DO(hash_final(hash_ctx, &Aiba));
        }

        memcpy(&out[out_len], ba_get_buf_const(Aiba), (n > u) ? u : n);
        out_len += (n > u) ? u : n;
        if (u >= n) {
            break;
        }

        DO(ba_to_uint8(Aiba, Ai, u));
        n -= u;

        for (j = 0; j < v; j++)
            B[j] = Ai[j % u];
        for (j = 0; j < Ilen; j += v) {
            int k;
            uint8_t* Ij = I + j;
            uint16_t c = 1;

            /* Work out Ij = Ij + B + 1 */
            for (k = (int)(v - 1); k >= 0; k--) {
                c += Ij[k] + B[k];
                Ij[k] = (unsigned char)c;
                c >>= 8;
            }
        }
    }

    CHECK_NOT_NULL(*out_ba = ba_alloc_from_uint8(out, out_len));

cleanup:
    secure_zero(out, sizeof(out));
    secure_zero(pass_utf16, pass_utf16_len);
    hash_free(hash_ctx);
    ba_free(D);
    ba_free(Aiba);
    ba_free(Iba);
    free(Ai);
    free(B);
    free(I);
    free(pass_utf16);

    return ret;
}

int pbkdf2(const char* pass, const ByteArray* salt, size_t iterations, size_t key_len, HashAlg hash_alg, ByteArray** dk)
{
    int ret = RET_OK;
    ByteArray* iv = NULL;
    ByteArray* pass_ba = NULL;
    ByteArray* count_ba = NULL;
    ByteArray* key = NULL;
    ByteArray* out = NULL;
    ByteArray* u = NULL;
    size_t cplen = 0;
    size_t i;
    unsigned int count = 1;
    uint8_t count_buf[4] = { 0 };
    HmacCtx* hmac_ctx = NULL;
    size_t hash_len = 0;

    CHECK_PARAM(pass != NULL);
    CHECK_PARAM(salt != NULL);
    CHECK_PARAM(dk != NULL);

    CHECK_NOT_NULL(out = ba_alloc());

    CHECK_NOT_NULL(pass_ba = ba_alloc_from_str(pass));

    /* F(P, S, c, i) = U1 xor U2 xor ... Uc
     *
     * U1 = PRF(P, S || i)
     * U2 = PRF(P, U1)
     * Uc = PRF(P, Uc-1)
     *
     * T_1 = F (P, S, c, 1) ,
     * T_2 = F (P, S, c, 2) ,
     * ...
     * T_l = F (P, S, c, l)
     */

    CHECK_NOT_NULL(hmac_ctx = hmac_alloc(hash_alg));
    hash_len = hash_get_size(hash_alg);

    while (key_len) {
        if (key_len > hash_len) {
            cplen = hash_len;
        }
        else {
            cplen = key_len;
        }

        count_buf[0] = (count >> 24) & 0xff;
        count_buf[1] = (count >> 16) & 0xff;
        count_buf[2] = (count >> 8) & 0xff;
        count_buf[3] = count & 0xff;

        CHECK_NOT_NULL((count_ba = ba_alloc_from_uint8(count_buf, sizeof(count_buf))));

        if (count == 1) {
            DO(hmac_init(hmac_ctx, pass_ba));
        }

        DO(hmac_update(hmac_ctx, salt));
        DO(hmac_update(hmac_ctx, count_ba));
        DO(hmac_final(hmac_ctx, &u));
        DO(hmac_reset(hmac_ctx));

        CHECK_NOT_NULL(key = ba_copy_with_alloc(u, 0, cplen));

        for (i = 1; i < iterations; i++) {
            DO(hmac_update(hmac_ctx, u));

            ba_free(u);
            u = NULL;

            DO(hmac_final(hmac_ctx, &u));
            DO(hmac_reset(hmac_ctx));
            DO(ba_xor(key, u));
        }

        //Добавляем результат в Т
        ba_append(key, 0, cplen, out);
        //Увеличиваем счетчик.
        count++;
        key_len -= cplen;

        ba_free(count_ba);
        ba_free_private(key);
        ba_free(u);
        count_ba = NULL;
        key = NULL;
        u = NULL;
    }

    *dk = out;
    out = NULL;

cleanup:
    hmac_free(hmac_ctx);
    ba_free_private(pass_ba);
    ba_free_private(out);
    ba_free(key);
    ba_free(u);
    ba_free(iv);
    ba_free(count_ba);

    return ret;
}

int pbkdf_self_test(void)
{
    //test vectors from rfc6070
    static const char pass[] = "password";
    static const uint8_t _salt[] = "salt";// (4 octets)
    static const uint32_t iterations = 2;
    static const uint8_t test_key[] = {
        0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57 };
    static const ByteArray salt = { (uint8_t*)_salt, 4 };

    int ret = RET_OK;
    ByteArray* key = NULL;

    DO(pbkdf2(pass, &salt, iterations, sizeof(test_key), HASH_ALG_SHA1, &key));
    if ((ba_get_len(key) != sizeof(test_key)) ||
        memcmp(ba_get_buf_const(key), test_key, sizeof(test_key)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

cleanup:
    ba_free(key);
    return ret;
}
