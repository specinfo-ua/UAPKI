/*
 * Copyright 2021-2026 The UAPKI Project Authors.
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

#define FILE_MARKER "uapkic/pbkdf.c"

#include <string.h>
#include "macros-internal.h"
#include "byte-utils-internal.h"
#include "byte-array-internal.h"
#include "pbkdf.h"
#include "hmac.h"

 //PBKDF1 && PBKDF2
 //RFC: https://www.ietf.org/rfc/rfc2898.txt

static int utf8_to_utf16be(const char* in, unsigned char** out, size_t* out_len)
{
    int ret = RET_OK;
    size_t in_len;
    size_t max_out_len;
    uint8_t* out_buf = NULL;
    const uint8_t* in_ptr = (const uint8_t*)in;
    unsigned char* out_ptr;
    size_t remaining_in;
    size_t written_bytes;

    CHECK_NOT_NULL(in);
    CHECK_NOT_NULL(out);
    CHECK_NOT_NULL(out_len);

    in_len = strlen(in) + 1;

    // Максимально можливий розмір UTF-16BE буфера (2 байти на кожен ASCII/UTF-8 байт)
    max_out_len = in_len * 2;
    if ((out_buf = malloc(max_out_len)) == NULL) {
        SET_ERROR(RET_MEMORY_ALLOC_ERROR); // Помилка виділення пам'яті
	}

    out_ptr = out_buf;
    remaining_in = in_len;
    written_bytes = 0;

    while (remaining_in > 0) {
        uint32_t cp = 0;
        size_t bytes_read = 0;

        // 1. Декодування UTF-8 у Code Point
        if ((in_ptr[0] & 0x80) == 0x00) {
            cp = in_ptr[0];
            bytes_read = 1;
        }
        else if (((in_ptr[0] & 0xE0) == 0xC0) && (remaining_in >= 2)) {
            if ((in_ptr[1] & 0xC0) != 0x80) { 
                SET_ERROR(RET_INVALID_UTF8_STR);
            }
            cp = ((in_ptr[0] & 0x1F) << 6) | (in_ptr[1] & 0x3F);
            bytes_read = 2;
        }
        else if (((in_ptr[0] & 0xF0) == 0xE0) && (remaining_in >= 3)) {
            if ((in_ptr[1] & 0xC0) != 0x80 || (in_ptr[2] & 0xC0) != 0x80) {
                SET_ERROR(RET_INVALID_UTF8_STR);
            }
            cp = ((in_ptr[0] & 0x0F) << 12) | ((in_ptr[1] & 0x3F) << 6) | (in_ptr[2] & 0x3F);
            bytes_read = 3;
        }
        else if (((in_ptr[0] & 0xF8) == 0xF0) && (remaining_in >= 4)) {
            if ((in_ptr[1] & 0xC0) != 0x80 || (in_ptr[2] & 0xC0) != 0x80 || (in_ptr[3] & 0xC0) != 0x80) {
                SET_ERROR(RET_INVALID_UTF8_STR);
            }
            cp = ((in_ptr[0] & 0x07) << 18) | ((in_ptr[1] & 0x3F) << 12) | ((in_ptr[2] & 0x3F) << 6) | (in_ptr[3] & 0x3F);
            bytes_read = 4;
        }
        else {
            SET_ERROR(RET_INVALID_UTF8_STR);
        }

        in_ptr += bytes_read;
        remaining_in -= bytes_read;

        // 2. Кодування Code Point в UTF-16BE (Big Endian)
        if (cp <= 0xFFFF) {
            // Захист від виходу за межі буфера (з урахуванням виділення
            // з припущення на однобайтні символи не має ніколи статись)
            if (written_bytes + 2 > max_out_len) {
                SET_ERROR(RET_INDEX_OUT_OF_RANGE);
            }

            out_ptr[0] = (unsigned char)(cp >> 8);   // Старший байт першим
            out_ptr[1] = (unsigned char)(cp & 0xFF); // Молодший байт другим
            out_ptr += 2;
            written_bytes += 2;
        }
        else if (cp <= 0x10FFFF) {
            uint16_t high_surrogate;
            uint16_t low_surrogate;

            if (written_bytes + 4 > max_out_len) {
                SET_ERROR(RET_INDEX_OUT_OF_RANGE);
            }

            // Розрахунок сурогатних пар для символів > 0xFFFF
            cp -= 0x10000;
            high_surrogate = (uint16_t)((cp >> 10) + 0xD800);
            low_surrogate = (uint16_t)((cp & 0x3FF) + 0xDC00);

            out_ptr[0] = (unsigned char)(high_surrogate >> 8);
            out_ptr[1] = (unsigned char)(high_surrogate & 0xFF);
            out_ptr[2] = (unsigned char)(low_surrogate >> 8);
            out_ptr[3] = (unsigned char)(low_surrogate & 0xFF);
            out_ptr += 4;
            written_bytes += 4;
        }
        else {
            SET_ERROR(RET_INVALID_UTF8_STR); // Code Point поза межами Unicode
        }
    }

    *out = out_buf;
    *out_len = written_bytes;
    return ret;

cleanup:
    free(out_buf);
    *out = NULL;
    *out_len = 0;
    return ret;
}

 //Це апгрейджений pbkdf1, але немає опису в RFC.
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

        // Додаємо результат в Т
        ba_append(key, 0, cplen, out);
		// Збільшуємо лічильник
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
