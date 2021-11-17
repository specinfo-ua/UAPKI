/*
 * Copyright 2021 The UAPKI Project Authors.
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

#include <memory.h>

#include "macros-internal.h"
#include "keywrap.h"
#include "drbg.h"
#include "dstu7624.h"
#include "gost28147.h"

#undef FILE_MARKER
#define FILE_MARKER "uapkic/keywrap.c"

#define DSTU7624_WRAP_IV_SIZE   32
#define DSTU7624_WRAP_KEY_SIZE  32
#define DSTU7624_WRAP_MAC_SIZE  32

#define GOST28147_WRAP_MAC_SIZE  4
#define GOST28147_WRAP_IV_SIZE   8
#define GOST28147_WRAP_KEY_SIZE 32

// Фіксовані вектори ініціалізаціїї другого етапу шифрування ключа
static const uint8_t DSTU7624_WRAP_IV[32] = { 
    0x69, 0x73, 0x27, 0x1D, 0x6E, 0x61, 0x1D, 0x06, 0x61, 0x67, 0x15, 0x04, 0x6C, 0x65, 0x50, 0x4C,
    0x20, 0x20, 0x00, 0x4F, 0x6D, 0x68, 0x01, 0x1F, 0x65, 0x61, 0x0C, 0x0C, 0x73, 0x73, 0x47, 0x14 };

static const uint8_t GOST28147_WRAP_IV[8] = {
    0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05 };

static int key_wrap_dstu7624_internal(const ByteArray* kek, const ByteArray* iv, const ByteArray* key, ByteArray** wraped_key)
{
    int ret = RET_OK;
    ByteArray* out = NULL;
    ByteArray* mac = NULL;
    ByteArray* w_key = NULL;
    ByteArray* biv_wrap = NULL;
    Dstu7624Ctx* ctx = NULL;

    CHECK_NOT_NULL(biv_wrap = ba_alloc_from_uint8(DSTU7624_WRAP_IV, sizeof(DSTU7624_WRAP_IV)));
    CHECK_NOT_NULL(w_key = ba_alloc());

    CHECK_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));

    DO(dstu7624_init_cmac(ctx, kek, 32, 32));
    DO(dstu7624_update_mac(ctx, key));
    DO(dstu7624_final_mac(ctx, &mac));

    DO(dstu7624_init_cfb(ctx, kek, iv, 32));
    DO(ba_append(iv, 0, 0, w_key));

    DO(dstu7624_encrypt(ctx, key, &out));
    DO(ba_append(out, 0, 0, w_key));
    ba_free(out);
    out = NULL;

    DO(dstu7624_encrypt(ctx, mac, &out));
    DO(ba_append(out, 0, 0, w_key));

    DO(ba_swap(w_key));

    DO(dstu7624_init_cfb(ctx, kek, biv_wrap, 32));
    DO(dstu7624_encrypt(ctx, w_key, wraped_key));

cleanup:
    ba_free(out);
    ba_free(biv_wrap);
    ba_free(mac);
    ba_free_private(w_key);
    dstu7624_free(ctx);
    return ret;
}

int key_wrap_dstu7624(const ByteArray* kek, const ByteArray* key, ByteArray** wraped_key)
{
    int ret = RET_OK;
    ByteArray* iv = NULL;

    CHECK_PARAM(kek);
    CHECK_PARAM(key);
    CHECK_PARAM(wraped_key);

    CHECK_NOT_NULL(iv = ba_alloc_by_len(DSTU7624_WRAP_IV_SIZE));
    DO(drbg_random(iv));

    DO(key_wrap_dstu7624_internal(kek, iv, key, wraped_key));

cleanup:
    ba_free(iv);
    return ret;
}

int key_unwrap_dstu7624(const ByteArray* kek, const ByteArray* wraped_key, ByteArray** key)
{
    int ret = RET_OK;
    ByteArray* key_unwrap = NULL;
    ByteArray* mac = NULL;
    ByteArray* actual_mac = NULL;
    ByteArray* dec_wraped_key = NULL;
    ByteArray* wrap_iv = NULL;
    ByteArray* iv = NULL;
    ByteArray* enc_key = NULL;
    ByteArray* enc_mac = NULL;
    Dstu7624Ctx* ctx = NULL;

    CHECK_PARAM(kek);
    CHECK_PARAM(wraped_key);
    CHECK_PARAM(key);

    CHECK_NOT_NULL(wrap_iv = ba_alloc_from_uint8(DSTU7624_WRAP_IV, sizeof(DSTU7624_WRAP_IV)));

    CHECK_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));

    DO(dstu7624_init_cfb(ctx, kek, wrap_iv, 32));
    DO(dstu7624_decrypt(ctx, wraped_key, &dec_wraped_key));
    DO(ba_swap(dec_wraped_key));

    CHECK_NOT_NULL(iv = ba_copy_with_alloc(dec_wraped_key, 0, DSTU7624_WRAP_IV_SIZE));

    DO(dstu7624_init_cfb(ctx, kek, iv, 32));
    CHECK_NOT_NULL(enc_key = ba_copy_with_alloc(dec_wraped_key, DSTU7624_WRAP_IV_SIZE, DSTU7624_WRAP_KEY_SIZE));
    DO(dstu7624_decrypt(ctx, enc_key, &key_unwrap));

    CHECK_NOT_NULL(enc_mac = ba_copy_with_alloc(dec_wraped_key, DSTU7624_WRAP_IV_SIZE + DSTU7624_WRAP_KEY_SIZE, DSTU7624_WRAP_MAC_SIZE));
    DO(dstu7624_decrypt(ctx, enc_mac, &mac));

    DO(dstu7624_init_cmac(ctx, kek, 32, 32));
    DO(dstu7624_update_mac(ctx, key_unwrap));
    DO(dstu7624_final_mac(ctx, &actual_mac));

    if (ba_cmp(actual_mac, mac)) {
        SET_ERROR(RET_INVALID_MAC);
    }

    *key = key_unwrap;
    key_unwrap = NULL;

cleanup:
    dstu7624_free(ctx);
    ba_free_private(key_unwrap);
    ba_free(mac);
    ba_free(actual_mac);
    ba_free(dec_wraped_key);
    ba_free(iv);
    ba_free(wrap_iv);
    ba_free(enc_key);
    ba_free(enc_mac);
    return ret;
}

static int key_wrap_gost28147_internal(const ByteArray* sbox, const ByteArray* kek, const ByteArray* iv, const ByteArray* key, ByteArray** wraped_key)
{
    ByteArray* out = NULL;
    ByteArray* mac = NULL;
    ByteArray* w_key = NULL;
    ByteArray* biv_wrap = NULL;
    int ret = RET_OK;
    Gost28147Ctx* params = NULL;

    CHECK_NOT_NULL(biv_wrap = ba_alloc_from_uint8(GOST28147_WRAP_IV, sizeof(GOST28147_WRAP_IV)));
    if (sbox) {
        CHECK_NOT_NULL(params = gost28147_alloc_user_sbox(sbox));
    }
    else {
        CHECK_NOT_NULL(params = gost28147_alloc(GOST28147_SBOX_ID_1));
    }

    CHECK_NOT_NULL(w_key = ba_alloc());
    DO(gost28147_init_mac(params, kek));
    DO(gost28147_update_mac(params, key));
    DO(gost28147_final_mac(params, &mac));

    DO(gost28147_init_cfb(params, kek, iv));
    DO(ba_append(iv, 0, 0, w_key));

    DO(gost28147_encrypt(params, key, &out));
    DO(ba_append(out, 0, 0, w_key));
    ba_free(out);
    out = NULL;

    DO(gost28147_encrypt(params, mac, &out));
    DO(ba_append(out, 0, 0, w_key));

    DO(ba_swap(w_key));

    DO(gost28147_init_cfb(params, kek, biv_wrap));
    DO(gost28147_encrypt(params, w_key, wraped_key));

cleanup:

    ba_free(out);
    ba_free(biv_wrap);
    ba_free(mac);
    ba_free_private(w_key);
    gost28147_free(params);
    return ret;
}

int key_wrap_gost28147(const ByteArray* sbox, const ByteArray* kek, const ByteArray* key, ByteArray** wraped_key)
{
    int ret = RET_OK;
    ByteArray* iv = NULL;

    CHECK_PARAM(kek);
    CHECK_PARAM(key);
    CHECK_PARAM(wraped_key);

    CHECK_NOT_NULL(iv = ba_alloc_by_len(GOST28147_WRAP_IV_SIZE));
    DO(drbg_random(iv));

    DO(key_wrap_gost28147_internal(sbox, kek, iv, key, wraped_key));

cleanup:

    ba_free(iv);
    return ret;
}

int key_unwrap_gost28147(const ByteArray* sbox, const ByteArray* kek, const ByteArray* wraped_key, ByteArray** key)
{
    int ret = RET_OK;
    ByteArray* key_unwrap = NULL;
    ByteArray* mac = NULL;
    ByteArray* actual_mac = NULL;
    ByteArray* dec_wraped_key = NULL;
    ByteArray* wrap_iv = NULL;
    ByteArray* iv = NULL;
    ByteArray* enc_key = NULL;
    ByteArray* enc_mac = NULL;

    Gost28147Ctx* params = NULL;

    CHECK_PARAM(kek);
    CHECK_PARAM(wraped_key);
    CHECK_PARAM(key);

    if (sbox) {
        CHECK_NOT_NULL(params = gost28147_alloc_user_sbox(sbox));
    }
    else {
        CHECK_NOT_NULL(params = gost28147_alloc(GOST28147_SBOX_ID_1));
    }

    CHECK_NOT_NULL(wrap_iv = ba_alloc_from_uint8(GOST28147_WRAP_IV, sizeof(GOST28147_WRAP_IV)));

    DO(gost28147_init_cfb(params, kek, wrap_iv));
    DO(gost28147_decrypt(params, wraped_key, &dec_wraped_key));
    DO(ba_swap(dec_wraped_key));

    CHECK_NOT_NULL(iv = ba_copy_with_alloc(dec_wraped_key, 0, GOST28147_WRAP_IV_SIZE));

    DO(gost28147_init_cfb(params, kek, iv));
    CHECK_NOT_NULL(enc_key = ba_copy_with_alloc(dec_wraped_key, GOST28147_WRAP_IV_SIZE, GOST28147_WRAP_KEY_SIZE));
    DO(gost28147_decrypt(params, enc_key, &key_unwrap));

    CHECK_NOT_NULL(enc_mac = ba_copy_with_alloc(dec_wraped_key, GOST28147_WRAP_IV_SIZE + GOST28147_WRAP_KEY_SIZE, GOST28147_WRAP_MAC_SIZE));
    DO(gost28147_decrypt(params, enc_mac, &mac));

    DO(gost28147_init_mac(params, kek));
    DO(gost28147_update_mac(params, key_unwrap));
    DO(gost28147_final_mac(params, &actual_mac));

    if (ba_cmp(actual_mac, mac)) {
        SET_ERROR(RET_INVALID_MAC);
    }

    *key = key_unwrap;
    key_unwrap = NULL;

cleanup:

    gost28147_free(params);
    ba_free_private(key_unwrap);
    ba_free(mac);
    ba_free(actual_mac);
    ba_free(dec_wraped_key);
    ba_free(iv);
    ba_free(wrap_iv);
    ba_free(enc_key);
    ba_free(enc_mac);

    return ret;
}

static int key_wrap_self_test_dstu7624(void)
{
    static const char* KEK = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    static const char* IV = "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F";
    static const char* CEK = "1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100";
    static const char* WRAPPED_CEK = "7B74FCBF080464F81BF8EAF10621B624A4F053446128396CC2F529BD3E2078DAD6BC0B4C5AAF47711D1BE5CDC0D4849EC50DC4484F7CF393BC7F5F3E8A8728CA13DDAEE30C297D6C82C8751E533A3E7591E7D400B89AE64237F692EC892333CD";

    int ret = RET_OK;
    ByteArray* kek = NULL;
    ByteArray* iv = NULL;
    ByteArray* cek = NULL;
    ByteArray* wraped_cek = NULL;
    ByteArray* _wraped_cek = NULL;
    ByteArray* _unwraped_cek = NULL;

    CHECK_NOT_NULL(kek = ba_alloc_from_hex(KEK));
    CHECK_NOT_NULL(iv = ba_alloc_from_hex(IV));
    CHECK_NOT_NULL(cek = ba_alloc_from_hex(CEK));
    CHECK_NOT_NULL(wraped_cek = ba_alloc_from_hex(WRAPPED_CEK));

    DO(key_wrap_dstu7624_internal(kek, iv, cek, &_wraped_cek));
    if (ba_cmp(wraped_cek, _wraped_cek) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

    DO(key_unwrap_dstu7624(kek, _wraped_cek, &_unwraped_cek));
    if (ba_cmp(cek, _unwraped_cek) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

cleanup:
    ba_free(kek);
    ba_free(iv);
    ba_free(cek);
    ba_free(wraped_cek);
    ba_free(_wraped_cek);
    ba_free(_unwraped_cek);

    return ret;
}

static int key_wrap_self_test_gost28147(void)
{
    static const char* KEK = "01000000010000000100000001000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    static const char* IV = "F477DA7AA6424A88";
    static const char* CEK = "01020304010203040102030401020304F1F2F3F4F5F6F7F8F1F2F3F4F5F6F7F8";
    static const char* WRAPPED_CEK = "52A513F1B4172CA6B5F1B8A03CA9A4E0ACB6E00E11E5E9BCDD446222EB97238DC3E4E24D2EC03E05A568EC51";

    int ret = RET_OK;
    ByteArray* kek = NULL;
    ByteArray* iv = NULL;
    ByteArray* cek = NULL;
    ByteArray* wraped_cek = NULL;
    ByteArray* _wraped_cek = NULL;
    ByteArray* _unwraped_cek = NULL;

    CHECK_NOT_NULL(kek = ba_alloc_from_hex(KEK));
    CHECK_NOT_NULL(iv = ba_alloc_from_hex(IV));
    CHECK_NOT_NULL(cek = ba_alloc_from_hex(CEK));
    CHECK_NOT_NULL(wraped_cek = ba_alloc_from_hex(WRAPPED_CEK));

    DO(key_wrap_gost28147_internal(NULL, kek, iv, cek, &_wraped_cek));
    if (ba_cmp(wraped_cek, _wraped_cek) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

    DO(key_unwrap_gost28147(NULL, kek, _wraped_cek, &_unwraped_cek));
    if (ba_cmp(cek, _unwraped_cek) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

cleanup:
    ba_free(kek);
    ba_free(iv);
    ba_free(cek);
    ba_free(wraped_cek);
    ba_free(_wraped_cek);
    ba_free(_unwraped_cek);

    return ret;
}

int key_wrap_self_test(void)
{
    int ret = RET_OK;

    DO(key_wrap_self_test_dstu7624());
    DO(key_wrap_self_test_gost28147());

cleanup:
    return ret;
}
