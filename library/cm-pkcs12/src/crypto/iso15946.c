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

#include "iso15946.h"
#include "aid.h"
#include "dstu4145-params.h"
#include "macros-internal.h"
#include "oids.h"
#include "private-key.h"
#include "uapkif.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
    #define DEBUG_OUTCON(expression) expression
#endif


#define KEY_LENGTH 256


/**
* ��������������� 32 ������ ����� � ������ ����. ��� ������������ ������������
* ������� "������� ���� �� ������ ���������� �� ��������
* �������" (big-endian).
*
* @param src    �����
* @param dst    ������ ����
* @param dstOff �������� � ������� ����
*/
static void iso15946_int2be(int src, void *dst)
{
    int i;
    uint8_t *ptr = dst;
    for (i = 0; i < 4; i++) {
        ptr[i] = (src >> (24 - i * 8));
    }
}


/**
* ������� ����������� SharedInfo. (rfc3278, $8.2)
*
* @param oid ������������� ���������
* @param baEntityInfo 64-������� ������ ��������� ����
* @param keySize
* @param baEncoded
*/
static int iso15946_shared_info(const char* oid, const ByteArray* baEntityInfo, const int keySize, ByteArray** baEncoded)
{
    int ret = RET_OK;
    ByteArray* ba_suppPubInfo = NULL;
    SharedInfo_t* shared_info = NULL;
    NULL_t* null_params = NULL;

    CHECK_NOT_NULL(ba_suppPubInfo = ba_alloc_by_len(4));
    iso15946_int2be(keySize, (void*)ba_get_buf(ba_suppPubInfo));

    ASN_ALLOC(shared_info);

    DO(asn_set_oid_from_text(oid, &shared_info->keyInfo.algorithm));
    if (oid_is_equal(OID_GOST28147_WRAP, oid)) {
        ASN_ALLOC(null_params);
        DO(asn_create_any(get_NULL_desc(), null_params, &shared_info->keyInfo.parameters));
    }

    if (baEntityInfo) {
        ASN_ALLOC(shared_info->entityUInfo);
        DO(asn_ba2OCTSTRING(baEntityInfo, shared_info->entityUInfo));
    }

    DO(asn_ba2OCTSTRING(ba_suppPubInfo, &shared_info->suppPubInfo));

    DO(asn_encode_ba(get_SharedInfo_desc(), shared_info, baEncoded));

cleanup:
    ba_free(ba_suppPubInfo);
    asn_free(get_SharedInfo_desc(), shared_info);
    asn_free(get_NULL_desc(), null_params);
    return ret;
}

static ByteArray *iso15946_get_not_zero(const ByteArray *zx)
{
    size_t len, i;
    const uint8_t *ptr = ba_get_buf_const(zx);

    if (ptr == NULL) {
        ERROR_ADD(RET_INVALID_PARAM);
        return NULL;
    }

    len = ba_get_len(zx);

    for (i = 0; i < len; i++) {
        if (ptr[i] != 0) {
            return ba_alloc_from_uint8(ptr + i, len - i);
        }
    }

    return NULL;
}

int iso15946_generate_secretc (const HashAlg hashAlgo, const char* oidWrapAlgo,
        const ByteArray* baEntityInfo, const ByteArray* baZx, ByteArray** baSecret)
{
    int ret = RET_OK;
    HashCtx* ctx = NULL;
    ByteArray* ba_sharedinfo = NULL;
    ByteArray* ba_hashdata = NULL;
    uint8_t COUNTER[4] = { 0, 0, 0, 1 };

    //DEBUG_OUTCON( printf("iso15946_generate_secretc(), baZx: ");ba_print(stdout, baZx); )
    //DEBUG_OUTCON( printf("iso15946_generate_secretc(), baEntityInfo: ");ba_print(stdout, baEntityInfo); )

    DO(iso15946_shared_info(oidWrapAlgo, baEntityInfo, KEY_LENGTH, &ba_sharedinfo));
    DEBUG_OUTCON( printf("iso15946_generate_secretc(), ba_sharedinfo: ");ba_print(stdout, ba_sharedinfo); )

    CHECK_NOT_NULL(ba_hashdata = iso15946_get_not_zero(baZx));
    //CHECK_NOT_NULL(ba_hashdata = ba_copy_with_alloc(baZx, 0, 0));
    DEBUG_OUTCON( printf("iso15946_generate_secretc(), ba_hashdata: ");ba_print(stdout, ba_hashdata); )

    CHECK_NOT_NULL(ctx = hash_alloc(hashAlgo));
    DO(hash_update(ctx, ba_hashdata));
    ba_free(ba_hashdata);

    // ��� ������������ �������� ����������� ������� �������������� ����������. ������� ���
    //
    // 5.6.3. KDF-������� � ������� ���� ����
    //   ...
    //   5) �������� ���������� ����� ���:
    //     ...
    //     �)  ���� ������� �� ������� ������ ���, �� �� ��� ��������� ��;
    //
    CHECK_NOT_NULL(ba_hashdata = ba_alloc_from_uint8(COUNTER, sizeof(COUNTER)));
    DEBUG_OUTCON( printf("iso15946_generate_secretc(), COUNTER: ");ba_print(stdout, ba_hashdata); )
    DO(hash_update(ctx, ba_hashdata));
    DO(hash_update(ctx, ba_sharedinfo));
    DO(hash_final(ctx, baSecret));
    DEBUG_OUTCON( printf("iso15946_generate_secretc(), ret baSecret: ");ba_print(stdout, *baSecret); )

cleanup:
    hash_free(ctx);
    ba_free(ba_hashdata);
    ba_free(ba_sharedinfo);
    return ret;
}

