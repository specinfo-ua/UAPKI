/*
 * Copyright (c) 2022, The UAPKI Project Authors.
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

//  Last update: 2022-04-25

#include "cipher-helper.h"
#include "dstu7624.h"
#include "gost28147.h"
#include "macros-internal.h"
#include "uapki-errors.h"


static const char* SHEX_GOST28147_SBOX_ID_1 = "A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC57904";


int UapkiNS::Cipher::Dstu7624::cryptData (const UapkiNS::AlgorithmIdentifier& algoId, const ByteArray* baKey,
    const Direction direction, const ByteArray* baDataIn, ByteArray** baDataOut)
{
    int ret = RET_OK;
    UapkiNS::SmartBA sba_iv;
    Dstu7624Ctx* ctx = nullptr;
    int dstu7624_mode = 0;

    if (algoId.algorithm == string(OID_DSTU7624_256_CFB)) {
        dstu7624_mode = 1;
    }
    else {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }

    DO(decodeParams(algoId.baParameters, &sba_iv));
    //  Support only DSTU7624_SBOX_1
    CHECK_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));

    switch (dstu7624_mode) {
    case 1:
        DO(dstu7624_init_cfb(ctx, baKey, sba_iv.get(), 32));
        break;
    default:
        break;
    }

    if (direction == Direction::ENCRYPT) {
        DO(dstu7624_encrypt(ctx, baDataIn, baDataOut));
    }
    else {
        DO(dstu7624_decrypt(ctx, baDataIn, baDataOut));
    }

cleanup:
    dstu7624_free(ctx);
    return ret;
}

int UapkiNS::Cipher::Dstu7624::decodeParams (const ByteArray* baEncoded, ByteArray** baIV)
{
    int ret = RET_OK;
    //  Dstu7624Parameters_t is missed - use GOST28147ParamsOptionalDke_t without DKE instead it
    GOST28147ParamsOptionalDke_t* dstu7624_params = nullptr;

    CHECK_NOT_NULL(dstu7624_params = (GOST28147ParamsOptionalDke_t*)asn_decode_ba_with_alloc(get_GOST28147ParamsOptionalDke_desc(), baEncoded));
    if (dstu7624_params->dke) {
        //  Must be absent: use GOST28147ParamsOptionalDke_t without DKE
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }
    DO(asn_OCTSTRING2ba(&dstu7624_params->iv, baIV));

cleanup:
    asn_free(get_GOST28147ParamsOptionalDke_desc(), dstu7624_params);
    return ret;
}

int UapkiNS::Cipher::Dstu7624::encodeParams (const ByteArray* baIV, ByteArray** baEncoded)
{
    int ret = RET_OK;
    //  Dstu7624Parameters_t is missed - use GOST28147ParamsOptionalDke_t without DKE instead it
    GOST28147ParamsOptionalDke_t* dstu7624_params = nullptr;

    ASN_ALLOC_TYPE(dstu7624_params, GOST28147ParamsOptionalDke_t);
    DO(asn_ba2OCTSTRING(baIV, &dstu7624_params->iv));

    DO(asn_encode_ba(get_GOST28147ParamsOptionalDke_desc(), dstu7624_params, baEncoded));

cleanup:
    asn_free(get_GOST28147ParamsOptionalDke_desc(), dstu7624_params);
    return ret;
}

int UapkiNS::Cipher::Dstu7624::generateKey (const size_t keyLen, ByteArray** baKey)
{
    return dstu7624_generate_key(keyLen, baKey);
}

int UapkiNS::Cipher::Dstu7624::generateIV (ByteArray** baIV)
{
    int ret = RET_OK;
    ByteArray* ba_iv = nullptr;

    CHECK_NOT_NULL(ba_iv = ba_alloc_by_len(SIZE_IV));
    DO(drbg_random(ba_iv));

    *baIV = ba_iv;
    ba_iv = nullptr;

cleanup:
    ba_free(ba_iv);
    return ret;
}


int UapkiNS::Cipher::Gost28147::cryptData (const UapkiNS::AlgorithmIdentifier& algoId, const ByteArray* baKey,
                    const Direction direction, const ByteArray* baDataIn, ByteArray** baDataOut)
{
    int ret = RET_OK;
    UapkiNS::SmartBA sba_iv, sba_sbox;
    Gost28147Ctx* ctx = nullptr;
    int gost28147_mode = 0;

    if (algoId.algorithm == string(OID_GOST28147_CTR)) {
        gost28147_mode = 2;
    }
    else if (algoId.algorithm == string(OID_GOST28147_CFB)) {
        gost28147_mode = 3;
    }
    else {
        SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
    }

    DO(decodeParams(algoId.baParameters, &sba_iv, &sba_sbox, false));
    if (sba_sbox.size() > 0) {
        CHECK_NOT_NULL(ctx = gost28147_alloc_user_sbox(sba_sbox.get()));
    }
    else {
        CHECK_NOT_NULL(ctx = gost28147_alloc(GOST28147_SBOX_DEFAULT));
    }

    switch (gost28147_mode) {
    case 2:
        DO(gost28147_init_ctr(ctx, baKey, sba_iv.get()));
        break;
    case 3:
        DO(gost28147_init_cfb(ctx, baKey, sba_iv.get()));
        break;
    default:
        break;
    }

    if (direction == Direction::ENCRYPT) {
        DO(gost28147_encrypt(ctx, baDataIn, baDataOut));
    }
    else {
        DO(gost28147_decrypt(ctx, baDataIn, baDataOut));
    }

cleanup:
    gost28147_free(ctx);
    return ret;
}

int UapkiNS::Cipher::Gost28147::decodeParams (const ByteArray* baEncoded, ByteArray** baIV, ByteArray** baDKE, const bool compressed)
{
    int ret = RET_OK;
    GOST28147ParamsOptionalDke_t* gost28147_params = nullptr;
    UapkiNS::SmartBA sba_sbox;

    CHECK_NOT_NULL(gost28147_params = (GOST28147ParamsOptionalDke_t*)asn_decode_ba_with_alloc(get_GOST28147ParamsOptionalDke_desc(), baEncoded));
    DO(asn_OCTSTRING2ba(&gost28147_params->iv, baIV));
    if (gost28147_params->dke) {
        if (compressed) {
            DO(asn_OCTSTRING2ba(gost28147_params->dke, baDKE));
        }
        else {
            const uint8_t* buf = gost28147_params->dke->buf;
            const size_t len = (size_t)gost28147_params->dke->size;
            if (!sba_sbox.set(ba_alloc_by_len(2 * len))) {
                SET_ERROR(RET_UAPKI_GENERAL_ERROR);
            }
            for (size_t i = 0, j = 0; i < len; i++) {
                const uint8_t byte = buf[i];
                //  Fast set - previous checked range
                ba_set_byte(sba_sbox.get(), j++, (uint8_t)(byte >> 4));
                ba_set_byte(sba_sbox.get(), j++, (uint8_t)(byte & 0x0F));
            }
            *baDKE = sba_sbox.get();
            sba_sbox.set(nullptr);
        }
    }

cleanup:
    asn_free(get_GOST28147ParamsOptionalDke_desc(), gost28147_params);
    return ret;
}

int UapkiNS::Cipher::Gost28147::encodeParams (const ByteArray* baIV, const ByteArray* baDKE, ByteArray** baEncoded)
{
    int ret = RET_OK;
    GOST28147ParamsOptionalDke_t* gost28147_params = nullptr;

    ASN_ALLOC_TYPE(gost28147_params, GOST28147ParamsOptionalDke_t);
    DO(asn_ba2OCTSTRING(baIV, &gost28147_params->iv));
    if (baDKE) {
        ASN_ALLOC_TYPE(gost28147_params->dke, OCTET_STRING_t);
        DO(asn_ba2OCTSTRING(baDKE, gost28147_params->dke));
    }

    DO(asn_encode_ba(get_GOST28147ParamsOptionalDke_desc(), gost28147_params, baEncoded));

cleanup:
    asn_free(get_GOST28147ParamsOptionalDke_desc(), gost28147_params);
    return ret;
}

int UapkiNS::Cipher::Gost28147::generateKey (ByteArray** baKey)
{
    return gost28147_generate_key(baKey);
}

int UapkiNS::Cipher::Gost28147::generateIV (ByteArray** baIV)
{
    int ret = RET_OK;
    ByteArray* ba_iv = nullptr;

    CHECK_NOT_NULL(ba_iv = ba_alloc_by_len(SIZE_IV));
    DO(drbg_random(ba_iv));

    *baIV = ba_iv;
    ba_iv = nullptr;

cleanup:
    ba_free(ba_iv);
    return ret;
}

int UapkiNS::Cipher::Gost28147::getDKE (const Gost28147SboxId sboxId, ByteArray** baCompressedDKE)
{
    const char* s_hex = nullptr;

    switch (sboxId) {
    case GOST28147_SBOX_DEFAULT:
    case GOST28147_SBOX_ID_1:
        s_hex = SHEX_GOST28147_SBOX_ID_1;
        break;
    default:
        return RET_INVALID_PARAM;
    }

    *baCompressedDKE = ba_alloc_from_hex(s_hex);
    return (*baCompressedDKE != nullptr) ? RET_OK : RET_UAPKI_GENERAL_ERROR;
}
