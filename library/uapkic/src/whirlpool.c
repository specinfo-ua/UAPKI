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

#include <string.h>
#include <stddef.h>

#include "whirlpool.h"
#include "byte-utils-internal.h"
#include "byte-array-internal.h"
#include "macros-internal.h"

#undef FILE_MARKER
#define FILE_MARKER "uapkic/whirlpool.c"

struct WhirlpoolCtx_st {
    uint64_t length, state[8];
    uint8_t buf[64];
    size_t curlen;
};

static const uint64_t sbox0[] = {
    0x18186018c07830d8ULL, 0x23238c2305af4626ULL, 0xc6c63fc67ef991b8ULL, 0xe8e887e8136fcdfbULL,
    0x878726874ca113cbULL, 0xb8b8dab8a9626d11ULL, 0x0101040108050209ULL, 0x4f4f214f426e9e0dULL,
    0x3636d836adee6c9bULL, 0xa6a6a2a6590451ffULL, 0xd2d26fd2debdb90cULL, 0xf5f5f3f5fb06f70eULL,
    0x7979f979ef80f296ULL, 0x6f6fa16f5fcede30ULL, 0x91917e91fcef3f6dULL, 0x52525552aa07a4f8ULL,
    0x60609d6027fdc047ULL, 0xbcbccabc89766535ULL, 0x9b9b569baccd2b37ULL, 0x8e8e028e048c018aULL,
    0xa3a3b6a371155bd2ULL, 0x0c0c300c603c186cULL, 0x7b7bf17bff8af684ULL, 0x3535d435b5e16a80ULL,
    0x1d1d741de8693af5ULL, 0xe0e0a7e05347ddb3ULL, 0xd7d77bd7f6acb321ULL, 0xc2c22fc25eed999cULL,
    0x2e2eb82e6d965c43ULL, 0x4b4b314b627a9629ULL, 0xfefedffea321e15dULL, 0x575741578216aed5ULL,
    0x15155415a8412abdULL, 0x7777c1779fb6eee8ULL, 0x3737dc37a5eb6e92ULL, 0xe5e5b3e57b56d79eULL,
    0x9f9f469f8cd92313ULL, 0xf0f0e7f0d317fd23ULL, 0x4a4a354a6a7f9420ULL, 0xdada4fda9e95a944ULL,
    0x58587d58fa25b0a2ULL, 0xc9c903c906ca8fcfULL, 0x2929a429558d527cULL, 0x0a0a280a5022145aULL,
    0xb1b1feb1e14f7f50ULL, 0xa0a0baa0691a5dc9ULL, 0x6b6bb16b7fdad614ULL, 0x85852e855cab17d9ULL,
    0xbdbdcebd8173673cULL, 0x5d5d695dd234ba8fULL, 0x1010401080502090ULL, 0xf4f4f7f4f303f507ULL,
    0xcbcb0bcb16c08bddULL, 0x3e3ef83eedc67cd3ULL, 0x0505140528110a2dULL, 0x676781671fe6ce78ULL,
    0xe4e4b7e47353d597ULL, 0x27279c2725bb4e02ULL, 0x4141194132588273ULL, 0x8b8b168b2c9d0ba7ULL,
    0xa7a7a6a7510153f6ULL, 0x7d7de97dcf94fab2ULL, 0x95956e95dcfb3749ULL, 0xd8d847d88e9fad56ULL,
    0xfbfbcbfb8b30eb70ULL, 0xeeee9fee2371c1cdULL, 0x7c7ced7cc791f8bbULL, 0x6666856617e3cc71ULL,
    0xdddd53dda68ea77bULL, 0x17175c17b84b2eafULL, 0x4747014702468e45ULL, 0x9e9e429e84dc211aULL,
    0xcaca0fca1ec589d4ULL, 0x2d2db42d75995a58ULL, 0xbfbfc6bf9179632eULL, 0x07071c07381b0e3fULL,
    0xadad8ead012347acULL, 0x5a5a755aea2fb4b0ULL, 0x838336836cb51befULL, 0x3333cc3385ff66b6ULL,
    0x636391633ff2c65cULL, 0x02020802100a0412ULL, 0xaaaa92aa39384993ULL, 0x7171d971afa8e2deULL,
    0xc8c807c80ecf8dc6ULL, 0x19196419c87d32d1ULL, 0x494939497270923bULL, 0xd9d943d9869aaf5fULL,
    0xf2f2eff2c31df931ULL, 0xe3e3abe34b48dba8ULL, 0x5b5b715be22ab6b9ULL, 0x88881a8834920dbcULL,
    0x9a9a529aa4c8293eULL, 0x262698262dbe4c0bULL, 0x3232c8328dfa64bfULL, 0xb0b0fab0e94a7d59ULL,
    0xe9e983e91b6acff2ULL, 0x0f0f3c0f78331e77ULL, 0xd5d573d5e6a6b733ULL, 0x80803a8074ba1df4ULL,
    0xbebec2be997c6127ULL, 0xcdcd13cd26de87ebULL, 0x3434d034bde46889ULL, 0x48483d487a759032ULL,
    0xffffdbffab24e354ULL, 0x7a7af57af78ff48dULL, 0x90907a90f4ea3d64ULL, 0x5f5f615fc23ebe9dULL,
    0x202080201da0403dULL, 0x6868bd6867d5d00fULL, 0x1a1a681ad07234caULL, 0xaeae82ae192c41b7ULL,
    0xb4b4eab4c95e757dULL, 0x54544d549a19a8ceULL, 0x93937693ece53b7fULL, 0x222288220daa442fULL,
    0x64648d6407e9c863ULL, 0xf1f1e3f1db12ff2aULL, 0x7373d173bfa2e6ccULL, 0x12124812905a2482ULL,
    0x40401d403a5d807aULL, 0x0808200840281048ULL, 0xc3c32bc356e89b95ULL, 0xecec97ec337bc5dfULL,
    0xdbdb4bdb9690ab4dULL, 0xa1a1bea1611f5fc0ULL, 0x8d8d0e8d1c830791ULL, 0x3d3df43df5c97ac8ULL,
    0x97976697ccf1335bULL, 0x0000000000000000ULL, 0xcfcf1bcf36d483f9ULL, 0x2b2bac2b4587566eULL,
    0x7676c57697b3ece1ULL, 0x8282328264b019e6ULL, 0xd6d67fd6fea9b128ULL, 0x1b1b6c1bd87736c3ULL,
    0xb5b5eeb5c15b7774ULL, 0xafaf86af112943beULL, 0x6a6ab56a77dfd41dULL, 0x50505d50ba0da0eaULL,
    0x45450945124c8a57ULL, 0xf3f3ebf3cb18fb38ULL, 0x3030c0309df060adULL, 0xefef9bef2b74c3c4ULL,
    0x3f3ffc3fe5c37edaULL, 0x55554955921caac7ULL, 0xa2a2b2a2791059dbULL, 0xeaea8fea0365c9e9ULL,
    0x656589650fecca6aULL, 0xbabad2bab9686903ULL, 0x2f2fbc2f65935e4aULL, 0xc0c027c04ee79d8eULL,
    0xdede5fdebe81a160ULL, 0x1c1c701ce06c38fcULL, 0xfdfdd3fdbb2ee746ULL, 0x4d4d294d52649a1fULL,
    0x92927292e4e03976ULL, 0x7575c9758fbceafaULL, 0x06061806301e0c36ULL, 0x8a8a128a249809aeULL,
    0xb2b2f2b2f940794bULL, 0xe6e6bfe66359d185ULL, 0x0e0e380e70361c7eULL, 0x1f1f7c1ff8633ee7ULL,
    0x6262956237f7c455ULL, 0xd4d477d4eea3b53aULL, 0xa8a89aa829324d81ULL, 0x96966296c4f43152ULL,
    0xf9f9c3f99b3aef62ULL, 0xc5c533c566f697a3ULL, 0x2525942535b14a10ULL, 0x59597959f220b2abULL,
    0x84842a8454ae15d0ULL, 0x7272d572b7a7e4c5ULL, 0x3939e439d5dd72ecULL, 0x4c4c2d4c5a619816ULL,
    0x5e5e655eca3bbc94ULL, 0x7878fd78e785f09fULL, 0x3838e038ddd870e5ULL, 0x8c8c0a8c14860598ULL,
    0xd1d163d1c6b2bf17ULL, 0xa5a5aea5410b57e4ULL, 0xe2e2afe2434dd9a1ULL, 0x616199612ff8c24eULL,
    0xb3b3f6b3f1457b42ULL, 0x2121842115a54234ULL, 0x9c9c4a9c94d62508ULL, 0x1e1e781ef0663ceeULL,
    0x4343114322528661ULL, 0xc7c73bc776fc93b1ULL, 0xfcfcd7fcb32be54fULL, 0x0404100420140824ULL,
    0x51515951b208a2e3ULL, 0x99995e99bcc72f25ULL, 0x6d6da96d4fc4da22ULL, 0x0d0d340d68391a65ULL,
    0xfafacffa8335e979ULL, 0xdfdf5bdfb684a369ULL, 0x7e7ee57ed79bfca9ULL, 0x242490243db44819ULL,
    0x3b3bec3bc5d776feULL, 0xabab96ab313d4b9aULL, 0xcece1fce3ed181f0ULL, 0x1111441188552299ULL,
    0x8f8f068f0c890383ULL, 0x4e4e254e4a6b9c04ULL, 0xb7b7e6b7d1517366ULL, 0xebeb8beb0b60cbe0ULL,
    0x3c3cf03cfdcc78c1ULL, 0x81813e817cbf1ffdULL, 0x94946a94d4fe3540ULL, 0xf7f7fbf7eb0cf31cULL,
    0xb9b9deb9a1676f18ULL, 0x13134c13985f268bULL, 0x2c2cb02c7d9c5851ULL, 0xd3d36bd3d6b8bb05ULL,
    0xe7e7bbe76b5cd38cULL, 0x6e6ea56e57cbdc39ULL, 0xc4c437c46ef395aaULL, 0x03030c03180f061bULL,
    0x565645568a13acdcULL, 0x44440d441a49885eULL, 0x7f7fe17fdf9efea0ULL, 0xa9a99ea921374f88ULL,
    0x2a2aa82a4d825467ULL, 0xbbbbd6bbb16d6b0aULL, 0xc1c123c146e29f87ULL, 0x53535153a202a6f1ULL,
    0xdcdc57dcae8ba572ULL, 0x0b0b2c0b58271653ULL, 0x9d9d4e9d9cd32701ULL, 0x6c6cad6c47c1d82bULL,
    0x3131c43195f562a4ULL, 0x7474cd7487b9e8f3ULL, 0xf6f6fff6e309f115ULL, 0x464605460a438c4cULL,
    0xacac8aac092645a5ULL, 0x89891e893c970fb5ULL, 0x14145014a04428b4ULL, 0xe1e1a3e15b42dfbaULL,
    0x16165816b04e2ca6ULL, 0x3a3ae83acdd274f7ULL, 0x6969b9696fd0d206ULL, 0x09092409482d1241ULL,
    0x7070dd70a7ade0d7ULL, 0xb6b6e2b6d954716fULL, 0xd0d067d0ceb7bd1eULL, 0xeded93ed3b7ec7d6ULL,
    0xcccc17cc2edb85e2ULL, 0x424215422a578468ULL, 0x98985a98b4c22d2cULL, 0xa4a4aaa4490e55edULL,
    0x2828a0285d885075ULL, 0x5c5c6d5cda31b886ULL, 0xf8f8c7f8933fed6bULL, 0x8686228644a411c2ULL };

static const uint64_t cont[] = {
    0x1823c6e887b8014fULL, 0x36a6d2f5796f9152ULL, 0x60bc9b8ea30c7b35ULL, 0x1de0d7c22e4bfe57ULL,
    0x157737e59ff04adaULL, 0x58c9290ab1a06b85ULL, 0xbd5d10f4cb3e0567ULL, 0xe427418ba77d95d8ULL,
    0xfbee7c66dd17479eULL, 0xca2dbf07ad5a8333ULL, 0x6302aa71c81949d9ULL };

#define ROR64c(x, y) (((((x) & 0xFFFFFFFFFFFFFFFFULL) >> ((uint64_t)(y) & 0x3FULL)) | ((x)<<(((uint64_t)64-((y)&63))&63))) & 0xFFFFFFFFFFFFFFFFULL)

#define SB0(x) sbox0[x]
#define SB1(x) ROR64c(sbox0[x], 8)
#define SB2(x) ROR64c(sbox0[x], 16)
#define SB3(x) ROR64c(sbox0[x], 24)
#define SB4(x) ROR64c(sbox0[x], 32)
#define SB5(x) ROR64c(sbox0[x], 40)
#define SB6(x) ROR64c(sbox0[x], 48)
#define SB7(x) ROR64c(sbox0[x], 56)

/* get a_{i,j} */
#define GB(a,i,j) ((a[(i) & 7] >> (8 * (j))) & 255)

/* shortcut macro to perform three functions at once */
#define theta_pi_gamma(a, i) \
   (SB0(GB(a, i-0, 7)) ^ SB1(GB(a, i-1, 6)) ^ SB2(GB(a, i-2, 5)) ^ SB3(GB(a, i-3, 4)) ^ \
    SB4(GB(a, i-4, 3)) ^ SB5(GB(a, i-5, 2)) ^ SB6(GB(a, i-6, 1)) ^ SB7(GB(a, i-7, 0)))

#define STORE64H(x, y)                                                                     \
do { (y)[0] = (uint8_t)(((x)>>56)&255); (y)[1] = (uint8_t)(((x)>>48)&255);     \
     (y)[2] = (uint8_t)(((x)>>40)&255); (y)[3] = (uint8_t)(((x)>>32)&255);     \
     (y)[4] = (uint8_t)(((x)>>24)&255); (y)[5] = (uint8_t)(((x)>>16)&255);     \
     (y)[6] = (uint8_t)(((x)>>8)&255); (y)[7] = (uint8_t)((x)&255); } while(0)

#define LOAD64H(x, y)                                                      \
do { x = (((uint64_t)((y)[0] & 255))<<56)|(((uint64_t)((y)[1] & 255))<<48) | \
         (((uint64_t)((y)[2] & 255))<<40)|(((uint64_t)((y)[3] & 255))<<32) | \
         (((uint64_t)((y)[4] & 255))<<24)|(((uint64_t)((y)[5] & 255))<<16) | \
         (((uint64_t)((y)[6] & 255))<<8)|(((uint64_t)((y)[7] & 255))); } while(0)

static void whirlpool_compress(WhirlpoolCtx* ctx)
{
    uint64_t K[2][8], T[3][8];
    size_t x, y;

    /* load the block/state */
    for (x = 0; x < 8; x++) {
        K[0][x] = ctx->state[x];

        LOAD64H(T[0][x], ctx->buf + (8 * x));
        T[2][x] = T[0][x];
        T[0][x] ^= K[0][x];
    }

    /* do rounds 1..10 */
    for (x = 0; x < 10; x += 2) {
        /* odd round */
        /* apply main transform to K[0] into K[1] */
        for (y = 0; y < 8; y++) {
            K[1][y] = theta_pi_gamma(K[0], y);
        }
        /* xor the constant */
        K[1][0] ^= cont[x];

        /* apply main transform to T[0] into T[1] */
        for (y = 0; y < 8; y++) {
            T[1][y] = theta_pi_gamma(T[0], y) ^ K[1][y];
        }

        /* even round */
        /* apply main transform to K[1] into K[0] */
        for (y = 0; y < 8; y++) {
            K[0][y] = theta_pi_gamma(K[1], y);
        }
        /* xor the constant */
        K[0][0] ^= cont[x + 1];

        /* apply main transform to T[1] into T[0] */
        for (y = 0; y < 8; y++) {
            T[0][y] = theta_pi_gamma(T[1], y) ^ K[0][y];
        }
    }

    /* store state */
    for (x = 0; x < 8; x++) {
        ctx->state[x] ^= T[0][x] ^ T[2][x];
    }
}

WhirlpoolCtx* whirlpool_alloc(void)
{
    return calloc(1, sizeof(WhirlpoolCtx));
}

WhirlpoolCtx* whirlpool_copy_with_alloc(const WhirlpoolCtx* ctx)
{
    WhirlpoolCtx* out = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CALLOC_CHECKED(out, sizeof(WhirlpoolCtx));
    memcpy(out, ctx, sizeof(WhirlpoolCtx));

cleanup:

    return out;
}

int whirlpool_update(WhirlpoolCtx* ctx, const ByteArray* msg)
{
    int ret = RET_OK;
    size_t n, inlen;
    const uint8_t* in;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(msg != NULL);

    in = msg->buf;
    inlen = msg->len;
    ctx->length += inlen * 8;

    while (inlen > 0) {
        n = inlen;
        if (n > (64 - ctx->curlen)) {
            n = 64 - ctx->curlen;
        }
        memcpy(ctx->buf + ctx->curlen, in, n);
        ctx->curlen += n;
        in += n;
        inlen -= n;
        if (ctx->curlen == 64) {
            whirlpool_compress(ctx);
            ctx->curlen = 0;
        }
    }

cleanup:
    return ret;
}

int whirlpool_final(WhirlpoolCtx *ctx, ByteArray** H)
{
    int ret = RET_OK;
    size_t i;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(H != NULL);
    CHECK_NOT_NULL(*H = ba_alloc_by_len(64));

    ctx->buf[ctx->curlen++] = (uint8_t)0x80;

    if (ctx->curlen > 32) {
        memset(ctx->buf + ctx->curlen, 0, 64 - ctx->curlen);
        whirlpool_compress(ctx);
        ctx->curlen = 0;
    }

    memset(ctx->buf + ctx->curlen, 0, 56 - ctx->curlen);
    STORE64H(ctx->length, ctx->buf + 56);
    whirlpool_compress(ctx);

    for (i = 0; i < 8; i++) {
        STORE64H(ctx->state[i], (*H)->buf + (8 * i));
    }

    memset(ctx, 0, sizeof(WhirlpoolCtx));

cleanup:
    return ret;
}

size_t whirlpool_get_block_size(const WhirlpoolCtx* ctx)
{
    (void)ctx;
    return 64;
}

void whirlpool_free(WhirlpoolCtx* ctx)
{
    if (ctx) {
        secure_zero(ctx, sizeof(WhirlpoolCtx));
        free(ctx);
    }
}

int whirlpool_self_test(void)
{
    // ДСТУ ISO/IEC 10118-3:2005. A.7.1, A.7.3
    static const uint8_t hNULL[] = {
        0x19, 0xFA, 0x61, 0xD7, 0x55, 0x22, 0xA4, 0x66, 0x9B, 0x44, 0xE3, 0x9C, 0x1D, 0x2E, 0x17, 0x26,
        0xC5, 0x30, 0x23, 0x21, 0x30, 0xD4, 0x07, 0xF8, 0x9A, 0xFE, 0xE0, 0x96, 0x49, 0x97, 0xF7, 0xA7,
        0x3E, 0x83, 0xBE, 0x69, 0x8B, 0x28, 0x8F, 0xEB, 0xCF, 0x88, 0xE3, 0xE0, 0x3C, 0x4F, 0x07, 0x57,
        0xEA, 0x89, 0x64, 0xE5, 0x9B, 0x63, 0xD9, 0x37, 0x08, 0xB1, 0x38, 0xCC, 0x42, 0xA6, 0x6E, 0xB3 };
    static const uint8_t M1[] = "abc";
    static const uint8_t H1[] = {
        0x4E, 0x24, 0x48, 0xA4, 0xC6, 0xF4, 0x86, 0xBB, 0x16, 0xB6, 0x56, 0x2C, 0x73, 0xB4, 0x02, 0x0B, 
        0xF3, 0x04, 0x3E, 0x3A, 0x73, 0x1B, 0xCE, 0x72, 0x1A, 0xE1, 0xB3, 0x03, 0xD9, 0x7E, 0x6D, 0x4C, 
        0x71, 0x81, 0xEE, 0xBD, 0xB6, 0xC5, 0x7E, 0x27, 0x7D, 0x0E, 0x34, 0x95, 0x71, 0x14, 0xCB, 0xD6, 
        0xC7, 0x97, 0xFC, 0x9D, 0x95, 0xD8, 0xB5, 0x82, 0xD2, 0x25, 0x29, 0x20, 0x76, 0xD4, 0xEE, 0xF5 };

    static const ByteArray ba_M1 = { (uint8_t*)M1, sizeof(M1) - 1 };

    int ret = RET_OK;
    WhirlpoolCtx* ctx = NULL;
    ByteArray* ba_hash = NULL;

    CHECK_NOT_NULL(ctx = whirlpool_alloc());
    DO(whirlpool_final(ctx, &ba_hash));
    if ((ba_hash->len != sizeof(hNULL)) ||
        (memcmp(ba_hash->buf, hNULL, sizeof(hNULL)) != 0)) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }
    ba_free(ba_hash);
    ba_hash = NULL;

    DO(whirlpool_update(ctx, &ba_M1));
    DO(whirlpool_final(ctx, &ba_hash));
    if ((ba_hash->len != sizeof(H1)) ||
        (memcmp(ba_hash->buf, H1, sizeof(H1)) != 0)) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

cleanup:
    ba_free(ba_hash);
    whirlpool_free(ctx);
    return ret;
}


