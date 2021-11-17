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

#include <memory.h>
#include <stdbool.h>

#include "dstu7564.h"
#include "byte-utils-internal.h"
#include "byte-array-internal.h"
#include "macros-internal.h"

#undef FILE_MARKER
#define FILE_MARKER "uapkic/dstu7564.c"

#define UINT64_LEN 8
#define ROWS 8
#define NB_512 8                                /* Number of 8-byte words in state for <=256-bit H code. */
#define NB_1024 16                              /* Number of 8-byte words in state for <=512-bit H code. */
#define STATE_BYTE_SIZE_512 (ROWS * NB_512)
#define STATE_BYTE_SIZE_1024 (ROWS * NB_1024)
#define NR_512 10                               /* Number of rounds for 512-bit state.*/
#define NR_1024 14                              /* Number of rounds for 1024-bit state.*/
#define REDUCTION_POLYNOMIAL 0x11d              /* x^8 + x^4 + x^3 + x^2 + 1 */
#define MAX_NUM_IN_BYTE 256
#define MAX_BLOCK_LEN 64
#define SBOX_LEN 1024

#define BITS_IN_BYTE 8

// з dstu7624
extern const uint64_t subrowcol_default[8][256];

#define table_G(in, v1,v2,v3,v4,v5,v6,v7,v8)      (uint64_t) ( subrowcol_default[0][v1       & 0xFF])^\
                                                  (uint64_t) ( subrowcol_default[1][v2 >> 8  & 0xFF])^\
                                                  (uint64_t) ( subrowcol_default[2][v3 >> 16 & 0xFF])^\
                                                  (uint64_t) ( subrowcol_default[3][v4 >> 24 & 0xFF])^\
                                                  (uint64_t) ( subrowcol_default[4][v5 >> 32 & 0xFF])^\
                                                  (uint64_t) ( subrowcol_default[5][v6 >> 40 & 0xFF])^\
                                                  (uint64_t) ( subrowcol_default[6][v7 >> 48 & 0xFF])^\
                                                  (uint64_t) ( subrowcol_default[7][v8 >> 56 & 0xFF]);

/*Константа для P раунда*/
static uint64_t p_pconst[NR_1024][NB_1024] = {
    {
        0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0,
    },
    {
        0x01, 0x11, 0x21, 0x31, 0x41, 0x51, 0x61, 0x71, 0x81, 0x91, 0xa1, 0xb1, 0xc1, 0xd1, 0xe1, 0xf1,
    },
    {
        0x02, 0x12, 0x22, 0x32, 0x42, 0x52, 0x62, 0x72, 0x82, 0x92, 0xa2, 0xb2, 0xc2, 0xd2, 0xe2, 0xf2,
    },
    {
        0x03, 0x13, 0x23, 0x33, 0x43, 0x53, 0x63, 0x73, 0x83, 0x93, 0xa3, 0xb3, 0xc3, 0xd3, 0xe3, 0xf3,
    },
    {
        0x04, 0x14, 0x24, 0x34, 0x44, 0x54, 0x64, 0x74, 0x84, 0x94, 0xa4, 0xb4, 0xc4, 0xd4, 0xe4, 0xf4,
    },
    {
        0x05, 0x15, 0x25, 0x35, 0x45, 0x55, 0x65, 0x75, 0x85, 0x95, 0xa5, 0xb5, 0xc5, 0xd5, 0xe5, 0xf5,
    },
    {
        0x06, 0x16, 0x26, 0x36, 0x46, 0x56, 0x66, 0x76, 0x86, 0x96, 0xa6, 0xb6, 0xc6, 0xd6, 0xe6, 0xf6,
    },
    {
        0x07, 0x17, 0x27, 0x37, 0x47, 0x57, 0x67, 0x77, 0x87, 0x97, 0xa7, 0xb7, 0xc7, 0xd7, 0xe7, 0xf7,
    },
    {
        0x08, 0x18, 0x28, 0x38, 0x48, 0x58, 0x68, 0x78, 0x88, 0x98, 0xa8, 0xb8, 0xc8, 0xd8, 0xe8, 0xf8,
    },
    {
        0x09, 0x19, 0x29, 0x39, 0x49, 0x59, 0x69, 0x79, 0x89, 0x99, 0xa9, 0xb9, 0xc9, 0xd9, 0xe9, 0xf9,
    },
    {
        0x0a, 0x1a, 0x2a, 0x3a, 0x4a, 0x5a, 0x6a, 0x7a, 0x8a, 0x9a, 0xaa, 0xba, 0xca, 0xda, 0xea, 0xfa,
    },
    {
        0x0b, 0x1b, 0x2b, 0x3b, 0x4b, 0x5b, 0x6b, 0x7b, 0x8b, 0x9b, 0xab, 0xbb, 0xcb, 0xdb, 0xeb, 0xfb,
    },
    {
        0x0c, 0x1c, 0x2c, 0x3c, 0x4c, 0x5c, 0x6c, 0x7c, 0x8c, 0x9c, 0xac, 0xbc, 0xcc, 0xdc, 0xec, 0xfc,
    },
    {
        0x0d, 0x1d, 0x2d, 0x3d, 0x4d, 0x5d, 0x6d, 0x7d, 0x8d, 0x9d, 0xad, 0xbd, 0xcd, 0xdd, 0xed, 0xfd,
    }
};

/*Константа для Q раунда, блок 64 байти*/
static uint64_t p_qconst_NB_512[NR_512][NB_512] = {
    {
        8138269444283625715ULL, 6985347939676778739ULL, 5832426435069931763ULL, 4679504930463084787ULL, 
        3526583425856237811ULL, 2373661921249390835ULL, 1220740416642543859ULL, 67818912035696883ULL
    },
    {
        8210327038321553651ULL, 7057405533714706675ULL, 5904484029107859699ULL, 4751562524501012723ULL, 
        3598641019894165747ULL, 2445719515287318771ULL, 1292798010680471795ULL, 139876506073624819ULL
    },
    {
        8282384632359481587ULL, 7129463127752634611ULL, 5976541623145787635ULL, 4823620118538940659ULL, 
        3670698613932093683ULL, 2517777109325246707ULL, 1364855604718399731ULL, 211934100111552755ULL
    },
    {
        8354442226397409523ULL, 7201520721790562547ULL, 6048599217183715571ULL, 4895677712576868595ULL, 
        3742756207970021619ULL, 2589834703363174643ULL, 1436913198756327667ULL, 283991694149480691ULL
    },
    {
        8426499820435337459ULL, 7273578315828490483ULL, 6120656811221643507ULL, 4967735306614796531ULL, 
        3814813802007949555ULL, 2661892297401102579ULL, 1508970792794255603ULL, 356049288187408627ULL
    },
    {
        8498557414473265395ULL, 7345635909866418419ULL, 6192714405259571443ULL, 5039792900652724467ULL, 
        3886871396045877491ULL, 2733949891439030515ULL, 1581028386832183539ULL, 428106882225336563ULL
    },
    {
        8570615008511193331ULL, 7417693503904346355ULL, 6264771999297499379ULL, 5111850494690652403ULL, 
        3958928990083805427ULL, 2806007485476958451ULL, 1653085980870111475ULL, 500164476263264499ULL
    },
    {
        8642672602549121267ULL, 7489751097942274291ULL, 6336829593335427315ULL, 5183908088728580339ULL, 
        4030986584121733363ULL, 2878065079514886387ULL, 1725143574908039411ULL, 572222070301192435ULL
    },
    {
        8714730196587049203ULL, 7561808691980202227ULL, 6408887187373355251ULL, 5255965682766508275ULL, 
        4103044178159661299ULL, 2950122673552814323ULL, 1797201168945967347ULL, 644279664339120371ULL
    },
    {
        8786787790624977139ULL, 7633866286018130163ULL, 6480944781411283187ULL, 5328023276804436211ULL, 
        4175101772197589235ULL, 3022180267590742259ULL, 1869258762983895283ULL, 716337258377048307ULL
    }
};

/*Константа для Q раунда, блок 128 байт*/
static uint64_t p_qconst_NB_1024[NR_1024][NB_1024] = {
    {
        17361641481138401523ULL, 16208719976531554547ULL, 15055798471924707571ULL, 13902876967317860595ULL, 
        12749955462711013619ULL, 11597033958104166643ULL, 10444112453497319667ULL, 9291190948890472691ULL, 
        8138269444283625715ULL, 6985347939676778739ULL, 5832426435069931763ULL, 4679504930463084787ULL, 
        3526583425856237811ULL, 2373661921249390835ULL, 1220740416642543859ULL, 67818912035696883ULL
    },
    {
        17433699075176329459ULL, 16280777570569482483ULL, 15127856065962635507ULL, 13974934561355788531ULL, 
        12822013056748941555ULL, 11669091552142094579ULL, 10516170047535247603ULL, 9363248542928400627ULL, 
        8210327038321553651ULL, 7057405533714706675ULL, 5904484029107859699ULL, 4751562524501012723ULL, 
        3598641019894165747ULL, 2445719515287318771ULL, 1292798010680471795ULL, 139876506073624819ULL
    },
    {
        17505756669214257395ULL, 16352835164607410419ULL, 15199913660000563443ULL, 14046992155393716467ULL, 
        12894070650786869491ULL, 11741149146180022515ULL, 10588227641573175539ULL, 9435306136966328563ULL, 
        8282384632359481587ULL, 7129463127752634611ULL, 5976541623145787635ULL, 4823620118538940659ULL, 
        3670698613932093683ULL, 2517777109325246707ULL, 1364855604718399731ULL, 211934100111552755ULL
    },
    {
        17577814263252185331ULL, 16424892758645338355ULL, 15271971254038491379ULL, 14119049749431644403ULL, 
        12966128244824797427ULL, 11813206740217950451ULL, 10660285235611103475ULL, 9507363731004256499ULL, 
        8354442226397409523ULL, 7201520721790562547ULL, 6048599217183715571ULL, 4895677712576868595ULL, 
        3742756207970021619ULL, 2589834703363174643ULL, 1436913198756327667ULL, 283991694149480691ULL
    },
    {
        17649871857290113267ULL, 16496950352683266291ULL, 15344028848076419315ULL, 14191107343469572339ULL, 
        13038185838862725363ULL, 11885264334255878387ULL, 10732342829649031411ULL, 9579421325042184435ULL, 
        8426499820435337459ULL, 7273578315828490483ULL, 6120656811221643507ULL, 4967735306614796531ULL, 
        3814813802007949555ULL, 2661892297401102579ULL, 1508970792794255603ULL, 356049288187408627ULL
    },
    {
        17721929451328041203ULL, 16569007946721194227ULL, 15416086442114347251ULL, 14263164937507500275ULL, 
        13110243432900653299ULL, 11957321928293806323ULL, 10804400423686959347ULL, 9651478919080112371ULL, 
        8498557414473265395ULL, 7345635909866418419ULL, 6192714405259571443ULL, 5039792900652724467ULL, 
        3886871396045877491ULL, 2733949891439030515ULL, 1581028386832183539ULL, 428106882225336563ULL
    },
    {
        17793987045365969139ULL, 16641065540759122163ULL, 15488144036152275187ULL, 14335222531545428211ULL, 
        13182301026938581235ULL, 12029379522331734259ULL, 10876458017724887283ULL, 9723536513118040307ULL, 
        8570615008511193331ULL, 7417693503904346355ULL, 6264771999297499379ULL, 5111850494690652403ULL, 
        3958928990083805427ULL, 2806007485476958451ULL, 1653085980870111475ULL, 500164476263264499ULL
    },
    {
        17866044639403897075ULL, 16713123134797050099ULL, 15560201630190203123ULL, 14407280125583356147ULL, 
        13254358620976509171ULL, 12101437116369662195ULL, 10948515611762815219ULL, 9795594107155968243ULL, 
        8642672602549121267ULL, 7489751097942274291ULL, 6336829593335427315ULL, 5183908088728580339ULL, 
        4030986584121733363ULL, 2878065079514886387ULL, 1725143574908039411ULL, 572222070301192435ULL
    },
    {
        17938102233441825011ULL, 16785180728834978035ULL, 15632259224228131059ULL, 14479337719621284083ULL, 
        13326416215014437107ULL, 12173494710407590131ULL, 11020573205800743155ULL, 9867651701193896179ULL, 
        8714730196587049203ULL, 7561808691980202227ULL, 6408887187373355251ULL, 5255965682766508275ULL, 
        4103044178159661299ULL, 2950122673552814323ULL, 1797201168945967347ULL, 644279664339120371ULL
    },
    {
        18010159827479752947ULL, 16857238322872905971ULL, 15704316818266058995ULL, 14551395313659212019ULL, 
        13398473809052365043ULL, 12245552304445518067ULL, 11092630799838671091ULL, 9939709295231824115ULL, 
        8786787790624977139ULL, 7633866286018130163ULL, 6480944781411283187ULL, 5328023276804436211ULL, 
        4175101772197589235ULL, 3022180267590742259ULL, 1869258762983895283ULL, 716337258377048307ULL
    },
    {
        18082217421517680883ULL, 16929295916910833907ULL, 15776374412303986931ULL, 14623452907697139955ULL, 
        13470531403090292979ULL, 12317609898483446003ULL, 11164688393876599027ULL, 10011766889269752051ULL, 
        8858845384662905075ULL, 7705923880056058099ULL, 6553002375449211123ULL, 5400080870842364147ULL, 
        4247159366235517171ULL, 3094237861628670195ULL, 1941316357021823219ULL, 788394852414976243ULL
    },
    {
        18154275015555608819ULL, 17001353510948761843ULL, 15848432006341914867ULL, 14695510501735067891ULL, 
        13542588997128220915ULL, 12389667492521373939ULL, 11236745987914526963ULL, 10083824483307679987ULL, 
        8930902978700833011ULL, 7777981474093986035ULL, 6625059969487139059ULL, 5472138464880292083ULL, 
        4319216960273445107ULL, 3166295455666598131ULL, 2013373951059751155ULL, 860452446452904179ULL
    },
    {
        18226332609593536755ULL, 17073411104986689779ULL, 15920489600379842803ULL, 14767568095772995827ULL, 
        13614646591166148851ULL, 12461725086559301875ULL, 11308803581952454899ULL, 10155882077345607923ULL, 
        9002960572738760947ULL, 7850039068131913971ULL, 6697117563525066995ULL, 5544196058918220019ULL, 
        4391274554311373043ULL, 3238353049704526067ULL, 2085431545097679091ULL, 932510040490832115ULL
    },
    {
        18298390203631464691ULL, 17145468699024617715ULL, 15992547194417770739ULL, 14839625689810923763ULL, 
        13686704185204076787ULL, 12533782680597229811ULL, 11380861175990382835ULL, 10227939671383535859ULL, 
        9075018166776688883ULL, 7922096662169841907ULL, 6769175157562994931ULL, 5616253652956147955ULL, 
        4463332148349300979ULL, 3310410643742454003ULL, 2157489139135607027ULL, 1004567634528760051ULL
    }
};

typedef struct {
    uint8_t key[STATE_BYTE_SIZE_1024];
    uint8_t invert_key[STATE_BYTE_SIZE_1024];
    size_t key_len;
} Dstu7564Hmac;

struct Dstu7564Ctx_st {
    uint8_t last_block[STATE_BYTE_SIZE_1024 * 2];
    size_t last_block_el;
    uint64_t msg_tot_len[2];
    uint8_t state[NB_1024 * ROWS];
    size_t nbytes;                              /* Number of bytes currently located in state. */
    size_t hash_nbytes;                         /* Hash code byte length. */
    size_t columns;                             /* Number of columns (8-byte vectors) located in internal state. */
    size_t is_inited;                           /* Reinit checker */
    size_t rounds;                              /* Number of rounds for current mode of operation. */
    Dstu7564Hmac *hmac;
};

static void dstu7564_hmac_free(Dstu7564Hmac *hmac) {
    if (hmac) {
        secure_zero(hmac, sizeof(Dstu7564Hmac));
        free(hmac);
    }
}

static void padding(uint8_t *buf, uint64_t buf_len_out, uint64_t *msg_tot_len, size_t nbytes)
{
    size_t zero_nbytes;
    size_t cur_pos;
    int i;
    uint64_t msg_len_bit_lo, msg_len_bit_hi;

    msg_len_bit_lo = (msg_tot_len[0] << 3);
    msg_len_bit_hi = (msg_tot_len[1] << 3) | (msg_tot_len[0] >> (64 - 3));

    cur_pos = buf_len_out % nbytes;
    zero_nbytes = (~((msg_len_bit_lo) + 97) % ((uint64_t)nbytes << 3)) >> 3;
    buf[cur_pos] = 0x80;
    cur_pos++;
    memset(&buf[cur_pos], 0, zero_nbytes);
    cur_pos += zero_nbytes;

    for (i = 0; i < 8; ++i, ++cur_pos) {
        buf[cur_pos] = ((msg_len_bit_lo) >> (i << 3)) & 0xFF;
    }

    for (i = 0; i < 4; ++i, ++cur_pos) {
        buf[cur_pos] = ((msg_len_bit_hi) >> (i << 3)) & 0xFF;
    }
}

static __inline void kupyna_G_xor(Dstu7564Ctx *ctx, uint64_t *in, uint64_t *out, size_t i)
{
    if (ctx->columns == NB_512) {
        uint64_t i0 = in[0];
        uint64_t i1 = in[1];
        uint64_t i2 = in[2];
        uint64_t i3 = in[3];
        uint64_t i4 = in[4];
        uint64_t i5 = in[5];
        uint64_t i6 = in[6];
        uint64_t i7 = in[7];
        i0 ^= p_pconst[i][0];
        i1 ^= p_pconst[i][1];
        i2 ^= p_pconst[i][2];
        i3 ^= p_pconst[i][3];
        i4 ^= p_pconst[i][4];
        i5 ^= p_pconst[i][5];
        i6 ^= p_pconst[i][6];
        i7 ^= p_pconst[i][7];
        out[0] = table_G(in, i0, i7, i6, i5, i4, i3, i2, i1);
        out[1] = table_G(in, i1, i0, i7, i6, i5, i4, i3, i2);
        out[2] = table_G(in, i2, i1, i0, i7, i6, i5, i4, i3);
        out[3] = table_G(in, i3, i2, i1, i0, i7, i6, i5, i4);
        out[4] = table_G(in, i4, i3, i2, i1, i0, i7, i6, i5);
        out[5] = table_G(in, i5, i4, i3, i2, i1, i0, i7, i6);
        out[6] = table_G(in, i6, i5, i4, i3, i2, i1, i0, i7);
        out[7] = table_G(in, i7, i6, i5, i4, i3, i2, i1, i0);
    } else {
        uint64_t i0 = in[0];
        uint64_t i1 = in[1];
        uint64_t i2 = in[2];
        uint64_t i3 = in[3];
        uint64_t i4 = in[4];
        uint64_t i5 = in[5];
        uint64_t i6 = in[6];
        uint64_t i7 = in[7];
        uint64_t i8 = in[8];
        uint64_t i9 = in[9];
        uint64_t i10 = in[10];
        uint64_t i11 = in[11];
        uint64_t i12 = in[12];
        uint64_t i13 = in[13];
        uint64_t i14 = in[14];
        uint64_t i15 = in[15];
        i0  ^= p_pconst[i][0];
        i1  ^= p_pconst[i][1];
        i2  ^= p_pconst[i][2];
        i3  ^= p_pconst[i][3];
        i4  ^= p_pconst[i][4];
        i5  ^= p_pconst[i][5];
        i6  ^= p_pconst[i][6];
        i7  ^= p_pconst[i][7];
        i8  ^= p_pconst[i][8];
        i9  ^= p_pconst[i][9];
        i10 ^= p_pconst[i][10];
        i11 ^= p_pconst[i][11];
        i12 ^= p_pconst[i][12];
        i13 ^= p_pconst[i][13];
        i14 ^= p_pconst[i][14];
        i15 ^= p_pconst[i][15];
        out[0 ] = table_G(in, i0, i15, i14, i13, i12, i11, i10, i5);
        out[1 ] = table_G(in, i1, i0, i15, i14, i13, i12, i11, i6);
        out[2 ] = table_G(in, i2, i1, i0, i15, i14, i13, i12, i7);
        out[3 ] = table_G(in, i3, i2, i1, i0, i15, i14, i13, i8);
        out[4 ] = table_G(in, i4, i3, i2, i1, i0, i15, i14, i9);
        out[5 ] = table_G(in, i5, i4, i3, i2, i1, i0, i15, i10);
        out[6 ] = table_G(in, i6, i5, i4, i3, i2, i1, i0, i11);
        out[7 ] = table_G(in, i7, i6, i5, i4, i3, i2, i1, i12);
        out[8 ] = table_G(in, i8, i7, i6, i5, i4, i3, i2, i13);
        out[9 ] = table_G(in, i9, i8, i7, i6, i5, i4, i3, i14);
        out[10] = table_G(in, i10, i9, i8, i7, i6, i5, i4, i15);
        out[11] = table_G(in, i11, i10, i9, i8, i7, i6, i5, i0);
        out[12] = table_G(in, i12, i11, i10, i9, i8, i7, i6, i1);
        out[13] = table_G(in, i13, i12, i11, i10, i9, i8, i7, i2);
        out[14] = table_G(in, i14, i13, i12, i11, i10, i9, i8, i3);
        out[15] = table_G(in, i15, i14, i13, i12, i11, i10, i9, i4);
    }
}

static __inline void kupyna_G_add(Dstu7564Ctx *ctx, uint64_t *in, uint64_t *out, size_t i)
{
    if (ctx->columns == NB_512) {
        uint64_t i0 = in[0];
        uint64_t i1 = in[1];
        uint64_t i2 = in[2];
        uint64_t i3 = in[3];
        uint64_t i4 = in[4];
        uint64_t i5 = in[5];
        uint64_t i6 = in[6];
        uint64_t i7 = in[7];
        i0 += p_qconst_NB_512[i][0];
        i1 += p_qconst_NB_512[i][1];
        i2 += p_qconst_NB_512[i][2];
        i3 += p_qconst_NB_512[i][3];
        i4 += p_qconst_NB_512[i][4];
        i5 += p_qconst_NB_512[i][5];
        i6 += p_qconst_NB_512[i][6];
        i7 += p_qconst_NB_512[i][7];
        out[0] = table_G(in, i0, i7, i6, i5, i4, i3, i2, i1);
        out[1] = table_G(in, i1, i0, i7, i6, i5, i4, i3, i2);
        out[2] = table_G(in, i2, i1, i0, i7, i6, i5, i4, i3);
        out[3] = table_G(in, i3, i2, i1, i0, i7, i6, i5, i4);
        out[4] = table_G(in, i4, i3, i2, i1, i0, i7, i6, i5);
        out[5] = table_G(in, i5, i4, i3, i2, i1, i0, i7, i6);
        out[6] = table_G(in, i6, i5, i4, i3, i2, i1, i0, i7);
        out[7] = table_G(in, i7, i6, i5, i4, i3, i2, i1, i0);
    } else {
        uint64_t i0 = in[0];
        uint64_t i1 = in[1];
        uint64_t i2 = in[2];
        uint64_t i3 = in[3];
        uint64_t i4 = in[4];
        uint64_t i5 = in[5];
        uint64_t i6 = in[6];
        uint64_t i7 = in[7];
        uint64_t i8 = in[8];
        uint64_t i9 = in[9];
        uint64_t i10 = in[10];
        uint64_t i11 = in[11];
        uint64_t i12 = in[12];
        uint64_t i13 = in[13];
        uint64_t i14 = in[14];
        uint64_t i15 = in[15];
        i0  += p_qconst_NB_1024[i][0];
        i1  += p_qconst_NB_1024[i][1];
        i2  += p_qconst_NB_1024[i][2];
        i3  += p_qconst_NB_1024[i][3];
        i4  += p_qconst_NB_1024[i][4];
        i5  += p_qconst_NB_1024[i][5];
        i6  += p_qconst_NB_1024[i][6];
        i7  += p_qconst_NB_1024[i][7];
        i8  += p_qconst_NB_1024[i][8];
        i9  += p_qconst_NB_1024[i][9];
        i10 += p_qconst_NB_1024[i][10];
        i11 += p_qconst_NB_1024[i][11];
        i12 += p_qconst_NB_1024[i][12];
        i13 += p_qconst_NB_1024[i][13];
        i14 += p_qconst_NB_1024[i][14];
        i15 += p_qconst_NB_1024[i][15];
        out[0 ] = table_G(in, i0, i15, i14, i13, i12, i11, i10, i5);
        out[1 ] = table_G(in, i1, i0, i15, i14, i13, i12, i11, i6);
        out[2 ] = table_G(in, i2, i1, i0, i15, i14, i13, i12, i7);
        out[3 ] = table_G(in, i3, i2, i1, i0, i15, i14, i13, i8);
        out[4 ] = table_G(in, i4, i3, i2, i1, i0, i15, i14, i9);
        out[5 ] = table_G(in, i5, i4, i3, i2, i1, i0, i15, i10);
        out[6 ] = table_G(in, i6, i5, i4, i3, i2, i1, i0, i11);
        out[7 ] = table_G(in, i7, i6, i5, i4, i3, i2, i1, i12);
        out[8 ] = table_G(in, i8, i7, i6, i5, i4, i3, i2, i13);
        out[9 ] = table_G(in, i9, i8, i7, i6, i5, i4, i3, i14);
        out[10] = table_G(in, i10, i9, i8, i7, i6, i5, i4, i15);
        out[11] = table_G(in, i11, i10, i9, i8, i7, i6, i5, i0);
        out[12] = table_G(in, i12, i11, i10, i9, i8, i7, i6, i1);
        out[13] = table_G(in, i13, i12, i11, i10, i9, i8, i7, i2);
        out[14] = table_G(in, i14, i13, i12, i11, i10, i9, i8, i3);
        out[15] = table_G(in, i15, i14, i13, i12, i11, i10, i9, i4);
    }
}

static __inline void P(Dstu7564Ctx *ctx, uint8_t *state_)
{
    uint64_t s[NB_1024];
    uint64_t state[NB_1024];
    size_t block_len;

    block_len = ctx->columns << 3;
    uint8_to_uint64(state_, ctx->columns << 3, state, ctx->columns);

    kupyna_G_xor(ctx, state, s, (size_t) 0);
    kupyna_G_xor(ctx, s, state, (size_t) 1);
    kupyna_G_xor(ctx, state, s, (size_t) 2);
    kupyna_G_xor(ctx, s, state, (size_t) 3);
    kupyna_G_xor(ctx, state, s, (size_t) 4);
    kupyna_G_xor(ctx, s, state, (size_t) 5);
    kupyna_G_xor(ctx, state, s, (size_t) 6);
    kupyna_G_xor(ctx, s, state, (size_t) 7);
    kupyna_G_xor(ctx, state, s, (size_t) 8);
    kupyna_G_xor(ctx, s, state, (size_t) 9);
    if (ctx->columns == NB_1024) {
        kupyna_G_xor(ctx, state, s, (size_t) 10);
        kupyna_G_xor(ctx, s, state, (size_t) 11);
        kupyna_G_xor(ctx, state, s, (size_t) 12);
        kupyna_G_xor(ctx, s, state, (size_t) 13);
    }

    uint64_to_uint8(state, ctx->columns, state_, block_len);
}

static __inline void Q(Dstu7564Ctx *ctx, uint8_t *state_)
{
    uint64_t s[NB_1024];
    uint64_t state[NB_1024];
    size_t block_len;

    block_len = ctx->columns << 3;
    uint8_to_uint64(state_, block_len, state, ctx->columns);

    kupyna_G_add(ctx, state, s, (size_t) 0);
    kupyna_G_add(ctx, s, state, (size_t) 1);
    kupyna_G_add(ctx, state, s, (size_t) 2);
    kupyna_G_add(ctx, s, state, (size_t) 3);
    kupyna_G_add(ctx, state, s, (size_t) 4);
    kupyna_G_add(ctx, s, state, (size_t) 5);
    kupyna_G_add(ctx, state, s, (size_t) 6);
    kupyna_G_add(ctx, s, state, (size_t) 7);
    kupyna_G_add(ctx, state, s, (size_t) 8);
    kupyna_G_add(ctx, s, state, (size_t) 9);
    if (ctx->columns == NB_1024) {
        kupyna_G_add(ctx, state, s, (size_t) 10);
        kupyna_G_add(ctx, s, state, (size_t) 11);
        kupyna_G_add(ctx, state, s, (size_t) 12);
        kupyna_G_add(ctx, s, state, (size_t) 13);
    }

    uint64_to_uint8(state, ctx->columns, state_, block_len);
}

static __inline void dstu7564_xor(void *arg1, void *arg2, void *out, size_t columns)
{
    uint64_t *a1 = (uint64_t *) arg1;
    uint64_t *a2 = (uint64_t *) arg2;
    uint64_t *o = (uint64_t *) out;

    o[0] = a1[0] ^ a2[0];
    o[1] = a1[1] ^ a2[1];
    o[2] = a1[2] ^ a2[2];
    o[3] = a1[3] ^ a2[3];
    o[4] = a1[4] ^ a2[4];
    o[5] = a1[5] ^ a2[5];
    o[6] = a1[6] ^ a2[6];
    o[7] = a1[7] ^ a2[7];
    if (columns == NB_1024) {
        o[8] = a1[8] ^ a2[8];
        o[9] = a1[9] ^ a2[9];
        o[10] = a1[10] ^ a2[10];
        o[11] = a1[11] ^ a2[11];
        o[12] = a1[12] ^ a2[12];
        o[13] = a1[13] ^ a2[13];
        o[14] = a1[14] ^ a2[14];
        o[15] = a1[15] ^ a2[15];
    }
}

static __inline void digest(Dstu7564Ctx *ctx, uint8_t *data)
{
    uint8_t temp1[NB_1024 * ROWS];
    uint8_t temp2[NB_1024 * ROWS];

    memcpy(temp2, data, ctx->columns << 3);
    dstu7564_xor(ctx->state, data, temp1, ctx->columns);

    P(ctx, temp1);
    Q(ctx, temp2);

    dstu7564_xor(temp1, temp2, temp2, ctx->columns);
    dstu7564_xor(ctx->state, temp2, ctx->state, ctx->columns);
}

static __inline int output_transformation(Dstu7564Ctx *ctx, ByteArray **hash_code)
{
    uint8_t temp[NB_1024 * ROWS];
    int ret = RET_OK;

    memcpy(temp, ctx->state, ROWS * NB_1024);

    P(ctx, temp);

    dstu7564_xor(ctx->state, temp, ctx->state, ctx->columns);

    CHECK_NOT_NULL(*hash_code = ba_alloc_from_uint8(ctx->state + ctx->nbytes - ctx->hash_nbytes, ctx->hash_nbytes));
    dstu7564_init(ctx, ctx->hash_nbytes);

cleanup:

    return ret;
}

Dstu7564Ctx *dstu7564_alloc(void)
{
    Dstu7564Ctx *ctx = NULL;
    int ret = RET_OK;

    CALLOC_CHECKED(ctx, sizeof(Dstu7564Ctx));

    ctx->is_inited = false;

cleanup:

    return ctx;
}

Dstu7564Ctx* dstu7564_copy_with_alloc(const Dstu7564Ctx* ctx)
{
    Dstu7564Ctx* out = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CALLOC_CHECKED(out, sizeof(Dstu7564Ctx));
    memcpy(out, ctx, sizeof(Dstu7564Ctx));
    if (ctx->hmac) {
        MALLOC_CHECKED(out->hmac, sizeof(Dstu7564Hmac));
        memcpy(out->hmac, ctx->hmac, sizeof(Dstu7564Hmac));
    }

cleanup:

    if (ret != RET_OK) {
        dstu7564_free(out);
        ctx = NULL;
    }

    return out;
}

void dstu7564_free(Dstu7564Ctx *ctx)
{
    if (ctx) {
        ctx->is_inited = false;
        dstu7564_hmac_free(ctx->hmac);
        secure_zero(ctx, sizeof(Dstu7564Ctx));
        free(ctx);
    }
}

int dstu7564_init(Dstu7564Ctx *ctx, size_t hash_nbytes)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx);
    CHECK_PARAM((hash_nbytes > 0) & (hash_nbytes <= 64));

    if (hash_nbytes <= 32) {
        ctx->rounds = NR_512;
        ctx->columns = NB_512;
        ctx->nbytes = STATE_BYTE_SIZE_512;
        memset(&ctx->state[0], 0, STATE_BYTE_SIZE_512);
        ctx->state[0] = STATE_BYTE_SIZE_512;
    } else {
        ctx->rounds = NR_1024;
        ctx->columns = NB_1024;
        ctx->nbytes = STATE_BYTE_SIZE_1024;
        memset(&ctx->state[0], 0, STATE_BYTE_SIZE_1024);
        ctx->state[0] = STATE_BYTE_SIZE_1024;
    }
    ctx->hash_nbytes = hash_nbytes;
    memset(&ctx->last_block, 0, STATE_BYTE_SIZE_1024 * 2);

    ctx->last_block_el = 0;
    ctx->msg_tot_len[0] = 0;
    ctx->msg_tot_len[1] = 0;

    if (ctx->is_inited == false) {
        ctx->hmac = NULL;
    }
    ctx->is_inited = true;

cleanup:

    return ret;
}

int dstu7564_update(Dstu7564Ctx *ctx, const ByteArray *data)
{
    int ret = RET_OK;
    uint8_t *data_buf = NULL;
    uint8_t *shifted_buf;
    size_t data_buf_len;
    size_t block_size;
    size_t i = 0;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(data != NULL);

    if (ctx->is_inited == false) {
        SET_ERROR(RET_CONTEXT_NOT_READY);
    }

    data_buf = data->buf;
    data_buf_len = data->len;

    block_size = ctx->nbytes;

    ctx->msg_tot_len[0] += data_buf_len;
    if (ctx->msg_tot_len[0] < (uint64_t)data_buf_len) {
        ctx->msg_tot_len[1]++;
    }

    if (ctx->last_block_el + data_buf_len < block_size) {
        memcpy(&ctx->last_block[ctx->last_block_el], data_buf, data_buf_len);
        ctx->last_block_el += data_buf_len;
        goto cleanup;
    }

    memcpy(&ctx->last_block[ctx->last_block_el], data_buf, block_size - ctx->last_block_el);
    digest(ctx, ctx->last_block);
    memset(&ctx->last_block[0], 0, MAX_BLOCK_LEN);

    shifted_buf = data_buf + (block_size - ctx->last_block_el);
    data_buf_len -= (block_size - ctx->last_block_el);
    for (i = 0; i + block_size <= data_buf_len; i += block_size) {
        digest(ctx, shifted_buf + i);
    }

    ctx->last_block_el = data_buf_len - i;
    if (ctx->last_block_el != 0) {
        memcpy(ctx->last_block, shifted_buf + i, ctx->last_block_el);
    }

cleanup:

    return ret;
}

int dstu7564_final(Dstu7564Ctx *ctx, ByteArray **hash_code)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(hash_code != NULL);
    if (ctx->is_inited == false) {
        SET_ERROR(RET_CONTEXT_NOT_READY);
    }

    padding(ctx->last_block, ctx->last_block_el, ctx->msg_tot_len, ctx->nbytes);
    digest(ctx, ctx->last_block);
    /*Якщо доповнуння призвело до утворення додаткового блоку - гешуємо його*/
    if (ctx->last_block_el > ctx->nbytes - 13) {
        digest(ctx, ctx->last_block + ctx->nbytes);
    }
    DO(output_transformation(ctx, hash_code));

cleanup:

    return ret;
}

int dstu7564_init_kmac(Dstu7564Ctx *ctx, const ByteArray *key, size_t mac_len)
{
    size_t key_buf_len;
    size_t i;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(mac_len == 32 || mac_len == 48 || mac_len == 64);
    key_buf_len = ba_get_len(key);
    CHECK_PARAM(key_buf_len == mac_len);

    /*HMAC(M,K) = H(PAD(K) || PAD(M) || (~K))*/
    DO(dstu7564_init(ctx, mac_len));

    dstu7564_hmac_free(ctx->hmac);
    ctx->hmac = NULL;

    CALLOC_CHECKED(ctx->hmac, sizeof(Dstu7564Hmac));

    DO(ba_to_uint8(key, ctx->hmac->key, key_buf_len));
    ctx->hmac->key_len = key_buf_len;

    memset(ctx->hmac->invert_key, 0, ctx->nbytes);
    memset(ctx->last_block, 0, ctx->nbytes);
    /*~K*/
    for (i = 0; i < key_buf_len; i++) {
        ctx->hmac->invert_key[i] = ~ctx->hmac->key[i];
    }
    /*PAD(K). Ключ всегда дополняется в один блок*/
    ctx->msg_tot_len[0] = key_buf_len;
    padding(ctx->hmac->key, key_buf_len, ctx->msg_tot_len, ctx->nbytes);
    ctx->msg_tot_len[0] = 0;

    /*HASH(PAD(K))*/
    digest(ctx, ctx->hmac->key);

    ctx->hash_nbytes = mac_len;

cleanup:

    return ret;
}

int dstu7564_update_kmac(Dstu7564Ctx *ctx, const ByteArray *data)
{
    int ret = RET_OK;
    if (ctx->is_inited == false) {
        SET_ERROR(RET_CONTEXT_NOT_READY);
    }

    DO(dstu7564_update(ctx, data));

cleanup:

    return ret;
}

int dstu7564_final_kmac(Dstu7564Ctx *ctx, ByteArray **mac)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(mac != NULL);
    if (ctx->is_inited == false) {
        SET_ERROR(RET_CONTEXT_NOT_READY);
    }

    /*PAD(M)*/
    padding(ctx->last_block, ctx->last_block_el, ctx->msg_tot_len, ctx->nbytes);
    digest(ctx, ctx->last_block);
    /*Вирівнюємо довжину на розмір блока*/
    ctx->msg_tot_len[0] += (uint64_t)ctx->nbytes - ctx->last_block_el;
    if (ctx->msg_tot_len[0] < ((uint64_t)ctx->nbytes - ctx->last_block_el)) {
        ctx->msg_tot_len[1]++;
    }

    /*Якщо доповнуння призвело до утворення додаткового блоку - гешуємо його*/
    if (ctx->last_block_el > ctx->nbytes - 13) {
        digest(ctx, ctx->last_block + ctx->nbytes);
        /*Додаємо довжину додаткового блоку*/
        ctx->msg_tot_len[0] += ctx->nbytes;
        if (ctx->msg_tot_len[0] < (uint64_t)ctx->nbytes) {
            ctx->msg_tot_len[1]++;
        }
    }

    memset(ctx->last_block, 0, ctx->nbytes);
    ctx->last_block_el = 0;

    /*Так как наше сообщение состоит еще из PAD(K) и ~K, то добавляем их размер.*/
    ctx->msg_tot_len[0] += ((uint64_t)ctx->nbytes + ctx->hmac->key_len);
    if (ctx->msg_tot_len[0] < ((uint64_t)ctx->nbytes + ctx->hmac->key_len)) {
        ctx->msg_tot_len[1]++;
    }
    
    memcpy(ctx->last_block, ctx->hmac->invert_key, ctx->hmac->key_len);
    /*H(PAD(PAD(K) || PAD(M) || (~K)))*/
    /*Высчитываем дополнение от всего сообщения.*/
    padding(ctx->last_block, ctx->hmac->key_len, ctx->msg_tot_len, ctx->nbytes);

    /*Последний digest. Ключ всегда дополняется в один блок*/
    digest(ctx, ctx->last_block);

    DO(output_transformation(ctx, mac));
    /*Выполняем hmac_init*/
    digest(ctx, ctx->hmac->key);

cleanup:

    return ret;
}

size_t dstu7564_get_block_size(const Dstu7564Ctx* ctx)
{
    if (ctx != NULL) {
        return ctx->nbytes;
    }
    return 0;
}

static int dstu7564_self_test_hash(void)
{
    // ДСТУ 7564:2014
    static const uint8_t M1[] = { 0xFF };
    static const uint8_t M2[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
        0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF };

    static const uint8_t H256_NULL[] = {
        0xCD, 0x51, 0x01, 0xD1, 0xCC, 0xDF, 0x0D, 0x1D, 0x1F, 0x4A, 0xDA, 0x56, 0xE8, 0x88, 0xCD, 0x72,
        0x4C, 0xA1, 0xA0, 0x83, 0x8A, 0x35, 0x21, 0xE7, 0x13, 0x1D, 0x4F, 0xB7, 0x8D, 0x0F, 0x5E, 0xB6 };
    static const uint8_t H256_8bit[] = {
        0xEA, 0x76, 0x77, 0xCA, 0x45, 0x26, 0x55, 0x56, 0x80, 0x44, 0x1C, 0x11, 0x79, 0x82, 0xEA, 0x14,
        0x05, 0x9E, 0xA6, 0xD0, 0xD7, 0x12, 0x4D, 0x6E, 0xCD, 0xB3, 0xDE, 0xEC, 0x49, 0xE8, 0x90, 0xF4 };
    static const uint8_t H256_512bit[] = {
        0x08, 0xF4, 0xEE, 0x6F, 0x1B, 0xE6, 0x90, 0x3B, 0x32, 0x4C, 0x4E, 0x27, 0x99, 0x0C, 0xB2, 0x4E,
        0xF6, 0x9D, 0xD5, 0x8D, 0xBE, 0x84, 0x81, 0x3E, 0xE0, 0xA5, 0x2F, 0x66, 0x31, 0x23, 0x98, 0x75 };
    static const uint8_t H256_760bit[] = {
        0x10, 0x75, 0xC8, 0xB0, 0xCB, 0x91, 0x0F, 0x11, 0x6B, 0xDA, 0x5F, 0xA1, 0xF1, 0x9C, 0x29, 0xCF,
        0x8E, 0xCC, 0x75, 0xCA, 0xFF, 0x72, 0x08, 0xBA, 0x29, 0x94, 0xB6, 0x8F, 0xC5, 0x6E, 0x8D, 0x16 };
    static const uint8_t H256_1024bit[] = {
        0x0A, 0x94, 0x74, 0xE6, 0x45, 0xA7, 0xD2, 0x5E, 0x25, 0x5E, 0x9E, 0x89, 0xFF, 0xF4, 0x2E, 0xC7,
        0xEB, 0x31, 0x34, 0x90, 0x07, 0x05, 0x92, 0x84, 0xF0, 0xB1, 0x82, 0xE4, 0x52, 0xBD, 0xA8, 0x82 };
    static const uint8_t H256_2048bit[] = {
        0xD3, 0x05, 0xA3, 0x2B, 0x96, 0x3D, 0x14, 0x9D, 0xC7, 0x65, 0xF6, 0x85, 0x94, 0x50, 0x5D, 0x40,
        0x77, 0x02, 0x4F, 0x83, 0x6C, 0x1B, 0xF0, 0x38, 0x06, 0xE1, 0x62, 0x4C, 0xE1, 0x76, 0xC0, 0x8F };

    static const uint8_t H512_NULL[] = {
        0x65, 0x6B, 0x2F, 0x4C, 0xD7, 0x14, 0x62, 0x38, 0x8B, 0x64, 0xA3, 0x70, 0x43, 0xEA, 0x55, 0xDB,
        0xE4, 0x45, 0xD4, 0x52, 0xAE, 0xCD, 0x46, 0xC3, 0x29, 0x83, 0x43, 0x31, 0x4E, 0xF0, 0x40, 0x19,
        0xBC, 0xFA, 0x3F, 0x04, 0x26, 0x5A, 0x98, 0x57, 0xF9, 0x1B, 0xE9, 0x1F, 0xCE, 0x19, 0x70, 0x96,
        0x18, 0x7C, 0xED, 0xA7, 0x8C, 0x9C, 0x1C, 0x02, 0x1C, 0x29, 0x4A, 0x06, 0x89, 0x19, 0x85, 0x38 };
    static const uint8_t H512_8bit[] = {
        0x87, 0x1B, 0x18, 0xCF, 0x75, 0x4B, 0x72, 0x74, 0x03, 0x07, 0xA9, 0x7B, 0x44, 0x9A, 0xBE, 0xB3,
        0x2B, 0x64, 0x44, 0x4C, 0xC0, 0xD5, 0xA4, 0xD6, 0x58, 0x30, 0xAE, 0x54, 0x56, 0x83, 0x7A, 0x72,
        0xD8, 0x45, 0x8F, 0x12, 0xC8, 0xF0, 0x6C, 0x98, 0xC6, 0x16, 0xAB, 0xE1, 0x18, 0x97, 0xF8, 0x62,
        0x63, 0xB5, 0xCB, 0x77, 0xC4, 0x20, 0xFB, 0x37, 0x53, 0x74, 0xBE, 0xC5, 0x2B, 0x6D, 0x02, 0x92 };
    static const uint8_t H512_512bit[] = {
        0x38, 0x13, 0xE2, 0x10, 0x91, 0x18, 0xCD, 0xFB, 0x5A, 0x6D, 0x5E, 0x72, 0xF7, 0x20, 0x8D, 0xCC,
        0xC8, 0x0A, 0x2D, 0xFB, 0x3A, 0xFD, 0xFB, 0x02, 0xF4, 0x69, 0x92, 0xB5, 0xED, 0xBE, 0x53, 0x6B,
        0x35, 0x60, 0xDD, 0x1D, 0x7E, 0x29, 0xC6, 0xF5, 0x39, 0x78, 0xAF, 0x58, 0xB4, 0x44, 0xE3, 0x7B,
        0xA6, 0x85, 0xC0, 0xDD, 0x91, 0x05, 0x33, 0xBA, 0x5D, 0x78, 0xEF, 0xFF, 0xC1, 0x3D, 0xE6, 0x2A };
    static const uint8_t H512_1024bit[] = {
        0x76, 0xED, 0x1A, 0xC2, 0x8B, 0x1D, 0x01, 0x43, 0x01, 0x3F, 0xFA, 0x87, 0x21, 0x3B, 0x40, 0x90,
        0xB3, 0x56, 0x44, 0x12, 0x63, 0xC1, 0x3E, 0x03, 0xFA, 0x06, 0x0A, 0x8C, 0xAD, 0xA3, 0x2B, 0x97,
        0x96, 0x35, 0x65, 0x7F, 0x25, 0x6B, 0x15, 0xD5, 0xFC, 0xA4, 0xA1, 0x74, 0xDE, 0x02, 0x9F, 0x0B,
        0x1B, 0x43, 0x87, 0xC8, 0x78, 0xFC, 0xC1, 0xC0, 0x0E, 0x87, 0x05, 0xD7, 0x83, 0xFD, 0x7F, 0xFE };
    static const uint8_t H512_1536bit[] = {
        0xB1, 0x89, 0xBF, 0xE9, 0x87, 0xF6, 0x82, 0xF5, 0xF1, 0x67, 0xF0, 0xD7, 0xFA, 0x56, 0x53, 0x30,
        0xE1, 0x26, 0xB6, 0xE5, 0x92, 0xB1, 0xC5, 0x5D, 0x44, 0x29, 0x90, 0x64, 0xEF, 0x95, 0xB1, 0xA5,
        0x7F, 0x3C, 0x2D, 0x0E, 0xCF, 0x17, 0x86, 0x9D, 0x1D, 0x19, 0x9E, 0xBB, 0xD0, 0x2E, 0x88, 0x57,
        0xFB, 0x8A, 0xDD, 0x67, 0xA8, 0xC3, 0x1F, 0x56, 0xCD, 0x82, 0xC0, 0x16, 0xCF, 0x74, 0x31, 0x21 };
    static const uint8_t H512_2048bit[] = {
        0x0D, 0xD0, 0x3D, 0x73, 0x50, 0xC4, 0x09, 0xCB, 0x3C, 0x29, 0xC2, 0x58, 0x93, 0xA0, 0x72, 0x4F,
        0x6B, 0x13, 0x3F, 0xA8, 0xB9, 0xEB, 0x90, 0xA6, 0x4D, 0x1A, 0x8F, 0xA9, 0x3B, 0x56, 0x55, 0x66,
        0x11, 0xEB, 0x18, 0x7D, 0x71, 0x5A, 0x95, 0x6B, 0x10, 0x7E, 0x3B, 0xFC, 0x76, 0x48, 0x22, 0x98,
        0x13, 0x3A, 0x9C, 0xE8, 0xCB, 0xC0, 0xBD, 0x5E, 0x14, 0x36, 0xA5, 0xB1, 0x97, 0x28, 0x4F, 0x7E };

    static const ByteArray ba_M1 = { (uint8_t*)M1, sizeof(M1) };
    
    int ret = RET_OK;
    Dstu7564Ctx* ctx = NULL;
    ByteArray* H = NULL;
    ByteArray* ba_M2 = NULL;

    CHECK_NOT_NULL(ba_M2 = ba_alloc_from_uint8(M2, sizeof(M2)));
    CHECK_NOT_NULL(ctx = dstu7564_alloc());

    // Купина-256
    DO(dstu7564_init(ctx, 32));
    DO(dstu7564_final(ctx, &H));
    if (H->len != sizeof(H256_NULL) ||
        memcmp(H->buf, H256_NULL, sizeof(H256_NULL)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }
    ba_free(H);
    H = NULL;

    DO(dstu7564_update(ctx, &ba_M1));
    DO(dstu7564_final(ctx, &H));
    if (H->len != sizeof(H256_8bit) ||
        memcmp(H->buf, H256_8bit, sizeof(H256_8bit)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }
    ba_free(H);
    H = NULL;

    ba_M2->len = 512 / 8;
    DO(dstu7564_update(ctx, ba_M2));
    DO(dstu7564_final(ctx, &H));
    if (H->len != sizeof(H256_512bit) ||
        memcmp(H->buf, H256_512bit, sizeof(H256_512bit)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }
    ba_free(H);
    H = NULL;

    ba_M2->len = 760 / 8;
    DO(dstu7564_update(ctx, ba_M2));
    DO(dstu7564_final(ctx, &H));
    if (H->len != sizeof(H256_760bit) ||
        memcmp(H->buf, H256_760bit, sizeof(H256_760bit)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }
    ba_free(H);
    H = NULL;

    ba_M2->len = 1024 / 8;
    DO(dstu7564_update(ctx, ba_M2));
    DO(dstu7564_final(ctx, &H));
    if (H->len != sizeof(H256_1024bit) ||
        memcmp(H->buf, H256_1024bit, sizeof(H256_1024bit)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }
    ba_free(H);
    H = NULL;

    ba_M2->len = 2048 / 8;
    DO(dstu7564_update(ctx, ba_M2));
    DO(dstu7564_final(ctx, &H));
    if (H->len != sizeof(H256_2048bit) ||
        memcmp(H->buf, H256_2048bit, sizeof(H256_2048bit)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }
    ba_free(H);
    H = NULL;

    // Купина-512
    DO(dstu7564_init(ctx, 64));
    DO(dstu7564_final(ctx, &H));
    if (H->len != sizeof(H512_NULL) ||
        memcmp(H->buf, H512_NULL, sizeof(H512_NULL)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }
    ba_free(H);
    H = NULL;

    DO(dstu7564_update(ctx, &ba_M1));
    DO(dstu7564_final(ctx, &H));
    if (H->len != sizeof(H512_8bit) ||
        memcmp(H->buf, H512_8bit, sizeof(H512_8bit)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }
    ba_free(H);
    H = NULL;

    ba_M2->len = 512 / 8;
    DO(dstu7564_update(ctx, ba_M2));
    DO(dstu7564_final(ctx, &H));
    if (H->len != sizeof(H512_512bit) ||
        memcmp(H->buf, H512_512bit, sizeof(H512_512bit)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }
    ba_free(H);
    H = NULL;

    ba_M2->len = 1024 / 8;
    DO(dstu7564_update(ctx, ba_M2));
    DO(dstu7564_final(ctx, &H));
    if (H->len != sizeof(H512_1024bit) ||
        memcmp(H->buf, H512_1024bit, sizeof(H512_1024bit)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }
    ba_free(H);
    H = NULL;

    ba_M2->len = 1536 / 8;
    DO(dstu7564_update(ctx, ba_M2));
    DO(dstu7564_final(ctx, &H));
    if (H->len != sizeof(H512_1536bit) ||
        memcmp(H->buf, H512_1536bit, sizeof(H512_1536bit)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }
    ba_free(H);
    H = NULL;

    ba_M2->len = 2048 / 8;
    DO(dstu7564_update(ctx, ba_M2));
    DO(dstu7564_final(ctx, &H));
    if (H->len != sizeof(H512_2048bit) ||
        memcmp(H->buf, H512_2048bit, sizeof(H512_2048bit)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

cleanup:
    dstu7564_free(ctx);
    ba_free(H);
    ba_free(ba_M2);
    return ret;
}

static int dstu7564_self_test_kmac(void)
{
    // ДСТУ 7564:2014
    static const uint8_t M[] = { 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E };
    static const uint8_t K256[] = {
        0x1F, 0x1E, 0x1D, 0x1C, 0x1B, 0x1A, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10, 
        0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };
    static const uint8_t KMAC256[] = {
        0xB6, 0x05, 0x94, 0xD5, 0x6F, 0xA7, 0x9B, 0xA2, 0x10, 0x31, 0x4C, 0x72, 0xC2, 0x49, 0x50, 0x87, 
        0xCC, 0xD0, 0xA9, 0x9F, 0xC0, 0x4A, 0xCF, 0xE2, 0xA3, 0x9E, 0xF6, 0x69, 0x92, 0x5D, 0x98, 0xEE };

    static const uint8_t K384[] = {
        0x2F, 0x2E, 0x2D, 0x2C, 0x2B, 0x2A, 0x29, 0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21, 0x20,
        0x1F, 0x1E, 0x1D, 0x1C, 0x1B, 0x1A, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10,
        0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };
    static const uint8_t KMAC384[] = {
        0xBE, 0xBF, 0xD8, 0xD7, 0x30, 0x33, 0x6F, 0x04, 0x3A, 0xBA, 0xCB, 0x41, 0x82, 0x9E, 0x79, 0xA4, 
        0xD3, 0x20, 0xAE, 0xDD, 0xD8, 0xD1, 0x40, 0x24, 0xD5, 0xB8, 0x05, 0xDA, 0x70, 0xC3, 0x96, 0xFA, 
        0x29, 0x5C, 0x28, 0x1A, 0x38, 0xB3, 0x0A, 0xE7, 0x28, 0xA3, 0x04, 0xB3, 0xF5, 0xAE, 0x49, 0x0E };

    static const uint8_t K512[] = {
        0x3F, 0x3E, 0x3D, 0x3C, 0x3B, 0x3A, 0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30,
        0x2F, 0x2E, 0x2D, 0x2C, 0x2B, 0x2A, 0x29, 0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21, 0x20,
        0x1F, 0x1E, 0x1D, 0x1C, 0x1B, 0x1A, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10,
        0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };
    static const uint8_t KMAC512[] = {
        0xF2, 0x70, 0x04, 0x3C, 0x06, 0xA5, 0xC3, 0x7E, 0x65, 0xD9, 0xD7, 0x91, 0xC5, 0xFB, 0xFB, 0x96, 
        0x6E, 0x5E, 0xE7, 0x09, 0xF8, 0xF5, 0x40, 0x19, 0xC9, 0xA5, 0x5B, 0x76, 0xCA, 0x40, 0xB7, 0x01, 
        0x00, 0x57, 0x9F, 0x26, 0x9C, 0xEC, 0x24, 0xE3, 0x47, 0xA9, 0xD8, 0x64, 0x61, 0x4C, 0xF3, 0xAB, 
        0xBF, 0x66, 0x10, 0x74, 0x2E, 0x4D, 0xB3, 0xBD, 0x2A, 0xBC, 0x00, 0x03, 0x87, 0xC4, 0x9D, 0x24 };

    static const ByteArray ba_M = { (uint8_t*)M, sizeof(M) };
    static const ByteArray ba_K256 = { (uint8_t*)K256, sizeof(K256) };
    static const ByteArray ba_K384 = { (uint8_t*)K384, sizeof(K384) };
    static const ByteArray ba_K512 = { (uint8_t*)K512, sizeof(K512) };

    int ret = RET_OK;
    Dstu7564Ctx* ctx = NULL;
    ByteArray* kmac = NULL;

    CHECK_NOT_NULL(ctx = dstu7564_alloc());

    DO(dstu7564_init_kmac(ctx, &ba_K256, sizeof(KMAC256)));
    DO(dstu7564_update_kmac(ctx, &ba_M));
    DO(dstu7564_final_kmac(ctx, &kmac));
    if (kmac->len != sizeof(KMAC256) ||
        memcmp(kmac->buf, KMAC256, sizeof(KMAC256)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }
    ba_free(kmac);
    kmac = NULL;

    DO(dstu7564_init_kmac(ctx, &ba_K384, sizeof(KMAC384)));
    DO(dstu7564_update_kmac(ctx, &ba_M));
    DO(dstu7564_final_kmac(ctx, &kmac));
    if (kmac->len != sizeof(KMAC384) ||
        memcmp(kmac->buf, KMAC384, sizeof(KMAC384)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }
    ba_free(kmac);
    kmac = NULL;

    DO(dstu7564_init_kmac(ctx, &ba_K512, sizeof(KMAC512)));
    DO(dstu7564_update_kmac(ctx, &ba_M));
    DO(dstu7564_final_kmac(ctx, &kmac));
    if (kmac->len != sizeof(KMAC512) ||
        memcmp(kmac->buf, KMAC512, sizeof(KMAC512)) != 0) {
        SET_ERROR(RET_SELF_TEST_FAIL);
    }

cleanup:

    dstu7564_free(ctx);
    ba_free(kmac);
    return ret;
}

int dstu7564_self_test(void)
{
    int ret = RET_OK;

    DO(dstu7564_self_test_hash());
    DO(dstu7564_self_test_kmac());

cleanup:
    return ret;
}
