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

#include "time-utils.h"
#include "asn1-ba-utils.h"
#include "macros-internal.h"
#include "uapki-errors.h"
#include <time.h>


static const char* HEX_ASN1_GENTIME_2K = "180F32303030303130313030303030305A";
static const size_t STIME_FORMAT_INDECES[14] = { 0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18 };


string TimeUtils::mstimeToFormat (const uint64_t msTime, const bool isLocal)
{
    string rv_stime;
    rv_stime.resize(20);
    const time_t t = msTime / 1000;
    if (!isLocal) {
        strftime((char*)rv_stime.data(), 20, "%Y-%m-%d %H:%M:%S", gmtime(&t));
    }
    else {
        strftime((char*)rv_stime.data(), 20, "%Y-%m-%d %H:%M:%S", localtime(&t));
    }
    return rv_stime;
}

uint64_t TimeUtils::nowMsTime (void)
{
    return time(NULL) * 1000;
}

string TimeUtils::stimeToFormat (const char* sTime)
{
    string rv_stime;
    if (sTime && (strlen(sTime) > 0)) {
        rv_stime = "YYYY-MM-DD hh:mm:ss";
        for (size_t i = 0; i < 14; i++) {
            rv_stime[STIME_FORMAT_INDECES[i]] = sTime[i];
        }

    }
    return rv_stime;
}

int TimeUtils::stimeToMstime (const char* sTime, uint64_t& msTime)
{
    int ret = RET_OK;
    ByteArray* ba_time = NULL;
    uint64_t ms = 0;

    if ((sTime != NULL) && (strlen(sTime) == 19) && (sTime[4] == '-') && (sTime[7] == '-')
    && (sTime[10] == ' ') && (sTime[13] == ':') && (sTime[16] == ':')) {
        ba_time = ba_alloc_from_hex(HEX_ASN1_GENTIME_2K);
        if (ba_time) {
            for (size_t i = 0; i < 14; i++) {
                ba_set_byte(ba_time, i + 2, sTime[STIME_FORMAT_INDECES[i]]);
            }
            DO(ba_decode_pkixtime(ba_time, &ms));
            msTime = ms;
        }
        else {
            ret = RET_UAPKI_GENERAL_ERROR;
        }
    }
    else {
        ret = RET_UAPKI_INVALID_PARAMETER;
    }

cleanup:
    ba_free(ba_time);
    return ret;
}
