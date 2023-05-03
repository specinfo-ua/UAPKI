/*
 * Copyright (c) 2023, The UAPKI Project Authors.
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

#include "time-util.h"
#include "asn1-utils.h"
#include "macros-internal.h"
#include "uapki-errors.h"
#include "uapki-ns.h"


using namespace std;


static const size_t STIME_FORMAT_INDECES[14] = { 0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18 };

static int two_digits_to_int (
        const char* s
)
{
    return (s[0] - 0x30) * 10 + (s[1] - 0x30);
}   //  two_digits_to_int


int TimeUtil::ftimeToMtime (
        const string& fTime,
        uint64_t& msTime
)
{
    if (
        (fTime.length() != 19) ||
        (fTime[4] != '-') || (fTime[7] != '-') ||
        ((fTime[10] != ' ') && (fTime[10] != 'T')) ||
        (fTime[13] != ':') || (fTime[16] != ':')
    ) return RET_UAPKI_INVALID_PARAMETER;

    ::tm tm_data;
    tm_data.tm_year = two_digits_to_int(&fTime[0]) * 100;
    tm_data.tm_year += two_digits_to_int(&fTime[2]) - 1900;
    tm_data.tm_mon = two_digits_to_int(&fTime[5]) - 1;
    tm_data.tm_mday = two_digits_to_int(&fTime[8]);
    tm_data.tm_hour = two_digits_to_int(&fTime[11]);
    tm_data.tm_min = two_digits_to_int(&fTime[14]);
    tm_data.tm_sec = two_digits_to_int(&fTime[17]);
    msTime = asn_tm2msec(&tm_data, 0);
    return RET_OK;
}

string TimeUtil::mtimeToFtime (
        const uint64_t msTime,
        const bool isLocal
)
{
    string rv_ftime;
    ::tm tm_data;
    if (asn_msecToTm(&tm_data, msTime, isLocal)) {
        rv_ftime = tmToFtime(tm_data);
    }
    return rv_ftime;
}

uint64_t TimeUtil::mtimeNow (void)
{
    return time(nullptr) * 1000;
}

string TimeUtil::stimeToFtime (
        const char* sTime
)
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

int TimeUtil::stimeToMtime (
        const string& sTime,
        uint64_t& msTime
)
{
    if (sTime.length() != 14) return RET_UAPKI_INVALID_PARAMETER;

    ::tm tm_data;
    tm_data.tm_year = two_digits_to_int(&sTime[0]) * 100;
    tm_data.tm_year += two_digits_to_int(&sTime[2]) - 1900;
    tm_data.tm_mon = two_digits_to_int(&sTime[4]) - 1;
    tm_data.tm_mday = two_digits_to_int(&sTime[6]);
    tm_data.tm_hour = two_digits_to_int(&sTime[8]);
    tm_data.tm_min = two_digits_to_int(&sTime[10]);
    tm_data.tm_sec = two_digits_to_int(&sTime[12]);
    msTime = asn_tm2msec(&tm_data, 0);
    return RET_OK;
}

string TimeUtil::tmToFtime (
        const ::tm& tmData
)
{
    string rv_ftime;
    rv_ftime.resize(24);
    strftime((char*)rv_ftime.data(), 23, "%Y-%m-%d %H:%M:%S", &tmData);
    rv_ftime.resize(19);
    return rv_ftime;
}
