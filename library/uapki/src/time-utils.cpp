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

#include "time-utils.h"
#include "asn1-ba-utils.h"
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


int TimeUtils::ftimeToMtime (
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
    msTime = tmToMstime(tm_data, 0);
    return RET_OK;
}

string TimeUtils::mstimeToFormat (
        const uint64_t msTime,
        const bool isLocal
)
{
    ::tm tm_data;
    string rv_stime;
    if (!mstimeToTm(tm_data, msTime, isLocal)) return rv_stime;

    rv_stime.resize(24);
    strftime((char*)rv_stime.data(), 23, "%Y-%m-%d %H:%M:%S", &tm_data);
    rv_stime.resize(19);
    return rv_stime;
}

bool TimeUtils::mstimeToTm (
        ::tm& tmData,
        const uint64_t msTime,
        const bool isLocal
)
{
    const uint64_t t_sec = msTime / 1000;
#if defined(_WIN32) || defined(__WINDOWS__)
    const errno_t err = (isLocal)
        ? ::localtime_s(&tmData, (time_t*)&t_sec)
        : ::gmtime_s(&tmData, (time_t*)&t_sec);
    return (err == 0);
#elif defined(__linux__) || defined(__APPLE__) || defined(__GNUC__)
    const ::tm* r_tm = (isLocal)
        ? ::localtime_r(&t_sec, &tmData)
        : ::gmtime_r(&t_sec, &tmData);
    return (r_tm);
#endif
}

uint64_t TimeUtils::mstimeNow (void)
{
    return time(nullptr) * 1000;
}

string TimeUtils::stimeToFormat (
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

int TimeUtils::stimeToMtime (
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
    msTime = tmToMstime(tm_data, 0);
    return RET_OK;
}

uint64_t TimeUtils::tmToMstime (
        ::tm& tmData,
        const int msec
)
{
    static const uint64_t m_to_d[12] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };
    uint64_t rv_t, month, year;

    month = tmData.tm_mon;
    year = tmData.tm_year + month / 12 + 1900;
    month %= 12;
    if (month < 0) {
        year -= 1;
        month += 12;
    }
    rv_t = (year - 1970) * 365 + m_to_d[month];
    if (month <= 1) {
        year -= 1;
    }
    rv_t += (year - 1968) / 4 - (year - 1900) / 100 + (year - 1600) / 400;
    rv_t += tmData.tm_mday - 1;
    rv_t *= 24;
    rv_t += tmData.tm_hour;
    rv_t *= 60;
    rv_t += tmData.tm_min;
    rv_t *= 60;
    rv_t += tmData.tm_sec;
    rv_t *= 1000;
    rv_t += msec;
    return rv_t;
}
