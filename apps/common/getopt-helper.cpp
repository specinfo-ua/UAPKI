/*
 * Copyright (c) 2024, The UAPKI Project Authors.
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

#include "getopt-helper.h"
#include <stdio.h>
#include <string.h>


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


GetOptHelper::GetOptHelper (void)
{
    DEBUG_OUTCON(puts("GetOptHelper::GetOptHelper()"));
}

GetOptHelper::~GetOptHelper (void)
{
    DEBUG_OUTCON(puts("GetOptHelper::~GetOptHelper()"));
    for (auto& it : m_OptionValues) {
        if (!it.second.empty()) {
            memset((void*)it.second.data(), 0, it.second.size());
        }
    }
}

void GetOptHelper::addOptionArgs (
        const char* option,
        const int countArgs
)
{
    m_OptionCntArgs.insert(pair<const string, const int>(string(option), countArgs));
}

string GetOptHelper::getValue (
        const string& key
) const
{
    string rv_s;
    const auto it = m_OptionValues.find(key);
    if (it != m_OptionValues.end()) {
        rv_s = it->second;
    }
    return rv_s;
}

bool GetOptHelper::getValue (
        const string& key,
        string& out
) const
{
    const auto it = m_OptionValues.find(key);
    if (it != m_OptionValues.end()) {
        out = it->second;
        return true;
    }
    return false;
}

bool GetOptHelper::hasValue (
        const string& key
) const
{
    const auto it = m_OptionValues.find(key);
    return (it != m_OptionValues.end());
}

const string GetOptHelper::lastArg (void) const
{
    return string("'") + m_LastArg + string("'");
}

GetOptHelper::Error GetOptHelper::parse (
        int argc,
        char* argv[]
)
{
    if (argc < 2) {
        m_LastArg = to_string(argc - 1);
        return Error::INVALID_COUNT_ARGUMENTS;
    }

    for (size_t i = 1; i < argc; i++) {
        m_LastArg = string(argv[i]);

        //  Check arg-paramName
        if ((m_LastArg.length() < 3) || (m_LastArg[0] != '-') || (m_LastArg[1] != '-')) {
            return Error::INVALID_OPTION;
        }
        const string s_option = m_LastArg.substr(2);
        const int cnt_args = optionCountArgs(s_option);
        if (cnt_args < 0) {
            return Error::UNKNOWN_OPTION;
        }

        //  Check exists arg-paramName in parsed list
        if (hasValue(s_option)) {
            return Error::ALREADY_OPTION;
        }

        string s_optionarg;
        if (cnt_args > 0) {
            if (++i >= argc) {
                return Error::OPTION_NEED_PARAMETER;
            }
            s_optionarg = string(argv[i]);
        }

        addValue(s_option, s_optionarg);
    }

    return Error::OK;
}

void GetOptHelper::addValue (
        const string& key,
        const string& value
)
{
    m_OptionValues.insert(pair<const string, const string>(key, value));
}

int GetOptHelper::optionCountArgs (
        const string& option
) const
{
    int rv_cnt = -1;
    const auto it = m_OptionCntArgs.find(option);
    if (it != m_OptionCntArgs.end()) {
        rv_cnt = it->second;
    }
    return rv_cnt;
}
