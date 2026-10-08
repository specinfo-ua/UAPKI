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

#ifndef GETOPT_HELPER_H
#define GETOPT_HELPER_H


#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <map>
#include <string>
#include <vector>


class GetOptHelper {
public:
    enum class Error : uint32_t {
        OK = 0,
        INVALID_COUNT_ARGUMENTS,
        INVALID_OPTION,
        UNKNOWN_OPTION,
        ALREADY_OPTION,
        OPTION_NEED_PARAMETER
    };  //  end enum Error

private:
    std::string m_LastArg;
    std::map<const std::string, const int>
                m_OptionCntArgs;
    std::map<const std::string, const std::string>
                m_OptionValues;

public:
    GetOptHelper (void);
    ~GetOptHelper (void);

    void addOptionArgs (
        const char* option,
        const int countArgs
    );
    std::string getValue (
        const std::string& key
    ) const;
    bool getValue (
        const std::string& key,
        std::string& out
    ) const;
    bool hasValue (
        const std::string& key
    ) const;
    const std::string lastArg (void) const;
    Error parse (
        int argc,
        char* argv[]
    );

private:
    void addValue (
        const std::string& key,
        const std::string& value
    );
    int optionCountArgs (
        const std::string& option
    ) const;

};  //  end class GetOptHelper


#endif
