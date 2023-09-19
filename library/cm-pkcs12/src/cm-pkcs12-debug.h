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

#ifndef CM_PKCS12_DEBUG_H
#define CM_PKCS12_DEBUG_H


#include <stdio.h>
#include <string>


#define DEBUG_OUTSTREAM_FILENAME "cm-pkcs12.log"
#define DEBUG_OUTSTREAM_FOPEN fopen(DEBUG_OUTSTREAM_FILENAME, "a")
#define DEBUG_OUTSTREAM_STDOUT stdout
#define DEBUG_OUTSTREAM_DEFAULT DEBUG_OUTSTREAM_FOPEN

#define DEBUG_OUTPUT_FUNC                                   \
static void debug_output (FILE* f, const std::string& msg)  \
{                                                           \
    if (!f) return;                                         \
    const std::string s_msg = msg + std::string("\n");      \
    fputs(s_msg.c_str(), f);                                \
    if (f != stdout) fclose(f);                             \
}


#endif
