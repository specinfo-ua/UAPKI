//  Last update: 2022-10-21

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
