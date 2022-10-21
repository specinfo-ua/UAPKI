//  Last update: 2022-10-21

#ifndef UAPKI_HOSTAPP_DEBUG_H
#define UAPKI_HOSTAPP_DEBUG_H


#include <stdio.h>
#include <string>


#define DEBUG_OUTSTREAM_FILENAME "uapki-hostapp.log"

#define DEBUG_OUTPUT_FUNC                                   \
static void debug_output (const std::string& msg)           \
{                                                           \
    FILE* f = fopen(DEBUG_OUTSTREAM_FILENAME, "a");         \
    if (!f) return;                                         \
    const std::string s_msg = msg + std::string("\n");      \
    fputs(s_msg.c_str(), f);                                \
    if (f != stdout) fclose(f);                             \
}


#endif
