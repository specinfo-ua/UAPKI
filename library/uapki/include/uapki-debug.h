//  Last update: 2022-11-04

#ifndef CM_PKCS12_DEBUG_H
#define CM_PKCS12_DEBUG_H


#include <stdio.h>
#include <string>


#define DEBUG_OUTSTREAM_FOPEN fopen("uapki.log", "a")
#define DEBUG_OUTSTREAM_STDOUT stdout

#define DEBUG_OUTPUT_OUTSTREAM_FUNC                                 \
static void debug_output_stream (                                   \
        FILE* f,                                                    \
        const std::string& method,                                  \
        const std::string& msg,                                     \
        const ByteArray* baData                                     \
)                                                                   \
{                                                                   \
    static size_t debug_output_ctr = 0;                             \
    if (!f) return;                                                 \
    std::string s_hex, s_msg;                                       \
    s_msg = std::string("[") + std::to_string(debug_output_ctr);    \
    s_msg += std::string("] BEGIN ") + method;                      \
    s_msg += std::string("\n") + msg + std::string("\n");           \
    if (ba_get_len(baData) > 0) {                                   \
        size_t len;                                                 \
        s_hex.resize(2 * ba_get_len(baData) + 1);                   \
        int ret = ba_to_hex(baData, (char*)s_hex.data(), &len);     \
        if (ret == RET_OK) {                                        \
            s_hex.pop_back();                                       \
            s_msg += s_hex + std::string("\n");                     \
        }                                                           \
    }                                                               \
    s_msg += std::string("[") + std::to_string(debug_output_ctr++); \
    s_msg += std::string("] END ") + method + std::string("\n");    \
    fputs(s_msg.c_str(), f);                                        \
    if (f != stdout) fclose(f);                                     \
}

#endif
