/*
 * Copyright (c) 2022, The UAPKI Project Authors.
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

 //  Last update: 2022-07-14

#include <stdlib.h>
#include <string.h>
#define DEFINE_OID(OID_NAME,OID_VAL) const char *OID_NAME = OID_VAL
#include "oids.h"
#undef DEFINE_OID

#undef FILE_MARKER
#define FILE_MARKER "common/pkix/oids.c"

bool oid_is_equal (const char* oid1, const char* oid2)
{
    return !strcmp(oid1, oid2);
}

bool oid_is_parent (const char* parent, const char* oid)
{
    size_t parent_len = strlen(parent);
    bool r = !strncmp(parent, oid, parent_len);
    if (r && (strlen(oid) > parent_len)) {
        r = oid[parent_len] == '.';
    }
    return r;
}

bool oid_is_valid (const char* oid)
{
    if (!oid) return false;

    const size_t len = strlen(oid);
    if (len < 3) return false;

    for (size_t i = 0; i < len; i++) {
        const uint8_t v = (uint8_t)oid[i];
        if ((v < 0x2E) || (v > 0x39) || (v == 0x2F)) return false;
    }

    if ((oid[0] < 0x30) || (oid[0] > 0x32) || (oid[1] != 0x2E) || (oid[len - 1] == 0x2E)) return false;

    for (size_t i = 1; i < len - 1; i++) {
        if ((oid[i] == 0x2E) && (oid[i + 1] == 0x2E)) {
            return false;
        }
    }

    uint64_t val = strtoul((const char*)oid + 2, NULL, 10);
    if (val > 39) return false;

    return true;
}
