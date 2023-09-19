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

#define FILE_MARKER "uapki/api/random-bytes.cpp"

#include "api-json-internal.h"
#include "drbg.h"
#include "parson-ba-utils.h"
#include "parson-helper.h"
#include "uapki-errors.h"
#include "uapki-ns.h"


int uapki_random_bytes (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    UapkiNS::SmartBA sba_random;
    const uint32_t len = ParsonHelper::jsonObjectGetUint32(joParams, "length", 0);

    if (len == 0) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    if (!sba_random.set(ba_alloc_by_len(len))) {
        SET_ERROR(RET_UAPKI_GENERAL_ERROR);
    }

    DO(drbg_random(sba_random.get()));

    DO(json_object_set_base64(joResult, "bytes", sba_random.get()));

cleanup:
    return ret;
}
