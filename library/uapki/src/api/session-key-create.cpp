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

#define FILE_MARKER "uapki/api/session-key-create.cpp"

#include "api-json-internal.h"
#include "cm-providers.h"
#include "parson-helper.h"
#include "uapki-ns.h"


using namespace std;


int uapki_session_key_create (JSON_Object* joParams, JSON_Object* joResult)
{
    if (!joParams) return RET_UAPKI_INVALID_PARAMETER;

    CmStorageProxy* storage = CmProviders::openedStorage();
    if (!storage) return RET_UAPKI_STORAGE_NOT_OPEN;

    string s_keyparam;
    ParsonHelper json;
    if (json_object_copy_all_items(json.create(), joParams) != JSONSuccess) return RET_UAPKI_GENERAL_ERROR;
    if (!json.serialize(s_keyparam)) return RET_UAPKI_GENERAL_ERROR;

    int ret = RET_OK;
    UapkiNS::SmartBA sba_keyid;

    DO(storage->sessionCreateKey(s_keyparam));
    DO(storage->keyGetInfo(&sba_keyid));

    DO(json_object_set_hex(joResult, "id", sba_keyid.get()));

cleanup:
    return ret;
}
