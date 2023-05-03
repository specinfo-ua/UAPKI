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

#ifndef UAPKI_STORE_UTIL_H
#define UAPKI_STORE_UTIL_H


#include "cer-store.h"
#include "crl-store.h"
#include "parson.h"


namespace CerStoreUtil {

    int detailInfoToJson (JSON_Object* joResult, const CerStore::Item* cerStoreItem);
    int extensionsToJson (JSON_Array* jaResult, const CerStore::Item* cerStoreItem, bool& selfSigned);
    int nameToJson (
        JSON_Object* joResult,
        const ByteArray* baEncoded
    );
    int nameToJson (
        JSON_Object* joResult,
        const Name_t& name
    );
    int ocspIdentifierToJson (
        JSON_Object* joResult,
        const ByteArray* baEncoded
    );
    int rdnameFromName (
        const Name_t& name,
        const char* type,
        std::string& value
    );
    int signatureInfoToJson (JSON_Object* joResult, const CerStore::Item* cerStoreItem);
    int spkiToJson (JSON_Object* joResult, const CerStore::Item* cerStoreItem, const bool encoded);
    int validityToJson (JSON_Object* joResult, const CerStore::Item* cerStoreItem);

}

namespace CrlStoreUtil {

    int crlIdentifierToJson (
        JSON_Object* joResult,
        const ByteArray* baEncoded
    );
    int infoToJson (
        JSON_Object* joResult,
        const CrlStore::Item* crlStoreItem
    );
    int revokedCertsToJson (
        JSON_Array* jaResult,
        const CrlStore::Item* crlStoreItem
    );

}


#endif
