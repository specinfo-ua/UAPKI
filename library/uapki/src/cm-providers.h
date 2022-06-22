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

#ifndef UAPKI_CM_PROVIDERS_H
#define UAPKI_CM_PROVIDERS_H

#include "cm-api.h"
#include "cm-storage-proxy.h"
#include "parson.h"
#include "uapkic.h"
#include <string>


struct CM_PROVIDER_ST;


class CmProviders {
public:
    static int loadProvider (const std::string& dir, const std::string& libName, const std::string& jsonParams);
    static void deinit (void);

    static size_t count (void);
    static int getInfo (const size_t index, JSON_Object* joResult);
    static struct CM_PROVIDER_ST* getProviderById (const std::string& providerId);
    static int listStorages (const std::string& providerId, JSON_Object* joResult);
    static int storageInfo (const std::string& providerId, const std::string& storageId, JSON_Object* joResult);
    static int storageOpen (const std::string& providerId, const std::string& storageId, JSON_Object* joParams);
    static int storageClose (void);

    static CmStorageProxy* openedStorage (void);

};  //  end class CmProviders


#endif
