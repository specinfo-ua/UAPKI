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

#ifndef UAPKI_CM_PROVIDERS_H
#define UAPKI_CM_PROVIDERS_H

#include "cm-api.h"
#include "cm-errors.h"
#include "parson.h"
#include "uapkic.h"


#include <string>


using namespace std;


struct CM_PROVIDER_ST;


class CmProviders {
public:
    static int loadProvider (const string& dir, const string& libName, const char* jsonParams);
    static void deinit (void);

    static size_t count (void);
    static int getInfo (const size_t index, JSON_Object* joResult);
    static struct CM_PROVIDER_ST* getProviderById (const char* id);
    static int listStorages (const char* providerId, JSON_Object* joResult);
    static int storageInfo (const char* providerId, const char* storageId, JSON_Object* joResult);
    static int storageOpen (const char* providerId, const char* storageId, JSON_Object* joParameters);
    static int storageClose (void);

    static void free (void* block);
    static void baFree (CM_BYTEARRAY* ba);
    static void arrayBaFree (const uint32_t count, CM_BYTEARRAY** arrayBa);

    static int sessionInfo (JSON_Object* joResult);
    static int sessionListKeys (JSON_Object* joResult);
    static int sessionGetCertificates (uint32_t* countCerts, CM_BYTEARRAY*** baCerts);
    static int sessionCreateKey (JSON_Object* joParameters, CM_BYTEARRAY** baKeyId);
    static int sessionDeleteKey (CM_BYTEARRAY* baKeyId);
    static int sessionSelectKey (CM_BYTEARRAY* baKeyId);
    static int sessionChangePassword (const CM_UTF8_CHAR* newPassword);

    static int keyIsSelected (void);
    static int keyGetInfo (CM_JSON_PCHAR* keyInfo, CM_BYTEARRAY** keyId);
    static int keyGetPublickey (CM_BYTEARRAY** baAlgorithmIdentifier, CM_BYTEARRAY** baPublicKey);
    static int keyInitUsage (JSON_Object* joParameters);
    static int keySetOtp (const CM_UTF8_CHAR* otp);
    static int keySign (const CM_UTF8_CHAR* signAlgo, const CM_BYTEARRAY* signAlgoParams,
            const uint32_t count, const CM_BYTEARRAY** baHashes, CM_BYTEARRAY*** baSignatures);
    static int keySignInit (const CM_UTF8_CHAR* signAlgo, const CM_BYTEARRAY* baSignAlgoParams);
    static int keySignUpdate (const CM_BYTEARRAY* baData);
    static int keySignFinal (CM_BYTEARRAY** baSignature);
    static int keySignData (const CM_UTF8_CHAR* signAlgo, const CM_BYTEARRAY* baSignAlgoParams,
            const CM_BYTEARRAY* baData, CM_BYTEARRAY** baSignature);
    static int keyGetCertificates (uint32_t* countCerts, CM_BYTEARRAY*** baCerts);
    static int keyAddCertificate (const CM_BYTEARRAY* baCert);
    static int keyGetCsr (const CM_UTF8_CHAR* signAlgo, const CM_BYTEARRAY* baSignAlgoParams,
            const CM_BYTEARRAY* baSubject, const CM_BYTEARRAY* baAttributes, CM_BYTEARRAY** baCsr);

};  //  end class CmProviders


#endif
