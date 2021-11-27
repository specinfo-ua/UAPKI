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

#ifndef PKCS12_UTILS_H
#define PKCS12_UTILS_H


#include "byte-array.h"
#include "uapkic.h"
#include "uapkif.h"

#ifdef __cplusplus
extern "C" {
#endif


int pkcs12_calc_hmac (const HashAlg hash_alg, const ByteArray * key, const ByteArray * msg, ByteArray ** hmac);
int pkcs12_get_data_and_calc_mac (const PFX_t * pfx, const char * pass,
        const char ** macAlgo, size_t * iterations, ByteArray ** baAuthsafe, ByteArray ** baMacValue);
int pkcs12_read_encrypted_content (const ContentInfo_t * content, const char * password, ByteArray ** data);
int pkcs12_read_cert_bag (const ANY_t * bagValue, ByteArray ** baCert, bool * isSdsiCert);
int pkcs12_read_shrouded_key_bag (const ANY_t * bagValue, const char * pass, ByteArray ** baPrivateKeyInfo, char ** oidKdf, char ** oidCipher);
int pkcs12_write_cert_bag (const ByteArray * baCert, ByteArray ** baEncoded);
int pkcs12_write_safecontents (const ByteArray ** baEncodedBags, const size_t count, ByteArray ** baEncoded);
int pkcs12_add_p7data_single_safecontent (AuthenticatedSafe_t * authentSafe, const ByteArray * baEncodedBag);
int pkcs12_add_p7encrypteddata (AuthenticatedSafe_t * authentSafe, const ByteArray * baEncryptedBytes);
int pkcs12_gen_macdata (const char * password, const char * hash, const size_t iterations,
        const ByteArray * baData, MacData_t ** macData);
int pkcs12_write_pfx (const ByteArray * baAuthsafe, const MacData_t * macData, ByteArray ** baEncoded);
int pkcs12_iit_read_kep_key(const ByteArray* baPrivkey, ByteArray** baKepPrivkey);


#ifdef __cplusplus
}
#endif


#endif
