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

#ifndef UAPKI_API_JSON_H
#define UAPKI_API_JSON_H

#include "ba-utils.h"
#include "cm-api.h"
#include "cm-errors.h"
#include "cm-providers.h"
#include "macros-internal.h"
#include "parson.h"
#include "parson-ba-utils.h"
#include "uapki-errors.h"
#include "uapki-export.h"
#include "uapki-ns.h"
#include <string.h>


#define ASN_ALLOC_TYPE(obj, typ) ((obj) = (typ*) calloc(1, sizeof(typ)));   \
    if ((obj) == NULL) { ret = RET_MEMORY_ALLOC_ERROR;                      \
                         ERROR_CREATE(ret);                                 \
                         goto cleanup; }


#ifdef __cplusplus
extern "C" {
#endif


int uapki_init (JSON_Object* joParams, JSON_Object* joResult);
int uapki_version (JSON_Object* joParams, JSON_Object* joResult);
int uapki_deinit (JSON_Object* joParams, JSON_Object* joResult);
int uapki_list_providers (JSON_Object* joParams, JSON_Object* joResult);
int uapki_provider_list_storages (JSON_Object* joParams, JSON_Object* joResult);
int uapki_provider_storage_info (JSON_Object* joParams, JSON_Object* joResult);

int uapki_storage_open  (JSON_Object* joParams, JSON_Object* joResult);
int uapki_storage_close (JSON_Object* joParams, JSON_Object* joResult);
int uapki_storage_change_password (JSON_Object* joParams, JSON_Object* joResult);

int uapki_session_list_keys (JSON_Object* joParams, JSON_Object* joResult);
int uapki_session_select_key (JSON_Object* joParams, JSON_Object* joResult);
int uapki_session_key_create (JSON_Object* joParams, JSON_Object* joResult);
int uapki_session_key_delete (JSON_Object* joParams, JSON_Object* joResult);

int uapki_key_get_csr (JSON_Object* joParams, JSON_Object* joResult);
int uapki_key_init_usage (JSON_Object* joParams, JSON_Object* joResult);

int uapki_sign (JSON_Object* joParams, JSON_Object* joResult);
int uapki_verify_signature (JSON_Object* joParams, JSON_Object* joResult);

int uapki_add_cert (JSON_Object* joParams, JSON_Object* joResult);
int uapki_cert_info (JSON_Object* joParams, JSON_Object* joResult);
int uapki_get_cert (JSON_Object* joParams, JSON_Object* joResult);
int uapki_list_certs (JSON_Object* joParams, JSON_Object* joResult);
int uapki_remove_cert (JSON_Object* joParams, JSON_Object* joResult);
int uapki_verify_cert (JSON_Object* joParams, JSON_Object* joResult);

int uapki_add_crl (JSON_Object* joParams, JSON_Object* joResult);
int uapki_crl_info (JSON_Object* joParams, JSON_Object* joResult);

int uapki_digest (JSON_Object* joParams, JSON_Object* joResult);
int uapki_asn1_decode (JSON_Object* joParams, JSON_Object* joResult);
int uapki_asn1_encode (JSON_Object* joParams, JSON_Object* joResult);

int uapki_decrypt (JSON_Object* joParams, JSON_Object* joResult);
int uapki_encrypt (JSON_Object* joParams, JSON_Object* joResult);

#ifdef __cplusplus
}
#endif

#endif
