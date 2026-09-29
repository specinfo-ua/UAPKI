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

#ifndef UAPKI_API_JSON_H
#define UAPKI_API_JSON_H

#include <string.h>
#include "ba-utils.h"
#include "cm-api.h"
#include "cm-errors.h"
#include "cm-providers.h"
#include "macros-internal.h"
#include "parson.h"
#include "parson-ba-utils.h"
#include "session.h"
#include "uapki-errors.h"
#include "uapki-export.h"
#include "uapki-ns.h"
#include "api-json-custom.h"


int uapki_init (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_version (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_deinit (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_list_providers (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_provider_list_storages (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_provider_storage_info (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);

int uapki_storage_open  (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_storage_close (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_storage_change_password (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);

int uapki_session_list_keys (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_session_select_key (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_session_key_create (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_session_key_delete (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);

int uapki_key_get_csr (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_verify_csr (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_key_init_usage (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);

int uapki_sign (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_verify_signature (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_modify_cms (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);

int uapki_build_cms_2pass (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_build_csr_2pass (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);

int uapki_add_cert (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_cert_info (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_get_cert (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_list_certs (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_remove_cert (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_verify_cert (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);

int uapki_add_crl (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_crl_info (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_list_crls (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_remove_crl (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);

int uapki_digest (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_asn1_decode (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_asn1_encode (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_generate_certbundle (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);

int uapki_decrypt (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_encrypt (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);

int uapki_random_bytes (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);
int uapki_cert_status_by_ocsp (UapkiNS::Context& context, JSON_Object* joParams, JSON_Object* joResult);

#ifdef API_JSON_INTERNAL_CUSTOM
  API_JSON_INTERNAL_CUSTOM
#endif

#endif
