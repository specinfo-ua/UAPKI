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

#include "api-json-internal.h"
#include "global-objects.h"
#include "parson-helper.h"
#include "time-utils.h"

#undef FILE_MARKER
#define FILE_MARKER "api/api-json.cpp"

extern "C" const char* error_code_to_str (int errorCode);

UAPKI_EXPORT char* process (const char* request)
{
    int err_code = RET_OK;
    ParsonHelper json_request, json_result;
    JSON_Object* jo_params = nullptr;
    JSON_Object* jo_result = nullptr;
    const char* s_method = nullptr;
    char* rv_sjson = nullptr;

    json_result.create();
    json_result.setInt64("errorCode", RET_UAPKI_GENERAL_ERROR); //  Reserved first place in JSON-response

    if (!json_request.parse(request)) {
        err_code = RET_UAPKI_INVALID_JSON_FORMAT;
        goto cleanup;
    };

    s_method = json_request.getString("method");
    if (!s_method) {
        err_code = RET_UAPKI_INVALID_METHOD;
        goto cleanup;
    }
    json_result.setString("method", s_method);

    jo_params = json_request.getObject("parameters");
    jo_result = json_result.setObject("result");
    if (!jo_result) {
        err_code = RET_UAPKI_GENERAL_ERROR;
        goto cleanup;
    }

    if (strcmp(s_method, "VERSION") == 0) {
        err_code = uapki_version(jo_params, jo_result);
    }
    else if (strcmp(s_method, "INIT") == 0) {
        err_code = uapki_init(jo_params, jo_result);
    }
    else if (strcmp(s_method, "DEINIT") == 0) {
        err_code = uapki_deinit(jo_params, jo_result);
    }
    else if (strcmp(s_method, "PROVIDERS") == 0) {
        err_code = uapki_list_providers(jo_params, jo_result);
    }
    else if (strcmp(s_method, "STORAGES") == 0) {
        err_code = uapki_provider_list_storages(jo_params, jo_result);
    }
    else if (strcmp(s_method, "STORAGE_INFO") == 0) {
        err_code = uapki_provider_storage_info(jo_params, jo_result);
    }
    else if (strcmp(s_method, "OPEN") == 0) {
        err_code = uapki_storage_open(jo_params, jo_result);
    }
    else if (strcmp(s_method, "CLOSE") == 0) {
        err_code = uapki_storage_close(jo_params, jo_result);
    }
    else if (strcmp(s_method, "KEYS") == 0) {
        err_code = uapki_session_list_keys(jo_params, jo_result);
    }
    else if (strcmp(s_method, "SELECT_KEY") == 0) {
        err_code = uapki_session_select_key(jo_params, jo_result);
    }
    else if (strcmp(s_method, "CREATE_KEY") == 0) {
        err_code = uapki_session_key_create(jo_params, jo_result);
    }
    else if (strcmp(s_method, "DELETE_KEY") == 0) {
        err_code = uapki_session_key_delete(jo_params, jo_result);
    }
    else if (strcmp(s_method, "GET_CSR") == 0) {
        err_code = uapki_key_get_csr(jo_params, jo_result);
    }
    else if (strcmp(s_method, "CHANGE_PASSWORD") == 0) {
        err_code = uapki_storage_change_password(jo_params, jo_result);
    }
    else if (strcmp(s_method, "INIT_KEY_USAGE") == 0) {
        err_code = uapki_key_init_usage(jo_params, jo_result);
    }
    else if (strcmp(s_method, "SIGN") == 0) {
        err_code = uapki_sign(jo_params, jo_result);
    }
    else if (strcmp(s_method, "VERIFY") == 0) {
        err_code = uapki_verify_signature(jo_params, jo_result);
    }
    else if (strcmp(s_method, "ADD_CERT") == 0) {
        err_code = uapki_add_cert(jo_params, jo_result);
    }
    else if (strcmp(s_method, "CERT_INFO") == 0) {
        err_code = uapki_cert_info(jo_params, jo_result);
    }
    else if (strcmp(s_method, "GET_CERT") == 0) {
        err_code = uapki_get_cert(jo_params, jo_result);
    }
    else if (strcmp(s_method, "LIST_CERTS") == 0) {
        err_code = uapki_list_certs(jo_params, jo_result);
    }
    else if (strcmp(s_method, "REMOVE_CERT") == 0) {
        err_code = uapki_remove_cert(jo_params, jo_result);
    }
    else if (strcmp(s_method, "VERIFY_CERT") == 0) {
        err_code = uapki_verify_cert(jo_params, jo_result);
    }
    else if (strcmp(s_method, "ADD_CRL") == 0) {
        err_code = uapki_add_crl(jo_params, jo_result);
    }
    else if (strcmp(s_method, "CRL_INFO") == 0) {
        err_code = uapki_crl_info(jo_params, jo_result);
    }
    else if (strcmp(s_method, "DIGEST") == 0) {
        err_code = uapki_digest(jo_params, jo_result);
    }
    else if (strcmp(s_method, "ASN1_DECODE") == 0) {
        err_code = uapki_asn1_decode(jo_params, jo_result);
    }
    else if (strcmp(s_method, "ASN1_ENCODE") == 0) {
        err_code = uapki_asn1_encode(jo_params, jo_result);
    }
    else {
        err_code = RET_UAPKI_INVALID_METHOD;
    }

cleanup:
    json_result.setInt32("errorCode", err_code);
    if (err_code != RET_OK) {
        json_result.setString("error", error_code_to_str(err_code));
    }
    if (ParsonHelper::jsonObjectGetBoolean(jo_params, "reportTime", false)) {
        const string s_time = TimeUtils::mstimeToFormat(TimeUtils::nowMsTime());
        json_object_set_string(jo_result, "reportTime", s_time.c_str());
    }
    json_result.serialize(&rv_sjson);
    return rv_sjson;
}

UAPKI_EXPORT void json_free (char* buf)
{ 
    free(buf);
}
