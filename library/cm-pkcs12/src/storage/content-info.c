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

#include <stdlib.h>
#include <stdbool.h>

#include "asn1-utils.h"
#include "cm-errors.h"
#include "content-info.h"
#include "macros-internal.h"
#include "oids.h"
#include "oid-utils.h"


#undef FILE_MARKER
#define FILE_MARKER "content-info.c"


int cinfo_get_type (const ContentInfo_t* cinfo, CinfoType *type)
{
    int ret = RET_OK;

    CHECK_PARAM(cinfo != NULL);
    CHECK_PARAM(type != NULL);

    if (OID_is_equal_oid(&cinfo->contentType, OID_PKCS7_DATA)) {
        *type = CONTENT_DATA;
    } else if (OID_is_equal_oid(&cinfo->contentType, OID_PKCS7_SIGNED_DATA)) {
        *type = CONTENT_SIGNED;
    } else if (OID_is_equal_oid(&cinfo->contentType, OID_PKCS7_DIGESTED_DATA)) {
        *type = CONTENT_DIGESTED;
    } else if (OID_is_equal_oid(&cinfo->contentType, OID_PKCS7_ENCRYPTED_DATA)) {
        *type = CONTENT_ENCRYPTED;
    } else if (OID_is_equal_oid(&cinfo->contentType, OID_PKCS7_ENVELOPED_DATA)) {
        *type = CONTENT_ENVELOPED;
    } else {
        *type = CONTENT_UNKNOWN;
    }

cleanup:
    return ret;
}

int cinfo_get_data (const ContentInfo_t* cinfo, ByteArray** data)
{
    int ret = RET_OK;
    OCTET_STRING_t* content = NULL;

    CHECK_PARAM(cinfo != NULL);
    CHECK_PARAM(data != NULL);

    if (!OID_is_equal_oid(&cinfo->contentType, OID_PKCS7_DATA)) {
        SET_ERROR(RET_CM_INVALID_CONTENT_INFO);
    }

    if (!cinfo->content.buf || !cinfo->content.size) {
        SET_ERROR(RET_CM_INVALID_CONTENT_INFO);
    }

    CHECK_NOT_NULL(content = asn_any2type(&cinfo->content, get_OCTET_STRING_desc()));
    DO(asn_OCTSTRING2ba(content, data));

cleanup:
    asn_free(get_OCTET_STRING_desc(), content);
    return ret;
}

int cinfo_get_encrypted_data (const ContentInfo_t* cinfo, EncryptedData_t* *encr_data)
{
    int ret = RET_OK;

    CHECK_PARAM(cinfo != NULL);
    CHECK_PARAM(encr_data != NULL);

    if (!OID_is_equal_oid(&cinfo->contentType, OID_PKCS7_ENCRYPTED_DATA)) {
        SET_ERROR(RET_CM_INVALID_CONTENT_INFO);
    }

    if (!cinfo->content.buf || !cinfo->content.size) {
        SET_ERROR(RET_CM_INVALID_CONTENT_INFO);
    }

    CHECK_NOT_NULL(*encr_data = asn_any2type(&cinfo->content, get_EncryptedData_desc()));

cleanup:

    return ret;
}

int cinfo_init_by_data (ContentInfo_t* cinfo, const ByteArray *data)
{
    int ret = RET_OK;
    OCTET_STRING_t* data_os = NULL;

    CHECK_PARAM(cinfo != NULL);
    CHECK_PARAM(data != NULL);

    ASN_FREE_CONTENT_PTR(get_ContentInfo_desc(), cinfo);

    DO(asn_set_oid_from_text(OID_PKCS7_DATA, &cinfo->contentType));

    DO(asn_create_octstring_from_ba(data, &data_os));
    DO(asn_set_any(get_OCTET_STRING_desc(), (void *)data_os, &cinfo->content));

cleanup:
    if (ret != RET_OK) {
        ASN_FREE_CONTENT_PTR(get_ContentInfo_desc(), cinfo);
    }
    asn_free(get_OCTET_STRING_desc(), data_os);
    return ret;
}

int cinfo_init_by_encrypted_data (ContentInfo_t* cinfo, const EncryptedData_t* encr_data)
{
    int ret = RET_OK;

    CHECK_PARAM(cinfo != NULL);
    CHECK_PARAM(encr_data != NULL);

    ASN_FREE_CONTENT_PTR(get_ContentInfo_desc(), cinfo);

    DO(asn_set_oid_from_text(OID_PKCS7_ENCRYPTED_DATA, &cinfo->contentType));
    DO(asn_set_any(get_EncryptedData_desc(), (void *)encr_data, &cinfo->content));

cleanup:
    if (ret != RET_OK) {
        ASN_FREE_CONTENT_PTR(get_ContentInfo_desc(), cinfo);
    }
    return ret;
}
