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

#include "attribute-utils.h"
#include "asn1-ba-utils.h"
#include "macros-internal.h"
#include "oid-utils.h"
#include "uapki-errors.h"


int attrs_add_attribute (Attributes_t* attrs, const char* attrType, const ByteArray* baEncoded)
{
    int ret = RET_OK;
    Attribute_t* attr = NULL;
    ANY_t* any = NULL;

    CHECK_PARAM(attrs != NULL);
    CHECK_PARAM(attrType != NULL);
    CHECK_PARAM(baEncoded != NULL);

    ASN_ALLOC(attr);
    DO(asn_set_oid_from_text(attrType, &attr->type));
    CHECK_NOT_NULL(any = asn_decode_ba_with_alloc(get_ANY_desc(), baEncoded));

    DO(ASN_SET_ADD(&attr->value.list, any));
    any = NULL;

    DO(ASN_SET_ADD(&attrs->list, attr));
    attr = NULL;

cleanup:
    asn_free(get_Attribute_desc(), attr);
    asn_free(get_ANY_desc(), any);
    return ret;
}

const Attribute_t* attrs_get_attr_by_oid (const Attributes_t* attrs, const char* oidType)
{
    if ((attrs != NULL) && (oidType != NULL)) {
        for (int i = 0; i < attrs->list.count; i++) {
            const Attribute_t* attr = attrs->list.array[i];
            if (OID_is_equal_oid(&attr->type, oidType)) return attr;
        }
    }
    return NULL;
}

int attrs_get_attrvalue_by_oid (const Attributes_t* attrs, const char* oidType, ByteArray** baEncoded)
{
    int ret = RET_OK;
    const Attribute_t* attr;

    CHECK_PARAM(baEncoded != NULL);

    attr = attrs_get_attr_by_oid(attrs, oidType);
    if (attr == NULL) {
        ret = RET_UAPKI_ATTRIBUTE_NOT_PRESENT;
        goto cleanup;
    }

    if (attr->value.list.count > 0) {
        const AttributeValue_t* attr_value = attr->value.list.array[0];
        *baEncoded = ba_alloc_from_uint8(attr_value->buf, attr_value->size);
    }
    else {
        *baEncoded = ba_alloc();
    }
    CHECK_NOT_NULL(*baEncoded);

cleanup:
    return ret;
}

int attrs_get_content_type (const Attributes_t* attrs, char** oidContentType)
{
    int ret = RET_OK;
    ByteArray* ba_encoded = NULL;

    CHECK_PARAM(oidContentType != NULL);

    DO(attrs_get_attrvalue_by_oid(attrs, OID_PKCS9_CONTENT_TYPE, &ba_encoded));
    DO(ba_decode_oid(ba_encoded, oidContentType));

cleanup:
    ba_free(ba_encoded);
    return ret;
}

int attrs_get_message_digest (const Attributes_t* attrs, ByteArray** baMessageDigest)
{
    int ret = RET_OK;
    ByteArray* ba_encoded = NULL;

    CHECK_PARAM(baMessageDigest != NULL);

    DO(attrs_get_attrvalue_by_oid(attrs, OID_PKCS9_MESSAGE_DIGEST, &ba_encoded));
    DO(ba_decode_octetstring(ba_encoded, baMessageDigest));

cleanup:
    ba_free(ba_encoded);
    return ret;
}

int attrs_get_signing_time (const Attributes_t* attrs, uint64_t* signingTime)
{
    int ret = RET_OK;
    ByteArray* ba_encoded = NULL;

    CHECK_PARAM(signingTime != NULL);

    DO(attrs_get_attrvalue_by_oid(attrs, OID_PKCS9_SIGNING_TIME, &ba_encoded));
    DO(ba_decode_pkixtime(ba_encoded, signingTime));

cleanup:
    ba_free(ba_encoded);
    return ret;
}

