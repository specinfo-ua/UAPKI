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

//  Last update: 2021-09-16

#include "extension-utils.h"
#include "asn1-ba-utils.h"
#include "attribute-utils.h"
#include "macros-internal.h"
#include "oid-utils.h"
#include "uapki-errors.h"


/*int build_extension(const char* oidExtnId, const bool critical, const ByteArray* baExtnValue, Extension_t** extension)
{
    int ret = RET_OK;
    Extension_t* extn = NULL;
    BOOLEAN_t cr = true;

    CHECK_PARAM(oidExtnId != NULL);
    CHECK_PARAM(baExtnValue != NULL);
    CHECK_PARAM(extension != NULL);

    ASN_ALLOC(extn);

    DO(asn_set_oid_from_text(oidExtnId, &extn->extnID));
    if (critical) {
        CHECK_NOT_NULL(extn->critical = (BOOLEAN_t*)asn_copy_with_alloc(get_BOOLEAN_desc(), &cr));
    }
    DO(asn_ba2OCTSTRING(baExtnValue, &extn->extnValue));

    *extension = extn;
    extn = NULL;

cleanup:
    asn_free(get_Extension_desc(), extn);
    return ret;
}*/

int extns_add_extension (Extensions_t* extns, const char* extnId, const bool critical, const ByteArray* baEncoded)
{
    int ret = RET_OK;
    Extension_t* extn = NULL;
    BOOLEAN_t cr = true;

    CHECK_PARAM(extns != NULL);
    CHECK_PARAM(extnId != NULL);
    CHECK_PARAM(baEncoded != NULL);

    ASN_ALLOC(extn);

    DO(asn_set_oid_from_text(extnId, &extn->extnID));
    if (critical) {
        CHECK_NOT_NULL(extn->critical = (BOOLEAN_t*)asn_copy_with_alloc(get_BOOLEAN_desc(), &cr));
    }
    DO(asn_ba2OCTSTRING(baEncoded, &extn->extnValue));

    DO(ASN_SEQUENCE_ADD(&extns->list, extn));
    extn = NULL;

cleanup:
    asn_free(get_Extension_desc(), extn);
    return ret;
}

int extns_add_ocsp_nonce (Extensions_t* extns, const ByteArray* baNonce)
{
    int ret = RET_OK;
    ByteArray* ba_encoded = NULL;

    DO(ba_encode_octetstring(baNonce, &ba_encoded));
    DO(extns_add_extension(extns, OID_PKIX_OcspNonce, false, ba_encoded));

cleanup:
    ba_free(ba_encoded);
    return ret;
}

int extns_add_subject_keyid (Extensions_t* extns, const ByteArray* baSubjectKeyId)
{
    int ret = RET_OK;
    ByteArray* ba_encoded = NULL;

    DO(ba_encode_octetstring(baSubjectKeyId, &ba_encoded));
    DO(extns_add_extension(extns, OID_X509v3_SubjectKeyIdentifier, false, ba_encoded));

cleanup:
    ba_free(ba_encoded);
    return ret;
}

const Extension_t* extns_get_extn_by_oid (const Extensions_t* extns, const char* oidExtnId)
{
    if ((extns != NULL) && (oidExtnId != NULL)) {
        for (int i = 0; i < extns->list.count; i++) {
            const Extension_t* extn = extns->list.array[i];
            if (OID_is_equal_oid(&extn->extnID, oidExtnId)) return extn;
        }
    }
    return NULL;
}

int extns_get_extnvalue_by_oid (const Extensions_t* extns, const char* oidExtnId, bool* critical, ByteArray** baEncoded)
{
    int ret = RET_OK;
    const Extension_t* extn;

    CHECK_PARAM(baEncoded != NULL);

    extn = extns_get_extn_by_oid(extns, oidExtnId);
    if (extn == NULL) {
        ret = RET_UAPKI_EXTENSION_NOT_PRESENT;
        goto cleanup;
    }

    //  critical (optional)
    if (critical != NULL) {
        *critical = false;
        if (extn->critical != NULL) {
            *critical = (extn->critical != 0);
        }
    }
    //  extnValue
    DO(asn_OCTSTRING2ba(&extn->extnValue, baEncoded));

cleanup:
    return ret;
}

int extns_get_authority_infoaccess (const Extensions_t* extns, char** urlOcsp)
{
    int ret = RET_OK, i;
    SubjectInfoAccess_t* si_access = NULL;
    ByteArray* ba_encoded = NULL;

    CHECK_PARAM(urlOcsp != NULL);

    DO(extns_get_extnvalue_by_oid(extns, OID_PKIX_AuthorityInfoAccess, NULL, &ba_encoded));

    CHECK_NOT_NULL(si_access = asn_decode_ba_with_alloc(get_SubjectInfoAccess_desc(), ba_encoded));

    for (i = 0; i < si_access->list.count; i++) {
        if (OID_is_equal_oid(&si_access->list.array[i]->accessMethod, OID_PKIX_OCSP)) {
            if (si_access->list.array[i]->accessLocation.present == GeneralName_PR_uniformResourceIdentifier) {
                const OCTET_STRING_t* octet_str = &si_access->list.array[i]->accessLocation.choice.uniformResourceIdentifier;
                DO(uint8_to_str_with_alloc(octet_str->buf, (const size_t)octet_str->size, urlOcsp));
                //now skip - return one value only
                break;
            }
        }
    }

cleanup:
    asn_free(get_SubjectInfoAccess_desc(), si_access);
    ba_free(ba_encoded);
    return ret;
}

int extns_get_authority_keyid (const Extensions_t* extns, ByteArray** baKeyId)
{
    int ret = RET_OK;
    AuthorityKeyIdentifier_t* auth_keyid = NULL;
    ByteArray* ba_encoded = NULL;

    CHECK_PARAM(baKeyId != NULL);

    DO(extns_get_extnvalue_by_oid(extns, OID_X509v3_AuthorityKeyIdentifier, NULL, &ba_encoded));

    CHECK_NOT_NULL(auth_keyid = asn_decode_ba_with_alloc(get_AuthorityKeyIdentifier_desc(), ba_encoded));
    if (auth_keyid->keyIdentifier != NULL) {
        DO(asn_OCTSTRING2ba(auth_keyid->keyIdentifier, baKeyId));
    }
    else {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

cleanup:
    asn_free(get_AuthorityKeyIdentifier_desc(), auth_keyid);
    ba_free(ba_encoded);
    return ret;
}

int extns_get_basic_constrains (const Extensions_t* extns, bool* cA, int* pathLenConstraint)
{
    int ret = RET_OK;
    BasicConstraints_t* basic_constraints = NULL;
    ByteArray* ba_encoded = NULL;
    bool critical = false;

    CHECK_PARAM(cA != NULL);
    CHECK_PARAM(pathLenConstraint != NULL);

    DO(extns_get_extnvalue_by_oid(extns, OID_X509v3_BasicConstraints, &critical, &ba_encoded));

    CHECK_NOT_NULL(basic_constraints = asn_decode_ba_with_alloc(get_BasicConstraints_desc(), ba_encoded));

    *cA = false;
    if (basic_constraints->cA != NULL) {
        *cA = (basic_constraints->cA != 0);
    }

    *pathLenConstraint = -1;
    if (basic_constraints->pathLenConstraint != NULL) {
        long path_len;
        DO(asn_INTEGER2long(basic_constraints->pathLenConstraint, &path_len));
        *pathLenConstraint = path_len;
    }

    ret = (critical) ? RET_OK : RET_UAPKI_EXTENSION_NOT_SET_CRITICAL;

cleanup:
    asn_free(get_BasicConstraints_desc(), basic_constraints);
    ba_free(ba_encoded);
    return ret;
}

int extns_get_crl_distribution_points (const Extensions_t* extns, char** urlFull)
{
    int ret = RET_OK;
    ByteArray* ba_encoded = NULL;
    const uint8_t* buf;
    size_t len;

    CHECK_PARAM(urlFull != NULL);

    ret = extns_get_extnvalue_by_oid(extns, OID_X509v3_CRLDistributionPoints, NULL, &ba_encoded);
    if (ret == RET_OK) {
        buf = ba_get_buf(ba_encoded);
        len = ba_get_len(ba_encoded);
        if ((len > 10) && (buf[0] == 0x30) && (buf[2] == 0x30) && (buf[4] == 0xA0) && (buf[6] == 0xA0) && (((size_t)buf[9] + 10) <= len)) {
            DO(uint8_to_str_with_alloc(buf + 10, buf[9], urlFull));
        }
    }

cleanup:
    ba_free(ba_encoded);
    return ret;
}

int extns_get_freshest_crl (const Extensions_t* extns, char** urlDelta)
{
    int ret = RET_OK;
    ByteArray* ba_encoded = NULL;
    const uint8_t* buf;
    size_t len;

    CHECK_PARAM(urlDelta != NULL);

    ret = extns_get_extnvalue_by_oid(extns, OID_X509v3_FreshestCRL, NULL, &ba_encoded);
    if (ret == RET_OK) {
        buf = ba_get_buf(ba_encoded);
        len = ba_get_len(ba_encoded);
        if ((len > 8) && (buf[0] == 0x30) && (buf[2] == 0x30) && (buf[4] == 0xA0) && (buf[6] == 0xA0) && (((size_t)buf[9] + 10) <= len)) {
            DO(uint8_to_str_with_alloc(buf + 10, buf[9], urlDelta));
        }
    }

cleanup:
    ba_free(ba_encoded);
    return ret;
}

int extns_get_crl_invalidity_date (const Extensions_t* extns, uint64_t* invalidityDate)
{
    int ret = RET_OK;
    ByteArray* ba_encoded = NULL;

    CHECK_PARAM(invalidityDate != NULL);

    DO(extns_get_extnvalue_by_oid(extns, OID_X509v3_InvalidityDate, NULL, &ba_encoded));

    DO(ba_decode_pkixtime(ba_encoded, invalidityDate));

cleanup:
    ba_free(ba_encoded);
    return ret;
}

int extns_get_crl_number (const Extensions_t* extns, ByteArray** baCrlNumber)
{
    int ret = RET_OK;
    CRLNumber_t* crl_number = NULL;
    ByteArray* ba_encoded = NULL;

    CHECK_PARAM(baCrlNumber != NULL);

    DO(extns_get_extnvalue_by_oid(extns, OID_X509v3_CRLNumber, NULL, &ba_encoded));

    CHECK_NOT_NULL(crl_number = asn_decode_ba_with_alloc(get_CRLNumber_desc(), ba_encoded));
    DO(asn_INTEGER2ba(crl_number, baCrlNumber));

cleanup:
    asn_free(get_CRLNumber_desc(), crl_number);
    ba_free(ba_encoded);
    return ret;
}

int extns_get_crl_reason (const Extensions_t* extns, uint32_t* crlReason)
{
    int ret = RET_OK;
    ByteArray* ba_encoded = NULL;

    CHECK_PARAM(crlReason != NULL);

    DO(extns_get_extnvalue_by_oid(extns, OID_X509v3_CRLReason, NULL, &ba_encoded));

    DO(ba_decode_enumerated(ba_encoded, crlReason));

cleanup:
    ba_free(ba_encoded);
    return ret;
}

int extns_get_delta_crl_indicator (const Extensions_t* extns, ByteArray** baDeltaCrlIndicator)
{
    int ret = RET_OK;
    CRLNumber_t* deltacrl_indicator = NULL;
    ByteArray* ba_encoded = NULL;
    bool critical = false;

    CHECK_PARAM(baDeltaCrlIndicator != NULL);

    DO(extns_get_extnvalue_by_oid(extns, OID_X509v3_DeltaCRLIndicator, &critical, &ba_encoded));

    CHECK_NOT_NULL(deltacrl_indicator = asn_decode_ba_with_alloc(get_CRLNumber_desc(), ba_encoded));
    DO(asn_INTEGER2ba(deltacrl_indicator, baDeltaCrlIndicator));

    ret = (critical) ? RET_OK : RET_UAPKI_EXTENSION_NOT_SET_CRITICAL;

cleanup:
    asn_free(get_CRLNumber_desc(), deltacrl_indicator);
    ba_free(ba_encoded);
    return ret;
}

int extns_get_key_usage (const Extensions_t* extns, uint32_t* keyUsage)
{
    int ret = RET_OK;
    KeyUsage_t* key_usage = NULL;
    ByteArray* ba_encoded = NULL;
    uint32_t u32_keyusage = 0;
    bool critical = false;

    CHECK_PARAM(extns != NULL);
    CHECK_PARAM(keyUsage != NULL);

    *keyUsage = 0;
    DO(extns_get_extnvalue_by_oid(extns, OID_X509v3_KeyUsage, &critical, &ba_encoded));

    CHECK_NOT_NULL(key_usage = asn_decode_ba_with_alloc(get_KeyUsage_desc(), ba_encoded));

    for (int bit_num = 0; bit_num < 9; bit_num++) {
        int bit_flag = 0;
        DO(asn_BITSTRING_get_bit(key_usage, bit_num, &bit_flag));
        if (bit_flag) {
            u32_keyusage |= (0x00000001 << bit_num);
        }
    }

cleanup:
    asn_free(get_KeyUsage_desc(), key_usage);
    ba_free(ba_encoded);
    return ret;
}

int extns_get_ocsp_nonce (const Extensions_t* extns, ByteArray** baNonce)
{
    int ret = RET_OK;
    ByteArray* ba_encoded = NULL;

    CHECK_PARAM(extns != NULL);
    CHECK_PARAM(baNonce != NULL);

    ret = extns_get_extnvalue_by_oid(extns, OID_PKIX_OcspNonce, NULL, &ba_encoded);
    if (ret == RET_OK) {
        DO(ba_decode_octetstring(ba_encoded, baNonce));
    }

cleanup:
    ba_free(ba_encoded);
    return ret;
}

int extns_get_subject_directory_attrs (const Extensions_t* extns, const char* oidType, ByteArray** baEncoded)
{
    int ret = RET_OK;
    SubjectDirectoryAttributes_t* subj_dirattrs = NULL;
    ByteArray* ba_encoded = NULL;

    CHECK_PARAM(oidType != NULL);
    CHECK_PARAM(baEncoded != NULL);

    ret = extns_get_extnvalue_by_oid(extns, OID_X509v3_SubjectDirectoryAttributes, NULL, &ba_encoded);
    if (ret == RET_OK) {
        CHECK_NOT_NULL(subj_dirattrs = asn_decode_ba_with_alloc(get_SubjectDirectoryAttributes_desc(), ba_encoded));
        DO(attrs_get_attrvalue_by_oid((const Attributes_t*)subj_dirattrs, oidType, baEncoded));
    }

cleanup:
    asn_free(get_SubjectDirectoryAttributes_desc(), subj_dirattrs);
    ba_free(ba_encoded);
    return ret;
}

int extns_get_subject_keyid (const Extensions_t* extns, ByteArray** baKeyId)
{
    int ret = RET_OK;
    SubjectKeyIdentifier_t* subj_keyid = NULL;
    ByteArray* ba_encoded = NULL;

    CHECK_PARAM(baKeyId != NULL);

    DO(extns_get_extnvalue_by_oid(extns, OID_X509v3_SubjectKeyIdentifier, NULL, &ba_encoded));

    CHECK_NOT_NULL(subj_keyid = asn_decode_ba_with_alloc(get_SubjectKeyIdentifier_desc(), ba_encoded));
    DO(asn_OCTSTRING2ba(subj_keyid, baKeyId));

cleanup:
    asn_free(get_SubjectKeyIdentifier_desc(), subj_keyid);
    ba_free(ba_encoded);
    return ret;
}

int extns_get_tsp_url (const Extensions_t* extns, char** urlTsp)
{
    int ret = RET_OK, i;
    SubjectInfoAccess_t* si_access = NULL;
    ByteArray* ba_encoded = NULL;

    CHECK_PARAM(extns != NULL);
    CHECK_PARAM(urlTsp != NULL);

    DO(extns_get_extnvalue_by_oid(extns, OID_PKIX_SubjectInfoAccess, NULL, &ba_encoded));

    CHECK_NOT_NULL(si_access = asn_decode_ba_with_alloc(get_SubjectInfoAccess_desc(), ba_encoded));

    for (i = 0; i < si_access->list.count; i++) {
        if (OID_is_equal_oid(&si_access->list.array[i]->accessMethod, OID_PKIX_TimeStamping)) {
            if (si_access->list.array[i]->accessLocation.present == GeneralName_PR_uniformResourceIdentifier) {
                const OCTET_STRING_t* octet_str = &si_access->list.array[i]->accessLocation.choice.uniformResourceIdentifier;
                DO(uint8_to_str_with_alloc(octet_str->buf, (const size_t)octet_str->size, urlTsp));
                //now skip - return one value only
                break;
            }
        }
    }

cleanup:
    asn_free(get_SubjectInfoAccess_desc(), si_access);
    ba_free(ba_encoded);
    return ret;
}

