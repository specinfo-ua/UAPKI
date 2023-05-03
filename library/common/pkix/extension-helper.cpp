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

#include "extension-helper.h"
#include "macros-internal.h"
#include "oid-utils.h"
#include "uapkif.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"


using namespace std;


namespace UapkiNS {


int ExtensionHelper::addOcspNonce (
        Extensions_t* extns,
        const ByteArray* baNonce
)
{
    int ret = RET_OK;
    UapkiNS::SmartBA sba_encoded;

    DO(UapkiNS::Util::encodeOctetString(baNonce, &sba_encoded));
    DO(UapkiNS::Util::addToExtensions(extns, OID_PKIX_OcspNonce, false, sba_encoded.get()));

cleanup:
    return ret;
}

int ExtensionHelper::addSubjectKeyId (
        Extensions_t* extns,
        const ByteArray* baSubjectKeyId
)
{
    int ret = RET_OK;
    UapkiNS::SmartBA sba_encoded;

    DO(UapkiNS::Util::encodeOctetString(baSubjectKeyId, &sba_encoded));
    DO(UapkiNS::Util::addToExtensions(extns, OID_X509v3_SubjectKeyIdentifier, false, sba_encoded.get()));

cleanup:
    return ret;
}

int ExtensionHelper::decodeAccessDescriptions (
        const ByteArray* baEncoded,
        const char* oidAccessMethod,
        vector<string>& uris
)
{
    int ret = RET_OK;
    SubjectInfoAccess_t* subject_infoaccess = nullptr;
    char* s_accessmethod = nullptr;
    char* s_uri = nullptr;

    CHECK_NOT_NULL(subject_infoaccess = (SubjectInfoAccess_t*)asn_decode_ba_with_alloc(get_SubjectInfoAccess_desc(), baEncoded));

    for (int i = 0; i < subject_infoaccess->list.count; i++) {
        const AccessDescription_t* access_descr = subject_infoaccess->list.array[i];

        DO(asn_oid_to_text(&access_descr->accessMethod, &s_accessmethod));

        if (
            oid_is_equal(s_accessmethod, oidAccessMethod) &&
            (access_descr->accessLocation.present == GeneralName_PR_uniformResourceIdentifier) &&
            (access_descr->accessLocation.choice.uniformResourceIdentifier.size > 0)
            ) {
            DO(UapkiNS::Util::pbufToStr(access_descr->accessLocation.choice.uniformResourceIdentifier.buf,
                access_descr->accessLocation.choice.uniformResourceIdentifier.size, &s_uri));
            uris.push_back(string(s_uri));
            ::free(s_uri);
            s_uri = nullptr;
        }

        ::free(s_accessmethod);
        s_accessmethod = nullptr;
    }

cleanup:
    asn_free(get_SubjectInfoAccess_desc(), subject_infoaccess);
    ::free(s_accessmethod);
    ::free(s_uri);
    return ret;
}

int ExtensionHelper::decodeDistributionPoints (
        const ByteArray* baEncoded,
        vector<string>& uris
)
{
    int ret = RET_OK;
    CRLDistributionPoints_t* distrib_points = nullptr;
    char* s_uri = nullptr;

    CHECK_NOT_NULL(distrib_points = (CRLDistributionPoints_t*)asn_decode_ba_with_alloc(get_CRLDistributionPoints_desc(), baEncoded));

    for (int i = 0; i < distrib_points->list.count; i++) {
        const DistributionPoint_t* distrib_point = distrib_points->list.array[i];
        if (distrib_point->distributionPoint
            && (distrib_point->distributionPoint->present == DistributionPointName_PR_fullName)
            && (distrib_point->distributionPoint->choice.fullName.list.count > 0)) {
            const GeneralName_t* general_name = distrib_point->distributionPoint->choice.fullName.list.array[0];
            if ((general_name->present == GeneralName_PR_uniformResourceIdentifier)
                && (general_name->choice.uniformResourceIdentifier.size > 0)) {
                DO(UapkiNS::Util::pbufToStr(general_name->choice.uniformResourceIdentifier.buf,
                    general_name->choice.uniformResourceIdentifier.size, &s_uri));
                uris.push_back(string(s_uri));
                ::free(s_uri);
                s_uri = nullptr;
            }
        }
    }

cleanup:
    asn_free(get_CRLDistributionPoints_desc(), distrib_points);
    ::free(s_uri);
    return ret;
}

int ExtensionHelper::getAuthorityInfoAccess(const Extensions_t* extns, char** urlOcsp)
{
    int ret = RET_OK, i;
    SubjectInfoAccess_t* si_access = NULL;
    ByteArray* ba_encoded = NULL;

    CHECK_PARAM(urlOcsp != NULL);

    DO(UapkiNS::Util::extnValueFromExtensions(extns, OID_PKIX_AuthorityInfoAccess, NULL, &ba_encoded));

    CHECK_NOT_NULL(si_access = (SubjectInfoAccess_t*)asn_decode_ba_with_alloc(get_SubjectInfoAccess_desc(), ba_encoded));

    for (i = 0; i < si_access->list.count; i++) {
        if (OID_is_equal_oid(&si_access->list.array[i]->accessMethod, OID_PKIX_OCSP)) {
            if (si_access->list.array[i]->accessLocation.present == GeneralName_PR_uniformResourceIdentifier) {
                const OCTET_STRING_t* octet_str = &si_access->list.array[i]->accessLocation.choice.uniformResourceIdentifier;
                DO(UapkiNS::Util::pbufToStr(octet_str->buf, (const size_t)octet_str->size, urlOcsp));
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

int ExtensionHelper::getAuthorityKeyId(const Extensions_t* extns, ByteArray** baKeyId)
{
    int ret = RET_OK;
    AuthorityKeyIdentifier_t* auth_keyid = NULL;
    ByteArray* ba_encoded = NULL;

    CHECK_PARAM(baKeyId != NULL);

    DO(UapkiNS::Util::extnValueFromExtensions(extns, OID_X509v3_AuthorityKeyIdentifier, NULL, &ba_encoded));

    CHECK_NOT_NULL(auth_keyid = (AuthorityKeyIdentifier_t*)asn_decode_ba_with_alloc(get_AuthorityKeyIdentifier_desc(), ba_encoded));
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

int ExtensionHelper::getBasicConstrains(const Extensions_t* extns, bool* cA, int* pathLenConstraint)
{
    int ret = RET_OK;
    BasicConstraints_t* basic_constraints = NULL;
    ByteArray* ba_encoded = NULL;
    bool critical = false;

    CHECK_PARAM(cA != NULL);
    CHECK_PARAM(pathLenConstraint != NULL);

    DO(UapkiNS::Util::extnValueFromExtensions(extns, OID_X509v3_BasicConstraints, &critical, &ba_encoded));

    CHECK_NOT_NULL(basic_constraints = (BasicConstraints_t*)asn_decode_ba_with_alloc(get_BasicConstraints_desc(), ba_encoded));

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

int ExtensionHelper::getCrlDistributionPoints(const Extensions_t* extns, char** urlFull)
{
    int ret = RET_OK;
    ByteArray* ba_encoded = NULL;
    const uint8_t* buf;
    size_t len;

    CHECK_PARAM(urlFull != NULL);

    ret = UapkiNS::Util::extnValueFromExtensions(extns, OID_X509v3_CRLDistributionPoints, NULL, &ba_encoded);
    if (ret == RET_OK) {
        buf = ba_get_buf(ba_encoded);
        len = ba_get_len(ba_encoded);
        if ((len > 10) && (buf[0] == 0x30) && (buf[2] == 0x30) && (buf[4] == 0xA0) && (buf[6] == 0xA0) && (((size_t)buf[9] + 10) <= len)) {
            DO(UapkiNS::Util::pbufToStr(buf + 10, buf[9], urlFull));
        }
    }

cleanup:
    ba_free(ba_encoded);
    return ret;
}

int ExtensionHelper::getFreshestCrl(const Extensions_t* extns, char** urlDelta)
{
    int ret = RET_OK;
    ByteArray* ba_encoded = NULL;
    const uint8_t* buf;
    size_t len;

    CHECK_PARAM(urlDelta != NULL);

    ret = UapkiNS::Util::extnValueFromExtensions(extns, OID_X509v3_FreshestCRL, NULL, &ba_encoded);
    if (ret == RET_OK) {
        buf = ba_get_buf(ba_encoded);
        len = ba_get_len(ba_encoded);
        if ((len > 8) && (buf[0] == 0x30) && (buf[2] == 0x30) && (buf[4] == 0xA0) && (buf[6] == 0xA0) && (((size_t)buf[9] + 10) <= len)) {
            DO(UapkiNS::Util::pbufToStr(buf + 10, buf[9], urlDelta));
        }
    }

cleanup:
    ba_free(ba_encoded);
    return ret;
}

int ExtensionHelper::getCrlInvalidityDate(const Extensions_t* extns, uint64_t* invalidityDate)
{
    int ret = RET_OK;
    ByteArray* ba_encoded = NULL;

    CHECK_PARAM(invalidityDate != NULL);

    DO(UapkiNS::Util::extnValueFromExtensions(extns, OID_X509v3_InvalidityDate, NULL, &ba_encoded));

    DO(UapkiNS::Util::decodePkixTime(ba_encoded, *invalidityDate));

cleanup:
    ba_free(ba_encoded);
    return ret;
}

int ExtensionHelper::getCrlNumber(const Extensions_t* extns, ByteArray** baCrlNumber)
{
    int ret = RET_OK;
    CRLNumber_t* crl_number = NULL;
    ByteArray* ba_encoded = NULL;

    CHECK_PARAM(baCrlNumber != NULL);

    DO(UapkiNS::Util::extnValueFromExtensions(extns, OID_X509v3_CRLNumber, NULL, &ba_encoded));

    CHECK_NOT_NULL(crl_number = (CRLNumber_t*)asn_decode_ba_with_alloc(get_CRLNumber_desc(), ba_encoded));
    DO(asn_INTEGER2ba(crl_number, baCrlNumber));

cleanup:
    asn_free(get_CRLNumber_desc(), crl_number);
    ba_free(ba_encoded);
    return ret;
}

int ExtensionHelper::getCrlReason(const Extensions_t* extns, uint32_t* crlReason)
{
    int ret = RET_OK;
    ByteArray* ba_encoded = NULL;

    CHECK_PARAM(crlReason != NULL);

    DO(UapkiNS::Util::extnValueFromExtensions(extns, OID_X509v3_CRLReason, NULL, &ba_encoded));

    DO(UapkiNS::Util::decodeEnumerated(ba_encoded, crlReason));

cleanup:
    ba_free(ba_encoded);
    return ret;
}

int ExtensionHelper::getDeltaCrlIndicator(const Extensions_t* extns, ByteArray** baDeltaCrlIndicator)
{
    int ret = RET_OK;
    CRLNumber_t* deltacrl_indicator = NULL;
    ByteArray* ba_encoded = NULL;
    bool critical = false;

    CHECK_PARAM(baDeltaCrlIndicator != NULL);

    DO(UapkiNS::Util::extnValueFromExtensions(extns, OID_X509v3_DeltaCRLIndicator, &critical, &ba_encoded));

    CHECK_NOT_NULL(deltacrl_indicator = (CRLNumber_t*)asn_decode_ba_with_alloc(get_CRLNumber_desc(), ba_encoded));
    DO(asn_INTEGER2ba(deltacrl_indicator, baDeltaCrlIndicator));

    ret = (critical) ? RET_OK : RET_UAPKI_EXTENSION_NOT_SET_CRITICAL;

cleanup:
    asn_free(get_CRLNumber_desc(), deltacrl_indicator);
    ba_free(ba_encoded);
    return ret;
}

int ExtensionHelper::getKeyUsage(const Extensions_t* extns, uint32_t* keyUsage)
{
    int ret = RET_OK;
    KeyUsage_t* key_usage = NULL;
    ByteArray* ba_encoded = NULL;
    uint32_t u32_keyusage = 0;
    bool critical = false;

    CHECK_PARAM(extns != NULL);
    CHECK_PARAM(keyUsage != NULL);

    *keyUsage = 0;
    DO(UapkiNS::Util::extnValueFromExtensions(extns, OID_X509v3_KeyUsage, &critical, &ba_encoded));

    CHECK_NOT_NULL(key_usage = (KeyUsage_t*)asn_decode_ba_with_alloc(get_KeyUsage_desc(), ba_encoded));

    for (int bit_num = 0; bit_num < 9; bit_num++) {
        int bit_flag = 0;
        DO(asn_BITSTRING_get_bit(key_usage, bit_num, &bit_flag));
        if (bit_flag) {
            u32_keyusage |= (0x00000001 << bit_num);
        }
    }

    *keyUsage = u32_keyusage;

cleanup:
    asn_free(get_KeyUsage_desc(), key_usage);
    ba_free(ba_encoded);
    return ret;
}

int ExtensionHelper::getOcspNonce(const Extensions_t* extns, ByteArray** baNonce)
{
    int ret = RET_OK;
    ByteArray* ba_encoded = NULL;

    CHECK_PARAM(extns != NULL);
    CHECK_PARAM(baNonce != NULL);

    ret = UapkiNS::Util::extnValueFromExtensions(extns, OID_PKIX_OcspNonce, NULL, &ba_encoded);
    if (ret == RET_OK) {
        DO(UapkiNS::Util::decodeOctetString(ba_encoded, baNonce));
    }

cleanup:
    ba_free(ba_encoded);
    return ret;
}

int ExtensionHelper::getSubjectDirectoryAttributes(const Extensions_t* extns, const char* oidType, ByteArray** baEncoded)
{
    int ret = RET_OK;
    SubjectDirectoryAttributes_t* subj_dirattrs = NULL;
    ByteArray* ba_encoded = NULL;

    CHECK_PARAM(oidType != NULL);
    CHECK_PARAM(baEncoded != NULL);

    ret = UapkiNS::Util::extnValueFromExtensions(extns, OID_X509v3_SubjectDirectoryAttributes, NULL, &ba_encoded);
    if (ret == RET_OK) {
        CHECK_NOT_NULL(subj_dirattrs = (SubjectDirectoryAttributes_t*)asn_decode_ba_with_alloc(get_SubjectDirectoryAttributes_desc(), ba_encoded));
        DO(UapkiNS::Util::attrValueFromAttributes((const Attributes_t*)subj_dirattrs, oidType, baEncoded));
    }

cleanup:
    asn_free(get_SubjectDirectoryAttributes_desc(), subj_dirattrs);
    ba_free(ba_encoded);
    return ret;
}

int ExtensionHelper::getSubjectKeyId(const Extensions_t* extns, ByteArray** baKeyId)
{
    int ret = RET_OK;
    SubjectKeyIdentifier_t* subj_keyid = NULL;
    ByteArray* ba_encoded = NULL;

    CHECK_PARAM(baKeyId != NULL);

    DO(UapkiNS::Util::extnValueFromExtensions(extns, OID_X509v3_SubjectKeyIdentifier, NULL, &ba_encoded));

    CHECK_NOT_NULL(subj_keyid = (SubjectKeyIdentifier_t*)asn_decode_ba_with_alloc(get_SubjectKeyIdentifier_desc(), ba_encoded));
    DO(asn_OCTSTRING2ba(subj_keyid, baKeyId));

cleanup:
    asn_free(get_SubjectKeyIdentifier_desc(), subj_keyid);
    ba_free(ba_encoded);
    return ret;
}

int ExtensionHelper::getTspUrl(const Extensions_t* extns, char** urlTsp)
{
    int ret = RET_OK, i;
    SubjectInfoAccess_t* si_access = NULL;
    ByteArray* ba_encoded = NULL;

    CHECK_PARAM(extns != NULL);
    CHECK_PARAM(urlTsp != NULL);

    DO(UapkiNS::Util::extnValueFromExtensions(extns, OID_PKIX_SubjectInfoAccess, NULL, &ba_encoded));

    CHECK_NOT_NULL(si_access = (SubjectInfoAccess_t*)asn_decode_ba_with_alloc(get_SubjectInfoAccess_desc(), ba_encoded));

    for (i = 0; i < si_access->list.count; i++) {
        if (OID_is_equal_oid(&si_access->list.array[i]->accessMethod, OID_PKIX_TimeStamping)) {
            if (si_access->list.array[i]->accessLocation.present == GeneralName_PR_uniformResourceIdentifier) {
                const OCTET_STRING_t* octet_str = &si_access->list.array[i]->accessLocation.choice.uniformResourceIdentifier;
                DO(UapkiNS::Util::pbufToStr(octet_str->buf, (const size_t)octet_str->size, urlTsp));
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


}   //  end namespace UapkiNS
