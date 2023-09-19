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

#define FILE_MARKER "common/pkix/extension-helper.cpp"

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
    SmartBA sba_encoded;

    DO(Util::encodeOctetString(baNonce, &sba_encoded));
    DO(Util::addToExtensions(extns, OID_PKIX_OcspNonce, false, sba_encoded.get()));

cleanup:
    return ret;
}

int ExtensionHelper::addSubjectKeyId (
        Extensions_t* extns,
        const ByteArray* baSubjectKeyId
)
{
    int ret = RET_OK;
    SmartBA sba_encoded;

    DO(Util::encodeOctetString(baSubjectKeyId, &sba_encoded));
    DO(Util::addToExtensions(extns, OID_X509v3_SubjectKeyIdentifier, false, sba_encoded.get()));

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
    string s_accessmethod;

    CHECK_NOT_NULL(subject_infoaccess = (SubjectInfoAccess_t*)asn_decode_ba_with_alloc(get_SubjectInfoAccess_desc(), baEncoded));

    for (int i = 0; i < subject_infoaccess->list.count; i++) {
        const AccessDescription_t* access_descr = subject_infoaccess->list.array[i];

        DO(Util::oidFromAsn1(&access_descr->accessMethod, s_accessmethod));

        if (
            oid_is_equal(s_accessmethod.c_str(), oidAccessMethod) &&
            (access_descr->accessLocation.present == GeneralName_PR_uniformResourceIdentifier) &&
            (access_descr->accessLocation.choice.uniformResourceIdentifier.size > 0)
        ) {
            char* s_uri = nullptr;
            DO(Util::pbufToStr(access_descr->accessLocation.choice.uniformResourceIdentifier.buf,
                access_descr->accessLocation.choice.uniformResourceIdentifier.size, &s_uri));
            uris.push_back(string(s_uri));
            ::free(s_uri);
            s_uri = nullptr;
        }
    }

cleanup:
    asn_free(get_SubjectInfoAccess_desc(), subject_infoaccess);
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
        if (
            distrib_point->distributionPoint &&
            (distrib_point->distributionPoint->present == DistributionPointName_PR_fullName) &&
            (distrib_point->distributionPoint->choice.fullName.list.count > 0)
        ) {
            const GeneralName_t* general_name = distrib_point->distributionPoint->choice.fullName.list.array[0];
            if ((general_name->present == GeneralName_PR_uniformResourceIdentifier)
                && (general_name->choice.uniformResourceIdentifier.size > 0)) {
                DO(Util::pbufToStr(general_name->choice.uniformResourceIdentifier.buf,
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

int ExtensionHelper::getAuthorityKeyId (
        const Extensions_t* extns,
        ByteArray** baKeyId
)
{
    int ret = RET_OK;
    AuthorityKeyIdentifier_t* auth_keyid = nullptr;
    SmartBA sba_encoded;

    CHECK_PARAM(baKeyId);

    DO(Util::extnValueFromExtensions(extns, OID_X509v3_AuthorityKeyIdentifier, nullptr, &sba_encoded));

    CHECK_NOT_NULL(auth_keyid = (AuthorityKeyIdentifier_t*)asn_decode_ba_with_alloc(get_AuthorityKeyIdentifier_desc(), sba_encoded.get()));
    if (auth_keyid->keyIdentifier) {
        DO(asn_OCTSTRING2ba(auth_keyid->keyIdentifier, baKeyId));
    }
    else {
        SET_ERROR(RET_UAPKI_INVALID_STRUCT);
    }

cleanup:
    asn_free(get_AuthorityKeyIdentifier_desc(), auth_keyid);
    return ret;
}

int ExtensionHelper::getBasicConstrains (
        const Extensions_t* extns,
        bool& cA,
        int& pathLenConstraint
)
{
    int ret = RET_OK;
    BasicConstraints_t* basic_constraints = nullptr;
    SmartBA sba_encoded;
    bool critical = false;

    CHECK_PARAM(cA);
    CHECK_PARAM(pathLenConstraint);

    DO(Util::extnValueFromExtensions(extns, OID_X509v3_BasicConstraints, &critical, &sba_encoded));

    CHECK_NOT_NULL(basic_constraints = (BasicConstraints_t*)asn_decode_ba_with_alloc(get_BasicConstraints_desc(), sba_encoded.get()));

    cA = false;
    if (basic_constraints->cA) {
        cA = (basic_constraints->cA != 0);
    }

    pathLenConstraint = -1;
    if (basic_constraints->pathLenConstraint) {
        long path_len;
        DO(asn_INTEGER2long(basic_constraints->pathLenConstraint, &path_len));
        pathLenConstraint = path_len;
    }

    ret = (critical) ? RET_OK : RET_UAPKI_EXTENSION_NOT_SET_CRITICAL;

cleanup:
    asn_free(get_BasicConstraints_desc(), basic_constraints);
    return ret;
}

int ExtensionHelper::getCrlInvalidityDate (
        const Extensions_t* extns,
        uint64_t& invalidityDate
)
{
    int ret = RET_OK;
    SmartBA sba_encoded;

    DO(Util::extnValueFromExtensions(extns, OID_X509v3_InvalidityDate, nullptr, &sba_encoded));

    DO(Util::decodePkixTime(sba_encoded.get(), invalidityDate));

cleanup:
    return ret;
}

int ExtensionHelper::getCrlNumber (
        const Extensions_t* extns,
        ByteArray** baCrlNumber
)
{
    int ret = RET_OK;
    CRLNumber_t* crl_number = nullptr;
    SmartBA sba_encoded;

    CHECK_PARAM(baCrlNumber);

    DO(Util::extnValueFromExtensions(extns, OID_X509v3_CRLNumber, nullptr, &sba_encoded));

    CHECK_NOT_NULL(crl_number = (CRLNumber_t*)asn_decode_ba_with_alloc(get_CRLNumber_desc(), sba_encoded.get()));
    DO(asn_INTEGER2ba(crl_number, baCrlNumber));

cleanup:
    asn_free(get_CRLNumber_desc(), crl_number);
    return ret;
}

int ExtensionHelper::getCrlReason (
        const Extensions_t* extns,
        uint32_t& crlReason
)
{
    int ret = RET_OK;
    SmartBA sba_encoded;

    DO(Util::extnValueFromExtensions(extns, OID_X509v3_CRLReason, NULL, &sba_encoded));

    DO(Util::decodeEnumerated(sba_encoded.get(), &crlReason));

cleanup:
    return ret;
}

int ExtensionHelper::getCrlUris (
        const Extensions_t* extns,
        const char* oidExtnId,
        vector<string>& uris
)
{
    int ret = RET_OK;
    SmartBA sba_extnvalue;

    DO(Util::extnValueFromExtensions(extns, oidExtnId, nullptr, &sba_extnvalue));

    DO(ExtensionHelper::decodeDistributionPoints(sba_extnvalue.get(), uris));

cleanup:
    return ret;
}

int ExtensionHelper::getDeltaCrlIndicator (
        const Extensions_t* extns,
        ByteArray** baDeltaCrlIndicator
)
{
    int ret = RET_OK;
    CRLNumber_t* deltacrl_indicator = nullptr;
    SmartBA sba_encoded;
    bool critical = false;

    CHECK_PARAM(baDeltaCrlIndicator);

    DO(Util::extnValueFromExtensions(extns, OID_X509v3_DeltaCRLIndicator, &critical, &sba_encoded));

    CHECK_NOT_NULL(deltacrl_indicator = (CRLNumber_t*)asn_decode_ba_with_alloc(get_CRLNumber_desc(), sba_encoded.get()));
    DO(asn_INTEGER2ba(deltacrl_indicator, baDeltaCrlIndicator));

    ret = (critical) ? RET_OK : RET_UAPKI_EXTENSION_NOT_SET_CRITICAL;

cleanup:
    asn_free(get_CRLNumber_desc(), deltacrl_indicator);
    return ret;
}

int ExtensionHelper::getKeyUsage (
        const Extensions_t* extns,
        uint32_t& keyUsage
)
{
    int ret = RET_OK;
    KeyUsage_t* key_usage = nullptr;
    SmartBA sba_encoded;
    bool critical = false;

    keyUsage = 0;
    DO(Util::extnValueFromExtensions(extns, OID_X509v3_KeyUsage, &critical, &sba_encoded));

    CHECK_NOT_NULL(key_usage = (KeyUsage_t*)asn_decode_ba_with_alloc(get_KeyUsage_desc(), sba_encoded.get()));

    for (int bit_num = 0; bit_num < 9; bit_num++) {
        int bit_flag = 0;
        DO(asn_BITSTRING_get_bit(key_usage, bit_num, &bit_flag));
        if (bit_flag) {
            keyUsage |= (0x00000001 << bit_num);
        }
    }

cleanup:
    asn_free(get_KeyUsage_desc(), key_usage);
    return ret;
}

int ExtensionHelper::getOcspNonce (
        const Extensions_t* extns,
        ByteArray** baNonce
)
{
    int ret = RET_OK;
    SmartBA sba_encoded;

    CHECK_PARAM(baNonce);

    ret = Util::extnValueFromExtensions(extns, OID_PKIX_OcspNonce, nullptr, &sba_encoded);
    if (ret == RET_OK) {
        DO(Util::decodeOctetString(sba_encoded.get(), baNonce));
    }

cleanup:
    return ret;
}

int ExtensionHelper::getOcspUris (
        const Extensions_t* extns,
        vector<string>& uris
)
{
    int ret = RET_OK;
    SmartBA sba_extnvalue;

    DO(Util::extnValueFromExtensions(extns, OID_PKIX_AuthorityInfoAccess, nullptr, &sba_extnvalue));

    DO(ExtensionHelper::decodeAccessDescriptions(sba_extnvalue.get(), OID_PKIX_OCSP, uris));

cleanup:
    return ret;
}

int ExtensionHelper::getSubjectDirectoryAttributes (
        const Extensions_t* extns,
        const char* oidType,
        ByteArray** baEncoded
)
{
    int ret = RET_OK;
    SubjectDirectoryAttributes_t* subjectdir_attrs = nullptr;
    SmartBA sba_encoded;

    CHECK_PARAM(oidType);
    CHECK_PARAM(baEncoded);

    ret = Util::extnValueFromExtensions(extns, OID_X509v3_SubjectDirectoryAttributes, nullptr, &sba_encoded);
    if (ret == RET_OK) {
        CHECK_NOT_NULL(subjectdir_attrs = (SubjectDirectoryAttributes_t*)asn_decode_ba_with_alloc(get_SubjectDirectoryAttributes_desc(), sba_encoded.get()));
        DO(Util::attrValueFromAttributes((const Attributes_t*)subjectdir_attrs, oidType, baEncoded));
    }

cleanup:
    asn_free(get_SubjectDirectoryAttributes_desc(), subjectdir_attrs);
    return ret;
}

int ExtensionHelper::getSubjectKeyId (
        const Extensions_t* extns,
        ByteArray** baKeyId
)
{
    int ret = RET_OK;
    SubjectKeyIdentifier_t* subject_keyid = nullptr;
    SmartBA sba_encoded;

    CHECK_PARAM(baKeyId);

    DO(Util::extnValueFromExtensions(extns, OID_X509v3_SubjectKeyIdentifier, nullptr, &sba_encoded));

    CHECK_NOT_NULL(subject_keyid = (SubjectKeyIdentifier_t*)asn_decode_ba_with_alloc(get_SubjectKeyIdentifier_desc(), sba_encoded.get()));
    DO(asn_OCTSTRING2ba(subject_keyid, baKeyId));

cleanup:
    asn_free(get_SubjectKeyIdentifier_desc(), subject_keyid);
    return ret;
}

int ExtensionHelper::getTspUris (
        const Extensions_t* extns,
        vector<string>& uris
)
{
    int ret = RET_OK;
    SmartBA sba_extnvalue;

    DO(Util::extnValueFromExtensions(extns, OID_PKIX_SubjectInfoAccess, nullptr, &sba_extnvalue));

    DO(ExtensionHelper::decodeAccessDescriptions(sba_extnvalue.get(), OID_PKIX_TimeStamping, uris));

cleanup:
    return ret;
}


}   //  end namespace UapkiNS
