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

#include "extnreq-helper.h"
#include "cm-errors.h"
#include "dstu-ns.h"
#include "macros-internal.h"
#include "oid-utils.h"
#include "uapkif.h"
#include "uapki-ns-util.h"


using namespace std;
using namespace UapkiNS;


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
    #define DEBUG_OUTCON(expression) expression
#endif


const uint8_t ExtnRequestHelper::DER_EXTNVALUE_QCSTATEMENTS_DEFAULT[22] = {
    0x30, 0x14,
          0x30, 0x08, 0x06, 0x06, 0x04, 0x00, 0x8E, 0x46, 0x01, 0x01,   //  '0.4.0.1862.1.1' etsiQcsCompliance
          0x30, 0x08, 0x06, 0x06, 0x04, 0x00, 0x8E, 0x46, 0x01, 0x04    //  '0.4.0.1862.1.4' etsiQcsQcSSCD
};
const char* ExtnRequestHelper::OID_PEN_SIS_PKATTESTATE = "1.3.6.1.4.1.54069.3.1.1.1";


static int parse_extendedkeyusage (
        const Extension_t* extn,
        vector<string>& keyPurposeIds
)
{
    int ret = RET_OK;
    ExtendedKeyUsage_t* ext_keyusage = (ExtendedKeyUsage_t*)asn_decode_with_alloc(get_ExtendedKeyUsage_desc(), extn->extnValue.buf, extn->extnValue.size);

    if (!ext_keyusage) return RET_CM_INVALID_PARAMETER;

    for (int i = 0; i < ext_keyusage->list.count; i++) {
        string s_keypurposeid;
        DO(Util::oidFromAsn1(ext_keyusage->list.array[i], s_keypurposeid));
        keyPurposeIds.push_back(s_keypurposeid);
    }

cleanup:
    asn_free(get_ExtendedKeyUsage_desc(), ext_keyusage);
    return ret;
}   //  parse_extendedkeyusage



ExtnRequestHelper::ExtnRequestHelper (void)
{
    DEBUG_OUTCON(puts("ExtnRequestHelper::ExtnRequestHelper()"));
}

ExtnRequestHelper::~ExtnRequestHelper (void)
{
    DEBUG_OUTCON(puts("ExtnRequestHelper::~ExtnRequestHelper()"));
}

int ExtnRequestHelper::addQcStatementsDefault (void)
{
    SmartBA sba_extnvalue;
    if (!sba_extnvalue.set(ba_alloc_from_uint8(DER_EXTNVALUE_QCSTATEMENTS_DEFAULT, sizeof(DER_EXTNVALUE_QCSTATEMENTS_DEFAULT)))) return RET_CM_GENERAL_ERROR;
    return encodeQcStatements(sba_extnvalue.get(), false);
}

size_t ExtnRequestHelper::build (void) {
    size_t cnt = 0, idx = 0;
    cnt += m_EncodedExtnSubjectKeyId.get() ? 1 : 0;
    cnt += m_EncodedExtnExtKeyUsage.get() ? 1 : 0;
    cnt += m_EncodedExtnQcStatements.get() ? 1 : 0;
    cnt += m_EncodedExtnPkAttestate.get() ? 1 : 0;
    cnt += m_EncodedCustomExtns.size();
    if (cnt == 0) return 0;

    m_EncodedExtns.resize(cnt);

    if (m_EncodedExtnSubjectKeyId.get()) {
        m_EncodedExtns[idx++] = m_EncodedExtnSubjectKeyId.pop();
    }
    if (m_EncodedExtnExtKeyUsage.get()) {
        m_EncodedExtns[idx++] = m_EncodedExtnExtKeyUsage.pop();
    }
    if (m_EncodedExtnQcStatements.get()) {
        m_EncodedExtns[idx++] = m_EncodedExtnQcStatements.pop();
    }
    if (m_EncodedExtnPkAttestate.get()) {
        m_EncodedExtns[idx++] = m_EncodedExtnPkAttestate.pop();
    }
    for (size_t i = 0; i < m_EncodedCustomExtns.size(); i++) {
        m_EncodedExtns[idx++] = m_EncodedCustomExtns[i];
        m_EncodedCustomExtns[i] = nullptr;
    }

    return cnt;
}

int ExtnRequestHelper::encodeExtKeyUsage (
        const char* keyPurposeId,
        const bool critical
)
{
    if (keyPurposeId) {
        m_KeyPurposeIds.push_back(string(keyPurposeId));
    }

    if (m_KeyPurposeIds.empty()) return RET_OK;

    int ret = RET_OK;
    ExtendedKeyUsage_t* ext_keyusage = nullptr;
    KeyPurposeId_t* key_purposeid = nullptr;
    SmartBA sba_extnvalue;

    ASN_ALLOC_TYPE(ext_keyusage, ExtendedKeyUsage_t);

    for (const auto& it : m_KeyPurposeIds) {
        ASN_ALLOC_TYPE(key_purposeid, KeyPurposeId_t);
        DO(Util::oidToAsn1(key_purposeid, it));
        DO(ASN_SEQUENCE_ADD(&ext_keyusage->list, key_purposeid));
        key_purposeid = nullptr;
    }

    DO(asn_encode_ba(get_ExtendedKeyUsage_desc(), ext_keyusage, &sba_extnvalue));

    DO(Util::encodeExtension(
        string(OID_X509v3_ExtendedKeyUsage),
        critical,
        sba_extnvalue.get(),
        &m_EncodedExtnExtKeyUsage
    ));

cleanup:
    asn_free(get_ExtendedKeyUsage_desc(), ext_keyusage);
    asn_free(get_KeyPurposeId_desc(), key_purposeid);
    return ret;
}

int ExtnRequestHelper::encodePkAttestate (
        const ByteArray* baPkAttestate,
        const bool critical
)
{
    int ret = RET_OK;

    DO(Util::encodeExtension(
        string(OID_PEN_SIS_PKATTESTATE),
        critical,
        baPkAttestate,
        &m_EncodedExtnPkAttestate
    ));

cleanup:
    return ret;
}

int ExtnRequestHelper::encodeQcStatements (
        const ByteArray* baExtnValue,
        const bool critical
)
{
    int ret = RET_OK;

    DO(Util::encodeExtension (
        string(OID_PKIX_QcStatements),
        critical,
        baExtnValue,
        &m_EncodedExtnQcStatements
    ));

cleanup:
    return ret;
}

int ExtnRequestHelper::encodeSubjectKeyId (
        const ByteArray* baKeyId,
        const bool critical
)
{
    int ret = RET_OK;
    SmartBA sba_extnvalue;

    DO(Util::encodeOctetString(baKeyId, &sba_extnvalue));

    DO(Util::encodeExtension(
        string(OID_X509v3_SubjectKeyIdentifier),
        critical,
        sba_extnvalue.get(),
        &m_EncodedExtnSubjectKeyId
    ));

cleanup:
    return ret;
}

bool ExtnRequestHelper::findKeyPurposeId (
        const char* keyPurposeId
)
{
    if (keyPurposeId) {
        const string s_oid = string(keyPurposeId);
        for (const auto& it : m_KeyPurposeIds) {
            if (it == s_oid) return true;
        }
    }
    return false;
}

void ExtnRequestHelper::pushCustomExtns (
        VectorBA& encodedCustomExtns
)
{
    if (!encodedCustomExtns.empty()) {
        m_EncodedCustomExtns.resize(encodedCustomExtns.size());
        for (size_t i = 0; i < m_EncodedCustomExtns.size(); i++) {
            m_EncodedCustomExtns[i] = encodedCustomExtns[i];
            encodedCustomExtns[i] = nullptr;
        }
        encodedCustomExtns.clear();
    }
}

void ExtnRequestHelper::setKeyPurposeIds (
        const vector<string>& keyPurposeIds
)
{
    m_KeyPurposeIds = keyPurposeIds;
}

int ExtnRequestHelper::parse (
        const ByteArray* baEncoded
)
{
    if (ba_get_len(baEncoded) == 0) return RET_OK;

    int ret = RET_OK;
    Extensions_t* extns = (Extensions_t*)asn_decode_ba_with_alloc(get_Extensions_desc(), baEncoded);
    if (!extns) return RET_CM_INVALID_PARAMETER;

    m_EncodedCustomExtns.reserve(extns->list.count);
    for (int i = 0; i < extns->list.count; i++) {
        const Extension_t* extn = extns->list.array[i];
        if (
            OID_is_equal_oid(&extn->extnID, OID_X509v3_SubjectKeyIdentifier) ||
            OID_is_equal_oid(&extn->extnID, OID_PKIX_QcStatements)
        ) {
            continue;
        } else if (OID_is_equal_oid(&extn->extnID, OID_X509v3_ExtendedKeyUsage)) {
            DO(parse_extendedkeyusage(extn, m_KeyPurposeIds));
        } else {
            SmartBA sba_encodedextn;
            DO(asn_encode_ba(get_Extension_desc(), extn, &sba_encodedextn));
            m_EncodedCustomExtns.push_back(sba_encodedextn.pop());
        }
    }

cleanup:
    asn_free(get_Extensions_desc(), extns);
    return ret;
}
