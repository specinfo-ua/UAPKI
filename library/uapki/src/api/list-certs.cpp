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

#define FILE_MARKER "uapki/api/list-certs.cpp"

#include "api-json-internal.h"
#include "extension-helper-json.h"
#include "global-objects.h"
#include "parson-ba-utils.h"
#include "parson-helper.h"
#include "oid-utils.h"
#include "store-json.h"
#include "uapki-errors.h"
#include "uapki-ns-util.h"
#include "time-util.h"


using namespace std;
using namespace UapkiNS;


static int basicconstraints_to_json (
        JSON_Object* joResult,
        const ByteArray* baEncoded
)
{
    int ret = RET_OK;
    BasicConstraints_t* basic_constraints = (BasicConstraints_t*)asn_decode_ba_with_alloc(get_BasicConstraints_desc(), baEncoded);
    if (!basic_constraints) return RET_UAPKI_INVALID_STRUCT;

    if (basic_constraints->cA) {
        const bool is_ca = (basic_constraints->cA != 0);
        DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "isCa", is_ca));
    }

cleanup:
    asn_free(get_BasicConstraints_desc(), basic_constraints);
    return ret;
}   //  basicconstraints_to_json

static int certstatusinfo_to_json (
        JSON_Object* joResult,
        const char* keyName,
        const Cert::CertStatusInfo& certStatusInfo
)
{
    if (certStatusInfo.status == UapkiNS::CertStatus::UNDEFINED) return RET_OK;

    int ret = RET_OK;
    JSON_Object* jo_result = nullptr;

    DO_JSON(json_object_set_value(joResult, keyName, json_value_init_object()));
    jo_result = json_object_get_object(joResult, keyName);

    DO_JSON(json_object_set_string(jo_result, "status", Crl::certStatusToStr(certStatusInfo.status)));
    DO_JSON(json_object_set_string(jo_result, "validTime", TimeUtil::mtimeToFtime(certStatusInfo.validTime).c_str()));

cleanup:
    return ret;
}   //  certstatusinfo_to_json

static int extendedkeyusage_to_json (
        JSON_Object* joResult,
        const ByteArray* baEncoded
)
{
    int ret = RET_OK;
    ExtendedKeyUsage_t* ext_keyusage = (ExtendedKeyUsage_t*)asn_decode_ba_with_alloc(get_ExtendedKeyUsage_desc(), baEncoded);
    if (!ext_keyusage) return RET_UAPKI_INVALID_STRUCT;

    (void)json_object_set_value(joResult, "extKeyUsage", json_value_init_array());
    JSON_Array* ja_keypurposeids = json_object_get_array(joResult, "extKeyUsage");

    for (int i = 0; i < ext_keyusage->list.count; i++) {
        const KeyPurposeId_t* key_purposeid = ext_keyusage->list.array[i];
        string s_keypurposeid;

        DO(Util::oidFromAsn1(key_purposeid, s_keypurposeid));
        DO_JSON(json_array_append_string(ja_keypurposeids, s_keypurposeid.c_str()));

        if (s_keypurposeid == string(OID_PKIX_KpOcspSigning)) {
            DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "isOcsp", true));
        }
        if (s_keypurposeid == string(OID_PKIX_KpTspSigning)) {
            DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "isTsp", true));
        }
        if (s_keypurposeid == string(OID_IIT_KEYPURPOSE_CMP_SIGNING)) {
            DO_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "isCmp", true));
        }
    }

cleanup:
    asn_free(get_ExtendedKeyUsage_desc(), ext_keyusage);
    return ret;
}   //  extendedkeyusage_to_json

static int extensions_to_json (
        JSON_Object* joResult,
        const Extensions_t* extns
)
{
    int ret = RET_OK;

    if (!extns) return RET_UAPKI_INVALID_STRUCT;

    for (int i = 0; i < extns->list.count; i++) {
        const Extension_t* extn = extns->list.array[i];
        string s_extnid;

        DO(Util::oidFromAsn1(&extn->extnID, s_extnid));

        if (oid_is_equal(s_extnid.c_str(), OID_X509v3_BasicConstraints)) {
            SmartBA sba_value;
            DO(asn_OCTSTRING2ba(&extn->extnValue, &sba_value));
            DO(basicconstraints_to_json(joResult, sba_value.get()));
        }
        else if (oid_is_equal(s_extnid.c_str(), OID_X509v3_KeyUsage)) {
            SmartBA sba_value;
            DO(asn_OCTSTRING2ba(&extn->extnValue, &sba_value));
            DO_JSON(json_object_set_value(joResult, "keyUsage", json_value_init_object()));
            DO(ExtensionHelper::DecodeToJsonObject::keyUsage(sba_value.get(), json_object_get_object(joResult, "keyUsage")));
        }
        else if (oid_is_equal(s_extnid.c_str(), OID_X509v3_ExtendedKeyUsage)) {
            SmartBA sba_value;
            DO(asn_OCTSTRING2ba(&extn->extnValue, &sba_value));
            DO(extendedkeyusage_to_json(joResult, sba_value.get()));
        }
    }

cleanup:
    return ret;
}   //  extensions_to_json

static int info_to_json (
        JSON_Object* joResult,
        const Cert::CerItem* cerItem
)
{
    int ret = RET_OK;
    const TBSCertificate_t& tbs_cert = cerItem->getCert()->tbsCertificate;

    DO(json_object_set_base64(joResult, "certId", cerItem->getCertId()));

    DO(json_object_set_hex(joResult, "serialNumber", cerItem->getSerialNumber()));
    DO_JSON(json_object_set_value(joResult, "issuer", json_value_init_object()));
    DO(nameToJson(json_object_get_object(joResult, "issuer"), tbs_cert.issuer));
    DO_JSON(json_object_set_value(joResult, "validity", json_value_init_object()));
    DO(validityToJson(joResult, cerItem));
    DO_JSON(json_object_set_value(joResult, "subject", json_value_init_object()));
    DO(nameToJson(json_object_get_object(joResult, "subject"), tbs_cert.subject));
    DO_JSON(json_object_set_string(joResult, "keyAlgo", cerItem->getKeyAlgo().c_str()));
    DO(json_object_set_hex(joResult, "subjectKeyIdentifier", cerItem->getKeyId()));
    DO(json_object_set_hex(joResult, "authorityKeyIdentifier", cerItem->getAuthorityKeyId()));
    DO(extensions_to_json(joResult, tbs_cert.extensions));

    DO(certstatusinfo_to_json(joResult, "statusByCRL", cerItem->getCertStatusByCrl()));
    DO(certstatusinfo_to_json(joResult, "statusByOCSP", cerItem->getCertStatusByOcsp()));

cleanup:
    return ret;
}   //  info_to_json


int uapki_list_certs (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    LibraryConfig* lib_config = get_config();
    Cert::CerStore* cer_store = get_cerstore();
    const bool from_storage = ParsonHelper::jsonObjectGetBoolean(joParams, "storage", false);
    const bool show_certinfos = ParsonHelper::jsonObjectGetBoolean(joParams, "showCertInfos", false);
    Pagination pagination;

    if (!lib_config || !cer_store) return RET_UAPKI_GENERAL_ERROR;
    if (!lib_config->isInitialized()) return RET_UAPKI_NOT_INITIALIZED;

    if (!pagination.parseParams(joParams)) return RET_UAPKI_INVALID_PARAMETER;

    (void)json_object_set_value(joResult, "certIds", json_value_init_array());
    JSON_Array* ja_certids = json_object_get_array(joResult, "certIds");
    JSON_Array* ja_certinfos = nullptr;
    if (show_certinfos) {
        (void)json_object_set_value(joResult, "certInfos", json_value_init_array());
        ja_certinfos = json_object_get_array(joResult, "certInfos");
    }

    if (!from_storage) {
        const vector<Cert::CerItem*> cer_items = cer_store->getCerItems();
        pagination.count = cer_items.size();
        pagination.calcParams();
        for (size_t idx = pagination.offset; idx < pagination.offsetLast; idx++) {
            Cert::CerItem* cer_item = cer_items[idx];
            DO(json_array_append_base64(ja_certids, cer_item->getCertId()));
            if (show_certinfos) {
                DO_JSON(json_array_append_value(ja_certinfos, json_value_init_object()));
                JSON_Object* jo_certinfo = json_array_get_object(ja_certinfos, idx);
                DO(info_to_json(jo_certinfo, cer_item));
            }
        }
    }
    else {
        UapkiNS::VectorBA vba_certs;
        vector<Cert::CerItem*> cer_items;

        CmStorageProxy* storage = CmProviders::openedStorage();
        if (!storage) return RET_UAPKI_STORAGE_NOT_OPEN;

        ret = storage->sessionGetCertificates(vba_certs);
        if (ret == RET_UAPKI_NOT_SUPPORTED) {
            DO(storage->keyGetCertificates(vba_certs));
        }

        for (const auto& it : vba_certs) {
            Cert::CerItem* cer_item = nullptr;
            ret = cer_store->getCertByEncoded(it, &cer_item);
            if (ret == RET_OK) {
                cer_items.push_back(cer_item);
                pagination.count++;
            }
        }

        pagination.calcParams();
        for (size_t idx = pagination.offset; idx < pagination.offsetLast; idx++) {
            Cert::CerItem* cer_item = cer_items[idx];
            DO(json_array_append_base64(ja_certids, cer_item->getCertId()));
            if (show_certinfos) {
                DO_JSON(json_array_append_value(ja_certinfos, json_value_init_object()));
                JSON_Object* jo_certinfo = json_array_get_object(ja_certinfos, idx);
                DO(info_to_json(jo_certinfo, cer_item));
            }
        }
    }

    DO(pagination.setResult(joResult));

cleanup:
    return ret;
}
