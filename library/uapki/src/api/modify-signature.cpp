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

#define FILE_MARKER "uapki/api/modify-signature.cpp"


#include "api-json-internal.h"
#include "cer-item.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include "signeddata-helper.h"
#include "store-json.h"
#include "uapki-errors.h"
#include "uapki-ns.h"


using namespace std;
using namespace UapkiNS;


struct Options {
    bool returnContent;
    bool returnCerts;
    bool returnCrls;
    bool returnEncodedSignerInfo;
};  //  end struct AddParams

struct RemoveParams {
    bool content;
    int  signIndex;
    bool certs;
    bool crls;
};  //  end struct RemoveParams


static int result_signinfo_to_json (
        JSON_Object* joSignInfo,
        Pkcs7::SignedDataParser::SignerInfo& signerInfo
)
{
    int ret = RET_OK;
    SmartBA sba_issuer, sba_serial, sba_keyid;

    DO(Cert::parseSID(signerInfo.getSidEncoded(), &sba_issuer, &sba_serial, &sba_keyid));
    DO_JSON(ParsonHelper::jsonObjectSetUint32(joSignInfo, "version", signerInfo.getVersion()));

    switch (signerInfo.getSidType()) {
    case Pkcs7::SignerIdentifierType::ISSUER_AND_SN:
        DO(json_object_set_hex(joSignInfo, "serialNumber", sba_serial.get()));
        DO(json_object_set_base64(joSignInfo, "issuerBytes", sba_issuer.get()));
        json_object_set_value(joSignInfo, "issuer", json_value_init_object());
        DO(nameToJson(json_object_get_object(joSignInfo, "issuer"), sba_issuer.get()));
        break;
    case Pkcs7::SignerIdentifierType::SUBJECT_KEYID:
        DO(json_object_set_hex(joSignInfo, "keyId", sba_keyid.get()));
        break;
    default:
        break;
    }

    DO_JSON(json_object_set_string(joSignInfo, "signAlgo", signerInfo.getSignatureAlgorithm().algorithm.c_str()));
    DO_JSON(json_object_set_string(joSignInfo, "digestAlgo", signerInfo.getDigestAlgorithm().algorithm.c_str()));
    DO_JSON(json_object_set_string(joSignInfo, "contentType", signerInfo.getContentType().c_str()));
    DO(json_object_set_base64(joSignInfo, "messageDigest", signerInfo.getMessageDigest()));

cleanup:
    return ret;
}   //  result_signinfo_to_json


int uapki_modify_signature (JSON_Object* joParams, JSON_Object* joResult)
{
    int ret = RET_OK;
    Pkcs7::SignedDataParser sdata_parser, sdata2_parser;
    vector<Pkcs7::SignedDataParser::SignerInfo> parsed_signerinfos;
    Pkcs7::SignedDataParser::SignerInfo parsed2_signerinfo;
    SignerInfo_t* signer2_info = nullptr;
    VectorBA vba_addcerts, vba_addcrls, vba_encodedsignerinfos;
    SmartBA sba_bytes, sba_content, sba_encodedaddsign;
    Options options = Options{ false, false, false, false };
    RemoveParams remove_params = RemoveParams{ false, -1, false, false };
    JSON_Object* jo_add = json_object_get_object(joParams, "add");
    JSON_Object* jo_options = json_object_get_object(joParams, "options");
    JSON_Object* jo_remove = json_object_get_object(joParams, "remove");
    JSON_Object* jo_content = nullptr;
    uint32_t signerinfo_ver = 1;
    bool need_rebuild = false;

    if (!sba_bytes.set(json_object_get_base64(joParams, "bytes"))) {
        SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
    }

    // section =remove=
    remove_params.content = ParsonHelper::jsonObjectGetBoolean(jo_remove, "content", false);
    remove_params.signIndex = ParsonHelper::jsonObjectGetInt32(jo_remove, "signIndex", -1);
    remove_params.certs = ParsonHelper::jsonObjectGetBoolean(jo_remove, "certificates", false);
    remove_params.crls = ParsonHelper::jsonObjectGetBoolean(jo_remove, "crls", false);
    need_rebuild = (remove_params.content || (remove_params.signIndex >= 0) || remove_params.certs || remove_params.crls);

    // section =add=
    if (ParsonHelper::jsonObjectHasValue(jo_add, "bytes", JSONString)) {
        SmartBA sba_addbytes;
        size_t addsign_idx = 0;
        if (!sba_addbytes.set(json_object_get_base64(jo_add, "bytes"))) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
        if (!ParsonHelper::jsonObjectGetBoolean(jo_add, "isSignerInfo", false)) {
            DO(sdata2_parser.parse(sba_addbytes.get()));
            addsign_idx = ParsonHelper::jsonObjectGetUint32(jo_add, "signIndex", 0);
            if (addsign_idx >= sdata2_parser.getCountSignerInfos()) {
                SET_ERROR(RET_UAPKI_INDEX_OUT_OF_RANGE);
            }

            DO(sdata2_parser.parseSignerInfo(addsign_idx, parsed2_signerinfo));
            DO(sdata2_parser.encodeSignerInfo(addsign_idx, &sba_encodedaddsign));
        }
        else {
            signer2_info = (SignerInfo_t*)asn_decode_ba_with_alloc(get_SignerInfo_desc(), sba_addbytes.get());
            if (!signer2_info) {
                SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
            }
            DO(parsed2_signerinfo.parse(signer2_info));
            sba_encodedaddsign.set(sba_addbytes.pop());
        }
        signerinfo_ver = parsed2_signerinfo.getVersion();
        need_rebuild = true;
    }
    if (ParsonHelper::jsonObjectHasValue(jo_add, "content", JSONString)) {
        if (!sba_content.set(json_object_get_base64(jo_add, "content"))) {
            SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
        }
        need_rebuild = true;
    }
    if (ParsonHelper::jsonObjectHasValue(jo_add, "certificates", JSONArray)) {
        JSON_Array* ja_certs = json_object_get_array(jo_add, "certificates");
        vba_addcerts.resize(json_array_get_count(ja_certs));
        for (size_t i = 0; i < vba_addcerts.size(); i++) {
            vba_addcerts[i] = json_array_get_base64(ja_certs, i);
            if (!vba_addcerts[i]) {
                SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
            }
        }
        need_rebuild |= !vba_addcerts.empty();
    }
    if (ParsonHelper::jsonObjectHasValue(jo_add, "crls", JSONArray)) {
        JSON_Array* ja_crls = json_object_get_array(jo_add, "crls");
        vba_addcrls.resize(json_array_get_count(ja_crls));
        for (size_t i = 0; i < vba_addcrls.size(); i++) {
            vba_addcrls[i] = json_array_get_base64(ja_crls, i);
            if (!vba_addcrls[i]) {
                SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
            }
        }
        need_rebuild |= !vba_addcrls.empty();
    }

    // section =options=
    options.returnContent = ParsonHelper::jsonObjectGetBoolean(jo_options, "returnContent", false);
    options.returnCerts = ParsonHelper::jsonObjectGetBoolean(jo_options, "returnCerts", false);
    options.returnCrls = ParsonHelper::jsonObjectGetBoolean(jo_options, "returnCrls", false);
    options.returnEncodedSignerInfo = ParsonHelper::jsonObjectGetBoolean(jo_options, "returnEncodedSignerInfo", false);

    // parse PKCS7-signedData (CAdES/CMS)
    DO(sdata_parser.parse(sba_bytes.get()));
    if (sdata_parser.getCountSignerInfos() > 0) {
        parsed_signerinfos.resize(sdata_parser.getCountSignerInfos());
        vba_encodedsignerinfos.resize(sdata_parser.getCountSignerInfos());
        for (size_t i = 0; i < parsed_signerinfos.size(); i++) {
            DO(sdata_parser.parseSignerInfo(i, parsed_signerinfos[i]));
            DO(sdata_parser.encodeSignerInfo(i, &vba_encodedsignerinfos[i]));
        }
    }

    // out info
    DO_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "version", sdata_parser.getVersion()));
    if (!sdata_parser.getDigestAlgorithms().empty()) {
        json_object_set_value(joResult, "digestAlgorithms", json_value_init_array());
        JSON_Array* ja_digestalgos = json_object_get_array(joResult, "digestAlgorithms");
        for (const auto& it : sdata_parser.getDigestAlgorithms()) {
            DO(json_array_append_string(ja_digestalgos, it.c_str()));
        }
    }
    json_object_set_value(joResult, "content", json_value_init_object());
    jo_content = json_object_get_object(joResult, "content");
    DO_JSON(json_object_set_string(jo_content, "type", sdata_parser.getEncapContentInfo().contentType.c_str()));
    if (!parsed_signerinfos.empty()) {
        DO_JSON(json_object_set_value(joResult, "signatureInfos", json_value_init_array()));
        JSON_Array* ja_signinfos = json_object_get_array(joResult, "signatureInfos");
        for (size_t i = 0; i < parsed_signerinfos.size(); i++) {
            JSON_Object* jo_signinfo = json_array_get_object(ja_signinfos, i);
            DO_JSON(json_array_append_value(ja_signinfos, json_value_init_object()));
            jo_signinfo = json_array_get_object(ja_signinfos, i);
            DO(result_signinfo_to_json(jo_signinfo, parsed_signerinfos[i]));
            if (options.returnEncodedSignerInfo) {
                DO(json_object_set_base64(jo_signinfo, "bytes", vba_encodedsignerinfos[i]));
            }
        }
    }

    // out optional info
    if (options.returnContent && (sdata_parser.getEncapContentInfo().baEncapContent)) {
        DO(json_object_set_base64(jo_content, "bytes", sdata_parser.getEncapContentInfo().baEncapContent));
    }
    if (options.returnCerts) {
        json_object_set_value(joResult, "certificates", json_value_init_array());
        JSON_Array* ja_certs = json_object_get_array(joResult, "certificates");
        for (const auto& it : sdata_parser.getCerts()) {
            DO(json_array_append_base64(ja_certs, it));
        }
    }
    if (options.returnCrls) {
        json_object_set_value(joResult, "crls", json_value_init_array());
        JSON_Array* ja_crls = json_object_get_array(joResult, "crls");
        for (const auto& it : sdata_parser.getCrls()) {
            DO(json_array_append_base64(ja_crls, it));
        }
    }

    if (need_rebuild) {
        Pkcs7::SignedDataBuilder sdata_builder;
        const ByteArray* refba_content = (remove_params.content) ? nullptr : sdata_parser.getEncapContentInfo().baEncapContent;
        if (!sba_content.empty()) {
            HashAlg hash_alg;
            SmartBA sba_digestmessage;
            if (parsed_signerinfos.empty()) {
                //  We will not add a signature to the cert-bundle
                SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
            }

            hash_alg = hash_from_oid(parsed_signerinfos[0].getDigestAlgorithm().algorithm.c_str());
            if (hash_alg == HashAlg::HASH_ALG_UNDEFINED) {
                SET_ERROR(RET_UAPKI_UNSUPPORTED_ALG);
            }
            DO(::hash(hash_alg, sba_content.get(), &sba_digestmessage));
            if (ba_cmp(parsed_signerinfos[0].getMessageDigest(), sba_digestmessage.get()) != 0) {
                SET_ERROR(RET_UAPKI_INVALID_DIGEST);
            }

            refba_content = sba_content.get();
        }

        if (remove_params.signIndex >= (int)sdata_parser.getCountSignerInfos()) {
            SET_ERROR(RET_UAPKI_INDEX_OUT_OF_RANGE);
        }

        DO(sdata_builder.init());

        if (!remove_params.certs) {
            for (const auto& it : sdata_parser.getCerts()) {
                DO(sdata_builder.addCertificate(it));
            }
        }
        for (const auto& it : vba_addcerts) {
            DO(sdata_builder.addCertificate(it));
        }
        if (!remove_params.crls) {
            for (const auto& it : sdata_parser.getCrls()) {
                DO(sdata_builder.addCrl(it));
            }
        }
        for (const auto& it : vba_addcrls) {
            DO(sdata_builder.addCrl(it));
        }
        for (size_t i = 0; i < vba_encodedsignerinfos.size(); i++) {
            if (remove_params.signIndex != (int)i) {
                DO(sdata_builder.addSignerInfo());
                Pkcs7::SignedDataBuilder::SignerInfo* signer_info = sdata_builder.getSignerInfo(sdata_builder.getCountSignerInfos() - 1);
                DO(signer_info->fillFromEncoded(vba_encodedsignerinfos[i]));
                if (parsed_signerinfos[i].getVersion() > signerinfo_ver) {
                    signerinfo_ver = parsed_signerinfos[i].getVersion();
                }
            }
        }

        if (!sba_encodedaddsign.empty()) {
            if (parsed_signerinfos.empty()) {
                //  We will not add a signature to the cert-bundle
                SET_ERROR(RET_UAPKI_INVALID_PARAMETER);
            }

            if (parsed2_signerinfo.getContentType() != sdata_parser.getEncapContentInfo().contentType) {
                SET_ERROR(RET_UAPKI_INVALID_CONTENT_TYPE);
            }
            for (const auto& it : parsed_signerinfos) {
                if (parsed2_signerinfo.getContentType() != it.getContentType()) {
                    SET_ERROR(RET_UAPKI_INVALID_CONTENT_TYPE);
                }
            }

            bool equal_digest = false;
            for (const auto& it : parsed_signerinfos) {
                equal_digest = (parsed2_signerinfo.getDigestAlgorithm().algorithm == it.getDigestAlgorithm().algorithm) &&
                    (ba_cmp(parsed2_signerinfo.getMessageDigest(), it.getMessageDigest()) == 0);
                if (equal_digest) break;
            }
            if (!equal_digest) {
                SET_ERROR(RET_UAPKI_INVALID_DIGEST);
            }

            DO(sdata_builder.addSignerInfo());
            Pkcs7::SignedDataBuilder::SignerInfo* signer_info = sdata_builder.getSignerInfo(sdata_builder.getCountSignerInfos() - 1);
            DO(signer_info->fillFromEncoded(sba_encodedaddsign.get()));
        }

        DO(sdata_builder.setVersion(signerinfo_ver));
        if (sdata_builder.getCountSignerInfos() == 0) {
            //  Cert-bundle must be not contain
            refba_content = nullptr;
        }
        DO(sdata_builder.setEncapContentInfo(sdata_parser.getEncapContentInfo().contentType, refba_content));

        DO(sdata_builder.encode());

        DO(json_object_set_base64(joResult, "bytes", sdata_builder.getEncoded()));
    }

cleanup:
    asn_free(get_SignerInfo_desc(), signer2_info);
    return ret;
}
