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

#define FILE_MARKER "cm-cryptoki/cm-cryptoki-json.cpp"

#include <string.h>
#include "cm-cryptoki.h"
#include "oid-utils.h"
#include "parson-ba-utils.h"
#include "parson-helper.h"
#include "uapki-ns.h"


#define CHECK_CM_JSON(func)                 \
    {                                       \
        if (!(func)) {                      \
            cm_err = RET_CM_JSON_FAILURE;   \
            goto cleanup;                   \
        }                                   \
    }

#define DO_CM_JSON(func)                    \
    {                                       \
        if ((func) != JSONSuccess) {        \
            cm_err = RET_CM_JSON_FAILURE;   \
            goto cleanup;                   \
        }                                   \
    }


#define CM_PKCS11_LIBVERSION "1.0.12"


using namespace std;
using namespace UapkiNS;


static const char* JSON_PROVIDER_INFO = "{"
    "\"id\": \"PKCS11\","                               //  required
    "\"apiVersion\": \"1.0.0\","                        //  required
    "\"libVersion\": \"" CM_PKCS11_LIBVERSION "\","     //  required
    "\"description\": \"CM-provider for PKCS11\","      //  required
    "\"manufacturer\": \"SPECINFOSYSTEMS LLC\","        //  required
    "\"supportListStorages\": true,"                    //  optional
    "\"flags\": 0"                                      //  optional
"}";


static CM_ERROR build_dstu_keywrap_parameters (
        const char* mechanismId,
        const CryptokiStorage::SupportedKeyDeriveAlgos& suppKeyDeriveAlgos,
        ParsonHelper& json
)
{
    CM_ERROR cm_err = RET_OK;
    JSON_Array* ja = nullptr;
    const bool is_dstu7624wrap = oid_is_equal(OID_DSTU7624_WRAP, mechanismId);

    CHECK_CM_JSON(json.setString("name", (is_dstu7624wrap) ? "DSTU7624-WRAP" : "GOST28147-WRAP (DSTU)"));
    ja = json.setArray("keyAlgo");
    DO_CM_JSON(json_array_append_string(ja, OID_DSTU4145_PARAM_PB_LE));
    ja = json.setArray("dhKdf");
    if (suppKeyDeriveAlgos.dstuCofactor) {
        DO_CM_JSON(json_array_append_string(ja, (is_dstu7624wrap) ? OID_COFACTOR_DH_DSTU7564_KDF : OID_COFACTOR_DH_GOST34311_KDF));
    }
    if (suppKeyDeriveAlgos.dstu) {
        DO_CM_JSON(json_array_append_string(ja, (is_dstu7624wrap) ? OID_STD_DH_DSTU7564_KDF : OID_STD_DH_GOST34311_KDF));
    }

cleanup:
    return cm_err;
}

static CM_ERROR build_ec_parameters (
        const char* name,
        const vector<uint32_t>& curveNames,
        const vector<string>& signAlgos,
        ParsonHelper& json
)
{
    CM_ERROR cm_err = RET_OK;
    JSON_Array* ja = nullptr;

    CHECK_CM_JSON(json.setString("name", name));
    ja = json.setArray("keyParam");
    for (size_t i = 0; i < curveNames.size(); i++) {
        DO_CM_JSON(json_array_append_string(ja, ecid_to_oid((EcParamsId)curveNames[i])));
    }
    ja = json.setArray("signAlgo");
    for (size_t i = 0; i < signAlgos.size(); i++) {
        DO_CM_JSON(json_array_append_string(ja, signAlgos[i].c_str()));
    }

cleanup:
    return cm_err;
}   //  build_ec_parameters

static CM_ERROR build_rsa_parameters (
        const vector<uint32_t>& keySizes,
        const vector<string>& signAlgos,
        ParsonHelper& json
)
{
    CM_ERROR cm_err = RET_OK;
    JSON_Array* ja = nullptr;

    CHECK_CM_JSON(json.setString("name", "RSA"));
    ja = json.setArray("keyParam");
    for (size_t i = 0; i < keySizes.size(); i++) {
        DO_CM_JSON(json_array_append_string(ja, to_string(keySizes[i]).c_str()));
    }
    ja = json.setArray("signAlgo");
    for (size_t i = 0; i < signAlgos.size(); i++) {
        DO_CM_JSON(json_array_append_string(ja, signAlgos[i].c_str()));
    }

cleanup:
    return cm_err;
}   //  build_rsa_parameters

static int device_info_to_json (
        const Cryptoki::TokenInfo& tokenInfo,
        const char* description,
        JSON_Object* joResult
)
{
    CM_ERROR cm_err = RET_OK;

    DO_CM_JSON(json_object_set_string(joResult, "id", tokenInfo.serialNumber.c_str()));
    DO_CM_JSON(json_object_set_string(joResult, "description", description));
    DO_CM_JSON(json_object_set_string(joResult, "manufacturer", tokenInfo.manufacturerId.c_str()));
    DO_CM_JSON(json_object_set_string(joResult, "model", tokenInfo.model.c_str()));
    DO_CM_JSON(json_object_set_string(joResult, "serial", tokenInfo.serialNumber.c_str()));
    DO_CM_JSON(json_object_set_string(joResult, "label", tokenInfo.label.c_str()));

cleanup:
    return cm_err;
}   //  device_info_to_json

static string get_device_description (
        const Cryptoki::TokenInfo& tokenInfo
)
{
    string rv_s;
    if ((tokenInfo.model == string("CC-337 RSA DSTU")) || (tokenInfo.model == string("ST-338"))) {
        rv_s = string("AVTOR Secure Token 337/338");
    }
    else {
        rv_s = tokenInfo.model;
    }
    return rv_s;
}   //  get_device_description

static string get_session_description (
        const Cryptoki::TokenInfo& tokenInfo
)
{
    string rv_s;
    if ((tokenInfo.model == string("CC-337 RSA DSTU")) || (tokenInfo.model == string("ST-338"))) {
        rv_s = string("AVTOR Secure Token 337/338 session");
    }
    else {
        rv_s = tokenInfo.model + string(" session");
    }
    return rv_s;
}   //  get_session_description


CM_ERROR CmCryptoki::deviceInfoToJson (
        const Cryptoki::TokenInfo& tokenInfo,
        JSON_Object* joResult,
        const bool isBasic
)
{
    const string s_description = get_device_description(tokenInfo);
    CM_ERROR cm_err = device_info_to_json(
        tokenInfo,
        s_description.c_str(),
        joResult
    );
    if (cm_err != RET_OK) return cm_err;

    if (!isBasic) {
        //  Password/PIN info
        const bool is_countlow = (tokenInfo.flags & CKF_USER_PIN_COUNT_LOW);
        const bool is_finaltry = (tokenInfo.flags & CKF_USER_PIN_FINAL_TRY);
        const bool is_locked = (tokenInfo.flags & CKF_USER_PIN_LOCKED);
        const bool is_tobechanged = (tokenInfo.flags & CKF_USER_PIN_TO_BE_CHANGED);
        uint32_t password_attempts_left = 0;
        if (!is_locked) {
            password_attempts_left = 255;
        }

        DO_CM_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "passwordCountLow", is_countlow));
        DO_CM_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "passwordFinalTry", is_finaltry));
        DO_CM_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "passwordLocked", is_locked));
        DO_CM_JSON(ParsonHelper::jsonObjectSetBoolean(joResult, "passwordToBeChanged", is_tobechanged));
        DO_CM_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "passwordAttemptsLeft", password_attempts_left));
        DO_CM_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "passwordMinLen", tokenInfo.minPinLen));
        DO_CM_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "passwordMaxLen", tokenInfo.maxPinLen));

        DO_CM_JSON(json_object_set_string(joResult, "flags", Cryptoki::uint32ToHex(tokenInfo.flags).c_str()));
        DO_CM_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "maxSessionCount", tokenInfo.maxSessionCount));
        DO_CM_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "sessionCount", tokenInfo.sessionCount));
        DO_CM_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "maxRwSessionCount", tokenInfo.maxRwSessionCount));
        DO_CM_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "rwSessionCount", tokenInfo.rwSessionCount));
        DO_CM_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "totalPublicMemory", tokenInfo.totalPublicMemory));
        DO_CM_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "freePublicMemory", tokenInfo.freePublicMemory));
        DO_CM_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "totalPrivateMemory", tokenInfo.totalPrivateMemory));
        DO_CM_JSON(ParsonHelper::jsonObjectSetUint32(joResult, "freePrivateMemory", tokenInfo.freePrivateMemory));

        DO_CM_JSON(json_object_set_string(joResult, "hardwareVersion", tokenInfo.hardwareVersion.toString().c_str()));
        DO_CM_JSON(json_object_set_string(joResult, "firmwareVersion", tokenInfo.firmwareVersion.toString().c_str()));
        DO_CM_JSON(json_object_set_string(joResult, "utcTime", tokenInfo.utcTime.c_str()));
    }

cleanup:
    return cm_err;
}

CM_ERROR CmCryptoki::keyInfoToJson (
        const CryptokiStorage::KeyInfo& keyInfo,
        JSON_Object* joResult
)
{
    if (!joResult) return RET_CM_GENERAL_ERROR;

    CM_ERROR cm_err = RET_OK;
    SmartBA sba_pubkey;
    DO_CM_JSON(json_object_set_string(joResult, "id", bufferToHex(keyInfo.keyId, false).c_str()));
    DO_CM_JSON(json_object_set_string(joResult, "mechanismId", keyInfo.mechanismId.c_str()));
    DO_CM_JSON(json_object_set_string(joResult, "parameterId", keyInfo.parameterId.c_str()));

    DO_CM_JSON(json_object_set_value(joResult, "signAlgo", json_value_init_array()));
    {
        JSON_Array* ja_signalgo = json_object_get_array(joResult, "signAlgo");
        for (const auto& it : keyInfo.signAlgo) {
            DO_CM_JSON(json_array_append_string(ja_signalgo, it.c_str()));
        }
    }

    cm_err = CryptokiStorage::getPublicKey(keyInfo, &sba_pubkey);
    if (cm_err != RET_OK) return cm_err;
    if (json_object_set_base64(joResult, "publicKey", sba_pubkey.get()) != RET_OK) return RET_CM_JSON_FAILURE;

    if (!keyInfo.label.empty()) {
        DO_CM_JSON(json_object_set_string(joResult, "label", keyInfo.label.c_str()));
    }

cleanup:
    return cm_err;
}

CM_ERROR CmCryptoki::listMechanismsToJson (
        const CryptokiStorage& storage,
        JSON_Array* jaMechanisms
)
{
    CM_ERROR cm_err = RET_OK;
    const CryptokiStorage::SupportedSignAlgos& supp_signalgos = storage.getSupportedSignAlgos();

    if (!supp_signalgos.dstu.empty()) {
        DO_CM_JSON(json_array_append_string(jaMechanisms, OID_DSTU4145_PARAM_PB_LE));
        if (storage.getSupportedKeyWrapAlgos().kalyna256wrap) {
            DO_CM_JSON(json_array_append_string(jaMechanisms, OID_DSTU7624_WRAP));
        }
        if (storage.getSupportedKeyWrapAlgos().gost28147wrap) {
            DO_CM_JSON(json_array_append_string(jaMechanisms, OID_GOST28147_WRAP));
        }
    }
    if (!supp_signalgos.ecdsa.empty()) {
        DO_CM_JSON(json_array_append_string(jaMechanisms, OID_EC_KEY));
    }
    if (!supp_signalgos.rsa.empty()) {
        DO_CM_JSON(json_array_append_string(jaMechanisms, OID_RSA));
    }

cleanup:
    return cm_err;
}

CM_ERROR CmCryptoki::mechanismParamsToJson (
        const CryptokiStorage& storage,
        const char* mechanismId,
        CM_JSON_PCHAR* jsonResult
)
{
    ParsonHelper json;
    if (!json.create()) return RET_CM_GENERAL_ERROR;

    const CryptokiStorage::SupportedKeyParams& supp_keyparams = storage.getSupportedKeyParams();
    const CryptokiStorage::SupportedSignAlgos& supp_signalgos = storage.getSupportedSignAlgos();

    CM_ERROR cm_err = RET_CM_INVALID_MECHANISM;
    if (oid_is_equal(OID_DSTU4145_PARAM_PB_LE, mechanismId) && !supp_signalgos.dstu.empty()) {
        cm_err = build_ec_parameters(
            "DSTU-4145",
            supp_keyparams.dstuCurves,
            supp_signalgos.dstu,
            json
        );
    }
    else if (oid_is_equal(OID_DSTU7624_WRAP, mechanismId) || oid_is_equal(OID_GOST28147_WRAP, mechanismId)) {
        cm_err = build_dstu_keywrap_parameters(
            mechanismId,
            storage.getSupportedKeyDeriveAlgos(),
            json
        );
    }
    else if (oid_is_equal(OID_EC_KEY, mechanismId) && !supp_signalgos.ecdsa.empty()) {
        cm_err = build_ec_parameters(
            "ECDSA",
            supp_keyparams.ecdsaCurves,
            supp_signalgos.ecdsa,
            json
        );
    }
    else if (oid_is_equal(OID_RSA, mechanismId) && !supp_signalgos.rsa.empty()) {
        cm_err = build_rsa_parameters(
            supp_keyparams.rsaKeySizes,
            supp_signalgos.rsa,
            json
        );
    }
    if (cm_err != RET_OK) return cm_err;

    CHECK_CM_JSON(json.serialize((char**)jsonResult));

cleanup:
    return cm_err;
}

CM_ERROR CmCryptoki::providerInfoToJson (
        CM_JSON_PCHAR* jsonResult
)
{
    if (!jsonResult) return RET_CM_INVALID_PARAMETER;

    *jsonResult = (CM_JSON_PCHAR)strdup(JSON_PROVIDER_INFO);
    return (*jsonResult != nullptr) ? RET_OK : RET_CM_GENERAL_ERROR;
}

CM_ERROR CmCryptoki::sessionInfoToJson (
        const CryptokiStorage& storage,
        CM_JSON_PCHAR* jsonResult
)
{
    ParsonHelper json;
    if (!json.create()) return RET_CM_GENERAL_ERROR;

    const Cryptoki::TokenInfo& token_info = storage.getTokenInfo();
    const string s_description = get_session_description(token_info);
    CM_ERROR cm_err = device_info_to_json(
        token_info,
        s_description.c_str(),
        json.rootObject()
    );
    if (cm_err != RET_OK) return cm_err;

    cm_err = listMechanismsToJson(storage, json.setArray("mechanisms"));
    if (cm_err != RET_OK) return cm_err;

    CHECK_CM_JSON(json.serialize((char**)jsonResult));

cleanup:
    return cm_err;
}
