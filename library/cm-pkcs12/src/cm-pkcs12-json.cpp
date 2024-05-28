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

#include "cm-api.h"
#include "cm-errors.h"
#include "cm-pkcs12.h"
#include "oids.h"
#include "parson.h"
#include "parson-helper.h"


#define CHECK_JSON(func)                    \
    {                                       \
        if (!(func)) {                      \
            cm_err = RET_CM_JSON_FAILURE;   \
            goto cleanup;                   \
        }                                   \
    }

#define DO_JSON(func)                       \
    {                                       \
        if ((func) != JSONSuccess) {        \
            cm_err = RET_CM_JSON_FAILURE;   \
            goto cleanup;                   \
        }                                   \
    }


using namespace std;


const char* CmPkcs12::CM_SESSION_DESCRIPTION    = "PKCS#12";
const char* CmPkcs12::CM_SESSION_MANUFACTURER   = "SPECINFOSYSTEMS LLC";
const char* CmPkcs12::CM_SESSION_MODEL          = "PKCS#12";
const char* CmPkcs12::FILENAME_ON_MEMORY        = "file://memory";


static const size_t DSTU_ECNAMES_NUMBER = 7;
static const char* DSTU_ECNAMES[DSTU_ECNAMES_NUMBER] = {
    OID_DSTU4145_PARAM_M233_PB, OID_DSTU4145_PARAM_M257_PB, OID_DSTU4145_PARAM_M307_PB, OID_DSTU4145_PARAM_M367_PB, OID_DSTU4145_PARAM_M431_PB,
    OID_DSTU4145_PARAM_M233_ONB, OID_DSTU4145_PARAM_M431_ONB
};

static const size_t SIGN_ALGO_DSTU_NUMBER = 4;
static const char* SIGN_ALGO_DSTU[SIGN_ALGO_DSTU_NUMBER] = {
    OID_DSTU4145_WITH_DSTU7564_256_PB, OID_DSTU4145_WITH_DSTU7564_384_PB, OID_DSTU4145_WITH_DSTU7564_512_PB,
    OID_DSTU4145_PARAM_PB_LE
};

static const size_t EC_NAMES_NUMBER = 3;
static const char* EC_NAMES[EC_NAMES_NUMBER] = {
    OID_NIST_P256, OID_NIST_P384, OID_NIST_P521
};

static const size_t SIGN_ALGO_ECDSA_NUMBER = 6;
static const char* SIGN_ALGOS_ECDSA[SIGN_ALGO_ECDSA_NUMBER] = {
    OID_ECDSA_WITH_SHA256, OID_ECDSA_WITH_SHA384, OID_ECDSA_WITH_SHA512,        //  ECDSA with SHA2
    OID_ECDSA_WITH_SHA3_256, OID_ECDSA_WITH_SHA3_384, OID_ECDSA_WITH_SHA3_512   //  ECDSA with SHA3
};

static const size_t RSA_BITS_NUMBER = 4;
static const char* RSA_BITS[RSA_BITS_NUMBER] = { "1024", "2048", "3072", "4096" };

static const size_t SIGN_ALGO_RSA_NUMBER = 8;
static const char* SIGN_ALGOS_RSA[SIGN_ALGO_RSA_NUMBER] = {
    OID_RSA_WITH_SHA256, OID_RSA_WITH_SHA384, OID_RSA_WITH_SHA512,          //  RSA with SHA2
    OID_RSA_WITH_SHA3_256, OID_RSA_WITH_SHA3_384, OID_RSA_WITH_SHA3_512,    //  RSA with SHA3
    OID_RSA_WITH_SM3, OID_RSA_PSS
};


static CM_ERROR build_dstu_parameters (ParsonHelper& json)
{
    CM_ERROR cm_err = RET_OK;
    JSON_Array* ja = nullptr;

    CHECK_JSON(json.setString("name", "DSTU-4145"));
    ja = json.setArray("keyParam");
    for (size_t i = 0; i < DSTU_ECNAMES_NUMBER; i++) {
        DO_JSON(json_array_append_string(ja, DSTU_ECNAMES[i]));
    }
    ja = json.setArray("signAlgo");
    for (size_t i = 0; i < SIGN_ALGO_DSTU_NUMBER; i++) {
        DO_JSON(json_array_append_string(ja, SIGN_ALGO_DSTU[i]));
    }

cleanup:
    return cm_err;
}

static CM_ERROR build_ecdsa_parameters (ParsonHelper& json)
{
    CM_ERROR cm_err = RET_OK;
    JSON_Array* ja = nullptr;

    CHECK_JSON(json.setString("name", "ECDSA"));
    ja = json.setArray("keyParam");
    for (size_t i = 0; i < EC_NAMES_NUMBER; i++) {
        DO_JSON(json_array_append_string(ja, EC_NAMES[i]));
    }
    ja = json.setArray("signAlgo");
    for (size_t i = 0; i < SIGN_ALGO_ECDSA_NUMBER; i++) {
        DO_JSON(json_array_append_string(ja, SIGN_ALGOS_ECDSA[i]));
    }

cleanup:
    return cm_err;
}

static CM_ERROR build_rsa_parameters (ParsonHelper& json)
{
    CM_ERROR cm_err = RET_OK;
    JSON_Array* ja = nullptr;

    CHECK_JSON(json.setString("name", "RSA"));
    ja = json.setArray("keyParam");
    for (size_t i = 0; i < RSA_BITS_NUMBER; i++) {
        DO_JSON(json_array_append_string(ja, RSA_BITS[i]));
    }
    ja = json.setArray("signAlgo");
    for (size_t i = 0; i < SIGN_ALGO_RSA_NUMBER; i++) {
        DO_JSON(json_array_append_string(ja, SIGN_ALGOS_RSA[i]));
    }

cleanup:
    return cm_err;
}

static CM_ERROR build_dstu_keywrap_parameters (const string& mechanismOid, ParsonHelper& json)
{
    CM_ERROR cm_err = RET_OK;
    JSON_Array* ja = nullptr;
    const bool is_dstu7624wrap = (mechanismOid == OID_DSTU7624_WRAP);

    CHECK_JSON(json.setString("name", (is_dstu7624wrap) ? "DSTU7624-WRAP" : "GOST28147-WRAP (DSTU)"));
    ja = json.setArray("keyAlgo");
    DO_JSON(json_array_append_string(ja, (is_dstu7624wrap) ? OID_DSTU4145_WITH_DSTU7564 : OID_DSTU4145_WITH_GOST3411));
    ja = json.setArray("dhKdf");
    DO_JSON(json_array_append_string(ja, (is_dstu7624wrap) ? OID_COFACTOR_DH_DSTU7564_KDF : OID_COFACTOR_DH_GOST34311_KDF));
    DO_JSON(json_array_append_string(ja, (is_dstu7624wrap) ? OID_STD_DH_DSTU7564_KDF : OID_STD_DH_GOST34311_KDF));

cleanup:
    return cm_err;
}


CM_ERROR CmPkcs12::keyInfoToJson (
        const StoreKeyInfo& keyInfo,
        JSON_Object* joResult
)
{
    CM_ERROR cm_err = RET_OK;

    DO_JSON(json_object_set_string(joResult, "id", keyInfo.id.c_str()));
    DO_JSON(json_object_set_string(joResult, "mechanismId", keyInfo.mechanismId.c_str()));
    DO_JSON(json_object_set_string(joResult, "parameterId", keyInfo.parameterId.c_str()));

    DO_JSON(json_object_set_value(joResult, "signAlgo", json_value_init_array()));
    cm_err = CmPkcs12::signAlgoByMechanismId(keyInfo.mechanismId.c_str(), json_object_get_array(joResult, "signAlgo"));
    if (cm_err != RET_OK) return cm_err;

    if (!keyInfo.label.empty()) {
        DO_JSON(json_object_set_string(joResult, "label", keyInfo.label.c_str()));
    }

cleanup:
    return cm_err;
}

CM_ERROR CmPkcs12::listMechanisms (
        JSON_Array* jaMechanisms
)
{
    CM_ERROR cm_err = RET_OK;
    DO_JSON(json_array_append_string(jaMechanisms, OID_DSTU4145_WITH_GOST3411));
    DO_JSON(json_array_append_string(jaMechanisms, OID_DSTU4145_WITH_DSTU7564));
    DO_JSON(json_array_append_string(jaMechanisms, OID_EC_KEY));
    DO_JSON(json_array_append_string(jaMechanisms, OID_RSA));
    DO_JSON(json_array_append_string(jaMechanisms, OID_GOST28147_WRAP));
    DO_JSON(json_array_append_string(jaMechanisms, OID_DSTU7624_WRAP));

cleanup:
    return cm_err;
}

CM_ERROR CmPkcs12::mechanismParamsToJson (
        const char* mechanismId,
        CM_JSON_PCHAR* jsonResult
)
{
    ParsonHelper json;
    if (!json.create()) return RET_CM_GENERAL_ERROR;

    CM_ERROR cm_err = RET_CM_INVALID_MECHANISM;
    const string mechanism_oid = string((char*)mechanismId);
    if (mechanism_oid == OID_EC_KEY) {
        cm_err = build_ecdsa_parameters(json);
    }
    else if (
        oid_is_parent(OID_DSTU4145_WITH_GOST3411, mechanismId) ||
        oid_is_parent(OID_DSTU4145_WITH_DSTU7564, mechanismId)
    ) {
        cm_err = build_dstu_parameters(json);
    }
    else if (mechanism_oid == OID_RSA) {
        cm_err = build_rsa_parameters(json);
    }
    else if (
        (mechanism_oid == OID_GOST28147_WRAP) ||
        (mechanism_oid == OID_DSTU7624_WRAP)
    ) {
        cm_err = build_dstu_keywrap_parameters(mechanism_oid, json);
    }
    if (cm_err != RET_OK) return cm_err;

    CHECK_JSON(json.serialize((char**)jsonResult));

cleanup:
    return cm_err;
}

CM_ERROR CmPkcs12::sessionInfoToJson (
        const string& filename,
        CM_JSON_PCHAR* jsonResult
)
{
    ParsonHelper json;
    if (!json.create()) return RET_CM_GENERAL_ERROR;

    CM_ERROR cm_err = RET_OK;
    CHECK_JSON(json.setString("id", !filename.empty() ? filename.c_str() : FILENAME_ON_MEMORY));
    CHECK_JSON(json.setString("description", CM_SESSION_DESCRIPTION));
    CHECK_JSON(json.setString("manufacturer", CM_SESSION_MANUFACTURER));
    CHECK_JSON(json.setString("label", ""));
    CHECK_JSON(json.setString("model", ""));
    CHECK_JSON(json.setString("serial", ""));
    cm_err = listMechanisms(json.setArray("mechanisms"));
    if (cm_err != RET_OK) return cm_err;

    CHECK_JSON(json.serialize((char**)jsonResult));

cleanup:
    return cm_err;
}

CM_ERROR CmPkcs12::signAlgoByMechanismId (
        const char* oid,
        JSON_Array* jaSignAlgos
)
{
    size_t cnt = 0;
    const char** sign_algos = nullptr;
    if (
        oid_is_parent(OID_DSTU4145_WITH_DSTU7564, oid) ||
        oid_is_parent(OID_DSTU4145_WITH_GOST3411, oid)
    ) {
        cnt = SIGN_ALGO_DSTU_NUMBER;
        sign_algos = SIGN_ALGO_DSTU;
    }
    else if (oid_is_equal(OID_EC_KEY, oid)) {
        cnt = SIGN_ALGO_ECDSA_NUMBER;
        sign_algos = SIGN_ALGOS_ECDSA;
    }
    else if (oid_is_equal(OID_RSA, oid)) {
        cnt = SIGN_ALGO_RSA_NUMBER;
        sign_algos = SIGN_ALGOS_RSA;
    }

    CM_ERROR cm_err = RET_OK;
    for (size_t i = 0; i < cnt; i++) {
        DO_JSON(json_array_append_string(jaSignAlgos, sign_algos[i]));
    }

cleanup:
    return cm_err;
}

