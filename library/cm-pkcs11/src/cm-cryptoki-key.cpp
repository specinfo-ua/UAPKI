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

#define FILE_MARKER "cm-cryptoki/cm-cryptoki-key.cpp"

#include "cm-cryptoki.h"
#include "certreq-builder.h"
#include "cryptoki-const.h"
#include "dstu-ns.h"
#include "extnreq-helper.h"
#include "macros-internal.h"
#include "oid-utils.h"
#include "parson-helper.h"
#include "uapkif.h"
#include "uapki-ns-util.h"
#include "cm-cryptoki-debug.h"


#define DEBUG_OUTPUT(msg)
#ifndef DEBUG_OUTPUT
DEBUG_OUTPUT_FUNC
#define DEBUG_OUTPUT(msg) debug_output(DEBUG_OUTSTREAM_DEFAULT, msg);
#endif


#define OID_SIS_QSCD            "1.3.6.1.4.1.54069.1"
#define OID_SIS_DIAMOND_1000    "1.3.6.1.4.1.54069.1.1.1.1"
#define OID_SIS_DIAMOND_2000    "1.3.6.1.4.1.54069.1.1.1.2"
#define OID_SIS_DIAMOND_3000    "1.3.6.1.4.1.54069.1.1.1.3"
#define OID_SIS_DIAMOND_4000    "1.3.6.1.4.1.54069.1.1.1.4"
#define OID_SIS_OLYMP_HS        "1.3.6.1.4.1.54069.1.2.1.1"
#define OID_SIS_OLYMP_MINI      "1.3.6.1.4.1.54069.1.2.1.2"
#define OID_AVTOR_STOKEN337     "1.3.6.1.4.1.19398.1.1.8.23"
#define OID_AVEST_KEY           "1.3.6.1.4.1.19398.1.1.8.25"
#define OID_AVTOR_STOKEN338     "1.3.6.1.4.1.19398.1.1.8.34"
//#define OID_ENTERPRISE_EXAMPLE  "1.3.6.1.4.1.99999.1.1"


using namespace std;
using namespace UapkiNS;


static int calc_keyid (
        const char* keyAlgo,
        const char* signAlgo,
        const ByteArray* baPubkey,
        ByteArray** baKeyId
)
{
    int ret = RET_OK;

    if (DstuNS::isDstu4145family(keyAlgo)) {
        DO(DstuNS::calcKeyId(
            oid_is_parent(OID_DSTU4145_WITH_DSTU7564, signAlgo),
            baPubkey,
            baKeyId
        ));
    }
    else {
        DO(::hash(HASH_ALG_SHA1, baPubkey, baKeyId));
    }

cleanup:
    return ret;
}   //  encode_subjectkeyid

static const char* keypurposeid_by_model (
        const string& model
)
{
    const char* rv_oid = nullptr;
    //  SIS
    if (model == string("DIAMOND 1000"))            rv_oid = OID_SIS_DIAMOND_1000;
    else if (model == string("DIAMOND 2000"))       rv_oid = OID_SIS_DIAMOND_2000;
    else if (model == string("DIAMOND 3000"))       rv_oid = OID_SIS_DIAMOND_3000;
    else if (model == string("DIAMOND 4000"))       rv_oid = OID_SIS_DIAMOND_4000;
    else if (model == string("OLYMP mini HSM"))     rv_oid = OID_SIS_OLYMP_MINI;
    else if (model == string("OLYMP HSM"))          rv_oid = OID_SIS_OLYMP_HS;
    //  OTHER VENDORS
    else if (model == string("AvestKey"))           rv_oid = OID_AVEST_KEY;
    else if (model == string("CC-337 RSA DSTU"))    rv_oid = OID_AVTOR_STOKEN337;
    else if (model == string("ST-338"))             rv_oid = OID_AVTOR_STOKEN338;
    return rv_oid;
}   //  keypurposeid_by_model

static size_t hashsize_by_signalgo (
        const char* signAlgo
)
{
    const HashAlg hash_alg = hash_from_oid(signAlgo);
    return hash_get_size(hash_alg);
}   //  hashsize_by_signalgo


static CM_ERROR cm_key_get_info (
        CM_SESSION_API* session,
        CM_JSON_PCHAR* keyInfo,
        CM_BYTEARRAY** baKeyId
)
{
    DEBUG_OUTPUT("cm_key_get_info()");
    if (!session) return RET_CM_NO_SESSION;
    if (!keyInfo && !baKeyId) return RET_CM_INVALID_PARAMETER;

    CmCryptoki::SessionContext* ss_ctx = (CmCryptoki::SessionContext*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    CryptokiStorage& storage = ss_ctx->getStorage();
    if (!storage.isOpened()) return RET_CM_STORAGE_NOT_OPEN;
    if (!storage.isAuthorized()) return RET_CM_NOT_AUTHORIZED;

    CryptokiStorage::KeyInfo& selected_key = storage.selectedKey();
    if (!selected_key.isPresent()) return RET_CM_KEY_NOT_SELECTED;

    SmartBA sba_keyid;
    if (baKeyId) {
        if (!sba_keyid.set(CryptokiStorage::bufferToBa(selected_key.keyId))) return RET_CM_GENERAL_ERROR;
    }
    if (keyInfo) {
        ParsonHelper json;
        const CM_ERROR cm_err = CmCryptoki::keyInfoToJson(selected_key, json.create());
        if (cm_err != RET_OK) return cm_err;
        if (!json.serialize((char**)keyInfo)) return RET_CM_GENERAL_ERROR;
    }

    if (baKeyId) {
        *baKeyId = (CM_BYTEARRAY*)sba_keyid.pop();
    }
    return RET_OK;
}   //  cm_key_get_info

static CM_ERROR cm_key_get_public_key (
        CM_SESSION_API* session,
        CM_BYTEARRAY** baAlgorithmIdentifier,
        CM_BYTEARRAY** baPublicKey
)
{
    DEBUG_OUTPUT("cm_key_get_public_key()");
    if (!session) return RET_CM_NO_SESSION;
    if (!baAlgorithmIdentifier && !baPublicKey) return RET_CM_INVALID_PARAMETER;

    CmCryptoki::SessionContext* ss_ctx = (CmCryptoki::SessionContext*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    CryptokiStorage& storage = ss_ctx->getStorage();
    if (!storage.isOpened()) return RET_CM_STORAGE_NOT_OPEN;
    if (!storage.isAuthorized()) return RET_CM_NOT_AUTHORIZED;

    CryptokiStorage::KeyInfo& selected_key = storage.selectedKey();
    if (!selected_key.isPresent()) return RET_CM_KEY_NOT_SELECTED;

    CM_ERROR cm_err = RET_OK;
    SmartBA sba_keyalgid, sba_pubkey;

    if (baAlgorithmIdentifier) {
        cm_err = CryptokiStorage::getAlgorithmIdentifier(selected_key, &sba_keyalgid);
        if (cm_err != RET_OK) return cm_err;
    }
    if (baPublicKey) {
        cm_err = CryptokiStorage::getPublicKey(selected_key, &sba_pubkey);
        if (cm_err != RET_OK) return cm_err;
    }

    if (baAlgorithmIdentifier) {
        *baAlgorithmIdentifier = (CM_BYTEARRAY*)sba_keyalgid.pop();
    }
    if (baPublicKey) {
        *baPublicKey = (CM_BYTEARRAY*)sba_pubkey.pop();
    }
    return cm_err;
}   //  cm_key_get_public_key

static CM_ERROR cm_key_sign (
        CM_SESSION_API* session,
        const CM_UTF8_CHAR* signAlgo,
        const CM_BYTEARRAY* baSignAlgoParams,
        const uint32_t count,
        const CM_BYTEARRAY** abaHashes,
        CM_BYTEARRAY*** abaSignatures
)
{
    DEBUG_OUTPUT("cm_key_sign()");
    if (!session) return RET_CM_NO_SESSION;
    if (!signAlgo || (count == 0) || !abaHashes || !abaSignatures) return RET_CM_INVALID_PARAMETER;

    const string s_signalgo = string((const char*)signAlgo);
    const size_t expected_hsize = hashsize_by_signalgo(s_signalgo.c_str());
    if (expected_hsize == 0) return RET_CM_UNSUPPORTED_ALG;
    for (uint32_t i = 0; i < count; i++) {
        if (ba_get_len((const ByteArray*)abaHashes[i]) != expected_hsize) return RET_CM_INVALID_HASH;
    }

    CmCryptoki::SessionContext* ss_ctx = (CmCryptoki::SessionContext*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    CryptokiStorage& storage = ss_ctx->getStorage();
    if (!storage.isOpened()) return RET_CM_STORAGE_NOT_OPEN;
    if (!storage.isAuthorized()) return RET_CM_NOT_AUTHORIZED;

    CryptokiStorage::KeyInfo& selected_key = storage.selectedKey();
    if (!selected_key.isPresent()) return RET_CM_KEY_NOT_SELECTED;

    CM_BYTEARRAY** aba_signatures = (CM_BYTEARRAY**)calloc(count, sizeof(CM_BYTEARRAY*));
    if (!aba_signatures) return RET_CM_GENERAL_ERROR;

    for (uint32_t i = 0; i < count; i++) {
        const CM_ERROR cm_err = storage.signHash(
            selected_key,
            s_signalgo,
            baSignAlgoParams,
            abaHashes[i],
            &aba_signatures[i]
        );
        if (cm_err != RET_OK) {
            for (size_t j = 0; j < i; j++) {
                ba_free((ByteArray*)aba_signatures[j]);
                aba_signatures[j] = nullptr;
            }
            ::free(aba_signatures);
            return cm_err;
        }
    }

    *abaSignatures = aba_signatures;
    return RET_OK;
}   //  cm_key_sign

static CM_ERROR cm_key_get_csr (
        CM_SESSION_API* session,
        const CM_UTF8_CHAR* signAlgo,
        const CM_BYTEARRAY* baSignAlgoParams,
        const CM_BYTEARRAY* baSubject,
        const CM_BYTEARRAY* baExtensionRequest,
        CM_BYTEARRAY** baCsrEncoded
)
{
    DEBUG_OUTPUT("cm_key_get_csr()");
    if (!session) return RET_CM_NO_SESSION;
    if (!baCsrEncoded) return RET_CM_INVALID_PARAMETER;

    CmCryptoki::SessionContext* ss_ctx = (CmCryptoki::SessionContext*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    CryptokiStorage& storage = ss_ctx->getStorage();
    if (!storage.isOpened()) return RET_CM_STORAGE_NOT_OPEN;
    if (!storage.isAuthorized()) return RET_CM_NOT_AUTHORIZED;

    CryptokiStorage::KeyInfo& selected_key = storage.selectedKey();
    if (!selected_key.isPresent()) return RET_CM_KEY_NOT_SELECTED;

    const char* s_signalgo = (const char*)signAlgo;
    if (!s_signalgo) {
        s_signalgo = storage.signAlgoByDefault(selected_key);
    }
    if (!s_signalgo) return RET_CM_UNSUPPORTED_ALG;

    SmartBA sba_keyalgid, sba_null, sba_pubkey, sba_signvalue;
    CM_ERROR cm_err = CryptokiStorage::getAlgorithmIdentifier(selected_key, &sba_keyalgid);
    if (cm_err != RET_OK) return cm_err;

    cm_err = CryptokiStorage::getPublicKey(selected_key, &sba_pubkey);
    if (cm_err != RET_OK) return cm_err;

    int ret = RET_OK;
    const ByteArray* rba_signalgoparams = (const ByteArray*)baSignAlgoParams;
    ExtnRequestHelper extnreq_helper;
    CertReqBuilder certreq_builder;
    const char* eku_device = nullptr;

    DO(extnreq_helper.parse((const ByteArray*)baExtensionRequest));
    DO(extnreq_helper.addQcStatementsDefault());
    if (ss_ctx->getProviderParams().ekuDevice) {
        eku_device = keypurposeid_by_model(storage.getTokenInfo().model);
        if (extnreq_helper.findKeyPurposeId(eku_device)) {
            eku_device = nullptr;
        }
    };
    DO(extnreq_helper.encodeExtKeyUsage(eku_device, false));
    if (ss_ctx->getProviderParams().pkAttestate) {
        Cryptoki::Buffer buf_pkattestate;
        cm_err = CmCryptoki::getKeyAttestate(storage, selected_key, buf_pkattestate);
        if (cm_err != RET_OK) return cm_err;
        if (!buf_pkattestate.empty()) {
            SmartBA sba_pkattestate;
            if (!sba_pkattestate.set(CryptokiStorage::bufferToBa(buf_pkattestate))) return RET_CM_GENERAL_ERROR;
            DO(extnreq_helper.encodePkAttestate(sba_pkattestate.get(), false));
        }
    }

    DO(certreq_builder.init(1));
    DO(certreq_builder.setSubjectPublicKeyInfo(sba_keyalgid.get(), sba_pubkey.get()));
    if (baSubject) {
        DO(certreq_builder.setSubject((const ByteArray*)baSubject));
    }
    if (ss_ctx->getProviderParams().subjectKeyId) {
        SmartBA sba_keyid;
        DO(calc_keyid(certreq_builder.getKeyAlgo().c_str(), s_signalgo, sba_pubkey.get(), &sba_keyid));
        DO(extnreq_helper.encodeSubjectKeyId(sba_keyid.get(), false));
    }
    if (extnreq_helper.build() > 0) {
        DO(certreq_builder.addExtensions(extnreq_helper.getEncodedExtns()));
    }
    DO(certreq_builder.encodeTbs());

    if (!rba_signalgoparams && (certreq_builder.getKeyAlgo() == string(OID_RSA))) {
        if (!sba_null.set(ba_alloc_from_uint8(CryptokiStorage::DER_ASN1_NULL, sizeof(CryptokiStorage::DER_ASN1_NULL)))) return RET_CM_GENERAL_ERROR;
        rba_signalgoparams = sba_null.get();
    }

    cm_err = storage.signData(
        selected_key,
        s_signalgo,
        (const CM_BYTEARRAY*)rba_signalgoparams,
        (const CM_BYTEARRAY*)certreq_builder.getTbsEncoded(),
        (CM_BYTEARRAY**)&sba_signvalue
    );
    if (cm_err != RET_OK) return cm_err;

    DO(certreq_builder.encodeCertRequest(
        s_signalgo,
        rba_signalgoparams,
        sba_signvalue.get()
    ));
    *baCsrEncoded = (CM_BYTEARRAY*)certreq_builder.getCsrEncoded(true);

cleanup:
    return ret;
}   //  cm_key_get_csr

static CM_ERROR cm_key_dh_wrap_key (
        CM_SESSION_API* session,
        const CM_UTF8_CHAR* kdfOid,
        const CM_UTF8_CHAR* wrapAlgOid,
        const uint32_t count,
        const CM_BYTEARRAY** abaPubkeys,
        const CM_BYTEARRAY** abaSessionKeys,
        CM_BYTEARRAY*** abaSalts,
        CM_BYTEARRAY*** abaWrappedKeys
)
{
    DEBUG_OUTPUT("cm_key_dh_wrap_key()");
    if (!session) return RET_CM_NO_SESSION;
    if (
        !kdfOid || !wrapAlgOid || (count == 0) ||
        !abaPubkeys || !abaSessionKeys || !abaWrappedKeys
    ) return RET_CM_INVALID_PARAMETER;

    CmCryptoki::SessionContext* ss_ctx = (CmCryptoki::SessionContext*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    CryptokiStorage& storage = ss_ctx->getStorage();
    if (!storage.isOpened()) return RET_CM_STORAGE_NOT_OPEN;
    if (!storage.isAuthorized()) return RET_CM_NOT_AUTHORIZED;

    CryptokiStorage::KeyInfo& selected_key = storage.selectedKey();
    if (!selected_key.isPresent()) return RET_CM_KEY_NOT_SELECTED;

    CM_BYTEARRAY** aba_stubsalts = nullptr;
    const int ret = storage.dhWrapKey(
        selected_key,
        (abaSalts),
        (const char*)kdfOid,
        (const char*)wrapAlgOid,
        count,
        abaPubkeys,
        abaSessionKeys,
        (abaSalts) ? abaSalts : &aba_stubsalts,
        abaWrappedKeys
    );
    return ret;
}   //  cm_key_dh_wrap_key

static CM_ERROR cm_key_dh_unwrap_key (
        CM_SESSION_API* session,
        const CM_UTF8_CHAR* kdfOid,
        const CM_UTF8_CHAR* wrapAlgOid,
        const uint32_t count,
        const CM_BYTEARRAY** abaPubkeys,
        const CM_BYTEARRAY** abaSalts,
        const CM_BYTEARRAY** abaWrappedKeys,
        CM_BYTEARRAY*** abaSessionKeys
)
{
    DEBUG_OUTPUT("cm_key_dh_unwrap_key()");
    if (!session) return RET_CM_NO_SESSION;
    if (
        !kdfOid || !wrapAlgOid || (count == 0) ||
        !abaPubkeys || !abaWrappedKeys || !abaSessionKeys
    ) return RET_CM_INVALID_PARAMETER;

    CmCryptoki::SessionContext* ss_ctx = (CmCryptoki::SessionContext*)session->ctx;
    if (!ss_ctx) return RET_CM_NO_SESSION;

    CryptokiStorage& storage = ss_ctx->getStorage();
    if (!storage.isOpened()) return RET_CM_STORAGE_NOT_OPEN;
    if (!storage.isAuthorized()) return RET_CM_NOT_AUTHORIZED;

    CryptokiStorage::KeyInfo& selected_key = storage.selectedKey();
    if (!selected_key.isPresent()) return RET_CM_KEY_NOT_SELECTED;

    const int ret = storage.dhUnwrapKey(
        selected_key,
        (const char*)kdfOid,
        (const char*)wrapAlgOid,
        count,
        abaPubkeys,
        abaSalts,
        abaWrappedKeys,
        abaSessionKeys
    );
    return ret;
}   //  cm_key_dh_unwrap_key


void CmCryptoki::SessionContext::assignKeyApi (void)
{
    m_KeyApi.getInfo = cm_key_get_info;
    m_KeyApi.getPublicKey = cm_key_get_public_key;
    m_KeyApi.initKeyUsage = nullptr;
    m_KeyApi.setOtp = nullptr;
    m_KeyApi.sign = cm_key_sign;
    m_KeyApi.signInit = nullptr;
    m_KeyApi.signUpdate = nullptr;
    m_KeyApi.signFinal = nullptr;
    m_KeyApi.getCertificates = nullptr;
    m_KeyApi.addCertificate = nullptr;
    m_KeyApi.getCsr = cm_key_get_csr;
    m_KeyApi.dh = nullptr;
    m_KeyApi.dhWrapKey = cm_key_dh_wrap_key;
    m_KeyApi.dhUnwrapKey = cm_key_dh_unwrap_key;
    m_KeyApi.decrypt = nullptr;
    m_KeyApi.encrypt = nullptr;
    m_KeyApi.setInfo = nullptr;
    m_KeyApi.exportKey = nullptr;
}
