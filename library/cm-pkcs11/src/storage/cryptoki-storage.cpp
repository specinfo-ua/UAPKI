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

#define FILE_MARKER "cm-cryptoki/storage/cryptoki-storage.cpp"

#include <stdlib.h>
#include "cryptoki-const.h"
#include "cryptoki-const-ukr.h"
#include "cryptoki-storage.h"
#include "dstu4145-params.h"
#include "ecdsa-params.h"
#include "macros-internal.h"
#include "oid-utils.h"
#include "uapki-ns-util.h"


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;
using namespace Cryptoki;
using namespace UapkiNS;


struct EcParamInfo {
    EcParamsId  ecParamsId;
    uint32_t    keySize;
};  //  end struct EcParamInfo

static const size_t DSTU4145_ECPARAMINFO_NUMBER = 5;
static const EcParamInfo DSTU4145_ECPARAMINFOS[DSTU4145_ECPARAMINFO_NUMBER] = {
    { EC_PARAMS_ID_DSTU4145_M257_PB, 257 },
    { EC_PARAMS_ID_DSTU4145_M431_PB, 431 },
    { EC_PARAMS_ID_DSTU4145_M233_PB, 233 },
    { EC_PARAMS_ID_DSTU4145_M307_PB, 307 },
    { EC_PARAMS_ID_DSTU4145_M367_PB, 367 },
};

static const size_t ECDSA_ECPARAMINFO_NUMBER = 3;
static const EcParamInfo ECDSA_ECPARAMINFOS[ECDSA_ECPARAMINFO_NUMBER] = {
    { EC_PARAMS_ID_NIST_P256, 256 },
    { EC_PARAMS_ID_NIST_P384, 384 },
    { EC_PARAMS_ID_NIST_P521, 521 }
};

static const size_t RSA_KEYSIZES_NUMBER = 4;
static const uint32_t RSA_KEYSIZES[RSA_KEYSIZES_NUMBER] = { 1024, 2048, 3072, 4096 };

const uint8_t CryptokiStorage::DER_ASN1_NULL[2] = { 0x05, 0x00 };
const uint8_t CryptokiStorage::DKE_DEFAULT_SBOX[64] = {
    0xA9, 0xD6, 0xEB, 0x45, 0xF1, 0x3C, 0x70, 0x82, 0x80, 0xC4, 0x96, 0x7B, 0x23, 0x1F, 0x5E, 0xAD,
    0xF6, 0x58, 0xEB, 0xA4, 0xC0, 0x37, 0x29, 0x1D, 0x38, 0xD9, 0x6B, 0xF0, 0x25, 0xCA, 0x4E, 0x17,
    0xF8, 0xE9, 0x72, 0x0D, 0xC6, 0x15, 0xB4, 0x3A, 0x28, 0x97, 0x5F, 0x0B, 0xC1, 0xDE, 0xA3, 0x64,
    0x38, 0xB5, 0x64, 0xEA, 0x2C, 0x17, 0x9F, 0xD0, 0x12, 0x3E, 0x6D, 0xB8, 0xFA, 0xC5, 0x79, 0x04
};
const uint8_t CryptokiStorage::DER_OID_NIST_P256[10] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
const uint8_t CryptokiStorage::DER_OID_NIST_P384[7]  = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
const uint8_t CryptokiStorage::DER_OID_NIST_P521[7]  = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 };


DEBUG_OUTCON(
static void buf_print (const char* msg, const uint8_t* buf, const size_t len)
{
    printf("%s", msg);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
    }
    puts("");
}
)


static bool encode_digestinfo (
        const HashAlg hashAlgo,
        const ByteArray* baDigest,
        Buffer& bufEncoded
)
{
    if ((hashAlgo == HASH_ALG_UNDEFINED) || (ba_get_len(baDigest) == 0)) return false;

    SmartBA sba_null;
    if (!sba_null.set(ba_alloc_from_uint8(CryptokiStorage::DER_ASN1_NULL, sizeof(CryptokiStorage::DER_ASN1_NULL)))) return false;

    int ret = RET_OK;
    uint8_t* encoded_bytes = nullptr;
    size_t encoded_len = 0;
    DigestInfo_t* digest_info = (DigestInfo_t*)calloc(1, sizeof(DigestInfo_t));
    if (!digest_info) return false;

    DO(Util::algorithmIdentifierToAsn1(
        digest_info->digestAlgorithm,
        hash_to_oid(hashAlgo),
        sba_null.get()
    ));
    DO(asn_ba2OCTSTRING(baDigest, &digest_info->digest));

    DO(asn_encode(get_DigestInfo_desc(), digest_info, &encoded_bytes, &encoded_len));

    bufEncoded.resize(encoded_len);
    memcpy((void*)bufEncoded.data(), encoded_bytes, bufEncoded.size());

cleanup:
    asn_free(get_DigestInfo_desc(), digest_info);
    uapkif_free(encoded_bytes);
    return (ret == RET_OK);
}   //  encode_digestinfo

static bool find_keyparam (
        const vector<uint32_t>& listParams,
        const uint32_t keyParam
)
{
    bool rv_found = false;
    for (const auto& it : listParams) {
        rv_found = (it == keyParam);
        if (rv_found) break;
    }
    return rv_found;
}   //  find_keyparam

static void reorder_signalgos (
        vector<string>& signAlgos, const string& defaultSignAlgos
)
{
    if (signAlgos.empty()) return;

    vector<string> reordered_signalgos;
    reordered_signalgos.reserve(signAlgos.size() + 1);
    reordered_signalgos.push_back(defaultSignAlgos);
    for (const auto& it : signAlgos) {
        if (it != defaultSignAlgos) {
            reordered_signalgos.push_back(it);
        }
    }
    if (reordered_signalgos.size() == signAlgos.size()) {
        signAlgos = reordered_signalgos;
    }
}   //  reorder_signalgos

static HashAlg hash_from_oid_dhkdf (
        const char* oid,
        bool& withCofactor
)
{
    HashAlg rv_hash = HASH_ALG_UNDEFINED;
    if (oid_is_equal(OID_COFACTOR_DH_DSTU7564_KDF, oid)) {
        rv_hash = HASH_ALG_DSTU7564_256;
        withCofactor = true;
    }
    else if (oid_is_equal(OID_COFACTOR_DH_GOST34311_KDF, oid)) {
        rv_hash = HASH_ALG_GOST34311;
        withCofactor = true;
    }
    //else if (oid_is_equal(OID_DHSINGLEPASS_COFACTOR_DH_SHA1_KDF, oid)) {
    //    rv_hash = HASH_ALG_SHA1;
    //    withCofactor = true;
    //}
    else if (oid_is_equal(OID_STD_DH_DSTU7564_KDF, oid)) {
        rv_hash = HASH_ALG_DSTU7564_256;
        withCofactor = false;
    }
    else if (oid_is_equal(OID_STD_DH_GOST34311_KDF, oid)) {
        rv_hash = HASH_ALG_GOST34311;
        withCofactor = false;
    }
    //else if (oid_is_equal(OID_DHSINGLEPASS_STD_DH_SHA1_KDF, oid)) {
    //    rv_hash = HASH_ALG_SHA1;
    //    withCofactor = false;
    //}
    //else if (oid_is_equal(OID_DHSINGLEPASS_STD_DH_SHA256_KDF, oid)) {
    //    rv_hash = HASH_ALG_SHA256;
    //    withCofactor = false;
    //}

    return rv_hash;
}   //  hash_from_oid_dhkdf

static int spki_get_encappubkey (
        const ByteArray* baSpki,
        ByteArray** baPubkey
)
{
    SubjectPublicKeyInfo_t* spki = (SubjectPublicKeyInfo_t*)asn_decode_ba_with_alloc(get_SubjectPublicKeyInfo_desc(), baSpki);
    if (!spki) return RET_CM_INVALID_PARAMETER;

    int ret = RET_OK;
    string s_keyalgo;
    DO(Util::oidFromAsn1(&spki->algorithm.algorithm, s_keyalgo));
    if (
        oid_is_parent(OID_DSTU4145_WITH_GOST3411, s_keyalgo.c_str()) ||
        oid_is_parent(OID_DSTU4145_WITH_DSTU7564, s_keyalgo.c_str())
    ) {
        DO(asn_BITSTRING2ba(&spki->subjectPublicKey, baPubkey));
    }
    else {
        SET_ERROR(RET_CM_UNSUPPORTED_ALG);
    }

cleanup:
    asn_free(get_SubjectPublicKeyInfo_desc(), spki);
    return ret;
}   //  spki_get_encappubkey


#ifndef CM_PKCS11_SKIP_SUBSTITUTE_ECPARAM
static const uint8_t* substitute_ecparam (
        const string& algoParam,
        size_t& lenParam
) {
    const uint8_t* rv = nullptr;
    if (algoParam == string(OID_NIST_P256)) {
        rv = CryptokiStorage::DER_OID_NIST_P256;
        lenParam = sizeof(CryptokiStorage::DER_OID_NIST_P256);
    }
    else if (algoParam == string(OID_NIST_P384)) {
        rv = CryptokiStorage::DER_OID_NIST_P384;
        lenParam = sizeof(CryptokiStorage::DER_OID_NIST_P384);
    }
    else if (algoParam == string(OID_NIST_P521)) {
        rv = CryptokiStorage::DER_OID_NIST_P521;
        lenParam = sizeof(CryptokiStorage::DER_OID_NIST_P521);
    }
    return rv;
}   //  substitute_ecparam
#endif


CryptokiStorage::KeyInfo::KeyInfo (void)
    : keyAlgo(KeyAlgo::UNDEFINED)
    , keyType(0xFFFFFFFF)
    , mechType(0xFFFFFFFF)
    , hPrivateKey((CK_OBJECT_HANDLE)-1)
    , hPublicKey((CK_OBJECT_HANDLE)-1)
{
}

CryptokiStorage::KeyInfo::~KeyInfo (void)
{
    reset();
}

bool CryptokiStorage::KeyInfo::equalKeyId (
        const uint8_t* bufKeyId,
        const size_t lenKeyId
) const
{
    return (
        (!keyId2.empty() && cmpBuffers(keyId2, bufKeyId, lenKeyId)) ||
        cmpBuffers(keyId, bufKeyId, lenKeyId)
    );
}

bool CryptokiStorage::KeyInfo::equalPublicKey (
        const uint8_t* bufPublicKey,
        const size_t lenPublicKey
) const
{
    bool rv_equal = false;
    switch (keyAlgo) {
    case KeyAlgo::DSTU:
        //  Note: ecPoint encapsulated OCTET_STRING in PKCS11 and CERT
        rv_equal = cmpBuffers(publicParams.ecPoint, bufPublicKey, lenPublicKey);
        break;
    case KeyAlgo::ECDSA:
        //  Note: ecPoint encapsulated OCTET_STRING in PKCS11
        if (publicParams.ecPoint.size() > lenPublicKey) {
            rv_equal = (memcmp(publicParams.ecPoint.data() + (publicParams.ecPoint.size() - lenPublicKey), bufPublicKey, lenPublicKey) == 0);
        }
        break;
    case KeyAlgo::RSA:
        //  Note: encoded RSAPublicKey (rfc8017 $A.1.1)
        rv_equal = cmpBuffers(publicParams.rsaPublicKey, bufPublicKey, lenPublicKey);
        break;
    default:
        break;
    }
    return rv_equal;
}

bool CryptokiStorage::KeyInfo::isPresent (void) const
{
    return (!keyId.empty());
}

void CryptokiStorage::KeyInfo::reset (void)
{
    keyAlgo = KeyAlgo::UNDEFINED;
    keyType = 0xFFFFFFFF;
    mechType = 0xFFFFFFFF;
    id.clear();
    keyId.clear();
    publicParams.reset();
    mechanismId.clear();
    parameterId.clear();
    label.clear();
    signAlgo.clear();
    hPrivateKey = (CK_OBJECT_HANDLE)-1;
    hPublicKey = (CK_OBJECT_HANDLE)-1;
}


CryptokiStorage::Password::~Password (void)
{
    reset();
}

void CryptokiStorage::Password::reset (void)
{
    if (!empty()) {
        for (auto& it : *this) {
            it = 0x00;
        }
        clear();
    }
}

void CryptokiStorage::Password::set (
    const char* pass
)
{
    reset();
    if (pass) {
        append(pass);
    }
}


CryptokiStorage::CryptokiStorage (
        Helper& iHelper
)
    : m_Session(iHelper)
    , m_ReadOnly(true)
    , m_SupportedKeyDeriveAlgos(SupportedKeyDeriveAlgos{ false, false })
    , m_SupportedKeyWrapAlgos(SupportedKeyWrapAlgos{ false, false })
{
    DEBUG_OUTCON(puts("CryptokiStorage::CryptokiStorage()"));
}

CryptokiStorage::~CryptokiStorage (void)
{
    DEBUG_OUTCON(puts("CryptokiStorage::~CryptokiStorage()"));
    close();
}

CM_ERROR CryptokiStorage::open (
        const CK_SLOT_ID slotId,
        const bool readOnly,
        const string& storageId
)
{
    m_StorageId.clear();
    m_ReadOnly = true;

    TokenInfo token_info;
    CK_RV ck_err = m_Session.getHelper().getTokenInfo(slotId, token_info);
    if (ck_err != CKR_OK) return toCmError(ck_err);

    const CM_ERROR cm_err = getSupportedMechanisms(slotId);
    if (cm_err != RET_OK) return cm_err;

    const CK_FLAGS flags = CKF_SERIAL_SESSION | (readOnly ? 0 : CKF_RW_SESSION);
    ck_err = m_Session.open(slotId, flags);
    if (ck_err != CKR_OK) return RET_CM_STORAGE_NOT_OPEN;

    m_ReadOnly = readOnly;
    m_StorageId = storageId;
    m_TokenInfo = token_info;

    reorder_signalgos(m_SupportedSignAlgos.dstu,  string(OID_DSTU4145_WITH_DSTU7564_256_PB));
    reorder_signalgos(m_SupportedSignAlgos.ecdsa, string(OID_ECDSA_WITH_SHA256));
    reorder_signalgos(m_SupportedSignAlgos.rsa,   string(OID_RSA_WITH_SHA256));

    return RET_OK;
}

CM_ERROR CryptokiStorage::login (
        const CK_USER_TYPE userType,
        const CK_CHAR_PTR pin
)
{
    (void)logout();
    if (!isOpened()) return RET_CM_STORAGE_NOT_OPEN;

    CM_ERROR cm_err = RET_OK;
    const CK_RV ck_err = m_Session.login(userType, pin);
    switch (ck_err) {
    case CKR::OK:
        //  Nothing
        break;
    case CKR::PIN_INCORRECT:
    case CKR::PIN_INVALID:
        cm_err = RET_CM_INVALID_PASSWORD;
        break;
    case CKR::PIN_LEN_RANGE:
    case CKR::PIN_EXPIRED:
    case CKR::PIN_LOCKED:
    default:
        cm_err = RET_CM_NOT_AUTHORIZED;
        break;
    }

    if ((cm_err == RET_OK) && !m_ReadOnly) {
        m_PasswordRwSession.set((const char*)pin);
    }
    return cm_err;
}

CM_ERROR CryptokiStorage::logout (void)
{
    if (!m_Session.isAuthorized()) return RET_OK;

    m_PasswordRwSession.reset();
    return toCmError(m_Session.logout());
}

CM_ERROR CryptokiStorage::close (void)
{
    if (m_Session.isAuthorized()) {
        const CK_RV ck_err = m_Session.logout();
        if (ck_err != CKR_OK) return toCmError(ck_err);
    }

    return toCmError(m_Session.close());
}

CM_ERROR CryptokiStorage::addCert (
        const bool isToken,
        const bool isPrivate,
        const Buffer& bufCertEncoded,
        const Buffer& bufId,
        const string& label,
        const vector<CK_ATTRIBUTE>& attrs,
        CK_OBJECT_HANDLE& hObject
)
{
    hObject = (CK_OBJECT_HANDLE)-1;
    if (bufCertEncoded.empty()) return RET_CM_INVALID_PARAMETER;

    return toCmError(m_Session.addCert(
        isToken,
        isPrivate,
        bufCertEncoded,
        bufId,
        label,
        attrs,
        hObject
    ));
}

CM_ERROR CryptokiStorage::addData (
        const bool isToken,
        const bool isPrivate,
        const bool isModifiable,
        const Buffer& bufData,
        const string& label,
        const string& application,
        const vector<CK_ATTRIBUTE>& attrs,
        CK_OBJECT_HANDLE& hObject
)
{
    hObject = (CK_OBJECT_HANDLE)-1;
    if (bufData.empty()) return RET_CM_INVALID_PARAMETER;

    return toCmError(m_Session.addData(
        isToken,
        isPrivate,
        isModifiable,
        bufData,
        label,
        application,
        attrs,
        hObject
    ));
}

CM_ERROR CryptokiStorage::buildGenKeyPairParams (
        KeyInfo& keyInfo
) const
{
    PublicParams& keyinfo_pubparams = keyInfo.publicParams;

    if (
        (keyInfo.mechanismId == string(OID_DSTU4145_WITH_GOST3411)) ||
        (keyInfo.mechanismId == string(OID_DSTU4145_PARAM_PB_LE))
    ) {
        const EcParamsId ecparam_id = ecid_from_oid(keyInfo.parameterId.c_str());
        if (!find_keyparam(m_SupportedKeyParams.dstuCurves, (uint32_t)ecparam_id)) {
            return RET_CM_UNSUPPORTED_ELLIPTIC_CURVE;
        }
        if (!encodeDstuParams(keyInfo.parameterId, keyinfo_pubparams.ecParams)) return RET_CM_GENERAL_ERROR;

        keyInfo.keyAlgo = KeyAlgo::DSTU;
        keyInfo.keyType = CKK::UKR::DSTU4145;
        keyInfo.mechType = CKM::UKR::DSTU4145_KEY_PAIR_GEN;
    }
    else if (keyInfo.mechanismId == string(OID_EC_KEY)) {
        const EcParamsId ecparam_id = ecid_from_oid(keyInfo.parameterId.c_str());
        if (!find_keyparam(m_SupportedKeyParams.ecdsaCurves, (uint32_t)ecparam_id)) {
            return RET_CM_UNSUPPORTED_ELLIPTIC_CURVE;
        }
        if (!encodeEcdsaParams(keyInfo.parameterId, keyinfo_pubparams.ecParams)) return RET_CM_GENERAL_ERROR;

        keyInfo.keyAlgo = KeyAlgo::ECDSA;
        keyInfo.keyType = CKK::ECDSA;
        keyInfo.mechType = CKM::EC_KEY_PAIR_GEN;
    }
    else if (keyInfo.mechanismId == string(OID_RSA)) {
        uint32_t modulus_bits;
        if (!strToUint32(keyInfo.parameterId, modulus_bits)) {
            return RET_CM_INVALID_PARAMETER;
        }
        if (!find_keyparam(m_SupportedKeyParams.rsaKeySizes, modulus_bits)) {
            return RET_CM_UNSUPPORTED_RSA_LEN;
        }

        keyInfo.keyAlgo = KeyAlgo::RSA;
        keyInfo.keyType = CKK::RSA;                     //  Note: for gen-key RSA not used
        keyInfo.mechType = CKM::RSA_PKCS_KEY_PAIR_GEN;  //  Note: for gen-key RSA not used
        keyInfo.parameterId = to_string(modulus_bits);
    }
    else {
        return RET_CM_UNSUPPORTED_ALG;
    }

    return RET_OK;
}

CM_ERROR CryptokiStorage::changePassword (
        const char* newPassword
)
{
    const CK_RV ck_err = m_Session.setPin((CK_CHAR_PTR)m_PasswordRwSession.c_str(), (CK_CHAR_PTR)newPassword);
    if (ck_err == CKR_OK) {
        m_PasswordRwSession.set(newPassword);
    }
    return toCmError(ck_err);
}

CM_ERROR CryptokiStorage::deleteFile (
        const CK_OBJECT_HANDLE hObject
)
{
    return toCmError(m_Session.destroyObject(hObject));
}

CM_ERROR CryptokiStorage::deleteKey (
        const KeyInfo& keyInfo
)
{
    if (cmpBuffers(selectedKey().keyId, keyInfo.keyId)) {
        //  Deselect deleting key
        selectKey();
    }

    const CM_ERROR cm_err = deleteFile(keyInfo.hPrivateKey);
    return cm_err;
}

CM_ERROR CryptokiStorage::findCerts (
        const bool isPrivate,
        const string& application,
        vector<CK_OBJECT_HANDLE>& objCerts
)
{
    CM_ERROR cm_err = findFiles(isPrivate, CKO::CERTIFICATE, objCerts);
    if (cm_err != RET_OK) return cm_err;

    cm_err = findCertsInData(isPrivate, application, objCerts);
    return cm_err;
}

CM_ERROR CryptokiStorage::findCertsInData (
        const bool isPrivate,
        const string& application,
        vector<CK_OBJECT_HANDLE>& objCerts
)
{
    const CK_OBJECT_CLASS obj_type = CKO::DATA;
    const CK_BBOOL is_private = isPrivate;
    const vector<CK_ATTRIBUTE> template_files = {
        { CKA::CLASS, (CK_VOID_PTR)&obj_type, sizeof(obj_type) },
        { CKA::TOKEN, (CK_VOID_PTR)&ATTRIBUTE_TRUE, sizeof(ATTRIBUTE_TRUE) },
        { CKA::PRIVATE, (CK_VOID_PTR)&is_private, sizeof(is_private) },
        { CKA::APPLICATION, (CK_VOID_PTR)application.data(), (CK_ULONG)application.length() }
    };
    return toCmError(m_Session.findObjects(template_files, objCerts));
}

CM_ERROR CryptokiStorage::findFiles (
        const bool isPrivate,
        const CK_OBJECT_CLASS objType,
        vector<CK_OBJECT_HANDLE>& objFiles
)
{
    return toCmError(m_Session.findFiles(
        true,
        isPrivate,
        objType,
        objFiles
    ));
}

CM_ERROR CryptokiStorage::findKeyPairs (
        vector<KeyInfo>& keyInfos
)
{
    vector<CK_OBJECT_HANDLE> list_privkeyobjects;
    const CK_RV ck_err = m_Session.findFiles(
        true,
        true,
        CKO::PRIVATE_KEY,
        list_privkeyobjects
    );
    if (ck_err != CKR_OK) return toCmError(ck_err);

    for (const auto& it : list_privkeyobjects) {
        KeyInfo key_info;
        const CM_ERROR cm_err = getKeyInfo(it, key_info);
        if ((cm_err == RET_OK) && key_info.isPresent()) {
            keyInfos.push_back(key_info);
        }
    }

    return RET_OK;
}

CM_ERROR CryptokiStorage::findObjects (
        const vector<CK_ATTRIBUTE>& findObjAttrs,
        vector<CK_OBJECT_HANDLE>& objects
)
{
    return toCmError(m_Session.findObjects(findObjAttrs, objects));
}

CM_ERROR CryptokiStorage::generateKeyPair (
        const GenerateKeyFlags& flags,
        KeyInfo& keyInfo
)
{
    DEBUG_OUTCON(printf("CryptokiStorage::generateKeyPair(): keyAlgo=%d  label='%s'\n", keyInfo.keyAlgo, keyInfo.label.c_str()));

    //  Generate 8 random printable chars
    SmartBA sba_buf;
    if (!sba_buf.set(ba_alloc_by_len(6))) return RET_CM_GENERAL_ERROR;

    CK_RV ck_err = m_Session.generateRandom((CK_BYTE_PTR)sba_buf.buf(), (const CK_ULONG)6);
    if (ck_err != CKR_OK) return toCmError(ck_err);

    size_t len_id = 9;
    keyInfo.id.resize(len_id);
    if (ba_to_base64(sba_buf.get(), (char*)keyInfo.id.data(), &len_id) != RET_OK) return RET_CM_GENERAL_ERROR;
    keyInfo.id.resize(len_id - 1);

    const CK_ATTRIBUTE attr_derive = { CKA::DERIVE, (CK_VOID_PTR)&ATTRIBUTE_TRUE, sizeof(ATTRIBUTE_TRUE) };
    const CK_ATTRIBUTE attr_nonextractable = { CKA::EXTRACTABLE, (CK_VOID_PTR)&ATTRIBUTE_FALSE, sizeof(ATTRIBUTE_FALSE) };
    const CK_ATTRIBUTE attr_token = { CKA::TOKEN, (CK_VOID_PTR)&ATTRIBUTE_TRUE, sizeof(ATTRIBUTE_TRUE) };
    vector<CK_ATTRIBUTE> template_publickey, template_privatekey;

    template_publickey.push_back(attr_token);
    template_privatekey.push_back(attr_nonextractable);
    if (flags.keyAgreement) template_privatekey.push_back(attr_derive);

    PublicParams& keyinfo_pubparams = keyInfo.publicParams;
    uint32_t modulus_bits = 0;

    switch (keyInfo.keyAlgo) {
    case KeyAlgo::DSTU:
        ck_err = m_Session.generateKeyPairDstu(
            keyInfo.mechType,
            keyInfo.keyType,
            keyinfo_pubparams.ecParams,
            keyInfo.id,
            keyInfo.label,
            template_publickey,
            template_privatekey,
            keyInfo.hPublicKey,
            keyInfo.hPrivateKey
        );
        break;
    case KeyAlgo::ECDSA:
        ck_err = m_Session.generateKeyPairEcdsa(
            keyInfo.mechType,
            keyInfo.keyType,
            keyinfo_pubparams.ecParams,
            keyInfo.id,
            keyInfo.label,
            template_publickey,
            template_privatekey,
            keyInfo.hPublicKey,
            keyInfo.hPrivateKey
        );
        break;
    case KeyAlgo::RSA:
        (void)strToUint32(keyInfo.parameterId, modulus_bits);
        ck_err = m_Session.generateKeyPairRsa(
            //  not used: keyInfo.mechType,
            //  not used: keyInfo.keyType,
            modulus_bits,
            Buffer(),// Use default publicExponent
            keyInfo.id,
            keyInfo.label,
            template_publickey,
            template_privatekey,
            keyInfo.hPublicKey,
            keyInfo.hPrivateKey
        );
        break;
    default:
        break;
    }

    return toCmError(ck_err);
}

CM_ERROR CryptokiStorage::getKeyInfo (
        const CK_OBJECT_HANDLE hObject,
        KeyInfo& keyInfo
)
{
    DEBUG_OUTCON(printf("CryptokiStorage::getKeyInfo(%d)\n", hObject));
    keyInfo = KeyInfo();
    keyInfo.hPrivateKey = hObject;

    CK_RV ck_err = m_Session.getAttributeBuffer(keyInfo.hPrivateKey, CKA::ID, keyInfo.id);
    if (ck_err != CKR_OK) return toCmError(ck_err);

    ck_err = m_Session.getAttributeText(keyInfo.hPrivateKey, CKA::LABEL, keyInfo.label);
    if (ck_err != CKR_OK) return toCmError(ck_err);

    const CK_ATTRIBUTE attr_keytype {
        CKA::KEY_TYPE, (CK_VOID_PTR)&keyInfo.keyType, (CK_ULONG)sizeof(keyInfo.keyType)
    };
    ck_err = m_Session.getAttributeValue(keyInfo.hPrivateKey, (CK_ATTRIBUTE_PTR)&attr_keytype);
    if (ck_err != CKR_OK) return toCmError(ck_err);

    switch (keyInfo.keyType) {
    case CKK::UKR::DSTU4145:    keyInfo.keyAlgo = KeyAlgo::DSTU;  break;
    case CKK::ECDSA:            keyInfo.keyAlgo = KeyAlgo::ECDSA; break;
    case CKK::RSA:              keyInfo.keyAlgo = KeyAlgo::RSA;   break;
    default: return RET_CM_UNSUPPORTED_ALG;
    }

    const vector<CK_ATTRIBUTE> template_pubkey = {
        { CKA::CLASS,   (CK_VOID_PTR)&CKO::PUBLIC_KEY,  sizeof(CKO::PUBLIC_KEY) },
        { CKA::ID,      (CK_VOID_PTR)keyInfo.id.data(), (CK_ULONG)keyInfo.id.size() }
    };

    vector<CK_OBJECT_HANDLE> list_pubkeyobjects;
    ck_err = m_Session.findObjects(template_pubkey, list_pubkeyobjects);
    if (ck_err != CKR_OK) return toCmError(ck_err);

    if (list_pubkeyobjects.size() != 1) return RET_CM_TOKEN_ERROR;
    keyInfo.hPublicKey = list_pubkeyobjects[0];

    CM_ERROR cm_err = RET_OK;
    switch (keyInfo.keyAlgo) {
    case KeyAlgo::DSTU:     cm_err = getKeyInfoDstu(keyInfo);  break;
    case KeyAlgo::ECDSA:    cm_err = getKeyInfoEcdsa(keyInfo); break;
    case KeyAlgo::RSA:      cm_err = getKeyInfoRsa(keyInfo);   break;
    default: break;
    }

    DEBUG_OUTCON(buf_print("  keyInfo.id, hex: ", keyInfo.id.data(), keyInfo.id.size()));
    return cm_err;
}

CM_ERROR CryptokiStorage::randomBytes (
        CM_BYTEARRAY* baBuffer
)
{
    const CK_ULONG len = (CK_ULONG)baBuffer->len;
    if (len == 0) return RET_CM_INVALID_PARAMETER;

    return toCmError(m_Session.generateRandom((CK_BYTE_PTR)baBuffer->buf, len));
}

CM_ERROR CryptokiStorage::readFile (
        const CK_OBJECT_HANDLE hObject,
        CM_BYTEARRAY** baData
)
{
    CK_ULONG vlen = 0;
    CK_RV ck_err = m_Session.getAttributeSize(hObject, CKA::VALUE, vlen);
    if (ck_err != CKR_OK) return toCmError(ck_err);

    ByteArray* ba_data = ba_alloc_by_len(vlen);
    if (!ba_data) return RET_CM_GENERAL_ERROR;

    CK_ATTRIBUTE attr_value = {
        CKA::VALUE, (CK_VOID_PTR)ba_get_buf(ba_data), vlen
    };
    ck_err = m_Session.getAttributeValue(hObject, (CK_ATTRIBUTE_PTR)&attr_value);
    if (ck_err != CKR_OK) {
        ba_free(ba_data);
        return toCmError(ck_err);
    }

    *baData = (CM_BYTEARRAY*)ba_data;
    return RET_OK;
}

CM_ERROR CryptokiStorage::readFile (
        const CK_OBJECT_HANDLE hObject,
        Cryptoki::Buffer& bufData
)
{
    CK_ULONG vlen = 0;
    CK_RV ck_err = m_Session.getAttributeSize(hObject, CKA::VALUE, vlen);
    if (ck_err != CKR_OK) return toCmError(ck_err);

    bufData.resize(vlen);
    if (vlen == 0) return RET_OK;

    CK_ATTRIBUTE attr_value = {
        CKA::VALUE, (CK_VOID_PTR)bufData.data(), vlen
    };
    ck_err = m_Session.getAttributeValue(hObject, (CK_ATTRIBUTE_PTR)&attr_value);
    if (ck_err != CKR_OK) {
        bufData.clear();
        return toCmError(ck_err);
    }

    return RET_OK;
}

void CryptokiStorage::selectKey (
        const KeyInfo& keyInfo
)
{
    m_SelectedKey = keyInfo;
}

const char* CryptokiStorage::signAlgoByDefault (
        const KeyInfo& keyInfo
) const
{
    const char* rv_signalgo = nullptr;
    switch (keyInfo.keyAlgo) {
    case KeyAlgo::DSTU:
        rv_signalgo = (!m_SupportedSignAlgos.dstu.empty()) ? m_SupportedSignAlgos.dstu[0].c_str() : nullptr;
        break;
    case KeyAlgo::ECDSA:
        rv_signalgo = (!m_SupportedSignAlgos.ecdsa.empty()) ? m_SupportedSignAlgos.ecdsa[0].c_str() : nullptr;
        break;
    case KeyAlgo::RSA:
        rv_signalgo = (!m_SupportedSignAlgos.rsa.empty()) ? m_SupportedSignAlgos.rsa[0].c_str() : nullptr;
        break;
    default:
        break;
    }
    return rv_signalgo;
}

CM_ERROR CryptokiStorage::signData (
        const KeyInfo& keyInfo,
        const string& signAlgo,    //  Parameter signAlgo must be contains oid-string
        const CM_BYTEARRAY* baSignAlgoParams,
        const CM_BYTEARRAY* baData,
        CM_BYTEARRAY** baSignature
)
{
    const HashAlg hash_algo = hashAlgBySignAlgo(keyInfo, signAlgo);
    if (hash_algo == HASH_ALG_UNDEFINED) return RET_CM_UNSUPPORTED_ALG;

    SmartBA sba_hash;
    int ret = ::hash(hash_algo, (const ByteArray*)baData, &sba_hash);
    if (ret != RET_OK) return (CM_ERROR)ret;

    const CM_ERROR cm_err = signHash(
        keyInfo,
        signAlgo,
        baSignAlgoParams,
        (const CM_BYTEARRAY*)sba_hash.get(),
        baSignature
    );
    return cm_err;
}

CM_ERROR CryptokiStorage::signHash (
        const KeyInfo& keyInfo,
        const string& signAlgo,
        const CM_BYTEARRAY* baSignAlgoParams,
        const CM_BYTEARRAY* baHash,
        CM_BYTEARRAY** baSignature
)
{
    //  Check support signAlgo
    bool is_found = false;
    for (const auto& it : keyInfo.signAlgo) {
        is_found = (it == signAlgo);
        if (is_found) break;
    }
    if (!is_found) return RET_CM_UNSUPPORTED_ALG;

    const CK_MECHANISM mech_param = { keyInfo.mechType, NULL_PTR, 0 };
    Buffer buf_hashvalue, buf_signvalue;

    switch (keyInfo.keyAlgo) {
    case KeyAlgo::DSTU:
    case KeyAlgo::ECDSA:
        if (!bufferFromBa((const ByteArray*)baHash, buf_hashvalue)) return RET_CM_GENERAL_ERROR;
        break;
    case KeyAlgo::RSA:
        if (!encode_digestinfo(
            hashAlgBySignAlgo(keyInfo, signAlgo),
            (const ByteArray*)baHash,
            buf_hashvalue)
        ) return RET_CM_GENERAL_ERROR;
        break;
    default:
        return RET_CM_UNSUPPORTED_ALG;
    }

    const CK_RV ck_err = m_Session.signHash(
        keyInfo.hPrivateKey,
        (CK_MECHANISM_PTR)&mech_param,
        buf_hashvalue,
        buf_signvalue
    );
    if (ck_err != CKR_OK) return toCmError(ck_err);

    switch (keyInfo.keyAlgo) {
    case KeyAlgo::DSTU:
    case KeyAlgo::RSA:
        *baSignature = (CM_BYTEARRAY*)bufferToBa(buf_signvalue);
        break;
    case KeyAlgo::ECDSA:
        (void)encodeEcdsaSignvalue(buf_signvalue, baSignature);
        break;
    default:
        break;
    }

    return (*baSignature) ? RET_OK : RET_CM_GENERAL_ERROR;
}

CM_ERROR CryptokiStorage::dhWrapKey (
        const KeyInfo& keyInfo,
        bool isStaticKey,
        const char* oidDhKdf,
        const char* oidWrapAlgo,
        const size_t count,
        const CM_BYTEARRAY** abaSpkis,
        const CM_BYTEARRAY** abaSessionKeys,
        CM_BYTEARRAY*** abaSalts,
        CM_BYTEARRAY*** abaWrappedKeys
)
{
    DeriveWrapKeyParams dwk_params = { 0, 0, 0, 0, 0 };
    bool with_cofactor;
    const HashAlg hash_algo = hash_from_oid_dhkdf(oidDhKdf, with_cofactor);
    if (hash_algo == HASH_ALG_UNDEFINED) {
        return RET_CM_UNSUPPORTED_KEY_DERIVATION_FUNC_ALG;
    }
    dwk_params.deriveMechType = with_cofactor ? CKM::UKR::DSTU4145_ECDH_COFACTOR_DERIVE : CKM::UKR::DSTU4145_ECDH_DERIVE;

    if (oid_is_equal(OID_DSTU7624_WRAP, oidWrapAlgo)) {
        dwk_params.kdf = CKD::UKR::KUPYNA256_KDF;
        dwk_params.deriveKeyType = CKK::UKR::KALYNA256;
        dwk_params.wrapKeyType = CKK::UKR::KALYNA256;
        dwk_params.wrapMechType = CKM::UKR::KALYNA256_WRAP;
    }
    else if (oid_is_equal(OID_GOST28147_WRAP, oidWrapAlgo)) {
        dwk_params.kdf = CKD::UKR::GOST34311_KDF;
        dwk_params.deriveKeyType = CKK::UKR::GOST28147;
        dwk_params.wrapKeyType = CKK::UKR::GOST28147;
        dwk_params.wrapMechType = CKM::UKR::GOST28147_WRAP;
    }
    else return RET_CM_UNSUPPORTED_CIPHER_ALG;

    for (size_t i = 0; i < count; i++) {
        if (!abaSpkis[i] || !abaSessionKeys[i]) {
            return RET_CM_INVALID_PARAMETER;
        }
    }

    ByteArray** aba_salts = nullptr;
    if (isStaticKey) {
        aba_salts = (ByteArray**)calloc(sizeof(ByteArray*), count);
        if (!aba_salts) return RET_CM_GENERAL_ERROR;
    }

    ByteArray** aba_wrappedkeys = (ByteArray**)calloc(sizeof(ByteArray*), count);
    if (!aba_wrappedkeys) {
        ::free(aba_salts);
        return RET_CM_GENERAL_ERROR;
    }

    int ret = RET_OK;
    CK_OBJECT_HANDLE h_derivedkey = (CK_OBJECT_HANDLE)-1;
    for (size_t i = 0; i < count; i++) {
        DEBUG_OUTCON(printf("CryptokiStorage::dhWrapKey(), wrap key [%zu]\n", i));

        if (isStaticKey) {
            ByteArray* ba_salt = aba_salts[i] = ba_alloc_by_len(64);
            if (!ba_salt) {
                SET_ERROR(RET_CM_GENERAL_ERROR);
            }
            DO((int)randomBytes((CM_BYTEARRAY*)aba_salts[i]));
        }

        DO((int)getDerivedKey(
            keyInfo,
            dwk_params,
            abaSpkis[i],
            isStaticKey ? (const CM_BYTEARRAY*)aba_salts[i] : nullptr,
            h_derivedkey
        ));

        Buffer buf_wrappedkey;
        DO((int)getWrappedKey(
            h_derivedkey,
            dwk_params,
            abaSessionKeys[i],
            buf_wrappedkey
        ));

        (void)m_Session.destroyObject(h_derivedkey);
        h_derivedkey = (CK_OBJECT_HANDLE)-1;

        aba_wrappedkeys[i] = bufferToBa(buf_wrappedkey);
        if (aba_wrappedkeys[i] == nullptr) {
            SET_ERROR(RET_CM_GENERAL_ERROR);
        }

        DEBUG_OUTCON(buf_print("baWrappedKey:\n  ", ba_get_buf(aba_wrappedkeys[i]), ba_get_len(aba_wrappedkeys[i])));
    }

    *abaSalts = (CM_BYTEARRAY**)aba_salts;
    aba_salts = nullptr;
    *abaWrappedKeys = (CM_BYTEARRAY**)aba_wrappedkeys;
    aba_wrappedkeys = nullptr;

cleanup:
    if (ret != RET_OK) {
        for (size_t i = 0; i < count; i++) {
            if (aba_salts) ba_free(aba_salts[i]);
            if (aba_wrappedkeys) ba_free(aba_wrappedkeys[i]);
        }
    }
    ::free(aba_wrappedkeys);
    ::free(aba_salts);
    if (h_derivedkey != (CK_OBJECT_HANDLE)-1) {
        (void)m_Session.destroyObject(h_derivedkey);
    }
    return (CM_ERROR)ret;
}

CM_ERROR CryptokiStorage::dhUnwrapKey (
        const KeyInfo& keyInfo,
        const char* oidDhKdf,
        const char* oidWrapAlgo,
        const size_t count,
        const CM_BYTEARRAY** abaSpkis,
        const CM_BYTEARRAY** abaSalts,
        const CM_BYTEARRAY** abaWrappedKeys,
    CM_BYTEARRAY*** abaSessionKeys
)
{
    DeriveWrapKeyParams dwk_params = { 0, 0, 0, 0, 0 };
    bool with_cofactor;
    const HashAlg hash_algo = hash_from_oid_dhkdf(oidDhKdf, with_cofactor);
    if (hash_algo == HASH_ALG_UNDEFINED) {
        return RET_CM_UNSUPPORTED_KEY_DERIVATION_FUNC_ALG;
    }
    dwk_params.deriveMechType = with_cofactor ? CKM::UKR::DSTU4145_ECDH_COFACTOR_DERIVE : CKM::UKR::DSTU4145_ECDH_DERIVE;

    if (oid_is_equal(OID_DSTU7624_WRAP, oidWrapAlgo)) {
        dwk_params.kdf = CKD::UKR::KUPYNA256_KDF;
        dwk_params.deriveKeyType = CKK::UKR::KALYNA256;
        dwk_params.wrapKeyType = CKK::UKR::KALYNA256;
        dwk_params.wrapMechType = CKM::UKR::KALYNA256_WRAP;
    }
    else if (oid_is_equal(OID_GOST28147_WRAP, oidWrapAlgo)) {
        dwk_params.kdf = CKD::UKR::GOST34311_KDF;
        dwk_params.deriveKeyType = CKK::UKR::GOST28147;
        dwk_params.wrapKeyType = CKK::UKR::GOST28147;
        dwk_params.wrapMechType = CKM::UKR::GOST28147_WRAP;
    }
    else return RET_CM_UNSUPPORTED_CIPHER_ALG;

    for (size_t i = 0; i < count; i++) {
        if (!abaSpkis[i] || !abaWrappedKeys[i]) {
            return RET_CM_INVALID_PARAMETER;
        }
    }

    ByteArray** aba_sessionkeys = (ByteArray**)calloc(sizeof(ByteArray*), count);
    if (!aba_sessionkeys) return RET_CM_GENERAL_ERROR;

    int ret = RET_OK;
    CK_OBJECT_HANDLE h_derivedkey = (CK_OBJECT_HANDLE)-1;
    for (size_t i = 0; i < count; i++) {
        DEBUG_OUTCON(printf("CryptokiStorage::dhUnwrapKey(), unwrap key [%zu]\n", i));

        DO((int)getDerivedKey(
            keyInfo,
            dwk_params,
            abaSpkis[i],
            (abaSalts) ? abaSalts[i] : nullptr,
            h_derivedkey
        ));

        Buffer buf_sessionkey;
        DO((int)getUnwrappedKey(
            h_derivedkey,
            dwk_params,
            abaWrappedKeys[i],
            buf_sessionkey
        ));

        (void)m_Session.destroyObject(h_derivedkey);
        h_derivedkey = (CK_OBJECT_HANDLE)-1;

        aba_sessionkeys[i] = bufferToBa(buf_sessionkey);
        if (aba_sessionkeys[i] == nullptr) {
            SET_ERROR(RET_CM_GENERAL_ERROR);
        }

        DEBUG_OUTCON(buf_print("baSessionKey:\n  ", ba_get_buf(aba_sessionkeys[i]), ba_get_len(aba_sessionkeys[i])));
    }

    *abaSessionKeys = (CM_BYTEARRAY**)aba_sessionkeys;
    aba_sessionkeys = nullptr;

cleanup:
    if ((ret != RET_OK) && aba_sessionkeys) {
        for (size_t i = 0; i < count; i++) {
            ba_free(aba_sessionkeys[i]);
        }
    }
    ::free(aba_sessionkeys);
    if (h_derivedkey != (CK_OBJECT_HANDLE)-1) {
        (void)m_Session.destroyObject(h_derivedkey);
    }
    return (CM_ERROR)ret;
}

CM_ERROR CryptokiStorage::getDerivedKey (
        const KeyInfo& keyInfo,
        const DeriveWrapKeyParams& dwkParams,
        const CM_BYTEARRAY* baSpki,
        const CM_BYTEARRAY* baSalt,
        CK_OBJECT_HANDLE& hDerivedKey
)
{
    SmartBA sba_ecpoint;
    CM_ERROR cm_err = (CM_ERROR)spki_get_encappubkey((const ByteArray*)baSpki, &sba_ecpoint);
    if (cm_err != RET_OK) return cm_err;

    CK_ECDH1_DERIVE_PARAMS derive_params = { 
        dwkParams.kdf,
        baSalt ? (CK_ULONG)baSalt->len : 0,
        baSalt ? (CK_BYTE_PTR)baSalt->buf : nullptr,
        (CK_ULONG)sba_ecpoint.size(),
        (CK_BYTE_PTR)sba_ecpoint.buf()
    };
    const CK_MECHANISM mech_param = {
        dwkParams.deriveMechType,
        (CK_VOID_PTR)&derive_params,
        sizeof(derive_params)
    };
    const CK_OBJECT_CLASS obj_type = CKO::SECRET_KEY;
    const vector<CK_ATTRIBUTE> derivekey_attrs = {
        { CKA::CLASS, (CK_VOID_PTR)&obj_type, sizeof(obj_type) },
        { CKA::KEY_TYPE, (CK_VOID_PTR)&dwkParams.deriveKeyType, sizeof(dwkParams.deriveKeyType) },
        { CKA::WRAP, (CK_VOID_PTR)&ATTRIBUTE_TRUE, sizeof(ATTRIBUTE_TRUE) },
        { CKA::UNWRAP, (CK_VOID_PTR)&ATTRIBUTE_TRUE, sizeof(ATTRIBUTE_TRUE) },
        { CKA::TOKEN, (CK_VOID_PTR)&ATTRIBUTE_FALSE, sizeof(ATTRIBUTE_FALSE) }
    };

    CK_RV ck_err = m_Session.deriveKey(
        (const CK_MECHANISM_PTR)&mech_param,
        keyInfo.hPrivateKey,
        derivekey_attrs,
        hDerivedKey
    );
    if (ck_err == CKR_ENCRYPTED_DATA_INVALID) {
        //  Note:
        //      this features the PKCS11-lib implementation by Avtor - when there are many keys,
        //      then an error CKR_ENCRYPTED_DATA_INVALID (non-specified for it API) may appear in C_DeriveKey()
        ck_err = CKR_DEVICE_MEMORY;
    }
    return toCmError(ck_err);
}

CM_ERROR CryptokiStorage::getDomainParameters (void)
{
    CM_ERROR cm_err = RET_OK;
    if (!m_SupportedSignAlgos.dstu.empty() || !m_SupportedSignAlgos.ecdsa.empty()) {
        const CK_OBJECT_CLASS obj_type = CKO::DOMAIN_PARAMETERS;
        const vector<CK_ATTRIBUTE> template_domainparams = {
            { CKA::CLASS, (CK_VOID_PTR)&obj_type, sizeof(obj_type) }
        };
        vector<CK_OBJECT_HANDLE> obj_domainparams;
        cm_err = findObjects(template_domainparams, obj_domainparams);
        if (cm_err != RET_OK) return cm_err;

        std::vector<EcParamsId> dstu_domainparams, ecdsa_domainparams;
        for (const auto& it : obj_domainparams) {
            vector<CK_ATTRIBUTE> template_domainparam = {
                { CKA::KEY_TYPE, NULL_PTR, 0 },
                { CKA::LABEL, NULL_PTR, 0 }
            };
            cm_err = m_Session.getAttributeValue(it, template_domainparam);
            if (cm_err != RET_OK) return cm_err;

            if ((template_domainparam[0].ulValueLen == sizeof(CK_KEY_TYPE)) && (template_domainparam[1].ulValueLen >= 3)) {
                CK_KEY_TYPE key_type = (CK_KEY_TYPE)-1;
                string s_ecparamid;

                template_domainparam[0].pValue = (CK_VOID_PTR)&key_type;
                s_ecparamid.resize(template_domainparam[1].ulValueLen);
                template_domainparam[1].pValue = (CK_VOID_PTR)s_ecparamid.data();

                cm_err = m_Session.getAttributeValue(it, template_domainparam);
                if (cm_err != RET_OK) return cm_err;

                const EcParamsId ecparam_id = ecid_from_oid(s_ecparamid.c_str());
                if (key_type == CKK::UKR::DSTU4145) {
                    if ((ecparam_id >= EC_PARAMS_ID_DSTU4145_M233_PB) && (ecparam_id <= EC_PARAMS_ID_DSTU4145_M431_PB)) {
                        dstu_domainparams.push_back(ecparam_id);
                    }
                }
                else if (key_type == CKK::ECDSA) {
                    if ((ecparam_id >= EC_PARAMS_ID_NIST_P256) && (ecparam_id <= EC_PARAMS_ID_NIST_P521)) {
                        ecdsa_domainparams.push_back(ecparam_id);
                    }
                }
            }
        }

        //todo: dstu_domainparams and ecdsa_domainparams - now it unused
    }

    return RET_OK;
}

CM_ERROR CryptokiStorage::getKeyInfoDstu (
        KeyInfo& keyInfo
)
{
    PublicParams& keyinfo_pubparams = keyInfo.publicParams;
    keyInfo.mechType = CKM::UKR::DSTU4145;
    keyInfo.mechanismId = string(OID_DSTU4145_PARAM_PB_LE);

    CK_RV ck_err = m_Session.getAttributeBuffer(keyInfo.hPublicKey, CKA::EC_PARAMS, keyinfo_pubparams.ecParams);
    if (ck_err != CKR_OK) return toCmError(ck_err);

    ck_err = m_Session.getAttributeBuffer(keyInfo.hPublicKey, CKA::EC_POINT, keyinfo_pubparams.ecPoint);
    if (ck_err != CKR_OK) return toCmError(ck_err);

    if (!decodeDstuParams(keyinfo_pubparams.ecParams, keyInfo.parameterId)) return RET_CM_TOKEN_ERROR;

    CM_ERROR cm_err = calcKeyId(
        HASH_ALG_GOST34311,
        keyinfo_pubparams.ecPoint,
        keyInfo.keyId
    );
    if (cm_err != RET_OK) return cm_err;

    cm_err = calcKeyId(
        HASH_ALG_DSTU7564_256,
        keyinfo_pubparams.ecPoint,
        keyInfo.keyId2
    );
    if (cm_err != RET_OK) return cm_err;

    keyInfo.signAlgo = m_SupportedSignAlgos.dstu;
    return RET_OK;
}

CM_ERROR CryptokiStorage::getKeyInfoEcdsa (
        KeyInfo& keyInfo
)
{
    PublicParams& keyinfo_pubparams = keyInfo.publicParams;
    keyInfo.mechType = CKM::ECDSA;
    keyInfo.mechanismId = string(OID_EC_KEY);

    CK_RV ck_err = m_Session.getAttributeBuffer(keyInfo.hPublicKey, CKA::EC_PARAMS, keyinfo_pubparams.ecParams);
    if (ck_err != CKR_OK) return toCmError(ck_err);

    //  Note: also ECDSA use encapsulated OCTET_STRING for pkcs11
    ck_err = m_Session.getAttributeBuffer(keyInfo.hPublicKey, CKA::EC_POINT, keyinfo_pubparams.ecPoint);
    if (ck_err != CKR_OK) return toCmError(ck_err);

    if (!decodeEcdsaParams(keyinfo_pubparams.ecParams, keyInfo.parameterId)) return RET_CM_TOKEN_ERROR;

    SmartBA sba_ecpoint, sba_pubkey;
    Buffer buf_pubkey;
    if (
        !sba_ecpoint.set(bufferToBa(keyinfo_pubparams.ecPoint)) ||
        (Util::decodeOctetString(sba_ecpoint.get(), &sba_pubkey) != RET_OK) ||
        !bufferFromBa(sba_pubkey.get(), buf_pubkey)
    ) return RET_CM_GENERAL_ERROR;

    const CM_ERROR cm_err = calcKeyId(
        HASH_ALG_SHA1,
        buf_pubkey,
        keyInfo.keyId
    );
    if (cm_err != RET_OK) return cm_err;

    keyInfo.signAlgo = m_SupportedSignAlgos.ecdsa;
    return RET_OK;
}

CM_ERROR CryptokiStorage::getKeyInfoRsa (
        KeyInfo& keyInfo
)
{
    PublicParams& keyinfo_pubparams = keyInfo.publicParams;
    keyInfo.mechType = CKM::RSA_PKCS;
    keyInfo.mechanismId = string(OID_RSA);

    CK_ULONG modulus_bits = 0;
    CK_ATTRIBUTE template_data = { CKA::MODULUS_BITS, (CK_VOID_PTR)&modulus_bits, sizeof(modulus_bits)};
    CK_RV ck_err = m_Session.getAttributeValue(keyInfo.hPublicKey, (CK_ATTRIBUTE_PTR)&template_data);
    if (ck_err != CKR_OK) return ck_err;
    keyInfo.parameterId = to_string(modulus_bits);

    ck_err = m_Session.getAttributeBuffer(keyInfo.hPublicKey, CKA::MODULUS, keyinfo_pubparams.rsaModulus);
    if (ck_err != CKR_OK) return toCmError(ck_err);

    ck_err = m_Session.getAttributeBuffer(keyInfo.hPublicKey, CKA::PUBLIC_EXPONENT, keyinfo_pubparams.rsaExponent);
    if (ck_err != CKR_OK) return toCmError(ck_err);

    if (!encodeRsaPublicKey(
        keyinfo_pubparams.rsaModulus,
        keyinfo_pubparams.rsaExponent,
        keyinfo_pubparams.rsaPublicKey
    )) return RET_CM_TOKEN_ERROR;

    const CM_ERROR cm_err = calcKeyId(
        HASH_ALG_SHA1,
        keyinfo_pubparams.rsaPublicKey,
        keyInfo.keyId
    );
    if (cm_err != RET_OK) return cm_err;

    keyInfo.signAlgo = m_SupportedSignAlgos.rsa;
    return RET_OK;
}

CM_ERROR CryptokiStorage::getSupportedMechanisms (
        const CK_SLOT_ID slotId
)
{
    Helper& helper = m_Session.getHelper();
    vector<CK_MECHANISM_TYPE> mech_types;
    MechanismInfo mech_info;
    CK_RV ck_err = helper.getMechanismList(slotId, mech_types);
    if (ck_err != CKR_OK) return toCmError(ck_err);

    //  Asym algos
    bool is_dstu4145 = false;
    bool is_ecdsa = false;
    bool is_rsa = false;
    //  Sign algos
    bool dstu_signalgos[4]  = { false, false, false, false };
    bool ecdsa_signalgos[9] = { false, false, false, false, false, false, false, false, false };
    bool rsa_signalgos[9]   = { false, false, false, false, false, false, false, false, false };

    for (const auto& it : mech_types) {
        //  DSTU-4145
        if (it == CKM::UKR::DSTU4145) is_dstu4145 = true;
        if (it == CKM::UKR::DSTU4145_WITH_GOST34311) dstu_signalgos[0] = true;
        if (it == CKM::UKR::DSTU4145_WITH_KUPYNA256) dstu_signalgos[1] = true;
        if (it == CKM::UKR::DSTU4145_WITH_KUPYNA384) dstu_signalgos[2] = true;
        if (it == CKM::UKR::DSTU4145_WITH_KUPYNA512) dstu_signalgos[3] = true;
        if (it == CKM::UKR::DSTU4145_ECDH_DERIVE)           m_SupportedKeyDeriveAlgos.dstu = true;
        if (it == CKM::UKR::DSTU4145_ECDH_COFACTOR_DERIVE)  m_SupportedKeyDeriveAlgos.dstuCofactor = true;
        if (it == CKM::UKR::GOST28147_WRAP)         m_SupportedKeyWrapAlgos.gost28147wrap = true;
        if (it == CKM::UKR::KALYNA256_WRAP)         m_SupportedKeyWrapAlgos.kalyna256wrap = true;

        //  ECDSA
        if (it == CKM::ECDSA) is_ecdsa = true;
        if (it == CKM::ECDSA_WITH_SHA1)     ecdsa_signalgos[0] = true;
        if (it == CKM::ECDSA_WITH_SHA224)   ecdsa_signalgos[1] = true;
        if (it == CKM::ECDSA_WITH_SHA256)   ecdsa_signalgos[2] = true;
        if (it == CKM::ECDSA_WITH_SHA384)   ecdsa_signalgos[3] = true;
        if (it == CKM::ECDSA_WITH_SHA512)   ecdsa_signalgos[4] = true;
        if (it == CKM::ECDSA_WITH_SHA3_224) ecdsa_signalgos[5] = true;
        if (it == CKM::ECDSA_WITH_SHA3_256) ecdsa_signalgos[6] = true;
        if (it == CKM::ECDSA_WITH_SHA3_384) ecdsa_signalgos[7] = true;
        if (it == CKM::ECDSA_WITH_SHA3_512) ecdsa_signalgos[8] = true;

        //  RSA
        if (it == CKM::RSA_PKCS) is_rsa = true;
        if (it == CKM::RSA_WITH_SHA1)       rsa_signalgos[0] = true;
        if (it == CKM::RSA_WITH_SHA224)     rsa_signalgos[1] = true;
        if (it == CKM::RSA_WITH_SHA256)     rsa_signalgos[2] = true;
        if (it == CKM::RSA_WITH_SHA384)     rsa_signalgos[3] = true;
        if (it == CKM::RSA_WITH_SHA512)     rsa_signalgos[4] = true;
        if (it == CKM::RSA_WITH_SHA3_224)   rsa_signalgos[5] = true;
        if (it == CKM::RSA_WITH_SHA3_256)   rsa_signalgos[6] = true;
        if (it == CKM::RSA_WITH_SHA3_384)   rsa_signalgos[7] = true;
        if (it == CKM::RSA_WITH_SHA3_512)   rsa_signalgos[8] = true;
    }

    if (is_dstu4145) {
        ck_err = helper.getMechanismInfo(slotId, CKM::UKR::DSTU4145_KEY_PAIR_GEN, mech_info);
        if (ck_err != CKR_OK) return toCmError(ck_err);
        if (mech_info.flags & (CKF_GENERATE_KEY_PAIR | CKF_HW)) {
            for (size_t i = 0; i < DSTU4145_ECPARAMINFO_NUMBER; i++) {
                const EcParamInfo& ecparam_info = DSTU4145_ECPARAMINFOS[i];
                if ((ecparam_info.keySize >= mech_info.minKeySize) && (ecparam_info.keySize <= mech_info.maxKeySize)) {
                    m_SupportedKeyParams.dstuCurves.push_back(ecparam_info.ecParamsId);
                }
            }
        }

        ck_err = helper.getMechanismInfo(slotId, CKM::UKR::DSTU4145, mech_info);
        if (ck_err != CKR_OK) return toCmError(ck_err);
        if (mech_info.flags & (CKF_SIGN | CKF_HW)) {
            vector<string>& signalgos_dstu = m_SupportedSignAlgos.dstu;
            //  If present any DSTU-signalgo then support all cases DSTU-signalgo
            if (dstu_signalgos[0] || dstu_signalgos[1] || dstu_signalgos[2] || dstu_signalgos[3]) {
                signalgos_dstu.push_back(string(OID_DSTU4145_WITH_DSTU7564_256_PB));
                signalgos_dstu.push_back(string(OID_DSTU4145_WITH_DSTU7564_384_PB));
                signalgos_dstu.push_back(string(OID_DSTU4145_WITH_DSTU7564_512_PB));
                signalgos_dstu.push_back(string(OID_DSTU4145_PARAM_PB_LE));
            }
        }

        if (m_SupportedKeyDeriveAlgos.dstu) {
            ck_err = helper.getMechanismInfo(slotId, CKM::UKR::DSTU4145_ECDH_DERIVE, mech_info);
            if (ck_err != CKR_OK) return toCmError(ck_err);
            m_SupportedKeyDeriveAlgos.dstu = (mech_info.flags & (CKF_DERIVE | CKF_HW));
        }
        if (m_SupportedKeyDeriveAlgos.dstuCofactor) {
            ck_err = helper.getMechanismInfo(slotId, CKM::UKR::DSTU4145_ECDH_COFACTOR_DERIVE, mech_info);
            if (ck_err != CKR_OK) return toCmError(ck_err);
            m_SupportedKeyDeriveAlgos.dstuCofactor = (mech_info.flags & (CKF_DERIVE | CKF_HW));
        }
    }

    if (is_ecdsa) {
        ck_err = helper.getMechanismInfo(slotId, CKM::EC_KEY_PAIR_GEN, mech_info);
        if (ck_err != CKR_OK) return toCmError(ck_err);
        if (mech_info.flags & (CKF_GENERATE_KEY_PAIR | CKF_HW)) {
            for (size_t i = 0; i < ECDSA_ECPARAMINFO_NUMBER; i++) {
                const EcParamInfo& ecparam_info = ECDSA_ECPARAMINFOS[i];
                if ((ecparam_info.keySize >= mech_info.minKeySize) && (ecparam_info.keySize <= mech_info.maxKeySize)) {
                    m_SupportedKeyParams.ecdsaCurves.push_back(ecparam_info.ecParamsId);
                }
            }
        }

        ck_err = helper.getMechanismInfo(slotId, CKM::ECDSA, mech_info);
        if (ck_err != CKR_OK) return toCmError(ck_err);
        if (mech_info.flags & (CKF_SIGN | CKF_HW)) {
            vector<string>& signalgos_ecdsa = m_SupportedSignAlgos.ecdsa;
            if (ecdsa_signalgos[2]) signalgos_ecdsa.push_back(string(OID_ECDSA_WITH_SHA256));
            if (ecdsa_signalgos[3]) signalgos_ecdsa.push_back(string(OID_ECDSA_WITH_SHA384));
            if (ecdsa_signalgos[4]) signalgos_ecdsa.push_back(string(OID_ECDSA_WITH_SHA512));
            if (ecdsa_signalgos[0]) signalgos_ecdsa.push_back(string(OID_ECDSA_WITH_SHA1));
            if (ecdsa_signalgos[1]) signalgos_ecdsa.push_back(string(OID_ECDSA_WITH_SHA224));
            if (ecdsa_signalgos[6]) signalgos_ecdsa.push_back(string(OID_ECDSA_WITH_SHA3_256));
            if (ecdsa_signalgos[7]) signalgos_ecdsa.push_back(string(OID_ECDSA_WITH_SHA3_384));
            if (ecdsa_signalgos[8]) signalgos_ecdsa.push_back(string(OID_ECDSA_WITH_SHA3_512));
            if (ecdsa_signalgos[5]) signalgos_ecdsa.push_back(string(OID_ECDSA_WITH_SHA3_224));
        }
    }

    if (is_rsa) {
        ck_err = helper.getMechanismInfo(slotId, CKM::RSA_PKCS_KEY_PAIR_GEN, mech_info);
        if (ck_err != CKR_OK) return toCmError(ck_err);
        if (mech_info.flags & (CKF_GENERATE_KEY_PAIR | CKF_HW)) {
            for (size_t i = 0; i < RSA_KEYSIZES_NUMBER; i++) {
                const uint32_t modulus_bits = RSA_KEYSIZES[i];
                if ((modulus_bits >= mech_info.minKeySize) && (modulus_bits <= mech_info.maxKeySize)) {
                    m_SupportedKeyParams.rsaKeySizes.push_back(modulus_bits);
                }
            }
        }

        ck_err = helper.getMechanismInfo(slotId, CKM::RSA_PKCS, mech_info);
        if (ck_err != CKR_OK) return toCmError(ck_err);
        if (mech_info.flags & (CKF_SIGN | CKF_HW)) {
            vector<string>& signalgos_rsa = m_SupportedSignAlgos.rsa;
            if (rsa_signalgos[2]) signalgos_rsa.push_back(string(OID_RSA_WITH_SHA256));
            if (rsa_signalgos[3]) signalgos_rsa.push_back(string(OID_RSA_WITH_SHA384));
            if (rsa_signalgos[4]) signalgos_rsa.push_back(string(OID_RSA_WITH_SHA512));
            if (rsa_signalgos[0]) signalgos_rsa.push_back(string(OID_RSA_WITH_SHA1));
            if (rsa_signalgos[1]) signalgos_rsa.push_back(string(OID_RSA_WITH_SHA224));
            if (rsa_signalgos[6]) signalgos_rsa.push_back(string(OID_RSA_WITH_SHA3_256));
            if (rsa_signalgos[7]) signalgos_rsa.push_back(string(OID_RSA_WITH_SHA3_384));
            if (rsa_signalgos[8]) signalgos_rsa.push_back(string(OID_RSA_WITH_SHA3_512));
            if (rsa_signalgos[5]) signalgos_rsa.push_back(string(OID_RSA_WITH_SHA3_224));
        }
    }

    return RET_OK;
}

CM_ERROR CryptokiStorage::getUnwrappedKey (
        const CK_OBJECT_HANDLE hDerivedKey,
        const DeriveWrapKeyParams& dwkParams,
        const CM_BYTEARRAY* baWrappedKey,
        Buffer& bufUnwrappedKey
)
{
    const Buffer buf_wrappedkey = bufferFromPtr(baWrappedKey->buf, baWrappedKey->len);
    if (buf_wrappedkey.empty()) return RET_CM_GENERAL_ERROR;

    const CK_OBJECT_CLASS obj_type = CKO::SECRET_KEY;
    const vector<CK_ATTRIBUTE> unwrapedkey_attrs = {
        { CKA::CLASS, (CK_VOID_PTR)&obj_type, sizeof(obj_type) },
        { CKA::KEY_TYPE, (CK_VOID_PTR)&dwkParams.wrapKeyType, sizeof(dwkParams.wrapKeyType) },
        { CKA::TOKEN, (CK_VOID_PTR)&ATTRIBUTE_FALSE, sizeof(ATTRIBUTE_FALSE) },
        { CKA::EXTRACTABLE, (CK_VOID_PTR)&ATTRIBUTE_TRUE, sizeof(ATTRIBUTE_TRUE) }
    };
    CK_OBJECT_HANDLE h_unwrappedkey = (CK_OBJECT_HANDLE)-1;
    const CK_MECHANISM mech_param = { dwkParams.wrapMechType, nullptr, 0};
    CK_RV ck_err = m_Session.unwrapKey(
        (const CK_MECHANISM_PTR)&mech_param,
        hDerivedKey,
        buf_wrappedkey,
        unwrapedkey_attrs,
        h_unwrappedkey
    );
    DEBUG_OUTCON(printf("CryptokiStorage::getUnwrappedKey(derivedKey: %d), unwrapedKey: %d\n", hDerivedKey, h_unwrappedkey));
    if (ck_err != CKR_OK) return toCmError(ck_err);

    ck_err = m_Session.getAttributeBuffer(
        h_unwrappedkey,
        CKA::VALUE,
        bufUnwrappedKey
    );

    (void)m_Session.destroyObject(h_unwrappedkey);
    return toCmError(ck_err);
}

CM_ERROR CryptokiStorage::getWrappedKey (
        const CK_OBJECT_HANDLE hDerivedKey,
        const DeriveWrapKeyParams& dwkParams,
        const CM_BYTEARRAY* baSessionKey,
        Buffer& bufWrappedKey
)
{
    const CK_OBJECT_CLASS obj_type = CKO::SECRET_KEY;
    const vector<CK_ATTRIBUTE> sessionkey_attrs = {
        { CKA::CLASS, (CK_VOID_PTR)&obj_type, sizeof(obj_type) },
        { CKA::KEY_TYPE, (CK_VOID_PTR)&dwkParams.wrapKeyType, sizeof(dwkParams.wrapKeyType) },
        { CKA::TOKEN, (CK_VOID_PTR)&ATTRIBUTE_FALSE, sizeof(ATTRIBUTE_FALSE) },
        { CKA::EXTRACTABLE, (CK_VOID_PTR)&ATTRIBUTE_TRUE, sizeof(ATTRIBUTE_TRUE) },
        { CKA::VALUE, (CK_VOID_PTR)baSessionKey->buf, (CK_ULONG)baSessionKey->len }
    };
    CK_OBJECT_HANDLE h_sessionkey = (CK_OBJECT_HANDLE)-1;
    CK_RV ck_err = m_Session.createObject(sessionkey_attrs, h_sessionkey);
    if (ck_err != CKR_OK) return toCmError(ck_err);

    const CK_MECHANISM mech_param = { dwkParams.wrapMechType, nullptr, 0 };
    ck_err = m_Session.wrapKey(
        (const CK_MECHANISM_PTR)&mech_param,
        hDerivedKey,
        h_sessionkey,
        bufWrappedKey
    );
    (void)m_Session.destroyObject(h_sessionkey);
    return toCmError(ck_err);
}

bool CryptokiStorage::bufferFromBa (
        const ByteArray* ba,
        Buffer& buf
)
{
    if (!ba) return false;

    buf.resize(ba_get_len(ba));
    memcpy((void*)buf.data(), ba_get_buf_const(ba), buf.size());
    return true;
}

ByteArray* CryptokiStorage::bufferToBa (
        const Buffer& buf
)
{
    return ba_alloc_from_uint8(buf.data(), buf.size());
}

bool CryptokiStorage::cmpBuffers (
        const Buffer& bufA,
        const Buffer& bufB
)
{
    return ((bufA.size() == bufB.size()) && (memcmp(bufA.data(), bufB.data(), bufB.size()) == 0));
}

bool CryptokiStorage::cmpBuffers (
        const Buffer& bufA,
        const uint8_t* pBufB,
        const size_t lenBufB
)
{
    return (pBufB && (bufA.size() == lenBufB) && (memcmp(bufA.data(), pBufB, lenBufB) == 0));
}

bool CryptokiStorage::strToUint32 (
        const char* str,
        uint32_t& value
)
{
    if (!str) return false;

    return strToUint32(string(str), value);
}

bool CryptokiStorage::strToUint32 (
        const string& str,
        uint32_t& value
)
{
    if (str.empty()) return false;

    bool ok = false;
    try {
        const unsigned long ul_value = stoul(str, nullptr, 10);
        value = (uint32_t)ul_value;
        ok = true;
    }
    catch (exception e) {}
    return ok;
}

CM_ERROR CryptokiStorage::calcKeyId (
        const HashAlg hashAlg,
        const Buffer& bufPublicKey,
        Buffer& bufKeyId
)
{
    SmartBA sba_keyid, sba_publickey;
    if (!sba_publickey.set(bufferToBa(bufPublicKey))) return RET_CM_GENERAL_ERROR;

    const int ret = ::hash(hashAlg, sba_publickey.get(), &sba_keyid);
    if (ret != RET_OK) return (CM_ERROR)ret;

    return bufferFromBa(sba_keyid.get(), bufKeyId) ? RET_OK : RET_CM_GENERAL_ERROR;
}

bool CryptokiStorage::decodeDstuParams (
        const Buffer& bufEcParams,
        string& namedCurve
)
{
    namedCurve.clear();
    if (bufEcParams.empty()) return false;

    DSTU4145Params_t* dstu_params = (DSTU4145Params_t*)asn_decode_with_alloc(get_DSTU4145Params_desc(), bufEcParams.data(), bufEcParams.size());
    if (!dstu_params) return false;

    char* s_curve = nullptr;
    const int ret = dstu4145_params_get_std_oid(&dstu_params->ellipticCurve, &s_curve);
    if ((ret == RET_OK) && s_curve) {
        namedCurve = string(s_curve);
    }

    asn_free(get_DSTU4145Params_desc(), dstu_params);
    ::free(s_curve);
    return (!namedCurve.empty());
}

bool CryptokiStorage::decodeEcdsaParams (
        const Buffer& bufEcParams,
        string& namedCurve
)
{
    namedCurve.clear();
    if (bufEcParams.empty()) return false;

    const EcParamsId ecid = EcParamsId(ecdsa_ecparams_get_ecid(bufEcParams.data(), bufEcParams.size()));
    if (ecid == EC_PARAMS_ID_UNDEFINED) return false;

    const char* s_oid = ecid_to_oid(ecid);
    if (!s_oid) return false;

    namedCurve = string(s_oid);
    return true;
}

bool CryptokiStorage::encodeDstuParams (
        const string& namedCurve,
        Buffer& bufEncoded
)
{
    if (namedCurve.empty()) return false;

    DSTU4145Params_t* dstu_params = (DSTU4145Params_t*)calloc(1, sizeof(DSTU4145Params_t));
    if (!dstu_params) return false;

    int ret = RET_OK;
    uint8_t* encoded_bytes = nullptr;
    size_t encoded_len = 0;
    dstu_params->ellipticCurve.present = DSTUEllipticCurve_PR_namedCurve;
    DO(Util::oidToAsn1(&dstu_params->ellipticCurve.choice.namedCurve, namedCurve));

    dstu_params->dke = (OCTET_STRING_t*)calloc(1, sizeof(OCTET_STRING_t));
    if (!dstu_params->dke) {
        SET_ERROR(RET_CM_GENERAL_ERROR);
    }
    DO(asn_bytes2OCTSTRING(dstu_params->dke, DKE_DEFAULT_SBOX, sizeof(DKE_DEFAULT_SBOX)));

    DO(asn_encode(get_DSTU4145Params_desc(), dstu_params, &encoded_bytes, &encoded_len));

    bufEncoded.resize(encoded_len);
    memcpy((void*)bufEncoded.data(), encoded_bytes, bufEncoded.size());

cleanup:
    asn_free(get_DSTU4145Params_desc(), dstu_params);
    ::free(encoded_bytes);
    return (ret == RET_OK);
}

bool CryptokiStorage::encodeEcdsaParams (
        const string& namedCurve,
        Buffer& bufEncoded
)
{
    if (namedCurve.size() < 3) return false;

    SmartBA sba_encoded;
    if (Util::encodeOid(namedCurve.c_str(), &sba_encoded) != RET_OK) return false;

    return bufferFromBa(sba_encoded.get(), bufEncoded);
}

bool CryptokiStorage::encodeEcdsaSignvalue (
        const Buffer& bufSignvalue,
        CM_BYTEARRAY** baEncoded
)
{
    int ret = RET_OK;
    const size_t half_len = bufSignvalue.size() / 2;
    ECDSA_Sig_Value_t* ec_sig = nullptr;
    SmartBA sba_r, sba_s;

    if (
        !sba_r.set(ba_alloc_from_uint8(bufSignvalue.data(), half_len)) ||
        !sba_s.set(ba_alloc_from_uint8(bufSignvalue.data() + half_len, half_len))
        ) {
        return false;
    }

    ASN_ALLOC_TYPE(ec_sig, ECDSA_Sig_Value_t);
    DO(asn_ba2INTEGER(sba_r.get(), &ec_sig->r));
    DO(asn_ba2INTEGER(sba_s.get(), &ec_sig->s));

    DO(asn_encode_ba(get_ECDSA_Sig_Value_desc(), ec_sig, (ByteArray**)baEncoded));

cleanup:
    asn_free(get_ECDSA_Sig_Value_desc(), ec_sig);
    return (ret == RET_OK);
}

bool CryptokiStorage::encodeRsaPublicKey (
        const Buffer& bufModulus,
        const Buffer& bufPublicExponent,
        Buffer& bufEncoded
)
{
    SmartBA sba_modulus, sba_pubexponent;
    if (bufModulus.empty() || !sba_modulus.set(bufferToBa(bufModulus))) return false;
    if (bufPublicExponent.empty() || !sba_pubexponent.set(bufferToBa(bufPublicExponent))) return false;

    RSAPublicKey_t* rsa_publickey = (RSAPublicKey_t*)calloc(1, sizeof(RSAPublicKey_t));
    if (!rsa_publickey) return false;

    int ret = RET_OK;
    uint8_t* encoded_bytes = nullptr;
    size_t encoded_len = 0;

    DO(asn_ba2INTEGER(sba_modulus.get(), &rsa_publickey->modulus));
    DO(asn_ba2INTEGER(sba_pubexponent.get(), &rsa_publickey->publicExponent));

    DO(asn_encode(get_RSAPublicKey_desc(), rsa_publickey, &encoded_bytes, &encoded_len));

    bufEncoded.resize(encoded_len);
    memcpy((void*)bufEncoded.data(), encoded_bytes, bufEncoded.size());

cleanup:
    asn_free(get_RSAPublicKey_desc(), rsa_publickey);
    ::free(encoded_bytes);
    return (ret == RET_OK);
}

CM_ERROR CryptokiStorage::getAlgorithmIdentifier (
        const KeyInfo& keyInfo,
        ByteArray** baEncoded
)
{
    const PublicParams& keyinfo_pubparams = keyInfo.publicParams;
    const uint8_t* pbuf_param = nullptr;
    size_t len_param = 0;

    switch (keyInfo.keyAlgo) {
    case KeyAlgo::DSTU:
        pbuf_param = keyinfo_pubparams.ecParams.data();
        len_param = keyinfo_pubparams.ecParams.size();
        break;
    case KeyAlgo::ECDSA:
#ifndef CM_PKCS11_SKIP_SUBSTITUTE_ECPARAM
        pbuf_param = substitute_ecparam(keyInfo.parameterId, len_param);
#else
        pbuf_param = keyinfo_pubparams.ecParams.data();
        len_param = keyinfo_pubparams.ecParams.size();
#endif
        break;
    case KeyAlgo::RSA:
        pbuf_param = DER_ASN1_NULL;
        len_param = sizeof(DER_ASN1_NULL);
        break;
    default:
        return RET_CM_UNSUPPORTED_ALG;
    }

    SmartBA sba_params;
    if (!sba_params.set(ba_alloc_from_uint8(pbuf_param, len_param))) return RET_CM_GENERAL_ERROR;

    const CM_ERROR cm_err = (CM_ERROR)Util::encodeAlgorithmIdentifier(keyInfo.mechanismId, sba_params.get(), baEncoded);
    return cm_err;
}

CM_ERROR CryptokiStorage::getPublicKey (
        const KeyInfo& keyInfo,
        ByteArray** baPubkey
)
{
    int ret = RET_OK;
    const PublicParams& keyinfo_pubparams = keyInfo.publicParams;
    SmartBA sba_pubkey, sba_ecpoint;

    switch (keyInfo.keyAlgo) {
    case KeyAlgo::ECDSA:
    case KeyAlgo::DSTU:
        if (!sba_ecpoint.set(bufferToBa(keyinfo_pubparams.ecPoint))) return RET_CM_GENERAL_ERROR;
        DO(Util::decodeOctetString(sba_ecpoint.get(), &sba_pubkey));
        break;
    case KeyAlgo::RSA:
        if (!sba_pubkey.set(bufferToBa(keyinfo_pubparams.rsaPublicKey))) return RET_CM_GENERAL_ERROR;
        break;
    default:
        return RET_CM_UNSUPPORTED_ALG;
    }

    *baPubkey = sba_pubkey.pop();

cleanup:
    return ret;
}

HashAlg CryptokiStorage::hashAlgBySignAlgo (
        const KeyInfo& keyInfo,
        const string& signAlgo
)
{
    if (signAlgo.empty()) return HASH_ALG_UNDEFINED;

    HashAlg rv_hashalg = HASH_ALG_UNDEFINED;
    const SignAlg sign_alg = signature_from_oid(signAlgo.c_str());
    if (sign_alg != SIGN_RSA_PSS) {
        rv_hashalg = hash_from_oid(signAlgo.c_str());
    }
    else {
        DEBUG_OUTCON(puts("TODO: CryptokiStorage::hashAlgBySignAlgo(): hash_from_rsa_pss(signAlgoParams, &hash_alg)"));
    }
    return rv_hashalg;
}

CM_ERROR CryptokiStorage::toCmError (
        const CK_RV ckRetValue
)
{
    switch (ckRetValue) {
    case CKR_OK:                            return RET_OK;
    case CKR_DEVICE_MEMORY:                 return RET_CM_TOKEN_NO_FREE_SPACE;
    case CKR_WRAPPED_KEY_INVALID:           return RET_CM_INVALID_WRAPPED_KEY;
    case CKR_CRYPTOKI_NOT_INITIALIZED:      return RET_CM_NOT_INITIALIZED;
    case CKR_CRYPTOKI_ALREADY_INITIALIZED:  return RET_CM_ALREADY_INITIALIZED;
    case CKR_LIBRARY_LOAD_FAILED:           return RET_CM_LIBRARY_NOT_LOADED;
    default: break;
    }
    return RET_CM_TOKEN_ERROR;
}
