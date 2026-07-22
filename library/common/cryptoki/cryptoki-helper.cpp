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

#include "cryptoki-helper.h"
#include "cryptoki-const.h"
#include <stdio.h>
#include <string.h>


#define DEBUG_OUTCON(expression)
#ifndef DEBUG_OUTCON
#define DEBUG_OUTCON(expression) expression
#endif


using namespace std;


namespace Cryptoki {


//  Upper bound for scanning NUL-terminated PIN arguments:
//  keeps strnlen() within a sane limit even if a non-terminated buffer is passed
static const size_t MAX_PIN_SCAN_LENGTH = 65535;


Helper::Helper (void)
    : m_IsInitialized(false)
    , m_LastResult(CKR_OK)
{
    DEBUG_OUTCON(puts("Cryptoki::Helper::Helper"));
}

Helper::~Helper (void)
{
    DEBUG_OUTCON(puts("Cryptoki::Helper::~Helper"));
    if (m_IsInitialized) {
        (void)finalize();
    }
}

CK_RV Helper::initialize (
        CK_VOID_PTR pInitArgs
)
{
    if (m_IsInitialized) return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    if (!getApi()) return CKR_LIBRARY_LOAD_FAILED;

    m_LastResult = getApi()->C_Initialize(pInitArgs);
    if (m_LastResult == CKR_OK) {
        m_IsInitialized = true;
    }
    return m_LastResult;
}

CK_RV Helper::finalize (
        CK_VOID_PTR pReserved
)
{
    if (!m_IsInitialized) return CKR_OK;

    m_LastResult = getApi()->C_Finalize(pReserved);
    if (m_LastResult == CKR_OK) {
        m_IsInitialized = false;
    }
    return m_LastResult;
}

CK_RV Helper::getInfo (
        LibraryInfo& libInfo
)
{
    libInfo = LibraryInfo();
    if (!m_IsInitialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    CK_INFO lib_info;
    memset(&lib_info, 0, sizeof(lib_info));

    m_LastResult = getApi()->C_GetInfo(&lib_info);
    if (m_LastResult == CKR_OK) {
        libInfo.cryptokiVersion.major = lib_info.cryptokiVersion.major;
        libInfo.cryptokiVersion.minor = lib_info.cryptokiVersion.minor;
        libInfo.manufacturerId = stringFromChars((CK_CHAR*)lib_info.manufacturerID, sizeof(CK_INFO::manufacturerID));
        libInfo.flags = lib_info.flags;
        libInfo.libraryDescription = stringFromChars((CK_CHAR*)lib_info.libraryDescription, sizeof(CK_INFO::libraryDescription));
        libInfo.libraryVersion.major = lib_info.libraryVersion.major;
        libInfo.libraryVersion.minor = lib_info.libraryVersion.minor;
    }
    return m_LastResult;
}

CK_RV Helper::getSlotList (
        const bool tokenPresent,
        vector<CK_SLOT_ID>& slotIds
)
{
    slotIds.clear();
    if (!m_IsInitialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    CK_ULONG cnt_slots = 0;
    m_LastResult = getApi()->C_GetSlotList(tokenPresent ? CK_TRUE : CK_FALSE, NULL_PTR, &cnt_slots);
    if (m_LastResult != CKR_OK) return m_LastResult;

    if (cnt_slots == 0) return CKR_OK;

    slotIds.resize((size_t)cnt_slots);
    m_LastResult = getApi()->C_GetSlotList(CK_TRUE, (CK_SLOT_ID_PTR)slotIds.data(), &cnt_slots);
    if (m_LastResult != CKR_OK) {
        slotIds.clear();
    }
    return m_LastResult;
}

CK_RV Helper::getSlotInfo (
        const CK_SLOT_ID slotId,
        SlotInfo& slotInfo
)
{
    slotInfo = SlotInfo();
    if (!m_IsInitialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    CK_SLOT_INFO slot_info;
    memset(&slot_info, 0, sizeof(slot_info));

    m_LastResult = getApi()->C_GetSlotInfo(slotId, &slot_info);
    if (m_LastResult == CKR_OK) {
        slotInfo.slotDescription = stringFromChars((CK_CHAR*)slot_info.slotDescription, sizeof(CK_SLOT_INFO::slotDescription));
        slotInfo.manufacturerId = stringFromChars((CK_CHAR*)slot_info.manufacturerID, sizeof(CK_SLOT_INFO::manufacturerID));
        slotInfo.flags = slot_info.flags;
        slotInfo.hardwareVersion.major = slot_info.hardwareVersion.major;
        slotInfo.hardwareVersion.minor = slot_info.hardwareVersion.minor;
        slotInfo.firmwareVersion.major = slot_info.firmwareVersion.major;
        slotInfo.firmwareVersion.minor = slot_info.firmwareVersion.minor;
    }
    return m_LastResult;
}

CK_RV Helper::getTokenInfo (
        const CK_SLOT_ID slotId,
        TokenInfo& tokenInfo
)
{
    tokenInfo = TokenInfo();
    if (!m_IsInitialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    CK_TOKEN_INFO token_info;
    memset(&token_info, 0, sizeof(token_info));

    m_LastResult = getApi()->C_GetTokenInfo(slotId, &token_info);
    if (m_LastResult == CKR_OK) {
        tokenInfo.label = stringFromChars((CK_CHAR*)token_info.label, sizeof(CK_TOKEN_INFO::label));
        tokenInfo.manufacturerId = stringFromChars((CK_CHAR*)token_info.manufacturerID, sizeof(CK_TOKEN_INFO::manufacturerID));
        tokenInfo.model = stringFromChars((CK_CHAR*)token_info.model, sizeof(CK_TOKEN_INFO::model));
        tokenInfo.serialNumber = stringFromChars((CK_CHAR*)token_info.serialNumber, sizeof(CK_TOKEN_INFO::serialNumber));
        tokenInfo.flags = token_info.flags;
        tokenInfo.maxSessionCount = token_info.ulMaxSessionCount;
        tokenInfo.sessionCount = token_info.ulSessionCount;
        tokenInfo.maxRwSessionCount = token_info.ulMaxRwSessionCount;
        tokenInfo.rwSessionCount = token_info.ulRwSessionCount;
        tokenInfo.maxPinLen = token_info.ulMaxPinLen;
        tokenInfo.minPinLen = token_info.ulMinPinLen;
        tokenInfo.totalPublicMemory = token_info.ulTotalPublicMemory;
        tokenInfo.freePublicMemory = token_info.ulFreePublicMemory;
        tokenInfo.totalPrivateMemory = token_info.ulTotalPrivateMemory;
        tokenInfo.freePrivateMemory = token_info.ulFreePrivateMemory;
        tokenInfo.hardwareVersion.major = token_info.hardwareVersion.major;
        tokenInfo.hardwareVersion.minor = token_info.hardwareVersion.minor;
        tokenInfo.firmwareVersion.major = token_info.firmwareVersion.major;
        tokenInfo.firmwareVersion.minor = token_info.firmwareVersion.minor;
        tokenInfo.utcTime = stringFromChars((CK_CHAR*)token_info.utcTime, sizeof(CK_TOKEN_INFO::utcTime));
    }
    return m_LastResult;
}

CK_RV Helper::getMechanismList (
        const CK_SLOT_ID slotId,
        vector<CK_MECHANISM_TYPE>& mechanismTypes
)
{
    mechanismTypes.clear();
    if (!m_IsInitialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    CK_ULONG cnt_mechanisms = 0;
    m_LastResult = getApi()->C_GetMechanismList(slotId, NULL_PTR, &cnt_mechanisms);
    if ((m_LastResult != CKR_OK) || (cnt_mechanisms == 0)) return m_LastResult;

    mechanismTypes.resize((size_t)cnt_mechanisms);
    m_LastResult = getApi()->C_GetMechanismList(slotId, (CK_MECHANISM_TYPE_PTR)mechanismTypes.data(), &cnt_mechanisms);
    if (m_LastResult != CKR_OK) {
        mechanismTypes.clear();
    }
    return m_LastResult;
}

CK_RV Helper::getMechanismInfo (
        const CK_SLOT_ID slotId,
        const CK_MECHANISM_TYPE mechanismType,
        MechanismInfo& mechanismInfo
)
{
    mechanismInfo = MechanismInfo();
    if (!m_IsInitialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    CK_MECHANISM_INFO mech_info;
    memset(&mech_info, 0, sizeof(mech_info));

    m_LastResult = getApi()->C_GetMechanismInfo(slotId, mechanismType, &mech_info);
    if (m_LastResult == CKR_OK) {
        mechanismInfo.minKeySize = mech_info.ulMinKeySize;
        mechanismInfo.maxKeySize = mech_info.ulMaxKeySize;
        mechanismInfo.flags = mech_info.flags;
    }
    return m_LastResult;
}

CK_RV Helper::closeAllSessions (
        const CK_SLOT_ID slotId
)
{
    if (!m_IsInitialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    m_LastResult = getApi()->C_CloseAllSessions(slotId);
    return m_LastResult;
}

CK_RV Helper::initToken (
        const CK_SLOT_ID slotId,
        const CK_CHAR_PTR pin,
        const CK_ULONG pinLen,
        const string& label
)
{
    if (!m_IsInitialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    CK_CHAR buf_label[MAXLEN_TOKEN_LABEL] = { 0 };
    (void)stringToChars(buf_label, sizeof(buf_label), label, CHAR_BLANK);
    m_LastResult = getApi()->C_InitToken(
        slotId,
        pin,
        pinLen,
        (CK_CHAR_PTR)buf_label
    );
    return m_LastResult;
}

CK_RV Helper::initToken (
        const CK_SLOT_ID slotId,
        const CK_CHAR_PTR pin,
        const string& label
)
{
    const CK_ULONG pin_len = pin ? (CK_ULONG)strnlen((const char*)pin, MAX_PIN_SCAN_LENGTH) : 0;
    return initToken(slotId, pin, pin_len, label);
}


Session::Session (
        Helper& iHelper
)
    : m_Helper(iHelper)
    , m_Handle((CK_SESSION_HANDLE)-1)
    , m_SlotId((CK_SLOT_ID)-1)
    , m_LastResult(CKR_OK)
    , m_IsAuthorized(false)
    , m_IsOpened(false)
{
    DEBUG_OUTCON(puts("Cryptoki::Session::Session"));
}

Session::~Session (void)
{
    DEBUG_OUTCON(puts("Cryptoki::Session::~Session"));
    (void)close();
}

CK_RV Session::open (
        const CK_SLOT_ID slotId,
        const CK_FLAGS flags
)
{
    if (!m_Helper.isInitialized()) return CKR_CRYPTOKI_NOT_INITIALIZED;

    (void)close();
    if (m_LastResult != CKR_OK) return m_LastResult;

    m_LastResult = getApi()->C_OpenSession(
        slotId,
        flags,
        NULL_PTR,
        NULL_PTR,
        &m_Handle
    );
    if (m_LastResult == CKR_OK) {
        m_SlotId = slotId;
        m_IsOpened = true;
    }
    return m_LastResult;
}

CK_RV Session::close (void)
{
    (void)logout();
    if (isOpened()) {
        m_LastResult = getApi()->C_CloseSession(m_Handle);
        if (m_LastResult == CKR_OK) {
            reset();
        }
    }
    else {
        m_LastResult = CKR_OK;
    }
    return m_LastResult;
}

CK_RV Session::login (
        const CK_USER_TYPE userType,
        const CK_CHAR_PTR pin,
        const CK_ULONG pinLen
)
{
    (void)logout();
    if (m_LastResult != CKR_OK) return m_LastResult;

    m_LastResult = getApi()->C_Login(
        m_Handle,
        userType,
        pin,
        pinLen
    );
    if (m_LastResult == CKR_OK) {
        m_IsAuthorized = true;
    }
    return m_LastResult;
}

CK_RV Session::login (
        const CK_USER_TYPE userType,
        const CK_CHAR_PTR pin
)
{
    const CK_ULONG pin_len = pin ? (CK_ULONG)strnlen((const char*)pin, MAX_PIN_SCAN_LENGTH) : 0;
    return login(userType, pin, pin_len);
}

CK_RV Session::logout (void)
{
    if (isAuthorized()) {
        m_LastResult = getApi()->C_Logout(m_Handle);
        if (m_LastResult == CKR_OK) {
            m_IsAuthorized = false;
        }
    }
    else {
        m_LastResult = CKR_OK;
    }

    return m_LastResult;
}

void Session::reset (void)
{
    m_Handle = (CK_SESSION_HANDLE)-1;
    m_SlotId = (CK_SLOT_ID)-1;
    m_IsAuthorized = false;
    m_IsOpened = false;
}

CK_RV Session::setPin (
        const CK_CHAR_PTR oldPin,
        const CK_ULONG oldPinLen,
        const CK_CHAR_PTR newPin,
        const CK_ULONG newPinLen
)
{
    m_LastResult = getApi()->C_SetPIN(
        m_Handle,
        oldPin,
        oldPinLen,
        newPin,
        newPinLen
    );
    return m_LastResult;
}

CK_RV Session::setPin (
        const CK_CHAR_PTR oldPin,
        const CK_CHAR_PTR newPin
)
{
    const CK_ULONG oldpin_len = oldPin ? (CK_ULONG)strnlen((const char*)oldPin, MAX_PIN_SCAN_LENGTH) : 0;
    const CK_ULONG newpin_len = newPin ? (CK_ULONG)strnlen((const char*)newPin, MAX_PIN_SCAN_LENGTH) : 0;
    return setPin(
        oldPin,
        oldpin_len,
        newPin,
        newpin_len
    );
}

CK_RV Session::initPin (
        const CK_CHAR_PTR pin,
        const CK_ULONG pinLen
)
{
    m_LastResult = getApi()->C_InitPIN(
        m_Handle,
        pin,
        pinLen
    );
    return m_LastResult;
}

CK_RV Session::initPin (
        const CK_CHAR_PTR pin
)
{
    const CK_ULONG pin_len = pin ? (CK_ULONG)strnlen((const char*)pin, MAX_PIN_SCAN_LENGTH) : 0;
    return initPin(pin, pin_len);
}

CK_RV Session::createObject (
        const CK_ATTRIBUTE_PTR pCreateObjAttrs,
        const CK_ULONG countCreateObjAttrs,
        CK_OBJECT_HANDLE& hObject
)
{
    hObject = (CK_OBJECT_HANDLE)-1;
    m_LastResult = getApi()->C_CreateObject(
        m_Handle,
        pCreateObjAttrs,
        countCreateObjAttrs,
        &hObject
    );
    return m_LastResult;
}

CK_RV Session::createObject (
        const vector<CK_ATTRIBUTE>& createObjAttrs,
        CK_OBJECT_HANDLE& hObject
)
{
    return createObject(
        (CK_ATTRIBUTE_PTR)createObjAttrs.data(),
        (CK_ULONG)createObjAttrs.size(),
        hObject
    );
}

CK_RV Session::deriveKey (
        const CK_MECHANISM_PTR pMechParam,
        const CK_OBJECT_HANDLE hBaseKey,
        const CK_ATTRIBUTE_PTR pDeriveKeyAttrs,
        const CK_ULONG countDeriveKeyAttrs,
        CK_OBJECT_HANDLE& hDerivedKey
)
{
    m_LastResult = getApi()->C_DeriveKey(
        m_Handle,
        pMechParam,
        hBaseKey,
        pDeriveKeyAttrs,
        countDeriveKeyAttrs,
        &hDerivedKey
    );
    return m_LastResult;
}

CK_RV Session::deriveKey (
        const CK_MECHANISM_PTR pMechParam,
        const CK_OBJECT_HANDLE hBaseKey,
        const vector<CK_ATTRIBUTE>& deriveKeyAttrs,
        CK_OBJECT_HANDLE& hDerivedKey
)
{
    m_LastResult = getApi()->C_DeriveKey(
        m_Handle,
        pMechParam,
        hBaseKey,
        (CK_ATTRIBUTE_PTR)deriveKeyAttrs.data(),
        (CK_ULONG)deriveKeyAttrs.size(),
        &hDerivedKey
    );
    return m_LastResult;
}

CK_RV Session::destroyObject (
        const CK_OBJECT_HANDLE hObject
)
{
    m_LastResult = getApi()->C_DestroyObject(m_Handle, hObject);
    return m_LastResult;
}

CK_RV Session::generateKeyPair (
        const CK_MECHANISM_PTR pMechParam,
        const CK_ATTRIBUTE_PTR pPublicKeyAttrs,
        const CK_ULONG countPublicKeyAttrs,
        const CK_ATTRIBUTE_PTR pPrivateKeyAttrs,
        const CK_ULONG countPrivateKeyAttrs,
        CK_OBJECT_HANDLE& hPublicKey,
        CK_OBJECT_HANDLE& hPrivateKey
)
{
    hPublicKey = (CK_OBJECT_HANDLE)-1;
    hPrivateKey = (CK_OBJECT_HANDLE)-1;
    m_LastResult = getApi()->C_GenerateKeyPair(
        m_Handle,
        pMechParam,
        pPublicKeyAttrs,
        countPublicKeyAttrs,
        pPrivateKeyAttrs,
        countPrivateKeyAttrs,
        &hPublicKey,
        &hPrivateKey
    );
    return m_LastResult;
}

CK_RV Session::generateKeyPair (
        const CK_MECHANISM_PTR pMechParam,
        const vector<CK_ATTRIBUTE>& publicKeyAttrs,
        const vector<CK_ATTRIBUTE>& privateKeyAttrs,
        CK_OBJECT_HANDLE& hPublicKey,
        CK_OBJECT_HANDLE& hPrivateKey
)
{
    return generateKeyPair(
        pMechParam,
        (CK_ATTRIBUTE_PTR)publicKeyAttrs.data(),
        (CK_ULONG)publicKeyAttrs.size(),
        (CK_ATTRIBUTE_PTR)privateKeyAttrs.data(),
        (CK_ULONG)privateKeyAttrs.size(),
        hPublicKey,
        hPrivateKey
    );
}

CK_RV Session::generateRandom (
        CK_BYTE_PTR pBuf,
        const CK_ULONG len
)
{
    m_LastResult = getApi()->C_GenerateRandom(m_Handle, pBuf, len);
    return m_LastResult;
}

CK_RV Session::generateRandom (
        Buffer& buf,
        const size_t len
)
{
    buf.resize(len);
    return generateRandom((CK_BYTE_PTR)buf.data(), (CK_ULONG)buf.size());
}

CK_RV Session::getAttributeValue (
        const CK_OBJECT_HANDLE hObject,
        CK_ATTRIBUTE_PTR pTemplateAttr
)
{
    m_LastResult = getApi()->C_GetAttributeValue(
        m_Handle,
        hObject,
        pTemplateAttr,
        1
    );
    return m_LastResult;
}

CK_RV Session::getAttributeValue (
        const CK_OBJECT_HANDLE hObject,
        CK_ATTRIBUTE_PTR pTemplateAttrs,
        const CK_ULONG countTemplateAttrs
)
{
    m_LastResult = getApi()->C_GetAttributeValue(
        m_Handle,
        hObject,
        pTemplateAttrs,
        countTemplateAttrs
    );
    return m_LastResult;
}

CK_RV Session::getAttributeValue (
        const CK_OBJECT_HANDLE hObject,
        const vector<CK_ATTRIBUTE>& templateAttrs
)
{
    return getAttributeValue(hObject, (CK_ATTRIBUTE_PTR)templateAttrs.data(), (CK_ULONG)templateAttrs.size());
}

CK_RV Session::setAttributeValue (
        const CK_OBJECT_HANDLE hObject,
        const CK_ATTRIBUTE_PTR pTemplateAttr
)
{
    m_LastResult = getApi()->C_SetAttributeValue(
        m_Handle,
        hObject,
        pTemplateAttr,
        1
    );
    return m_LastResult;
}

CK_RV Session::setAttributeValue (
        const CK_OBJECT_HANDLE hObject,
        const CK_ATTRIBUTE_PTR pTemplateAttrs,
        const CK_ULONG countTemplateAttrs
)
{
    m_LastResult = getApi()->C_SetAttributeValue(
        m_Handle,
        hObject,
        pTemplateAttrs,
        countTemplateAttrs
    );
    return m_LastResult;
}

CK_RV Session::setAttributeValue (
        const CK_OBJECT_HANDLE hObject,
        const vector<CK_ATTRIBUTE>& templateAttrs
)
{
    return setAttributeValue(
        hObject,
        (CK_ATTRIBUTE_PTR)templateAttrs.data(),
        (CK_ULONG)templateAttrs.size()
    );
}

CK_RV Session::unwrapKey (
        const CK_MECHANISM_PTR pMechParam,
        const CK_OBJECT_HANDLE hUnwrappingKey,
        const Buffer& wrappedKey,
        const CK_ATTRIBUTE_PTR pTemplateAttrs,
        const CK_ULONG countTemplateAttrs,
        CK_OBJECT_HANDLE& hUnwrapedKey
)
{
    m_LastResult = getApi()->C_UnwrapKey(
        m_Handle,
        pMechParam,
        hUnwrappingKey,
        (CK_BYTE_PTR)wrappedKey.data(),
        (CK_ULONG)wrappedKey.size(),
        pTemplateAttrs,
        countTemplateAttrs,
        &hUnwrapedKey
    );
    return m_LastResult;
}

CK_RV Session::unwrapKey (
        const CK_MECHANISM_PTR pMechParam,
        const CK_OBJECT_HANDLE hUnwrappingKey,
        const Buffer& wrappedKey,
        const vector<CK_ATTRIBUTE>& templateAttrs,
        CK_OBJECT_HANDLE& hUnwrapedKey
)
{
    return unwrapKey(
        pMechParam,
        hUnwrappingKey,
        wrappedKey,
        (CK_ATTRIBUTE_PTR)templateAttrs.data(),
        (CK_ULONG)templateAttrs.size(),
        hUnwrapedKey
    );
}

CK_RV Session::wrapKey (
        const CK_MECHANISM_PTR pMechParam,
        const CK_OBJECT_HANDLE hWrappingKey,
        const CK_OBJECT_HANDLE hKey,
        Buffer& wrappedKey
)
{
    CK_ULONG len_wrappedkey = 0;
    wrappedKey.clear();
    m_LastResult = getApi()->C_WrapKey(
        m_Handle,
        pMechParam,
        hWrappingKey,
        hKey,
        nullptr,
        &len_wrappedkey
    );
    if (m_LastResult != CKR_OK) return m_LastResult;

    wrappedKey.resize((size_t)len_wrappedkey);
    m_LastResult = getApi()->C_WrapKey(
        m_Handle,
        pMechParam,
        hWrappingKey,
        hKey,
        (CK_BYTE_PTR)wrappedKey.data(),
        &len_wrappedkey
    );
    return m_LastResult;
}

CK_RV Session::addCert (
        const bool isToken,
        const bool isPrivate,
        const Buffer& buf,
        const Buffer& id,
        const string& label,
        const vector<CK_ATTRIBUTE>& attrs,
        CK_OBJECT_HANDLE& hObject
)
{
    if (buf.empty()) return CKR_ARGUMENTS_BAD;

    const CK_BBOOL is_token = isToken;
    const CK_BBOOL is_private = isPrivate;
    const CK_ULONG cert_type = CKC::X_509;
    const CK_ATTRIBUTE attr_id = { CKA::ID, (CK_VOID_PTR)id.data(), (CK_ULONG)id.size() };
    const CK_ATTRIBUTE attr_label = { CKA::LABEL, (CK_VOID_PTR)label.data(), (CK_ULONG)label.length() };
    vector<CK_ATTRIBUTE> template_addcert = {
        { CKA::CLASS, (CK_VOID_PTR)&CKO::CERTIFICATE, sizeof(CKO::CERTIFICATE) },
        { CKA::TOKEN, (CK_VOID_PTR)&is_token, sizeof(is_token) },
        { CKA::PRIVATE, (CK_VOID_PTR)&is_private, sizeof(is_private) },
        { CKA::CERTIFICATE_TYPE, (CK_VOID_PTR)&cert_type, sizeof(cert_type) },
        { CKA::VALUE, (CK_VOID_PTR)buf.data(), (CK_ULONG)buf.size() }
    };

    if (attr_id.ulValueLen > 0) {
        template_addcert.push_back(attr_id);
    }
    if (attr_label.ulValueLen > 0) {
        template_addcert.push_back(attr_label);
    }

    for (const auto& it : attrs) {
        template_addcert.push_back(it);
    }

    return createObject(template_addcert, hObject);
}

CK_RV Session::addData (
        const bool isToken,
        const bool isPrivate,
        const bool isModifiable,
        const Buffer& buf,
        const string& label,
        const string& application,
        const vector<CK_ATTRIBUTE>& attrs,
        CK_OBJECT_HANDLE& hObject
)
{
    if (buf.empty()) return CKR_ARGUMENTS_BAD;

    const CK_BBOOL is_token = isToken;
    const CK_BBOOL is_private = isPrivate;
    const CK_BBOOL is_modifiable = isModifiable;
    const CK_ATTRIBUTE attr_label = { CKA::LABEL, (CK_VOID_PTR)label.data(), (CK_ULONG)label.length() };
    const CK_ATTRIBUTE attr_app = { CKA::APPLICATION, (CK_VOID_PTR)application.data(), (CK_ULONG)application.length() };
    vector<CK_ATTRIBUTE> template_adddata = {
        { CKA::CLASS, (CK_VOID_PTR)&CKO::DATA, sizeof(CKO::DATA) },
        { CKA::TOKEN, (CK_VOID_PTR)&is_token, sizeof(is_token) },
        { CKA::PRIVATE, (CK_VOID_PTR)&is_private, sizeof(is_private) },
        { CKA::MODIFIABLE, (CK_VOID_PTR)&is_modifiable, sizeof(is_modifiable) },
        { CKA::VALUE, (CK_VOID_PTR)buf.data(), (CK_ULONG)buf.size() }
    };

    if (attr_label.ulValueLen > 0) {
        template_adddata.push_back(attr_label);
    }
    if (attr_app.ulValueLen > 0) {
        template_adddata.push_back(attr_app);
    }

    for (const auto& it : attrs) {
        template_adddata.push_back(it);
    }

    return createObject(template_adddata, hObject);
}

CK_RV Session::findFiles (
        const bool isToken,
        const bool isPrivate,
        const CK_OBJECT_CLASS objType,
        vector<CK_OBJECT_HANDLE>& objFiles
)
{
    objFiles.clear();

    const CK_BBOOL is_token = isToken;
    const CK_BBOOL is_private = isPrivate;
    const vector<CK_ATTRIBUTE> template_files = {
        { CKA::CLASS, (CK_VOID_PTR)&objType, sizeof(objType) },
        { CKA::TOKEN, (CK_VOID_PTR)&is_token, sizeof(is_token) },
        { CKA::PRIVATE, (CK_VOID_PTR)&is_private, sizeof(is_private) }
    };
    return findObjects(template_files, objFiles);
}

CK_RV Session::findFiles (
        const bool isToken,
        const bool isPrivate,
        const CK_OBJECT_CLASS objType,
        const Buffer& id,
        const string& label,
        const string& application,
        vector<CK_OBJECT_HANDLE>& objFiles
)
{
    objFiles.clear();

    const CK_BBOOL is_token = isToken;
    const CK_BBOOL is_private = isPrivate;
    const CK_ATTRIBUTE attr_id = { CKA::ID, (CK_VOID_PTR)id.data(), (CK_ULONG)id.size() };
    const CK_ATTRIBUTE attr_label = { CKA::LABEL, (CK_VOID_PTR)label.data(), (CK_ULONG)label.length() };
    const CK_ATTRIBUTE attr_app = { CKA::LABEL, (CK_VOID_PTR)application.data(), (CK_ULONG)application.length() };
    vector<CK_ATTRIBUTE> template_files = {
        { CKA::CLASS, (CK_VOID_PTR)&objType, sizeof(objType) },
        { CKA::TOKEN, (CK_VOID_PTR)&is_token, sizeof(is_token) },
        { CKA::PRIVATE, (CK_VOID_PTR)&is_private, sizeof(is_private) }
    };

    if (attr_id.ulValueLen > 0) {
        template_files.push_back(attr_id);
    }
    if (attr_label.ulValueLen > 0) {
        template_files.push_back(attr_label);
    }
    if (attr_app.ulValueLen > 0) {
        template_files.push_back(attr_app);
    }

    return findObjects(template_files, objFiles);
}

CK_RV Session::findKeys (
        vector<CK_OBJECT_HANDLE>& objKeys
)
{
    return findFiles(true, true, CKO::PRIVATE_KEY, objKeys);
}

CK_RV Session::findObjects (
        const CK_ATTRIBUTE_PTR pFindObjAttrs,
        const CK_ULONG countFindObjAttrs,
        vector<CK_OBJECT_HANDLE>& objects
)
{
    m_LastResult = getApi()->C_FindObjectsInit(m_Handle, pFindObjAttrs, countFindObjAttrs);
    if (m_LastResult != CKR_OK) return m_LastResult;

    CK_ULONG cnt_objects = 1;
    while (cnt_objects > 0) {
        CK_OBJECT_HANDLE h_obj = 0;
        m_LastResult = getApi()->C_FindObjects(m_Handle, &h_obj, 1, &cnt_objects);
        if (m_LastResult != CKR_OK) break;
        if (cnt_objects > 0) {
            objects.push_back(h_obj);
        }
    }

    m_LastResult = getApi()->C_FindObjectsFinal(m_Handle);
    return m_LastResult;
}

CK_RV Session::findObjects (
        const vector<CK_ATTRIBUTE>& findObjAttrs,
        vector<CK_OBJECT_HANDLE>& objects
)
{
    return findObjects((CK_ATTRIBUTE_PTR)findObjAttrs.data(), (CK_ULONG)findObjAttrs.size(), objects);
}

CK_RV Session::generateKeyPairDstu (
        const CK_MECHANISM_TYPE mechType,
        const CK_KEY_TYPE keyType,
        const Buffer& ecParam,
        const Buffer& id,
        const string& label,
        const vector<CK_ATTRIBUTE>& publicKeyAttrs,
        const vector<CK_ATTRIBUTE>& privateKeyAttrs,
        CK_OBJECT_HANDLE& hPublicKey,
        CK_OBJECT_HANDLE& hPrivateKey
)
{
    const CK_MECHANISM mech_param = { mechType, NULL_PTR, 0 };
    const CK_ATTRIBUTE attr_id = { CKA::ID, (CK_VOID_PTR)id.data(), (CK_ULONG)id.size() };
    const CK_ATTRIBUTE attr_label = { CKA::LABEL, (CK_VOID_PTR)label.data(), (CK_ULONG)label.size() };
    vector<CK_ATTRIBUTE> template_publickey = {
        { CKA::CLASS, (CK_VOID_PTR)&CKO::PUBLIC_KEY, sizeof(CKO::PUBLIC_KEY) },
        { CKA::KEY_TYPE, (CK_VOID_PTR)&keyType, sizeof(keyType) },
        { CKA::VERIFY, (CK_VOID_PTR)&ATTRIBUTE_TRUE, sizeof(ATTRIBUTE_TRUE) },
        { CKA::EC_PARAMS, (CK_VOID_PTR)ecParam.data(), (CK_ULONG)ecParam.size() }
    };
    vector<CK_ATTRIBUTE> template_privatekey = {
        { CKA::CLASS, (CK_VOID_PTR)&CKO::PRIVATE_KEY, sizeof(CKO::PRIVATE_KEY) },
        { CKA::TOKEN, (CK_VOID_PTR)&ATTRIBUTE_TRUE, sizeof(ATTRIBUTE_TRUE) },
        { CKA::PRIVATE, (CK_VOID_PTR)&ATTRIBUTE_TRUE, sizeof(ATTRIBUTE_TRUE) },
        { CKA::KEY_TYPE, (CK_VOID_PTR)&keyType, sizeof(keyType) },
        { CKA::SIGN, (CK_VOID_PTR)&ATTRIBUTE_TRUE, sizeof(ATTRIBUTE_TRUE) },
        { CKA::EC_PARAMS, (CK_VOID_PTR)ecParam.data(), (CK_ULONG)ecParam.size() }
    };

    if (attr_id.ulValueLen > 0) {
        template_publickey.push_back(attr_id);
        template_privatekey.push_back(attr_id);
    }
    if (attr_label.ulValueLen > 0) {
        template_publickey.push_back(attr_label);
        template_privatekey.push_back(attr_label);
    }

    for (const auto& it : publicKeyAttrs) {
        template_publickey.push_back(it);
    }
    for (const auto& it : privateKeyAttrs) {
        template_privatekey.push_back(it);
    }

    return generateKeyPair(
        (CK_MECHANISM_PTR)&mech_param,
        template_publickey,
        template_privatekey,
        hPublicKey,
        hPrivateKey
    );
}

CK_RV Session::generateKeyPairEcdsa (
        const CK_MECHANISM_TYPE mechType,
        const CK_KEY_TYPE keyType,
        const Buffer& ecParam,
        const Buffer& id,
        const string& label,
        const vector<CK_ATTRIBUTE>& publicKeyAttrs,
        const vector<CK_ATTRIBUTE>& privateKeyAttrs,
        CK_OBJECT_HANDLE& hPublicKey,
        CK_OBJECT_HANDLE& hPrivateKey
)
{
    const CK_MECHANISM mech_param = { mechType, NULL_PTR, 0 };
    const CK_ATTRIBUTE attr_id = { CKA::ID, (CK_VOID_PTR)id.data(), (CK_ULONG)id.size() };
    const CK_ATTRIBUTE attr_label = { CKA::LABEL, (CK_VOID_PTR)label.data(), (CK_ULONG)label.size() };
    vector<CK_ATTRIBUTE> template_publickey = {
        { CKA::CLASS, (CK_VOID_PTR)&CKO::PUBLIC_KEY, sizeof(CKO::PUBLIC_KEY) },
        { CKA::KEY_TYPE, (CK_VOID_PTR)&keyType, sizeof(keyType) },
        { CKA::VERIFY, (CK_VOID_PTR)&ATTRIBUTE_TRUE, sizeof(ATTRIBUTE_TRUE) },
        { CKA::EC_PARAMS, (CK_VOID_PTR)ecParam.data(), (CK_ULONG)ecParam.size() }
    };
    vector<CK_ATTRIBUTE> template_privatekey = {
        { CKA::CLASS, (CK_VOID_PTR)&CKO::PRIVATE_KEY, sizeof(CKO::PRIVATE_KEY) },
        { CKA::TOKEN, (CK_VOID_PTR)&ATTRIBUTE_TRUE, sizeof(ATTRIBUTE_TRUE) },
        { CKA::PRIVATE, (CK_VOID_PTR)&ATTRIBUTE_TRUE, sizeof(ATTRIBUTE_TRUE) },
        { CKA::KEY_TYPE, (CK_VOID_PTR)&keyType, sizeof(keyType) },
        { CKA::SENSITIVE, (CK_VOID_PTR)&ATTRIBUTE_TRUE, sizeof(ATTRIBUTE_TRUE) },
        { CKA::SIGN, (CK_VOID_PTR)&ATTRIBUTE_TRUE, sizeof(ATTRIBUTE_TRUE) }
    };

    if (attr_id.ulValueLen > 0) {
        template_publickey.push_back(attr_id);
        template_privatekey.push_back(attr_id);
    }
    if (attr_label.ulValueLen > 0) {
        template_publickey.push_back(attr_label);
        template_privatekey.push_back(attr_label);
    }

    for (const auto& it : publicKeyAttrs) {
        template_publickey.push_back(it);
    }
    for (const auto& it : privateKeyAttrs) {
        template_privatekey.push_back(it);
    }

    return generateKeyPair(
        (CK_MECHANISM_PTR)&mech_param,
        template_publickey,
        template_privatekey,
        hPublicKey,
        hPrivateKey
    );
}

CK_RV Session::generateKeyPairRsa (
        const CK_ULONG modulusBits,
        const Buffer& publicExponent,
        const Buffer& id,
        const string& label,
        const vector<CK_ATTRIBUTE>& publicKeyAttrs,
        const vector<CK_ATTRIBUTE>& privateKeyAttrs,
        CK_OBJECT_HANDLE& hPublicKey,
        CK_OBJECT_HANDLE& hPrivateKey
)
{
    const CK_MECHANISM mech_param = { CKM::RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
    const CK_ATTRIBUTE attr_id = { CKA::ID, (CK_VOID_PTR)id.data(), (CK_ULONG)id.size() };
    const CK_ATTRIBUTE attr_label = { CKA::LABEL, (CK_VOID_PTR)label.data(), (CK_ULONG)label.size() };
    const CK_ATTRIBUTE attr_publicexp = { CKA::PUBLIC_EXPONENT, (CK_VOID_PTR)publicExponent.data(), (CK_ULONG)publicExponent.size() };
    vector<CK_ATTRIBUTE> template_publickey = {
        { CKA::MODULUS_BITS, (CK_VOID_PTR)&modulusBits, sizeof(modulusBits) },
        { CKA::ENCRYPT, (CK_VOID_PTR)&ATTRIBUTE_TRUE, sizeof(ATTRIBUTE_TRUE) },
        { CKA::VERIFY, (CK_VOID_PTR)&ATTRIBUTE_TRUE, sizeof(ATTRIBUTE_TRUE) },
        { CKA::WRAP, (CK_VOID_PTR)&ATTRIBUTE_TRUE, sizeof(ATTRIBUTE_TRUE) }
    };
    vector<CK_ATTRIBUTE> template_privatekey = {
        { CKA::TOKEN, (CK_VOID_PTR)&ATTRIBUTE_TRUE, sizeof(ATTRIBUTE_TRUE) },
        { CKA::PRIVATE, (CK_VOID_PTR)&ATTRIBUTE_TRUE, sizeof(ATTRIBUTE_TRUE) },
        { CKA::DECRYPT, (CK_VOID_PTR)&ATTRIBUTE_TRUE, sizeof(ATTRIBUTE_TRUE) },
        { CKA::SENSITIVE, (CK_VOID_PTR)&ATTRIBUTE_TRUE, sizeof(ATTRIBUTE_TRUE) },
        { CKA::SIGN, (CK_VOID_PTR)&ATTRIBUTE_TRUE, sizeof(ATTRIBUTE_TRUE) },
        { CKA::UNWRAP, (CK_VOID_PTR)&ATTRIBUTE_TRUE, sizeof(ATTRIBUTE_TRUE) }
    };

    if (attr_id.ulValueLen > 0) {
        template_publickey.push_back(attr_id);
        template_privatekey.push_back(attr_id);
    }
    if (attr_label.ulValueLen > 0) {
        template_publickey.push_back(attr_label);
        template_privatekey.push_back(attr_label);
    }
    if (attr_publicexp.ulValueLen > 0) {
        template_publickey.push_back(attr_publicexp);
    }

    for (const auto& it : publicKeyAttrs) {
        template_publickey.push_back(it);
    }
    for (const auto& it : privateKeyAttrs) {
        template_privatekey.push_back(it);
    }

    return generateKeyPair(
        (CK_MECHANISM_PTR)&mech_param,
        template_publickey,
        template_privatekey,
        hPublicKey,
        hPrivateKey
    );
}

CK_RV Session::getAttributeBool (
        const CK_OBJECT_HANDLE hObject,
        const CK_ATTRIBUTE_TYPE attrType,
        CK_BBOOL& value
)
{
    value = CK_FALSE;

    CK_ATTRIBUTE template_data = { attrType, NULL_PTR, 0 };
    const CK_RV ck_err = getAttributeValue(hObject, (CK_ATTRIBUTE_PTR)&template_data);
    if (ck_err != CKR_OK) return ck_err;

    if (template_data.ulValueLen != sizeof(value)) return CKR_ATTRIBUTE_VALUE_INVALID;

    template_data.pValue = (CK_VOID_PTR)&value;
    return getAttributeValue(hObject, (CK_ATTRIBUTE_PTR)&template_data);
}

CK_RV Session::getAttributeBuffer (
        const CK_OBJECT_HANDLE hObject,
        const CK_ATTRIBUTE_TYPE attrType,
        const size_t maxLen,
        Buffer& buf
)
{
    buf.resize(maxLen);

    const CK_ATTRIBUTE template_data = { attrType, (CK_VOID_PTR)buf.data(), (CK_ULONG)buf.size() };
    const CK_RV ck_err = getAttributeValue(hObject, (CK_ATTRIBUTE_PTR)&template_data);
    if (ck_err == CKR_OK) {
        buf.resize((size_t)template_data.ulValueLen);
    }
    return ck_err;
}

CK_RV Session::getAttributeBuffer (
        const CK_OBJECT_HANDLE hObject,
        const CK_ATTRIBUTE_TYPE attrType,
        Buffer& buf
)
{
    buf.clear();

    CK_ATTRIBUTE template_data = { attrType, NULL_PTR, 0 };
    const CK_RV ck_err = getAttributeValue(hObject, (CK_ATTRIBUTE_PTR)&template_data);
    if (ck_err != CKR_OK) return ck_err;

    if (template_data.ulValueLen == 0) return CKR_OK;

    buf.resize((size_t)template_data.ulValueLen);
    template_data.pValue = (CK_VOID_PTR)buf.data();
    return getAttributeValue(hObject, (CK_ATTRIBUTE_PTR)&template_data);
}

CK_RV Session::getAttributeSize (
        const CK_OBJECT_HANDLE hObject,
        const CK_ATTRIBUTE_TYPE attrType,
        CK_ULONG& valueLen
)
{
    const CK_ATTRIBUTE template_size = { attrType, NULL_PTR, 0 };
    const CK_RV ck_err = getAttributeValue(hObject, (CK_ATTRIBUTE_PTR)&template_size);
    if (ck_err == CKR_OK) {
        valueLen = template_size.ulValueLen;
    }
    return ck_err;
}

CK_RV Session::getAttributeText (
        const CK_OBJECT_HANDLE hObject,
        const CK_ATTRIBUTE_TYPE attrType,
        const size_t maxLen,
        string& text
)
{
    text.resize(maxLen);

    const CK_ATTRIBUTE template_text = { attrType, (CK_VOID_PTR)text.data(), (CK_ULONG)text.size() };
    const CK_RV ck_err = getAttributeValue(hObject, (CK_ATTRIBUTE_PTR)&template_text);
    if (ck_err == CKR_OK) {
        text.resize((size_t)template_text.ulValueLen);
    }
    return ck_err;
}

CK_RV Session::getAttributeText (
        const CK_OBJECT_HANDLE hObject,
        const CK_ATTRIBUTE_TYPE attrType,
        string& text
)
{
    text.clear();

    CK_ATTRIBUTE template_text = { attrType, NULL_PTR, 0 };
    const CK_RV ck_err = getAttributeValue(hObject, (CK_ATTRIBUTE_PTR)&template_text);
    if (ck_err != CKR_OK) return ck_err;

    if (template_text.ulValueLen == 0) return CKR_OK;

    text.resize((size_t)template_text.ulValueLen);
    template_text.pValue = (CK_VOID_PTR)text.data();
    return getAttributeValue(hObject, (CK_ATTRIBUTE_PTR)&template_text);
}

CK_RV Session::getAttributeUlong (
        const CK_OBJECT_HANDLE hObject,
        const CK_ATTRIBUTE_TYPE attrType,
        CK_ULONG& value
)
{
    value = 0;

    CK_ATTRIBUTE template_data = { attrType, NULL_PTR, 0 };
    const CK_RV ck_err = getAttributeValue(hObject, (CK_ATTRIBUTE_PTR)&template_data);
    if (ck_err != CKR_OK) return ck_err;

    if (template_data.ulValueLen != sizeof(value)) return CKR_ATTRIBUTE_VALUE_INVALID;

    template_data.pValue = (CK_VOID_PTR)&value;
    return getAttributeValue(hObject, (CK_ATTRIBUTE_PTR)&template_data);
}

CK_RV Session::getSessionInfo (
        SessionInfo& sessionInfo
)
{
    sessionInfo = SessionInfo();
    CK_SESSION_INFO session_info;
    memset(&session_info, 0, sizeof(session_info));

    m_LastResult = getApi()->C_GetSessionInfo(m_Handle, &session_info);
    if (m_LastResult == CKR_OK) {
        sessionInfo.slotId = session_info.slotID;
        sessionInfo.state = session_info.state;
        sessionInfo.flags = session_info.flags;
        sessionInfo.deviceError = session_info.ulDeviceError;
    }
    return m_LastResult;
}

CK_RV Session::setAttributeText (
        const CK_OBJECT_HANDLE hObject,
        const CK_ATTRIBUTE_TYPE attrType,
        const string& text
)
{
    const CK_ATTRIBUTE template_label = { attrType, (CK_VOID_PTR)text.data(), (CK_ULONG)text.size() };
    return setAttributeValue(hObject, (CK_ATTRIBUTE_PTR)&template_label);
}

CK_RV Session::signHash (
        const CK_OBJECT_HANDLE hObject,
        const CK_MECHANISM_PTR pMechParam,
        const Buffer& hashValue,
        Buffer& signValue
)
{
    signValue.clear();

    m_LastResult = getApi()->C_SignInit(m_Handle, pMechParam, hObject);
    if (m_LastResult != CKR_OK) return m_LastResult;

    CK_ULONG len_signvalue = 0;
    m_LastResult = getApi()->C_Sign(
        m_Handle,
        (CK_BYTE_PTR)hashValue.data(),
        (CK_ULONG)hashValue.size(),
        NULL_PTR,
        &len_signvalue
    );
    if (m_LastResult != CKR_OK) return m_LastResult;

    signValue.resize((size_t)len_signvalue);
    m_LastResult = getApi()->C_Sign(
        m_Handle,
        (CK_BYTE_PTR)hashValue.data(),
        (CK_ULONG)hashValue.size(),
        (CK_BYTE_PTR)signValue.data(),
        &len_signvalue
    );
    return m_LastResult;
}


Buffer bufferFromPtr (
        const CK_BYTE_PTR buf,
        const size_t len
)
{
    Buffer rv_buf;
    if (!buf || (len == 0)) return rv_buf;

    rv_buf.resize(len);
    memcpy((void*)rv_buf.data(), (const void*)buf, rv_buf.size());
    return rv_buf;
}

string stringFromChars (
        const CK_CHAR* buf,
        size_t len
)
{
    size_t idx_b = 0, idx_e = len - 1;
    for (size_t i = 0; i < len; i++) {
        if (buf[i] > 0x20) break;
        idx_b++;
    }
    for (size_t i = len - 1; i > 0; i--) {
        if (buf[i] > 0x20) break;
        idx_e--;
    }

    string rv_s;
    if (idx_b > idx_e) return rv_s;

    rv_s.resize(idx_e - idx_b + 1);
    memcpy((void*)rv_s.data(), buf + idx_b, rv_s.size());
    return rv_s;
}

bool stringToChars (
        CK_CHAR* buf,
        const size_t len,
        const string& text,
        const CK_CHAR fillChar
)
{
    if (!buf) return false;

    memset((void*)buf, fillChar, len);
    const size_t max_len = (text.size() < len) ? text.size() : len;
    memcpy((void*)buf, text.data(), max_len);
    return true;
}

string uint32ToHex (
        const uint32_t value
)
{
    string rv_hex;
    rv_hex.resize(8);
    std::snprintf(&rv_hex[0], 9, "%08X", value);
    return rv_hex;
}


}   //  end namespace Cryptoki
