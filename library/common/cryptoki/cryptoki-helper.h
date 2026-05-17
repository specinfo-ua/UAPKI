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

#ifndef CRYPTOKI_HELPER_H
#define CRYPTOKI_HELPER_H


#include "cryptoki-loader.h"
#include <vector>


namespace Cryptoki {


constexpr CK_CHAR   CHAR_BLANK          = 0x20;
constexpr size_t    MAXLEN_TOKEN_LABEL  = 32;


typedef std::vector<CK_BYTE> Buffer;


struct LibraryInfo {
    Version     cryptokiVersion;
    std::string manufacturerId;
    uint32_t    flags;
    std::string libraryDescription;
    Version     libraryVersion;
    LibraryInfo (void)
        : flags(0)
    {}
};  //  end struct LibraryInfo

struct MechanismInfo {
    uint32_t    minKeySize;
    uint32_t    maxKeySize;
    uint32_t    flags;
    MechanismInfo (void)
        : minKeySize(0)
        , maxKeySize(0)
        , flags(0)
    {}
};  //  end struct MechanismInfo

struct SessionInfo {
    CK_SLOT_ID  slotId;
    uint32_t    state;
    uint32_t    flags;
    uint32_t    deviceError;
    SessionInfo (void)
        : slotId(0)
        , state(0)
        , flags(0)
        , deviceError(0)
    {}
};  //  end struct SessionInfo

struct SlotInfo {
    std::string slotDescription;
    std::string manufacturerId;
    uint32_t    flags;
    Version     hardwareVersion;
    Version     firmwareVersion;
    SlotInfo (void)
        : flags(0)
    {}
};  //  end struct SlotInfo

struct TokenInfo {
    std::string label;
    std::string manufacturerId;
    std::string model;
    std::string serialNumber;
    uint32_t    flags;
    uint32_t    maxSessionCount;
    uint32_t    sessionCount;
    uint32_t    maxRwSessionCount;
    uint32_t    rwSessionCount;
    uint32_t    maxPinLen;
    uint32_t    minPinLen;
    uint32_t    totalPublicMemory;
    uint32_t    freePublicMemory;
    uint32_t    totalPrivateMemory;
    uint32_t    freePrivateMemory;
    Version     hardwareVersion;
    Version     firmwareVersion;
    std::string utcTime;
    TokenInfo (void)
        : flags(0)
        , maxSessionCount(0)
        , sessionCount(0)
        , maxRwSessionCount(0)
        , rwSessionCount(0)
        , maxPinLen(0)
        , minPinLen(0)
        , totalPublicMemory(0)
        , freePublicMemory(0)
        , totalPrivateMemory(0)
        , freePrivateMemory(0)
    {}
};  //  end struct TokenInfo


class Session;


class Helper : public Loader
{
    bool    m_IsInitialized;
    CK_RV   m_LastResult;

public:
    Helper (void);
    ~Helper (void);

    CK_RV initialize (
            CK_VOID_PTR pInitArgs = nullptr
    );
    CK_RV finalize (
            CK_VOID_PTR pReserved = nullptr
    );
    CK_RV getLastResult (void) const {
        return m_LastResult;
    }
    bool isInitialized (void) const {
        return m_IsInitialized;
    }

    CK_RV getInfo (
        LibraryInfo& libInfo
    );
    CK_RV getSlotList (
        const bool tokenPresent,
        std::vector<CK_SLOT_ID>& slotIds
    );
    CK_RV getSlotInfo (
        const CK_SLOT_ID slotId,
        SlotInfo& slotInfo
    );
    CK_RV getTokenInfo (
        const CK_SLOT_ID slotId,
        TokenInfo& tokenInfo
    );
    CK_RV getMechanismList (
        const CK_SLOT_ID slotId,
        std::vector<CK_MECHANISM_TYPE>& mechanismTypes
    );
    CK_RV getMechanismInfo (
        const CK_SLOT_ID slotId,
        const CK_MECHANISM_TYPE mechanismType,
        MechanismInfo& mechanismInfo
    );
    CK_RV closeAllSessions (
        const CK_SLOT_ID slotId
    );
    CK_RV initToken (//not checked
        const CK_SLOT_ID slotId,
        const CK_CHAR_PTR pin,
        const CK_ULONG pinLen,
        const std::string& label
    );
    CK_RV initToken (//not checked
        const CK_SLOT_ID slotId,
        const CK_CHAR_PTR pin,
        const std::string& label
    );

};  //  end class Helper


class Session {
    Helper&     m_Helper;
    CK_SESSION_HANDLE
                m_Handle;
    CK_SLOT_ID  m_SlotId;
    CK_RV       m_LastResult;
    bool        m_IsAuthorized;
    bool        m_IsOpened;

public:
    Session (
        Helper& iHelper
    );
    ~Session (void);

    CK_FUNCTION_LIST_PTR getApi (void) const {
        return m_Helper.getApi();
    }
    CK_SESSION_HANDLE getHandle (void) const {
        return m_Handle;
    }
    Helper& getHelper (void) {
        return m_Helper;
    }
    CK_RV getLastResult (void) const {
        return m_LastResult;
    }
    CK_SLOT_ID getSlotId (void) const {
        return m_SlotId;
    }
    bool isAuthorized (void) const {
        return m_IsAuthorized;
    }
    bool isOpened (void) const {
        return m_IsOpened;
    }

    CK_RV open (
        const CK_SLOT_ID slotId,
        const CK_FLAGS flags
    );
    CK_RV close (void);
    CK_RV login (
        const CK_USER_TYPE userType,
        const CK_CHAR_PTR pin,
        const CK_ULONG pinLen
    );
    CK_RV login (
        const CK_USER_TYPE userType,
        const CK_CHAR_PTR pin
    );
    CK_RV logout (void);
    void reset (void);

    CK_RV setPin (
        const CK_CHAR_PTR oldPin,
        const CK_ULONG oldPinLen,
        const CK_CHAR_PTR newPin,
        const CK_ULONG newPinLen
    );
    CK_RV setPin (
        const CK_CHAR_PTR oldPin,
        const CK_CHAR_PTR newPin
    );
    CK_RV initPin (//not checked
        const CK_CHAR_PTR pin,
        const CK_ULONG pinLen
    );
    CK_RV initPin (//not checked
        const CK_CHAR_PTR pin
    );

public:
    CK_RV createObject (
        const CK_ATTRIBUTE_PTR pCreateObjAttrs,
        const CK_ULONG countCreateObjAttrs,
        CK_OBJECT_HANDLE& hObject
    );
    CK_RV createObject (
        const std::vector<CK_ATTRIBUTE>& createObjAttrs,
        CK_OBJECT_HANDLE& hObject
    );
    CK_RV deriveKey (
        const CK_MECHANISM_PTR pMechParam,
        const CK_OBJECT_HANDLE hBaseKey,
        const CK_ATTRIBUTE_PTR pDeriveKeyAttrs,
        const CK_ULONG countDeriveKeyAttrs,
        CK_OBJECT_HANDLE& hDerivedKey
    );
    CK_RV deriveKey (
        const CK_MECHANISM_PTR pMechParam,
        const CK_OBJECT_HANDLE hBaseKey,
        const std::vector<CK_ATTRIBUTE>& deriveKeyAttrs,
        CK_OBJECT_HANDLE& hDerivedKey
    );
    CK_RV destroyObject (
        const CK_OBJECT_HANDLE hObject
    );
    CK_RV generateKeyPair (
        const CK_MECHANISM_PTR pMechParam,
        const CK_ATTRIBUTE_PTR pPublicKeyAttrs,
        const CK_ULONG countPublicKeyAttrs,
        const CK_ATTRIBUTE_PTR pPrivateKeyAttrs,
        const CK_ULONG countPrivateKeyAttrs,
        CK_OBJECT_HANDLE& hPublicKey,
        CK_OBJECT_HANDLE& hPrivateKey
    );
    CK_RV generateKeyPair (
        const CK_MECHANISM_PTR pMechParam,
        const std::vector<CK_ATTRIBUTE>& publicKeyAttrs,
        const std::vector<CK_ATTRIBUTE>& privateKeyAttrs,
        CK_OBJECT_HANDLE& hPublicKey,
        CK_OBJECT_HANDLE& hPrivateKey
    );
    CK_RV generateRandom (
        CK_BYTE_PTR pBuf,
        const CK_ULONG len
    );
    CK_RV generateRandom (
        Buffer& buf,
        const size_t len
    );
    CK_RV getAttributeValue (
        const CK_OBJECT_HANDLE hObject,
        CK_ATTRIBUTE_PTR pTemplateAttr
    );
    CK_RV getAttributeValue (
        const CK_OBJECT_HANDLE hObject,
        const CK_ATTRIBUTE_PTR pTemplateAttrs,
        const CK_ULONG countTemplateAttrs
    );
    CK_RV getAttributeValue (
        const CK_OBJECT_HANDLE hObject,
        const std::vector<CK_ATTRIBUTE>& templateAttrs
    );
    CK_RV setAttributeValue (
        const CK_OBJECT_HANDLE hObject,
        const CK_ATTRIBUTE_PTR pTemplateAttr
    );
    CK_RV setAttributeValue (
        const CK_OBJECT_HANDLE hObject,
        const CK_ATTRIBUTE_PTR pTemplateAttrs,
        const CK_ULONG countTemplateAttrs
    );
    CK_RV setAttributeValue (
        const CK_OBJECT_HANDLE hObject,
        const std::vector<CK_ATTRIBUTE>& templateAttrs
    );
    CK_RV unwrapKey (
        const CK_MECHANISM_PTR pMechParam,
        const CK_OBJECT_HANDLE hUnwrappingKey,
        const Buffer& wrappedKey,
        const CK_ATTRIBUTE_PTR pTemplateAttrs,
        const CK_ULONG countTemplateAttrs,
        CK_OBJECT_HANDLE& hUnwrapedKey
    );
    CK_RV unwrapKey (
        const CK_MECHANISM_PTR pMechParam,
        const CK_OBJECT_HANDLE hUnwrappingKey,
        const Buffer& wrappedKey,
        const std::vector<CK_ATTRIBUTE>& templateAttrs,
        CK_OBJECT_HANDLE& hUnwrapedKey
    );
    CK_RV wrapKey (
        const CK_MECHANISM_PTR pMechParam,
        const CK_OBJECT_HANDLE hWrappingKey,
        const CK_OBJECT_HANDLE hKey,
        Buffer& wrappedKey
    );

public:
    //  Block SMART-functions
    CK_RV addCert (
        const bool isToken,
        const bool isPrivate,
        const Buffer& buf,
        const Buffer& id,
        const std::string& label,
        const std::vector<CK_ATTRIBUTE>& attrs,
        CK_OBJECT_HANDLE& hObject
    );
    CK_RV addData (
        const bool isToken,
        const bool isPrivate,
        const bool isModifiable,
        const Buffer& buf,
        const std::string& label,
        const std::string& application,
        const std::vector<CK_ATTRIBUTE>& attrs,
        CK_OBJECT_HANDLE& hObject
    );
    CK_RV findFiles (
        const bool isToken,
        const bool isPrivate,
        const CK_OBJECT_CLASS objType,
        std::vector<CK_OBJECT_HANDLE>& objFiles
    );
    CK_RV findFiles (
        const bool isToken,
        const bool isPrivate,
        const CK_OBJECT_CLASS objType,
        const Buffer& id,
        const std::string& label,
        const std::string& application,
        std::vector<CK_OBJECT_HANDLE>& objFiles
    );
    CK_RV findKeys (
        std::vector<CK_OBJECT_HANDLE>& objKeys
    );
    CK_RV findObjects (
        const CK_ATTRIBUTE_PTR pFindObjAttrs,
        const CK_ULONG countFindObjAttrs,
        std::vector<CK_OBJECT_HANDLE>& objects
    );
    CK_RV findObjects (
        const std::vector<CK_ATTRIBUTE>& findObjAttrs,
        std::vector<CK_OBJECT_HANDLE>& objects
    );
    CK_RV generateKeyPairDstu (
        const CK_MECHANISM_TYPE mechType,
        const CK_KEY_TYPE keyType,
        const Buffer& ecParam,
        const Buffer& id,
        const std::string& label,
        const std::vector<CK_ATTRIBUTE>& publicKeyAttrs,
        const std::vector<CK_ATTRIBUTE>& privateKeyAttrs,
        CK_OBJECT_HANDLE& hPublicKey,
        CK_OBJECT_HANDLE& hPrivateKey
    );
    CK_RV generateKeyPairEcdsa (
        const CK_MECHANISM_TYPE mechType,
        const CK_KEY_TYPE keyType,
        const Buffer& ecParam,
        const Buffer& id,
        const std::string& label,
        const std::vector<CK_ATTRIBUTE>& publicKeyAttrs,
        const std::vector<CK_ATTRIBUTE>& privateKeyAttrs,
        CK_OBJECT_HANDLE& hPublicKey,
        CK_OBJECT_HANDLE& hPrivateKey
    );
    CK_RV generateKeyPairRsa (
        const CK_ULONG modulusBits,
        const Buffer& publicExponent,
        const Buffer& id,
        const std::string& label,
        const std::vector<CK_ATTRIBUTE>& publicKeyAttrs,
        const std::vector<CK_ATTRIBUTE>& privateKeyAttrs,
        CK_OBJECT_HANDLE& hPublicKey,
        CK_OBJECT_HANDLE& hPrivateKey
    );
    CK_RV getAttributeBool (
        const CK_OBJECT_HANDLE hObject,
        const CK_ATTRIBUTE_TYPE attrType,
        CK_BBOOL& value
    );
    CK_RV getAttributeBuffer (
        const CK_OBJECT_HANDLE hObject,
        const CK_ATTRIBUTE_TYPE attrType,
        const size_t maxLen,
        Buffer& buf
    );
    CK_RV getAttributeBuffer (
        const CK_OBJECT_HANDLE hObject,
        const CK_ATTRIBUTE_TYPE attrType,
        Buffer& buf
    );
    CK_RV getAttributeSize (
        const CK_OBJECT_HANDLE hObject,
        const CK_ATTRIBUTE_TYPE attrType,
        CK_ULONG& valueLen
    );
    CK_RV getAttributeText (
        const CK_OBJECT_HANDLE hObject,
        const CK_ATTRIBUTE_TYPE attrType,
        const size_t maxLen,
        std::string& text
    );
    CK_RV getAttributeText (
        const CK_OBJECT_HANDLE hObject,
        const CK_ATTRIBUTE_TYPE attrType,
        std::string& text
    );
    CK_RV getAttributeUlong (
        const CK_OBJECT_HANDLE hObject,
        const CK_ATTRIBUTE_TYPE attrType,
        CK_ULONG& value
    );
    CK_RV getSessionInfo (
        SessionInfo& sessionInfo
    );
    CK_RV setAttributeText (
        const CK_OBJECT_HANDLE hObject,
        const CK_ATTRIBUTE_TYPE attrType,
        const std::string& text
    );
    CK_RV signHash (
        const CK_OBJECT_HANDLE hObject,
        const CK_MECHANISM_PTR pMechParam,
        const Buffer& hashValue,
        Buffer& signValue
    );

};  //  end class Session


Buffer bufferFromPtr (
    const CK_BYTE_PTR buf,
    const size_t len
);

std::string stringFromChars (
    const CK_CHAR* buf,
    size_t len
);

bool stringToChars (
    CK_CHAR* buf,
    const size_t len,
    const std::string& text,
    const CK_CHAR fillChar = CHAR_BLANK
);

std::string uint32ToHex (
    const uint32_t value
);


}   //  end namespace Cryptoki

#endif
