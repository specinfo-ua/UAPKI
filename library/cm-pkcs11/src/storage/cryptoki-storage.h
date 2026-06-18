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

#ifndef CRYPTOKI_STORAGE_H
#define CRYPTOKI_STORAGE_H


#include "byte-array.h"
#include "cm-api.h"
#include "cm-errors.h"
#include "cryptoki-helper.h"
#include "hash.h"
#include "pkcs11.h"
#include <string>
#include <vector>


class CryptokiStorage
{
public:
    enum class KeyAlgo : uint32_t {
        UNDEFINED   = 0,
        //  Asym-key
        DSTU        = 1,
        ECDSA       = 2,
        RSA         = 3,
        //  Sym-key
        AES         = 4,
        GOST28147   = 5,
        KALYNA      = 6,
    };  //  end enum KeyAlgo

    struct GenerateKeyFlags {
        bool keyAgreement;
        GenerateKeyFlags (void)
            : keyAgreement(false)
        {}
    };  //  end struct GenerateKeyFlags

    struct DeriveWrapKeyParams {
        //  DerivedKey
        CK_EC_KDF_TYPE
                    kdf;
        CK_MECHANISM_TYPE
                    deriveMechType;
        CK_KEY_TYPE deriveKeyType;
        //  WrappedKey/UnwrappedKey
        CK_KEY_TYPE wrapKeyType;
        CK_MECHANISM_TYPE
                    wrapMechType;
    };  //  end struct DeriveWrapKeyParams

    struct PublicParams {
        //  EC-params
        Cryptoki::Buffer
                    ecParams;
        Cryptoki::Buffer
                    ecPoint;
        //  RSA-params
        Cryptoki::Buffer
                    rsaModulus;
        Cryptoki::Buffer
                    rsaExponent;
        Cryptoki::Buffer
                    rsaPublicKey;

        void reset (void) {
            ecParams.clear();
            ecPoint.clear();
            rsaModulus.clear();
            rsaExponent.clear();
            rsaPublicKey.clear();
        }
    };  //  end struct PublicParams

    struct KeyInfo {
        KeyAlgo     keyAlgo;
        Cryptoki::Buffer
                    id;             // id equal ID-KeyPair, id not equal keyId
        Cryptoki::Buffer
                    keyId;
        Cryptoki::Buffer
                    keyId2;         // only for DSTU-key
        CK_KEY_TYPE keyType;
        CK_MECHANISM_TYPE
                    mechType;
        PublicParams
                    publicParams;
        std::string mechanismId;
        std::string parameterId;
        std::string label;
        std::vector<std::string>
                    signAlgo;
        CK_OBJECT_HANDLE
                    hPrivateKey;    // the object handle will possible be not actual
        CK_OBJECT_HANDLE
                    hPublicKey;     // the object handle will possible be not actual

        KeyInfo (void);
        ~KeyInfo (void);

        bool equalKeyId (
            const uint8_t* bufKeyId,
            const size_t lenKeyId
        ) const;
        bool equalPublicKey (
            const uint8_t* bufPublicKey,
            const size_t lenPublicKey
        ) const;
        bool isPresent (void) const;
        void reset (void);

    };  //  end struct KeyInfo

    class Password : public std::string {
    public:
        ~Password (void);

        void reset (void);
        void set (
            const char* pass
        );

    };  //  end class Password

    struct SupportedKeyDeriveAlgos {
        bool        dstu;
        bool        dstuCofactor;
    };  //  end struct SupportedKeyDeriveAlgos

    struct SupportedKeyParams {
        std::vector<uint32_t>
                    dstuCurves,
                    ecdsaCurves,
                    rsaKeySizes;
    };  //  end struct SupportedKeyParams

    struct SupportedKeyWrapAlgos {
        bool        gost28147wrap;
        bool        kalyna256wrap;
    };  //  end struct SupportedKeyWrapAlgos

    struct SupportedSignAlgos {
        std::vector<std::string>
                    dstu,
                    ecdsa,
                    rsa;
    };  //  end struct SupportedSignAlgos

private:
    Cryptoki::Session
                m_Session;
    std::string m_StorageId;
    bool        m_ReadOnly;
    SupportedKeyDeriveAlgos
                m_SupportedKeyDeriveAlgos;
    SupportedKeyParams
                m_SupportedKeyParams;
    SupportedSignAlgos
                m_SupportedSignAlgos;
    SupportedKeyWrapAlgos
                m_SupportedKeyWrapAlgos;
    Cryptoki::TokenInfo
                m_TokenInfo;
    KeyInfo     m_SelectedKey;
    Password    m_PasswordRwSession;

public:
    CryptokiStorage (
        Cryptoki::Helper& iHelper
    );
    ~CryptokiStorage (void);

    CM_ERROR open (
        const CK_SLOT_ID slotId,
        const bool readOnly,
        const std::string& storageId
    );
    CM_ERROR login (
        const CK_USER_TYPE userType,
        const CK_CHAR_PTR pin
    );
    CM_ERROR logout (void);
    CM_ERROR close (void);

    CM_ERROR addCert (
        const bool isToken,
        const bool isPrivate,
        const Cryptoki::Buffer& bufCertEncoded,
        const Cryptoki::Buffer& bufId,
        const std::string& label,
        const std::vector<CK_ATTRIBUTE>& attrs,
        CK_OBJECT_HANDLE& hObject
    );
    CM_ERROR addData (
        const bool isToken,
        const bool isPrivate,
        const bool isModifiable,
        const Cryptoki::Buffer& bufData,
        const std::string& label,
        const std::string& application,
        const std::vector<CK_ATTRIBUTE>& attrs,
        CK_OBJECT_HANDLE& hObject
    );
    CM_ERROR buildGenKeyPairParams (
        KeyInfo& keyInfo
    ) const;
    CM_ERROR changePassword (
        const char* newPassword
    );
    CM_ERROR deleteFile (
        const CK_OBJECT_HANDLE hObject
    );
    CM_ERROR deleteKey (
        const KeyInfo& keyInfo
    );
    CM_ERROR findCerts (
        const bool isPrivate,
        const std::string& application,
        std::vector<CK_OBJECT_HANDLE>& objCerts
    );
    CM_ERROR findCertsInData (
        const bool isPrivate,
        const std::string& application,
        std::vector<CK_OBJECT_HANDLE>& objCerts
    );
    CM_ERROR findFiles (
        const bool isPrivate,
        const CK_OBJECT_CLASS objType,
        std::vector<CK_OBJECT_HANDLE>& objFiles
    );
    CM_ERROR findKeyPairs (
        std::vector<KeyInfo>& keyInfos
    );
    CM_ERROR findObjects (
        const std::vector<CK_ATTRIBUTE>& findObjAttrs,
        std::vector<CK_OBJECT_HANDLE>& objects
    );
    CM_ERROR generateKeyPair (
        const GenerateKeyFlags& flags,
        KeyInfo& keyInfo
    );
    CM_ERROR getKeyInfo (
        const CK_OBJECT_HANDLE hObject,
        KeyInfo& keyInfo
    );
    CM_ERROR randomBytes (
        CM_BYTEARRAY* baBuffer
    );
    CM_ERROR readFile (
        const CK_OBJECT_HANDLE hObject,
        CM_BYTEARRAY** baData
    );
    CM_ERROR readFile (
        const CK_OBJECT_HANDLE hObject,
        Cryptoki::Buffer& bufData
    );
    void selectKey (
        const KeyInfo& keyInfo = KeyInfo()
    );
    const char* signAlgoByDefault (
        const KeyInfo& keyInfo
    ) const;
    CM_ERROR signData (
        const KeyInfo& keyInfo,
        const std::string& signAlgo,    //  Parameter signAlgo must be contains oid-string
        const CM_BYTEARRAY* baSignAlgoParams,
        const CM_BYTEARRAY* baData,
        CM_BYTEARRAY** baSignature
    );
    CM_ERROR signHash (
        const KeyInfo& keyInfo,
        const std::string& signAlgo,    //  Parameter signAlgo must be contains oid-string
        const CM_BYTEARRAY* baSignAlgoParams,
        const CM_BYTEARRAY* baHash,
        CM_BYTEARRAY** baSignature
    );
    CM_ERROR dhWrapKey (
        const KeyInfo& keyInfo,
        bool isStaticKey,
        const char* oidDhKdf,
        const char* oidWrapAlgo,
        const size_t count,
        const CM_BYTEARRAY** abaSpkis,
        const CM_BYTEARRAY** abaSessionKeys,
        CM_BYTEARRAY*** abaSalts,
        CM_BYTEARRAY*** abaWrappedKeys
    );
    CM_ERROR dhUnwrapKey (
        const KeyInfo& keyInfo,
        const char* oidDhKdf,
        const char* oidWrapAlgo,
        const size_t count,
        const CM_BYTEARRAY** abaSpkis,
        const CM_BYTEARRAY** abaSalts,
        const CM_BYTEARRAY** abaWrappedKeys,
        CM_BYTEARRAY*** abaSessionKeys
    );

public:
    Cryptoki::Session& getSession (void) {
        return m_Session;
    }
    const std::string& getStorageId (void) const {
        return m_StorageId;
    }
    const SupportedKeyDeriveAlgos& getSupportedKeyDeriveAlgos (void) const {
        return m_SupportedKeyDeriveAlgos;
    }
    const SupportedKeyParams& getSupportedKeyParams (void) const {
        return m_SupportedKeyParams;
    }
    const SupportedKeyWrapAlgos& getSupportedKeyWrapAlgos (void) const {
        return m_SupportedKeyWrapAlgos;
    }
    const SupportedSignAlgos& getSupportedSignAlgos (void) const {
        return m_SupportedSignAlgos;
    }
    const Cryptoki::TokenInfo& getTokenInfo (void) const {
        return m_TokenInfo;
    }
    bool isAuthorized (void) const {
        return m_Session.isAuthorized();
    }
    bool isOpened (void) const {
        return m_Session.isOpened();
    }
    bool isReadOnly (void) const {
        return m_ReadOnly;
    }
    KeyInfo& selectedKey (void) {
        return m_SelectedKey;
    }

private:
    CM_ERROR getDerivedKey (
        const KeyInfo& keyInfo,
        const DeriveWrapKeyParams& dwkParams,
        const CM_BYTEARRAY* baSpki,
        const CM_BYTEARRAY* baSalt,
        CK_OBJECT_HANDLE& hDerivedKey
    );
    CM_ERROR getDomainParameters (void);
    CM_ERROR getKeyInfoDstu (
        KeyInfo& keyInfo
    );
    CM_ERROR getKeyInfoEcdsa (
        KeyInfo& keyInfo
    );
    CM_ERROR getKeyInfoRsa (
        KeyInfo& keyInfo
    );
    CM_ERROR getSupportedMechanisms (
        const CK_SLOT_ID slotId
    );
    CM_ERROR getUnwrappedKey (
        const CK_OBJECT_HANDLE hDerivedKey,
        const DeriveWrapKeyParams& dwkParams,
        const CM_BYTEARRAY* baWrappedKey,
        Cryptoki::Buffer& bufUnwrappedKey
    );
    CM_ERROR getWrappedKey (
        const CK_OBJECT_HANDLE hDerivedKey,
        const DeriveWrapKeyParams& dwkParams,
        const CM_BYTEARRAY* baSessionKey,
        Cryptoki::Buffer& bufWrappedKey
    );

public:
    static bool bufferFromBa (
        const ByteArray* ba,
        Cryptoki::Buffer& buf
    );
    static ByteArray* bufferToBa (
        const Cryptoki::Buffer& buf
    );
    static bool cmpBuffers (
        const Cryptoki::Buffer& bufA,
        const Cryptoki::Buffer& bufB
    );
    static bool cmpBuffers (
        const Cryptoki::Buffer& bufA,
        const uint8_t* pBufB,
        const size_t lenBufB
    );
    static bool strToUint32 (
        const char* str,
        uint32_t& value
    );
    static bool strToUint32 (
        const std::string& str,
        uint32_t& value
    );

public:
    static CM_ERROR calcKeyId (
        const HashAlg hashAlg,
        const Cryptoki::Buffer& bufPublicKey,
        Cryptoki::Buffer& bufKeyId
    );
    static bool decodeDstuParams (
        const Cryptoki::Buffer& bufEcParams,
        std::string& namedCurve
    );
    static bool decodeEcdsaParams (
        const Cryptoki::Buffer& bufEcParams,
        std::string& namedCurve
    );
    static bool encodeDstuParams (
        const std::string& namedCurve,
        Cryptoki::Buffer& bufEncoded
    );
    static bool encodeEcdsaParams (
        const std::string& namedCurve,
        Cryptoki::Buffer& bufEncoded
    );
    static bool encodeEcdsaSignvalue (
        const Cryptoki::Buffer& bufSignvalue,
        CM_BYTEARRAY** baEncoded
    );
    static bool encodeRsaPublicKey (
        const Cryptoki::Buffer& bufModulus,
        const Cryptoki::Buffer& bufPublicExponent,
        Cryptoki::Buffer& bufEncoded
    );
    static CM_ERROR getAlgorithmIdentifier (
        const KeyInfo& keyInfo,
        ByteArray** baEncoded
    );
    static CM_ERROR getPublicKey (
        const KeyInfo& keyInfo,
        ByteArray** baPubkey
    );
    static HashAlg hashAlgBySignAlgo (
        const KeyInfo& keyInfo,
        const std::string& signAlgo
    );
    static CM_ERROR toCmError (
        const CK_RV ckRetValue
    );

    static const uint8_t DER_ASN1_NULL[2];
    static const uint8_t DKE_DEFAULT_SBOX[64];
    static const uint8_t DER_OID_NIST_P256[10];
    static const uint8_t DER_OID_NIST_P384[7];
    static const uint8_t DER_OID_NIST_P521[7];

};  //  end class CryptokiStorage


#endif
