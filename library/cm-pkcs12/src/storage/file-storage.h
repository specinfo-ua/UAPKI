/*
 * Copyright (c) 2022, The UAPKI Project Authors.
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

#ifndef FILE_STORAGE_H
#define FILE_STORAGE_H


#include "cm-api.h"
#include "byte-array.h"
#include "store-bag.h"


struct FileStorageParam
{
    const char* bagCipher;
    const char* bagKdf;
    const char* macAlgo;
    size_t      iterations;

    FileStorageParam (void);

    void setDefault (const FileStorageParam* defValues = nullptr);

};  //  end struct FileStorageParam


class FileStorage
{
    ByteArray*  m_Buffer;
    std::string m_Filename;
    bool        m_IsCreate;
    bool        m_IsOpen;
    std::string m_Password;
    bool        m_ReadOnly;
    vector<StoreBag*>
                m_SafeBags;
    StoreBag*   m_SelectedKey;
    FileStorageParam
                m_StorageParam;

public:
    FileStorage (void);
    ~FileStorage (void);

    const std::string& filename (void) const { return m_Filename; }
    const bool isCreate (void) const { return m_IsCreate; }
    const bool isOpen (void) const { return m_IsOpen; }
    const char* password (void) const { return m_Password.c_str(); }
    const bool isReadOnly (void) const { return m_ReadOnly; }
    StoreBag* selectedKey (void) const { return m_SelectedKey; }
    FileStorageParam& storageParam (void) { return m_StorageParam; }

    void addBag (const StoreBag* bag);
    int changePassword (const char* password);
    void create (const std::string& fileName);
    int decode (const char* password);
    void deleteBag (const StoreBag* bag);
    vector<StoreBag*> listBags (const StoreBag::BAG_TYPE bagType);
    void loadFromBuffer (ByteArray* baEncoded, const bool readOnly);
    int loadFromFile (const std::string& fileName, const bool readOnly);
    void reset (void);
    void selectKey (const StoreBag* storeBagKey);
    void setOpen (const char* password);
    int store (const char* password = nullptr);

private:
    int decodeIit (const char* password);
    int decodeJks (const char* password);
    int decodePkcs12 (const char* password);
    int decodePkcs8e (const char* password);

    int readContents (const ByteArray* baAuthsafe, const char* password);
    int readSafeContents (const ByteArray* baSafeContents, const char* password);
    int encodeAuthenticatedSafe (const char* password, ByteArray** baEncoded);
    int encodePfx (const char* password, const ByteArray* baEncoded);
    int saveBuffer (void);

public:
    static const char* checkCipherOid (const char* oid, const char* oidDefault);
    static const char* checkHashOid (const char* oid, const char* oidDefault);

};  //  end class FileStorage


#endif
