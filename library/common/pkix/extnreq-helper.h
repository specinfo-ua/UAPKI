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

#ifndef EXTNREQ_HELPER_H
#define EXTNREQ_HELPER_H

#include "byte-array.h"
#include "uapki-ns.h"


class ExtnRequestHelper {
    UapkiNS::SmartBA
            m_EncodedExtnExtKeyUsage,
            m_EncodedExtnQcStatements,
            m_EncodedExtnSubjectKeyId,
            m_EncodedExtnPkAttestate;
    std::vector<std::string>
            m_KeyPurposeIds;
    UapkiNS::VectorBA
            m_EncodedCustomExtns,
            m_EncodedExtns;

public:
    ExtnRequestHelper (void);
    ~ExtnRequestHelper (void);

    int parse (
        const ByteArray* baEncoded
    );

    int addQcStatementsDefault (void);
    int encodeExtKeyUsage ( //  must be call after parse() or setKeyPurposeIds()
        const char* keyPurposeId,
        const bool critical
    );
    int encodePkAttestate (
        const ByteArray* baKeyId,
        const bool critical
    );
    int encodeQcStatements (
        const ByteArray* baExtnValue,
        const bool critical
    );
    int encodeSubjectKeyId (
        const ByteArray* baKeyId,
        const bool critical
    );
    bool findKeyPurposeId (
        const char* keyPurposeId
    );
    void pushCustomExtns (
        UapkiNS::VectorBA& encodedCustomExtns
    );
    void setKeyPurposeIds (
        const std::vector<std::string>& keyPurposeIds
    );

    size_t build (void);

    const UapkiNS::VectorBA& getEncodedExtns (void) {
        return m_EncodedExtns;
    }
    const std::vector<std::string>& getKeyPurposeIds (void) {
        return m_KeyPurposeIds;
    }

public:
    static const uint8_t DER_EXTNVALUE_QCSTATEMENTS_DEFAULT[22];
    static const char*   OID_PEN_SIS_PKATTESTATE;

};  //  end class ExtnRequestHelper


#endif
