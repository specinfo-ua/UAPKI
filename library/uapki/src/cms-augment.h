/*
 * Copyright (c) 2026, The UAPKI Project Authors.
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

#ifndef UAPKI_CMS_AUGMENT_H
#define UAPKI_CMS_AUGMENT_H


#include "archive-timestamp-v3.h"
#include "content-hasher.h"
#include "doc-verify.h"
#include "parson.h"
#include "signature-format.h"


namespace UapkiNS {

namespace Doc {

//  Augmentation of a CAdES signature (ETSI EN 319 102-1, 4.3.3 - 4.3.5; EN 319 122-1): CAdES-T, CAdES-B-LT,
//  CAdES-B-LTA. One code for AUGMENT_CMS and for SIGN with the formats CAdES-B-LT and CAdES-B-LTA
namespace Augment {

    static const uint32_t REVOCATION_FRESHNESS_MAX = 120;   //  minutes

    struct Params {
        SignatureFormat
                    signatureFormat;    //  CADES_T, CADES_B_LT or CADES_B_LTA
        int         signerInfoIndex;    //  -1 - all signers
        //  The options of the validation (EN 319 102-1, 4.3.4.4: the signature is validated before the
        //  validation data is added): onlyCrl, checkCriticalExtensions, caRemovesExpiredCerts,
        //  revocationMinThisUpdate
        Verify::VerifyOptions
                    verifyOptions;

        Params (void)
            : signatureFormat(SignatureFormat::UNDEFINED)
            , signerInfoIndex(-1)
        {}
    };  //  end struct Params

    //  An archive-time-stamp-v3 with its hash index in the token (TS 101 733 6.4.2-6.4.3: ats-hash-index;
    //  EN 319 122-1 5.5.2-5.5.3: ats-hash-index-v3) added to the SignerInfo idxSigner of the signature
    int addArchiveTimeStamp (
        LibraryConfig* libConfig,
        Cert::CerStore* cerStore,
        Crl::CrlStore* crlStore,
        const ByteArray* baSignature,
        const size_t idxSigner,
        const Pkcs7::AtsV3::IndexType indexType,
        ByteArray** baResult
    );

    //  baAugmented - the augmented signature; joResult (optional) - "signatureInfos" with the result of the
    //  validation (as VERIFY) of the augmented signers
    int augmentCms (
        LibraryConfig* libConfig,
        Cert::CerStore* cerStore,
        Crl::CrlStore* crlStore,
        const ByteArray* baSignature,
        ContentHasher& contentHasher,
        const bool isDigest,
        const Params& params,
        ByteArray** baAugmented,
        JSON_Object* joResult,
        std::vector<std::string>* warnings = nullptr
    );

}   //  end namespace Augment

}   //  end namespace Doc

}   //  end namespace UapkiNS


#endif
