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

package com.specinfosystems.uapki;

import com.google.gson.annotations.SerializedName;

import java.time.Instant;
import java.util.List;

/**
 * Результат перевірки одного підпису (метод VERIFY)
 */
public record SignatureData(
        String signerCertId,
        Certificate signerCertInfo,
        String signatureFormat,
        String status,
        boolean validSignatures,
        boolean validDigests,
        @SerializedName("bestSignatureTime") String bestSignatureTimeRaw,
        @SerializedName("signAlgo") String signAlgoOid,
        @SerializedName("digestAlgo") String digestAlgoOid,
        String statusSignature,
        String statusMessageDigest,
        @SerializedName("signingTime") String signingTimeRaw,
        SignaturePolicy signaturePolicy,
        String statusEssCert,
        @SerializedName("contentTS") TimeStampInfo contentTs,
        @SerializedName("signatureTS") TimeStampInfo signatureTs,
        @SerializedName("archiveTS") TimeStampInfo archiveTs,
        String statusCertificateRefs,
        List<CertRefInfo> certificateRefs,
        List<String> certValues,
        List<RevocationRefInfo> revocationRefs,
        List<AttributeInfo> signedAttributes,
        List<AttributeInfo> unsignedAttributes,
        List<CertChainInfo> certificateChain,
        List<ExpectedCertInfo> expectedCerts,
        List<ExpectedCrlInfo> expectedCrls,
        List<String> warnings) {

    public SignatureData {
        signerCertId = Util.str(signerCertId);
        signatureFormat = Util.str(signatureFormat);
        status = Util.str(status);
        bestSignatureTimeRaw = Util.str(bestSignatureTimeRaw);
        signAlgoOid = Util.str(signAlgoOid);
        digestAlgoOid = Util.str(digestAlgoOid);
        statusSignature = Util.str(statusSignature);
        statusMessageDigest = Util.str(statusMessageDigest);
        statusEssCert = Util.str(statusEssCert);
    }

    public Instant bestSignatureTime() {
        return Uapki.convertUtcTimeToInstant(bestSignatureTimeRaw);
    }

    public SignAlgo signAlgo() {
        return SignAlgo.fromOid(signAlgoOid);
    }

    public Instant signingTime() {
        return signingTimeRaw != null ? Uapki.convertUtcTimeToInstant(signingTimeRaw) : null;
    }
}
