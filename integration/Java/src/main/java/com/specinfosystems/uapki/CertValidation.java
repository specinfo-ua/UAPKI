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

/**
 * Результат перевірки сертифіката (метод VERIFY_CERT)
 */
public record CertValidation(
        @SerializedName("validateTime") String validateTimeRaw,
        String subjectCertId,
        Validity validity,
        boolean expired,
        boolean selfSigned,
        boolean trusted,
        String statusSignature,
        String issuerCertId,
        @SerializedName("validateByCRL") ValidateByCrlInfo validateByCrl,
        @SerializedName("validateByOCSP") ValidateByOcspInfo validateByOcsp) {

    public CertValidation {
        validateTimeRaw = Util.str(validateTimeRaw);
        subjectCertId = Util.str(subjectCertId);
        if (validity == null) validity = new Validity(null, null);
        statusSignature = Util.str(statusSignature);
    }

    public Instant validateTime() {
        return Uapki.convertUtcTimeToInstant(validateTimeRaw);
    }
}
