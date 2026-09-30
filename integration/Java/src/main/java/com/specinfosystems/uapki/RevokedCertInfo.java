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
 * Відкликаний сертифікат у СВС
 */
public record RevokedCertInfo(
        @SerializedName("userCertificate") String userCertificateRaw,
        @SerializedName("revocationDate") String revocationDateRaw,
        @SerializedName("crlReason") String crlReasonRaw,
        @SerializedName("invalidityDate") String invalidityDateRaw) {

    public RevokedCertInfo {
        userCertificateRaw = Util.str(userCertificateRaw);
        revocationDateRaw = Util.str(revocationDateRaw);
        crlReasonRaw = Util.str(crlReasonRaw);
    }

    /**
     * @return серійний номер сертифіката
     */
    public byte[] userCertificate() {
        return Util.fromHex(userCertificateRaw);
    }

    public Instant revocationDate() {
        return Uapki.convertUtcTimeToInstant(revocationDateRaw);
    }

    /**
     * @return код причини відкликання (RFC 5280)
     * @throws IllegalArgumentException для невідомої причини
     */
    public short crlReason() {
        switch (crlReasonRaw) {
            case "UNDEFINED":
            case "UNSPECIFIED": return 0;
            case "KEY_COMPROMISE": return 1;
            case "CA_COMPROMISE": return 2;
            case "AFFILIATION_CHANGED": return 3;
            case "SUPERSEDED": return 4;
            case "CESSATION_OF_OPERATION": return 5;
            case "CERTIFICATE_HOLD": return 6;
            case "REMOVE_FROM_CRL": return 8;
            case "PRIVILEGE_WITHDRAWN": return 9;
            case "AA_COMPROMISE": return 10;
            default: throw new IllegalArgumentException("Unknown CRL reason code: " + crlReasonRaw);
        }
    }

    public Instant invalidityDate() {
        return invalidityDateRaw == null ? null : Uapki.convertUtcTimeToInstant(invalidityDateRaw);
    }
}
