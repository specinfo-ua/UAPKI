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

import java.math.BigInteger;
import java.time.Instant;
import java.util.List;

/**
 * Інформація про СВС (методи CRL_INFO, LIST_CRLS)
 */
public record CrlInfo(
        String crlId,
        DistinguishedName issuer,
        @SerializedName("thisUpdate") String thisUpdateRaw,
        @SerializedName("nextUpdate") String nextUpdateRaw,
        int countRevokedCerts,
        String authorityKeyId,
        @SerializedName("crlNumber") String crlNumberRaw,
        @SerializedName("deltaCrlIndicator") String deltaCrlIndicatorRaw,
        List<RevokedCertInfo> revokedCerts,
        @SerializedName("freshestCRL") List<String> freshestCrl) {

    public CrlInfo {
        crlId = Util.str(crlId);
        thisUpdateRaw = Util.str(thisUpdateRaw);
        nextUpdateRaw = Util.str(nextUpdateRaw);
        authorityKeyId = Util.str(authorityKeyId);
        crlNumberRaw = Util.str(crlNumberRaw);
    }

    public Instant thisUpdate() {
        return Uapki.convertUtcTimeToInstant(thisUpdateRaw);
    }

    public Instant nextUpdate() {
        return Uapki.convertUtcTimeToInstant(nextUpdateRaw);
    }

    /**
     * @return номер СВС (з hex-рядка)
     */
    public BigInteger crlNumber() {
        return new BigInteger(crlNumberRaw, 16);
    }

    public BigInteger deltaCrlIndicator() {
        return deltaCrlIndicatorRaw == null ? null : new BigInteger(deltaCrlIndicatorRaw, 16);
    }

    /**
     * @return настав час наступного оновлення СВС
     */
    public boolean isObsolete() {
        return Instant.now().isAfter(nextUpdate());
    }
}
