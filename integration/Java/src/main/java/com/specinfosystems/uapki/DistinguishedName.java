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

/**
 * Розрізнювальне ім'я (issuer, subject)
 */
public record DistinguishedName(
        @SerializedName("C") String c,
        @SerializedName("SERIALNUMBER") String serialNumber,
        @SerializedName("CN") String cn,
        @SerializedName("SN") String sn,
        @SerializedName("O") String o,
        @SerializedName("OU") String ou,
        @SerializedName("OI") String oi,
        @SerializedName("L") String l,
        @SerializedName("S") String s,
        @SerializedName("STREET") String street,
        @SerializedName("G") String g,
        @SerializedName("H") String h,
        @SerializedName("TITLE") String title) {

    /**
     * @return ім'я у вигляді "CN=...; O=...; ..."
     */
    public String asString() {
        StringBuilder result = new StringBuilder();
        String delimiter = "; ";
        if (cn != null) result.append("CN=").append(cn).append(delimiter);
        if (o != null) result.append("O=").append(o).append(delimiter);
        if (ou != null) result.append("OU=").append(ou).append(delimiter);
        if (oi != null) result.append("OI=").append(oi).append(delimiter);
        if (serialNumber != null) result.append("SERIALNUMBER=").append(serialNumber).append(delimiter);
        if (c != null) result.append("C=").append(c).append(delimiter);
        if (l != null) result.append("L=").append(l).append(delimiter);
        if (s != null) result.append("S=").append(s).append(delimiter);
        if (street != null) result.append("STREET=").append(street).append(delimiter);
        if (title != null) result.append("TITLE=").append(title).append(delimiter);
        if (g != null) result.append("G=").append(g).append(delimiter);
        if (sn != null) result.append("SN=").append(sn).append(delimiter);
        if (result.length() >= delimiter.length())
            result.setLength(result.length() - delimiter.length());
        return result.toString();
    }
}
