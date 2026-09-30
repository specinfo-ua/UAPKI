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

/**
 * Використання ключа сертифіката (keyUsage)
 */
public record CertKeyUsage(
        boolean digitalSignature,
        boolean contentCommitment,
        boolean keyEncipherment,
        boolean dataEncipherment,
        boolean keyAgreement,
        boolean keyCertSign,
        boolean crlSign,
        boolean encipherOnly,
        boolean decipherOnly) {

    /**
     * Порожнє використання ключа (усі ознаки false)
     */
    public static final CertKeyUsage NONE = fromInt(0);

    /**
     * @param value біти keyUsage (біт 0 - digitalSignature, ..., біт 8 - decipherOnly)
     * @return використання ключа
     */
    public static CertKeyUsage fromInt(int value) {
        return new CertKeyUsage(
                (value & (1 << 0)) != 0,
                (value & (1 << 1)) != 0,
                (value & (1 << 2)) != 0,
                (value & (1 << 3)) != 0,
                (value & (1 << 4)) != 0,
                (value & (1 << 5)) != 0,
                (value & (1 << 6)) != 0,
                (value & (1 << 7)) != 0,
                (value & (1 << 8)) != 0);
    }

    /**
     * @param extn розширення keyUsage (2.5.29.15)
     * @return використання ключа
     */
    public static CertKeyUsage fromExtension(Extension extn) {
        DecodedExtensionValue ku = extn.decoded() == null ? null : extn.decoded().value();
        if (ku == null)
            return NONE;
        return new CertKeyUsage(
                Boolean.TRUE.equals(ku.digitalSignature()),
                Boolean.TRUE.equals(ku.contentCommitment()),
                Boolean.TRUE.equals(ku.keyEncipherment()),
                Boolean.TRUE.equals(ku.dataEncipherment()),
                Boolean.TRUE.equals(ku.keyAgreement()),
                Boolean.TRUE.equals(ku.keyCertSign()),
                Boolean.TRUE.equals(ku.crlSign()),
                Boolean.TRUE.equals(ku.encipherOnly()),
                Boolean.TRUE.equals(ku.decipherOnly()));
    }

    /**
     * @return перелік призначень через кому (з ресурсів UapkiResources)
     */
    public String asString() {
        StringBuilder s = new StringBuilder();
        String delimiter = ", ";
        if (digitalSignature) s.append(UapkiResources.getString("DigitalSignature")).append(delimiter);
        if (contentCommitment) s.append(UapkiResources.getString("NonRepudiation")).append(delimiter);
        if (keyEncipherment) s.append(UapkiResources.getString("KeyEncipherment")).append(delimiter);
        if (dataEncipherment) s.append(UapkiResources.getString("DataEncipherment")).append(delimiter);
        if (keyAgreement) s.append(UapkiResources.getString("KeyAgreement")).append(delimiter);
        if (keyCertSign) s.append(UapkiResources.getString("KeyCertSign")).append(delimiter);
        if (crlSign) s.append(UapkiResources.getString("CrlSign")).append(delimiter);
        if (encipherOnly) s.append(UapkiResources.getString("EncipherOnly")).append(delimiter);
        if (decipherOnly) s.append(UapkiResources.getString("DecipherOnly")).append(delimiter);
        if (s.length() >= delimiter.length())
            s.setLength(s.length() - delimiter.length());
        return s.toString();
    }

    /**
     * @return біти keyUsage (біт 0 - digitalSignature, ..., біт 8 - decipherOnly)
     */
    public short asInt() {
        int ret = 0;
        if (digitalSignature) ret |= 1 << 0;
        if (contentCommitment) ret |= 1 << 1;
        if (keyEncipherment) ret |= 1 << 2;
        if (dataEncipherment) ret |= 1 << 3;
        if (keyAgreement) ret |= 1 << 4;
        if (keyCertSign) ret |= 1 << 5;
        if (crlSign) ret |= 1 << 6;
        if (encipherOnly) ret |= 1 << 7;
        if (decipherOnly) ret |= 1 << 8;
        return (short) ret;
    }
}
