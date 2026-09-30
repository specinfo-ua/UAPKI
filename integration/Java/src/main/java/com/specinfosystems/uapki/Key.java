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

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Ключ у сховищі (методи KEYS, SELECT_KEY)
 */
public final class Key {
    private static final DateTimeFormatter DISPLAY_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd hh:mm").withZone(ZoneOffset.UTC);

    private String id;
    private String keyId2;
    private String mechanismId;
    private String parameterId;
    private String label;
    private String application;
    private String certId;

    private transient List<CertificateShortInfo> certs;

    private Key() {
    }

    public String id() { return Util.str(id); }
    public String keyId2() { return keyId2; }
    public String mechanismId() { return Util.str(mechanismId); }
    public String parameterId() { return Util.str(parameterId); }
    public String label() { return label; }
    public String application() { return application; }
    public String certId() { return certId; }

    public KeyAlgo keyAlgo() {
        return KeyAlgo.fromOid(mechanismId());
    }

    /**
     * @throws UapkiException якщо параметр не підтримується
     */
    public KeyParameter keyParam() {
        return KeyParameter.fromOid(parameterId());
    }

    public String keyAlgoAndParamDisplay() {
        String s1 = "", s2 = "";
        try { s1 = keyAlgo().displayName(); } catch (RuntimeException e) { /* do nothing */ }
        try { s2 = keyParam().displayName(); } catch (RuntimeException e) { /* do nothing */ }
        if (s1.length() > 0 && s2.length() > 0)
            return s1 + " (" + s2 + ")";
        return s1;
    }

    public String keyAlgoDisplay() {
        return keyAlgo().displayName();
    }

    public String keyParamDisplay() {
        return keyParam().displayName();
    }

    /**
     * @return сертифікати ключа (заповнюються під час відкриття сховища) або null
     */
    public List<CertificateShortInfo> certs() {
        return certs;
    }

    void setCerts(List<CertificateShortInfo> certs) {
        this.certs = certs;
    }

    public String usageDisplay() {
        return usage().displayName();
    }

    /**
     * @return найпізніший час закінчення строку чинності сертифікатів ключа або null
     */
    public Instant dateTime() {
        if (certs != null && !certs.isEmpty()) {
            Instant max = null;
            for (CertificateShortInfo cert : certs) {
                Instant t = cert.validity().notAfter();
                if (max == null || t.isAfter(max))
                    max = t;
            }
            return max;
        }
        return null;
    }

    public String dateTimeDisplay() {
        Instant t = dateTime();
        return t != null ? DISPLAY_FORMAT.format(t) : "";
    }

    public String name() {
        if (certs != null && !certs.isEmpty())
            return certs.get(0).subject().cn() + "\n" + certs.get(0).subject().o();

        String name = "Сертифікат відсутній";
        if (label != null) {
            if (label.startsWith("SIG:"))
                return name + "\nЗгенеровано: " + DISPLAY_FORMAT.format(Uapki.convertUtcTimeToInstant(label.substring(4)));
            if (label.startsWith("KEP:"))
                return name + "\nЗгенеровано: " + DISPLAY_FORMAT.format(Uapki.convertUtcTimeToInstant(label.substring(4)));
            //  Almaz
            if (label.startsWith("SIGN-"))
                return name + "\nКонтекст: " + label.substring(5);
            if (label.startsWith("KEP-"))
                return name + "\nКонтекст: " + label.substring(4);
        }
        return name;
    }

    public KeyUsage usage() {
        if (certs != null && !certs.isEmpty()) {
            CertificateShortInfo cert = certs.get(0);
            if (cert.keyUsage().keyAgreement())
                return KeyUsage.KEY_AGREEMENT;
            if (cert.keyUsage().keyEncipherment())
                return KeyUsage.KEY_ENCIPHERMENT;
            if (cert.keyUsage().digitalSignature())
                return KeyUsage.SIGNATURE;
        } else if (label != null) {
            if (label.startsWith("SIG") || label.equals("KM AFD1"))
                return KeyUsage.SIGNATURE;
            if (label.startsWith("KEP") || label.equals("KM AFD2"))
                return keyAlgo() != KeyAlgo.RSA ? KeyUsage.KEY_AGREEMENT : KeyUsage.KEY_ENCIPHERMENT;
        }
        return KeyUsage.ANY;
    }
}
