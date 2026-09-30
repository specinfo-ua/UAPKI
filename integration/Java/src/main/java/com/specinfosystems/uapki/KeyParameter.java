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

import java.util.Arrays;

/**
 * Параметр ключа (крива або довжина ключа RSA)
 */
public enum KeyParameter {
    M233_PB("1.2.804.2.1.1.1.1.3.1.1.2.5"),
    M257_PB("1.2.804.2.1.1.1.1.3.1.1.2.6"),
    M307_PB("1.2.804.2.1.1.1.1.3.1.1.2.7"),
    M367_PB("1.2.804.2.1.1.1.1.3.1.1.2.8"),
    M431_PB("1.2.804.2.1.1.1.1.3.1.1.2.9"),
    P256("1.2.840.10045.3.1.7"),
    P384("1.3.132.0.34"),
    P521("1.3.132.0.35"),
    RSA1024("1024"),
    RSA1536("1536"),
    RSA2048("2048"),
    RSA3072("3072"),
    RSA4096("4096"),
    UNSUPPORTED(null);

    private static final byte[] P256_OID = { 0x06, 0x08, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x03, 0x01, 0x07 };
    private static final byte[] P384_OID = { 0x06, 0x05, 0x2B, (byte) 0x81, 0x04, 0x00, 0x22 };
    private static final byte[] P521_OID = { 0x06, 0x05, 0x2B, (byte) 0x81, 0x04, 0x00, 0x23 };

    private final String oid;

    KeyParameter(String oid) {
        this.oid = oid;
    }

    /**
     * @return OID кривої або довжина ключа RSA
     * @throws UapkiException для {@link #UNSUPPORTED}
     */
    public String oid() {
        if (oid == null)
            throw new UapkiException("Непідтримуваний параметр ключа");
        return oid;
    }

    /**
     * @param value OID кривої або довжина ключа RSA
     * @return параметр ключа
     * @throws UapkiException якщо параметр не підтримується
     */
    public static KeyParameter fromOid(String value) {
        for (KeyParameter p : values()) {
            if (p.oid != null && p.oid.equals(value))
                return p;
        }
        throw new UapkiException("Непідтримуваний параметр ключа");
    }

    /**
     * Визначає параметр ключа за DER-кодованими параметрами алгоритму
     *
     * @param value DER-кодовані параметри
     * @param algo  алгоритм ключа
     * @return параметр ключа або {@link #UNSUPPORTED}
     * @throws UapkiException якщо параметр ДСТУ 4145 не підтримується
     */
    public static KeyParameter fromDer(byte[] value, KeyAlgo algo) {
        if (algo == KeyAlgo.DSTU4145)
            return DstuParameters.getKeyParameterByValue(value);

        if (algo == KeyAlgo.ECDSA) {
            if (Arrays.equals(value, P256_OID)) return P256;
            if (Arrays.equals(value, P384_OID)) return P384;
            if (Arrays.equals(value, P521_OID)) return P521;
        }

        return UNSUPPORTED;
    }

    /**
     * @return назва для відображення (з ресурсів UapkiResources)
     */
    public String displayName() {
        return UapkiResources.displayName(this);
    }
}
