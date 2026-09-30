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
 * Алгоритм підпису
 */
public enum SignAlgo {
    DSTU4145_GOST34311("1.2.804.2.1.1.1.1.3.1.1"),
    DSTU4145_KUPYNA256("1.2.804.2.1.1.1.1.3.6.1.1"),
    DSTU4145_KUPYNA384("1.2.804.2.1.1.1.1.3.6.2.1"),
    DSTU4145_KUPYNA512("1.2.804.2.1.1.1.1.3.6.3.1"),
    ECDSA_SHA("1.2.840.10045.4.1"),
    ECDSA_SHA224("1.2.840.10045.4.3.1"),
    ECDSA_SHA256("1.2.840.10045.4.3.2"),
    ECDSA_SHA384("1.2.840.10045.4.3.3"),
    ECDSA_SHA512("1.2.840.10045.4.3.4"),
    RSA_PKCS_SHA("1.2.840.113549.1.1.5"),
    RSA_PKCS_SHA224("1.2.840.113549.1.1.14"),
    RSA_PKCS_SHA256("1.2.840.113549.1.1.11"),
    RSA_PKCS_SHA384("1.2.840.113549.1.1.12"),
    RSA_PKCS_SHA512("1.2.840.113549.1.1.13"),
    RSA_PSS("1.2.840.113549.1.1.10"),
    UNSUPPORTED(null);

    private final String oid;

    SignAlgo(String oid) {
        this.oid = oid;
    }

    /**
     * @return OID алгоритму підпису
     * @throws UapkiException для {@link #UNSUPPORTED}
     */
    public String oid() {
        if (oid == null)
            throw new UapkiException("Непідтримуваний алгоритм підпису");
        return oid;
    }

    /**
     * @param oid OID алгоритму підпису
     * @return алгоритм або {@link #UNSUPPORTED}
     */
    public static SignAlgo fromOid(String oid) {
        if (oid == null) return UNSUPPORTED;
        if (oid.startsWith("1.2.804.2.1.1.1.1.3.6.1")) return DSTU4145_KUPYNA256;
        if (oid.startsWith("1.2.804.2.1.1.1.1.3.6.2")) return DSTU4145_KUPYNA384;
        if (oid.startsWith("1.2.804.2.1.1.1.1.3.6.3")) return DSTU4145_KUPYNA512;
        for (SignAlgo a : values()) {
            if (a.oid != null && a.oid.equals(oid))
                return a;
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
