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
 * Алгоритм гешування
 */
public enum HashAlgo {
    GOST34311("1.2.804.2.1.1.1.1.2.1"),
    KUPYNA256("1.2.804.2.1.1.1.1.2.2.1"),
    KUPYNA384("1.2.804.2.1.1.1.1.2.2.2"),
    KUPYNA512("1.2.804.2.1.1.1.1.2.2.3"),
    SHA("1.3.14.3.2.26"),
    SHA224("2.16.840.1.101.3.4.2.4"),
    SHA256("2.16.840.1.101.3.4.2.1"),
    SHA384("2.16.840.1.101.3.4.2.2"),
    SHA512("2.16.840.1.101.3.4.2.3"),
    SHA3_224("2.16.840.1.101.3.4.2.7"),
    SHA3_256("2.16.840.1.101.3.4.2.8"),
    SHA3_384("2.16.840.1.101.3.4.2.9"),
    SHA3_512("2.16.840.1.101.3.4.2.10"),
    UNSUPPORTED(null);

    private final String oid;

    HashAlgo(String oid) {
        this.oid = oid;
    }

    /**
     * @return OID алгоритму гешування
     * @throws UapkiException для {@link #UNSUPPORTED}
     */
    public String oid() {
        if (oid == null)
            throw new UapkiException("Непідтримуваний алгоритм гешування");
        return oid;
    }

    /**
     * @param oid OID алгоритму гешування
     * @return алгоритм або {@link #UNSUPPORTED}
     */
    public static HashAlgo fromOid(String oid) {
        for (HashAlgo a : values()) {
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
