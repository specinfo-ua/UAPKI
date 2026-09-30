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
 * Відкритий ключ сертифіката
 */
public record SubjectPublicKeyInfo(
        @SerializedName("bytes") byte[] bytes,
        @SerializedName("algorithm") String algorithmRaw,
        @SerializedName("parameters") byte[] parametersRaw,
        @SerializedName("publicKey") byte[] publicKeyRaw) {

    public SubjectPublicKeyInfo {
        bytes = Util.bytes(bytes);
        algorithmRaw = Util.str(algorithmRaw);
        publicKeyRaw = Util.bytes(publicKeyRaw);
    }

    public String algorithmName() {
        return algorithm().displayName();
    }

    /**
     * @return параметри у hex або "NULL"
     */
    public String parametersValue() {
        return parametersRaw == null ? "NULL" : Util.toHex(parametersRaw);
    }

    /**
     * @return відкритий ключ у hex
     */
    public String publicKey() {
        return Util.toHex(publicKeyRaw);
    }

    public KeyAlgo algorithm() {
        return KeyAlgo.fromOid(algorithmRaw);
    }

    /**
     * @return параметр ключа або null, якщо його не визначено
     */
    public KeyParameter parameters() {
        KeyAlgo algo = algorithm();
        if (algo == KeyAlgo.DSTU4145 || algo == KeyAlgo.ECDSA) {
            try {
                return KeyParameter.fromDer(parametersRaw, algo);
            } catch (RuntimeException e) {
                return null;
            }
        } else if (algo == KeyAlgo.RSA) {
            switch (publicKeyBits()) {
                case 1024: return KeyParameter.RSA1024;
                case 1536: return KeyParameter.RSA1536;
                case 2048: return KeyParameter.RSA2048;
                case 3072: return KeyParameter.RSA3072;
                case 4096: return KeyParameter.RSA4096;
                default: return null;
            }
        }
        return null;
    }

    public int publicKeyBits() {
        KeyAlgo algo = algorithm();
        byte[] pk = publicKeyRaw;
        if (algo == KeyAlgo.DSTU4145) {
            return pk.length * 8;
        } else if (algo == KeyAlgo.ECDSA) {
            int pkBits = (pk.length - 1) * 8;
            if (pk[0] == 0x04)
                pkBits >>= 1;
            return pkBits;
        } else if (algo == KeyAlgo.RSA) {
            int offset = 2;
            int lenLen = 1;
            if ((pk[1] & 0x80) == 0x80)
                offset += pk[1] & 0xF;

            offset++;

            if ((pk[offset] & 0x80) == 0x80) {
                lenLen = pk[offset] & 0xF;
                offset++;
            }

            int pkBits = (pk[offset] & 0xFF) * 8;
            if (lenLen == 2) {
                pkBits *= 256;
                pkBits += (pk[offset + 1] & 0xFF) * 8;
            }

            if (pk[offset + lenLen] == 0)
                pkBits -= 8;

            return pkBits;
        }
        return 0;
    }
}
