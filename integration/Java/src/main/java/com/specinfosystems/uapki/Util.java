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

import java.util.List;

final class Util {
    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    private Util() {
    }

    static String str(String s) {
        return s == null ? "" : s;
    }

    static <T> List<T> list(List<T> l) {
        return l == null ? List.of() : l;
    }

    static byte[] bytes(byte[] b) {
        return b == null ? new byte[0] : b;
    }

    /**
     * Converts byte array to hex string (upper case)
     */
    static String toHex(byte[] data) {
        char[] chars = new char[data.length * 2];
        int j = 0;
        for (byte t : data) {
            chars[j++] = HEX[(t >> 4) & 0xF];
            chars[j++] = HEX[t & 0xF];
        }
        return new String(chars);
    }

    /**
     * Converts hex string to byte array. Accepts optional "0x" prefix and ignores leading/trailing spaces
     */
    static byte[] fromHex(String s) {
        s = s.trim();
        if (s.startsWith("0x") || s.startsWith("0X"))
            s = s.substring(2);
        if ((s.length() & 1) != 0)
            throw new IllegalArgumentException("Invalid hex length.");
        byte[] r = new byte[s.length() / 2];
        for (int i = 0, j = 0; i < s.length(); i += 2, j++) {
            int hi = Character.digit(s.charAt(i), 16);
            int lo = Character.digit(s.charAt(i + 1), 16);
            if (hi < 0 || lo < 0)
                throw new IllegalArgumentException("Invalid hex char.");
            r[j] = (byte) ((hi << 4) | lo);
        }
        return r;
    }

    /**
     * File extension with the dot (as Path.GetExtension in .NET), or "" if there is none
     */
    static String extension(String path) {
        int sep = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
        int dot = path.lastIndexOf('.');
        return (dot > sep && dot < path.length() - 1) ? path.substring(dot) : "";
    }
}
