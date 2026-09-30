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

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

/**
 * Функції нативної бібліотеки uapki (JNA). Бібліотека шукається JNA: jna.library.path, потім системні шляхи
 * (PATH у Windows, LD_LIBRARY_PATH у Linux, DYLD_LIBRARY_PATH у macOS)
 */
interface UapkiNative extends Library {
    String LIBRARY_NAME = "uapki";

    //  Global instance (as in 2.x)
    Pointer process(byte[] requestUtf8Z);

    void json_free(Pointer response);

    //  Sessions (3.0)
    Pointer uapki_session_create();

    void uapki_session_free(Pointer session);

    Pointer uapki_session_process(Pointer session, Pointer memory, byte[] requestUtf8Z);

    Pointer uapki_session_shared_memory_create();

    void uapki_session_shared_memory_free(Pointer memory);

    Pointer uapki_session_shared_memory_process(Pointer memory, byte[] requestUtf8Z);

    /**
     * Завантажує бібліотеку під час першого звернення
     */
    final class Holder {
        private static volatile UapkiNative lib;

        private Holder() {
        }

        static UapkiNative get() {
            UapkiNative l = lib;
            if (l == null) {
                synchronized (Holder.class) {
                    l = lib;
                    if (l == null)
                        lib = l = Native.load(LIBRARY_NAME, UapkiNative.class);
                }
            }
            return l;
        }
    }
}
