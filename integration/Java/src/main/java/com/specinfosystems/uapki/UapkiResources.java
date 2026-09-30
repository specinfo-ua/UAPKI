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

import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * Рядки для відображення (UapkiResources.properties - українською, UapkiResources_en.properties - англійською);
 * мова обирається за {@link java.util.Locale#getDefault()}
 */
public final class UapkiResources {
    private static final String BUNDLE_NAME = "com.specinfosystems.uapki.UapkiResources";

    private UapkiResources() {
    }

    /**
     * @return набір ресурсів для поточної локалі
     */
    public static ResourceBundle bundle() {
        return ResourceBundle.getBundle(BUNDLE_NAME);
    }

    /**
     * @param key ключ ресурсу (наприклад, "DigitalSignature", "SubjectType")
     * @return рядок або null, якщо ключ відсутній
     */
    public static String getString(String key) {
        try {
            return bundle().getString(key);
        } catch (MissingResourceException e) {
            return null;
        }
    }

    /**
     * @param e значення переліку
     * @return назва за ключем "&lt;ТипПереліку&gt;_&lt;ЗНАЧЕННЯ&gt;" або "[[ЗНАЧЕННЯ]]", якщо ключ відсутній
     */
    public static String displayName(Enum<?> e) {
        String s = getString(e.getDeclaringClass().getSimpleName() + "_" + e.name());
        return (s == null || s.isBlank()) ? "[[" + e.name() + "]]" : s;
    }
}
