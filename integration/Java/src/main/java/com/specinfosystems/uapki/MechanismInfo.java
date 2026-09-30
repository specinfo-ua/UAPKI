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

import java.util.ArrayList;
import java.util.List;

/**
 * Механізм (алгоритм ключа) сховища ключів
 */
public record MechanismInfo(
        String id,
        String name,
        @SerializedName("keyParam") List<String> keyParamRaw,
        @SerializedName("signAlgo") List<String> signAlgoRaw) {

    public MechanismInfo {
        id = Util.str(id);
        name = Util.str(name);
        keyParamRaw = Util.list(keyParamRaw);
        signAlgoRaw = Util.list(signAlgoRaw);
    }

    public KeyAlgo algo() {
        return KeyAlgo.fromOid(id);
    }

    /**
     * @return підтримувані параметри ключа (непідтримувані пропускаються)
     */
    public List<KeyParameter> keyParams() {
        List<KeyParameter> ret = new ArrayList<>();
        for (String param : keyParamRaw) {
            try {
                ret.add(KeyParameter.fromOid(param));
            } catch (RuntimeException e) {
                //  skip
            }
        }
        return ret;
    }

    public List<SignAlgo> signAlgos() {
        List<SignAlgo> ret = new ArrayList<>();
        for (String alg : signAlgoRaw)
            ret.add(SignAlgo.fromOid(alg));
        return ret;
    }
}
