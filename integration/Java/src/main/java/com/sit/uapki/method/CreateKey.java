/*
 * Copyright (c) 2021, The UAPKI Project Authors.
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

package com.sit.uapki.method;

import com.sit.uapki.common.PkiOid;
import com.sit.uapki.key.KeyId;

/**
 * Classes for CREATE_KEY-method
 */
public interface CreateKey {
    static final String METHOD = "CREATE_KEY";

    class Parameters {
        final String mechanismId;
        final String parameterId;
        final String label;

        public Parameters (PkiOid mechanismId, PkiOid parameterId, String label) {
            this.mechanismId = mechanismId.toString();
            this.parameterId = parameterId.toString();
            this.label = label;
        }

        public Parameters (PkiOid mechanismId, int bits, String label) {
            this.mechanismId = mechanismId.toString();
            this.parameterId = String.valueOf(bits);
            this.label = label;
        }
    }   //  end class Parameters

    class Result {
        String id;

        public KeyId getId() {
            return new KeyId(id);
        }
    }   //  end class Result

}
